/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketHTTPClient.c - HTTP Client with HTTP/1.1 and HTTP/2 Support */

#include <assert.h>
#include <string.h>

#include "core/Arena.h"
#include "core/SocketCrypto.h"
#include "core/SocketMetrics.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTP2.h"
#include "http/SocketHTTP-private.h"
#include "http/SocketHTTPClient-private.h"
#include "http/SocketHTTPClient.h"
#include "socket/Socket.h"
SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTPClient);

const Except_T SocketHTTPClient_Failed
    = { &SocketHTTPClient_Failed, "HTTP client operation failed" };
const Except_T SocketHTTPClient_DNSFailed
    = { &SocketHTTPClient_DNSFailed, "DNS resolution failed" };
const Except_T SocketHTTPClient_ConnectFailed
    = { &SocketHTTPClient_ConnectFailed, "Connection failed" };
#if SOCKET_HAS_TLS
const Except_T SocketHTTPClient_TLSFailed
    = { &SocketHTTPClient_TLSFailed, "TLS handshake failed" };
#endif
const Except_T SocketHTTPClient_Timeout
    = { &SocketHTTPClient_Timeout, "Request timeout" };
const Except_T SocketHTTPClient_ProtocolError
    = { &SocketHTTPClient_ProtocolError, "HTTP protocol error" };
const Except_T SocketHTTPClient_TooManyRedirects
    = { &SocketHTTPClient_TooManyRedirects, "Too many redirects" };
const Except_T SocketHTTPClient_ResponseTooLarge
    = { &SocketHTTPClient_ResponseTooLarge, "Response body too large" };

static const char *error_strings[]
    = { [HTTPCLIENT_OK] = "Success",
        [HTTPCLIENT_ERROR_DNS] = "DNS resolution failed",
        [HTTPCLIENT_ERROR_CONNECT] = "Connection failed",
#if SOCKET_HAS_TLS
        [HTTPCLIENT_ERROR_TLS] = "TLS handshake failed",
#endif
        [HTTPCLIENT_ERROR_TIMEOUT] = "Request timeout",
        [HTTPCLIENT_ERROR_PROTOCOL] = "HTTP protocol error",
        [HTTPCLIENT_ERROR_TOO_MANY_REDIRECTS] = "Too many redirects",
        [HTTPCLIENT_ERROR_RESPONSE_TOO_LARGE] = "Response body too large",
        [HTTPCLIENT_ERROR_CANCELLED] = "Request cancelled",
        [HTTPCLIENT_ERROR_OUT_OF_MEMORY] = "Out of memory" };

int
SocketHTTPClient_error_is_retryable (SocketHTTPClient_Error error)
{
  switch (error)
    {
    /* Retryable errors - transient conditions that may resolve */
    case HTTPCLIENT_ERROR_DNS:     /* DNS server may recover */
    case HTTPCLIENT_ERROR_CONNECT: /* Server may restart */
    case HTTPCLIENT_ERROR_TIMEOUT: /* Network congestion may clear */
      return 1;

    /* Non-retryable errors - permanent or configuration issues */
    case HTTPCLIENT_OK: /* Not an error */
#if SOCKET_HAS_TLS
    case HTTPCLIENT_ERROR_TLS: /* Config mismatch */
#endif
    case HTTPCLIENT_ERROR_PROTOCOL:           /* Server bug */
    case HTTPCLIENT_ERROR_TOO_MANY_REDIRECTS: /* Redirect loop */
    case HTTPCLIENT_ERROR_RESPONSE_TOO_LARGE: /* Size limit */
    case HTTPCLIENT_ERROR_CANCELLED:          /* User cancelled */
    case HTTPCLIENT_ERROR_OUT_OF_MEMORY:      /* Resource exhaustion */
    case HTTPCLIENT_ERROR_LIMIT_EXCEEDED:     /* Pool limits reached */
      return 0;

    default:
      /* Unknown errors default to non-retryable for safety */
      return 0;
    }
}

/**
 * @brief Allocate structure from arena with automatic cleanup on failure.
 *
 * Exception-based variant: disposes arena and raises SocketHTTPClient_Failed.
 * Used in constructors that propagate errors via exceptions.
 *
 * @param arena Arena to allocate from
 * @param ptr Pointer variable to assign (will be set to allocated memory)
 * @param type Type of structure to allocate (e.g., *client, *req)
 * @param msg Error message for exception
 */
#define HTTPCLIENT_ARENA_CALLOC_OR_RAISE(arena, ptr, type, msg)                \
  do                                                                           \
    {                                                                          \
      (ptr) = CALLOC ((arena), 1, sizeof (type));                              \
      if ((ptr) == NULL)                                                       \
        {                                                                      \
          Arena_dispose (&(arena));                                            \
          SOCKET_RAISE_MSG (SocketHTTPClient, SocketHTTPClient_Failed, (msg)); \
        }                                                                      \
    }                                                                          \
  while (0)

/**
 * @brief Allocate structure from arena with error code on failure.
 *
 * Return-code variant: disposes arena, sets last_error, returns NULL.
 * Used in constructors that report errors via return codes.
 *
 * @param arena Arena to allocate from
 * @param ptr Pointer variable to assign (will be set to allocated memory)
 * @param type Type of structure to allocate (e.g., *req, *prep)
 * @param client_expr Expression to access client (e.g., client, prep->client)
 */
#define HTTPCLIENT_ARENA_CALLOC_OR_RETURN(arena, ptr, type, client_expr) \
  do                                                                     \
    {                                                                    \
      (ptr) = CALLOC ((arena), 1, sizeof (type));                        \
      if ((ptr) == NULL)                                                 \
        {                                                                \
          Arena_dispose (&(arena));                                      \
          (client_expr)->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;    \
          return NULL;                                                   \
        }                                                                \
    }                                                                    \
  while (0)

/* Forward declaration for secure clearing of auth credentials */
static void secure_clear_auth (SocketHTTPClient_Auth *auth);

/* Forward declaration for recursive request execution.
 * Used by handle_401_auth_retry() and handle_redirect() for retry logic. */
static int execute_request_internal (SocketHTTPClient_T client,
                                     SocketHTTPClient_Request_T req,
                                     SocketHTTPClient_Response *response,
                                     int redirect_count,
                                     int auth_retry_count);

static inline SocketHTTPClient_Auth *
get_effective_auth (SocketHTTPClient_T client, SocketHTTPClient_Request_T req)
{
  return req->auth != NULL ? req->auth : client->default_auth;
}

static inline const char *
get_path_or_root (const SocketHTTP_URI *uri)
{
  return uri->path != NULL ? uri->path : "/";
}

/**
 * httpclient_auth_copy_to_arena - Copy auth strings into arena
 * @arena: Arena for string allocation
 * @dest: Destination auth structure (already allocated)
 * @src: Source auth structure
 */
static void
httpclient_auth_copy_to_arena (Arena_T arena,
                               SocketHTTPClient_Auth *dest,
                               const SocketHTTPClient_Auth *src)
{
  *dest = *src;
  dest->username = socket_util_arena_strdup (arena, src->username);
  dest->password = socket_util_arena_strdup (arena, src->password);
  dest->token = socket_util_arena_strdup (arena, src->token);
}

void
SocketHTTPClient_config_defaults (SocketHTTPClient_Config *config)
{
  assert (config != NULL);

  memset (config, 0, sizeof (*config));

  /* Protocol */
  config->max_version = HTTP_VERSION_2;
  config->allow_http2_cleartext = 0;

  /* Connection pooling */
  config->enable_connection_pool = 1;
  config->max_connections_per_host = HTTPCLIENT_DEFAULT_MAX_CONNS_PER_HOST;
  config->max_total_connections = HTTPCLIENT_DEFAULT_MAX_TOTAL_CONNS;
  config->idle_timeout_ms = HTTPCLIENT_DEFAULT_IDLE_TIMEOUT_MS;

  /* Timeouts */
  config->connect_timeout_ms = HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT_MS;
  config->request_timeout_ms = HTTPCLIENT_DEFAULT_REQUEST_TIMEOUT_MS;
  config->dns_timeout_ms = HTTPCLIENT_DEFAULT_DNS_TIMEOUT_MS;

  /* Redirects */
  config->follow_redirects = HTTPCLIENT_DEFAULT_MAX_REDIRECTS;
  config->redirect_on_post = 0;

  /* Compression */
  config->accept_encoding
      = HTTPCLIENT_ENCODING_GZIP | HTTPCLIENT_ENCODING_DEFLATE;
  config->auto_decompress = 1;

  /* TLS */
  config->tls_context = NULL;
  config->verify_ssl = 1;

  /* Proxy */
  config->proxy = NULL;

  /* User agent */
  config->user_agent = HTTPCLIENT_DEFAULT_USER_AGENT;

  /* Limits */
  config->max_response_size = HTTPCLIENT_DEFAULT_MAX_RESPONSE_SIZE;

  /* Retry configuration (default: disabled for backward compatibility) */
  config->enable_retry = HTTPCLIENT_DEFAULT_ENABLE_RETRY;
  config->max_retries = HTTPCLIENT_DEFAULT_MAX_RETRIES;
  config->retry_initial_delay_ms = HTTPCLIENT_DEFAULT_RETRY_INITIAL_DELAY_MS;
  config->retry_max_delay_ms = HTTPCLIENT_DEFAULT_RETRY_MAX_DELAY_MS;
  config->retry_on_connection_error = HTTPCLIENT_DEFAULT_RETRY_ON_CONNECT;
  config->retry_on_timeout = HTTPCLIENT_DEFAULT_RETRY_ON_TIMEOUT;
  config->retry_on_5xx = HTTPCLIENT_DEFAULT_RETRY_ON_5XX;

  /* Security */
  config->enforce_samesite = HTTPCLIENT_DEFAULT_ENFORCE_SAMESITE;

  /* Benchmark mode (default: disabled) */
  config->discard_body = 0;

  /* Async I/O (io_uring) - disabled by default for backward compatibility */
  config->enable_async_io = HTTPCLIENT_DEFAULT_ENABLE_ASYNC_IO;
}

/**
 * @brief Validate and duplicate user agent string.
 * @return 0 on success, -1 on error (raises exception)
 *
 * SECURITY: Validates user agent for control characters to prevent header
 * injection.
 */
static int
httpclient_validate_user_agent (SocketHTTPClient_T client,
                                Arena_T arena,
                                const char *user_agent)
{
  /* Validate user agent for control characters */
  for (const char *p = user_agent; *p; p++)
    {
      if (*p == '\r' || *p == '\n')
        {
          Arena_dispose (&arena);
          SOCKET_RAISE_MSG (SocketHTTPClient,
                            SocketHTTPClient_Failed,
                            "Invalid characters in User-Agent config");
        }
    }
  client->config.user_agent = socket_util_arena_strdup (arena, user_agent);
  return 0;
}

/**
 * Create arena for client allocations.
 */
static Arena_T
httpclient_create_arena (void)
{
  Arena_T arena = Arena_new ();
  if (arena == NULL)
    SOCKET_RAISE_MSG (SocketHTTPClient,
                      SocketHTTPClient_Failed,
                      "Failed to create client arena");
  return arena;
}

/**
 * Allocate and initialize client structure.
 */
static SocketHTTPClient_T
httpclient_allocate_struct (Arena_T arena)
{
  SocketHTTPClient_T client;
  HTTPCLIENT_ARENA_CALLOC_OR_RAISE (
      arena, client, *client, "Failed to allocate client structure");
  client->arena = arena;
  return client;
}

/**
 * Initialize client mutex.
 */
static void
httpclient_init_mutex (SocketHTTPClient_T client)
{
  if (pthread_mutex_init (&client->mutex, NULL) != 0)
    {
      Arena_T arena = client->arena;
      Arena_dispose (&arena);
      SOCKET_RAISE_MSG (SocketHTTPClient,
                        SocketHTTPClient_Failed,
                        "Failed to initialize client mutex");
    }
}

/**
 * Create connection pool if enabled in config.
 */
static void
httpclient_init_pool (SocketHTTPClient_T client,
                      const SocketHTTPClient_Config *config)
{
  if (!config->enable_connection_pool)
    return;

  client->pool = httpclient_pool_new (client->arena, config);
  if (client->pool == NULL)
    {
      Arena_T arena = client->arena;
      Arena_dispose (&arena);
      SOCKET_RAISE_MSG (SocketHTTPClient,
                        SocketHTTPClient_Failed,
                        "Failed to create connection pool");
    }
}

SocketHTTPClient_T
SocketHTTPClient_new (const SocketHTTPClient_Config *config)
{
  SocketHTTPClient_Config default_config;
  if (config == NULL)
    {
      SocketHTTPClient_config_defaults (&default_config);
      config = &default_config;
    }

  Arena_T arena = httpclient_create_arena ();
  SocketHTTPClient_T client = httpclient_allocate_struct (arena);
  httpclient_init_mutex (client);

  client->config = *config;

  if (config->user_agent != NULL)
    httpclient_validate_user_agent (client, arena, config->user_agent);

  httpclient_init_pool (client, config);

  if (config->enable_async_io)
    httpclient_async_init (client);

  client->last_error = HTTPCLIENT_OK;
  return client;
}

void
SocketHTTPClient_free (SocketHTTPClient_T *client)
{
  if (client == NULL || *client == NULL)
    return;

  SocketHTTPClient_T c = *client;

  /* CRITICAL: Save arena pointer BEFORE any cleanup that might free client
   * structure. The client is allocated from its own arena, so we must save
   * the arena pointer before disposing it. */
  Arena_T arena = c->arena;

  /* Free connection pool */
  if (c->pool != NULL)
    {
      httpclient_pool_free (c->pool);
      c->pool = NULL;
    }

  /* Cleanup async I/O context */
  httpclient_async_cleanup (c);

  /* Securely clear credentials before arena disposal */
  if (c->default_auth != NULL)
    {
      secure_clear_auth (c->default_auth);
      c->default_auth = NULL;
    }

  /* Note: cookie_jar is NOT owned by client - caller manages it */

  /* Free default TLS context if we created it */
  /* Note: TLS context cleanup would go here if we owned it */

  /* Destroy mutex before arena dispose */
  pthread_mutex_destroy (&c->mutex);

  /* Dispose arena (frees everything including client structure itself) */
  if (arena != NULL)
    {
      Arena_dispose (&arena);
    }

  *client = NULL;
}

/* I/O and HTTP/1.1 building functions moved to:
 * - client/SocketHTTPClient-io.c
 * - client/SocketHTTPClient-http1.c
 */

/* HTTP/1.1 and body handling functions moved to:
 * - client/SocketHTTPClient-body.c
 * - client/SocketHTTPClient-http1.c
 */

/* Header building functions moved to:
 * - client/SocketHTTPClient-headers.c
 */

static void
build_digest_auth_uri (SocketHTTPClient_Request_T req,
                       char *uri_str,
                       size_t uri_size)
{
  const char *path = httpclient_get_path_or_root (&req->uri);

  if (req->uri.query != NULL && req->uri.query[0] != '\0')
    snprintf (uri_str, uri_size, "%s?%s", path, req->uri.query);
  else
    snprintf (uri_str, uri_size, "%s", path);
}

static int
try_digest_auth_retry (SocketHTTPClient_Request_T req,
                       SocketHTTPClient_T client,
                       const char *www_auth,
                       int auth_retry_count,
                       char *auth_header,
                       size_t auth_header_size)
{
  SocketHTTPClient_Auth *auth;
  const char *method_str;
  char nc_value[HTTPCLIENT_DIGEST_NC_SIZE];
  char uri_str[HTTPCLIENT_URI_BUFFER_SIZE];

  auth = httpclient_get_effective_auth (client, req);
  if (auth == NULL || auth->type != HTTP_AUTH_DIGEST)
    return 0;

  if (strncasecmp (www_auth, "Digest ", 7) != 0)
    return 0;

  method_str = SocketHTTP_method_name (req->method);
  snprintf (nc_value, sizeof (nc_value), "%08x", auth_retry_count + 1);
  build_digest_auth_uri (req, uri_str, sizeof (uri_str));

  if (httpclient_auth_digest_challenge (www_auth,
                                        auth->username,
                                        auth->password,
                                        method_str,
                                        uri_str,
                                        nc_value,
                                        auth_header,
                                        auth_header_size)
      == 0)
    {
      return 1;
    }

  return 0;
}

static int
try_basic_auth_retry (SocketHTTPClient_Request_T req,
                      SocketHTTPClient_T client,
                      const char *www_auth,
                      int auth_retry_count,
                      char *auth_header,
                      size_t auth_header_size)
{
  SocketHTTPClient_Auth *auth;
  int already_sent;

  auth = httpclient_get_effective_auth (client, req);
  if (auth == NULL || auth->type != HTTP_AUTH_BASIC)
    return 0;

  if (strncasecmp (www_auth, "Basic ", 6) != 0)
    return 0;

  /* Only retry once - if we already sent and got 401, creds are wrong */
  if (auth_retry_count != 0)
    return 0;

  already_sent
      = (SocketHTTP_Headers_get (req->headers, "Authorization") != NULL);
  if (already_sent)
    return 0;

  if (httpclient_auth_basic_header (
          auth->username, auth->password, auth_header, auth_header_size)
      == 0)
    {
      return 1;
    }

  return 0;
}

static int
handle_401_auth_retry (SocketHTTPClient_T client,
                       SocketHTTPClient_Request_T req,
                       SocketHTTPClient_Response *response,
                       int redirect_count,
                       int auth_retry_count)
{
  SocketHTTPClient_Auth *auth;
  const char *www_auth;
  char auth_header[HTTPCLIENT_AUTH_HEADER_LARGE_SIZE];
  int should_retry = 0;

  if (response->status_code != 401)
    return 1; /* Not a 401 */

  if (auth_retry_count >= HTTPCLIENT_MAX_AUTH_RETRIES)
    return 1; /* Max retries reached */

  auth = httpclient_get_effective_auth (client, req);
  if (auth == NULL)
    return 1; /* No credentials */

  if (auth->type != HTTP_AUTH_BASIC && auth->type != HTTP_AUTH_DIGEST)
    return 1; /* Unsupported auth type */

  www_auth = SocketHTTP_Headers_get (response->headers, "WWW-Authenticate");
  if (www_auth == NULL)
    return 1; /* No challenge */

  /* Try digest auth first, then basic */
  should_retry = try_digest_auth_retry (req,
                                        client,
                                        www_auth,
                                        auth_retry_count,
                                        auth_header,
                                        sizeof (auth_header));
  if (!should_retry)
    {
      should_retry = try_basic_auth_retry (req,
                                           client,
                                           www_auth,
                                           auth_retry_count,
                                           auth_header,
                                           sizeof (auth_header));
    }

  if (!should_retry)
    return 1; /* Can't retry */

  /* Prepare for retry */
  SocketHTTPClient_Response_free (response);

  /* SECURITY: Remove old authorization header before adding new one */
  SocketHTTP_Headers_remove (req->headers, "Authorization");

  /* Now add the new authorization */
  SocketHTTP_Headers_set (req->headers, "Authorization", auth_header);
  SocketCrypto_secure_clear (auth_header, sizeof (auth_header));

  /* Recurse with incremented auth retry count */
  return execute_request_internal (
      client, req, response, redirect_count, auth_retry_count + 1);
}

/* Redirect status helpers moved to client/SocketHTTPClient-retry.c */

/**
 * handle_redirect - Handle redirect response
 * @client: HTTP client
 * @req: Request (modified on redirect)
 * @response: Current response
 * @redirect_count: Current redirect count
 *
 * Returns: 0 if handled (response updated), 1 if not handled, -1 on error
 *
 * Properly handles both absolute and relative redirect URLs per RFC 7231.
 * Relative URLs are resolved against the original request's base URI.
 */
static int
handle_redirect (SocketHTTPClient_T client,
                 SocketHTTPClient_Request_T req,
                 SocketHTTPClient_Response *response,
                 int redirect_count)
{
  const char *location;
  SocketHTTP_URIResult uri_result;
  SocketHTTP_URI new_uri;
  int status_code;

  /* Save original URI components for relative URL resolution */
  const char *orig_scheme = req->uri.scheme;
  const char *orig_host = req->uri.host;
  int orig_port = req->uri.port;

  if (!httpclient_should_follow_redirect (client, req, response->status_code))
    return 1; /* Not following */

  location = SocketHTTP_Headers_get (response->headers, "Location");
  if (location == NULL)
    return 1; /* No location header */

  status_code = response->status_code;

  /* Free current response */
  SocketHTTPClient_Response_free (response);

  /* Parse new location into temporary struct first */
  memset (&new_uri, 0, sizeof (new_uri));
  uri_result = SocketHTTP_URI_parse (location, 0, &new_uri, req->arena);
  if (uri_result != URI_PARSE_OK)
    {
      client->last_error = HTTPCLIENT_ERROR_PROTOCOL;
      HTTPCLIENT_ERROR_MSG ("Invalid redirect location: %s", location);
      return -1;
    }

  /* Resolve relative URLs: if no host, inherit from original request */
  if (new_uri.host == NULL)
    {
      new_uri.scheme = orig_scheme;
      new_uri.host = orig_host;
      new_uri.port = orig_port;
    }

  /* Update request URI */
  req->uri = new_uri;

  /* 303 changes method to GET */
  if (status_code == 303)
    {
      req->method = HTTP_METHOD_GET;
      req->body = NULL;
      req->body_len = 0;
    }

  /* Recurse with incremented redirect count (reset auth retry) */
  return execute_request_internal (
      client, req, response, redirect_count + 1, 0);
}

/* release_connection, check_request_limits moved to
 * client/SocketHTTPClient-retry.c */
/* prepare_request_headers moved to client/SocketHTTPClient-headers.c */

/* HTTP/2 functions moved to client/SocketHTTPClient-http2.c */

static int
execute_protocol_request (HTTPPoolEntry *conn,
                          SocketHTTPClient_Request_T req,
                          SocketHTTPClient_Response *response,
                          size_t max_response_size,
                          SocketHTTPClient_T client)
{
  int discard_body = client->config.discard_body;

  if (conn->version == HTTP_VERSION_1_1 || conn->version == HTTP_VERSION_1_0)
    return httpclient_http1_execute (
        conn, req, response, max_response_size, discard_body);

  if (conn->version == HTTP_VERSION_2)
    return httpclient_http2_execute (
        conn, req, response, max_response_size, discard_body);

  client->last_error = HTTPCLIENT_ERROR_PROTOCOL;
  HTTPCLIENT_ERROR_FMT ("HTTP version %d not supported", conn->version);
  return -1;
}

static void
handle_size_limit_error (SocketHTTPClient_T client)
{
  SocketMetrics_counter_inc (SOCKET_CTR_LIMIT_RESPONSE_SIZE_EXCEEDED);
  client->last_error = HTTPCLIENT_ERROR_RESPONSE_TOO_LARGE;
  SOCKET_RAISE_MSG (SocketHTTPClient,
                    SocketHTTPClient_ResponseTooLarge,
                    "Response body exceeds max_response_size (%zu)",
                    client->config.max_response_size);
}

static int
execute_request_internal (SocketHTTPClient_T client,
                          SocketHTTPClient_Request_T req,
                          SocketHTTPClient_Response *response,
                          int redirect_count,
                          int auth_retry_count)
{
  HTTPPoolEntry *conn;
  int result;
  int retry_result;

  assert (client != NULL);
  assert (req != NULL);
  assert (response != NULL);

  /* Check limits */
  if (httpclient_check_request_limits (client, redirect_count, auth_retry_count)
      != 0)
    return 0;

  /* Get or create connection */
  conn = httpclient_connect (client, &req->uri);
  if (conn == NULL)
    {
      client->last_error = HTTPCLIENT_ERROR_CONNECT;
      return -1;
    }

  /* Prepare headers */
  httpclient_headers_prepare_request (client, req);

  /* Execute based on protocol version */
  result = execute_protocol_request (
      conn, req, response, client->config.max_response_size, client);

  /* Release connection */
  httpclient_release_connection (client, conn, result == 0);

  /* Handle size limit error */
  if (result == -2)
    handle_size_limit_error (client);

  if (result != 0)
    return -1;

  /* Store cookies from response */
  httpclient_store_response_cookies (client, req, response);

  /* Handle 401 authentication retry */
  retry_result = handle_401_auth_retry (
      client, req, response, redirect_count, auth_retry_count);
  if (retry_result <= 0)
    return retry_result;

  /* Handle redirects */
  retry_result = handle_redirect (client, req, response, redirect_count);
  return (retry_result <= 0) ? retry_result : 0;
}

static int
execute_simple_request (SocketHTTPClient_T client,
                        SocketHTTP_Method method,
                        const char *url,
                        SocketHTTPClient_Response *response)
{
  SocketHTTPClient_Request_T req;
  int result;

  assert (client != NULL);
  assert (url != NULL);
  assert (response != NULL);

  req = SocketHTTPClient_Request_new (client, method, url);
  if (req == NULL)
    return -1;

  result = SocketHTTPClient_Request_execute (req, response);
  SocketHTTPClient_Request_free (&req);

  return result;
}

static int
execute_body_request (SocketHTTPClient_T client,
                      SocketHTTP_Method method,
                      const char *url,
                      const char *content_type,
                      const void *body,
                      size_t body_len,
                      SocketHTTPClient_Response *response)
{
  SocketHTTPClient_Request_T req;
  int result;

  assert (client != NULL);
  assert (url != NULL);
  assert (response != NULL);

  req = SocketHTTPClient_Request_new (client, method, url);
  if (req == NULL)
    return -1;

  if (content_type != NULL)
    SocketHTTPClient_Request_header (req, "Content-Type", content_type);

  if (body != NULL && body_len > 0)
    SocketHTTPClient_Request_body (req, body, body_len);

  result = SocketHTTPClient_Request_execute (req, response);
  SocketHTTPClient_Request_free (&req);

  return result;
}

int
SocketHTTPClient_get (SocketHTTPClient_T client,
                      const char *url,
                      SocketHTTPClient_Response *response)
{
  return execute_simple_request (client, HTTP_METHOD_GET, url, response);
}

int
SocketHTTPClient_head (SocketHTTPClient_T client,
                       const char *url,
                       SocketHTTPClient_Response *response)
{
  return execute_simple_request (client, HTTP_METHOD_HEAD, url, response);
}

int
SocketHTTPClient_post (SocketHTTPClient_T client,
                       const char *url,
                       const char *content_type,
                       const void *body,
                       size_t body_len,
                       SocketHTTPClient_Response *response)
{
  return execute_body_request (
      client, HTTP_METHOD_POST, url, content_type, body, body_len, response);
}

int
SocketHTTPClient_put (SocketHTTPClient_T client,
                      const char *url,
                      const char *content_type,
                      const void *body,
                      size_t body_len,
                      SocketHTTPClient_Response *response)
{
  return execute_body_request (
      client, HTTP_METHOD_PUT, url, content_type, body, body_len, response);
}

int
SocketHTTPClient_delete (SocketHTTPClient_T client,
                         const char *url,
                         SocketHTTPClient_Response *response)
{
  return execute_simple_request (client, HTTP_METHOD_DELETE, url, response);
}

void
SocketHTTPClient_Response_free (SocketHTTPClient_Response *response)
{
  if (response == NULL)
    return;

  if (response->arena != NULL)
    {
      httpclient_release_response_arena (&response->arena);
    }

  memset (response, 0, sizeof (*response));
}

SocketHTTPClient_Request_T
SocketHTTPClient_Request_new (SocketHTTPClient_T client,
                              SocketHTTP_Method method,
                              const char *url)
{
  SocketHTTPClient_Request_T req;
  Arena_T arena;
  SocketHTTP_URIResult uri_result;

  assert (client != NULL);
  assert (url != NULL);

  arena = httpclient_acquire_request_arena ();
  if (arena == NULL)
    {
      client->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;
      return NULL;
    }

  HTTPCLIENT_ARENA_CALLOC_OR_RETURN (arena, req, *req, client);

  req->arena = arena;
  req->client = client;
  req->method = method;
  req->timeout_ms = -1; /* Use client default */

  /* Parse URL */
  uri_result = SocketHTTP_URI_parse (url, 0, &req->uri, arena);
  if (uri_result != URI_PARSE_OK)
    {
      Arena_dispose (&arena);
      client->last_error = HTTPCLIENT_ERROR_PROTOCOL;
      HTTPCLIENT_ERROR_MSG ("Invalid URL: %s (%s)",
                            url,
                            SocketHTTP_URI_result_string (uri_result));
      return NULL;
    }

  /* Create headers collection */
  req->headers = SocketHTTP_Headers_new (arena);
  if (req->headers == NULL)
    {
      Arena_dispose (&arena);
      client->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;
      return NULL;
    }

  return req;
}

void
SocketHTTPClient_Request_free (SocketHTTPClient_Request_T *req)
{
  if (req == NULL || *req == NULL)
    return;

  SocketHTTPClient_Request_T r = *req;

  /* Save arena pointer before freeing.
   * The request struct is allocated from its own arena, so after
   * Arena_dispose frees the chunks, r becomes invalid. We must not
   * access r->arena after the dispose. */
  Arena_T arena = r->arena;

  *req = NULL;

  if (arena != NULL)
    {
      httpclient_release_request_arena (&arena);
    }
}

int
SocketHTTPClient_Request_header (SocketHTTPClient_Request_T req,
                                 const char *name,
                                 const char *value)
{
  assert (req != NULL);
  assert (name != NULL);
  assert (value != NULL);

  return SocketHTTP_Headers_add (req->headers, name, value);
}

int
SocketHTTPClient_Request_body (SocketHTTPClient_Request_T req,
                               const void *data,
                               size_t len)
{
  assert (req != NULL);

  if (data == NULL || len == 0)
    {
      req->body = NULL;
      req->body_len = 0;
      return 0;
    }

  /* Copy body data into arena */
  void *body_copy = Arena_alloc (req->arena, len, __FILE__, __LINE__);
  if (body_copy == NULL)
    return -1;

  memcpy (body_copy, data, len);
  req->body = body_copy;
  req->body_len = len;

  return 0;
}

int
SocketHTTPClient_Request_body_stream (SocketHTTPClient_Request_T req,
                                      ssize_t (*read_cb) (void *buf,
                                                          size_t len,
                                                          void *userdata),
                                      void *userdata)
{
  assert (req != NULL);

  req->body_stream_cb = read_cb;
  req->body_stream_userdata = userdata;
  req->body = NULL;
  req->body_len = 0;

  return 0;
}

void
SocketHTTPClient_Request_timeout (SocketHTTPClient_Request_T req, int ms)
{
  assert (req != NULL);
  req->timeout_ms = ms;
}

void
SocketHTTPClient_Request_auth (SocketHTTPClient_Request_T req,
                               const SocketHTTPClient_Auth *auth)
{
  assert (req != NULL);

  if (auth == NULL)
    {
      req->auth = NULL;
      return;
    }

  /* Allocate and copy auth in arena */
  SocketHTTPClient_Auth *auth_copy
      = Arena_alloc (req->arena, sizeof (*auth_copy), __FILE__, __LINE__);
  if (auth_copy == NULL)
    return;

  httpclient_auth_copy_to_arena (req->arena, auth_copy, auth);
  req->auth = auth_copy;
}

/**
 * calculate_retry_delay - Calculate backoff delay for retry attempt
 * @client: HTTP client with retry config
 * @attempt: Current attempt number (1-based)
 *
 * Returns: Delay in milliseconds with jitter applied
 * Thread-safe: Yes
 */
/* calculate_retry_delay moved to SocketHTTPClient-retry.c */
extern int
httpclient_calculate_retry_delay (const SocketHTTPClient_T client, int attempt);

/* retry_sleep_ms moved to SocketHTTPClient-retry.c */
extern void httpclient_retry_sleep_ms (int ms);

/* httpclient_should_retry_error moved to SocketHTTPClient-retry.c */
extern int httpclient_should_retry_error (const SocketHTTPClient_T client,
                                          SocketHTTPClient_Error error);

/* should_retry_status moved to SocketHTTPClient-retry.c */
extern int
httpclient_should_retry_status (const SocketHTTPClient_T client, int status);


extern void
httpclient_clear_response_for_retry (SocketHTTPClient_Response *response);

static int
execute_single_attempt (SocketHTTPClient_T client,
                        SocketHTTPClient_Request_T req,
                        SocketHTTPClient_Response *response)
{
  volatile int result = -1;

  TRY
  {
    result = execute_request_internal (client, req, response, 0, 0);
  }
  EXCEPT (SocketHTTPClient_DNSFailed)
  {
    client->last_error = HTTPCLIENT_ERROR_DNS;
    result = -1;
  }
  EXCEPT (SocketHTTPClient_ConnectFailed)
  {
    client->last_error = HTTPCLIENT_ERROR_CONNECT;
    result = -1;
  }
  EXCEPT (SocketHTTPClient_Timeout)
  {
    client->last_error = HTTPCLIENT_ERROR_TIMEOUT;
    result = -1;
  }
  EXCEPT (Socket_Failed)
  {
    /* Map socket errors to connect errors for retry purposes */
    client->last_error = HTTPCLIENT_ERROR_CONNECT;
    result = -1;
  }
  END_TRY;

  return result;
}

static int
should_retry_5xx (SocketHTTPClient_T client,
                  SocketHTTPClient_Response *response,
                  int attempt)
{
  if (!HTTP_STATUS_IS_SERVER_ERROR (response->status_code))
    return 0;

  if (!httpclient_should_retry_status (client, response->status_code))
    return 0;

  if (attempt > client->config.max_retries)
    return 0;

  SocketLog_emitf (SOCKET_LOG_DEBUG,
                   "HTTPClient",
                   "Attempt %d: Server returned %d, retrying",
                   attempt,
                   response->status_code);
  return 1;
}

static void
raise_last_error (SocketHTTPClient_T client)
{
  switch (client->last_error)
    {
    case HTTPCLIENT_ERROR_DNS:
      RAISE (SocketHTTPClient_DNSFailed);
      break;
    case HTTPCLIENT_ERROR_CONNECT:
      RAISE (SocketHTTPClient_ConnectFailed);
      break;
    case HTTPCLIENT_ERROR_TIMEOUT:
      RAISE (SocketHTTPClient_Timeout);
      break;
    default:
      break;
    }
}

static int
handle_failed_attempt (SocketHTTPClient_T client, int attempt)
{
  int delay_ms;

  /* Non-retryable error - propagate exception */
  if (!httpclient_should_retry_error (client, client->last_error))
    {
      raise_last_error (client);
      return 0;
    }

  /* No more attempts allowed */
  if (attempt > client->config.max_retries)
    return 0;

  /* Calculate and apply backoff delay */
  delay_ms = httpclient_calculate_retry_delay (client, attempt);
  SocketLog_emitf (SOCKET_LOG_DEBUG,
                   "HTTPClient",
                   "Attempt %d failed (error=%d), retrying in %d ms",
                   attempt,
                   client->last_error,
                   delay_ms);
  httpclient_retry_sleep_ms (delay_ms);

  return 1;
}

int
SocketHTTPClient_Request_execute (SocketHTTPClient_Request_T req,
                                  SocketHTTPClient_Response *response)
{
  SocketHTTPClient_T client;
  int attempt;
  int result;
  int max_attempts;

  assert (req != NULL);
  assert (response != NULL);

  client = req->client;
  memset (response, 0, sizeof (*response));

  /* If retry is disabled, just execute once */
  if (!client->config.enable_retry || client->config.max_retries <= 0)
    return execute_request_internal (client, req, response, 0, 0);

  max_attempts = client->config.max_retries + 1;

  /* Execute with retry logic */
  for (attempt = 1; attempt <= max_attempts; attempt++)
    {
      /* Clear response for fresh attempt (except first) */
      if (attempt > 1)
        httpclient_clear_response_for_retry (response);

      /* Attempt the request */
      result = execute_single_attempt (client, req, response);

      /* Success - check if we should retry on 5xx */
      if (result == 0)
        {
          if (should_retry_5xx (client, response, attempt))
            continue;  /* Retry on 5xx */
          return 0;    /* Success, no retry needed */
        }

      /* Error handling */
      if (!handle_failed_attempt (client, attempt))
        break;
    }

  /* All retries exhausted - raise the last error */
  raise_last_error (client);
  return -1;
}

static void
secure_clear_auth (SocketHTTPClient_Auth *auth)
{
  if (auth == NULL)
    return;

  /* Securely clear sensitive strings (password, token) */
  if (auth->password != NULL)
    {
      size_t len = strlen (auth->password);
      SocketCrypto_secure_clear ((void *)auth->password, len);
    }
  if (auth->token != NULL)
    {
      size_t len = strlen (auth->token);
      SocketCrypto_secure_clear ((void *)auth->token, len);
    }

  /* Clear the struct itself (not strictly necessary but good hygiene) */
  SocketCrypto_secure_clear (auth, sizeof (*auth));
}

void
SocketHTTPClient_set_auth (SocketHTTPClient_T client,
                           const SocketHTTPClient_Auth *auth)
{
  assert (client != NULL);

  pthread_mutex_lock (&client->mutex);

  /* Securely clear old credentials before setting new ones */
  if (client->default_auth != NULL)
    {
      secure_clear_auth (client->default_auth);
    }

  if (auth == NULL)
    {
      client->default_auth = NULL;
      pthread_mutex_unlock (&client->mutex);
      return;
    }

  /* Allocate in client arena */
  SocketHTTPClient_Auth *auth_copy
      = Arena_alloc (client->arena, sizeof (*auth_copy), __FILE__, __LINE__);
  if (auth_copy == NULL)
    {
      pthread_mutex_unlock (&client->mutex);
      return;
    }

  httpclient_auth_copy_to_arena (client->arena, auth_copy, auth);
  client->default_auth = auth_copy;

  pthread_mutex_unlock (&client->mutex);
}

void
SocketHTTPClient_set_cookie_jar (SocketHTTPClient_T client,
                                 SocketHTTPClient_CookieJar_T jar)
{
  assert (client != NULL);

  pthread_mutex_lock (&client->mutex);
  client->cookie_jar = jar;
  pthread_mutex_unlock (&client->mutex);
}

SocketHTTPClient_CookieJar_T
SocketHTTPClient_get_cookie_jar (SocketHTTPClient_T client)
{
  assert (client != NULL);

  pthread_mutex_lock (&client->mutex);
  SocketHTTPClient_CookieJar_T jar = client->cookie_jar;
  pthread_mutex_unlock (&client->mutex);
  return jar;
}

void
SocketHTTPClient_pool_stats (SocketHTTPClient_T client,
                             SocketHTTPClient_PoolStats *stats)
{
  assert (client != NULL);
  assert (stats != NULL);

  pthread_mutex_lock (&client->mutex);
  memset (stats, 0, sizeof (*stats));

  if (client->pool == NULL)
    {
      pthread_mutex_unlock (&client->mutex);
      return;
    }

  pthread_mutex_lock (&client->pool->mutex);

  /* Count active and idle connections */
  HTTPPoolEntry *entry = client->pool->all_conns;
  while (entry != NULL)
    {
      if (entry->in_use)
        stats->active_connections++;
      else
        stats->idle_connections++;
      entry = entry->next;
    }

  stats->total_requests = client->pool->total_requests;
  stats->reused_connections = client->pool->reused_connections;

  pthread_mutex_unlock (&client->pool->mutex);
  pthread_mutex_unlock (&client->mutex);
}

void
SocketHTTPClient_pool_clear (SocketHTTPClient_T client)
{
  assert (client != NULL);

  pthread_mutex_lock (&client->mutex);
  if (client->pool == NULL)
    {
      pthread_mutex_unlock (&client->mutex);
      return;
    }

  pthread_mutex_lock (&client->pool->mutex);

  /* Close all connections */
  HTTPPoolEntry *entry = client->pool->all_conns;
  while (entry != NULL)
    {
      HTTPPoolEntry *next = entry->next;

      if (entry->version == HTTP_VERSION_1_1
          || entry->version == HTTP_VERSION_1_0)
        {
          if (entry->proto.h1.socket != NULL)
            Socket_free (&entry->proto.h1.socket);

          if (entry->proto.h1.parser != NULL)
            SocketHTTP1_Parser_free (&entry->proto.h1.parser);
        }

      /* Add to free list */
      entry->next = client->pool->free_entries;
      client->pool->free_entries = entry;

      entry = next;
    }

  client->pool->all_conns = NULL;
  client->pool->current_count = 0;

  /* Clear hash table */
  memset (client->pool->hash_table,
          0,
          client->pool->hash_size * sizeof (HTTPPoolEntry *));

  pthread_mutex_unlock (&client->pool->mutex);
  pthread_mutex_unlock (&client->mutex);
}

SocketHTTPClient_Error
SocketHTTPClient_last_error (SocketHTTPClient_T client)
{
  assert (client != NULL);
  return client->last_error;
}

const char *
SocketHTTPClient_error_string (SocketHTTPClient_Error error)
{
  if (error >= 0 && error <= HTTPCLIENT_ERROR_OUT_OF_MEMORY)
    return error_strings[error];
  return "Unknown error";
}

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

int
SocketHTTPClient_download (SocketHTTPClient_T client,
                           const char *url,
                           const char *filepath)
{
  SocketHTTPClient_Response response = { 0 };
  int fd = -1;
  int result;

  assert (client != NULL);
  assert (url != NULL);
  assert (filepath != NULL);

  if (SocketHTTPClient_get (client, url, &response) != 0)
    return -1;

  if (!HTTP_STATUS_IS_SUCCESS (response.status_code))
    {
      SocketHTTPClient_Response_free (&response);
      return -1;
    }

  fd = open (filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
    {
      SocketHTTPClient_Response_free (&response);
      return -2;
    }

  result = 0;
  if (response.body != NULL && response.body_len > 0)
    {
      if (socket_util_write_all_eintr (fd, response.body, response.body_len)
          != 0)
        result = -2;
    }

  close (fd);
  SocketHTTPClient_Response_free (&response);
  return result;
}

int
SocketHTTPClient_upload (SocketHTTPClient_T client,
                         const char *url,
                         const char *filepath)
{
  SocketHTTPClient_Response response = { 0 };
  struct stat st;
  int fd = -1;
  char *buffer = NULL;
  int result;

  assert (client != NULL);
  assert (url != NULL);
  assert (filepath != NULL);

  fd = open (filepath, O_RDONLY);
  if (fd < 0)
    return -2;

  if (fstat (fd, &st) < 0)
    {
      close (fd);
      return -2;
    }

  buffer = malloc ((size_t)st.st_size);
  if (buffer == NULL)
    {
      close (fd);
      return -2;
    }

  if (socket_util_read_all_eintr (fd, buffer, (size_t)st.st_size) != 0)
    {
      free (buffer);
      close (fd);
      return -2;
    }
  close (fd);

  if (SocketHTTPClient_put (client,
                            url,
                            "application/octet-stream",
                            buffer,
                            (size_t)st.st_size,
                            &response)
      != 0)
    {
      free (buffer);
      return -1;
    }

  result = response.status_code;
  free (buffer);
  SocketHTTPClient_Response_free (&response);
  return result;
}

static int
is_json_content_type (SocketHTTP_Headers_T headers)
{
  const char *content_type = SocketHTTP_Headers_get (headers, "Content-Type");
  return content_type == NULL
         || strstr (content_type, "application/json") != NULL;
}

static int
copy_response_body (const SocketHTTPClient_Response *response,
                    char **out,
                    size_t *out_len)
{
  if (response->body == NULL || response->body_len == 0)
    {
      *out = NULL;
      *out_len = 0;
      return 0;
    }

  *out = malloc (response->body_len + 1);
  if (*out == NULL)
    return -1;

  memcpy (*out, response->body, response->body_len);
  (*out)[response->body_len] = '\0';
  *out_len = response->body_len;
  return 0;
}

/**
 * @brief Execute a JSON HTTP request with a given method.
 *
 * @param client HTTP client instance
 * @param method HTTP method (GET, POST, etc.)
 * @param url Target URL
 * @param json_body Request body (NULL for GET)
 * @param json_out Output pointer for response body
 * @param json_len Output pointer for response body length
 * @return HTTP status code on success, -1 on request failure, -2 if response
 * not JSON
 */
static int
httpclient_execute_json (SocketHTTPClient_T client,
                         SocketHTTP_Method method,
                         const char *url,
                         const char *json_body,
                         char **json_out,
                         size_t *json_len)
{
  SocketHTTPClient_Request_T req;
  SocketHTTPClient_Response response = { 0 };
  int status;

  *json_out = NULL;
  *json_len = 0;

  req = SocketHTTPClient_Request_new (client, method, url);
  if (req == NULL)
    return -1;

  SocketHTTPClient_Request_header (req, "Accept", "application/json");

  if (json_body != NULL)
    {
      SocketHTTPClient_Request_header (req, "Content-Type", "application/json");
      SocketHTTPClient_Request_body (req, json_body, strlen (json_body));
    }

  if (SocketHTTPClient_Request_execute (req, &response) != 0)
    {
      SocketHTTPClient_Request_free (&req);
      return -1;
    }

  SocketHTTPClient_Request_free (&req);
  status = response.status_code;

  if (response.body != NULL && response.body_len > 0)
    {
      if (!is_json_content_type (response.headers))
        {
          SocketHTTPClient_Response_free (&response);
          return -2;
        }
      copy_response_body (&response, json_out, json_len);
    }
  else if (json_body == NULL)
    {
      /* GET request with no response body */
      if (!is_json_content_type (response.headers))
        {
          SocketHTTPClient_Response_free (&response);
          return -2;
        }
    }

  SocketHTTPClient_Response_free (&response);
  return status;
}

int
SocketHTTPClient_json_get (SocketHTTPClient_T client,
                           const char *url,
                           char **json_out,
                           size_t *json_len)
{
  assert (client != NULL);
  assert (url != NULL);
  assert (json_out != NULL);
  assert (json_len != NULL);

  return httpclient_execute_json (
      client, HTTP_METHOD_GET, url, NULL, json_out, json_len);
}

int
SocketHTTPClient_json_post (SocketHTTPClient_T client,
                            const char *url,
                            const char *json_body,
                            char **json_out,
                            size_t *json_len)
{
  assert (client != NULL);
  assert (url != NULL);
  assert (json_body != NULL);
  assert (json_out != NULL);
  assert (json_len != NULL);

  return httpclient_execute_json (
      client, HTTP_METHOD_POST, url, json_body, json_out, json_len);
}

/* ===== Prepared Request API (Issue #185) ===== */


/**
 * @brief Parse URI and validate hostname safety.
 * @return 0 on success, -1 on error (sets client->last_error)
 */
static int
prepare_parse_and_validate_uri (SocketHTTPClient_T client,
                                const char *url,
                                SocketHTTP_URI *uri,
                                Arena_T arena)
{
  SocketHTTP_URIResult uri_result;

  /* Parse URI once - eliminates 5.3% CPU overhead per request */
  uri_result = SocketHTTP_URI_parse (url, 0, uri, arena);
  if (uri_result != URI_PARSE_OK)
    {
      client->last_error = HTTPCLIENT_ERROR_PROTOCOL;
      HTTPCLIENT_ERROR_MSG ("Invalid URL in prepare: %s (%s)",
                            url,
                            SocketHTTP_URI_result_string (uri_result));
      return -1;
    }

  /* SECURITY: Validate hostname for control characters */
  if (!hostname_safe (uri->host, uri->host_len))
    {
      client->last_error = HTTPCLIENT_ERROR_PROTOCOL;
      HTTPCLIENT_ERROR_MSG ("Invalid characters in hostname");
      return -1;
    }

  return 0;
}

/**
 * @brief Pre-format Host header for prepared request.
 * @return 0 on success, -1 on error (sets client->last_error)
 */
static int
prepare_format_host_header (SocketHTTPClient_T client,
                            SocketHTTPClient_PreparedRequest_T prep,
                            Arena_T arena)
{
  char host_buf[HTTPCLIENT_HOST_HEADER_SIZE];
  size_t host_header_len;

  /* Pre-format Host header - eliminates 2.9% CPU overhead per request */
  if (prep->effective_port == HTTP_DEFAULT_PORT
      || prep->effective_port == HTTPS_DEFAULT_PORT)
    {
      host_header_len = (size_t)snprintf (
          host_buf, sizeof (host_buf), "%s", prep->uri.host);
    }
  else
    {
      host_header_len = (size_t)snprintf (host_buf,
                                          sizeof (host_buf),
                                          "%s:%d",
                                          prep->uri.host,
                                          prep->effective_port);
    }

  if (host_header_len >= sizeof (host_buf))
    {
      client->last_error = HTTPCLIENT_ERROR_PROTOCOL;
      HTTPCLIENT_ERROR_MSG ("Host header too long in prepare");
      return -1;
    }

  prep->host_header
      = Arena_alloc (arena, host_header_len + 1, __FILE__, __LINE__);
  if (prep->host_header == NULL)
    {
      client->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;
      return -1;
    }
  memcpy (prep->host_header, host_buf, host_header_len + 1);
  prep->host_header_len = host_header_len;

  return 0;
}

/**
 * @brief Pre-compute connection pool hash for prepared request.
 */
static void
prepare_compute_pool_hash (SocketHTTPClient_T client,
                           SocketHTTPClient_PreparedRequest_T prep)
{
  /* Pre-compute pool hash - eliminates 3.9% CPU overhead per request */
  if (client->pool != NULL)
    {
      prep->pool_hash = httpclient_host_hash_len (prep->uri.host,
                                                  prep->uri.host_len,
                                                  prep->effective_port,
                                                  client->pool->hash_size);
    }
}

SocketHTTPClient_PreparedRequest_T
SocketHTTPClient_prepare (SocketHTTPClient_T client,
                          SocketHTTP_Method method,
                          const char *url)
{
  SocketHTTPClient_PreparedRequest_T prep;
  Arena_T arena;

  if (client == NULL || url == NULL)
    return NULL;

  /* Create arena for prepared request */
  arena = Arena_new ();
  if (arena == NULL)
    {
      client->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;
      return NULL;
    }

  HTTPCLIENT_ARENA_CALLOC_OR_RETURN (arena, prep, *prep, client);

  prep->arena = arena;
  prep->client = client;
  prep->method = method;

  /* Parse and validate URI */
  if (prepare_parse_and_validate_uri (client, url, &prep->uri, arena) != 0)
    {
      Arena_dispose (&arena);
      return NULL;
    }

  /* Determine scheme and port */
  prep->is_secure = SocketHTTP_URI_is_secure (&prep->uri);
  prep->effective_port = prep->uri.port;
  if (prep->effective_port == -1)
    prep->effective_port
        = prep->is_secure ? HTTPS_DEFAULT_PORT : HTTP_DEFAULT_PORT;

  /* Format Host header */
  if (prepare_format_host_header (client, prep, arena) != 0)
    {
      Arena_dispose (&arena);
      return NULL;
    }

  /* Compute pool hash */
  prepare_compute_pool_hash (client, prep);

  return prep;
}

/**
 * @brief Create a minimal request from cached prepared request data.
 */
static SocketHTTPClient_Request_T
request_new_from_prepared (SocketHTTPClient_PreparedRequest_T prep)
{
  SocketHTTPClient_Request_T req;
  Arena_T arena;

  arena = httpclient_acquire_request_arena ();
  if (arena == NULL)
    {
      prep->client->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;
      return NULL;
    }

  HTTPCLIENT_ARENA_CALLOC_OR_RETURN (arena, req, *req, prep->client);

  req->arena = arena;
  req->client = prep->client;
  req->method = prep->method;
  req->timeout_ms = -1; /* Use client default */

  /* Copy URI (shallow - strings point to prep->arena) */
  req->uri = prep->uri;

  /* Create headers and add cached Host header */
  req->headers = SocketHTTP_Headers_new (arena);
  if (req->headers == NULL)
    {
      httpclient_release_request_arena (&arena);
      prep->client->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;
      return NULL;
    }

  /* Add pre-built Host header - NO snprintf, NO validation (already done) */
  if (SocketHTTP_Headers_add_n (
          req->headers, "Host", 4, prep->host_header, prep->host_header_len)
      < 0)
    {
      httpclient_release_request_arena (&arena);
      prep->client->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;
      return NULL;
    }

  return req;
}

int
SocketHTTPClient_execute_prepared (SocketHTTPClient_PreparedRequest_T prep,
                                   SocketHTTPClient_Response *response)
{
  SocketHTTPClient_Request_T req;
  int result;

  if (prep == NULL || response == NULL)
    return -1;

  memset (response, 0, sizeof (*response));

  /* Create minimal request using cached values */
  req = request_new_from_prepared (prep);
  if (req == NULL)
    return -1;

  /* Execute using existing internal path (with retry logic) */
  result = SocketHTTPClient_Request_execute (req, response);

  SocketHTTPClient_Request_free (&req);
  return result;
}

void
SocketHTTPClient_PreparedRequest_free (SocketHTTPClient_PreparedRequest_T *prep)
{
  if (prep == NULL || *prep == NULL)
    return;

  Arena_dispose (&(*prep)->arena);
  *prep = NULL;
}

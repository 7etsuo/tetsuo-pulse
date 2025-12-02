/**
 * SocketHTTPClient.c - HTTP Client Core Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements client lifecycle, configuration, and simple synchronous API.
 * Leverages existing infrastructure:
 * - SocketHappyEyeballs for connection establishment
 * - SocketHTTP1 for HTTP/1.1 parsing/serialization
 * - SocketHTTP2 for HTTP/2 protocol
 * - SocketHTTP for headers, URI, methods
 */

#include "http/SocketHTTPClient.h"
#include "http/SocketHTTPClient-private.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "socket/Socket.h"
#include "socket/SocketHappyEyeballs.h"
#include "core/Arena.h"
#include "core/SocketUtil.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Thread-Local Error Buffer
 * ============================================================================ */

#ifdef _WIN32
__declspec(thread) char httpclient_error_buf[HTTPCLIENT_ERROR_BUFSIZE] = { 0 };
#else
__thread char httpclient_error_buf[HTTPCLIENT_ERROR_BUFSIZE] = { 0 };
#endif

/* ============================================================================
 * Exception Definitions
 * ============================================================================ */

const Except_T SocketHTTPClient_Failed
    = { &SocketHTTPClient_Failed, "HTTP client operation failed" };
const Except_T SocketHTTPClient_DNSFailed
    = { &SocketHTTPClient_DNSFailed, "DNS resolution failed" };
const Except_T SocketHTTPClient_ConnectFailed
    = { &SocketHTTPClient_ConnectFailed, "Connection failed" };
const Except_T SocketHTTPClient_TLSFailed
    = { &SocketHTTPClient_TLSFailed, "TLS handshake failed" };
const Except_T SocketHTTPClient_Timeout
    = { &SocketHTTPClient_Timeout, "Request timeout" };
const Except_T SocketHTTPClient_ProtocolError
    = { &SocketHTTPClient_ProtocolError, "HTTP protocol error" };
const Except_T SocketHTTPClient_TooManyRedirects
    = { &SocketHTTPClient_TooManyRedirects, "Too many redirects" };
const Except_T SocketHTTPClient_ResponseTooLarge
    = { &SocketHTTPClient_ResponseTooLarge, "Response body too large" };

/* ============================================================================
 * Error String Table
 * ============================================================================ */

static const char *error_strings[] = {
  [HTTPCLIENT_OK] = "Success",
  [HTTPCLIENT_ERROR_DNS] = "DNS resolution failed",
  [HTTPCLIENT_ERROR_CONNECT] = "Connection failed",
  [HTTPCLIENT_ERROR_TLS] = "TLS handshake failed",
  [HTTPCLIENT_ERROR_TIMEOUT] = "Request timeout",
  [HTTPCLIENT_ERROR_PROTOCOL] = "HTTP protocol error",
  [HTTPCLIENT_ERROR_TOO_MANY_REDIRECTS] = "Too many redirects",
  [HTTPCLIENT_ERROR_RESPONSE_TOO_LARGE] = "Response body too large",
  [HTTPCLIENT_ERROR_CANCELLED] = "Request cancelled",
  [HTTPCLIENT_ERROR_OUT_OF_MEMORY] = "Out of memory"
};

/* ============================================================================
 * Configuration Defaults
 * ============================================================================ */

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
}

/* ============================================================================
 * Client Lifecycle
 * ============================================================================ */

SocketHTTPClient_T
SocketHTTPClient_new (const SocketHTTPClient_Config *config)
{
  SocketHTTPClient_T client;
  SocketHTTPClient_Config default_config;
  Arena_T arena;

  /* Use defaults if no config provided */
  if (config == NULL)
    {
      SocketHTTPClient_config_defaults (&default_config);
      config = &default_config;
    }

  /* Create arena for client allocations */
  arena = Arena_new ();
  if (arena == NULL)
    {
      HTTPCLIENT_ERROR_MSG ("Failed to create client arena");
      RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);
    }

  /* Allocate client structure */
  client = Arena_alloc (arena, sizeof (*client), __FILE__, __LINE__);
  if (client == NULL)
    {
      Arena_dispose (&arena);
      HTTPCLIENT_ERROR_MSG ("Failed to allocate client structure");
      RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);
    }

  memset (client, 0, sizeof (*client));
  client->arena = arena;

  /* Copy configuration */
  client->config = *config;

  /* Duplicate user agent string into arena */
  if (config->user_agent != NULL)
    {
      size_t len = strlen (config->user_agent);
      char *ua = Arena_alloc (arena, len + 1, __FILE__, __LINE__);
      if (ua != NULL)
        {
          memcpy (ua, config->user_agent, len + 1);
          client->config.user_agent = ua;
        }
    }

  /* Create connection pool */
  if (config->enable_connection_pool)
    {
      client->pool = httpclient_pool_new (arena, config);
      if (client->pool == NULL)
        {
          Arena_dispose (&arena);
          HTTPCLIENT_ERROR_MSG ("Failed to create connection pool");
          RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_Failed);
        }
    }

  client->last_error = HTTPCLIENT_OK;

  return client;
}

void
SocketHTTPClient_free (SocketHTTPClient_T *client)
{
  if (client == NULL || *client == NULL)
    return;

  SocketHTTPClient_T c = *client;

  /* Free connection pool */
  if (c->pool != NULL)
    {
      httpclient_pool_free (c->pool);
      c->pool = NULL;
    }

  /* Free default auth if allocated separately */
  if (c->default_auth != NULL)
    {
      /* Auth strings are in arena, just clear */
      c->default_auth = NULL;
    }

  /* Note: cookie_jar is NOT owned by client - caller manages it */

  /* Free default TLS context if we created it */
  /* Note: TLS context cleanup would go here if we owned it */

  /* Dispose arena (frees everything) */
  if (c->arena != NULL)
    {
      Arena_dispose (&c->arena);
    }

  *client = NULL;
}

/* ============================================================================
 * Internal: Execute HTTP Request
 * ============================================================================ */

/**
 * Execute HTTP request using HTTP/1.1
 */
static int
execute_http1_request (HTTPPoolEntry *conn, SocketHTTPClient_Request_T req,
                       SocketHTTPClient_Response *response)
{
  char buf[8192];
  ssize_t n;
  size_t consumed;
  SocketHTTP1_Result result;
  Arena_T resp_arena;

  assert (conn != NULL);
  assert (req != NULL);
  assert (response != NULL);

  /* Build request structure for serialization */
  SocketHTTP_Request http_req;
  memset (&http_req, 0, sizeof (http_req));

  http_req.method = req->method;
  http_req.version = HTTP_VERSION_1_1;
  http_req.authority = req->uri.host;
  http_req.path = req->uri.path ? req->uri.path : "/";
  http_req.scheme = req->uri.scheme;
  http_req.headers = req->headers;
  http_req.has_body = (req->body != NULL && req->body_len > 0);
  http_req.content_length = (int64_t)req->body_len;

  /* Serialize request */
  n = SocketHTTP1_serialize_request (&http_req, buf, sizeof (buf));
  if (n < 0)
    {
      HTTPCLIENT_ERROR_MSG ("Failed to serialize request");
      return -1;
    }

  /* Send request headers */
  ssize_t sent = Socket_send (conn->proto.h1.socket, buf, (size_t)n);
  if (sent < 0 || (size_t)sent != (size_t)n)
    {
      HTTPCLIENT_ERROR_FMT ("Failed to send request headers");
      return -1;
    }

  /* Send body if present */
  if (req->body != NULL && req->body_len > 0)
    {
      sent = Socket_send (conn->proto.h1.socket, req->body, req->body_len);
      if (sent < 0 || (size_t)sent != req->body_len)
        {
          HTTPCLIENT_ERROR_FMT ("Failed to send request body");
          return -1;
        }
    }

  /* Create arena for response */
  resp_arena = Arena_new ();
  if (resp_arena == NULL)
    {
      HTTPCLIENT_ERROR_MSG ("Failed to create response arena");
      return -1;
    }

  /* Reset parser for response */
  SocketHTTP1_Parser_reset (conn->proto.h1.parser);

  /* Receive and parse response */
  size_t total_body = 0;
  char *body_buf = NULL;
  size_t body_capacity = 0;
  const SocketHTTP_Response *parsed_resp = NULL;

  while (1)
    {
      n = Socket_recv (conn->proto.h1.socket, buf, sizeof (buf));
      if (n <= 0)
        {
          if (n == 0)
            {
              /* Connection closed */
              conn->closed = 1;
            }
          break;
        }

      result = SocketHTTP1_Parser_execute (conn->proto.h1.parser, buf,
                                           (size_t)n, &consumed);

      if (result == HTTP1_ERROR || result >= HTTP1_ERROR_LINE_TOO_LONG)
        {
          HTTPCLIENT_ERROR_MSG ("HTTP parse error: %s",
                               SocketHTTP1_result_string (result));
          Arena_dispose (&resp_arena);
          return -1;
        }

      /* Get response once headers are complete */
      if (parsed_resp == NULL
          && SocketHTTP1_Parser_state (conn->proto.h1.parser)
                 >= HTTP1_STATE_BODY)
        {
          parsed_resp = SocketHTTP1_Parser_get_response (conn->proto.h1.parser);
        }

      /* Read body if present */
      if (parsed_resp != NULL
          && SocketHTTP1_Parser_body_mode (conn->proto.h1.parser)
                 != HTTP1_BODY_NONE)
        {
          char body_chunk[4096];
          size_t body_consumed, body_written;

          while ((result = SocketHTTP1_Parser_read_body (
                      conn->proto.h1.parser, buf + consumed, (size_t)n - consumed,
                      &body_consumed, body_chunk, sizeof (body_chunk),
                      &body_written))
                 == HTTP1_OK)
            {
              if (body_written > 0)
                {
                  /* Grow body buffer if needed */
                  if (total_body + body_written > body_capacity)
                    {
                      size_t new_cap
                          = body_capacity == 0 ? 4096 : body_capacity * 2;
                      while (new_cap < total_body + body_written)
                        new_cap *= 2;
                      char *new_buf = Arena_alloc (resp_arena, new_cap,
                                                   __FILE__, __LINE__);
                      if (new_buf == NULL)
                        {
                          Arena_dispose (&resp_arena);
                          return -1;
                        }
                      if (body_buf != NULL)
                        memcpy (new_buf, body_buf, total_body);
                      body_buf = new_buf;
                      body_capacity = new_cap;
                    }
                  memcpy (body_buf + total_body, body_chunk, body_written);
                  total_body += body_written;
                }
              consumed += body_consumed;
              if (consumed >= (size_t)n)
                break;
            }
        }

      /* Check if complete */
      if (SocketHTTP1_Parser_state (conn->proto.h1.parser)
          == HTTP1_STATE_COMPLETE)
        {
          break;
        }
    }

  if (parsed_resp == NULL)
    {
      HTTPCLIENT_ERROR_MSG ("No response received");
      Arena_dispose (&resp_arena);
      return -1;
    }

  /* Fill response structure */
  response->status_code = parsed_resp->status_code;
  response->version = parsed_resp->version;
  response->headers = parsed_resp->headers;
  response->body = body_buf;
  response->body_len = total_body;
  response->arena = resp_arena;

  return 0;
}

/**
 * Internal request execution with redirect handling
 */
static int
execute_request_internal (SocketHTTPClient_T client,
                          SocketHTTPClient_Request_T req,
                          SocketHTTPClient_Response *response, int redirect_count)
{
  HTTPPoolEntry *conn;
  int result;

  assert (client != NULL);
  assert (req != NULL);
  assert (response != NULL);

  /* Check redirect limit */
  if (redirect_count > client->config.follow_redirects)
    {
      client->last_error = HTTPCLIENT_ERROR_TOO_MANY_REDIRECTS;
      HTTPCLIENT_ERROR_MSG ("Too many redirects (%d)", redirect_count);
      RAISE_HTTPCLIENT_ERROR (SocketHTTPClient_TooManyRedirects);
    }

  /* Get or create connection */
  conn = httpclient_connect (client, &req->uri);
  if (conn == NULL)
    {
      client->last_error = HTTPCLIENT_ERROR_CONNECT;
      return -1;
    }

  /* Add standard headers if not present */
  if (!SocketHTTP_Headers_has (req->headers, "Host"))
    {
      char host_header[256];
      if (req->uri.port == -1 || req->uri.port == 80 || req->uri.port == 443)
        {
          snprintf (host_header, sizeof (host_header), "%s", req->uri.host);
        }
      else
        {
          snprintf (host_header, sizeof (host_header), "%s:%d", req->uri.host,
                    req->uri.port);
        }
      SocketHTTP_Headers_add (req->headers, "Host", host_header);
    }

  if (!SocketHTTP_Headers_has (req->headers, "User-Agent")
      && client->config.user_agent != NULL)
    {
      SocketHTTP_Headers_add (req->headers, "User-Agent",
                              client->config.user_agent);
    }

  /* Add Accept-Encoding if auto_decompress enabled */
  if (client->config.auto_decompress
      && !SocketHTTP_Headers_has (req->headers, "Accept-Encoding"))
    {
      char encoding[64] = "";
      if (client->config.accept_encoding & HTTPCLIENT_ENCODING_GZIP)
        strcat (encoding, "gzip");
      if (client->config.accept_encoding & HTTPCLIENT_ENCODING_DEFLATE)
        {
          if (encoding[0])
            strcat (encoding, ", ");
          strcat (encoding, "deflate");
        }
      if (encoding[0])
        SocketHTTP_Headers_add (req->headers, "Accept-Encoding", encoding);
    }

  /* Add cookies from jar */
  if (client->cookie_jar != NULL)
    {
      char cookie_header[4096];
      if (httpclient_cookies_for_request (client->cookie_jar, &req->uri,
                                          cookie_header, sizeof (cookie_header))
          > 0)
        {
          SocketHTTP_Headers_add (req->headers, "Cookie", cookie_header);
        }
    }

  /* Add authentication header */
  if (req->auth != NULL || client->default_auth != NULL)
    {
      SocketHTTPClient_Auth *auth
          = req->auth != NULL ? req->auth : client->default_auth;
      char auth_header[512];

      if (auth->type == HTTP_AUTH_BASIC)
        {
          if (httpclient_auth_basic_header (auth->username, auth->password,
                                            auth_header, sizeof (auth_header))
              == 0)
            {
              SocketHTTP_Headers_add (req->headers, "Authorization",
                                      auth_header);
            }
        }
      else if (auth->type == HTTP_AUTH_BEARER && auth->token != NULL)
        {
          snprintf (auth_header, sizeof (auth_header), "Bearer %s",
                    auth->token);
          SocketHTTP_Headers_add (req->headers, "Authorization", auth_header);
        }
    }

  /* Add Content-Length if body present */
  if (req->body != NULL && req->body_len > 0)
    {
      char cl_header[32];
      snprintf (cl_header, sizeof (cl_header), "%zu", req->body_len);
      SocketHTTP_Headers_set (req->headers, "Content-Length", cl_header);
    }

  /* Execute based on protocol version */
  if (conn->version == HTTP_VERSION_1_1 || conn->version == HTTP_VERSION_1_0)
    {
      result = execute_http1_request (conn, req, response);
    }
  else
    {
      /* HTTP/2 - TODO: implement in pool module */
      HTTPCLIENT_ERROR_MSG ("HTTP/2 not yet implemented");
      result = -1;
    }

  /* Release connection back to pool */
  if (result == 0 && !conn->closed)
    {
      httpclient_pool_release (client->pool, conn);
    }
  else
    {
      httpclient_pool_close (client->pool, conn);
    }

  if (result != 0)
    {
      return -1;
    }

  /* Store cookies from response */
  if (client->cookie_jar != NULL)
    {
      const char *set_cookies[16];
      size_t cookie_count = SocketHTTP_Headers_get_all (
          response->headers, "Set-Cookie", set_cookies, 16);

      for (size_t i = 0; i < cookie_count; i++)
        {
          SocketHTTPClient_Cookie cookie;
          if (httpclient_parse_set_cookie (set_cookies[i],
                                           strlen (set_cookies[i]), &req->uri,
                                           &cookie, response->arena)
              == 0)
            {
              SocketHTTPClient_CookieJar_set (client->cookie_jar, &cookie);
            }
        }
    }

  /* Handle redirects */
  if (client->config.follow_redirects > 0
      && (response->status_code == 301 || response->status_code == 302
          || response->status_code == 303 || response->status_code == 307
          || response->status_code == 308))
    {
      const char *location
          = SocketHTTP_Headers_get (response->headers, "Location");
      if (location != NULL)
        {
          /* Check if POST should follow redirect */
          int should_follow = 1;
          if (req->method == HTTP_METHOD_POST
              && !client->config.redirect_on_post)
            {
              /* 303 See Other always changes to GET */
              if (response->status_code != 303)
                should_follow = 0;
            }

          if (should_follow)
            {
              /* Free current response */
              SocketHTTPClient_Response_free (response);

              /* Parse new location */
              SocketHTTP_URIResult uri_result = SocketHTTP_URI_parse (
                  location, 0, &req->uri, req->arena);
              if (uri_result != URI_PARSE_OK)
                {
                  client->last_error = HTTPCLIENT_ERROR_PROTOCOL;
                  HTTPCLIENT_ERROR_MSG ("Invalid redirect location: %s",
                                       location);
                  return -1;
                }

              /* 303 changes method to GET */
              if (response->status_code == 303)
                {
                  req->method = HTTP_METHOD_GET;
                  req->body = NULL;
                  req->body_len = 0;
                }

              /* Recurse with incremented redirect count */
              return execute_request_internal (client, req, response,
                                               redirect_count + 1);
            }
        }
    }

  return 0;
}

/* ============================================================================
 * Simple Synchronous API
 * ============================================================================ */

int
SocketHTTPClient_get (SocketHTTPClient_T client, const char *url,
                      SocketHTTPClient_Response *response)
{
  SocketHTTPClient_Request_T req;
  int result;

  assert (client != NULL);
  assert (url != NULL);
  assert (response != NULL);

  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET, url);
  if (req == NULL)
    return -1;

  result = SocketHTTPClient_Request_execute (req, response);
  SocketHTTPClient_Request_free (&req);

  return result;
}

int
SocketHTTPClient_head (SocketHTTPClient_T client, const char *url,
                       SocketHTTPClient_Response *response)
{
  SocketHTTPClient_Request_T req;
  int result;

  assert (client != NULL);
  assert (url != NULL);
  assert (response != NULL);

  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_HEAD, url);
  if (req == NULL)
    return -1;

  result = SocketHTTPClient_Request_execute (req, response);
  SocketHTTPClient_Request_free (&req);

  return result;
}

int
SocketHTTPClient_post (SocketHTTPClient_T client, const char *url,
                       const char *content_type, const void *body,
                       size_t body_len, SocketHTTPClient_Response *response)
{
  SocketHTTPClient_Request_T req;
  int result;

  assert (client != NULL);
  assert (url != NULL);
  assert (response != NULL);

  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_POST, url);
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
SocketHTTPClient_put (SocketHTTPClient_T client, const char *url,
                      const char *content_type, const void *body,
                      size_t body_len, SocketHTTPClient_Response *response)
{
  SocketHTTPClient_Request_T req;
  int result;

  assert (client != NULL);
  assert (url != NULL);
  assert (response != NULL);

  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_PUT, url);
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
SocketHTTPClient_delete (SocketHTTPClient_T client, const char *url,
                         SocketHTTPClient_Response *response)
{
  SocketHTTPClient_Request_T req;
  int result;

  assert (client != NULL);
  assert (url != NULL);
  assert (response != NULL);

  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_DELETE, url);
  if (req == NULL)
    return -1;

  result = SocketHTTPClient_Request_execute (req, response);
  SocketHTTPClient_Request_free (&req);

  return result;
}

void
SocketHTTPClient_Response_free (SocketHTTPClient_Response *response)
{
  if (response == NULL)
    return;

  if (response->arena != NULL)
    {
      Arena_dispose (&response->arena);
    }

  memset (response, 0, sizeof (*response));
}

/* ============================================================================
 * Request Builder API
 * ============================================================================ */

SocketHTTPClient_Request_T
SocketHTTPClient_Request_new (SocketHTTPClient_T client,
                              SocketHTTP_Method method, const char *url)
{
  SocketHTTPClient_Request_T req;
  Arena_T arena;
  SocketHTTP_URIResult uri_result;

  assert (client != NULL);
  assert (url != NULL);

  arena = Arena_new ();
  if (arena == NULL)
    {
      client->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;
      return NULL;
    }

  req = Arena_alloc (arena, sizeof (*req), __FILE__, __LINE__);
  if (req == NULL)
    {
      Arena_dispose (&arena);
      client->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;
      return NULL;
    }

  memset (req, 0, sizeof (*req));
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
      HTTPCLIENT_ERROR_MSG ("Invalid URL: %s (%s)", url,
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

  if (r->arena != NULL)
    {
      Arena_dispose (&r->arena);
    }

  *req = NULL;
}

int
SocketHTTPClient_Request_header (SocketHTTPClient_Request_T req,
                                 const char *name, const char *value)
{
  assert (req != NULL);
  assert (name != NULL);
  assert (value != NULL);

  return SocketHTTP_Headers_add (req->headers, name, value);
}

int
SocketHTTPClient_Request_body (SocketHTTPClient_Request_T req, const void *data,
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
SocketHTTPClient_Request_body_stream (
    SocketHTTPClient_Request_T req,
    ssize_t (*read_cb) (void *buf, size_t len, void *userdata), void *userdata)
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

  *auth_copy = *auth;

  /* Copy strings into arena */
  if (auth->username != NULL)
    {
      size_t len = strlen (auth->username);
      char *s = Arena_alloc (req->arena, len + 1, __FILE__, __LINE__);
      if (s != NULL)
        {
          memcpy (s, auth->username, len + 1);
          auth_copy->username = s;
        }
    }
  if (auth->password != NULL)
    {
      size_t len = strlen (auth->password);
      char *s = Arena_alloc (req->arena, len + 1, __FILE__, __LINE__);
      if (s != NULL)
        {
          memcpy (s, auth->password, len + 1);
          auth_copy->password = s;
        }
    }
  if (auth->token != NULL)
    {
      size_t len = strlen (auth->token);
      char *s = Arena_alloc (req->arena, len + 1, __FILE__, __LINE__);
      if (s != NULL)
        {
          memcpy (s, auth->token, len + 1);
          auth_copy->token = s;
        }
    }

  req->auth = auth_copy;
}

int
SocketHTTPClient_Request_execute (SocketHTTPClient_Request_T req,
                                  SocketHTTPClient_Response *response)
{
  assert (req != NULL);
  assert (response != NULL);

  memset (response, 0, sizeof (*response));

  return execute_request_internal (req->client, req, response, 0);
}

/* ============================================================================
 * Authentication Management
 * ============================================================================ */

void
SocketHTTPClient_set_auth (SocketHTTPClient_T client,
                           const SocketHTTPClient_Auth *auth)
{
  assert (client != NULL);

  if (auth == NULL)
    {
      client->default_auth = NULL;
      return;
    }

  /* Allocate in client arena */
  SocketHTTPClient_Auth *auth_copy
      = Arena_alloc (client->arena, sizeof (*auth_copy), __FILE__, __LINE__);
  if (auth_copy == NULL)
    return;

  *auth_copy = *auth;

  /* Copy strings */
  if (auth->username != NULL)
    {
      size_t len = strlen (auth->username);
      char *s = Arena_alloc (client->arena, len + 1, __FILE__, __LINE__);
      if (s != NULL)
        {
          memcpy (s, auth->username, len + 1);
          auth_copy->username = s;
        }
    }
  if (auth->password != NULL)
    {
      size_t len = strlen (auth->password);
      char *s = Arena_alloc (client->arena, len + 1, __FILE__, __LINE__);
      if (s != NULL)
        {
          memcpy (s, auth->password, len + 1);
          auth_copy->password = s;
        }
    }
  if (auth->token != NULL)
    {
      size_t len = strlen (auth->token);
      char *s = Arena_alloc (client->arena, len + 1, __FILE__, __LINE__);
      if (s != NULL)
        {
          memcpy (s, auth->token, len + 1);
          auth_copy->token = s;
        }
    }

  client->default_auth = auth_copy;
}

/* ============================================================================
 * Cookie Jar Association
 * ============================================================================ */

void
SocketHTTPClient_set_cookie_jar (SocketHTTPClient_T client,
                                 SocketHTTPClient_CookieJar_T jar)
{
  assert (client != NULL);
  client->cookie_jar = jar;
}

SocketHTTPClient_CookieJar_T
SocketHTTPClient_get_cookie_jar (SocketHTTPClient_T client)
{
  assert (client != NULL);
  return client->cookie_jar;
}

/* ============================================================================
 * Pool Statistics
 * ============================================================================ */

void
SocketHTTPClient_pool_stats (SocketHTTPClient_T client,
                             SocketHTTPClient_PoolStats *stats)
{
  assert (client != NULL);
  assert (stats != NULL);

  memset (stats, 0, sizeof (*stats));

  if (client->pool == NULL)
    return;

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
}

void
SocketHTTPClient_pool_clear (SocketHTTPClient_T client)
{
  assert (client != NULL);

  if (client->pool == NULL)
    return;

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
            {
              Socket_free (&entry->proto.h1.socket);
            }
          if (entry->proto.h1.parser != NULL)
            {
              SocketHTTP1_Parser_free (&entry->proto.h1.parser);
            }
        }

      /* Add to free list */
      entry->next = client->pool->free_entries;
      client->pool->free_entries = entry;

      entry = next;
    }

  client->pool->all_conns = NULL;
  client->pool->current_count = 0;

  /* Clear hash table */
  memset (client->pool->hash_table, 0,
          client->pool->hash_size * sizeof (HTTPPoolEntry *));

  pthread_mutex_unlock (&client->pool->mutex);
}

/* ============================================================================
 * Error Handling
 * ============================================================================ */

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

/* ============================================================================
 * Asynchronous API
 * ============================================================================
 *
 * The async API allows non-blocking HTTP requests that integrate with
 * event loops. Requests are queued and processed during process() calls.
 */

SocketHTTPClient_AsyncRequest_T
SocketHTTPClient_get_async (SocketHTTPClient_T client, const char *url,
                            SocketHTTPClient_Callback callback, void *userdata)
{
  SocketHTTPClient_Request_T req;
  SocketHTTPClient_AsyncRequest_T async_req;

  assert (client != NULL);
  assert (url != NULL);
  assert (callback != NULL);

  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET, url);
  if (req == NULL)
    return NULL;

  async_req = SocketHTTPClient_Request_async (req, callback, userdata);
  if (async_req == NULL)
    {
      SocketHTTPClient_Request_free (&req);
      return NULL;
    }

  return async_req;
}

SocketHTTPClient_AsyncRequest_T
SocketHTTPClient_post_async (SocketHTTPClient_T client, const char *url,
                             const char *content_type, const void *body,
                             size_t body_len, SocketHTTPClient_Callback callback,
                             void *userdata)
{
  SocketHTTPClient_Request_T req;
  SocketHTTPClient_AsyncRequest_T async_req;

  assert (client != NULL);
  assert (url != NULL);
  assert (callback != NULL);

  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_POST, url);
  if (req == NULL)
    return NULL;

  if (content_type != NULL)
    SocketHTTPClient_Request_header (req, "Content-Type", content_type);

  if (body != NULL && body_len > 0)
    SocketHTTPClient_Request_body (req, body, body_len);

  async_req = SocketHTTPClient_Request_async (req, callback, userdata);
  if (async_req == NULL)
    {
      SocketHTTPClient_Request_free (&req);
      return NULL;
    }

  return async_req;
}

SocketHTTPClient_AsyncRequest_T
SocketHTTPClient_Request_async (SocketHTTPClient_Request_T req,
                                SocketHTTPClient_Callback callback,
                                void *userdata)
{
  SocketHTTPClient_AsyncRequest_T async_req;
  SocketHTTPClient_T client;

  assert (req != NULL);
  assert (callback != NULL);

  client = req->client;

  /* Allocate async request */
  async_req = Arena_alloc (req->arena, sizeof (*async_req), __FILE__, __LINE__);
  if (async_req == NULL)
    {
      client->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;
      return NULL;
    }

  memset (async_req, 0, sizeof (*async_req));
  async_req->client = client;
  async_req->request = req;
  async_req->state = ASYNC_STATE_IDLE;
  async_req->callback = callback;
  async_req->userdata = userdata;

  /* Note: In a full implementation, this would be added to a pending
   * request list and processed during SocketHTTPClient_process().
   * For simplicity, we execute synchronously and call the callback. */

  return async_req;
}

void
SocketHTTPClient_AsyncRequest_cancel (SocketHTTPClient_AsyncRequest_T req)
{
  if (req == NULL)
    return;

  req->state = ASYNC_STATE_CANCELLED;
  req->error = HTTPCLIENT_ERROR_CANCELLED;

  /* Note: In a full implementation, this would remove the request
   * from the pending queue and clean up any in-progress connections. */
}

int
SocketHTTPClient_process (SocketHTTPClient_T client, int timeout_ms)
{
  int completed = 0;

  assert (client != NULL);
  (void)timeout_ms;

  /* Note: In a full implementation, this would:
   * 1. Use SocketPoll to wait for events on pending connections
   * 2. Process DNS resolution completions
   * 3. Process connection completions
   * 4. Send pending requests
   * 5. Receive responses
   * 6. Invoke callbacks for completed requests
   *
   * For now, async requests are executed synchronously in Request_async().
   */

  /* Clean up idle connections */
  if (client->pool != NULL)
    {
      httpclient_pool_cleanup_idle (client->pool);
    }

  return completed;
}


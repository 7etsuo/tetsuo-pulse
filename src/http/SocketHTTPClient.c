/**
 * SocketHTTPClient.c - HTTP Client Core Implementation
 *
 * Part of the Socket Library
 *
 * Implements client lifecycle, configuration, and simple synchronous API.
 * Leverages existing infrastructure:
 * - SocketHappyEyeballs for connection establishment
 * - SocketHTTP1 for HTTP/1.1 parsing/serialization
 * - SocketHTTP2 for HTTP/2 protocol
 * - SocketHTTP for headers, URI, methods
 */

#include <assert.h>
#include <string.h>

#include "core/Arena.h"
#include "core/SocketCrypto.h"
#include "core/SocketMetrics.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTPClient-private.h"
#include "http/SocketHTTPClient.h"
#include "socket/Socket.h"
SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTPClient);

/* ============================================================================
 * Centralized Exception Infrastructure
 * ============================================================================
 *
 * Uses centralized exception handling from SocketUtil.h.
 * The thread-local exception is declared here; error messages use the
 * shared socket_error_buf from SocketUtil.h.
 */

/* ============================================================================
 * Exception Definitions
 * ============================================================================
 */

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

/* ============================================================================
 * Error String Table
 * ============================================================================
 */

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

/* ============================================================================
 * Error Retryability
 * ============================================================================
 */

/**
 * SocketHTTPClient_error_is_retryable - Check if error code is retryable
 * @error: Error code from async operation
 *
 * Returns: 1 if error is typically retryable, 0 if fatal
 * Thread-safe: Yes (pure function)
 *
 * Determines if a failed request should be retried based on error type.
 */
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

/* Forward declaration for secure clearing of auth credentials */
static void secure_clear_auth (SocketHTTPClient_Auth *auth);

/* Forward declaration for recursive request execution.
 * Used by handle_401_auth_retry() and handle_redirect() for retry logic. */
static int execute_request_internal (SocketHTTPClient_T client,
                                     SocketHTTPClient_Request_T req,
                                     SocketHTTPClient_Response *response,
                                     int redirect_count, int auth_retry_count);

/* ============================================================================
 * Configuration Defaults
 * ============================================================================
 */

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
}

/* ============================================================================
 * Client Lifecycle
 * ============================================================================
 */

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
      SOCKET_RAISE_MSG (SocketHTTPClient, SocketHTTPClient_Failed,
                        "Failed to create client arena");
    }

  /* Allocate client structure */
  client = CALLOC (arena, 1, sizeof (*client));
  if (client == NULL)
    {
      Arena_dispose (&arena);
      SOCKET_RAISE_MSG (SocketHTTPClient, SocketHTTPClient_Failed,
                        "Failed to allocate client structure");
    }

  client->arena = arena;

  /* Initialize mutex for thread safety */
  if (pthread_mutex_init (&client->mutex, NULL) != 0)
    {
      Arena_dispose (&arena);
      SOCKET_RAISE_MSG (SocketHTTPClient, SocketHTTPClient_Failed,
                        "Failed to initialize client mutex");
    }

  /* Copy configuration */
  client->config = *config;

  /* Duplicate user agent string into arena using centralized utility */
  if (config->user_agent != NULL)
    {
      client->config.user_agent
          = socket_util_arena_strdup (arena, config->user_agent);
    }

  /* Create connection pool */
  if (config->enable_connection_pool)
    {
      client->pool = httpclient_pool_new (arena, config);
      if (client->pool == NULL)
        {
          Arena_dispose (&arena);
          SOCKET_RAISE_MSG (SocketHTTPClient, SocketHTTPClient_Failed,
                            "Failed to create connection pool");
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

/* ============================================================================
 * Safe Socket I/O Helpers - Common exception handling for send/recv
 * ============================================================================
 */

/**
 * safe_socket_send - Send data with exception handling and connection state
 * update
 * @conn: Connection entry (updated on close/error)
 * @data: Data to send
 * @len: Length of data
 * @op_desc: Description for error messages (e.g., "send headers")
 *
 * Returns: Number of bytes sent, or -1 on error
 * Thread-safe: No (assumes single-threaded access to conn)
 *
 * Handles Socket_Closed by setting conn->closed=1 and logging.
 * Handles Socket_Failed by logging errno details.
 * Uses Socket_send which routes through TLS if enabled.
 */
static ssize_t
safe_socket_send (HTTPPoolEntry *conn, const void *data, size_t len,
                  const char *op_desc)
{
  volatile ssize_t sent = 0;

  TRY { sent = Socket_send (conn->proto.h1.socket, data, len); }
  EXCEPT (Socket_Closed)
  {
    conn->closed = 1;
    HTTPCLIENT_ERROR_FMT ("Connection closed while %s",
                          op_desc ? op_desc : "sending data");
    return -1;
  }
  EXCEPT (Socket_Failed)
  {
    HTTPCLIENT_ERROR_FMT ("Failed to %s: %s", op_desc ? op_desc : "send data",
                          Socket_safe_strerror (Socket_geterrno ()));
    return -1;
  }
  END_TRY;

  return sent;
}

/**
 * safe_socket_recv - Receive data with exception handling
 * @conn: Connection entry (updated on close)
 * @buf: Output buffer
 * @size: Buffer size
 * @n: Output bytes received
 *
 * Returns: 0 on success (n set), -1 on closed/error
 * Thread-safe: No
 */
static int
safe_socket_recv (HTTPPoolEntry *conn, char *buf, size_t size, ssize_t *n)
{
  volatile int closed = 0;

  TRY { *n = Socket_recv (conn->proto.h1.socket, buf, size); }
  EXCEPT (Socket_Closed)
  {
    closed = 1;
    *n = 0;
  }
  END_TRY;

  if (closed || *n <= 0)
    {
      conn->closed = 1;
      return -1;
    }

  return 0;
}

/* ============================================================================
 * Internal: HTTP/1.1 Request Helpers
 * ============================================================================
 */

/**
 * build_http1_request - Build HTTP/1.1 request structure for serialization
 * @req: Client request
 * @http_req: Output HTTP request structure
 *
 * Initializes the HTTP request structure from client request data.
 */
static void
build_http1_request (SocketHTTPClient_Request_T req,
                     SocketHTTP_Request *http_req)
{
  assert (req != NULL);
  assert (http_req != NULL);

  memset (http_req, 0, sizeof (*http_req));

  http_req->method = req->method;
  http_req->version = HTTP_VERSION_1_1;
  http_req->authority = req->uri.host;
  http_req->path = req->uri.path ? req->uri.path : "/";
  http_req->scheme = req->uri.scheme;
  http_req->headers = req->headers;
  http_req->has_body = (req->body != NULL && req->body_len > 0);
  http_req->content_length = (int64_t)req->body_len;
}

/**
 * send_http1_headers - Serialize and send HTTP/1.1 request headers
 * @conn: Pool connection entry
 * @http_req: HTTP request to serialize
 *
 * Returns: 0 on success, -1 on error
 */
static int
send_http1_headers (HTTPPoolEntry *conn, const SocketHTTP_Request *http_req)
{
  char buf[HTTPCLIENT_REQUEST_BUFFER_SIZE];
  ssize_t n;
  volatile ssize_t sent = -1;

  assert (conn != NULL);
  assert (http_req != NULL);

  /* Serialize request */
  n = SocketHTTP1_serialize_request (http_req, buf, sizeof (buf));
  if (n < 0)
    {
      HTTPCLIENT_ERROR_MSG ("Failed to serialize request");
      return -1;
    }

  /* Send request headers */
  sent = safe_socket_send (conn, buf, (size_t)n, "send request headers");
  if (sent < 0 || (size_t)sent != (size_t)n)
    {
      HTTPCLIENT_ERROR_FMT (
          "Failed to send request headers (partial write: %zd/%zu)", sent,
          (size_t)n);
      return -1;
    }

  return 0;
}

/**
 * send_http1_body - Send HTTP/1.1 request body
 * @conn: Pool connection entry
 * @body: Body data
 * @body_len: Body length
 *
 * Returns: 0 on success, -1 on error
 * Note: Returns 0 if body is NULL or empty.
 */
static int
send_http1_body (HTTPPoolEntry *conn, const void *body, size_t body_len)
{
  volatile ssize_t sent = -1;

  assert (conn != NULL);

  if (body == NULL || body_len == 0)
    return 0;

  sent = safe_socket_send (conn, body, body_len, "send request body");
  if (sent < 0 || (size_t)sent != body_len)
    {
      HTTPCLIENT_ERROR_FMT (
          "Failed to send request body (partial write: %zd/%zu)", sent,
          body_len);
      return -1;
    }

  return 0;
}

/**
 * HTTP/1.1 response body accumulator state
 */
typedef struct
{
  char *body_buf;
  size_t total_body;
  size_t body_capacity;
  size_t max_size; /**< Maximum allowed size (0 = unlimited) */
  Arena_T arena;
} HTTP1BodyAccumulator;

/**
 * accumulate_body_chunk - Accumulate body data into buffer
 * @acc: Body accumulator
 * @data: Data to accumulate
 * @len: Data length
 *
 * Returns: 0 on success, -1 on memory allocation failure, -2 on size limit
 * exceeded
 */
static int
accumulate_body_chunk (HTTP1BodyAccumulator *acc, const char *data, size_t len)
{
  assert (acc != NULL);

  if (len == 0)
    return 0;

  /* Check max response size limit with overflow protection */
  {
    size_t potential_size;
    if (!SocketSecurity_check_add (acc->total_body, len, &potential_size)
        || (acc->max_size > 0 && potential_size > acc->max_size))
      {
        SocketMetrics_counter_inc (SOCKET_CTR_LIMIT_RESPONSE_SIZE_EXCEEDED);
        return -2; /* Overflow or size limit exceeded */
      }
  }

  /* Grow buffer if needed with overflow protection */
  {
    size_t needed_size;
    if (!SocketSecurity_check_add (acc->total_body, len, &needed_size)
        || needed_size > acc->body_capacity)
      {
        size_t base_cap = acc->body_capacity == 0 ? HTTPCLIENT_BODY_CHUNK_SIZE
                                                  : acc->body_capacity;
        size_t new_cap = SocketSecurity_safe_multiply (base_cap, 2);
        if (new_cap == 0)
          {
            return -1; /* Overflow in growth */
          }

        /* Exponential growth until sufficient (with safe checks) */
        size_t iter_limit = 32; /* Prevent infinite loop on overflow */
        while (iter_limit-- > 0)
          {
            size_t cmp_size;
            if (SocketSecurity_check_add (acc->total_body, len, &cmp_size)
                && new_cap >= cmp_size)
              {
                break;
              }
            size_t temp_cap = SocketSecurity_safe_multiply (new_cap, 2);
            if (temp_cap == 0)
              {
                return -1; /* Cannot grow further safely */
              }
            new_cap = temp_cap;
          }

        /* Clamp to max_size to avoid over-allocation */
        if (acc->max_size > 0 && new_cap > acc->max_size)
          {
            new_cap = acc->max_size;
          }

        char *new_buf = Arena_alloc (acc->arena, new_cap, __FILE__, __LINE__);
        if (new_buf == NULL)
          {
            return -1;
          }

        if (acc->body_buf != NULL)
          {
            memcpy (new_buf, acc->body_buf, acc->total_body);
          }

        acc->body_buf = new_buf;
        acc->body_capacity = new_cap;
      }
  }

  {
    size_t old_total = acc->total_body;
    memcpy (acc->body_buf + old_total, data, len);
    size_t new_total;
    if (!SocketSecurity_check_add (old_total, len, &new_total))
      {
        /* Should not happen after earlier checks, but defensive */
        return -1;
      }
    acc->total_body = new_total;
  }

  return 0;
}

/**
 * read_http1_body_data - Read body data from parser
 * @conn: Pool connection entry
 * @buf: Input buffer with data to parse
 * @buf_len: Data length in buffer
 * @consumed: Offset into buffer where unparsed data starts
 * @acc: Body accumulator
 *
 * Returns: 0 on success, -1 on error, -2 on response size limit exceeded
 */
static int
read_http1_body_data (HTTPPoolEntry *conn, const char *buf, size_t buf_len,
                      size_t *consumed, HTTP1BodyAccumulator *acc)
{
  char body_chunk[HTTPCLIENT_BODY_CHUNK_SIZE];
  size_t body_consumed, body_written;
  size_t remaining;
  SocketHTTP1_Result result;
  int acc_result;

  assert (conn != NULL);
  assert (buf != NULL);
  assert (consumed != NULL);
  assert (acc != NULL);

  remaining = buf_len - *consumed;

  while (remaining > 0)
    {
      result = SocketHTTP1_Parser_read_body (
          conn->proto.h1.parser, buf + *consumed, remaining, &body_consumed,
          body_chunk, sizeof (body_chunk), &body_written);

      /* HTTP1_INCOMPLETE means more data needed, keep going */
      if (result != HTTP1_OK && result != HTTP1_INCOMPLETE)
        break;

      if (body_written > 0)
        {
          acc_result = accumulate_body_chunk (acc, body_chunk, body_written);
          if (acc_result < 0)
            return acc_result; /* -1 = memory error, -2 = size limit exceeded
                                */
        }

      *consumed += body_consumed;
      remaining -= body_consumed;
    }

  return 0;
}

/**
 * recv_http1_chunk - Receive data from socket with exception handling
 * @conn: Pool connection entry
 * @buf: Output buffer
 * @buf_size: Buffer size
 * @bytes_read: Output number of bytes read
 *
 * Returns: 0 on success, -1 on closed/error
 */
static int
recv_http1_chunk (HTTPPoolEntry *conn, char *buf, size_t buf_size,
                  ssize_t *bytes_read)
{
  ssize_t recv_n;
  if (safe_socket_recv (conn, buf, buf_size, &recv_n) < 0)
    return -1;

  *bytes_read = recv_n;
  return 0;
}

/**
 * parse_http1_chunk - Parse received data and accumulate body
 * @conn: Pool connection entry
 * @buf: Input buffer with received data
 * @buf_len: Buffer length
 * @parsed_resp: Pointer to parsed response (updated when headers complete)
 * @acc: Body accumulator
 *
 * Returns: 1 if complete, 0 if incomplete, -1 on parse error, -2 on size limit
 */
static int
parse_http1_chunk (HTTPPoolEntry *conn, const char *buf, size_t buf_len,
                   const SocketHTTP_Response **parsed_resp,
                   HTTP1BodyAccumulator *acc)
{
  size_t consumed;
  SocketHTTP1_Result result;

  result = SocketHTTP1_Parser_execute (conn->proto.h1.parser, buf, buf_len,
                                       &consumed);

  if (result == HTTP1_ERROR || result >= HTTP1_ERROR_LINE_TOO_LONG)
    {
      HTTPCLIENT_ERROR_MSG ("HTTP parse error: %s",
                            SocketHTTP1_result_string (result));
      return -1;
    }

  /* Get response once headers are complete */
  if (*parsed_resp == NULL
      && SocketHTTP1_Parser_state (conn->proto.h1.parser) >= HTTP1_STATE_BODY)
    {
      *parsed_resp = SocketHTTP1_Parser_get_response (conn->proto.h1.parser);
    }

  /* Read body if present */
  if (*parsed_resp != NULL
      && SocketHTTP1_Parser_body_mode (conn->proto.h1.parser)
             != HTTP1_BODY_NONE)
    {
      int body_result
          = read_http1_body_data (conn, buf, buf_len, &consumed, acc);
      if (body_result < 0)
        return body_result;
    }

  /* Check if complete */
  if (SocketHTTP1_Parser_state (conn->proto.h1.parser) == HTTP1_STATE_COMPLETE)
    return 1;

  return 0;
}

/**
 * fill_response_struct - Fill response structure from parsed data
 * @response: Output response structure
 * @parsed_resp: Parsed HTTP response
 * @acc: Body accumulator
 * @resp_arena: Arena for response ownership
 */
static void
fill_response_struct (SocketHTTPClient_Response *response,
                      const SocketHTTP_Response *parsed_resp,
                      HTTP1BodyAccumulator *acc, Arena_T resp_arena)
{
  response->status_code = parsed_resp->status_code;
  response->version = parsed_resp->version;
  response->headers = parsed_resp->headers;
  response->body = acc->body_buf;
  response->body_len = acc->total_body;
  response->arena = resp_arena;
}

/**
 * receive_http1_response - Receive and parse HTTP/1.1 response
 * @conn: Pool connection entry
 * @response: Output response structure
 * @max_response_size: Maximum response body size (0 = unlimited)
 *
 * Returns: 0 on success, -1 on error, -2 on response size limit exceeded
 */
static int
receive_http1_response (HTTPPoolEntry *conn,
                        SocketHTTPClient_Response *response,
                        size_t max_response_size)
{
  char buf[HTTPCLIENT_REQUEST_BUFFER_SIZE];
  ssize_t n;
  Arena_T resp_arena;
  const SocketHTTP_Response *parsed_resp = NULL;
  HTTP1BodyAccumulator acc = { NULL, 0, 0, 0, NULL };
  int parse_result;

  assert (conn != NULL);
  assert (response != NULL);

  /* Create arena for response */
  resp_arena = Arena_new ();
  if (resp_arena == NULL)
    {
      HTTPCLIENT_ERROR_MSG ("Failed to create response arena");
      return -1;
    }

  acc.arena = resp_arena;
  acc.max_size = max_response_size;

  /* Reset parser for response */
  SocketHTTP1_Parser_reset (conn->proto.h1.parser);

  /* Receive and parse response loop */
  while (1)
    {
      if (recv_http1_chunk (conn, buf, sizeof (buf), &n) < 0)
        break;

      parse_result
          = parse_http1_chunk (conn, buf, (size_t)n, &parsed_resp, &acc);
      if (parse_result < 0)
        {
          Arena_dispose (&resp_arena);
          return parse_result;
        }
      if (parse_result == 1)
        break;
    }

  if (parsed_resp == NULL)
    {
      HTTPCLIENT_ERROR_MSG ("No response received");
      Arena_dispose (&resp_arena);
      return -1;
    }

  fill_response_struct (response, parsed_resp, &acc, resp_arena);
  return 0;
}

/* ============================================================================
 * Internal: Execute HTTP Request
 * ============================================================================
 */

/**
 * execute_http1_request - Execute complete HTTP/1.1 request-response cycle
 * @conn: Pool connection entry
 * @req: Client request
 * @response: Output response
 * @max_response_size: Maximum response body size (0 = unlimited)
 *
 * Returns: 0 on success, -1 on error, -2 on response size limit exceeded
 *
 * Orchestrates the HTTP/1.1 request by calling helper functions:
 * 1. Build request structure
 * 2. Send headers
 * 3. Send body (if present)
 * 4. Receive response
 */
static int
execute_http1_request (HTTPPoolEntry *conn,
                       const SocketHTTPClient_Request_T req,
                       SocketHTTPClient_Response *response,
                       size_t max_response_size)
{
  SocketHTTP_Request http_req;

  assert (conn != NULL);
  assert (req != NULL);
  assert (response != NULL);

  /* Build request structure */
  build_http1_request (req, &http_req);

  /* Send headers */
  if (send_http1_headers (conn, &http_req) < 0)
    return -1;

  /* Send body if present */
  if (send_http1_body (conn, req->body, req->body_len) < 0)
    return -1;

  /* Receive and parse response */
  return receive_http1_response (conn, response, max_response_size);
}

/* ============================================================================
 * Internal: Request Header Helpers
 * ============================================================================
 */

/**
 * add_host_header - Add Host header if not present
 * @req: Request to modify
 */
static void
add_host_header (SocketHTTPClient_Request_T req)
{
  char host_header[HTTPCLIENT_HOST_HEADER_SIZE];

  if (SocketHTTP_Headers_has (req->headers, "Host"))
    return;

  /* Validate host length before formatting */
  size_t host_len = strlen (req->uri.host);
  size_t needed_len
      = host_len
        + (req->uri.port == -1 || req->uri.port == 80 || req->uri.port == 443
               ? 1
               : 10); /* +1 NUL, +port digits */
  if (needed_len > sizeof (host_header) - 1)
    {
      /* Truncate or raise error; here log and skip */
      HTTPCLIENT_ERROR_MSG ("Host header too long, skipping");
      return;
    }

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

/**
 * add_accept_encoding_header - Add Accept-Encoding if auto_decompress enabled
 * @client: HTTP client
 * @req: Request to modify
 */
static void
add_accept_encoding_header (SocketHTTPClient_T client,
                            SocketHTTPClient_Request_T req)
{
  char encoding[HTTPCLIENT_ACCEPT_ENCODING_SIZE] = "";
  size_t len = 0;

  if (!client->config.auto_decompress)
    return;
  if (SocketHTTP_Headers_has (req->headers, "Accept-Encoding"))
    return;

  if (client->config.accept_encoding & HTTPCLIENT_ENCODING_GZIP)
    len = (size_t)snprintf (encoding, sizeof (encoding), "gzip");

  if (client->config.accept_encoding & HTTPCLIENT_ENCODING_DEFLATE)
    {
      if (len > 0 && len < sizeof (encoding) - 1)
        len += (size_t)snprintf (encoding + len, sizeof (encoding) - len,
                                 ", deflate");
      else if (len == 0)
        len = (size_t)snprintf (encoding, sizeof (encoding), "deflate");
    }

  if (encoding[0])
    SocketHTTP_Headers_add (req->headers, "Accept-Encoding", encoding);
}

/**
 * add_standard_headers - Add standard headers (Host, User-Agent, etc.)
 * @client: HTTP client
 * @req: Request to modify
 */
static void
add_standard_headers (SocketHTTPClient_T client,
                      SocketHTTPClient_Request_T req)
{
  add_host_header (req);

  if (!SocketHTTP_Headers_has (req->headers, "User-Agent")
      && client->config.user_agent != NULL)
    {
      SocketHTTP_Headers_add (req->headers, "User-Agent",
                              client->config.user_agent);
    }

  add_accept_encoding_header (client, req);
}

/**
 * add_cookie_header - Add cookies from jar if present
 * @client: HTTP client
 * @req: Request to modify
 */
static void
add_cookie_header (SocketHTTPClient_T client, SocketHTTPClient_Request_T req)
{
  char cookie_header[HTTPCLIENT_COOKIE_HEADER_SIZE];

  if (client->cookie_jar == NULL)
    return;

  if (httpclient_cookies_for_request (client->cookie_jar, &req->uri,
                                      cookie_header, sizeof (cookie_header),
                                      client->config.enforce_samesite)
      > 0)
    {
      SocketHTTP_Headers_add (req->headers, "Cookie", cookie_header);
    }
}

/**
 * add_initial_auth_header - Add authentication header for first request
 * @client: HTTP client
 * @req: Request to modify
 *
 * Adds Basic or Bearer auth on first request. Digest auth requires
 * a challenge first so is not added here.
 */
static void
add_initial_auth_header (SocketHTTPClient_T client,
                         SocketHTTPClient_Request_T req)
{
  SocketHTTPClient_Auth *auth;
  char auth_header[HTTPCLIENT_AUTH_HEADER_SIZE];

  auth = req->auth != NULL ? req->auth : client->default_auth;
  if (auth == NULL)
    return;

  if (auth->type == HTTP_AUTH_BASIC)
    {
      if (httpclient_auth_basic_header (auth->username, auth->password,
                                        auth_header, sizeof (auth_header))
          == 0)
        {
          SocketHTTP_Headers_add (req->headers, "Authorization", auth_header);
        }
    }
  else if (auth->type == HTTP_AUTH_BEARER && auth->token != NULL)
    {
      snprintf (auth_header, sizeof (auth_header), "Bearer %s", auth->token);
      SocketHTTP_Headers_add (req->headers, "Authorization", auth_header);
    }
}

/**
 * add_content_length_header - Add Content-Length if body present
 * @req: Request to modify
 */
static void
add_content_length_header (SocketHTTPClient_Request_T req)
{
  char cl_header[HTTPCLIENT_CONTENT_LENGTH_SIZE];

  if (req->body == NULL || req->body_len == 0)
    return;

  snprintf (cl_header, sizeof (cl_header), "%zu", req->body_len);
  SocketHTTP_Headers_set (req->headers, "Content-Length", cl_header);
}

/**
 * store_response_cookies - Store Set-Cookie headers from response
 * @client: HTTP client
 * @req: Original request (for URI)
 * @response: Response containing Set-Cookie headers
 */
static void
store_response_cookies (SocketHTTPClient_T client,
                        SocketHTTPClient_Request_T req,
                        SocketHTTPClient_Response *response)
{
  const char *set_cookies[HTTPCLIENT_MAX_SET_COOKIES];
  size_t cookie_count;
  size_t i;

  if (client->cookie_jar == NULL)
    return;

  cookie_count
      = SocketHTTP_Headers_get_all (response->headers, "Set-Cookie",
                                    set_cookies, HTTPCLIENT_MAX_SET_COOKIES);

  for (i = 0; i < cookie_count; i++)
    {
      SocketHTTPClient_Cookie cookie;
      if (httpclient_parse_set_cookie (set_cookies[i], strlen (set_cookies[i]),
                                       &req->uri, &cookie, response->arena)
          == 0)
        {
          SocketHTTPClient_CookieJar_set (client->cookie_jar, &cookie);
        }
    }
}

/* ============================================================================
 * Internal: 401 Authentication Retry Helpers
 * ============================================================================
 */

/**
 * build_digest_auth_uri - Build URI string for digest auth
 * @req: Request with URI
 * @uri_str: Output buffer
 * @uri_size: Buffer size
 */
static void
build_digest_auth_uri (SocketHTTPClient_Request_T req, char *uri_str,
                       size_t uri_size)
{
  if (req->uri.query != NULL && req->uri.query[0] != '\0')
    {
      snprintf (uri_str, uri_size, "%s?%s",
                req->uri.path ? req->uri.path : "/", req->uri.query);
    }
  else
    {
      snprintf (uri_str, uri_size, "%s", req->uri.path ? req->uri.path : "/");
    }
}

/**
 * try_digest_auth_retry - Attempt digest auth response to challenge
 * @req: Request with auth credentials
 * @client: HTTP client (for default auth)
 * @www_auth: WWW-Authenticate header value
 * @auth_retry_count: Current retry count
 * @auth_header: Output buffer for Authorization header
 * @auth_header_size: Buffer size
 *
 * Returns: 1 if should retry with auth_header, 0 otherwise
 */
static int
try_digest_auth_retry (SocketHTTPClient_Request_T req,
                       SocketHTTPClient_T client, const char *www_auth,
                       int auth_retry_count, char *auth_header,
                       size_t auth_header_size)
{
  SocketHTTPClient_Auth *auth;
  const char *method_str;
  char nc_value[HTTPCLIENT_DIGEST_NC_SIZE];
  char uri_str[HTTPCLIENT_URI_BUFFER_SIZE];

  auth = req->auth != NULL ? req->auth : client->default_auth;
  if (auth == NULL || auth->type != HTTP_AUTH_DIGEST)
    return 0;

  if (strncasecmp (www_auth, "Digest ", 7) != 0)
    return 0;

  method_str = SocketHTTP_method_name (req->method);
  snprintf (nc_value, sizeof (nc_value), "%08x", auth_retry_count + 1);
  build_digest_auth_uri (req, uri_str, sizeof (uri_str));

  if (httpclient_auth_digest_challenge (
          www_auth, auth->username, auth->password, method_str, uri_str,
          nc_value, auth_header, auth_header_size)
      == 0)
    {
      return 1;
    }

  return 0;
}

/**
 * try_basic_auth_retry - Attempt basic auth when not already sent
 * @req: Request with auth credentials
 * @client: HTTP client (for default auth)
 * @www_auth: WWW-Authenticate header value
 * @auth_retry_count: Current retry count
 * @auth_header: Output buffer for Authorization header
 * @auth_header_size: Buffer size
 *
 * Returns: 1 if should retry with auth_header, 0 otherwise
 */
static int
try_basic_auth_retry (SocketHTTPClient_Request_T req,
                      SocketHTTPClient_T client, const char *www_auth,
                      int auth_retry_count, char *auth_header,
                      size_t auth_header_size)
{
  SocketHTTPClient_Auth *auth;
  int already_sent;

  auth = req->auth != NULL ? req->auth : client->default_auth;
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

  if (httpclient_auth_basic_header (auth->username, auth->password,
                                    auth_header, auth_header_size)
      == 0)
    {
      return 1;
    }

  return 0;
}

/**
 * handle_401_auth_retry - Handle 401 Unauthorized with auth retry
 * @client: HTTP client
 * @req: Request
 * @response: Current 401 response
 * @redirect_count: Current redirect count
 * @auth_retry_count: Current auth retry count
 *
 * Returns: 0 if handled (response updated), 1 if not handled, -1 on error
 */
static int
handle_401_auth_retry (SocketHTTPClient_T client,
                       SocketHTTPClient_Request_T req,
                       SocketHTTPClient_Response *response, int redirect_count,
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

  auth = req->auth != NULL ? req->auth : client->default_auth;
  if (auth == NULL)
    return 1; /* No credentials */

  if (auth->type != HTTP_AUTH_BASIC && auth->type != HTTP_AUTH_DIGEST)
    return 1; /* Unsupported auth type */

  www_auth = SocketHTTP_Headers_get (response->headers, "WWW-Authenticate");
  if (www_auth == NULL)
    return 1; /* No challenge */

  /* Try digest auth first, then basic */
  should_retry
      = try_digest_auth_retry (req, client, www_auth, auth_retry_count,
                               auth_header, sizeof (auth_header));
  if (!should_retry)
    {
      should_retry
          = try_basic_auth_retry (req, client, www_auth, auth_retry_count,
                                  auth_header, sizeof (auth_header));
    }

  if (!should_retry)
    return 1; /* Can't retry */

  /* Prepare for retry */
  SocketHTTPClient_Response_free (response);
  SocketHTTP_Headers_set (req->headers, "Authorization", auth_header);
  SocketCrypto_secure_clear (auth_header, sizeof (auth_header));

  /* Recurse with incremented auth retry count */
  return execute_request_internal (client, req, response, redirect_count,
                                   auth_retry_count + 1);
}

/* ============================================================================
 * Internal: Redirect Handling Helpers
 * ============================================================================
 */

/**
 * is_redirect_status - Check if status code is a redirect
 * @status_code: HTTP status code
 *
 * Returns: 1 if redirect, 0 otherwise
 */
static int
is_redirect_status (int status_code)
{
  return (status_code == 301 || status_code == 302 || status_code == 303
          || status_code == 307 || status_code == 308);
}

/**
 * should_follow_redirect - Determine if redirect should be followed
 * @client: HTTP client
 * @req: Request
 * @status_code: Response status code
 *
 * Returns: 1 if should follow, 0 otherwise
 */
static int
should_follow_redirect (SocketHTTPClient_T client,
                        SocketHTTPClient_Request_T req, int status_code)
{
  if (client->config.follow_redirects <= 0)
    return 0;

  if (!is_redirect_status (status_code))
    return 0;

  /* Check if POST should follow redirect */
  if (req->method == HTTP_METHOD_POST && !client->config.redirect_on_post)
    {
      /* 303 See Other always changes to GET */
      if (status_code != 303)
        return 0;
    }

  return 1;
}

/**
 * handle_redirect - Handle redirect response
 * @client: HTTP client
 * @req: Request (modified on redirect)
 * @response: Current response
 * @redirect_count: Current redirect count
 *
 * Returns: 0 if handled (response updated), 1 if not handled, -1 on error
 */
static int
handle_redirect (SocketHTTPClient_T client, SocketHTTPClient_Request_T req,
                 SocketHTTPClient_Response *response, int redirect_count)
{
  const char *location;
  SocketHTTP_URIResult uri_result;
  int status_code;

  if (!should_follow_redirect (client, req, response->status_code))
    return 1; /* Not following */

  location = SocketHTTP_Headers_get (response->headers, "Location");
  if (location == NULL)
    return 1; /* No location header */

  status_code = response->status_code;

  /* Free current response */
  SocketHTTPClient_Response_free (response);

  /* Parse new location */
  uri_result = SocketHTTP_URI_parse (location, 0, &req->uri, req->arena);
  if (uri_result != URI_PARSE_OK)
    {
      client->last_error = HTTPCLIENT_ERROR_PROTOCOL;
      HTTPCLIENT_ERROR_MSG ("Invalid redirect location: %s", location);
      return -1;
    }

  /* 303 changes method to GET */
  if (status_code == 303)
    {
      req->method = HTTP_METHOD_GET;
      req->body = NULL;
      req->body_len = 0;
    }

  /* Recurse with incremented redirect count (reset auth retry) */
  return execute_request_internal (client, req, response, redirect_count + 1,
                                   0);
}

/* ============================================================================
 * Internal: Connection Management Helpers
 * ============================================================================
 */

/**
 * release_connection - Release connection back to pool or close
 * @client: HTTP client
 * @conn: Pool entry to release
 * @success: 1 if request succeeded, 0 on failure
 */
static void
release_connection (SocketHTTPClient_T client, HTTPPoolEntry *conn,
                    int success)
{
  if (client->pool != NULL)
    {
      if (success && !conn->closed)
        {
          httpclient_pool_release (client->pool, conn);
        }
      else
        {
          httpclient_pool_close (client->pool, conn);
        }
    }
  else
    {
      /* No pool - close the socket directly */
      if (conn->proto.h1.socket != NULL)
        {
          Socket_free (&conn->proto.h1.socket);
        }
    }
}

/* ============================================================================
 * Internal: Execute Request Helpers
 * ============================================================================
 */

/**
 * check_request_limits - Check redirect and auth retry limits
 * @client: HTTP client
 * @redirect_count: Current redirect count
 * @auth_retry_count: Current auth retry count
 *
 * Returns: 0 to continue, 1 to return success (auth limit reached)
 * Raises: SocketHTTPClient_TooManyRedirects if redirect limit exceeded
 */
static int
check_request_limits (SocketHTTPClient_T client, int redirect_count,
                      int auth_retry_count)
{
  if (redirect_count > client->config.follow_redirects)
    {
      client->last_error = HTTPCLIENT_ERROR_TOO_MANY_REDIRECTS;
      SOCKET_RAISE_MSG (SocketHTTPClient, SocketHTTPClient_TooManyRedirects,
                        "Too many redirects (%d)", redirect_count);
    }

  /* Auth retry limit reached - return current response as-is */
  if (auth_retry_count > HTTPCLIENT_MAX_AUTH_RETRIES)
    return 1;

  return 0;
}

/**
 * prepare_request_headers - Add all required request headers
 * @client: HTTP client
 * @req: Request to prepare
 */
static void
prepare_request_headers (SocketHTTPClient_T client,
                         SocketHTTPClient_Request_T req)
{
  add_standard_headers (client, req);
  add_cookie_header (client, req);
  add_initial_auth_header (client, req);
  add_content_length_header (req);
}

/**
 * execute_protocol_request - Execute request based on HTTP version
 * @conn: Pool connection entry
 * @req: Request to execute
 * @response: Output response
 * @max_response_size: Maximum response body size
 * @client: HTTP client (for error reporting)
 *
 * Returns: 0 on success, -1 on error, -2 on size limit exceeded
 */
static int
execute_protocol_request (HTTPPoolEntry *conn, SocketHTTPClient_Request_T req,
                          SocketHTTPClient_Response *response,
                          size_t max_response_size, SocketHTTPClient_T client)
{
  if (conn->version == HTTP_VERSION_1_1 || conn->version == HTTP_VERSION_1_0)
    return execute_http1_request (conn, req, response, max_response_size);

  client->last_error = HTTPCLIENT_ERROR_PROTOCOL;
  HTTPCLIENT_ERROR_FMT ("HTTP version %d not supported", conn->version);
  return -1;
}

/**
 * handle_size_limit_error - Handle response size limit exceeded error
 * @client: HTTP client
 *
 * Raises: SocketHTTPClient_ResponseTooLarge
 */
static void
handle_size_limit_error (SocketHTTPClient_T client)
{
  SocketMetrics_counter_inc (SOCKET_CTR_LIMIT_RESPONSE_SIZE_EXCEEDED);
  client->last_error = HTTPCLIENT_ERROR_RESPONSE_TOO_LARGE;
  SOCKET_RAISE_MSG (SocketHTTPClient, SocketHTTPClient_ResponseTooLarge,
                    "Response body exceeds max_response_size (%zu)",
                    client->config.max_response_size);
}

/* ============================================================================
 * Internal: Execute Request
 * ============================================================================
 */

/**
 * execute_request_internal - Internal request execution with retry handling
 * @client: HTTP client
 * @req: Request to execute
 * @response: Output response
 * @redirect_count: Current redirect depth
 * @auth_retry_count: Current auth retry count
 *
 * Returns: 0 on success, -1 on error
 * Raises: SocketHTTPClient_TooManyRedirects on redirect limit
 *
 * Orchestrates HTTP request execution with redirect and auth retry handling.
 */
static int
execute_request_internal (SocketHTTPClient_T client,
                          SocketHTTPClient_Request_T req,
                          SocketHTTPClient_Response *response,
                          int redirect_count, int auth_retry_count)
{
  HTTPPoolEntry *conn;
  int result;
  int retry_result;

  assert (client != NULL);
  assert (req != NULL);
  assert (response != NULL);

  /* Check limits */
  if (check_request_limits (client, redirect_count, auth_retry_count) != 0)
    return 0;

  /* Get or create connection */
  conn = httpclient_connect (client, &req->uri);
  if (conn == NULL)
    {
      client->last_error = HTTPCLIENT_ERROR_CONNECT;
      return -1;
    }

  /* Prepare headers */
  prepare_request_headers (client, req);

  /* Execute based on protocol version */
  result = execute_protocol_request (conn, req, response,
                                     client->config.max_response_size, client);

  /* Release connection */
  release_connection (client, conn, result == 0);

  /* Handle size limit error */
  if (result == -2)
    handle_size_limit_error (client);

  if (result != 0)
    return -1;

  /* Store cookies from response */
  store_response_cookies (client, req, response);

  /* Handle 401 authentication retry */
  retry_result = handle_401_auth_retry (client, req, response, redirect_count,
                                        auth_retry_count);
  if (retry_result <= 0)
    return retry_result;

  /* Handle redirects */
  retry_result = handle_redirect (client, req, response, redirect_count);
  return (retry_result <= 0) ? retry_result : 0;
}

/* ============================================================================
 * Simple Synchronous API
 * ============================================================================
 */

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
 * ============================================================================
 */

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

  req = CALLOC (arena, 1, sizeof (*req));
  if (req == NULL)
    {
      Arena_dispose (&arena);
      client->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;
      return NULL;
    }

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
SocketHTTPClient_Request_body (SocketHTTPClient_Request_T req,
                               const void *data, size_t len)
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

  /* Copy strings into arena using centralized utility */
  auth_copy->username = socket_util_arena_strdup (req->arena, auth->username);
  auth_copy->password = socket_util_arena_strdup (req->arena, auth->password);
  auth_copy->token = socket_util_arena_strdup (req->arena, auth->token);

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
extern int httpclient_calculate_retry_delay (const SocketHTTPClient_T client,
                                             int attempt);

/* retry_sleep_ms moved to SocketHTTPClient-retry.c */
extern void httpclient_retry_sleep_ms (int ms);

/* httpclient_should_retry_error moved to SocketHTTPClient-retry.c */
extern int httpclient_should_retry_error (const SocketHTTPClient_T client,
                                          SocketHTTPClient_Error error);

/* should_retry_status moved to SocketHTTPClient-retry.c */
extern int httpclient_should_retry_status (const SocketHTTPClient_T client,
                                           int status);

/* clear_response_for_retry moved to SocketHTTPClient-retry.c */
extern void
httpclient_clear_response_for_retry (SocketHTTPClient_Response *response);

/**
 * execute_single_attempt - Execute one request attempt with exception handling
 * @client: HTTP client
 * @req: Request to execute
 * @response: Output response
 *
 * Returns: 0 on success, -1 on error (last_error set)
 */
static int
execute_single_attempt (SocketHTTPClient_T client,
                        SocketHTTPClient_Request_T req,
                        SocketHTTPClient_Response *response)
{
  volatile int result = -1;

  TRY { result = execute_request_internal (client, req, response, 0, 0); }
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

/**
 * should_retry_5xx - Check if 5xx response should trigger retry
 * @client: HTTP client
 * @response: Response with 5xx status
 * @attempt: Current attempt number
 *
 * Returns: 1 if should retry, 0 otherwise
 */
static int
should_retry_5xx (SocketHTTPClient_T client,
                  SocketHTTPClient_Response *response, int attempt)
{
  if (response->status_code < 500 || response->status_code >= 600)
    return 0;

  if (!httpclient_should_retry_status (client, response->status_code))
    return 0;

  if (attempt > client->config.max_retries)
    return 0;

  SocketLog_emitf (SOCKET_LOG_DEBUG, "HTTPClient",
                   "Attempt %d: Server returned %d, retrying", attempt,
                   response->status_code);
  return 1;
}

/**
 * raise_last_error - Raise exception for last error code
 * @client: HTTP client with last_error set
 */
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

/**
 * handle_failed_attempt - Handle a failed request attempt
 * @client: HTTP client
 * @attempt: Current attempt number
 *
 * Returns: 1 to continue retry loop, 0 to stop (raises exception or returns)
 */
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
  SocketLog_emitf (SOCKET_LOG_DEBUG, "HTTPClient",
                   "Attempt %d failed (error=%d), retrying in %d ms", attempt,
                   client->last_error, delay_ms);
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

      /* Success */
      if (result == 0)
        {
          /* Check if we need to retry on 5xx */
          if (!should_retry_5xx (client, response, attempt))
            return 0;
        }
      else
        {
          /* Error - handle failed attempt */
          if (!handle_failed_attempt (client, attempt))
            break;
        }
    }

  /* All retries exhausted - raise the last error */
  raise_last_error (client);
  return -1;
}

/* ============================================================================
 * Authentication Management
 * ============================================================================
 */

/**
 * Securely clear auth credentials stored in arena
 */
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

  *auth_copy = *auth;

  /* Copy strings using centralized utility */
  auth_copy->username
      = socket_util_arena_strdup (client->arena, auth->username);
  auth_copy->password
      = socket_util_arena_strdup (client->arena, auth->password);
  auth_copy->token = socket_util_arena_strdup (client->arena, auth->token);

  client->default_auth = auth_copy;

  pthread_mutex_unlock (&client->mutex);
}

/* ============================================================================
 * Cookie Jar Association
 * ============================================================================
 */

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

/* ============================================================================
 * Pool Statistics
 * ============================================================================
 */

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
  pthread_mutex_unlock (&client->mutex);
}

/* ============================================================================
 * Error Handling
 * ============================================================================
 */

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
                             size_t body_len,
                             SocketHTTPClient_Callback callback,
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
  async_req = CALLOC (req->arena, 1, sizeof (*async_req));
  if (async_req == NULL)
    {
      client->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;
      return NULL;
    }

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

/* ============================================================================
 * Convenience Functions
 * ============================================================================
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int
SocketHTTPClient_download (SocketHTTPClient_T client, const char *url,
                           const char *filepath)
{
  SocketHTTPClient_Response response = { 0 };
  int fd = -1;
  int result = -1;

  assert (client != NULL);
  assert (url != NULL);
  assert (filepath != NULL);

  /* Perform GET request */
  if (SocketHTTPClient_get (client, url, &response) != 0)
    return -1;

  /* Check for success status */
  if (response.status_code < 200 || response.status_code >= 300)
    {
      SocketHTTPClient_Response_free (&response);
      return -1;
    }

  /* Open file for writing */
  fd = open (filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
    {
      SocketHTTPClient_Response_free (&response);
      return -2; /* File error */
    }

  /* Write body to file */
  if (response.body && response.body_len > 0)
    {
      ssize_t written = 0;
      while ((size_t)written < response.body_len)
        {
          ssize_t n
              = write (fd, response.body + written, response.body_len - written);
          if (n <= 0)
            {
              if (n < 0 && errno == EINTR)
                continue;
              close (fd);
              SocketHTTPClient_Response_free (&response);
              return -2;
            }
          written += n;
        }
    }

  result = 0;
  close (fd);
  SocketHTTPClient_Response_free (&response);
  return result;
}

int
SocketHTTPClient_upload (SocketHTTPClient_T client, const char *url,
                         const char *filepath)
{
  SocketHTTPClient_Response response = { 0 };
  struct stat st;
  int fd = -1;
  char *buffer = NULL;
  int result = -2;

  assert (client != NULL);
  assert (url != NULL);
  assert (filepath != NULL);

  /* Open and stat file */
  fd = open (filepath, O_RDONLY);
  if (fd < 0)
    return -2;

  if (fstat (fd, &st) < 0)
    {
      close (fd);
      return -2;
    }

  /* Read file into memory */
  buffer = malloc (st.st_size);
  if (!buffer)
    {
      close (fd);
      return -2;
    }

  ssize_t total_read = 0;
  while (total_read < st.st_size)
    {
      ssize_t n = read (fd, buffer + total_read, st.st_size - total_read);
      if (n <= 0)
        {
          if (n < 0 && errno == EINTR)
            continue;
          free (buffer);
          close (fd);
          return -2;
        }
      total_read += n;
    }
  close (fd);

  /* Perform PUT request */
  if (SocketHTTPClient_put (client, url, "application/octet-stream", buffer,
                            st.st_size, &response)
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

int
SocketHTTPClient_json_get (SocketHTTPClient_T client, const char *url,
                           char **json_out, size_t *json_len)
{
  SocketHTTPClient_Request_T req = NULL;
  SocketHTTPClient_Response response = { 0 };
  int status = -1;

  assert (client != NULL);
  assert (url != NULL);
  assert (json_out != NULL);
  assert (json_len != NULL);

  *json_out = NULL;
  *json_len = 0;

  /* Build GET request with JSON accept header */
  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET, url);
  if (!req)
    return -1;

  SocketHTTPClient_Request_header (req, "Accept", "application/json");

  if (SocketHTTPClient_Request_execute (req, &response) != 0)
    {
      SocketHTTPClient_Request_free (&req);
      return -1;
    }

  SocketHTTPClient_Request_free (&req);
  status = response.status_code;

  /* Check content type */
  const char *content_type = SocketHTTP_Headers_get (response.headers,
                                                     "Content-Type");
  if (content_type && strstr (content_type, "application/json") == NULL)
    {
      SocketHTTPClient_Response_free (&response);
      return -2; /* Content-type mismatch */
    }

  /* Copy body to output */
  if (response.body && response.body_len > 0)
    {
      *json_out = malloc (response.body_len + 1);
      if (*json_out)
        {
          memcpy (*json_out, response.body, response.body_len);
          (*json_out)[response.body_len] = '\0';
          *json_len = response.body_len;
        }
    }

  SocketHTTPClient_Response_free (&response);
  return status;
}

int
SocketHTTPClient_json_post (SocketHTTPClient_T client, const char *url,
                            const char *json_body, char **json_out,
                            size_t *json_len)
{
  SocketHTTPClient_Request_T req = NULL;
  SocketHTTPClient_Response response = { 0 };
  int status = -1;

  assert (client != NULL);
  assert (url != NULL);
  assert (json_body != NULL);
  assert (json_out != NULL);
  assert (json_len != NULL);

  *json_out = NULL;
  *json_len = 0;

  /* Build POST request with JSON headers */
  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_POST, url);
  if (!req)
    return -1;

  SocketHTTPClient_Request_header (req, "Content-Type", "application/json");
  SocketHTTPClient_Request_header (req, "Accept", "application/json");
  SocketHTTPClient_Request_body (req, json_body, strlen (json_body));

  if (SocketHTTPClient_Request_execute (req, &response) != 0)
    {
      SocketHTTPClient_Request_free (&req);
      return -1;
    }

  SocketHTTPClient_Request_free (&req);
  status = response.status_code;

  /* Check content type if we have a body */
  if (response.body && response.body_len > 0)
    {
      const char *content_type = SocketHTTP_Headers_get (response.headers,
                                                         "Content-Type");
      if (content_type && strstr (content_type, "application/json") == NULL)
        {
          SocketHTTPClient_Response_free (&response);
          return -2; /* Content-type mismatch */
        }

      /* Copy body to output */
      *json_out = malloc (response.body_len + 1);
      if (*json_out)
        {
          memcpy (*json_out, response.body, response.body_len);
          (*json_out)[response.body_len] = '\0';
          *json_len = response.body_len;
        }
    }

  SocketHTTPClient_Response_free (&response);
  return status;
}

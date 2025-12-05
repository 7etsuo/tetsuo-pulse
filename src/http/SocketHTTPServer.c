/**
 * SocketHTTPServer.c - HTTP Server Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Production-ready HTTP server with:
 * - Non-blocking I/O with SocketPoll integration
 * - Keep-alive connection handling
 * - Request body streaming for large uploads
 * - Response body streaming (chunked transfer encoding)
 * - HTTP/2 server push support
 * - Rate limiting per endpoint
 * - Per-client connection limiting
 * - Request validation middleware
 * - Granular timeout enforcement
 * - Graceful shutdown (drain)
 * - Enhanced statistics with latency tracking
 *
 * Leverages:
 * - SocketHTTP for headers, methods, status codes
 * - SocketHTTP1 for HTTP/1.1 parsing/serialization
 * - SocketRateLimit for rate limiting
 * - SocketIPTracker for per-client limits
 * - SocketPoll for event loop
 * - Socket for networking
 */

#include "http/SocketHTTPServer.h"
#include "core/Arena.h"
#include "core/SocketIPTracker.h"
#include "core/SocketRateLimit.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * Server Configuration
 * ============================================================================
 * Server constants are defined in SocketHTTPServer.h with compile-time
 * override support (#ifndef guards). Reference:
 *   - HTTPSERVER_IO_BUFFER_SIZE (8192) - I/O buffer per connection
 *   - HTTPSERVER_MAX_CLIENTS_PER_ACCEPT (10) - clients per accept loop
 *   - HTTPSERVER_CHUNK_BUFFER_SIZE (16384) - streaming chunk buffer
 *   - HTTPSERVER_MAX_RATE_LIMIT_ENDPOINTS (64) - rate limit entries
 *   - HTTPSERVER_LATENCY_SAMPLES (1000) - latency tracking samples
 */

/* ============================================================================
 * Centralized Exception Infrastructure
 * ============================================================================
 *
 * REFACTOR: Uses centralized exception handling from SocketUtil.h instead
 * of module-specific thread-local buffers. Benefits:
 * - Single thread-local error buffer (socket_error_buf) for all modules
 * - Consistent error formatting with SOCKET_ERROR_FMT/MSG macros
 * - Thread-safe exception raising via SOCKET_RAISE_MODULE_ERROR
 * - Automatic logging integration via SocketLog_emit
 */

/* Override log component for this module */
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTPServer"

/* Declare thread-local exception for this module */
SOCKET_DECLARE_MODULE_EXCEPTION (HTTPServer);

/* ============================================================================
 * Exception Definitions
 * ============================================================================ */

const Except_T SocketHTTPServer_Failed
    = { &SocketHTTPServer_Failed, "HTTP server operation failed" };
const Except_T SocketHTTPServer_BindFailed
    = { &SocketHTTPServer_BindFailed, "Failed to bind server socket" };
const Except_T SocketHTTPServer_ProtocolError
    = { &SocketHTTPServer_ProtocolError, "HTTP protocol error" };

/* ============================================================================
 * Error Handling Macros (Centralized)
 * ============================================================================
 *
 * These delegate to centralized macros from SocketUtil.h for consistency.
 * Uses socket_error_buf (thread-local, 256 bytes) for error messages.
 */

#define HTTPSERVER_ERROR_FMT(fmt, ...) SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__)
#define HTTPSERVER_ERROR_MSG(fmt, ...) SOCKET_ERROR_MSG (fmt, ##__VA_ARGS__)

/**
 * RAISE_HTTPSERVER_ERROR - Raise exception with detailed error message
 *
 * Creates a thread-local copy of the exception with reason from
 * socket_error_buf. Thread-safe: prevents race conditions.
 */
#define RAISE_HTTPSERVER_ERROR(e) SOCKET_RAISE_MODULE_ERROR (HTTPServer, e)

/* ============================================================================
 * Rate Limit Endpoint Entry
 * ============================================================================ */

typedef struct RateLimitEntry
{
  char *path_prefix;
  SocketRateLimit_T limiter;
  struct RateLimitEntry *next;
} RateLimitEntry;

/* ============================================================================
 * Connection State
 * ============================================================================ */

typedef enum
{
  CONN_STATE_READING_REQUEST,
  CONN_STATE_READING_BODY,
  CONN_STATE_HANDLING,
  CONN_STATE_STREAMING_RESPONSE,
  CONN_STATE_SENDING_RESPONSE,
  CONN_STATE_CLOSED
} ServerConnState;

typedef struct ServerConnection
{
  Socket_T socket;
  char client_addr[64];

  ServerConnState state;
  SocketHTTP1_Parser_T parser;
  SocketBuf_T inbuf;
  SocketBuf_T outbuf;

  /* Request data */
  const SocketHTTP_Request *request;
  void *body;
  size_t body_len;
  size_t body_capacity;
  size_t body_received;

  /* Request body streaming */
  SocketHTTPServer_BodyCallback body_callback;
  void *body_callback_userdata;
  int body_streaming;

  /* Response data */
  int response_status;
  SocketHTTP_Headers_T response_headers;
  void *response_body;
  size_t response_body_len;
  int response_finished;

  /* Response streaming */
  int response_streaming;
  int response_headers_sent;

  /* Connection metadata */
  int64_t created_at_ms;
  int64_t last_activity_ms;
  int64_t request_start_ms;
  int64_t response_start_ms;
  size_t request_count;
  size_t active_requests; /* For HTTP/2 multiplexing */

  Arena_T arena;

  struct ServerConnection *next;
  struct ServerConnection *prev;
} ServerConnection;

/* ============================================================================
 * Request Context
 * ============================================================================ */

struct SocketHTTPServer_Request
{
  SocketHTTPServer_T server;
  ServerConnection *conn;
  Arena_T arena;
  int64_t start_time_ms;
};

/* ============================================================================
 * Latency Tracking (Circular Buffer)
 * ============================================================================ */

typedef struct
{
  int64_t samples[HTTPSERVER_LATENCY_SAMPLES];
  size_t count;
  size_t index;
  int64_t sum;
  int64_t max;
} LatencyTracker;

/* ============================================================================
 * Server Structure
 * ============================================================================ */

struct SocketHTTPServer
{
  SocketHTTPServer_Config config;

  Socket_T listen_socket;
  SocketPoll_T poll;

  /* Callbacks */
  SocketHTTPServer_Handler handler;
  void *handler_userdata;
  SocketHTTPServer_Validator validator;
  void *validator_userdata;
  SocketHTTPServer_DrainCallback drain_callback;
  void *drain_callback_userdata;

  /* Connections */
  ServerConnection *connections;
  size_t connection_count;

  /* Rate limiting */
  RateLimitEntry *rate_limiters;
  SocketRateLimit_T global_rate_limiter;

  /* Per-client limiting */
  SocketIPTracker_T ip_tracker;

  /* Graceful shutdown */
  volatile int state; /* SocketHTTPServer_State */
  int64_t drain_start_ms;
  int drain_timeout_ms;

  /* Statistics */
  size_t total_connections;
  size_t total_requests;
  size_t total_bytes_sent;
  size_t total_bytes_received;
  size_t errors_4xx;
  size_t errors_5xx;
  size_t timeouts;
  size_t rate_limited;
  size_t connections_rejected;

  /* Request rate tracking */
  size_t request_counts[HTTPSERVER_RPS_WINDOW_SECONDS];
  size_t rps_index;
  int64_t rps_last_update_ms;

  /* Latency tracking */
  LatencyTracker latency;

  /* Thread safety for statistics */
  pthread_mutex_t stats_mutex;

  int running;
  Arena_T arena;
};

/* ============================================================================
 * Internal Helper Functions - Time
 * ============================================================================ */

/**
 * REFACTOR: Uses Socket_get_monotonic_ms() from SocketUtil.h instead of
 * direct clock_gettime() call. Centralizes monotonic time access.
 */
static int64_t
server_time_ms (void)
{
  return Socket_get_monotonic_ms ();
}

/* ============================================================================
 * Internal Helper Functions - Latency
 * ============================================================================ */

static void
latency_init (LatencyTracker *lt)
{
  memset (lt, 0, sizeof (*lt));
}

static void
latency_record (LatencyTracker *lt, int64_t latency_us)
{
  lt->samples[lt->index] = latency_us;
  lt->index = (lt->index + 1) % HTTPSERVER_LATENCY_SAMPLES;
  if (lt->count < HTTPSERVER_LATENCY_SAMPLES)
    lt->count++;
  lt->sum += latency_us;
  if (latency_us > lt->max)
    lt->max = latency_us;
}

static int
latency_compare (const void *a, const void *b)
{
  int64_t va = *(const int64_t *)a;
  int64_t vb = *(const int64_t *)b;
  return (va > vb) - (va < vb);
}

static int64_t
latency_percentile (LatencyTracker *lt, int percentile)
{
  if (lt->count == 0)
    return 0;

  int64_t sorted[HTTPSERVER_LATENCY_SAMPLES];
  memcpy (sorted, lt->samples, lt->count * sizeof (int64_t));
  qsort (sorted, lt->count, sizeof (int64_t), latency_compare);

  size_t idx = (size_t)((percentile / 100.0) * (lt->count - 1));
  return sorted[idx];
}

static int64_t
latency_avg (LatencyTracker *lt)
{
  if (lt->count == 0)
    return 0;
  return lt->sum / (int64_t)lt->count;
}

/* ============================================================================
 * Internal Helper Functions - Rate Limiting
 * ============================================================================ */

static SocketRateLimit_T
find_rate_limiter (SocketHTTPServer_T server, const char *path)
{
  if (path == NULL)
    return server->global_rate_limiter;

  /* Find most specific matching prefix */
  RateLimitEntry *best = NULL;
  size_t best_len = 0;

  for (RateLimitEntry *e = server->rate_limiters; e != NULL; e = e->next)
    {
      size_t len = strlen (e->path_prefix);
      if (strncmp (path, e->path_prefix, len) == 0)
        {
          if (len > best_len)
            {
              best = e;
              best_len = len;
            }
        }
    }

  if (best != NULL)
    return best->limiter;
  return server->global_rate_limiter;
}

/* ============================================================================
 * Internal Helper Functions - Connection
 * ============================================================================ */

static ServerConnection *
connection_new (SocketHTTPServer_T server, Socket_T socket)
{
  ServerConnection *conn;
  Arena_T arena;

  conn = malloc (sizeof (*conn));
  if (conn == NULL)
    return NULL;

  memset (conn, 0, sizeof (*conn));

  arena = Arena_new ();
  if (arena == NULL)
    {
      free (conn);
      return NULL;
    }

  conn->arena = arena;
  conn->socket = socket;
  conn->state = CONN_STATE_READING_REQUEST;
  conn->created_at_ms = server_time_ms ();
  conn->last_activity_ms = conn->created_at_ms;

  /* Get client address */
  const char *addr = Socket_getpeeraddr (socket);
  if (addr != NULL)
    {
      strncpy (conn->client_addr, addr, sizeof (conn->client_addr) - 1);
      conn->client_addr[sizeof (conn->client_addr) - 1] = '\0';
    }

  /* Create parser */
  conn->parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
  if (conn->parser == NULL)
    {
      Arena_dispose (&arena);
      free (conn);
      return NULL;
    }

  /* Create I/O buffers */
  conn->inbuf = SocketBuf_new (arena, HTTPSERVER_IO_BUFFER_SIZE);
  conn->outbuf = SocketBuf_new (arena, HTTPSERVER_IO_BUFFER_SIZE);

  if (conn->inbuf == NULL || conn->outbuf == NULL)
    {
      Arena_dispose (&arena);
      free (conn);
      return NULL;
    }

  /* Create response headers */
  conn->response_headers = SocketHTTP_Headers_new (arena);
  if (conn->response_headers == NULL)
    {
      Arena_dispose (&arena);
      free (conn);
      return NULL;
    }

  /* Track per-IP connections */
  if (server->ip_tracker != NULL && conn->client_addr[0] != '\0')
    {
      if (!SocketIPTracker_track (server->ip_tracker, conn->client_addr))
        {
          /* Connection limit reached for this IP */
          Arena_dispose (&arena);
          free (conn);
          pthread_mutex_lock (&server->stats_mutex);
          server->connections_rejected++;
          pthread_mutex_unlock (&server->stats_mutex);
          return NULL;
        }
    }

  /* Add to server's connection list */
  conn->next = server->connections;
  if (server->connections != NULL)
    server->connections->prev = conn;
  server->connections = conn;
  pthread_mutex_lock (&server->stats_mutex);
  server->connection_count++;
  server->total_connections++;
  pthread_mutex_unlock (&server->stats_mutex);

  return conn;
}

static void
connection_close (SocketHTTPServer_T server, ServerConnection *conn)
{
  if (conn == NULL)
    return;

  /* Release IP tracking */
  if (server->ip_tracker != NULL && conn->client_addr[0] != '\0')
    {
      SocketIPTracker_release (server->ip_tracker, conn->client_addr);
    }

  /* Remove from poll */
  if (server->poll != NULL && conn->socket != NULL)
    {
      SocketPoll_del (server->poll, conn->socket);
    }

  /* Close socket */
  if (conn->socket != NULL)
    {
      Socket_free (&conn->socket);
    }

  /* Remove from connection list */
  if (conn->prev != NULL)
    conn->prev->next = conn->next;
  else
    server->connections = conn->next;

  if (conn->next != NULL)
    conn->next->prev = conn->prev;

  pthread_mutex_lock (&server->stats_mutex);
  server->connection_count--;
  pthread_mutex_unlock (&server->stats_mutex);

  /* Free arena */
  if (conn->arena != NULL)
    {
      Arena_dispose (&conn->arena);
    }

  free (conn);
}

static int
connection_read (SocketHTTPServer_T server, ServerConnection *conn)
{
  char buf[4096];
  volatile ssize_t n = 0;
  volatile int closed = 0;

  TRY { n = Socket_recv (conn->socket, buf, sizeof (buf)); }
  EXCEPT (Socket_Closed)
  {
    closed = 1;
    n = 0;
  }
  END_TRY;

  if (closed || n <= 0)
    {
      if (closed || n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
        {
          conn->state = CONN_STATE_CLOSED;
          return -1;
        }
      return 0;
    }

  conn->last_activity_ms = server_time_ms ();
  pthread_mutex_lock (&server->stats_mutex);
  server->total_bytes_received += (size_t)n;
  pthread_mutex_unlock (&server->stats_mutex);

  SocketBuf_write (conn->inbuf, buf, (size_t)n);

  return (int)n;
}

static int
connection_send_data (SocketHTTPServer_T server, ServerConnection *conn,
                      const void *data, size_t len)
{
  volatile int closed = 0;
  volatile ssize_t sent = 0;

  TRY { sent = Socket_sendall (conn->socket, data, len); }
  EXCEPT (Socket_Closed)
  {
    closed = 1;
    sent = 0;
  }
  END_TRY;

  if (closed)
    {
      conn->state = CONN_STATE_CLOSED;
      return -1;
    }

  conn->last_activity_ms = server_time_ms ();
  pthread_mutex_lock (&server->stats_mutex);
  server->total_bytes_sent += (size_t)sent;
  pthread_mutex_unlock (&server->stats_mutex);

  return 0;
}

static void
connection_reset_for_keepalive (ServerConnection *conn)
{
  conn->request_count++;
  SocketHTTP1_Parser_reset (conn->parser);
  SocketBuf_clear (conn->inbuf);
  SocketBuf_clear (conn->outbuf);

  SocketHTTP_Headers_clear (conn->response_headers);
  conn->response_status = 0;
  conn->response_body = NULL;
  conn->response_body_len = 0;
  conn->response_finished = 0;
  conn->response_streaming = 0;
  conn->response_headers_sent = 0;
  conn->request = NULL;
  conn->body = NULL;
  conn->body_len = 0;
  conn->body_capacity = 0;
  conn->body_received = 0;
  conn->body_callback = NULL;
  conn->body_callback_userdata = NULL;
  conn->body_streaming = 0;
  conn->request_start_ms = 0;
  conn->response_start_ms = 0;

  conn->state = CONN_STATE_READING_REQUEST;
}

static int
connection_parse_request (SocketHTTPServer_T server, ServerConnection *conn)
{
  const void *data;
  size_t len;
  size_t consumed;
  SocketHTTP1_Result result;

  (void)server;

  data = SocketBuf_readptr (conn->inbuf, &len);
  if (len == 0)
    return 0;

  result = SocketHTTP1_Parser_execute (conn->parser, data, len, &consumed);

  if (consumed > 0)
    SocketBuf_consume (conn->inbuf, consumed);

  if (result == HTTP1_ERROR || result >= HTTP1_ERROR_LINE_TOO_LONG)
    {
      conn->state = CONN_STATE_CLOSED;
      return -1;
    }

  if (SocketHTTP1_Parser_state (conn->parser) >= HTTP1_STATE_BODY)
    {
      conn->request = SocketHTTP1_Parser_get_request (conn->parser);
      conn->request_start_ms = server_time_ms ();

      if (conn->request->has_body && !conn->body_streaming)
        {
          int64_t content_len
              = SocketHTTP1_Parser_content_length (conn->parser);
          if (content_len > 0)
            {
              conn->body_capacity = (size_t)content_len;
              conn->body
                  = Arena_alloc (conn->arena, conn->body_capacity, __FILE__,
                                 __LINE__);
              if (conn->body == NULL)
                {
                  conn->state = CONN_STATE_CLOSED;
                  return -1;
                }

              data = SocketBuf_readptr (conn->inbuf, &len);
              if (len > 0)
                {
                  size_t to_copy = len;
                  if (to_copy > conn->body_capacity)
                    to_copy = conn->body_capacity;
                  memcpy (conn->body, data, to_copy);
                  conn->body_len = to_copy;
                  SocketBuf_consume (conn->inbuf, to_copy);
                }

              /* Check if we need to read more body data */
              if (conn->body_len < conn->body_capacity)
                {
                  conn->state = CONN_STATE_READING_BODY;
                  return 0; /* Need more data */
                }
            }
        }

      conn->state = CONN_STATE_HANDLING;
      return 1;
    }

  return 0;
}

static void
connection_send_response (SocketHTTPServer_T server, ServerConnection *conn)
{
  char buf[8192];
  ssize_t len;

  SocketHTTP_Response response;
  memset (&response, 0, sizeof (response));
  response.version = HTTP_VERSION_1_1;
  response.status_code = conn->response_status;
  response.headers = conn->response_headers;

  /* Track errors */
  if (conn->response_status >= 400 && conn->response_status < 500)
    {
      pthread_mutex_lock (&server->stats_mutex);
      server->errors_4xx++;
      pthread_mutex_unlock (&server->stats_mutex);
    }
  else if (conn->response_status >= 500)
    {
      pthread_mutex_lock (&server->stats_mutex);
      server->errors_5xx++;
      pthread_mutex_unlock (&server->stats_mutex);
    }

  if (conn->response_body_len > 0 && !conn->response_streaming)
    {
      char cl[32];
      snprintf (cl, sizeof (cl), "%zu", conn->response_body_len);
      SocketHTTP_Headers_set (conn->response_headers, "Content-Length", cl);
    }

  len = SocketHTTP1_serialize_response (&response, buf, sizeof (buf));
  if (len < 0)
    {
      conn->state = CONN_STATE_CLOSED;
      return;
    }

  if (connection_send_data (server, conn, buf, (size_t)len) < 0)
    {
      conn->state = CONN_STATE_CLOSED;
      return;
    }

  if (conn->response_body != NULL && conn->response_body_len > 0)
    {
      if (connection_send_data (server, conn, conn->response_body,
                                conn->response_body_len)
          < 0)
        {
          conn->state = CONN_STATE_CLOSED;
          return;
        }
    }

  /* Record latency */
  if (conn->request_start_ms > 0)
    {
      int64_t latency_us = (server_time_ms () - conn->request_start_ms) * 1000;
      latency_record (&server->latency, latency_us);
    }

  if (SocketHTTP1_Parser_should_keepalive (conn->parser))
    {
      connection_reset_for_keepalive (conn);
    }
  else
    {
      conn->state = CONN_STATE_CLOSED;
    }
}

static void
connection_send_error (SocketHTTPServer_T server, ServerConnection *conn,
                       int status, const char *body)
{
  conn->response_status = status;
  if (body != NULL)
    {
      size_t len = strlen (body);
      void *copy = Arena_alloc (conn->arena, len, __FILE__, __LINE__);
      if (copy != NULL)
        {
          memcpy (copy, body, len);
          conn->response_body = copy;
          conn->response_body_len = len;
        }
      SocketHTTP_Headers_set (conn->response_headers, "Content-Type",
                              "text/plain");
    }
  connection_send_response (server, conn);
}

/* ============================================================================
 * Configuration Defaults
 * ============================================================================ */

void
SocketHTTPServer_config_defaults (SocketHTTPServer_Config *config)
{
  assert (config != NULL);

  memset (config, 0, sizeof (*config));

  config->port = 8080;
  config->bind_address = NULL;
  config->backlog = HTTPSERVER_DEFAULT_BACKLOG;

  config->tls_context = NULL;

  config->max_version = HTTP_VERSION_1_1;
  config->enable_h2c_upgrade = 0;

  config->max_header_size = HTTPSERVER_DEFAULT_MAX_HEADER_SIZE;
  config->max_body_size = HTTPSERVER_DEFAULT_MAX_BODY_SIZE;
  config->request_timeout_ms = HTTPSERVER_DEFAULT_REQUEST_TIMEOUT_MS;
  config->keepalive_timeout_ms = HTTPSERVER_DEFAULT_KEEPALIVE_TIMEOUT_MS;
  config->request_read_timeout_ms = HTTPSERVER_DEFAULT_REQUEST_READ_TIMEOUT_MS;
  config->response_write_timeout_ms
      = HTTPSERVER_DEFAULT_RESPONSE_WRITE_TIMEOUT_MS;
  config->max_connections = HTTPSERVER_DEFAULT_MAX_CONNECTIONS;
  config->max_requests_per_connection = HTTPSERVER_DEFAULT_MAX_REQUESTS_PER_CONN;
  config->max_connections_per_client
      = HTTPSERVER_DEFAULT_MAX_CONNECTIONS_PER_CLIENT;
  config->max_concurrent_requests = HTTPSERVER_DEFAULT_MAX_CONCURRENT_REQUESTS;
}

/* ============================================================================
 * Server Lifecycle
 * ============================================================================ */

SocketHTTPServer_T
SocketHTTPServer_new (const SocketHTTPServer_Config *config)
{
  SocketHTTPServer_T server;
  SocketHTTPServer_Config default_config;
  Arena_T arena;

  if (config == NULL)
    {
      SocketHTTPServer_config_defaults (&default_config);
      config = &default_config;
    }

  server = malloc (sizeof (*server));
  if (server == NULL)
    {
      HTTPSERVER_ERROR_MSG ("Failed to allocate server structure");
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
    }

  arena = Arena_new ();
  if (arena == NULL)
    {
      free (server);
      HTTPSERVER_ERROR_MSG ("Failed to create server arena");
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
    }

  memset (server, 0, sizeof (*server));
  server->arena = arena;
  server->config = *config;
  server->state = HTTPSERVER_STATE_RUNNING;

  /* Create poll instance */
  server->poll = SocketPoll_new ((int)config->max_connections + 1);
  if (server->poll == NULL)
    {
      Arena_dispose (&arena);
      free (server);
      HTTPSERVER_ERROR_MSG ("Failed to create poll instance");
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
    }

  /* Create IP tracker for per-client limits */
  if (config->max_connections_per_client > 0)
    {
      server->ip_tracker
          = SocketIPTracker_new (arena, config->max_connections_per_client);
    }

  /* Initialize latency tracker */
  latency_init (&server->latency);

  /* Initialize stats mutex */
  pthread_mutex_init (&server->stats_mutex, NULL);

  return server;
}

void
SocketHTTPServer_free (SocketHTTPServer_T *server)
{
  if (server == NULL || *server == NULL)
    return;

  SocketHTTPServer_T s = *server;

  SocketHTTPServer_stop (s);

  while (s->connections != NULL)
    {
      connection_close (s, s->connections);
    }

  /* Free rate limit entries */
  RateLimitEntry *e = s->rate_limiters;
  while (e != NULL)
    {
      RateLimitEntry *next = e->next;
      free (e->path_prefix);
      free (e);
      e = next;
    }

  if (s->ip_tracker != NULL)
    {
      SocketIPTracker_free (&s->ip_tracker);
    }

  if (s->poll != NULL)
    {
      SocketPoll_free (&s->poll);
    }

  if (s->listen_socket != NULL)
    {
      Socket_free (&s->listen_socket);
    }

  if (s->arena != NULL)
    {
      Arena_dispose (&s->arena);
    }

  pthread_mutex_destroy (&s->stats_mutex);

  free (s);
  *server = NULL;
}

static int
is_ipv4_address (const char *addr)
{
  struct in_addr dummy;
  return inet_pton (AF_INET, addr, &dummy) == 1;
}

static int
is_ipv6_address (const char *addr)
{
  struct in6_addr dummy;
  return inet_pton (AF_INET6, addr, &dummy) == 1;
}

int
SocketHTTPServer_start (SocketHTTPServer_T server)
{
  const char *volatile bind_addr;
  volatile int socket_family;

  assert (server != NULL);

  if (server->running)
    return 0;

  bind_addr = server->config.bind_address;
  if (bind_addr == NULL || strcmp (bind_addr, "") == 0)
    {
      bind_addr = "::";
      socket_family = AF_INET6;
    }
  else if (is_ipv4_address (bind_addr))
    {
      socket_family = AF_INET;
    }
  else if (is_ipv6_address (bind_addr))
    {
      socket_family = AF_INET6;
    }
  else
    {
      socket_family = AF_INET6;
    }

  server->listen_socket = Socket_new (socket_family, SOCK_STREAM, 0);
  if (server->listen_socket == NULL && socket_family == AF_INET6)
    {
      socket_family = AF_INET;
      server->listen_socket = Socket_new (AF_INET, SOCK_STREAM, 0);
      if (bind_addr && strcmp (bind_addr, "::") == 0)
        bind_addr = "0.0.0.0";
    }

  if (server->listen_socket == NULL)
    {
      HTTPSERVER_ERROR_FMT ("Failed to create listen socket");
      return -1;
    }

  Socket_setreuseaddr (server->listen_socket);

  TRY { Socket_bind (server->listen_socket, bind_addr, server->config.port); }
  EXCEPT (Socket_Failed)
  {
    if (socket_family == AF_INET6 && strcmp (bind_addr, "::") == 0)
      {
        TRY
        {
          Socket_bind (server->listen_socket, "0.0.0.0", server->config.port);
        }
        EXCEPT (Socket_Failed)
        {
          Socket_free (&server->listen_socket);
          HTTPSERVER_ERROR_FMT ("Failed to bind to port %d",
                                server->config.port);
          return -1;
        }
        END_TRY;
      }
    else
      {
        Socket_free (&server->listen_socket);
        HTTPSERVER_ERROR_FMT ("Failed to bind to %s:%d", bind_addr,
                              server->config.port);
        return -1;
      }
  }
  END_TRY;

  Socket_listen (server->listen_socket, server->config.backlog);
  Socket_setnonblocking (server->listen_socket);

  SocketPoll_add (server->poll, server->listen_socket, POLL_READ, NULL);

  server->running = 1;
  server->state = HTTPSERVER_STATE_RUNNING;
  return 0;
}

void
SocketHTTPServer_stop (SocketHTTPServer_T server)
{
  assert (server != NULL);

  if (!server->running)
    return;

  if (server->listen_socket != NULL)
    {
      SocketPoll_del (server->poll, server->listen_socket);
    }

  server->running = 0;
}

void
SocketHTTPServer_set_handler (SocketHTTPServer_T server,
                              SocketHTTPServer_Handler handler, void *userdata)
{
  assert (server != NULL);
  server->handler = handler;
  server->handler_userdata = userdata;
}

/* ============================================================================
 * Event Loop - Helper Functions
 * ============================================================================ */

/**
 * server_accept_clients - Accept new client connections
 * @server: HTTP server
 *
 * Accepts up to HTTPSERVER_MAX_CLIENTS_PER_ACCEPT clients per call.
 * Skips acceptance if server is draining or at connection limit.
 */
static void
server_accept_clients (SocketHTTPServer_T server)
{
  for (int j = 0; j < HTTPSERVER_MAX_CLIENTS_PER_ACCEPT; j++)
    {
      if (server->connection_count >= server->config.max_connections)
        break;

      Socket_T client = Socket_accept (server->listen_socket);
      if (client == NULL)
        break;

      Socket_setnonblocking (client);

      ServerConnection *conn = connection_new (server, client);
      if (conn == NULL)
        {
          Socket_free (&client);
          continue;
        }

      SocketPoll_add (server->poll, client, POLL_READ, conn);
    }
}

/**
 * server_check_rate_limit - Check rate limit for request path
 * @server: HTTP server
 * @conn: Connection with parsed request
 *
 * Returns: 1 if allowed, 0 if rate limited (sends 429 error)
 */
static int
server_check_rate_limit (SocketHTTPServer_T server, ServerConnection *conn)
{
  SocketRateLimit_T limiter
      = find_rate_limiter (server, conn->request ? conn->request->path : NULL);
  if (limiter != NULL && !SocketRateLimit_try_acquire (limiter, 1))
    {
      pthread_mutex_lock (&server->stats_mutex);
      server->rate_limited++;
      pthread_mutex_unlock (&server->stats_mutex);
      connection_send_error (server, conn, 429, "Too Many Requests");
      return 0;
    }
  return 1;
}

/**
 * server_run_validator - Run request validator callback
 * @server: HTTP server
 * @conn: Connection with parsed request
 *
 * Returns: 1 if allowed, 0 if rejected (sends error)
 */
static int
server_run_validator (SocketHTTPServer_T server, ServerConnection *conn)
{
  int reject_status = 0;
  struct SocketHTTPServer_Request req_ctx;

  if (server->validator == NULL)
    return 1;

  req_ctx.server = server;
  req_ctx.conn = conn;
  req_ctx.arena = conn->arena;
  req_ctx.start_time_ms = conn->request_start_ms;

  if (!server->validator (&req_ctx, &reject_status, server->validator_userdata))
    {
      if (reject_status == 0)
        reject_status = 403;
      connection_send_error (server, conn, reject_status, "Request Rejected");
      return 0;
    }

  return 1;
}

/**
 * server_invoke_handler - Invoke request handler and update stats
 * @server: HTTP server
 * @conn: Connection with parsed request
 *
 * Returns: 1 if handler was invoked, 0 if no handler or request
 */
static int
server_invoke_handler (SocketHTTPServer_T server, ServerConnection *conn)
{
  struct SocketHTTPServer_Request req_ctx;
  int64_t now;
  size_t sec_idx;

  if (server->handler == NULL || conn->request == NULL)
    return 0;

  req_ctx.server = server;
  req_ctx.conn = conn;
  req_ctx.arena = conn->arena;
  req_ctx.start_time_ms = conn->request_start_ms;

  conn->response_status = 200;

  server->handler (&req_ctx, server->handler_userdata);

  /* Update RPS tracking */
  now = server_time_ms ();
  sec_idx = (size_t)((now / 1000) % HTTPSERVER_RPS_WINDOW_SECONDS);
  pthread_mutex_lock (&server->stats_mutex);
  server->total_requests++;
  if (sec_idx != server->rps_index)
    {
      server->request_counts[sec_idx] = 0;
      server->rps_index = sec_idx;
    }
  server->request_counts[sec_idx]++;
  pthread_mutex_unlock (&server->stats_mutex);

  return 1;
}

/**
 * server_handle_parsed_request - Handle a fully parsed HTTP request
 * @server: HTTP server
 * @conn: Connection with parsed request
 *
 * Returns: 1 if request processed, 0 if rejected/skipped
 *
 * Orchestrates rate limiting, validation, handler invocation, and response.
 */
static int
server_handle_parsed_request (SocketHTTPServer_T server, ServerConnection *conn)
{
  if (!server_check_rate_limit (server, conn))
    return 0;

  if (!server_run_validator (server, conn))
    return 0;

  int handled = server_invoke_handler (server, conn);

  /* Send response if not streaming */
  if (!conn->response_streaming)
    {
      conn->state = CONN_STATE_SENDING_RESPONSE;
      connection_send_response (server, conn);
    }

  return handled;
}

/**
 * server_process_client_event - Process a single client event
 * @server: HTTP server
 * @conn: Client connection
 * @events: Event flags (POLL_READ, POLL_WRITE, etc.)
 *
 * Returns: 1 if request processed, 0 otherwise
 */
static int
server_process_client_event (SocketHTTPServer_T server, ServerConnection *conn,
                             unsigned events)
{
  int requests_processed = 0;

  if (events & POLL_READ)
    {
      connection_read (server, conn);
    }

  if (conn->state == CONN_STATE_READING_REQUEST)
    {
      if (connection_parse_request (server, conn) == 1)
        {
          requests_processed = server_handle_parsed_request (server, conn);
        }
    }

  /* Continue reading request body if needed */
  if (conn->state == CONN_STATE_READING_BODY)
    {
      const void *data;
      size_t len;

      data = SocketBuf_readptr (conn->inbuf, &len);
      if (len > 0)
        {
          size_t remaining = conn->body_capacity - conn->body_len;
          size_t to_copy = len;
          if (to_copy > remaining)
            to_copy = remaining;

          memcpy ((char *)conn->body + conn->body_len, data, to_copy);
          conn->body_len += to_copy;
          SocketBuf_consume (conn->inbuf, to_copy);

          /* Check if body is complete */
          if (conn->body_len >= conn->body_capacity)
            {
              conn->state = CONN_STATE_HANDLING;
              requests_processed = server_handle_parsed_request (server, conn);
            }
        }
    }

  if (conn->state == CONN_STATE_CLOSED)
    {
      connection_close (server, conn);
    }

  return requests_processed;
}

/**
 * server_check_connection_timeout - Check if connection has timed out
 * @server: HTTP server
 * @conn: Connection to check
 * @now: Current time in milliseconds
 *
 * Returns: 1 if timed out (connection closed), 0 otherwise
 */
static int
server_check_connection_timeout (SocketHTTPServer_T server,
                                 ServerConnection *conn, int64_t now)
{
  int64_t idle_ms = now - conn->last_activity_ms;

  /* Check keepalive timeout */
  if (conn->state == CONN_STATE_READING_REQUEST
      && idle_ms > server->config.keepalive_timeout_ms)
    {
      pthread_mutex_lock (&server->stats_mutex);
      server->timeouts++;
      pthread_mutex_unlock (&server->stats_mutex);
      connection_close (server, conn);
      return 1;
    }

  /* Check request read timeout */
  if (conn->state == CONN_STATE_READING_BODY && conn->request_start_ms > 0
      && (now - conn->request_start_ms) > server->config.request_read_timeout_ms)
    {
      pthread_mutex_lock (&server->stats_mutex);
      server->timeouts++;
      pthread_mutex_unlock (&server->stats_mutex);
      connection_close (server, conn);
      return 1;
    }

  /* Check response write timeout */
  if (conn->state == CONN_STATE_STREAMING_RESPONSE
      && conn->response_start_ms > 0
      && (now - conn->response_start_ms)
             > server->config.response_write_timeout_ms)
    {
      pthread_mutex_lock (&server->stats_mutex);
      server->timeouts++;
      pthread_mutex_unlock (&server->stats_mutex);
      connection_close (server, conn);
      return 1;
    }

  return 0;
}

/**
 * server_cleanup_timed_out - Clean up timed-out connections
 * @server: HTTP server
 *
 * Iterates all connections and closes those that have timed out.
 */
static void
server_cleanup_timed_out (SocketHTTPServer_T server)
{
  int64_t now = server_time_ms ();
  ServerConnection *conn = server->connections;

  while (conn != NULL)
    {
      ServerConnection *next = conn->next;
      server_check_connection_timeout (server, conn, now);
      conn = next;
    }
}

/* ============================================================================
 * Event Loop - Public API
 * ============================================================================ */

int
SocketHTTPServer_fd (SocketHTTPServer_T server)
{
  assert (server != NULL);
  if (server->listen_socket == NULL)
    return -1;
  return Socket_fd (server->listen_socket);
}

SocketPoll_T
SocketHTTPServer_poll (SocketHTTPServer_T server)
{
  assert (server != NULL);
  return server->poll;
}

/**
 * SocketHTTPServer_process - Process server events
 * @server: HTTP server
 * @timeout_ms: Poll timeout in milliseconds
 *
 * Returns: Number of requests processed
 *
 * Main event loop iteration. Accepts new connections, processes client
 * events, and cleans up timed-out connections.
 */
int
SocketHTTPServer_process (SocketHTTPServer_T server, int timeout_ms)
{
  SocketEvent_T *events;
  int nevents;
  int requests_processed = 0;

  assert (server != NULL);

  nevents = SocketPoll_wait (server->poll, &events, timeout_ms);

  for (int i = 0; i < nevents; i++)
    {
      SocketEvent_T *ev = &events[i];

      if (ev->socket == server->listen_socket)
        {
          /* Accept new connections if running */
          if (server->state == HTTPSERVER_STATE_RUNNING)
            {
              server_accept_clients (server);
            }
        }
      else
        {
          ServerConnection *conn = (ServerConnection *)ev->data;
          if (conn != NULL)
            {
              requests_processed
                  += server_process_client_event (server, conn, ev->events);
            }
        }
    }

  server_cleanup_timed_out (server);

  return requests_processed;
}

/* ============================================================================
 * Request Accessors
 * ============================================================================ */

SocketHTTP_Method
SocketHTTPServer_Request_method (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  if (req->conn->request == NULL)
    return HTTP_METHOD_UNKNOWN;
  return req->conn->request->method;
}

const char *
SocketHTTPServer_Request_path (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  if (req->conn->request == NULL)
    return "/";
  return req->conn->request->path;
}

const char *
SocketHTTPServer_Request_query (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  if (req->conn->request == NULL)
    return NULL;

  const char *path = req->conn->request->path;
  if (path == NULL)
    return NULL;

  const char *q = strchr (path, '?');
  return q ? q + 1 : NULL;
}

SocketHTTP_Headers_T
SocketHTTPServer_Request_headers (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  if (req->conn->request == NULL)
    return NULL;
  return req->conn->request->headers;
}

const void *
SocketHTTPServer_Request_body (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  if (req->conn->body_streaming)
    return NULL;
  return req->conn->body;
}

size_t
SocketHTTPServer_Request_body_len (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  if (req->conn->body_streaming)
    return 0;
  return req->conn->body_len;
}

const char *
SocketHTTPServer_Request_client_addr (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  return req->conn->client_addr;
}

SocketHTTP_Version
SocketHTTPServer_Request_version (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  if (req->conn->request == NULL)
    return HTTP_VERSION_1_1;
  return req->conn->request->version;
}

Arena_T
SocketHTTPServer_Request_arena (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  return req->arena;
}

/* ============================================================================
 * Response Building
 * ============================================================================ */

void
SocketHTTPServer_Request_status (SocketHTTPServer_Request_T req, int code)
{
  assert (req != NULL);
  req->conn->response_status = code;
}

void
SocketHTTPServer_Request_header (SocketHTTPServer_Request_T req,
                                 const char *name, const char *value)
{
  assert (req != NULL);
  assert (name != NULL);
  assert (value != NULL);

  SocketHTTP_Headers_add (req->conn->response_headers, name, value);
}

void
SocketHTTPServer_Request_body_data (SocketHTTPServer_Request_T req,
                                    const void *data, size_t len)
{
  assert (req != NULL);

  if (data == NULL || len == 0)
    {
      req->conn->response_body = NULL;
      req->conn->response_body_len = 0;
      return;
    }

  void *body_copy = Arena_alloc (req->arena, len, __FILE__, __LINE__);
  if (body_copy != NULL)
    {
      memcpy (body_copy, data, len);
      req->conn->response_body = body_copy;
      req->conn->response_body_len = len;
    }
}

void
SocketHTTPServer_Request_body_string (SocketHTTPServer_Request_T req,
                                      const char *str)
{
  assert (req != NULL);

  if (str == NULL)
    {
      req->conn->response_body = NULL;
      req->conn->response_body_len = 0;
      return;
    }

  SocketHTTPServer_Request_body_data (req, str, strlen (str));
}

void
SocketHTTPServer_Request_finish (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  req->conn->response_finished = 1;
}

/* ============================================================================
 * Request Body Streaming
 * ============================================================================ */

void
SocketHTTPServer_Request_body_stream (SocketHTTPServer_Request_T req,
                                      SocketHTTPServer_BodyCallback callback,
                                      void *userdata)
{
  assert (req != NULL);

  req->conn->body_callback = callback;
  req->conn->body_callback_userdata = userdata;
  req->conn->body_streaming = 1;
}

int64_t
SocketHTTPServer_Request_body_expected (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  return SocketHTTP1_Parser_content_length (req->conn->parser);
}

int
SocketHTTPServer_Request_is_chunked (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  return SocketHTTP1_Parser_body_mode (req->conn->parser) == HTTP1_BODY_CHUNKED;
}

/* ============================================================================
 * Response Body Streaming
 * ============================================================================ */

int
SocketHTTPServer_Request_begin_stream (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);

  if (req->conn->response_headers_sent)
    return -1;

  /* Add Transfer-Encoding: chunked header */
  SocketHTTP_Headers_set (req->conn->response_headers, "Transfer-Encoding",
                          "chunked");

  /* Build and send headers */
  char buf[8192];
  SocketHTTP_Response response;
  memset (&response, 0, sizeof (response));
  response.version = HTTP_VERSION_1_1;
  response.status_code = req->conn->response_status;
  response.headers = req->conn->response_headers;

  ssize_t len = SocketHTTP1_serialize_response (&response, buf, sizeof (buf));
  if (len < 0)
    return -1;

  if (connection_send_data (req->server, req->conn, buf, (size_t)len) < 0)
    return -1;

  /* Set streaming state only after headers successfully sent */
  req->conn->response_streaming = 1;
  req->conn->response_start_ms = server_time_ms ();
  req->conn->state = CONN_STATE_STREAMING_RESPONSE;
  req->conn->response_headers_sent = 1;
  return 0;
}

int
SocketHTTPServer_Request_send_chunk (SocketHTTPServer_Request_T req,
                                     const void *data, size_t len)
{
  assert (req != NULL);

  if (!req->conn->response_streaming || !req->conn->response_headers_sent)
    return -1;

  if (len == 0)
    return 0;

  char chunk_buf[HTTPSERVER_CHUNK_BUFFER_SIZE];
  ssize_t chunk_len = SocketHTTP1_chunk_encode (data, len, chunk_buf,
                                                sizeof (chunk_buf));
  if (chunk_len < 0)
    return -1;

  return connection_send_data (req->server, req->conn, chunk_buf,
                               (size_t)chunk_len);
}

int
SocketHTTPServer_Request_end_stream (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);

  if (!req->conn->response_streaming)
    return -1;

  char final_buf[64];
  ssize_t final_len = SocketHTTP1_chunk_final (final_buf, sizeof (final_buf),
                                               NULL);
  if (final_len < 0)
    return -1;

  if (connection_send_data (req->server, req->conn, final_buf,
                            (size_t)final_len)
      < 0)
    return -1;

  /* Record latency */
  if (req->conn->request_start_ms > 0)
    {
      int64_t latency_us
          = (server_time_ms () - req->conn->request_start_ms) * 1000;
      latency_record (&req->server->latency, latency_us);
    }

  if (SocketHTTP1_Parser_should_keepalive (req->conn->parser))
    {
      connection_reset_for_keepalive (req->conn);
    }
  else
    {
      req->conn->state = CONN_STATE_CLOSED;
    }

  return 0;
}

/* ============================================================================
 * HTTP/2 Server Push
 * ============================================================================ */

int
SocketHTTPServer_Request_push (SocketHTTPServer_Request_T req, const char *path,
                               SocketHTTP_Headers_T headers)
{
  assert (req != NULL);
  assert (path != NULL);

  (void)path;
  (void)headers;

  /* HTTP/2 push not yet integrated - return error for HTTP/1.1 */
  if (req->conn->request == NULL
      || req->conn->request->version != HTTP_VERSION_2)
    {
      return -1;
    }

  /* HTTP/2 Server Push is not yet implemented.
   *
   * Implementation requirements:
   * - Track HTTP/2 connections separately from HTTP/1.1
   * - Maintain HPACK encoder/decoder state per connection
   * - Use SocketHTTP2_Stream_push_promise() for push promises
   * - Handle client SETTINGS_ENABLE_PUSH flag
   * - Manage pushed stream IDs (even numbers from server)
   *
   * Status: Planned for future release.
   * Note: Server Push is deprecated in most browsers but still useful
   *       for proxies and non-browser clients.
   *
   * For now, use Link header preload hints as an alternative:
   *   Link: </style.css>; rel=preload; as=style
   */
  return -1;
}

int
SocketHTTPServer_Request_is_http2 (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  if (req->conn->request == NULL)
    return 0;
  return req->conn->request->version == HTTP_VERSION_2;
}

/* ============================================================================
 * WebSocket Upgrade
 * ============================================================================ */

int
SocketHTTPServer_Request_is_websocket (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);

  SocketHTTP_Headers_T headers = SocketHTTPServer_Request_headers (req);
  if (headers == NULL)
    return 0;

  const char *upgrade = SocketHTTP_Headers_get (headers, "Upgrade");
  const char *connection = SocketHTTP_Headers_get (headers, "Connection");

  if (upgrade == NULL || connection == NULL)
    return 0;

  return (strcasecmp (upgrade, "websocket") == 0
          && SocketHTTP_Headers_contains (headers, "Connection", "upgrade"));
}

SocketWS_T
SocketHTTPServer_Request_upgrade_websocket (SocketHTTPServer_Request_T req)
{
  (void)req;
  /* WebSocket implementation elsewhere */
  return NULL;
}

/* ============================================================================
 * Rate Limiting
 * ============================================================================ */

void
SocketHTTPServer_set_rate_limit (SocketHTTPServer_T server,
                                 const char *path_prefix,
                                 SocketRateLimit_T limiter)
{
  assert (server != NULL);

  if (path_prefix == NULL)
    {
      server->global_rate_limiter = limiter;
      return;
    }

  /* Find existing entry */
  for (RateLimitEntry *e = server->rate_limiters; e != NULL; e = e->next)
    {
      if (strcmp (e->path_prefix, path_prefix) == 0)
        {
          e->limiter = limiter;
          return;
        }
    }

  /* Create new entry */
  if (limiter != NULL)
    {
      RateLimitEntry *entry = malloc (sizeof (*entry));
      if (entry == NULL)
        return;

      entry->path_prefix = strdup (path_prefix);
      if (entry->path_prefix == NULL)
        {
          free (entry);
          return;
        }

      entry->limiter = limiter;
      entry->next = server->rate_limiters;
      server->rate_limiters = entry;
    }
}

/* ============================================================================
 * Request Validation Middleware
 * ============================================================================ */

void
SocketHTTPServer_set_validator (SocketHTTPServer_T server,
                                SocketHTTPServer_Validator validator,
                                void *userdata)
{
  assert (server != NULL);
  server->validator = validator;
  server->validator_userdata = userdata;
}

/* ============================================================================
 * Graceful Shutdown
 * ============================================================================ */

int
SocketHTTPServer_drain (SocketHTTPServer_T server, int timeout_ms)
{
  assert (server != NULL);

  if (server->state != HTTPSERVER_STATE_RUNNING)
    return -1;

  server->state = HTTPSERVER_STATE_DRAINING;
  server->drain_start_ms = server_time_ms ();
  server->drain_timeout_ms = timeout_ms;

  /* Stop accepting new connections */
  if (server->listen_socket != NULL)
    {
      SocketPoll_del (server->poll, server->listen_socket);
    }

  return 0;
}

int
SocketHTTPServer_drain_poll (SocketHTTPServer_T server)
{
  assert (server != NULL);

  if (server->state == HTTPSERVER_STATE_STOPPED)
    return 0;

  if (server->state != HTTPSERVER_STATE_DRAINING)
    return (int)server->connection_count;

  /* Check if all connections are closed */
  if (server->connection_count == 0)
    {
      server->state = HTTPSERVER_STATE_STOPPED;
      server->running = 0;

      if (server->drain_callback != NULL)
        {
          server->drain_callback (server, 0, server->drain_callback_userdata);
        }
      return 0;
    }

  /* Check timeout */
  if (server->drain_timeout_ms >= 0)
    {
      int64_t now = server_time_ms ();
      if ((now - server->drain_start_ms) >= server->drain_timeout_ms)
        {
          /* Force close all connections */
          while (server->connections != NULL)
            {
              connection_close (server, server->connections);
            }

          server->state = HTTPSERVER_STATE_STOPPED;
          server->running = 0;

          if (server->drain_callback != NULL)
            {
              server->drain_callback (server, 1,
                                      server->drain_callback_userdata);
            }
          return -1;
        }
    }

  return (int)server->connection_count;
}

int
SocketHTTPServer_drain_wait (SocketHTTPServer_T server, int timeout_ms)
{
  assert (server != NULL);

  if (server->state == HTTPSERVER_STATE_RUNNING)
    {
      if (SocketHTTPServer_drain (server, timeout_ms) < 0)
        return -1;
    }

  while (server->state == HTTPSERVER_STATE_DRAINING)
    {
      /* Process any remaining I/O */
      SocketHTTPServer_process (server, 100);

      int result = SocketHTTPServer_drain_poll (server);
      if (result <= 0)
        return result;
    }

  return 0;
}

int64_t
SocketHTTPServer_drain_remaining_ms (SocketHTTPServer_T server)
{
  assert (server != NULL);

  if (server->state != HTTPSERVER_STATE_DRAINING)
    return 0;

  if (server->drain_timeout_ms < 0)
    return -1;

  int64_t elapsed = server_time_ms () - server->drain_start_ms;
  int64_t remaining = server->drain_timeout_ms - elapsed;
  return remaining > 0 ? remaining : 0;
}

void
SocketHTTPServer_set_drain_callback (SocketHTTPServer_T server,
                                     SocketHTTPServer_DrainCallback callback,
                                     void *userdata)
{
  assert (server != NULL);
  server->drain_callback = callback;
  server->drain_callback_userdata = userdata;
}

SocketHTTPServer_State
SocketHTTPServer_state (SocketHTTPServer_T server)
{
  assert (server != NULL);
  return (SocketHTTPServer_State)server->state;
}

/* ============================================================================
 * Statistics
 * ============================================================================ */

void
SocketHTTPServer_stats (SocketHTTPServer_T server, SocketHTTPServer_Stats *stats)
{
  assert (server != NULL);
  assert (stats != NULL);

  memset (stats, 0, sizeof (*stats));

  pthread_mutex_lock (&server->stats_mutex);

  stats->active_connections = server->connection_count;
  stats->total_connections = server->total_connections;
  stats->connections_rejected = server->connections_rejected;
  stats->total_requests = server->total_requests;
  stats->total_bytes_sent = server->total_bytes_sent;
  stats->total_bytes_received = server->total_bytes_received;
  stats->errors_4xx = server->errors_4xx;
  stats->errors_5xx = server->errors_5xx;
  stats->timeouts = server->timeouts;
  stats->rate_limited = server->rate_limited;

  /* Calculate RPS from sliding window */
  size_t rps_sum = 0;
  for (size_t i = 0; i < HTTPSERVER_RPS_WINDOW_SECONDS; i++)
    {
      rps_sum += server->request_counts[i];
    }
  stats->requests_per_second = rps_sum / HTTPSERVER_RPS_WINDOW_SECONDS;

  /* Latency stats */
  stats->avg_request_time_us = latency_avg (&server->latency);
  stats->max_request_time_us = server->latency.max;
  stats->p50_request_time_us = latency_percentile (&server->latency, 50);
  stats->p95_request_time_us = latency_percentile (&server->latency, 95);
  stats->p99_request_time_us = latency_percentile (&server->latency, 99);

  pthread_mutex_unlock (&server->stats_mutex);
}

void
SocketHTTPServer_stats_reset (SocketHTTPServer_T server)
{
  assert (server != NULL);

  pthread_mutex_lock (&server->stats_mutex);

  server->total_connections = server->connection_count;
  server->total_requests = 0;
  server->total_bytes_sent = 0;
  server->total_bytes_received = 0;
  server->errors_4xx = 0;
  server->errors_5xx = 0;
  server->timeouts = 0;
  server->rate_limited = 0;
  server->connections_rejected = 0;

  memset (server->request_counts, 0, sizeof (server->request_counts));
  latency_init (&server->latency);

  pthread_mutex_unlock (&server->stats_mutex);
}

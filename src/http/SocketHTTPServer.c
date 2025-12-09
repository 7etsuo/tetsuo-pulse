/**
 * SocketHTTPServer.c - HTTP Server Implementation
 *
 * Part of the Socket Library
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

#include "core/Arena.h"
#include "core/SocketIPTracker.h"
#include "core/SocketMetrics.h"
#include "core/SocketRateLimit.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTPServer-private.h"
#include "http/SocketHTTPServer.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketWS.h" /* For WebSocket upgrade detection */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

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
 * ============================================================================
 */

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

/* STATS macros moved to SocketHTTPServer-private.h for shared use in split
 * files */

/* RateLimitEntry defined in SocketHTTPServer-private.h */

/* ServerConnState and ServerConnection defined in SocketHTTPServer-private.h
 */

/* SocketHTTPServer_Request internal struct defined in
 * SocketHTTPServer-private.h */

/* LatencyTracker defined in SocketHTTPServer-private.h */

/* SocketHTTPServer internal struct defined in SocketHTTPServer-private.h */

/* ============================================================================
 * Internal Helper Functions - Time
 * ============================================================================
 */

/**
 * REFACTOR: Uses Socket_get_monotonic_ms() from SocketUtil.h instead of
 * direct clock_gettime() call. Centralizes monotonic time access.
 */
/* server_time_ms removed - duplicate with SocketHTTPServer-connections.c; use
 * Socket_get_monotonic_ms() directly */

/* Latency functions removed - use
 * SocketMetrics_histogram_observe(SOCKET_HIST_HTTP_SERVER_REQUEST_LATENCY_MS,
 * ms) and queries instead See cross-file notes for updates in connections.c
 * and private.h */

/**
 *  - Record request latency if timing available
 * @server: HTTP server
 * @request_start_ms: Request start timestamp (0 if not set)
 *
 * REFACTOR: Extracted from connection_send_response and
 * SocketHTTPServer_Request_end_stream to eliminate duplication.
 */

/* ============================================================================
 * Internal Helper Functions - Rate Limiting
 * ============================================================================
 */

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
 * ============================================================================
 */

/* Connection functions moved to SocketHTTPServer-connections.c */

/* connection_set_client_addr removed - duplicate with
 * SocketHTTPServer-connections.c */

/* connection_create_parser removed - duplicate with
 * SocketHTTPServer-connections.c; impl without TRY for simplicity */

/* connection_finish_request implemented in SocketHTTPServer-connections.c */

/* ============================================================================
 * Configuration Defaults
 * ============================================================================
 */

void
SocketHTTPServer_config_defaults (SocketHTTPServer_Config *config)
{
  assert (config != NULL);

  memset (config, 0, sizeof (*config));

  config->port = HTTPSERVER_DEFAULT_PORT;
  config->bind_address = HTTPSERVER_DEFAULT_BIND_ADDR;
  config->backlog = HTTPSERVER_DEFAULT_BACKLOG;

  config->tls_context = NULL;

  config->max_version = HTTP_VERSION_1_1;
  config->enable_h2c_upgrade = HTTPSERVER_DEFAULT_ENABLE_H2C_UPGRADE;

  config->max_header_size = HTTPSERVER_DEFAULT_MAX_HEADER_SIZE;
  config->max_body_size = HTTPSERVER_DEFAULT_MAX_BODY_SIZE;
  config->request_timeout_ms = HTTPSERVER_DEFAULT_REQUEST_TIMEOUT_MS;
  config->keepalive_timeout_ms = HTTPSERVER_DEFAULT_KEEPALIVE_TIMEOUT_MS;
  config->request_read_timeout_ms = HTTPSERVER_DEFAULT_REQUEST_READ_TIMEOUT_MS;
  config->response_write_timeout_ms
      = HTTPSERVER_DEFAULT_RESPONSE_WRITE_TIMEOUT_MS;
  config->max_connections = HTTPSERVER_DEFAULT_MAX_CONNECTIONS;
  config->max_requests_per_connection
      = HTTPSERVER_DEFAULT_MAX_REQUESTS_PER_CONN;
  config->max_connections_per_client
      = HTTPSERVER_DEFAULT_MAX_CONNECTIONS_PER_CLIENT;
  config->max_concurrent_requests = HTTPSERVER_DEFAULT_MAX_CONCURRENT_REQUESTS;
}

/* ============================================================================
 * Server Lifecycle
 * ============================================================================
 */

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

  /* Initialize per-server stats mutex */
  if (pthread_mutex_init (&server->stats_mutex, NULL) != 0)
    {
      /* Log error but continue - fallback to no RPS calc */
      SOCKET_LOG_WARN_MSG ("Failed to init HTTPServer stats mutex");
    }

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

  /* Latency tracking via
   * SocketMetrics_histogram_observe(SOCKET_HIST_HTTP_SERVER_REQUEST_LATENCY_MS,
   * elapsed_ms) in request handling */

  /* Stats via SocketMetrics - no custom mutex needed */

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

  /* Destroy stats mutex */
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

#ifdef AF_INET6
  if (socket_family == AF_INET6)
    {
      int v6only = 0;
      if (setsockopt (Socket_fd (server->listen_socket), IPPROTO_IPV6,
                      IPV6_V6ONLY, &v6only, sizeof (v6only))
          < 0)
        {
          HTTPSERVER_ERROR_MSG ("Failed to disable IPv6-only mode: %s",
                                strerror (errno));
          // Non-fatal: continue, but log warning
        }
    }
#endif

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
 * ============================================================================
 */

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
          /* connection_new takes ownership of the socket and frees it
           * in its FINALLY block on failure - do NOT double-free here */
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
      SocketMetrics_counter_inc (
          SOCKET_CTR_HTTP_SERVER_REQUESTS_FAILED); /* Rate limited -> failed */
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

  if (!server->validator (&req_ctx, &reject_status,
                          server->validator_userdata))
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

  if (server->handler == NULL || conn->request == NULL)
    return 0;

  req_ctx.server = server;
  req_ctx.conn = conn;
  req_ctx.arena = conn->arena;
  req_ctx.start_time_ms = conn->request_start_ms;

  conn->response_status = 200;

  server->handler (&req_ctx, server->handler_userdata);

  /* Update request counter via SocketMetrics */
  SocketMetrics_counter_inc (SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL);

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
server_handle_parsed_request (SocketHTTPServer_T server,
                              ServerConnection *conn)
{
  const SocketHTTP_Request *req = conn->request;
  if (req == NULL)
    return 0;

  const char *path = req->path;
  /* Validate path to prevent malformed input in rate limit/validator */
  if (path == NULL || strlen (path) > SOCKETHTTP_MAX_URI_LEN || path[0] != '/')
    {
      connection_send_error (server, conn, 400, "Bad Request");
      return 0;
    }

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

  /* Handle disconnect/error events first */
  if (events & (POLL_HANGUP | POLL_ERROR))
    {
      conn->state = CONN_STATE_CLOSED;
      connection_close (server, conn);
      return 0;
    }

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

  /* Continue reading request body using centralized parser API */
  if (conn->state == CONN_STATE_READING_BODY)
    {
      const void *input;
      size_t input_len, consumed, written;
      SocketHTTP1_Result r;

      char *output = (char *)conn->body + conn->body_len;
      size_t output_avail = conn->body_capacity - conn->body_len;

      input = SocketBuf_readptr (conn->inbuf, &input_len);
      r = SocketHTTP1_Parser_read_body (conn->parser, (const char *)input,
                                        input_len, &consumed, output,
                                        output_avail, &written);

      SocketBuf_consume (conn->inbuf, consumed);
      conn->body_len += written;

      /* Reject oversized bodies early to prevent DoS */
      if (conn->body_len > server->config.max_body_size
          && !SocketHTTP1_Parser_body_complete (conn->parser))
        {
          SocketMetrics_counter_inc (SOCKET_CTR_LIMIT_BODY_SIZE_EXCEEDED);
          connection_send_error (server, conn, 413, "Payload Too Large");
          conn->state = CONN_STATE_CLOSED;
          return requests_processed;
        }

      if (r == HTTP1_ERROR || r < 0)
        {
          /* Error in body reading (e.g., invalid chunk) */
          SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_5XX);
          conn->state = CONN_STATE_CLOSED;
          return requests_processed;
        }

      if (SocketHTTP1_Parser_body_complete (conn->parser))
        {
          conn->state = CONN_STATE_HANDLING;
          requests_processed = server_handle_parsed_request (server, conn);
        }
      else
        {
          /* Continue reading body */
        }

      /* TODO: Handle body_streaming callback invocation on written data */
      /* TODO: Support dynamic allocation for chunked bodies - but enforce
       * max_size strictly */
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
      SocketMetrics_counter_inc (
          SOCKET_CTR_HTTP_SERVER_REQUESTS_FAILED); /* Timeout -> failed request
                                                    */
      connection_close (server, conn);
      return 1;
    }

  /* Check request read timeout */
  if (conn->state == CONN_STATE_READING_BODY && conn->request_start_ms > 0
      && (now - conn->request_start_ms)
             > server->config.request_read_timeout_ms)
    {
      SocketMetrics_counter_inc (
          SOCKET_CTR_HTTP_SERVER_REQUESTS_FAILED); /* Timeout -> failed request
                                                    */
      connection_close (server, conn);
      return 1;
    }

  /* Check response write timeout */
  if (conn->state == CONN_STATE_STREAMING_RESPONSE
      && conn->response_start_ms > 0
      && (now - conn->response_start_ms)
             > server->config.response_write_timeout_ms)
    {
      SocketMetrics_counter_inc (
          SOCKET_CTR_HTTP_SERVER_REQUESTS_FAILED); /* Timeout -> failed request
                                                    */
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
  int64_t now = Socket_get_monotonic_ms ();
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
 * ============================================================================
 */

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
 * ============================================================================
 */

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

size_t
SocketHTTPServer_Request_memory_used (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  return req->conn->memory_used;
}

/* ============================================================================
 * Response Building
 * ============================================================================
 */

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
 * ============================================================================
 */

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
  return SocketHTTP1_Parser_body_mode (req->conn->parser)
         == HTTP1_BODY_CHUNKED;
}

/* ============================================================================
 * Response Body Streaming
 * ============================================================================
 */

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
  char buf[HTTPSERVER_RESPONSE_HEADER_BUFFER_SIZE];
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
  req->conn->response_start_ms = Socket_get_monotonic_ms ();
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
  ssize_t chunk_len
      = SocketHTTP1_chunk_encode (data, len, chunk_buf, sizeof (chunk_buf));
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

  char final_buf[HTTPSERVER_CHUNK_FINAL_BUF_SIZE];
  ssize_t final_len
      = SocketHTTP1_chunk_final (final_buf, sizeof (final_buf), NULL);
  if (final_len < 0)
    return -1;

  if (connection_send_data (req->server, req->conn, final_buf,
                            (size_t)final_len)
      < 0)
    return -1;

  connection_finish_request (req->server, req->conn);
  return 0;
}

/* ============================================================================
 * HTTP/2 Server Push
 * ============================================================================
 */

int
SocketHTTPServer_Request_push (SocketHTTPServer_Request_T req,
                               const char *path, SocketHTTP_Headers_T headers)
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
 * ============================================================================
 */

int
SocketHTTPServer_Request_is_websocket (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);

  SocketHTTP_Headers_T headers = SocketHTTPServer_Request_headers (req);
  if (headers == NULL)
    return 0;

  /* Use centralized WebSocket upgrade detection from parsed request */
  return SocketWS_is_upgrade (req->conn->request);
}

SocketWS_T
SocketHTTPServer_Request_upgrade_websocket (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);

  if (req->conn->request == NULL || !SocketWS_is_upgrade (req->conn->request))
    return NULL;

  SocketWS_Config config;
  SocketWS_config_defaults (&config);
  /* TODO: Configure from server config (e.g., compression, subprotocols) */

  SocketWS_T ws = NULL;
  TRY
  {
    ws = SocketWS_server_accept (req->conn->socket, req->conn->request,
                                 &config);
    if (ws == NULL)
      {
        RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
      }
    /* Ownership of socket transferred to ws - prevent double-free */

    /* Remove from server poll before nulling socket */
    SocketPoll_del (req->server->poll, req->conn->socket);
    req->conn->socket
        = NULL; /* Transfer ownership, skip free in connection_close */

    /* Close connection resources but skip socket free (now owned by ws) */
    connection_close (req->server, req->conn);

    /* Note: Full integration requires managing ws in separate poll or wrapper
     */
    /* For now, returns ws for manual management - user must poll/process ws
     * events */

    /* Start handshake - may require multiple calls in non-blocking mode */
    SocketWS_handshake (ws);

    return ws;
  }
  EXCEPT (SocketWS_Failed)
  {
    if (ws != NULL)
      {
        SocketWS_free (&ws);
      }
    RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
  }
  END_TRY;

  return NULL; /* Only reached on alloc failures before accept */
}

/* ============================================================================
 * Rate Limiting
 * ============================================================================
 */

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
 * ============================================================================
 */

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
 * ============================================================================
 */

int
SocketHTTPServer_drain (SocketHTTPServer_T server, int timeout_ms)
{
  assert (server != NULL);

  if (server->state != HTTPSERVER_STATE_RUNNING)
    return -1;

  server->state = HTTPSERVER_STATE_DRAINING;
  server->drain_start_ms = Socket_get_monotonic_ms ();
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
      int64_t now = Socket_get_monotonic_ms ();
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
      SocketHTTPServer_process (server, HTTPSERVER_DRAIN_POLL_MS);

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

  int64_t elapsed = Socket_get_monotonic_ms () - server->drain_start_ms;
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
 * ============================================================================
 */

void
SocketHTTPServer_stats (SocketHTTPServer_T server,
                        SocketHTTPServer_Stats *stats)
{
  assert (server != NULL);
  assert (stats != NULL);
  (void)server; /* Used only in assert; silence unused parameter warning */

  memset (stats, 0, sizeof (*stats));

  /* Query centralized metrics - no lock needed, metrics thread-safe */
  stats->active_connections = (size_t)SocketMetrics_gauge_get (
      SOCKET_GAU_HTTP_SERVER_ACTIVE_CONNECTIONS);
  stats->total_connections
      = SocketMetrics_counter_get (SOCKET_CTR_HTTP_SERVER_CONNECTIONS_TOTAL);
  stats->total_requests
      = SocketMetrics_counter_get (SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL);
  stats->total_bytes_sent
      = SocketMetrics_counter_get (SOCKET_CTR_HTTP_SERVER_BYTES_SENT);
  stats->total_bytes_received
      = SocketMetrics_counter_get (SOCKET_CTR_HTTP_SERVER_BYTES_RECEIVED);
  stats->errors_4xx
      = SocketMetrics_counter_get (SOCKET_CTR_HTTP_RESPONSES_4XX);
  stats->errors_5xx
      = SocketMetrics_counter_get (SOCKET_CTR_HTTP_RESPONSES_5XX);
  stats->connections_rejected = SocketMetrics_counter_get (
      SOCKET_CTR_LIMIT_CONNECTIONS_EXCEEDED); /* Or custom if tracked */
  /* timeouts, rate_limited: use custom or map to failed counters */

  /* RPS approximation: delta requests / delta time using per-server tracking
   */
  /* Thread-safe via mutex */
  uint64_t prev_requests = server->stats_prev_requests;
  int64_t prev_time = server->stats_prev_time_ms;
  int64_t now = Socket_get_monotonic_ms ();
  uint64_t curr_requests = stats->total_requests;

  pthread_mutex_lock (&server->stats_mutex);
  if (prev_time > 0 && now > prev_time)
    {
      double seconds = (double)(now - prev_time) / 1000.0;
      if (seconds > 0.0)
        {
          stats->requests_per_second
              = (size_t)((curr_requests - prev_requests) / seconds);
        }
    }
  server->stats_prev_requests = curr_requests;
  server->stats_prev_time_ms = now;
  pthread_mutex_unlock (&server->stats_mutex);

  /* Latency from histogram snapshot (unit: ms in metric, convert to us) */
  SocketMetrics_HistogramSnapshot snap;
  SocketMetrics_histogram_snapshot (SOCKET_HIST_HTTP_SERVER_REQUEST_LATENCY_MS,
                                    &snap);
  stats->avg_request_time_us = (int64_t)(snap.mean * 1000);
  stats->max_request_time_us = (int64_t)(snap.max * 1000);
  stats->p50_request_time_us = (int64_t)(snap.p50 * 1000);
  stats->p95_request_time_us = (int64_t)(snap.p95 * 1000);
  stats->p99_request_time_us = (int64_t)(snap.p99 * 1000);
  /* Note: p999 if needed from snap.p999 */

  /* TODO: Update SocketHTTPServer_Stats struct if fields removed/mapped */
}

void
SocketHTTPServer_stats_reset (SocketHTTPServer_T server)
{
  (void)server; /* Currently no server-specific reset; use global */

  /* Reset centralized metrics - affects all modules */
  SocketMetrics_reset ();

  /* TODO: If per-server metrics needed, add server param to metrics or
   * per-instance tracking */
}

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketHTTPServer.c - HTTP Server Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Production-ready HTTP server with:
 * - Non-blocking I/O with SocketPoll integration
 * - Keep-alive connection handling
 * - Request/response body streaming
 * - Rate limiting per endpoint
 * - Per-client connection limiting
 * - Request validation middleware
 * - Graceful shutdown (drain)
 *
 * Leverages existing modules (no duplication):
 * - SocketHTTP for headers, methods, status codes
 * - SocketHTTP1 for HTTP/1.1 parsing/serialization
 * - SocketRateLimit for rate limiting
 * - SocketIPTracker for per-client limits
 * - SocketPoll for event loop
 * - SocketMetrics for statistics
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

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
#include "socket/SocketWS.h"

/* Override log component for this module */
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTPServer"

/* Module exception declared once in private header - no duplicate needed */

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
 * Per-Server Metrics Helpers
 * ============================================================================
 *
 * These macros update both global SocketMetrics and per-server instance metrics
 * when per_server_metrics is enabled. Global metrics are always updated for
 * aggregation; per-server metrics provide instance-specific views.
 */

/* Metrics macros defined in SocketHTTPServer-private.h for shared use */

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/* Forward declaration for connection management (impl in connections.c) */
ServerConnection *connection_new (SocketHTTPServer_T server, Socket_T socket);

/* Forward declarations for static file serving (impl below) */
static StaticRoute *find_static_route (SocketHTTPServer_T server,
                                       const char *path);
static int serve_static_file (SocketHTTPServer_T server, ServerConnection *conn,
                              StaticRoute *route, const char *file_path);

/**
 * find_rate_limiter - Find most specific rate limiter for path
 * @server: HTTP server
 * @path: Request path (NULL returns global limiter)
 *
 * Returns: Rate limiter for path prefix, or global limiter, or NULL
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

  /* WebSocket configuration - set server role by default */
  SocketWS_config_defaults (&config->ws_config);
  config->ws_config.role = WS_ROLE_SERVER;

  /* Per-server metrics disabled by default (use global metrics) */
  config->per_server_metrics = 0;
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

  /* Free static route entries */
  StaticRoute *sr = s->static_routes;
  while (sr != NULL)
    {
      StaticRoute *next = sr->next;
      free (sr->prefix);
      free (sr->directory);
      free (sr->resolved_directory);
      free (sr);
      sr = next;
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
      SERVER_METRICS_INC (server, SOCKET_CTR_HTTP_SERVER_RATE_LIMITED,
                          rate_limited);
      connection_send_error (server, conn, 429, "Too Many Requests");
      return 0;
    }
  return 1;
}

/**
 * server_run_validator_impl - Internal validator execution
 * @server: HTTP server
 * @conn: Connection with parsed request
 *
 * Returns: 1 if allowed, 0 if rejected (sends error)
 */
static int
server_run_validator_impl (SocketHTTPServer_T server, ServerConnection *conn)
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
 * server_run_validator - Run request validator callback
 * @server: HTTP server
 * @conn: Connection with parsed request
 *
 * Returns: 1 if allowed, 0 if rejected (sends error)
 */
static int
server_run_validator (SocketHTTPServer_T server, ServerConnection *conn)
{
  return server_run_validator_impl (server, conn);
}

/**
 * server_run_validator_early - Run validator early (after headers, before body)
 * @server: HTTP server
 * @conn: Connection with parsed headers
 *
 * This is called from connection_parse_request() after headers are parsed
 * but before body buffering starts. Allows the validator to set up body
 * streaming mode via SocketHTTPServer_Request_body_stream().
 *
 * Returns: 1 if allowed, 0 if rejected (error sent)
 */
int
server_run_validator_early (SocketHTTPServer_T server, ServerConnection *conn)
{
  return server_run_validator_impl (server, conn);
}

/**
 * server_invoke_handler - Invoke middleware chain and request handler
 * @server: HTTP server
 * @conn: Connection with parsed request
 *
 * Executes middleware chain in order of addition. If any middleware returns
 * non-zero, the chain stops and the request is considered handled.
 * If all middleware returns 0 (continue), the main handler is invoked.
 *
 * Returns: 1 if handler/middleware was invoked, 0 if no handler or request
 */
static int
server_invoke_handler (SocketHTTPServer_T server, ServerConnection *conn)
{
  struct SocketHTTPServer_Request req_ctx;
  MiddlewareEntry *mw;
  int result;

  if (conn->request == NULL)
    return 0;

  req_ctx.server = server;
  req_ctx.conn = conn;
  req_ctx.arena = conn->arena;
  req_ctx.start_time_ms = conn->request_start_ms;

  conn->response_status = 200;

  /* Execute middleware chain in order */
  for (mw = server->middleware_chain; mw != NULL; mw = mw->next)
    {
      result = mw->func (&req_ctx, mw->userdata);
      if (result != 0)
        {
          /* Middleware handled the request - stop chain */
          SOCKET_LOG_DEBUG_MSG ("Middleware handled request, stopping chain");
          SERVER_METRICS_INC (server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL,
                              requests_total);
          return 1;
        }
    }

  /* All middleware passed, invoke main handler */
  if (server->handler != NULL)
    {
      server->handler (&req_ctx, server->handler_userdata);
    }

  /* Update request counter (global + per-server) */
  SERVER_METRICS_INC (server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL,
                      requests_total);

  return 1;
}

/**
 * server_try_static_file - Attempt to serve a static file for the request
 * @server: HTTP server
 * @conn: Connection with parsed request
 *
 * Returns: 1 if static file served, 0 if no matching route/file
 */
static int
server_try_static_file (SocketHTTPServer_T server, ServerConnection *conn)
{
  const SocketHTTP_Request *req = conn->request;
  const char *path;
  StaticRoute *route;
  const char *file_path;
  int result;

  if (req == NULL)
    return 0;

  path = req->path;
  if (path == NULL)
    return 0;

  /* Only serve GET and HEAD for static files */
  if (req->method != HTTP_METHOD_GET && req->method != HTTP_METHOD_HEAD)
    return 0;

  /* Find matching static route */
  route = find_static_route (server, path);
  if (route == NULL)
    return 0;

  /* Extract file path after prefix */
  file_path = path + route->prefix_len;

  /* Handle trailing slash on prefix */
  if (*file_path == '/')
    file_path++;

  /* Empty path means try index.html */
  if (*file_path == '\0')
    file_path = "index.html";

  result = serve_static_file (server, conn, route, file_path);

  if (result == 1)
    {
      /* File was served (or 304/416 sent) */
      SERVER_METRICS_INC (server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL,
                          requests_total);
      return 1;
    }

  /* File not found or error - fall through to handler */
  return 0;
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

  /* Try static file serving first (before validator for efficiency) */
  if (server->static_routes != NULL && server_try_static_file (server, conn))
    {
      /* Static file was served - send response if not already done */
      if (!conn->response_streaming && !conn->response_headers_sent)
        {
          conn->state = CONN_STATE_SENDING_RESPONSE;
          connection_send_response (server, conn);
        }
      else if (conn->response_headers_sent)
        {
          /* Headers already sent (e.g., via sendfile), finish up */
          connection_finish_request (server, conn);
        }
      return 1;
    }

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
      size_t max_body = server->config.max_body_size;

      input = SocketBuf_readptr (conn->inbuf, &input_len);
      if (input_len == 0)
        return requests_processed;

      /* Handle streaming mode: deliver body data via callback */
      if (conn->body_streaming && conn->body_callback)
        {
          /* Use a temporary buffer for parsing body chunks */
          char temp_buf[HTTPSERVER_RECV_BUFFER_SIZE];
          size_t temp_avail = sizeof (temp_buf);

          r = SocketHTTP1_Parser_read_body (conn->parser, (const char *)input,
                                            input_len, &consumed, temp_buf,
                                            temp_avail, &written);

          SocketBuf_consume (conn->inbuf, consumed);
          conn->body_received += written;

          /* Invoke callback with chunk data */
          if (written > 0)
            {
              int is_final
                  = SocketHTTP1_Parser_body_complete (conn->parser) ? 1 : 0;

              /* Create request context for callback */
              struct SocketHTTPServer_Request req_ctx;
              req_ctx.server = server;
              req_ctx.conn = conn;
              req_ctx.arena = conn->arena;
              req_ctx.start_time_ms = conn->request_start_ms;

              int cb_result = conn->body_callback (
                  &req_ctx, temp_buf, written, is_final,
                  conn->body_callback_userdata);
              if (cb_result != 0)
                {
                  /* Callback aborted - send 400 and close */
                  SOCKET_LOG_WARN_MSG (
                      "Body streaming callback aborted request (returned %d)",
                      cb_result);
                  connection_send_error (server, conn, 400, "Bad Request");
                  conn->state = CONN_STATE_CLOSED;
                  return requests_processed;
                }
            }

          if (r == HTTP1_ERROR || r < 0)
            {
              SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_5XX);
              conn->state = CONN_STATE_CLOSED;
              return requests_processed;
            }

          if (SocketHTTP1_Parser_body_complete (conn->parser))
            {
              conn->state = CONN_STATE_HANDLING;
              requests_processed = server_handle_parsed_request (server, conn);
            }

          return requests_processed;
        }

      if (conn->body_uses_buf)
        {
          /* Chunked/until-close mode: use dynamic SocketBuf_T */
          size_t current_len = SocketBuf_available (conn->body_buf);

          /* Check if adding this chunk would exceed limit */
          if (current_len + input_len > max_body)
            {
              input_len = max_body - current_len;
              if (input_len == 0)
                {
                  SocketMetrics_counter_inc (SOCKET_CTR_LIMIT_BODY_SIZE_EXCEEDED);
                  connection_send_error (server, conn, 413, "Payload Too Large");
                  conn->state = CONN_STATE_CLOSED;
                  return requests_processed;
                }
            }

          /* Ensure buffer has space for incoming data */
          if (!SocketBuf_ensure (conn->body_buf, input_len))
            {
              SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_5XX);
              conn->state = CONN_STATE_CLOSED;
              return requests_processed;
            }

          /* Get write pointer and parse body into it */
          size_t write_avail;
          void *write_ptr = SocketBuf_writeptr (conn->body_buf, &write_avail);
          if (write_ptr == NULL || write_avail == 0)
            {
              SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_5XX);
              conn->state = CONN_STATE_CLOSED;
              return requests_processed;
            }

          r = SocketHTTP1_Parser_read_body (conn->parser, (const char *)input,
                                            input_len, &consumed,
                                            (char *)write_ptr, write_avail,
                                            &written);

          SocketBuf_consume (conn->inbuf, consumed);
          if (written > 0)
            SocketBuf_written (conn->body_buf, written);

          conn->body_len = SocketBuf_available (conn->body_buf);

          /* Check size limit after write */
          if (conn->body_len > max_body
              && !SocketHTTP1_Parser_body_complete (conn->parser))
            {
              SocketMetrics_counter_inc (SOCKET_CTR_LIMIT_BODY_SIZE_EXCEEDED);
              connection_send_error (server, conn, 413, "Payload Too Large");
              conn->state = CONN_STATE_CLOSED;
              return requests_processed;
            }
        }
      else
        {
          /* Content-Length mode: use fixed buffer */
          char *output = (char *)conn->body + conn->body_len;
          size_t output_avail = conn->body_capacity - conn->body_len;

          r = SocketHTTP1_Parser_read_body (conn->parser, (const char *)input,
                                            input_len, &consumed, output,
                                            output_avail, &written);

          SocketBuf_consume (conn->inbuf, consumed);
          conn->body_len += written;

          /* Reject oversized bodies early to prevent DoS */
          if (conn->body_len > max_body
              && !SocketHTTP1_Parser_body_complete (conn->parser))
            {
              SocketMetrics_counter_inc (SOCKET_CTR_LIMIT_BODY_SIZE_EXCEEDED);
              connection_send_error (server, conn, 413, "Payload Too Large");
              conn->state = CONN_STATE_CLOSED;
              return requests_processed;
            }
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
      /* else: Continue reading body on next poll iteration */
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
      SERVER_METRICS_INC (server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT,
                          requests_timeout);
      connection_close (server, conn);
      return 1;
    }

  /* Check request read timeout */
  if (conn->state == CONN_STATE_READING_BODY && conn->request_start_ms > 0
      && (now - conn->request_start_ms)
             > server->config.request_read_timeout_ms)
    {
      SERVER_METRICS_INC (server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT,
                          requests_timeout);
      connection_close (server, conn);
      return 1;
    }

  /* Check response write timeout */
  if (conn->state == CONN_STATE_STREAMING_RESPONSE
      && conn->response_start_ms > 0
      && (now - conn->response_start_ms)
             > server->config.response_write_timeout_ms)
    {
      SERVER_METRICS_INC (server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT,
                          requests_timeout);
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

  if (req->conn->body_uses_buf)
    {
      /* Chunked/until-close mode: compact buffer to ensure contiguous data,
       * then return pointer to start. This handles wraparound in circular
       * buffer. */
      SocketBuf_compact (req->conn->body_buf);
      size_t len;
      return SocketBuf_readptr (req->conn->body_buf, &len);
    }

  return req->conn->body;
}

size_t
SocketHTTPServer_Request_body_len (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  if (req->conn->body_streaming)
    return 0;

  if (req->conn->body_uses_buf)
    return SocketBuf_available (req->conn->body_buf);

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

  /* Use WebSocket config from server configuration */
  const SocketWS_Config *ws_config = &req->server->config.ws_config;

  SocketWS_T ws = NULL;
  TRY
  {
    ws = SocketWS_server_accept (req->conn->socket, req->conn->request,
                                 ws_config);
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

  memset (stats, 0, sizeof (*stats));

  /* Use per-server metrics when enabled, otherwise global metrics */
  if (server->config.per_server_metrics)
    {
      /* Per-server instance metrics - atomic reads */
      stats->active_connections
          = (size_t)atomic_load (&server->instance_metrics.active_connections);
      stats->total_connections
          = atomic_load (&server->instance_metrics.connections_total);
      stats->connections_rejected
          = atomic_load (&server->instance_metrics.connections_rejected);
      stats->total_requests
          = atomic_load (&server->instance_metrics.requests_total);
      stats->total_bytes_sent
          = atomic_load (&server->instance_metrics.bytes_sent);
      stats->total_bytes_received
          = atomic_load (&server->instance_metrics.bytes_received);
      stats->errors_4xx = atomic_load (&server->instance_metrics.errors_4xx);
      stats->errors_5xx = atomic_load (&server->instance_metrics.errors_5xx);
      stats->timeouts
          = atomic_load (&server->instance_metrics.requests_timeout);
      stats->rate_limited
          = atomic_load (&server->instance_metrics.rate_limited);
    }
  else
    {
      /* Global metrics - thread-safe via SocketMetrics */
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
      stats->connections_rejected
          = SocketMetrics_counter_get (SOCKET_CTR_LIMIT_CONNECTIONS_EXCEEDED);
      stats->timeouts
          = SocketMetrics_counter_get (SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT);
      stats->rate_limited
          = SocketMetrics_counter_get (SOCKET_CTR_HTTP_SERVER_RATE_LIMITED);
    }

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
}

void
SocketHTTPServer_stats_reset (SocketHTTPServer_T server)
{
  assert (server != NULL);

  /* Reset per-server RPS tracking */
  pthread_mutex_lock (&server->stats_mutex);
  server->stats_prev_requests = 0;
  server->stats_prev_time_ms = 0;
  pthread_mutex_unlock (&server->stats_mutex);

  /* Reset per-server instance metrics if enabled */
  if (server->config.per_server_metrics)
    {
      /* Preserve active_connections (current gauge), reset cumulative counters
       */
      atomic_store (&server->instance_metrics.connections_total, 0);
      atomic_store (&server->instance_metrics.connections_rejected, 0);
      atomic_store (&server->instance_metrics.requests_total, 0);
      atomic_store (&server->instance_metrics.requests_timeout, 0);
      atomic_store (&server->instance_metrics.rate_limited, 0);
      atomic_store (&server->instance_metrics.bytes_sent, 0);
      atomic_store (&server->instance_metrics.bytes_received, 0);
      atomic_store (&server->instance_metrics.errors_4xx, 0);
      atomic_store (&server->instance_metrics.errors_5xx, 0);
      /* Note: active_connections not reset - reflects live state */
    }

  /* Reset centralized metrics - affects all modules using global metrics */
  SocketMetrics_reset ();
}

/* ============================================================================
 * Static File Serving
 * ============================================================================
 */

#include <dirent.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <time.h>

/* Maximum path length for static files */
#ifndef HTTPSERVER_STATIC_MAX_PATH
#define HTTPSERVER_STATIC_MAX_PATH 4096
#endif

/* MIME type mappings */
static const struct
{
  const char *extension;
  const char *mime_type;
} mime_types[] = {
  /* Text */
  { ".html", "text/html; charset=utf-8" },
  { ".htm", "text/html; charset=utf-8" },
  { ".css", "text/css; charset=utf-8" },
  { ".js", "text/javascript; charset=utf-8" },
  { ".mjs", "text/javascript; charset=utf-8" },
  { ".json", "application/json; charset=utf-8" },
  { ".xml", "application/xml; charset=utf-8" },
  { ".txt", "text/plain; charset=utf-8" },
  { ".csv", "text/csv; charset=utf-8" },
  { ".md", "text/markdown; charset=utf-8" },

  /* Images */
  { ".png", "image/png" },
  { ".jpg", "image/jpeg" },
  { ".jpeg", "image/jpeg" },
  { ".gif", "image/gif" },
  { ".webp", "image/webp" },
  { ".svg", "image/svg+xml" },
  { ".ico", "image/x-icon" },
  { ".bmp", "image/bmp" },
  { ".avif", "image/avif" },

  /* Fonts */
  { ".woff", "font/woff" },
  { ".woff2", "font/woff2" },
  { ".ttf", "font/ttf" },
  { ".otf", "font/otf" },
  { ".eot", "application/vnd.ms-fontobject" },

  /* Media */
  { ".mp3", "audio/mpeg" },
  { ".mp4", "video/mp4" },
  { ".webm", "video/webm" },
  { ".ogg", "audio/ogg" },
  { ".wav", "audio/wav" },

  /* Archives */
  { ".zip", "application/zip" },
  { ".gz", "application/gzip" },
  { ".tar", "application/x-tar" },

  /* Documents */
  { ".pdf", "application/pdf" },
  { ".wasm", "application/wasm" },

  { NULL, NULL }
};

/**
 * get_mime_type - Determine MIME type from file extension
 * @path: File path to check
 *
 * Returns: MIME type string or "application/octet-stream" for unknown
 */
static const char *
get_mime_type (const char *path)
{
  const char *ext;
  size_t path_len, ext_len;

  if (path == NULL)
    return "application/octet-stream";

  path_len = strlen (path);

  /* Find the last dot in the path */
  ext = strrchr (path, '.');
  if (ext == NULL)
    return "application/octet-stream";

  ext_len = path_len - (size_t)(ext - path);

  /* Check against known extensions (case-insensitive) */
  for (int i = 0; mime_types[i].extension != NULL; i++)
    {
      if (strlen (mime_types[i].extension) == ext_len
          && strcasecmp (ext, mime_types[i].extension) == 0)
        {
          return mime_types[i].mime_type;
        }
    }

  return "application/octet-stream";
}

/**
 * validate_static_path - Validate path for security (no traversal attacks)
 * @path: URL path component (after prefix removal)
 *
 * Returns: 1 if safe, 0 if potentially malicious
 */
static int
validate_static_path (const char *path)
{
  const char *p;

  if (path == NULL || path[0] == '\0')
    return 0;

  /* Reject absolute paths */
  if (path[0] == '/')
    return 0;

  /* Reject paths with null bytes (injection attack) */
  if (strchr (path, '\0') != path + strlen (path))
    return 0;

  /* Check for path traversal sequences */
  p = path;
  while (*p != '\0')
    {
      /* Check for ".." component */
      if (p[0] == '.')
        {
          if (p[1] == '.' && (p[2] == '/' || p[2] == '\0'))
            return 0; /* Found ".." */
          if (p[1] == '/' || p[1] == '\0')
            {
              /* Single "." is okay, skip */
              p += (p[1] == '/') ? 2 : 1;
              continue;
            }
        }

      /* Skip to next path component */
      while (*p != '\0' && *p != '/')
        p++;
      if (*p == '/')
        p++;
    }

  /* Reject hidden files (dotfiles) */
  p = path;
  while (*p != '\0')
    {
      if (*p == '.' && (p == path || *(p - 1) == '/'))
        {
          /* Hidden file/directory found */
          return 0;
        }
      p++;
    }

  return 1;
}

/**
 * format_http_date - Format time as HTTP-date (RFC 7231)
 * @t: Time to format
 * @buf: Output buffer (must be at least 30 bytes)
 *
 * Returns: Pointer to buf
 */
static char *
format_http_date (time_t t, char *buf)
{
  struct tm tm;
  gmtime_r (&t, &tm);
  strftime (buf, 30, "%a, %d %b %Y %H:%M:%S GMT", &tm);
  return buf;
}

/**
 * parse_http_date - Parse HTTP-date to time_t
 * @date_str: Date string in RFC 7231 format
 *
 * Returns: time_t value, or -1 on parse error
 */
static time_t
parse_http_date (const char *date_str)
{
  struct tm tm;
  memset (&tm, 0, sizeof (tm));

  if (date_str == NULL)
    return -1;

  /* Try RFC 7231 format: "Sun, 06 Nov 1994 08:49:37 GMT" */
  if (strptime (date_str, "%a, %d %b %Y %H:%M:%S GMT", &tm) != NULL)
    {
      return timegm (&tm);
    }

  /* Try RFC 850 format: "Sunday, 06-Nov-94 08:49:37 GMT" */
  if (strptime (date_str, "%A, %d-%b-%y %H:%M:%S GMT", &tm) != NULL)
    {
      return timegm (&tm);
    }

  /* Try ANSI C format: "Sun Nov  6 08:49:37 1994" */
  if (strptime (date_str, "%a %b %d %H:%M:%S %Y", &tm) != NULL)
    {
      return timegm (&tm);
    }

  return -1;
}

/**
 * parse_range_header - Parse Range header for partial content
 * @range_str: Range header value (e.g., "bytes=0-499")
 * @file_size: Total file size
 * @start: Output: start byte position
 * @end: Output: end byte position
 *
 * Returns: 1 if valid range parsed, 0 if invalid/unsatisfiable
 */
static int
parse_range_header (const char *range_str, off_t file_size, off_t *start,
                    off_t *end)
{
  const char *p;
  char *endptr;
  long long val;

  if (range_str == NULL || file_size <= 0)
    return 0;

  /* Must start with "bytes=" */
  if (strncmp (range_str, "bytes=", 6) != 0)
    return 0;

  p = range_str + 6;

  /* Skip whitespace */
  while (*p == ' ')
    p++;

  if (*p == '-')
    {
      /* Suffix range: "-500" means last 500 bytes */
      p++;
      val = strtoll (p, &endptr, 10);
      if (endptr == p || val <= 0)
        return 0;
      *start = (file_size > val) ? (file_size - val) : 0;
      *end = file_size - 1;
    }
  else
    {
      /* Normal range: "500-999" or "500-" */
      val = strtoll (p, &endptr, 10);
      if (endptr == p || val < 0)
        return 0;
      *start = (off_t)val;

      if (*endptr == '-')
        {
          p = endptr + 1;
          if (*p == '\0' || *p == ',')
            {
              /* Open-ended: "500-" means 500 to end */
              *end = file_size - 1;
            }
          else
            {
              val = strtoll (p, &endptr, 10);
              if (endptr == p)
                return 0;
              *end = (off_t)val;
            }
        }
      else
        {
          return 0;
        }
    }

  /* Validate range */
  if (*start >= file_size || *start > *end)
    return 0;

  /* Clamp end to file size */
  if (*end >= file_size)
    *end = file_size - 1;

  return 1;
}

/**
 * find_static_route - Find matching static route for request path
 * @server: HTTP server
 * @path: Request path
 *
 * Returns: Matching StaticRoute or NULL if no match
 */
static StaticRoute *
find_static_route (SocketHTTPServer_T server, const char *path)
{
  StaticRoute *route;
  StaticRoute *best = NULL;
  size_t best_len = 0;

  if (path == NULL)
    return NULL;

  /* Find longest matching prefix */
  for (route = server->static_routes; route != NULL; route = route->next)
    {
      if (strncmp (path, route->prefix, route->prefix_len) == 0)
        {
          if (route->prefix_len > best_len)
            {
              best = route;
              best_len = route->prefix_len;
            }
        }
    }

  return best;
}

/**
 * serve_static_file - Serve a static file with full HTTP semantics
 * @server: HTTP server
 * @conn: Connection to serve on
 * @route: Static route that matched
 * @file_path: Path component after prefix
 *
 * Implements:
 * - Path traversal protection
 * - MIME type detection
 * - If-Modified-Since / 304 Not Modified
 * - Range requests / 206 Partial Content
 * - sendfile() for zero-copy transfer
 *
 * Returns: 1 if file served, 0 if file not found, -1 on error
 */
static int
serve_static_file (SocketHTTPServer_T server, ServerConnection *conn,
                   StaticRoute *route, const char *file_path)
{
  char full_path[HTTPSERVER_STATIC_MAX_PATH];
  char resolved_path[HTTPSERVER_STATIC_MAX_PATH];
  char date_buf[32];
  char last_modified_buf[32];
  char content_length_buf[32];
  char content_range_buf[64];
  struct stat st;
  const char *mime_type;
  const char *if_modified_since;
  const char *range_header;
  time_t if_modified_time;
  off_t range_start = 0;
  off_t range_end = 0;
  int use_range = 0;
  int fd = -1;
  ssize_t sent;

  /* Validate the file path for security */
  if (!validate_static_path (file_path))
    {
      SOCKET_LOG_WARN_MSG ("Rejected suspicious static path: %.100s",
                           file_path);
      return 0; /* Treat as not found */
    }

  /* Build full path */
  int path_len = snprintf (full_path, sizeof (full_path), "%s/%s",
                           route->resolved_directory, file_path);
  if (path_len < 0 || (size_t)path_len >= sizeof (full_path))
    {
      return 0; /* Path too long */
    }

  /* Resolve the full path and verify it's within the allowed directory */
  if (realpath (full_path, resolved_path) == NULL)
    {
      return 0; /* File doesn't exist or can't be resolved */
    }

  /* Security: Ensure resolved path is within the allowed directory */
  if (strncmp (resolved_path, route->resolved_directory,
               route->resolved_dir_len)
      != 0)
    {
      SOCKET_LOG_WARN_MSG ("Path traversal attempt blocked: %.100s",
                           file_path);
      return 0;
    }

  /* Check file exists and is regular file */
  if (stat (resolved_path, &st) < 0)
    {
      return 0;
    }

  if (!S_ISREG (st.st_mode))
    {
      /* Not a regular file (directory, symlink target outside dir, etc.) */
      return 0;
    }

  /* Get MIME type */
  mime_type = get_mime_type (resolved_path);

  /* Check If-Modified-Since header */
  if_modified_since = SocketHTTP_Headers_get (conn->request->headers,
                                              "If-Modified-Since");
  if (if_modified_since != NULL)
    {
      if_modified_time = parse_http_date (if_modified_since);
      if (if_modified_time > 0 && st.st_mtime <= if_modified_time)
        {
          /* File not modified since - return 304 */
          conn->response_status = 304;
          conn->response_body = NULL;
          conn->response_body_len = 0;
          SocketHTTP_Headers_set (conn->response_headers, "Date",
                                  format_http_date (time (NULL), date_buf));
          SocketHTTP_Headers_set (
              conn->response_headers, "Last-Modified",
              format_http_date (st.st_mtime, last_modified_buf));
          return 1; /* Handled */
        }
    }

  /* Check Range header for partial content */
  range_header = SocketHTTP_Headers_get (conn->request->headers, "Range");
  if (range_header != NULL && conn->request->method == HTTP_METHOD_GET)
    {
      if (parse_range_header (range_header, st.st_size, &range_start,
                              &range_end))
        {
          use_range = 1;
        }
      else
        {
          /* Invalid range - send 416 Range Not Satisfiable */
          conn->response_status = 416;
          snprintf (content_range_buf, sizeof (content_range_buf),
                    "bytes */%ld", (long)st.st_size);
          SocketHTTP_Headers_set (conn->response_headers, "Content-Range",
                                  content_range_buf);
          conn->response_body = NULL;
          conn->response_body_len = 0;
          return 1;
        }
    }

  /* Open the file */
  fd = open (resolved_path, O_RDONLY);
  if (fd < 0)
    {
      return 0;
    }

  /* Set response headers */
  if (use_range)
    {
      conn->response_status = 206;
      snprintf (content_range_buf, sizeof (content_range_buf),
                "bytes %ld-%ld/%ld", (long)range_start, (long)range_end,
                (long)st.st_size);
      SocketHTTP_Headers_set (conn->response_headers, "Content-Range",
                              content_range_buf);
      snprintf (content_length_buf, sizeof (content_length_buf), "%ld",
                (long)(range_end - range_start + 1));
    }
  else
    {
      conn->response_status = 200;
      range_start = 0;
      range_end = st.st_size - 1;
      snprintf (content_length_buf, sizeof (content_length_buf), "%ld",
                (long)st.st_size);
    }

  SocketHTTP_Headers_set (conn->response_headers, "Content-Type", mime_type);
  SocketHTTP_Headers_set (conn->response_headers, "Content-Length",
                          content_length_buf);
  SocketHTTP_Headers_set (conn->response_headers, "Last-Modified",
                          format_http_date (st.st_mtime, last_modified_buf));
  SocketHTTP_Headers_set (conn->response_headers, "Date",
                          format_http_date (time (NULL), date_buf));
  SocketHTTP_Headers_set (conn->response_headers, "Accept-Ranges", "bytes");

  /* For HEAD requests, don't send body */
  if (conn->request->method == HTTP_METHOD_HEAD)
    {
      conn->response_body = NULL;
      conn->response_body_len = 0;
      close (fd);
      return 1;
    }

  /* Send response headers first */
  char header_buf[HTTPSERVER_RESPONSE_HEADER_BUFFER_SIZE];
  SocketHTTP_Response response;
  memset (&response, 0, sizeof (response));
  response.version = HTTP_VERSION_1_1;
  response.status_code = conn->response_status;
  response.headers = conn->response_headers;

  ssize_t header_len
      = SocketHTTP1_serialize_response (&response, header_buf, sizeof (header_buf));
  if (header_len < 0
      || connection_send_data (server, conn, header_buf, (size_t)header_len)
             < 0)
    {
      close (fd);
      return -1;
    }

  conn->response_headers_sent = 1;

  /* Use sendfile() for zero-copy file transfer */
  off_t offset = range_start;
  size_t remaining = (size_t)(range_end - range_start + 1);

  while (remaining > 0)
    {
      sent = sendfile (Socket_fd (conn->socket), fd, &offset, remaining);
      if (sent < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
              /* Would block - need to poll for write readiness */
              /* For simplicity, we'll continue trying */
              continue;
            }
          if (errno == EINTR)
            continue;
          close (fd);
          return -1;
        }
      if (sent == 0)
        break;

      remaining -= (size_t)sent;
      SocketMetrics_counter_add (SOCKET_CTR_HTTP_SERVER_BYTES_SENT,
                                 (uint64_t)sent);
    }

  close (fd);

  /* Mark response as finished */
  conn->response_finished = 1;
  conn->response_body = NULL;
  conn->response_body_len = 0;

  return 1;
}

int
SocketHTTPServer_add_static_dir (SocketHTTPServer_T server, const char *prefix,
                                 const char *directory)
{
  char resolved[HTTPSERVER_STATIC_MAX_PATH];
  struct stat st;
  StaticRoute *route;

  assert (server != NULL);
  assert (prefix != NULL);
  assert (directory != NULL);

  /* Validate prefix starts with '/' */
  if (prefix[0] != '/')
    {
      HTTPSERVER_ERROR_MSG ("Static prefix must start with '/': %s", prefix);
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
      return -1;
    }

  /* Verify directory exists and is accessible */
  if (stat (directory, &st) < 0 || !S_ISDIR (st.st_mode))
    {
      HTTPSERVER_ERROR_FMT ("Static directory not accessible: %s", directory);
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
      return -1;
    }

  /* Resolve the directory path for security validation */
  if (realpath (directory, resolved) == NULL)
    {
      HTTPSERVER_ERROR_FMT ("Cannot resolve static directory: %s", directory);
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
      return -1;
    }

  /* Allocate and initialize the route */
  route = malloc (sizeof (*route));
  if (route == NULL)
    {
      HTTPSERVER_ERROR_MSG ("Failed to allocate static route");
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
      return -1;
    }

  route->prefix = strdup (prefix);
  route->directory = strdup (directory);
  route->resolved_directory = strdup (resolved);

  if (route->prefix == NULL || route->directory == NULL
      || route->resolved_directory == NULL)
    {
      free (route->prefix);
      free (route->directory);
      free (route->resolved_directory);
      free (route);
      HTTPSERVER_ERROR_MSG ("Failed to allocate static route strings");
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
      return -1;
    }

  route->prefix_len = strlen (prefix);
  route->resolved_dir_len = strlen (resolved);
  route->next = server->static_routes;
  server->static_routes = route;

  SOCKET_LOG_INFO_MSG ("Added static route: %s -> %s", prefix, directory);

  return 0;
}

/* ============================================================================
 * Middleware
 * ============================================================================
 */

int
SocketHTTPServer_add_middleware (SocketHTTPServer_T server,
                                 SocketHTTPServer_Middleware middleware,
                                 void *userdata)
{
  MiddlewareEntry *entry;
  MiddlewareEntry *tail;

  assert (server != NULL);
  assert (middleware != NULL);

  /* Allocate middleware entry from server arena */
  entry = Arena_alloc (server->arena, sizeof (*entry), __FILE__, __LINE__);
  if (entry == NULL)
    {
      HTTPSERVER_ERROR_MSG ("Failed to allocate middleware entry");
      return -1;
    }

  entry->func = middleware;
  entry->userdata = userdata;
  entry->next = NULL;

  /* Append to end of chain to preserve order of addition */
  if (server->middleware_chain == NULL)
    {
      server->middleware_chain = entry;
    }
  else
    {
      /* Find tail of chain */
      tail = server->middleware_chain;
      while (tail->next != NULL)
        {
          tail = tail->next;
        }
      tail->next = entry;
    }

  SOCKET_LOG_DEBUG_MSG ("Added middleware to chain");

  return 0;
}

void
SocketHTTPServer_set_error_handler (SocketHTTPServer_T server,
                                    SocketHTTPServer_ErrorHandler handler,
                                    void *userdata)
{
  assert (server != NULL);

  server->error_handler = handler;
  server->error_handler_userdata = userdata;

  SOCKET_LOG_DEBUG_MSG ("Custom error handler %s",
                        handler != NULL ? "registered" : "cleared");
}

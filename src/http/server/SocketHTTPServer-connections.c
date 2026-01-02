/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketHTTPServer-connections.c - Connection management for HTTP/1.1 and
 * HTTP/2 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "core/SocketMetrics.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTPServer-http1.h"
#include "http/SocketHTTPServer-private.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketWS.h"
#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#endif

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTPServer);

static void
record_request_latency (SocketHTTPServer_T server, int64_t request_start_ms);
static SocketHTTP1_Parser_T
connection_create_parser (Arena_T arena, const SocketHTTPServer_Config *config);
static int
connection_add_to_server (SocketHTTPServer_T server, ServerConnection *conn);
static int setup_body_buffer_fixed (SocketHTTPServer_T server,
                                    ServerConnection *conn,
                                    size_t content_length,
                                    size_t max_body);
static int setup_body_buffer_dynamic (SocketHTTPServer_T server,
                                      ServerConnection *conn,
                                      size_t max_body);
static int connection_setup_body_buffer (SocketHTTPServer_T server,
                                         ServerConnection *conn);
static int connection_read_initial_body (SocketHTTPServer_T server,
                                         ServerConnection *conn);
static int connection_read_body_streaming (SocketHTTPServer_T server,
                                           ServerConnection *conn,
                                           const void *input,
                                           size_t input_len);
static int connection_read_body_chunked (SocketHTTPServer_T server,
                                         ServerConnection *conn,
                                         const void *input,
                                         size_t input_len);
static int connection_read_body_fixed (SocketHTTPServer_T server,
                                       ServerConnection *conn,
                                       const void *input,
                                       size_t input_len);
static void connection_reject_oversized_body (SocketHTTPServer_T server,
                                              ServerConnection *conn);
static size_t connection_check_body_size_limit (size_t max_body,
                                                size_t current_received,
                                                size_t input_len);

static void connection_init_request_ctx (SocketHTTPServer_T server,
                                         ServerConnection *conn,
                                         struct SocketHTTPServer_Request *ctx);
static void
connection_setup_tls (ServerConnection *conn, SocketTLSContext_T tls_context);

/* Read data from socket into connection buffer. Returns >0 bytes read, 0 on
 * EAGAIN, -1 on error/close */
int
connection_read (SocketHTTPServer_T server, ServerConnection *conn)
{
  char buf[HTTPSERVER_RECV_BUFFER_SIZE];
  volatile ssize_t n = 0;
  volatile int closed = 0;

  TRY
  {
    n = Socket_recv (conn->socket, buf, sizeof (buf));
  }
  EXCEPT (Socket_Closed)
  {
    closed = 1;
    n = 0;
  }
  END_TRY;

  /* Handle error/close first - early return to reduce nesting. */
  if (closed || n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK))
    {
      conn->state = CONN_STATE_CLOSED;
      return -1;
    }

  /* EAGAIN/EWOULDBLOCK on non-blocking socket */
  if (n <= 0)
    return 0;

  conn->last_activity_ms = Socket_get_monotonic_ms ();
  SERVER_METRICS_ADD (server,
                      SOCKET_CTR_HTTP_SERVER_BYTES_RECEIVED,
                      bytes_received,
                      (uint64_t)n);
  SocketBuf_write (conn->inbuf, buf, (size_t)n);

  return (int)n;
}

/* Send data over connection socket. Returns 0 on success, -1 on error */
int
connection_send_data (SocketHTTPServer_T server,
                      ServerConnection *conn,
                      const void *data,
                      size_t len)
{
  volatile int closed = 0;
  volatile ssize_t sent = 0;

  TRY
  {
    sent = Socket_sendall (conn->socket, data, len);
  }
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

  conn->last_activity_ms = Socket_get_monotonic_ms ();
  SERVER_METRICS_ADD (
      server, SOCKET_CTR_HTTP_SERVER_BYTES_SENT, bytes_sent, (uint64_t)sent);
  return 0;
}

/* Reset connection for next keep-alive request */
void
connection_reset_for_keepalive (ServerConnection *conn)
{
  conn->request_count++;
  SocketHTTP1_Parser_reset (conn->parser);
  SocketBuf_clear (conn->inbuf);
  SocketBuf_clear (conn->outbuf);

  if (conn->body_uses_buf && conn->body_buf != NULL)
    {
      SocketBuf_release (&conn->body_buf);
      conn->body_uses_buf = 0;
    }

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

/* Complete request processing. Records latency and either resets for keep-alive
 * or closes */
void
connection_finish_request (SocketHTTPServer_T server, ServerConnection *conn)
{
  record_request_latency (server, conn->request_start_ms);

  if (SocketHTTP1_Parser_should_keepalive (conn->parser))
    connection_reset_for_keepalive (conn);
  else
    conn->state = CONN_STATE_CLOSED;
}

/* Send 413 Payload Too Large and close connection */
static void
connection_reject_oversized_body (SocketHTTPServer_T server,
                                  ServerConnection *conn)
{
  SocketMetrics_counter_inc (SOCKET_CTR_LIMIT_BODY_SIZE_EXCEEDED);
  connection_send_error (server, conn, 413, "Payload Too Large");
  conn->state = CONN_STATE_CLOSED;
}

/* Check if incoming data would exceed body size limit. Returns safe process
 * length, or 0 if limit already reached */
static size_t
connection_check_body_size_limit (size_t max_body,
                                  size_t current_received,
                                  size_t input_len)
{
  if (max_body == 0)
    return input_len;

  uint64_t total;
  if (!socket_util_safe_add_u64 (current_received, input_len, &total)
      || total > max_body)
    {
      size_t remaining = max_body - current_received;
      return remaining;
    }

  return input_len;
}

static void
connection_init_request_ctx (SocketHTTPServer_T server,
                             ServerConnection *conn,
                             struct SocketHTTPServer_Request *ctx)
{
  ctx->server = server;
  ctx->conn = conn;
  ctx->h2_stream = NULL;
  ctx->arena = conn->arena;
  ctx->start_time_ms = conn->request_start_ms;
}

/* Setup body buffer for fixed Content-Length mode */
static int
setup_body_buffer_fixed (SocketHTTPServer_T server,
                         ServerConnection *conn,
                         size_t content_length,
                         size_t max_body)
{
  if (content_length > max_body)
    {
      connection_reject_oversized_body (server, conn);
      return -1;
    }

  conn->body_capacity = content_length;
  conn->body
      = Arena_alloc (conn->arena, conn->body_capacity, __FILE__, __LINE__);
  if (conn->body == NULL)
    {
      conn->state = CONN_STATE_CLOSED;
      return -1;
    }

  conn->memory_used += conn->body_capacity;
  return 0;
}

/* Setup body buffer for chunked/until-close mode */
static int
setup_body_buffer_dynamic (SocketHTTPServer_T server,
                           ServerConnection *conn,
                           size_t max_body)
{
  size_t initial_size = HTTPSERVER_CHUNKED_BODY_INITIAL_SIZE;

  (void)server;

  if (initial_size > max_body)
    initial_size = max_body;

  if (conn->body_uses_buf && conn->body_buf != NULL)
    {
      SocketBuf_release (&conn->body_buf);
      conn->body_uses_buf = 0;
    }

  conn->body_buf = SocketBuf_new (conn->arena, initial_size);
  if (conn->body_buf == NULL)
    {
      conn->state = CONN_STATE_CLOSED;
      return -1;
    }

  conn->body_uses_buf = 1;
  conn->body_capacity = max_body; /* Max allowed, not current capacity */
  conn->memory_used += initial_size;
  return 0;
}

/* Allocate body buffer: fixed size for Content-Length, dynamic SocketBuf for
 * chunked/until-close */
static int
connection_setup_body_buffer (SocketHTTPServer_T server, ServerConnection *conn)
{
  SocketHTTP1_BodyMode mode = SocketHTTP1_Parser_body_mode (conn->parser);
  int64_t cl = SocketHTTP1_Parser_content_length (conn->parser);
  size_t max_body = server->config.max_body_size;

  conn->body_uses_buf = 0;

  if (mode == HTTP1_BODY_CONTENT_LENGTH && cl > 0)
    return setup_body_buffer_fixed (server, conn, (size_t)cl, max_body);

  if (mode == HTTP1_BODY_CHUNKED || mode == HTTP1_BODY_UNTIL_CLOSE)
    return setup_body_buffer_dynamic (server, conn, max_body);

  return 0;
}

/* Handle streaming mode: deliver body data via callback. Returns 0 if more data
 * needed, 1 if complete, -1 on error */
static int
connection_read_body_streaming (SocketHTTPServer_T server,
                                ServerConnection *conn,
                                const void *input,
                                size_t input_len)
{
  char temp_buf[HTTPSERVER_RECV_BUFFER_SIZE];
  size_t temp_avail = sizeof (temp_buf);
  size_t max_body = server->config.max_body_size;
  size_t process_len = input_len;
  size_t body_consumed, written;
  SocketHTTP1_Result r;

  /* Check body size limit */
  process_len = connection_check_body_size_limit (
      max_body, conn->body_received, input_len);
  if (process_len == 0)
    {
      connection_reject_oversized_body (server, conn);
      return -1;
    }

  r = SocketHTTP1_Parser_read_body (conn->parser,
                                    (const char *)input,
                                    process_len,
                                    &body_consumed,
                                    temp_buf,
                                    temp_avail,
                                    &written);

  SocketBuf_consume (conn->inbuf, body_consumed);
  conn->body_received += written;

  /* Invoke callback with chunk data */
  if (written > 0)
    {
      int is_final = SocketHTTP1_Parser_body_complete (conn->parser) ? 1 : 0;

      /* Create request context for callback */
      struct SocketHTTPServer_Request req_ctx;
      connection_init_request_ctx (server, conn, &req_ctx);

      int cb_result = conn->body_callback (
          &req_ctx, temp_buf, written, is_final, conn->body_callback_userdata);
      if (cb_result != 0)
        {
          /* Callback aborted - send 400 and close */
          SOCKET_LOG_WARN_MSG (
              "Body streaming callback aborted request (returned %d)",
              cb_result);
          connection_send_error (server, conn, 400, "Bad Request");
          conn->state = CONN_STATE_CLOSED;
          return -1;
        }
    }

  if (r == HTTP1_ERROR)
    {
      conn->state = CONN_STATE_CLOSED;
      return -1;
    }

  if (!SocketHTTP1_Parser_body_complete (conn->parser))
    {
      conn->state = CONN_STATE_READING_BODY;
      return 0;
    }

  /* Body complete */
  return 1;
}

/* Handle chunked/until-close mode with dynamic buffer. Returns 0 if more data
 * needed, 1 if complete, -1 on error */
static int
connection_read_body_chunked (SocketHTTPServer_T server,
                              ServerConnection *conn,
                              const void *input,
                              size_t input_len)
{
  size_t max_body = server->config.max_body_size;
  size_t current_len = SocketBuf_available (conn->body_buf);
  size_t body_consumed, written;
  SocketHTTP1_Result r;

  /* Check if adding this chunk would exceed limit */
  uint64_t total;
  if (!socket_util_safe_add_u64 (current_len, input_len, &total)
      || total > max_body)
    {
      /* Only accept up to limit */
      input_len = max_body - current_len;
      if (input_len == 0)
        {
          connection_reject_oversized_body (server, conn);
          return -1;
        }
    }

  /* Ensure buffer has space for incoming data */
  if (!SocketBuf_ensure (conn->body_buf, input_len))
    {
      conn->state = CONN_STATE_CLOSED;
      return -1;
    }

  /* Get write pointer and parse body into it */
  size_t write_avail;
  void *write_ptr = SocketBuf_writeptr (conn->body_buf, &write_avail);
  if (write_ptr == NULL || write_avail == 0)
    {
      conn->state = CONN_STATE_CLOSED;
      return -1;
    }

  r = SocketHTTP1_Parser_read_body (conn->parser,
                                    (const char *)input,
                                    input_len,
                                    &body_consumed,
                                    (char *)write_ptr,
                                    write_avail,
                                    &written);

  SocketBuf_consume (conn->inbuf, body_consumed);
  if (written > 0)
    SocketBuf_written (conn->body_buf, written);

  conn->body_len = SocketBuf_available (conn->body_buf);

  if (r == HTTP1_ERROR)
    {
      conn->state = CONN_STATE_CLOSED;
      return -1;
    }

  if (!SocketHTTP1_Parser_body_complete (conn->parser))
    {
      conn->state = CONN_STATE_READING_BODY;
      return 0;
    }

  return 1;
}

/* Handle fixed Content-Length mode. Returns 0 if more data needed, 1 if
 * complete, -1 on error */
static int
connection_read_body_fixed (SocketHTTPServer_T server,
                            ServerConnection *conn,
                            const void *input,
                            size_t input_len)
{
  size_t max_body = server->config.max_body_size;
  size_t process_len = input_len;
  size_t body_consumed, written;
  SocketHTTP1_Result r;

  /* Check body size limit */
  process_len
      = connection_check_body_size_limit (max_body, conn->body_len, input_len);
  if (process_len == 0)
    {
      connection_reject_oversized_body (server, conn);
      return -1;
    }

  char *output = (char *)conn->body + conn->body_len;
  size_t output_avail = conn->body_capacity - conn->body_len;

  r = SocketHTTP1_Parser_read_body (conn->parser,
                                    (const char *)input,
                                    process_len,
                                    &body_consumed,
                                    output,
                                    output_avail,
                                    &written);

  SocketBuf_consume (conn->inbuf, body_consumed);
  conn->body_len += written;

  if (r == HTTP1_ERROR)
    {
      conn->state = CONN_STATE_CLOSED;
      return -1;
    }

  if (!SocketHTTP1_Parser_body_complete (conn->parser))
    {
      conn->state = CONN_STATE_READING_BODY;
      return 0;
    }

  return 1;
}

/* Read initial body data. Dispatches to appropriate handler based on mode.
 * Returns 0 if more data needed, 1 if complete, -1 on error */
static int
connection_read_initial_body (SocketHTTPServer_T server, ServerConnection *conn)
{
  const void *input;
  size_t input_len;

  input = SocketBuf_readptr (conn->inbuf, &input_len);
  if (input_len == 0)
    {
      conn->state = CONN_STATE_READING_BODY;
      return 0;
    }

  /* Dispatch to appropriate handler based on mode */
  if (conn->body_streaming && conn->body_callback)
    return connection_read_body_streaming (server, conn, input, input_len);
  else if (conn->body_uses_buf)
    return connection_read_body_chunked (server, conn, input, input_len);
  else
    return connection_read_body_fixed (server, conn, input, input_len);
}

/**
 * Execute HTTP/1.1 parser on buffered input.
 * Returns parser result via output params.
 */
static SocketHTTP1_Result
connection_execute_parser (ServerConnection *conn, int *need_more)
{
  const void *data;
  size_t len, consumed;

  data = SocketBuf_readptr (conn->inbuf, &len);
  if (len == 0)
    {
      *need_more = 1;
      return HTTP1_OK;
    }

  *need_more = 0;
  SocketHTTP1_Result result
      = SocketHTTP1_Parser_execute (conn->parser, data, len, &consumed);

  if (consumed > 0)
    SocketBuf_consume (conn->inbuf, consumed);

  return result;
}

/**
 * Handle request body setup after headers are complete.
 * Returns 0 need more data, 1 ready, -1 error.
 */
static int
connection_handle_body (SocketHTTPServer_T server, ServerConnection *conn)
{
  if (!conn->request->has_body)
    {
      conn->state = CONN_STATE_HANDLING;
      return 1;
    }

  if (!conn->body_streaming)
    {
      if (connection_setup_body_buffer (server, conn) < 0)
        return -1;

      if (conn->body_capacity > 0)
        {
          int body_result = connection_read_initial_body (server, conn);
          if (body_result <= 0)
            return body_result;
        }

      conn->state = CONN_STATE_HANDLING;
      return 1;
    }

  /* Streaming mode enabled by validator */
  int body_result = connection_read_initial_body (server, conn);
  if (body_result <= 0)
    return body_result;

  conn->state = CONN_STATE_HANDLING;
  return 1;
}

/* Parse HTTP request. Runs validator on headers complete, sets up body
 * handling. Returns 0 need more data, 1 ready, -1 error */
int
connection_parse_request (SocketHTTPServer_T server, ServerConnection *conn)
{
  int need_more;
  SocketHTTP1_Result result = connection_execute_parser (conn, &need_more);

  if (need_more)
    return 0;

  if (result == HTTP1_ERROR || result >= HTTP1_ERROR_LINE_TOO_LONG)
    {
      conn->state = CONN_STATE_CLOSED;
      return -1;
    }

  if (SocketHTTP1_Parser_state (conn->parser) < HTTP1_STATE_BODY)
    return 0;

  /* Headers complete - setup request handling */
  conn->request = SocketHTTP1_Parser_get_request (conn->parser);
  conn->body_mode = SocketHTTP1_Parser_body_mode (conn->parser);
  conn->request_start_ms = Socket_get_monotonic_ms ();

  if (!server_run_validator_early (server, conn))
    return -1;

  return connection_handle_body (server, conn);
}

/* Serialize and send HTTP response with headers and body */
void
connection_send_response (SocketHTTPServer_T server, ServerConnection *conn)
{
  char buf[HTTPSERVER_RESPONSE_HEADER_BUFFER_SIZE];
  ssize_t len;
  SocketHTTP_Response response;

  memset (&response, 0, sizeof (response));
  response.version = HTTP_VERSION_1_1;
  response.status_code = conn->response_status;
  response.headers = conn->response_headers;

  /* Track error metrics */
  if (conn->response_status >= 400 && conn->response_status < 500)
    {
      SERVER_METRICS_INC (server, SOCKET_CTR_HTTP_RESPONSES_4XX, errors_4xx);
    }
  else if (conn->response_status >= 500)
    {
      SERVER_METRICS_INC (server, SOCKET_CTR_HTTP_RESPONSES_5XX, errors_5xx);
    }

  /* Set Content-Length for non-streaming responses */
  if (conn->response_body_len <= 0 || conn->response_streaming)
    goto serialize_response;

  char cl[HTTPSERVER_CONTENT_LENGTH_BUF_SIZE];
  int ret = snprintf (cl, sizeof (cl), "%zu", conn->response_body_len);
  if (ret < 0 || ret >= (int)sizeof (cl))
    {
      /* Defensive check: should never happen with 32-byte buffer for
       * size_t, but handle gracefully if buffer size assumptions change. */
      conn->state = CONN_STATE_CLOSED;
      return;
    }
  SocketHTTP_Headers_set (conn->response_headers, "Content-Length", cl);

serialize_response:

  len = SocketHTTP1_serialize_response (&response, buf, sizeof (buf));
  if (len < 0)
    {
      conn->state = CONN_STATE_CLOSED;
      return;
    }

  if (connection_send_data (server, conn, buf, (size_t)len) < 0)
    return;

  if (conn->response_body != NULL && conn->response_body_len > 0)
    {
      if (connection_send_data (
              server, conn, conn->response_body, conn->response_body_len)
          < 0)
        return;
    }

  connection_finish_request (server, conn);
}

/* Send HTTP error response. Uses custom error handler if registered, otherwise
 * sends default text/plain */
void
connection_send_error (SocketHTTPServer_T server,
                       ServerConnection *conn,
                       int status,
                       const char *body)
{
  conn->response_status = status;

  /* If a custom error handler is registered, invoke it */
  if (server->error_handler != NULL)
    {
      struct SocketHTTPServer_Request req_ctx;
      connection_init_request_ctx (server, conn, &req_ctx);

      /* Handler is responsible for setting headers, body, and calling finish */
      server->error_handler (&req_ctx, status, server->error_handler_userdata);
      return;
    }

  /* Default error response: plain text with status message */
  if (body != NULL)
    {
      size_t len = strlen (body);
      char *copy = socket_util_arena_strndup (conn->arena, body, len);
      if (copy != NULL)
        {
          conn->response_body = copy;
          conn->response_body_len = len;
        }
      SocketHTTP_Headers_set (
          conn->response_headers, "Content-Type", "text/plain");
    }

  connection_send_response (server, conn);
}

/* Create HTTP/1.1 parser with server config limits */
static SocketHTTP1_Parser_T
connection_create_parser (Arena_T arena, const SocketHTTPServer_Config *config)
{
  SocketHTTP1_Config pcfg;
  SocketHTTP1_config_defaults (&pcfg);
  pcfg.max_header_size = config->max_header_size;

  SocketHTTP1_Parser_T p
      = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &pcfg, arena);
  if (p == NULL)
    RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);

  return p;
}

/* Record request latency to histogram */
static void
record_request_latency (SocketHTTPServer_T server, int64_t request_start_ms)
{
  (void)server;

  if (request_start_ms > 0)
    {
      int64_t elapsed_ms = Socket_get_monotonic_ms () - request_start_ms;
      SocketMetrics_histogram_observe (
          SOCKET_HIST_HTTP_SERVER_REQUEST_LATENCY_MS, (double)elapsed_ms);
    }
}

/* Add connection to server list and track IP for per-IP limits. Returns -1 if
 * IP limit exceeded */
static int
connection_add_to_server (SocketHTTPServer_T server, ServerConnection *conn)
{
  /* Track per-IP connections */
  if (server->ip_tracker != NULL && conn->client_addr[0] != '\0')
    {
      if (!SocketIPTracker_track (server->ip_tracker, conn->client_addr))
        {
          SERVER_METRICS_INC (server,
                              SOCKET_CTR_LIMIT_CONNECTIONS_EXCEEDED,
                              connections_rejected);
          return -1;
        }
    }

  /* Add to server's connection list */
  conn->next = server->connections;
  if (server->connections != NULL)
    server->connections->prev = conn;
  server->connections = conn;

  /* Update global + per-server metrics */
  SERVER_GAUGE_INC (
      server, SOCKET_GAU_HTTP_SERVER_ACTIVE_CONNECTIONS, active_connections);
  SERVER_METRICS_INC (
      server, SOCKET_CTR_HTTP_SERVER_CONNECTIONS_TOTAL, connections_total);

  return 0;
}

/* Clean up partially initialized connection */
static void
connection_cleanup_partial (ServerConnection *conn, int resources_initialized)
{
  if (resources_initialized && conn->arena != NULL)
    Arena_dispose (&conn->arena);
  if (conn->socket != NULL)
    Socket_free (&conn->socket);
  free (conn);
}

/* Configure TLS on connection socket. Sets up handshake state. Raises
 * exception if TLS requested but not available at compile time. */
static void
connection_setup_tls (ServerConnection *conn, SocketTLSContext_T tls_context)
{
#if SOCKET_HAS_TLS
  conn->tls_enabled = 1;
  conn->tls_handshake_done = 0;
  SocketTLS_enable (conn->socket, tls_context);
  conn->state = CONN_STATE_TLS_HANDSHAKE;
#else
  (void)conn;
  (void)tls_context;
  HTTPSERVER_ERROR_MSG ("TLS requested but SOCKET_HAS_TLS=0");
  RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
#endif
}

/* Allocate and initialize new connection. On failure, cleans up and closes
 * socket */
ServerConnection *
connection_new (SocketHTTPServer_T server, Socket_T socket)
{
  ServerConnection *volatile conn = NULL;
  volatile int resources_ok = 0;
  volatile int added_to_server = 0;

  conn = malloc (sizeof (*conn));
  if (conn == NULL)
    return NULL;

  memset (conn, 0, sizeof (*conn));

  TRY
  {
    /* Initialize connection resources: arena, buffers, parser. Enables TLS if
     * configured */
    Arena_T arena = Arena_new ();
    conn->arena = arena;
    conn->socket = socket;

    conn->state = CONN_STATE_READING_REQUEST;
    conn->created_at_ms = Socket_get_monotonic_ms ();
    conn->last_activity_ms = conn->created_at_ms;

    /* Cache client IP address from socket peer address */
    const char *addr = Socket_getpeeraddr (conn->socket);
    if (addr != NULL)
      {
        (void)socket_util_safe_strncpy (
            conn->client_addr, addr, sizeof (conn->client_addr));
      }

    conn->parser = connection_create_parser (arena, &server->config);
    conn->inbuf = SocketBuf_new (arena, HTTPSERVER_IO_BUFFER_SIZE);
    conn->outbuf = SocketBuf_new (arena, HTTPSERVER_IO_BUFFER_SIZE);
    conn->response_headers = SocketHTTP_Headers_new (arena);

    conn->memory_used = sizeof (*conn) + (2 * HTTPSERVER_IO_BUFFER_SIZE);

    /* Optional TLS enable: handshake is driven by server event loop. */
    if (server->config.tls_context != NULL)
      connection_setup_tls (conn, server->config.tls_context);

    resources_ok = 1;

    if (connection_add_to_server (server, conn) < 0)
      {
        connection_cleanup_partial (conn, 1);
        RETURN NULL;
      }
    added_to_server = 1;

    RETURN conn;
  }
  FINALLY
  {
    /* On exception, clean up if not successfully added to server */
    if (!added_to_server)
      connection_cleanup_partial (conn, resources_ok);
  }
  END_TRY;

  return NULL;
}

/**
 * Free WebSocket and HTTP/2 protocol-specific resources.
 */
static void
connection_close_protocols (ServerConnection *conn)
{
  if (conn->websocket != NULL)
    SocketWS_free (&conn->websocket);

  if (conn->http2_conn != NULL)
    SocketHTTP2_Conn_free (&conn->http2_conn);

  while (conn->http2_streams != NULL)
    {
      ServerHTTP2Stream *next = conn->http2_streams->next;
      if (conn->http2_streams->arena != NULL)
        Arena_dispose (&conn->http2_streams->arena);
      conn->http2_streams = next;
    }
}

/**
 * Close socket and remove from poll.
 */
static void
connection_close_socket (SocketHTTPServer_T server, ServerConnection *conn)
{
  if (server->ip_tracker != NULL && conn->client_addr[0] != '\0')
    SocketIPTracker_release (server->ip_tracker, conn->client_addr);

  if (server->poll != NULL && conn->socket != NULL)
    SocketPoll_del (server->poll, conn->socket);

  if (conn->socket != NULL)
    Socket_free (&conn->socket);
}

/**
 * Remove connection from server's linked list.
 */
static void
connection_unlink (SocketHTTPServer_T server, ServerConnection *conn)
{
  if (conn->prev != NULL)
    conn->prev->next = conn->next;
  else
    server->connections = conn->next;

  if (conn->next != NULL)
    conn->next->prev = conn->prev;

  conn->next = NULL;
  conn->prev = NULL;
}

/**
 * Release connection's allocated buffers and arena.
 */
static void
connection_release_resources (ServerConnection *conn)
{
  if (conn->body_uses_buf && conn->body_buf != NULL)
    {
      SocketBuf_release (&conn->body_buf);
      conn->body_uses_buf = 0;
    }

  if (conn->arena != NULL)
    Arena_dispose (&conn->arena);
}

/**
 * connection_close - Mark connection for deferred deletion
 *
 * Releases all resources (socket, arena, buffers) but defers the actual
 * free() until end of event loop iteration. This prevents use-after-free
 * when multiple events for the same connection arrive in a single poll
 * batch (common with io_uring multishot polls).
 *
 * Safe to call multiple times - subsequent calls are no-ops.
 */
void
connection_close (SocketHTTPServer_T server, ServerConnection *conn)
{
  if (conn == NULL || conn->pending_close)
    return;

  conn->pending_close = 1;

  connection_close_protocols (conn);
  connection_close_socket (server, conn);
  connection_unlink (server, conn);

  SERVER_GAUGE_DEC (
      server, SOCKET_GAU_HTTP_SERVER_ACTIVE_CONNECTIONS, active_connections);

  connection_release_resources (conn);

  conn->next_pending = server->pending_close_list;
  server->pending_close_list = conn;
}

/**
 * connection_free_pending - Free all connections marked for close
 *
 * Called at end of event loop iteration to actually free() connections
 * that were closed during event processing. This ensures no events
 * in the current batch can reference freed memory.
 */
void
connection_free_pending (SocketHTTPServer_T server)
{
  ServerConnection *conn = server->pending_close_list;
  while (conn != NULL)
    {
      ServerConnection *next = conn->next_pending;
      free (conn);
      conn = next;
    }
  server->pending_close_list = NULL;
}

/**
 * check_global_lifetime_timeout - Check global connection lifetime limit
 * @server: HTTP server
 * @conn: Connection to check
 * @now: Current time in milliseconds
 *
 * SECURITY: Defense-in-depth against connections held indefinitely.
 * Applies to all states. Set to 0 to disable.
 *
 * Returns: 1 if timed out (connection closed), 0 otherwise
 */
static int
check_global_lifetime_timeout (SocketHTTPServer_T server,
                               ServerConnection *conn,
                               int64_t now)
{
  if (server->config.max_connection_lifetime_ms <= 0)
    return 0;

  int64_t connection_age_ms = now - conn->created_at_ms;
  if (connection_age_ms > server->config.max_connection_lifetime_ms)
    {
      SOCKET_LOG_WARN_MSG (
          "Connection lifetime exceeded (%lld ms > %d ms), closing connection",
          (long long)connection_age_ms,
          server->config.max_connection_lifetime_ms);
      SERVER_METRICS_INC (
          server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT, requests_timeout);
      connection_close (server, conn);
      return 1;
    }
  return 0;
}

/**
 * check_tls_handshake_timeout - Check TLS handshake timeout
 * @server: HTTP server
 * @conn: Connection to check
 * @now: Current time in milliseconds
 *
 * SECURITY: Prevents slowloris attacks during TLS negotiation phase.
 *
 * Returns: 1 if timed out (connection closed), 0 otherwise
 */
static int
check_tls_handshake_timeout (SocketHTTPServer_T server,
                             ServerConnection *conn,
                             int64_t now)
{
  if (conn->state != CONN_STATE_TLS_HANDSHAKE)
    return 0;
  if (server->config.tls_handshake_timeout_ms <= 0)
    return 0;

  int64_t idle_ms = now - conn->last_activity_ms;
  if (idle_ms > server->config.tls_handshake_timeout_ms)
    {
      SOCKET_LOG_WARN_MSG (
          "TLS handshake timeout (%lld ms > %d ms), closing connection",
          (long long)idle_ms,
          server->config.tls_handshake_timeout_ms);
      SERVER_METRICS_INC (
          server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT, requests_timeout);
      connection_close (server, conn);
      return 1;
    }
  return 0;
}

/**
 * check_request_timeout - Check request parsing and body reading timeouts
 * @server: HTTP server
 * @conn: Connection to check
 * @now: Current time in milliseconds
 *
 * SECURITY: Prevents slowloris attacks where headers/body are sent slowly.
 *
 * Returns: 1 if timed out (connection closed), 0 otherwise
 */
static int
check_request_timeout (SocketHTTPServer_T server,
                       ServerConnection *conn,
                       int64_t now)
{
  int64_t idle_ms = now - conn->last_activity_ms;

  /* Keepalive timeout for idle connections */
  if (conn->state == CONN_STATE_READING_REQUEST
      && idle_ms > server->config.keepalive_timeout_ms)
    {
      SERVER_METRICS_INC (
          server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT, requests_timeout);
      connection_close (server, conn);
      return 1;
    }

  /* Header parsing timeout */
  if (conn->state == CONN_STATE_READING_REQUEST && conn->request_start_ms > 0
      && (now - conn->request_start_ms)
             > server->config.request_read_timeout_ms)
    {
      SOCKET_LOG_WARN_MSG (
          "Header parsing timeout (%lld ms > %d ms), closing connection",
          (long long)(now - conn->request_start_ms),
          server->config.request_read_timeout_ms);
      SERVER_METRICS_INC (
          server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT, requests_timeout);
      connection_close (server, conn);
      return 1;
    }

  /* Request body reading timeout */
  if (conn->state == CONN_STATE_READING_BODY && conn->request_start_ms > 0
      && (now - conn->request_start_ms)
             > server->config.request_read_timeout_ms)
    {
      SERVER_METRICS_INC (
          server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT, requests_timeout);
      connection_close (server, conn);
      return 1;
    }

  return 0;
}

/**
 * check_response_timeout - Check response write timeout
 * @server: HTTP server
 * @conn: Connection to check
 * @now: Current time in milliseconds
 *
 * Returns: 1 if timed out (connection closed), 0 otherwise
 */
static int
check_response_timeout (SocketHTTPServer_T server,
                        ServerConnection *conn,
                        int64_t now)
{
  if (conn->state != CONN_STATE_STREAMING_RESPONSE)
    return 0;
  if (conn->response_start_ms <= 0)
    return 0;

  if ((now - conn->response_start_ms)
      > server->config.response_write_timeout_ms)
    {
      SERVER_METRICS_INC (
          server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT, requests_timeout);
      connection_close (server, conn);
      return 1;
    }
  return 0;
}

/**
 * check_http2_timeout - Check HTTP/2 idle connection timeout
 * @server: HTTP server
 * @conn: Connection to check
 * @now: Current time in milliseconds
 *
 * SECURITY: Prevents resource exhaustion from idle HTTP/2 connections.
 *
 * Returns: 1 if timed out (connection closed), 0 otherwise
 */
static int
check_http2_timeout (SocketHTTPServer_T server,
                     ServerConnection *conn,
                     int64_t now)
{
  if (conn->state != CONN_STATE_HTTP2)
    return 0;

  int64_t idle_ms = now - conn->last_activity_ms;
  if (idle_ms > server->config.keepalive_timeout_ms)
    {
      SOCKET_LOG_WARN_MSG ("HTTP/2 connection idle timeout (%lld ms > %d ms), "
                           "closing connection",
                           (long long)idle_ms,
                           server->config.keepalive_timeout_ms);
      SERVER_METRICS_INC (
          server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT, requests_timeout);
      connection_close (server, conn);
      return 1;
    }
  return 0;
}

/**
 * server_check_connection_timeout - Check if connection has timed out
 * @server: HTTP server
 * @conn: Connection to check
 * @now: Current time in milliseconds
 *
 * SECURITY: Enhanced timeout enforcement to prevent Slowloris attacks
 * - TLS handshake timeout (CONN_STATE_TLS_HANDSHAKE)
 * - HTTP/2 idle connection timeout (CONN_STATE_HTTP2)
 * - Header parsing timeout (CONN_STATE_READING_REQUEST with partial data)
 * - Global connection lifetime limit (defense-in-depth)
 *
 * Returns: 1 if timed out (connection closed), 0 otherwise
 */
int
server_check_connection_timeout (SocketHTTPServer_T server,
                                 ServerConnection *conn,
                                 int64_t now)
{
  if (check_global_lifetime_timeout (server, conn, now))
    return 1;
  if (check_tls_handshake_timeout (server, conn, now))
    return 1;
  if (check_request_timeout (server, conn, now))
    return 1;
  if (check_response_timeout (server, conn, now))
    return 1;
  if (check_http2_timeout (server, conn, now))
    return 1;

  return 0;
}

#if SOCKET_HAS_TLS
/**
 * select_protocol_after_handshake - Select HTTP protocol after TLS handshake
 * @server: HTTP server
 * @conn: Connection with completed TLS handshake
 *
 * Determines protocol (HTTP/2 or HTTP/1.1) based on ALPN negotiation,
 * enables the selected protocol, and transitions connection state.
 *
 * Returns: 0 on success, -1 on error
 */
int
select_protocol_after_handshake (SocketHTTPServer_T server,
                                 ServerConnection *conn)
{
  const char *alpn;

  assert (server != NULL);
  assert (conn != NULL);
  assert (conn->tls_handshake_done);

  /* Decide protocol by ALPN. If not negotiated, fall back to HTTP/1.1. */
  alpn = SocketTLS_get_alpn_selected (conn->socket);
  if (alpn != NULL && strcmp (alpn, "h2") == 0
      && server->config.max_version >= HTTP_VERSION_2)
    {
      /* Enable HTTP/2 - use early return to reduce nesting. */
      if (server_http2_enable (server, conn) < 0)
        {
          conn->state = CONN_STATE_CLOSED;
          return -1;
        }
      conn->is_http2 = 1;
      conn->state = CONN_STATE_HTTP2;
      SocketPoll_mod (server->poll, conn->socket, POLL_READ | POLL_WRITE, conn);
    }
  else
    {
      conn->is_http2 = 0;
      conn->state = CONN_STATE_READING_REQUEST;
      SocketPoll_mod (server->poll, conn->socket, POLL_READ, conn);
    }

  return 0;
}

/**
 * server_process_tls_handshake - Process TLS handshake for connection
 * @server: HTTP server
 * @conn: Connection in TLS handshake state
 * @events: Poll events (unused, handshake determines next step)
 *
 * Continues TLS handshake, transitioning to HTTP/2 or HTTP/1.1 on completion.
 *
 * Returns: 0 on success (handshake continuing or complete), -1 on error
 */
static int
server_process_tls_handshake (SocketHTTPServer_T server,
                              ServerConnection *conn,
                              unsigned events)
{
  volatile TLSHandshakeState hs = TLS_HANDSHAKE_NOT_STARTED;

  (void)events;

  assert (server != NULL);
  assert (conn != NULL);

  TRY
  {
    hs = SocketTLS_handshake (conn->socket);
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    conn->state = CONN_STATE_CLOSED;
    return -1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    conn->state = CONN_STATE_CLOSED;
    return -1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    conn->state = CONN_STATE_CLOSED;
    return -1;
  }
  END_TRY;

  if (hs == TLS_HANDSHAKE_COMPLETE)
    {
      conn->tls_handshake_done = 1;
      return select_protocol_after_handshake (server, conn);
    }

  /* Continue handshake: narrow poll interest to avoid busy loops. */
  if (hs == TLS_HANDSHAKE_WANT_READ)
    SocketPoll_mod (server->poll, conn->socket, POLL_READ, conn);
  else if (hs == TLS_HANDSHAKE_WANT_WRITE)
    SocketPoll_mod (server->poll, conn->socket, POLL_WRITE, conn);
  else
    SocketPoll_mod (server->poll, conn->socket, POLL_READ | POLL_WRITE, conn);

  return 0;
}
#endif

/**
 * server_process_websocket - Process WebSocket connection events
 * @server: HTTP server
 * @conn: WebSocket connection
 * @events: Poll events
 *
 * Processes WebSocket I/O and delivers received messages via callback.
 *
 * Returns: 0 on success, -1 on error (connection should be closed)
 */
static int
server_process_websocket (SocketHTTPServer_T server,
                          ServerConnection *conn,
                          unsigned events)
{
  volatile int status = 0;

  assert (server != NULL);
  assert (conn != NULL);
  assert (conn->websocket != NULL);

  TRY
  {
    status = SocketWS_process (conn->websocket, events);
  }
  EXCEPT (SocketWS_Failed)
  {
    return -1;
  }
  EXCEPT (SocketWS_ProtocolError)
  {
    return -1;
  }
  EXCEPT (SocketWS_Closed)
  {
    return -1;
  }
  END_TRY;

  if (status < 0)
    return -1;

  /* Process received messages via callback */
  while (SocketWS_recv_available (conn->websocket) > 0)
    {
      SocketWS_Message msg;
      int result = SocketWS_recv_message (conn->websocket, &msg);
      if (result > 0 && conn->ws_callback != NULL)
        {
          int is_final
              = (SocketWS_state (conn->websocket) == WS_STATE_CLOSING
                 || SocketWS_state (conn->websocket) == WS_STATE_CLOSED)
                    ? 1
                    : 0;
          conn->ws_callback (
              NULL, msg.data, msg.len, is_final, conn->ws_callback_userdata);
          free (msg.data);
        }
      else if (result <= 0)
        {
          return -1;
        }
    }

  /* Check if connection closed */
  if (SocketWS_state (conn->websocket) == WS_STATE_CLOSED)
    return -1;

  /* Update poll events */
  unsigned ws_events = SocketWS_poll_events (conn->websocket);
  SocketPoll_mod (server->poll, conn->socket, ws_events, conn);

  return 0;
}

/**
 * server_process_client_event - Process a single client event
 * @server: HTTP server
 * @conn: Client connection
 * @events: Event flags (POLL_READ, POLL_WRITE, etc.)
 *
 * Main event dispatcher for client connections. Routes events to appropriate
 * protocol handler based on connection state.
 *
 * Returns: 1 if request processed, 0 otherwise
 */
int
server_process_client_event (SocketHTTPServer_T server,
                             ServerConnection *conn,
                             unsigned events)
{
  int requests_processed = 0;

  if (server_try_http2_prior_knowledge (server, conn, events))
    return 0;

  /* Handle disconnect/error events first */
  if (events & (POLL_HANGUP | POLL_ERROR))
    {
      conn->state = CONN_STATE_CLOSED;
      connection_close (server, conn);
      return 0;
    }

  if (events & POLL_READ)
    {
      /* TLS handshake, HTTP/2, and WebSocket handle their own I/O.
       * Only read into HTTP/1.1 buffer for request parsing states. */
      if (conn->state != CONN_STATE_TLS_HANDSHAKE
          && conn->state != CONN_STATE_HTTP2
          && conn->state != CONN_STATE_WEBSOCKET)
        connection_read (server, conn);
    }

  if (conn->state == CONN_STATE_TLS_HANDSHAKE)
    {
#if SOCKET_HAS_TLS
      if (server_process_tls_handshake (server, conn, events) < 0)
        conn->state = CONN_STATE_CLOSED;
#else
      conn->state = CONN_STATE_CLOSED;
#endif
    }

  if (conn->state == CONN_STATE_HTTP2)
    {
      if (server_process_http2 (server, conn, events) < 0)
        conn->state = CONN_STATE_CLOSED;
      if (conn->state == CONN_STATE_CLOSED)
        {
          connection_close (server, conn);
        }
      return 0;
    }

  if (conn->state == CONN_STATE_WEBSOCKET)
    {
      if (server_process_websocket (server, conn, events) < 0)
        conn->state = CONN_STATE_CLOSED;
      if (conn->state == CONN_STATE_CLOSED)
        {
          connection_close (server, conn);
        }
      return 0;
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
      int result = server_process_body_reading (server, conn);
      if (result > 0)
        requests_processed = result;
    }

  if (conn->state == CONN_STATE_CLOSED)
    {
      connection_close (server, conn);
    }

  return requests_processed;
}

void
connection_transition_to_websocket (SocketHTTPServer_T server,
                                    ServerConnection *conn,
                                    SocketWS_T ws,
                                    SocketHTTPServer_BodyCallback callback,
                                    void *userdata)
{
  conn->websocket = ws;
  conn->ws_callback = callback;
  conn->ws_callback_userdata = userdata;
  conn->response_streaming = 1;
  conn->state = CONN_STATE_WEBSOCKET;

  unsigned ws_events = SocketWS_poll_events (ws);
  SocketPoll_mod (server->poll, conn->socket, ws_events, conn);
}

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketHTTPServer-connections.c - Connection Management Implementation
 *
 * Part of the Socket Library
 *
 * Handles individual HTTP connection lifecycle, I/O, parsing, response
 * sending.
 *
 * Following C Interfaces and Implementations patterns
 */

#include <stdlib.h>
#include <string.h>

#include "core/SocketMetrics.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTPServer-private.h"
#include "socket/Socket.h"

/* ============================================================================
 * Internal Helper Declarations
 * ============================================================================
 */

static void record_request_latency (SocketHTTPServer_T server,
                                    int64_t request_start_ms);
static void connection_set_client_addr (ServerConnection *conn);
static SocketHTTP1_Parser_T connection_create_parser (Arena_T arena,
                                                      const SocketHTTPServer_Config *config);
static int connection_init_resources (SocketHTTPServer_T server,
                                      ServerConnection *conn,
                                      Socket_T socket);
static int connection_add_to_server (SocketHTTPServer_T server,
                                     ServerConnection *conn);
static int connection_setup_body_buffer (SocketHTTPServer_T server,
                                         ServerConnection *conn);
static int connection_read_initial_body (SocketHTTPServer_T server,
                                         ServerConnection *conn);
static void connection_reject_oversized_body (SocketHTTPServer_T server,
                                              ServerConnection *conn);
/* Non-static - used from SocketHTTPServer.c */
void connection_send_error (SocketHTTPServer_T server,
                            ServerConnection *conn,
                            int status_code,
                            const char *reason);

/* Forward declaration for public helper used before definition */
void connection_send_error (SocketHTTPServer_T server, ServerConnection *conn,
                            int status, const char *body);

/* ============================================================================
 * Connection I/O
 * ============================================================================
 */

/**
 * connection_read - Read data from connection socket into buffer
 * @server: HTTP server (unused, kept for API consistency)
 * @conn: Connection to read from
 *
 * Returns: >0 bytes read, 0 on would-block, -1 on error/close
 */
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

  if (closed || n <= 0)
    {
      if (closed || n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
        {
          conn->state = CONN_STATE_CLOSED;
          return -1;
        }
      return 0;
    }

  conn->last_activity_ms = Socket_get_monotonic_ms ();
  SERVER_METRICS_ADD (server, SOCKET_CTR_HTTP_SERVER_BYTES_RECEIVED,
                      bytes_received, (uint64_t)n);
  SocketBuf_write (conn->inbuf, buf, (size_t)n);

  return (int)n;
}

/**
 * connection_send_data - Send data over connection socket
 * @server: HTTP server (for per-server metrics)
 * @conn: Connection to send on
 * @data: Data buffer to send
 * @len: Length of data
 *
 * Returns: 0 on success, -1 on error
 */
int
connection_send_data (SocketHTTPServer_T server, ServerConnection *conn,
                      const void *data, size_t len)
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
  SERVER_METRICS_ADD (server, SOCKET_CTR_HTTP_SERVER_BYTES_SENT, bytes_sent,
                      (uint64_t)sent);
  return 0;
}

/* ============================================================================
 * Connection State Management
 * ============================================================================
 */

/**
 * connection_reset_for_keepalive - Reset connection for next request
 * @conn: Connection to reset
 *
 * Clears per-request state while preserving socket and buffers.
 */
void
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

/**
 * connection_finish_request - Complete request processing
 * @server: HTTP server
 * @conn: Connection
 *
 * Records latency and either resets for keep-alive or closes connection.
 */
void
connection_finish_request (SocketHTTPServer_T server, ServerConnection *conn)
{
  record_request_latency (server, conn->request_start_ms);

  if (SocketHTTP1_Parser_should_keepalive (conn->parser))
    connection_reset_for_keepalive (conn);
  else
    conn->state = CONN_STATE_CLOSED;
}

/* ============================================================================
 * Request Parsing
 * ============================================================================
 */

/**
 * connection_reject_oversized_body - Send 413 and close connection
 * @server: HTTP server
 * @conn: Connection with oversized body
 */
static void
connection_reject_oversized_body (SocketHTTPServer_T server,
                                  ServerConnection *conn)
{
  SocketMetrics_counter_inc (SOCKET_CTR_LIMIT_BODY_SIZE_EXCEEDED);
  connection_send_error (server, conn, 413, "Payload Too Large");
  conn->state = CONN_STATE_CLOSED;
}

/**
 * connection_setup_body_buffer - Allocate body buffer based on mode
 * @server: HTTP server for config
 * @conn: Connection with parsed headers
 *
 * For Content-Length mode: allocates exact buffer size upfront.
 * For Chunked/Until-Close mode: uses SocketBuf_T with dynamic growth.
 *
 * Returns: 0 on success, -1 on failure (state set to CLOSED)
 */
static int
connection_setup_body_buffer (SocketHTTPServer_T server, ServerConnection *conn)
{
  SocketHTTP1_BodyMode mode = SocketHTTP1_Parser_body_mode (conn->parser);
  int64_t cl = SocketHTTP1_Parser_content_length (conn->parser);
  size_t max_body = server->config.max_body_size;

  conn->body_mode = mode;
  conn->body_uses_buf = 0;

  if (mode == HTTP1_BODY_CONTENT_LENGTH && cl > 0)
    {
      /* Fixed-size body: allocate exact capacity */
      if ((size_t)cl > max_body)
        {
          connection_reject_oversized_body (server, conn);
          return -1;
        }
      conn->body_capacity = (size_t)cl;
      conn->body = Arena_alloc (conn->arena, conn->body_capacity, __FILE__,
                                __LINE__);
      if (conn->body == NULL)
        {
          conn->state = CONN_STATE_CLOSED;
          return -1;
        }
      conn->memory_used += conn->body_capacity;
    }
  else if (mode == HTTP1_BODY_CHUNKED || mode == HTTP1_BODY_UNTIL_CLOSE)
    {
      /* Dynamic body: use SocketBuf_T that can grow up to max_body_size.
       * Start with small initial capacity to avoid wasting memory. */
      size_t initial_size = HTTPSERVER_CHUNKED_BODY_INITIAL_SIZE;
      if (initial_size > max_body)
        initial_size = max_body;

      conn->body_buf = SocketBuf_new (conn->arena, initial_size);
      if (conn->body_buf == NULL)
        {
          conn->state = CONN_STATE_CLOSED;
          return -1;
        }
      conn->body_uses_buf = 1;
      conn->body_capacity = max_body; /* Max allowed, not current capacity */
      conn->memory_used += initial_size;
    }

  return 0;
}

/**
 * connection_read_initial_body - Read initial body data from input buffer
 * @server: HTTP server for config
 * @conn: Connection with body buffer allocated
 *
 * Handles both fixed-size body (Content-Length) and dynamic body (chunked).
 * Supports streaming mode where body data is delivered via callback.
 *
 * Returns: 0 if more data needed, 1 if body complete, -1 on error
 */
static int
connection_read_initial_body (SocketHTTPServer_T server, ServerConnection *conn)
{
  const void *input;
  size_t input_len, body_consumed, written;
  SocketHTTP1_Result r;

  input = SocketBuf_readptr (conn->inbuf, &input_len);
  if (input_len == 0)
    {
      conn->state = CONN_STATE_READING_BODY;
      return 0;
    }

  /* Handle streaming mode: deliver body data via callback instead of buffering
   */
  if (conn->body_streaming && conn->body_callback)
    {
      /* Use a temporary buffer for parsing body chunks */
      char temp_buf[HTTPSERVER_RECV_BUFFER_SIZE];
      size_t temp_avail = sizeof (temp_buf);

      r = SocketHTTP1_Parser_read_body (conn->parser, (const char *)input,
                                        input_len, &body_consumed, temp_buf,
                                        temp_avail, &written);

      SocketBuf_consume (conn->inbuf, body_consumed);
      conn->body_received += written;

      /* Invoke callback with chunk data */
      if (written > 0)
        {
          int is_final = SocketHTTP1_Parser_body_complete (conn->parser) ? 1 : 0;

          /* Create request context for callback */
          struct SocketHTTPServer_Request req_ctx;
          req_ctx.server = server;
          req_ctx.conn = conn;
          req_ctx.arena = conn->arena;
          req_ctx.start_time_ms = conn->request_start_ms;

          int cb_result = conn->body_callback (&req_ctx, temp_buf, written,
                                               is_final,
                                               conn->body_callback_userdata);
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

  if (conn->body_uses_buf)
    {
      /* Chunked/until-close mode: use dynamic SocketBuf_T */
      size_t max_body = server->config.max_body_size;
      size_t current_len = SocketBuf_available (conn->body_buf);

      /* Check if adding this chunk would exceed limit */
      if (current_len + input_len > max_body)
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

      r = SocketHTTP1_Parser_read_body (conn->parser, (const char *)input,
                                        input_len, &body_consumed,
                                        (char *)write_ptr, write_avail,
                                        &written);

      SocketBuf_consume (conn->inbuf, body_consumed);
      if (written > 0)
        SocketBuf_written (conn->body_buf, written);

      conn->body_len = SocketBuf_available (conn->body_buf);

      /* Check size limit after write */
      if (conn->body_len > max_body
          && !SocketHTTP1_Parser_body_complete (conn->parser))
        {
          connection_reject_oversized_body (server, conn);
          return -1;
        }
    }
  else
    {
      /* Content-Length mode: use fixed buffer */
      char *output = (char *)conn->body + conn->body_len;
      size_t output_avail = conn->body_capacity - conn->body_len;

      r = SocketHTTP1_Parser_read_body (conn->parser, (const char *)input,
                                        input_len, &body_consumed, output,
                                        output_avail, &written);

      SocketBuf_consume (conn->inbuf, body_consumed);
      conn->body_len += written;

      /* Reject oversized bodies early */
      if (conn->body_len > server->config.max_body_size
          && !SocketHTTP1_Parser_body_complete (conn->parser))
        {
          connection_reject_oversized_body (server, conn);
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

  return 1;
}

/**
 * connection_parse_request - Parse incoming HTTP request
 * @server: HTTP server
 * @conn: Connection with data in inbuf
 *
 * Returns: 0 need more data, 1 request ready, -1 error
 */
int
connection_parse_request (SocketHTTPServer_T server, ServerConnection *conn)
{
  const void *data;
  size_t len, consumed;
  SocketHTTP1_Result result;

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

  if (SocketHTTP1_Parser_state (conn->parser) < HTTP1_STATE_BODY)
    return 0;

  /* Headers complete - setup request handling */
  conn->request = SocketHTTP1_Parser_get_request (conn->parser);
  conn->request_start_ms = Socket_get_monotonic_ms ();

  /* Run validator early to allow streaming mode setup before body buffering.
   * The validator can call SocketHTTPServer_Request_body_stream() to enable
   * streaming mode for the request body. */
  if (!server_run_validator_early (server, conn))
    {
      /* Validator rejected - error already sent */
      return -1;
    }

  /* Handle request body if present */
  if (conn->request->has_body && !conn->body_streaming)
    {
      /* Normal buffered mode: allocate body buffer */
      if (connection_setup_body_buffer (server, conn) < 0)
        return -1;

      if (conn->body_capacity > 0)
        {
          int body_result = connection_read_initial_body (server, conn);
          if (body_result <= 0)
            return body_result;
        }
    }
  else if (conn->request->has_body && conn->body_streaming)
    {
      /* Streaming mode enabled by validator - read initial body with callback */
      conn->body_mode = SocketHTTP1_Parser_body_mode (conn->parser);
      int body_result = connection_read_initial_body (server, conn);
      if (body_result <= 0)
        return body_result;
    }

  conn->state = CONN_STATE_HANDLING;
  return 1;
}

/* ============================================================================
 * Response Sending
 * ============================================================================
 */

/**
 * connection_send_response - Serialize and send HTTP response
 * @server: HTTP server
 * @conn: Connection with response data set
 */
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
  if (conn->response_body_len > 0 && !conn->response_streaming)
    {
      char cl[HTTPSERVER_CONTENT_LENGTH_BUF_SIZE];
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
    return;

  if (conn->response_body != NULL && conn->response_body_len > 0)
    {
      if (connection_send_data (server, conn, conn->response_body,
                                conn->response_body_len) < 0)
        return;
    }

  connection_finish_request (server, conn);
}

/**
 * connection_send_error - Send HTTP error response
 * @server: HTTP server
 * @conn: Connection to send error on
 * @status: HTTP status code
 * @body: Optional error message body
 *
 * If a custom error handler is registered via SocketHTTPServer_set_error_handler(),
 * it will be invoked to allow custom error page generation. The handler can set
 * response headers and body, then call SocketHTTPServer_Request_finish().
 * If no custom handler is set, a default text/plain response is sent.
 */
void
connection_send_error (SocketHTTPServer_T server, ServerConnection *conn,
                       int status, const char *body)
{
  conn->response_status = status;

  /* If a custom error handler is registered, invoke it */
  if (server->error_handler != NULL)
    {
      struct SocketHTTPServer_Request req_ctx;
      req_ctx.server = server;
      req_ctx.conn = conn;
      req_ctx.arena = conn->arena;
      req_ctx.start_time_ms = conn->request_start_ms;

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
      SocketHTTP_Headers_set (conn->response_headers, "Content-Type",
                              "text/plain");
    }

  connection_send_response (server, conn);
}

/* ============================================================================
 * Connection Lifecycle - Helpers
 * ============================================================================
 */

/**
 * connection_set_client_addr - Cache client IP address
 * @conn: Connection to update
 */
static void
connection_set_client_addr (ServerConnection *conn)
{
  const char *addr = Socket_getpeeraddr (conn->socket);
  if (addr != NULL)
    {
      strncpy (conn->client_addr, addr, sizeof (conn->client_addr) - 1);
      conn->client_addr[sizeof (conn->client_addr) - 1] = '\0';
    }
}

/**
 * connection_create_parser - Create HTTP/1.1 parser with server config
 * @arena: Arena for parser allocations
 * @config: Server configuration
 *
 * Returns: New parser or raises SocketHTTPServer_Failed
 */
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

/**
 * record_request_latency - Record request processing time
 * @server: HTTP server (unused)
 * @request_start_ms: Request start timestamp
 */
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

/**
 * connection_init_resources - Initialize connection buffers and parser
 * @server: HTTP server
 * @conn: Allocated connection struct (zeroed)
 * @socket: Client socket
 *
 * Returns: 0 on success, -1 on failure
 */
static int
connection_init_resources (SocketHTTPServer_T server, ServerConnection *conn,
                           Socket_T socket)
{
  Arena_T arena = Arena_new ();
  conn->arena = arena;
  conn->socket = socket;

  conn->state = CONN_STATE_READING_REQUEST;
  conn->created_at_ms = Socket_get_monotonic_ms ();
  conn->last_activity_ms = conn->created_at_ms;

  connection_set_client_addr (conn);
  conn->parser = connection_create_parser (arena, &server->config);
  conn->inbuf = SocketBuf_new (arena, HTTPSERVER_IO_BUFFER_SIZE);
  conn->outbuf = SocketBuf_new (arena, HTTPSERVER_IO_BUFFER_SIZE);
  conn->response_headers = SocketHTTP_Headers_new (arena);

  conn->memory_used = sizeof (*conn) + (2 * HTTPSERVER_IO_BUFFER_SIZE);
  return 0;
}

/**
 * connection_add_to_server - Add connection to server's list and track IP
 * @server: HTTP server
 * @conn: Initialized connection
 *
 * Returns: 0 on success, -1 if IP limit exceeded
 */
static int
connection_add_to_server (SocketHTTPServer_T server, ServerConnection *conn)
{
  /* Track per-IP connections */
  if (server->ip_tracker != NULL && conn->client_addr[0] != '\0')
    {
      if (!SocketIPTracker_track (server->ip_tracker, conn->client_addr))
        {
          SERVER_METRICS_INC (server, SOCKET_CTR_LIMIT_CONNECTIONS_EXCEEDED,
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
  SERVER_GAUGE_INC (server, SOCKET_GAU_HTTP_SERVER_ACTIVE_CONNECTIONS,
                    active_connections);
  SERVER_METRICS_INC (server, SOCKET_CTR_HTTP_SERVER_CONNECTIONS_TOTAL,
                      connections_total);

  return 0;
}

/* ============================================================================
 * Connection Lifecycle - Public
 * ============================================================================
 */

/**
 * connection_new - Allocate and initialize new connection
 * @server: HTTP server
 * @socket: Accepted client socket (ownership transferred)
 *
 * Returns: New connection or NULL on failure
 */
ServerConnection *
connection_new (SocketHTTPServer_T server, Socket_T socket)
{
  ServerConnection *volatile conn;
  volatile int resources_ok = 0;
  volatile int added_to_server = 0;

  conn = malloc (sizeof (*conn));
  if (conn == NULL)
    return NULL;

  memset (conn, 0, sizeof (*conn));

  TRY
  {
    if (connection_init_resources (server, conn, socket) < 0)
      goto cleanup;
    resources_ok = 1;

    if (connection_add_to_server (server, conn) < 0)
      goto cleanup;
    added_to_server = 1;

    RETURN conn;

  cleanup:;
  }
  FINALLY
  {
    if (!added_to_server)
      {
        if (resources_ok && conn->arena != NULL)
          Arena_dispose (&conn->arena);
        if (conn->socket != NULL)
          Socket_free (&conn->socket);
        free (conn);
      }
  }
  END_TRY;

  return NULL;
}

/**
 * connection_close - Close and cleanup connection
 * @server: HTTP server
 * @conn: Connection to close
 */
void
connection_close (SocketHTTPServer_T server, ServerConnection *conn)
{
  if (conn == NULL)
    return;

  /* Release IP tracking */
  if (server->ip_tracker != NULL && conn->client_addr[0] != '\0')
    SocketIPTracker_release (server->ip_tracker, conn->client_addr);

  /* Remove from poll */
  if (server->poll != NULL && conn->socket != NULL)
    SocketPoll_del (server->poll, conn->socket);

  /* Close socket */
  if (conn->socket != NULL)
    Socket_free (&conn->socket);

  /* Remove from connection list */
  if (conn->prev != NULL)
    conn->prev->next = conn->next;
  else
    server->connections = conn->next;

  if (conn->next != NULL)
    conn->next->prev = conn->prev;

  /* Update global + per-server metrics */
  SERVER_GAUGE_DEC (server, SOCKET_GAU_HTTP_SERVER_ACTIVE_CONNECTIONS,
                    active_connections);

  /* Free arena */
  if (conn->arena != NULL)
    Arena_dispose (&conn->arena);

  free (conn);
}

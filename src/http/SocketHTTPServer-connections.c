/**
 * SocketHTTPServer-connections.c - Connection Management Implementation
 *
 * Part of the Socket Library
 *
 * Handles individual HTTP connection lifecycle, I/O, parsing, response sending.
 *
 * Following C Interfaces and Implementations patterns
 */

#include <stdlib.h>

#include "http/SocketHTTPServer-private.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP1.h"
#include "socket/Socket.h"
#include "core/SocketMetrics.h" /* for any metrics if added */

SOCKET_DECLARE_MODULE_EXCEPTION (HTTPServer);

/* Forward declarations */
static void record_request_latency (SocketHTTPServer_T server,
                                    int64_t request_start_ms);

static int64_t
server_time_ms (void)
{
  return Socket_get_monotonic_ms ();
}

int
connection_read (SocketHTTPServer_T server, ServerConnection *conn)
{
  char buf[HTTPSERVER_RECV_BUFFER_SIZE];
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
  STATS_ADD (server, total_bytes_received, (size_t)n);
  SocketBuf_write (conn->inbuf, buf, (size_t)n);

  return (int)n;
}

int
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
  STATS_ADD (server, total_bytes_sent, (size_t)sent);
  return 0;
}

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
 * REFACTOR: Extracted from connection_send_response and
 * SocketHTTPServer_Request_end_stream to eliminate duplication.
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

int
connection_parse_request (SocketHTTPServer_T server, ServerConnection *conn)
{
  const void *data;
  size_t len;
  size_t consumed;
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
              /* Enforce max body size limit */
              if ((size_t)content_len > server->config.max_body_size)
                {
                  SocketMetrics_counter_inc (SOCKET_CTR_LIMIT_BODY_SIZE_EXCEEDED);
                  connection_send_error (server, conn, 413,
                                         "Payload Too Large");
                  conn->state = CONN_STATE_CLOSED;
                  return -1;
                }

              conn->body_capacity = (size_t)content_len;
              conn->body
                  = Arena_alloc (conn->arena, conn->body_capacity, __FILE__,
                                 __LINE__);
              if (conn->body == NULL)
                {
                  conn->state = CONN_STATE_CLOSED;
                  return -1;
                }

              /* Track body buffer in connection memory */
              conn->memory_used += conn->body_capacity;

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

  /* Track errors */
  if (conn->response_status >= 400 && conn->response_status < 500)
    STATS_INC (server, errors_4xx);
  else if (conn->response_status >= 500)
    STATS_INC (server, errors_5xx);

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

  connection_finish_request (server, conn);
}

void
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

static SocketHTTP1_Parser_T
connection_create_parser (Arena_T arena, const SocketHTTPServer_Config *config)
{
  SocketHTTP1_Config pcfg;
  SocketHTTP1_config_defaults (&pcfg);
  pcfg.max_header_size = config->max_header_size;
  SocketHTTP1_Parser_T p = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &pcfg, arena);
  if (p == NULL)
    RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
  return p;
}

static void
record_request_latency (SocketHTTPServer_T server, int64_t request_start_ms)
{
  if (request_start_ms > 0)
    {
      int64_t latency_us = (server_time_ms () - request_start_ms) * 1000;
      latency_record (&server->latency, latency_us);
    }
}

ServerConnection *
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
  connection_set_client_addr (conn);

  /* Create parser with server's configured limits */
  conn->parser = connection_create_parser (arena, &server->config);

  /* Create I/O buffers */
  conn->inbuf = SocketBuf_new (arena, HTTPSERVER_IO_BUFFER_SIZE);
  conn->outbuf = SocketBuf_new (arena, HTTPSERVER_IO_BUFFER_SIZE);
  /* Note: SocketBuf_new raises on fail, so no NULL check needed if using exception policy */

  /* Create response headers */
  conn->response_headers = SocketHTTP_Headers_new (arena);
  /* Assume raises on fail or handle in SocketHTTP_Headers_new */

  /* Initialize memory tracking (base allocation: conn struct + I/O buffers) */
  conn->memory_used = sizeof (*conn) + (2 * HTTPSERVER_IO_BUFFER_SIZE);

  /* Track per-IP connections */
  if (server->ip_tracker != NULL && conn->client_addr[0] != '\0')
    {
      if (!SocketIPTracker_track (server->ip_tracker, conn->client_addr))
        {
          /* Connection limit reached for this IP */
          Arena_dispose (&arena);
          free (conn);
          STATS_INC (server, connections_rejected);
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

void
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

  STATS_DEC (server, connection_count);

  /* Free arena */
  if (conn->arena != NULL)
    {
      Arena_dispose (&conn->arena);
    }

  free (conn);
}
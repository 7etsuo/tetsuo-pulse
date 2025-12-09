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

#include "core/SocketMetrics.h" /* for any metrics if added */
#include "core/SocketUtil.h"
#include "http/SocketHTTP1.h"

#include "http/SocketHTTPServer-private.h"
#include "socket/Socket.h"


/* Forward declarations */
static void record_request_latency (SocketHTTPServer_T server,
                                    int64_t request_start_ms);
void connection_send_error (SocketHTTPServer_T server, ServerConnection *conn,
                                   int status, const char *body);

int
connection_read (SocketHTTPServer_T server, ServerConnection *conn)
{
  char buf[HTTPSERVER_RECV_BUFFER_SIZE];
  volatile ssize_t n = 0;
  volatile int closed = 0;

  (void)server; /* Unused - kept for API consistency */

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

  conn->last_activity_ms = Socket_get_monotonic_ms ();
  SocketMetrics_counter_add (SOCKET_CTR_HTTP_SERVER_BYTES_RECEIVED, (size_t)n);
  SocketBuf_write (conn->inbuf, buf, (size_t)n);

  return (int)n;
}

int
connection_send_data (SocketHTTPServer_T server, ServerConnection *conn,
                      const void *data, size_t len)
{
  volatile int closed = 0;
  volatile ssize_t sent = 0;

  (void)server; /* Unused - kept for API consistency */

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

  conn->last_activity_ms = Socket_get_monotonic_ms ();
  SocketMetrics_counter_add (SOCKET_CTR_HTTP_SERVER_BYTES_SENT, (size_t)sent);
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
      conn->request_start_ms = Socket_get_monotonic_ms ();

      if (conn->request->has_body && !conn->body_streaming)
        {
          SocketHTTP1_BodyMode mode
              = SocketHTTP1_Parser_body_mode (conn->parser);
          int64_t cl = SocketHTTP1_Parser_content_length (conn->parser);
          size_t max_body = server->config.max_body_size;

          size_t capacity = 0;
          if (mode == HTTP1_BODY_CONTENT_LENGTH && cl > 0)
            {
              if ((size_t)cl > max_body)
                {
                  SocketMetrics_counter_inc (
                      SOCKET_CTR_LIMIT_BODY_SIZE_EXCEEDED);
                  connection_send_error (server, conn, 413,
                                         "Payload Too Large");
                  conn->state = CONN_STATE_CLOSED;
                  return -1;
                }
              capacity = (size_t)cl;
            }
          else if (mode == HTTP1_BODY_CHUNKED
                   || mode == HTTP1_BODY_UNTIL_CLOSE)
            {
              /* Use max for unknown size */
              capacity = max_body;
            }

          if (capacity > 0)
            {
              conn->body_capacity = capacity;
              conn->body
                  = Arena_alloc (conn->arena, capacity, __FILE__, __LINE__);
              if (conn->body == NULL)
                {
                  conn->state = CONN_STATE_CLOSED;
                  return -1;
                }
              conn->memory_used += capacity;
              conn->body_mode = mode; /* Track mode in conn if needed */

              /* Initial body read using centralized API */
              const void *input;
              size_t input_len, consumed, written;
              input = SocketBuf_readptr (conn->inbuf, &input_len);
              SocketHTTP1_Result r = SocketHTTP1_Parser_read_body (
                  conn->parser, (const char *)input, input_len, &consumed,
                  (char *)conn->body, capacity, &written);
              SocketBuf_consume (conn->inbuf, consumed);
              conn->body_len = written;

              /* Reject oversized bodies early to prevent DoS - even on initial
               * read */
              if (conn->body_len > server->config.max_body_size
                  && !SocketHTTP1_Parser_body_complete (conn->parser))
                {
                  SocketMetrics_counter_inc (
                      SOCKET_CTR_LIMIT_BODY_SIZE_EXCEEDED);
                  connection_send_error (server, conn, 413,
                                         "Payload Too Large");
                  conn->state = CONN_STATE_CLOSED;
                  return -1;
                }

              if (r == HTTP1_ERROR)
                {
                  conn->state = CONN_STATE_CLOSED;
                  return -1;
                }

              if (!SocketHTTP1_Parser_body_complete (conn->parser))
                {
                  conn->state = CONN_STATE_READING_BODY;
                  return 0; /* Need more data */
                }
              /* Else body complete, fall to HANDLING */
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

  /* Track errors via metrics */
  if (conn->response_status >= 400 && conn->response_status < 500)
    SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_4XX);
  else if (conn->response_status >= 500)
    SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_5XX);

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

void connection_send_error (SocketHTTPServer_T server, ServerConnection *conn,
                       int status, const char *body)
{
  conn->response_status = status;
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
  SocketHTTP1_Parser_T p
      = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &pcfg, arena);
  if (p == NULL)
    RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
  return p;
}

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
  /* latency_record removed - use metrics histogram */
}

ServerConnection *
connection_new (SocketHTTPServer_T server, Socket_T socket)
{
  ServerConnection *volatile conn;
  Arena_T arena;

  conn = malloc (sizeof (*conn));
  if (conn == NULL)
    return NULL;

  memset (conn, 0, sizeof (*conn));

  volatile int transferred = 0;

  TRY
  {
    arena = Arena_new ();
    conn->arena = arena;
    transferred = 1; /* arena transferred */

    conn->socket = socket;
    transferred = 2; /* socket transferred */

    conn->state = CONN_STATE_READING_REQUEST;
    conn->created_at_ms = Socket_get_monotonic_ms ();
    conn->last_activity_ms = conn->created_at_ms;

    /* Get client address */
    connection_set_client_addr (conn);

    /* Create parser with server's configured limits */
    conn->parser = connection_create_parser (arena, &server->config);
    transferred = 3; /* parser transferred */

    /* Create I/O buffers */
    conn->inbuf = SocketBuf_new (arena, HTTPSERVER_IO_BUFFER_SIZE);
    conn->outbuf = SocketBuf_new (arena, HTTPSERVER_IO_BUFFER_SIZE);
    /* Note: SocketBuf_new raises on fail, so no NULL check needed if using
     * exception policy */
    transferred = 4; /* buffers transferred */

    /* Create response headers */
    conn->response_headers = SocketHTTP_Headers_new (arena);
    /* Assume raises on fail or handle in SocketHTTP_Headers_new */

    /* Initialize memory tracking (base allocation: conn struct + I/O buffers)
     */
    conn->memory_used = sizeof (*conn) + (2 * HTTPSERVER_IO_BUFFER_SIZE);

    /* Track per-IP connections */
    if (server->ip_tracker != NULL && conn->client_addr[0] != '\0')
      {
        if (!SocketIPTracker_track (server->ip_tracker, conn->client_addr))
          {
            /* Connection limit reached for this IP - trigger cleanup via
             * FINALLY Note: DO NOT use RETURN here as it skips FINALLY cleanup
             * Leave transferred at 4 so FINALLY cleans up arena, socket, and
             * conn */
            SocketMetrics_counter_inc (SOCKET_CTR_LIMIT_CONNECTIONS_EXCEEDED);
            goto cleanup_and_return_null;
          }
      }

    /* Add to server's connection list */
    conn->next = server->connections;
    if (server->connections != NULL)
      server->connections->prev = conn;
    server->connections = conn;

    /* Thread-safe metrics calls - no lock needed */
    SocketMetrics_gauge_inc (SOCKET_GAU_HTTP_SERVER_ACTIVE_CONNECTIONS);
    SocketMetrics_counter_inc (SOCKET_CTR_HTTP_SERVER_CONNECTIONS_TOTAL);

    transferred = 5; /* fully transferred */
    RETURN conn;

  cleanup_and_return_null:
      /* Explicit cleanup path for rejected connections (e.g., IP limit
       * exceeded) This label is jumped to from validation failures above */
      ; /* Empty statement needed after label before block end */
  }
  FINALLY
  {
    if (transferred < 5)
      {
        if (transferred >= 1 && conn->arena != NULL)
          Arena_dispose (&conn->arena);
        if (transferred >= 2 && conn->socket != NULL)
          Socket_free (&conn->socket);
        free (conn);
      }
  }
  END_TRY;

  return NULL; /* Reached when cleanup_and_return_null is used */
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

  SocketMetrics_gauge_dec (SOCKET_GAU_HTTP_SERVER_ACTIVE_CONNECTIONS);

  /* Free arena */
  if (conn->arena != NULL)
    {
      Arena_dispose (&conn->arena);
    }

  free (conn);
}

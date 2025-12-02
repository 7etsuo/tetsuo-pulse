/**
 * SocketHTTPServer.c - HTTP Server Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Event-driven HTTP server supporting HTTP/1.1:
 * - Non-blocking I/O with SocketPoll integration
 * - Keep-alive connection handling
 * - Request body parsing (Content-Length and chunked)
 * - Streaming response support
 *
 * Leverages:
 * - SocketHTTP for headers, methods, status codes
 * - SocketHTTP1 for HTTP/1.1 parsing/serialization
 * - SocketPoll for event loop
 * - Socket for networking
 */

#include "http/SocketHTTPServer.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "poll/SocketPoll.h"
#include "core/Arena.h"
#include "core/SocketUtil.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * Server Configuration
 * ============================================================================ */

#define SERVER_IO_BUFFER_SIZE 8192
#define SERVER_MAX_CLIENTS_PER_ACCEPT 10

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
 * Thread-Local Error Buffer
 * ============================================================================ */

#define HTTPSERVER_ERROR_BUFSIZE 256

#ifdef _WIN32
static __declspec(thread) char httpserver_error_buf[HTTPSERVER_ERROR_BUFSIZE];
static __declspec(thread) Except_T HTTPServer_DetailedException;
#else
static __thread char httpserver_error_buf[HTTPSERVER_ERROR_BUFSIZE];
static __thread Except_T HTTPServer_DetailedException;
#endif

#define HTTPSERVER_ERROR_FMT(fmt, ...)                                         \
  snprintf (httpserver_error_buf, HTTPSERVER_ERROR_BUFSIZE,                    \
            fmt " (errno: %d - %s)", ##__VA_ARGS__, errno, strerror (errno))

#define HTTPSERVER_ERROR_MSG(fmt, ...)                                         \
  snprintf (httpserver_error_buf, HTTPSERVER_ERROR_BUFSIZE, fmt, ##__VA_ARGS__)

#define RAISE_HTTPSERVER_ERROR(exception)                                      \
  do                                                                           \
    {                                                                          \
      HTTPServer_DetailedException = (exception);                              \
      HTTPServer_DetailedException.reason = httpserver_error_buf;              \
      RAISE (HTTPServer_DetailedException);                                    \
    }                                                                          \
  while (0)

/* ============================================================================
 * Connection State
 * ============================================================================ */

typedef enum
{
  CONN_STATE_READING_REQUEST,
  CONN_STATE_HANDLING,
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

  /* Response data */
  int response_status;
  SocketHTTP_Headers_T response_headers;
  void *response_body;
  size_t response_body_len;
  int response_finished;

  /* Connection metadata */
  time_t created_at;
  time_t last_activity;
  size_t request_count;

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
};

/* ============================================================================
 * Server Structure
 * ============================================================================ */

struct SocketHTTPServer
{
  SocketHTTPServer_Config config;

  Socket_T listen_socket;
  SocketPoll_T poll;

  SocketHTTPServer_Handler handler;
  void *handler_userdata;

  ServerConnection *connections;
  size_t connection_count;

  /* Statistics */
  size_t total_requests;
  size_t total_bytes_sent;
  size_t total_bytes_received;

  int running;
  Arena_T arena;
};

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

static time_t
server_time (void)
{
  struct timespec ts;
  if (clock_gettime (CLOCK_MONOTONIC, &ts) == 0)
    return ts.tv_sec;
  return time (NULL);
}

static ServerConnection *
connection_new (SocketHTTPServer_T server, Socket_T socket)
{
  ServerConnection *conn;
  Arena_T arena;

  arena = Arena_new ();
  if (arena == NULL)
    return NULL;

  conn = Arena_alloc (arena, sizeof (*conn), __FILE__, __LINE__);
  if (conn == NULL)
    {
      Arena_dispose (&arena);
      return NULL;
    }

  memset (conn, 0, sizeof (*conn));
  conn->arena = arena;
  conn->socket = socket;
  conn->state = CONN_STATE_READING_REQUEST;
  conn->created_at = server_time ();
  conn->last_activity = conn->created_at;

  /* Get client address */
  const char *addr = Socket_getpeeraddr (socket);
  if (addr != NULL)
    {
      strncpy (conn->client_addr, addr, sizeof (conn->client_addr) - 1);
    }

  /* Create parser */
  conn->parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
  if (conn->parser == NULL)
    {
      Arena_dispose (&arena);
      return NULL;
    }

  /* Create I/O buffers */
  conn->inbuf = SocketBuf_new (arena, SERVER_IO_BUFFER_SIZE);
  conn->outbuf = SocketBuf_new (arena, SERVER_IO_BUFFER_SIZE);

  if (conn->inbuf == NULL || conn->outbuf == NULL)
    {
      Arena_dispose (&arena);
      return NULL;
    }

  /* Create response headers */
  conn->response_headers = SocketHTTP_Headers_new (arena);
  if (conn->response_headers == NULL)
    {
      Arena_dispose (&arena);
      return NULL;
    }

  /* Add to server's connection list */
  conn->next = server->connections;
  if (server->connections != NULL)
    server->connections->prev = conn;
  server->connections = conn;
  server->connection_count++;

  return conn;
}

static void
connection_close (SocketHTTPServer_T server, ServerConnection *conn)
{
  if (conn == NULL)
    return;

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

  server->connection_count--;

  /* Free arena */
  if (conn->arena != NULL)
    {
      Arena_dispose (&conn->arena);
    }
}

static int
connection_read (ServerConnection *conn)
{
  char buf[4096];
  ssize_t n;

  n = Socket_recv (conn->socket, buf, sizeof (buf));
  if (n <= 0)
    {
      if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
        {
          conn->state = CONN_STATE_CLOSED;
          return -1;
        }
      return 0; /* Would block */
    }

  conn->last_activity = server_time ();

  /* Write to input buffer */
  SocketBuf_write (conn->inbuf, buf, (size_t)n);

  return (int)n;
}

static int
connection_write (ServerConnection *conn)
{
  const void *data;
  size_t len;
  ssize_t n;

  data = SocketBuf_readptr (conn->outbuf, &len);
  if (len == 0)
    return 0;

  n = Socket_send (conn->socket, data, len);
  if (n <= 0)
    {
      if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
        {
          conn->state = CONN_STATE_CLOSED;
          return -1;
        }
      return 0; /* Would block */
    }

  SocketBuf_consume (conn->inbuf, (size_t)n);
  conn->last_activity = server_time ();

  return (int)n;
}

static int
connection_parse_request (ServerConnection *conn)
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

      /* Read body if present */
      if (conn->request->has_body)
        {
          int64_t content_len = SocketHTTP1_Parser_content_length (conn->parser);
          if (content_len > 0)
            {
              /* Allocate body buffer */
              conn->body_capacity = (size_t)content_len;
              conn->body = Arena_alloc (conn->arena, conn->body_capacity,
                                        __FILE__, __LINE__);
              if (conn->body == NULL)
                {
                  conn->state = CONN_STATE_CLOSED;
                  return -1;
                }

              /* Read body from input buffer */
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
            }
        }

      conn->state = CONN_STATE_HANDLING;
      return 1;
    }

  return 0;
}

static void
connection_send_response (ServerConnection *conn)
{
  char buf[8192];
  ssize_t len;

  /* Build response */
  SocketHTTP_Response response;
  memset (&response, 0, sizeof (response));
  response.version = HTTP_VERSION_1_1;
  response.status_code = conn->response_status;
  response.headers = conn->response_headers;

  /* Add Content-Length if body present */
  if (conn->response_body_len > 0)
    {
      char cl[32];
      snprintf (cl, sizeof (cl), "%zu", conn->response_body_len);
      SocketHTTP_Headers_set (conn->response_headers, "Content-Length", cl);
    }

  /* Serialize response */
  len = SocketHTTP1_serialize_response (&response, buf, sizeof (buf));
  if (len < 0)
    {
      conn->state = CONN_STATE_CLOSED;
      return;
    }

  /* Send headers */
  Socket_send (conn->socket, buf, (size_t)len);

  /* Send body */
  if (conn->response_body != NULL && conn->response_body_len > 0)
    {
      Socket_send (conn->socket, conn->response_body, conn->response_body_len);
    }

  /* Check keep-alive */
  if (SocketHTTP1_Parser_should_keepalive (conn->parser))
    {
      conn->request_count++;
      SocketHTTP1_Parser_reset (conn->parser);
      SocketBuf_clear (conn->inbuf);
      SocketBuf_clear (conn->outbuf);

      /* Reset response state */
      SocketHTTP_Headers_clear (conn->response_headers);
      conn->response_status = 0;
      conn->response_body = NULL;
      conn->response_body_len = 0;
      conn->response_finished = 0;
      conn->request = NULL;
      conn->body = NULL;
      conn->body_len = 0;

      conn->state = CONN_STATE_READING_REQUEST;
    }
  else
    {
      conn->state = CONN_STATE_CLOSED;
    }
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
  config->max_connections = HTTPSERVER_DEFAULT_MAX_CONNECTIONS;
  config->max_requests_per_connection = HTTPSERVER_DEFAULT_MAX_REQUESTS_PER_CONN;
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

  arena = Arena_new ();
  if (arena == NULL)
    {
      HTTPSERVER_ERROR_MSG ("Failed to create server arena");
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
    }

  server = Arena_alloc (arena, sizeof (*server), __FILE__, __LINE__);
  if (server == NULL)
    {
      Arena_dispose (&arena);
      HTTPSERVER_ERROR_MSG ("Failed to allocate server structure");
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
    }

  memset (server, 0, sizeof (*server));
  server->arena = arena;
  server->config = *config;

  /* Create poll instance */
  server->poll = SocketPoll_new (config->max_connections + 1);
  if (server->poll == NULL)
    {
      Arena_dispose (&arena);
      HTTPSERVER_ERROR_MSG ("Failed to create poll instance");
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
    }

  return server;
}

void
SocketHTTPServer_free (SocketHTTPServer_T *server)
{
  if (server == NULL || *server == NULL)
    return;

  SocketHTTPServer_T s = *server;

  /* Stop server */
  SocketHTTPServer_stop (s);

  /* Close all connections */
  while (s->connections != NULL)
    {
      connection_close (s, s->connections);
    }

  /* Free poll */
  if (s->poll != NULL)
    {
      SocketPoll_free (&s->poll);
    }

  /* Close listen socket */
  if (s->listen_socket != NULL)
    {
      Socket_free (&s->listen_socket);
    }

  /* Free arena */
  if (s->arena != NULL)
    {
      Arena_dispose (&s->arena);
    }

  *server = NULL;
}

int
SocketHTTPServer_start (SocketHTTPServer_T server)
{
  const char *bind_addr;

  assert (server != NULL);

  if (server->running)
    return 0;

  /* Create listen socket */
  server->listen_socket = Socket_new (AF_INET6, SOCK_STREAM, 0);
  if (server->listen_socket == NULL)
    {
      /* Try IPv4 */
      server->listen_socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    }

  if (server->listen_socket == NULL)
    {
      HTTPSERVER_ERROR_FMT ("Failed to create listen socket");
      return -1;
    }

  Socket_setreuseaddr (server->listen_socket);

  /* Bind */
  bind_addr = server->config.bind_address;
  if (bind_addr == NULL)
    bind_addr = "::";

  TRY
    {
      Socket_bind (server->listen_socket, bind_addr, server->config.port);
    }
  EXCEPT (Socket_Failed)
    {
      /* Try 0.0.0.0 if :: failed */
      if (strcmp (bind_addr, "::") == 0)
        {
          TRY
            {
              Socket_bind (server->listen_socket, "0.0.0.0",
                           server->config.port);
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

  /* Listen */
  Socket_listen (server->listen_socket, server->config.backlog);
  Socket_setnonblocking (server->listen_socket);

  /* Add to poll */
  SocketPoll_add (server->poll, server->listen_socket, POLL_READ, NULL);

  server->running = 1;
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
 * Event Loop
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

int
SocketHTTPServer_process (SocketHTTPServer_T server, int timeout_ms)
{
  SocketEvent_T *events;
  int nevents;
  int requests_processed = 0;

  assert (server != NULL);

  /* Wait for events */
  nevents = SocketPoll_wait (server->poll, &events, timeout_ms);

  for (int i = 0; i < nevents; i++)
    {
      SocketEvent_T *ev = &events[i];

      if (ev->socket == server->listen_socket)
        {
          /* Accept new connections */
          for (int j = 0; j < SERVER_MAX_CLIENTS_PER_ACCEPT; j++)
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
      else
        {
          /* Handle client I/O */
          ServerConnection *conn = (ServerConnection *)ev->data;
          if (conn == NULL)
            continue;

          if (ev->events & POLL_READ)
            {
              connection_read (conn);
            }

          if (conn->state == CONN_STATE_READING_REQUEST)
            {
              if (connection_parse_request (conn) == 1)
                {
                  /* Request complete - invoke handler */
                  if (server->handler != NULL && conn->request != NULL)
                    {
                      struct SocketHTTPServer_Request req_ctx;
                      req_ctx.server = server;
                      req_ctx.conn = conn;
                      req_ctx.arena = conn->arena;

                      /* Set default response */
                      conn->response_status = 200;

                      server->handler (&req_ctx, server->handler_userdata);
                      requests_processed++;
                      server->total_requests++;
                    }

                  /* Send response */
                  conn->state = CONN_STATE_SENDING_RESPONSE;
                  connection_send_response (conn);
                }
            }

          if (conn->state == CONN_STATE_CLOSED)
            {
              connection_close (server, conn);
            }
        }
    }

  /* Clean up timed-out connections */
  time_t now = server_time ();
  ServerConnection *conn = server->connections;
  while (conn != NULL)
    {
      ServerConnection *next = conn->next;

      int idle_ms = (int)(now - conn->last_activity) * 1000;
      if (idle_ms > server->config.keepalive_timeout_ms)
        {
          connection_close (server, conn);
        }

      conn = next;
    }

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

  /* Extract query from path */
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
  return req->conn->body;
}

size_t
SocketHTTPServer_Request_body_len (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
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

  /* Copy body to arena */
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
 * WebSocket Upgrade (Stub - implemented in Phase 9)
 * ============================================================================ */

int
SocketHTTPServer_Request_is_websocket (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);

  SocketHTTP_Headers_T headers = SocketHTTPServer_Request_headers (req);
  if (headers == NULL)
    return 0;

  /* Check for WebSocket upgrade */
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
  /* WebSocket implementation in Phase 9 */
  return NULL;
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
  stats->active_connections = server->connection_count;
  stats->total_requests = server->total_requests;
  stats->total_bytes_sent = server->total_bytes_sent;
  stats->total_bytes_received = server->total_bytes_received;
}


/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketHTTPServer.c - HTTP/1.1 and HTTP/2 server with TLS, rate limiting, and
 * connection pooling */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "core/Arena.h"
#include "core/SocketIPTracker.h"
#include "core/SocketMetrics.h"
#include "core/SocketRateLimit.h"
#include "core/SocketCrypto.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTPServer-private.h"
#include "http/SocketHTTPServer.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketWS.h"
#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#endif

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTPServer"

#define SERVER_LOG_ERROR(fmt, ...) SOCKET_LOG_ERROR_MSG (fmt, ##__VA_ARGS__)

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTPServer);

const Except_T SocketHTTPServer_Failed
    = { &SocketHTTPServer_Failed, "HTTP server operation failed" };
const Except_T SocketHTTPServer_BindFailed
    = { &SocketHTTPServer_BindFailed, "Failed to bind server socket" };
const Except_T SocketHTTPServer_ProtocolError
    = { &SocketHTTPServer_ProtocolError, "HTTP protocol error" };

ServerConnection *connection_new (SocketHTTPServer_T server, Socket_T socket);

/* Find most specific rate limiter for path prefix */
SocketRateLimit_T
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
      if (strncmp (path, e->path_prefix, len) == 0 && len > best_len)
        {
          best = e;
          best_len = len;
        }
    }

  if (best != NULL)
    return best->limiter;
  return server->global_rate_limiter;
}

void
SocketHTTPServer_config_defaults (SocketHTTPServer_Config *config)
{
  assert (config != NULL);

  memset (config, 0, sizeof (*config));

  config->port = HTTPSERVER_DEFAULT_PORT;
  config->bind_address = HTTPSERVER_DEFAULT_BIND_ADDR;
  config->backlog = HTTPSERVER_DEFAULT_BACKLOG;

  config->tls_context = NULL;

  config->max_version = HTTP_VERSION_2;
  config->enable_h2c_upgrade = HTTPSERVER_DEFAULT_ENABLE_H2C_UPGRADE;

  config->max_header_size = HTTPSERVER_DEFAULT_MAX_HEADER_SIZE;
  config->max_body_size = HTTPSERVER_DEFAULT_MAX_BODY_SIZE;
  config->request_timeout_ms = HTTPSERVER_DEFAULT_REQUEST_TIMEOUT_MS;
  config->keepalive_timeout_ms = HTTPSERVER_DEFAULT_KEEPALIVE_TIMEOUT_MS;
  config->request_read_timeout_ms = HTTPSERVER_DEFAULT_REQUEST_READ_TIMEOUT_MS;
  config->response_write_timeout_ms
      = HTTPSERVER_DEFAULT_RESPONSE_WRITE_TIMEOUT_MS;
  config->tls_handshake_timeout_ms
      = HTTPSERVER_DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS;
  config->max_connection_lifetime_ms
      = HTTPSERVER_DEFAULT_MAX_CONNECTION_LIFETIME_MS;
  config->max_connections = HTTPSERVER_DEFAULT_MAX_CONNECTIONS;
  config->max_requests_per_connection
      = HTTPSERVER_DEFAULT_MAX_REQUESTS_PER_CONN;
  config->max_connections_per_client
      = HTTPSERVER_DEFAULT_MAX_CONNECTIONS_PER_CLIENT;
  config->max_concurrent_requests = HTTPSERVER_DEFAULT_MAX_CONCURRENT_REQUESTS;

  SocketWS_config_defaults (&config->ws_config);
  config->ws_config.role = WS_ROLE_SERVER;

  config->per_server_metrics = 0;
}

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

  /* Free any connections that were closed but deferred deletion */
  connection_free_pending (s);

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
  else if (inet_pton (AF_INET, bind_addr, &(struct in_addr){ 0 }) == 1)
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
      if (setsockopt (Socket_fd (server->listen_socket),
                      IPPROTO_IPV6,
                      IPV6_V6ONLY,
                      &v6only,
                      sizeof (v6only))
          < 0)
        {
          HTTPSERVER_ERROR_MSG ("Failed to disable IPv6-only mode: %s",
                                strerror (errno));
          // Non-fatal: continue, but log warning
        }
    }
#endif

  TRY
  {
    Socket_bind (server->listen_socket, bind_addr, server->config.port);
  }
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
        HTTPSERVER_ERROR_FMT (
            "Failed to bind to %s:%d", bind_addr, server->config.port);
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
                              SocketHTTPServer_Handler handler,
                              void *userdata)
{
  assert (server != NULL);
  server->handler = handler;
  server->handler_userdata = userdata;
}

/* Accept new client connections up to max limit */
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

      /* During TLS handshake we must poll for write readiness too. */
      if (conn->state == CONN_STATE_TLS_HANDSHAKE)
        SocketPoll_add (server->poll, client, POLL_READ | POLL_WRITE, conn);
      else
        SocketPoll_add (server->poll, client, POLL_READ, conn);
    }
}


#if SOCKET_HAS_TLS
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

      /* Decide protocol by ALPN. If not negotiated, fall back to HTTP/1.1. */
      const char *alpn = SocketTLS_get_alpn_selected (conn->socket);
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
          SocketPoll_mod (
              server->poll, conn->socket, POLL_READ | POLL_WRITE, conn);
        }
      else
        {
          conn->is_http2 = 0;
          conn->state = CONN_STATE_READING_REQUEST;
          SocketPoll_mod (server->poll, conn->socket, POLL_READ, conn);
        }

      return 0;
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

static int
server_process_http2 (SocketHTTPServer_T server,
                      ServerConnection *conn,
                      unsigned events)
{
  volatile int r = 0;
  volatile int f = 0;
  volatile int stream_error = 0;

  assert (server != NULL);
  assert (conn != NULL);

  if (conn->http2_conn == NULL)
    {
      if (server_http2_enable (server, conn) < 0)
        return -1;
    }

  TRY
  {
    r = SocketHTTP2_Conn_process (conn->http2_conn, events);
  }
  EXCEPT (SocketHTTP2_ProtocolError)
  {
    return -1;
  }
  EXCEPT (SocketHTTP2_FlowControlError)
  {
    return -1;
  }
  EXCEPT (SocketHTTP2_StreamError)
  {
    /* Stream-level error: non-fatal for the connection (RFC 9113).
     * The core resets the offending stream; other streams may continue. */
    if (Except_frame.exception != NULL
        && Except_frame.exception->reason != NULL)
      SOCKET_LOG_WARN_MSG ("HTTP/2 stream error: %s",
                           Except_frame.exception->reason);
    stream_error = 1;
    r = 0;
  }
  EXCEPT (Socket_Failed)
  {
    return -1;
  }
  END_TRY;

  if (!stream_error && r < 0)
    return -1;

  TRY
  {
    f = SocketHTTP2_Conn_flush (conn->http2_conn);
  }
  EXCEPT (Socket_Failed)
  {
    return -1;
  }
  EXCEPT (SocketHTTP2_FlowControlError)
  {
    return -1;
  }
  END_TRY;

  if (SocketHTTP2_Conn_is_closed (conn->http2_conn))
    return -1;

  if (f == 1)
    SocketPoll_mod (server->poll, conn->socket, POLL_READ | POLL_WRITE, conn);
  else
    SocketPoll_mod (server->poll, conn->socket, POLL_READ, conn);

  return 0;
}

static int
server_header_has_token_ci (const char *value, const char *token)
{
  const char *p;
  size_t token_len;

  if (value == NULL || token == NULL)
    return 0;

  token_len = strlen (token);
  if (token_len == 0)
    return 0;

  p = value;
  while (*p != '\0')
    {
      while (*p == ' ' || *p == '\t' || *p == ',')
        p++;
      if (*p == '\0')
        break;

      const char *start = p;
      while (*p != '\0' && *p != ',')
        p++;
      const char *end = p;

      while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
        end--;

      size_t len = (size_t)(end - start);
      if (len == token_len && strncasecmp (start, token, token_len) == 0)
        return 1;
    }

  return 0;
}

static int
server_decode_http2_settings (Arena_T arena,
                              const char *b64url,
                              unsigned char **out,
                              size_t *out_len)
{
  size_t in_len;
  char *tmp;
  size_t tmp_len;
  unsigned char *decoded;
  size_t decoded_max;
  ssize_t decoded_len;

  assert (out != NULL);
  assert (out_len != NULL);

  *out = NULL;
  *out_len = 0;

  if (b64url == NULL)
    return -1;

  in_len = strlen (b64url);
  if (in_len == 0)
    return -1;

  /* HTTP2-Settings uses base64url (token68) without padding */
  tmp_len = in_len;
  tmp = Arena_alloc (arena, tmp_len + 1, __FILE__, __LINE__);
  if (tmp == NULL)
    return -1;

  for (size_t i = 0; i < in_len; i++)
    {
      char c = b64url[i];
      if (c == '-')
        c = '+';
      else if (c == '_')
        c = '/';
      tmp[i] = c;
    }
  tmp[tmp_len] = '\0';

  decoded_max = SocketCrypto_base64_decoded_size (tmp_len);
  decoded = Arena_alloc (arena, decoded_max, __FILE__, __LINE__);
  if (decoded == NULL)
    return -1;

  decoded_len = -1;
  TRY
  {
    decoded_len
        = SocketCrypto_base64_decode (tmp, tmp_len, decoded, decoded_max);
  }
  EXCEPT (SocketCrypto_Failed)
  {
    return -1;
  }
  END_TRY;
  if (decoded_len < 0)
    return -1;

  *out = decoded;
  *out_len = (size_t)decoded_len;
  return 0;
}

/* RFC 9113 §8.3: Check if header should be copied during h2c upgrade.
 * Returns 1 if header should be copied, 0 if it should be filtered out. */
static int
should_copy_header_to_h2 (const char *name, const char *value)
{
  if (name == NULL || value == NULL)
    return 0;

  /* RFC 9113 §8.3.1: Connection-specific headers must be removed */
  if (strcasecmp (name, "Connection") == 0 || strcasecmp (name, "Upgrade") == 0
      || strcasecmp (name, "HTTP2-Settings") == 0
      || strcasecmp (name, "Keep-Alive") == 0
      || strcasecmp (name, "Proxy-Connection") == 0)
    return 0;

  /* Host header is converted to :authority pseudo-header */
  if (strcasecmp (name, "Host") == 0)
    return 0;

  /* RFC 9113 §8.2.2: TE header only allowed with value "trailers" */
  if (strcasecmp (name, "TE") == 0 && strcasecmp (value, "trailers") != 0)
    return 0;

  return 1;
}

static int
server_try_h2c_upgrade (SocketHTTPServer_T server, ServerConnection *conn)
{
  const SocketHTTP_Request *req;
  SocketHTTP_Headers_T headers;
  const char *upgrade;
  const char *connection;
  const char *settings_b64;
  unsigned char *settings_payload = NULL;
  size_t settings_len = 0;

  assert (server != NULL);
  assert (conn != NULL);

  if (!server->config.enable_h2c_upgrade)
    return 0;
  if (server->config.max_version < HTTP_VERSION_2)
    return 0;
  if (server->config.tls_context != NULL)
    return 0; /* h2c is cleartext */

  req = conn->request;
  if (req == NULL || req->headers == NULL)
    return 0;

  headers = req->headers;
  upgrade = SocketHTTP_Headers_get (headers, "Upgrade");
  connection = SocketHTTP_Headers_get (headers, "Connection");
  settings_b64 = SocketHTTP_Headers_get (headers, "HTTP2-Settings");

  if (upgrade == NULL || strcasecmp (upgrade, "h2c") != 0)
    return 0;

  if (!server_header_has_token_ci (connection, "Upgrade")
      || !server_header_has_token_ci (connection, "HTTP2-Settings"))
    return 0;

  /* RFC 9113 §3.2.1: If the upgrade request contains a payload body, it must
   * be fully received before switching to HTTP/2 frames. */
  if (req->has_body)
    return 0;

  /* RFC 9113 §3.2.1: There MUST be exactly one HTTP2-Settings header */
  if (settings_b64 == NULL)
    return 0;

  /* Count HTTP2-Settings headers - there must be exactly one */
  const char *settings_values[10]; /* Max 10 headers should be sufficient */
  size_t settings_count = SocketHTTP_Headers_get_all (
      headers,
      "HTTP2-Settings",
      settings_values,
      sizeof (settings_values) / sizeof (settings_values[0]));

  if (settings_count != 1)
    return 0;

  if (server_decode_http2_settings (
          conn->arena, settings_b64, &settings_payload, &settings_len)
      < 0)
    {
      connection_send_error (server, conn, 400, "Bad Request");
      conn->state = CONN_STATE_CLOSED;
      return 1;
    }

  /* Send 101 Switching Protocols for h2c upgrade. */
  {
    char resp_buf[HTTPSERVER_RESPONSE_HEADER_BUFFER_SIZE];
    SocketHTTP_Headers_T resp_headers = SocketHTTP_Headers_new (conn->arena);
    SocketHTTP_Response resp;
    ssize_t resp_len;

    if (resp_headers == NULL)
      {
        conn->state = CONN_STATE_CLOSED;
        return 1;
      }

    SocketHTTP_Headers_set (resp_headers, "Connection", "Upgrade");
    SocketHTTP_Headers_set (resp_headers, "Upgrade", "h2c");

    memset (&resp, 0, sizeof (resp));
    resp.version = HTTP_VERSION_1_1;
    resp.status_code = 101;
    resp.headers = resp_headers;

    resp_len
        = SocketHTTP1_serialize_response (&resp, resp_buf, sizeof (resp_buf));
    if (resp_len < 0
        || connection_send_data (server, conn, resp_buf, (size_t)resp_len) < 0)
      {
        conn->state = CONN_STATE_CLOSED;
        return 1;
      }
  }

  conn->http2_conn = SocketHTTP2_Conn_upgrade_server (
      conn->socket, req, settings_payload, settings_len, conn->arena);
  if (conn->http2_conn == NULL)
    {
      conn->state = CONN_STATE_CLOSED;
      return 1;
    }

  conn->is_http2 = 1;
  conn->state = CONN_STATE_HTTP2;

  if (server_http2_enable (server, conn) < 0)
    {
      conn->state = CONN_STATE_CLOSED;
      return 1;
    }

  /* Transfer any already-buffered bytes (read by HTTP/1 parser) into HTTP/2
   * recv buffer so we don't drop frames sent immediately after upgrade. */
  while (SocketBuf_available (conn->inbuf) > 0)
    {
      size_t avail = 0;
      const void *ptr = SocketBuf_readptr (conn->inbuf, &avail);
      if (avail == 0 || ptr == NULL)
        break;
      if (!SocketBuf_ensure (conn->http2_conn->recv_buf, avail))
        break;
      SocketBuf_write (conn->http2_conn->recv_buf, ptr, avail);
      SocketBuf_consume (conn->inbuf, avail);
    }

  SocketHTTP2_Stream_T stream1
      = SocketHTTP2_Conn_get_stream (conn->http2_conn, 1);
  if (stream1 != NULL)
    {
      ServerHTTP2Stream *s
          = server_http2_stream_get_or_create (server, conn, stream1);
      if (s != NULL && s->request == NULL)
        {
          SocketHTTP_Request *h2req;
          SocketHTTP_Headers_T h2h;
          const char *host;

          h2req = Arena_alloc (s->arena, sizeof (*h2req), __FILE__, __LINE__);
          h2h = SocketHTTP_Headers_new (s->arena);
          if (h2req != NULL && h2h != NULL)
            {
              memset (h2req, 0, sizeof (*h2req));

              host = SocketHTTP_Headers_get (headers, "Host");
              h2req->method = req->method;
              h2req->version = HTTP_VERSION_2;
              h2req->scheme = "http";
              h2req->authority
                  = host ? socket_util_arena_strdup (s->arena, host) : "";
              h2req->path = req->path
                                ? socket_util_arena_strdup (s->arena, req->path)
                                : "/";
              h2req->headers = h2h;
              h2req->content_length = -1;
              h2req->has_body = 0;

              for (size_t i = 0; i < SocketHTTP_Headers_count (headers); i++)
                {
                  const SocketHTTP_Header *hdr
                      = SocketHTTP_Headers_at (headers, i);
                  if (hdr == NULL)
                    continue;
                  if (should_copy_header_to_h2 (hdr->name, hdr->value))
                    SocketHTTP_Headers_add (h2h, hdr->name, hdr->value);
                }

              s->request = h2req;
              s->request_complete = 1;
              s->request_end_stream = 1;

              HTTP2ServerCallbackCtx tmp;
              tmp.server = server;
              tmp.conn = conn;
              server_http2_handle_request (&tmp, s);
            }
        }
    }

  SocketPoll_mod (server->poll, conn->socket, POLL_READ | POLL_WRITE, conn);
  return 1;
}

static int
server_try_http2_prior_knowledge (SocketHTTPServer_T server,
                                  ServerConnection *conn,
                                  unsigned events)
{
  unsigned char preface[HTTP2_PREFACE_SIZE];
  int fd;
  ssize_t n;

  assert (server != NULL);
  assert (conn != NULL);

  if (!(events & POLL_READ))
    return 0;
  if (server->config.tls_context != NULL)
    return 0;
  if (server->config.max_version < HTTP_VERSION_2)
    return 0;
  if (conn->state != CONN_STATE_READING_REQUEST)
    return 0;
  if (conn->http2_conn != NULL || conn->is_http2)
    return 0;

  fd = Socket_fd (conn->socket);
  n = recv (fd, preface, sizeof (preface), MSG_PEEK | MSG_DONTWAIT);
  if (n < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      return 0;
    }
  if ((size_t)n < sizeof (preface))
    return 0;

  if (memcmp (preface, HTTP2_CLIENT_PREFACE, HTTP2_PREFACE_SIZE) != 0)
    return 0;

  conn->is_http2 = 1;
  conn->state = CONN_STATE_HTTP2;

  if (server_http2_enable (server, conn) < 0)
    {
      conn->state = CONN_STATE_CLOSED;
      return 0;
    }

  (void)server_process_http2 (server, conn, events);
  return 1;
}

/* Check rate limit for request path. Returns 1 if allowed, 0 if rate limited
 * (sends 429) */
static int
server_check_rate_limit (SocketHTTPServer_T server, ServerConnection *conn)
{
  SocketRateLimit_T limiter
      = find_rate_limiter (server, conn->request ? conn->request->path : NULL);
  if (limiter != NULL && !SocketRateLimit_try_acquire (limiter, 1))
    {
      SERVER_METRICS_INC (
          server, SOCKET_CTR_HTTP_SERVER_RATE_LIMITED, rate_limited);
      connection_send_error (server, conn, 429, "Too Many Requests");
      return 0;
    }
  return 1;
}

/* Run validator callback. Returns 1 if allowed, 0 if rejected */
static int
server_run_validator_impl (SocketHTTPServer_T server, ServerConnection *conn)
{
  int reject_status = 0;
  struct SocketHTTPServer_Request req_ctx;

  if (server->validator == NULL)
    return 1;

  req_ctx.server = server;
  req_ctx.conn = conn;
  req_ctx.h2_stream = NULL;
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

/* Run validator early (after headers, before body). Allows setting up body
 * streaming */
int
server_run_validator_early (SocketHTTPServer_T server, ServerConnection *conn)
{
  return server_run_validator_impl (server, conn);
}

/* Invoke middleware chain and request handler. Middleware can short-circuit by
 * returning non-zero */
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
  req_ctx.h2_stream = NULL;
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
          SERVER_METRICS_INC (
              server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL, requests_total);
          return 1;
        }
    }

  /* All middleware passed, invoke main handler */
  if (server->handler != NULL)
    {
      server->handler (&req_ctx, server->handler_userdata);
    }

  /* Update request counter (global + per-server) */
  SERVER_METRICS_INC (
      server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL, requests_total);

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
  route = server_find_static_route (server, path);
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

  result = server_serve_static_file (server, conn, route, file_path);

  if (result == 1)
    {
      /* File was served (or 304/416 sent) */
      SERVER_METRICS_INC (
          server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL, requests_total);
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
server_handle_parsed_request (SocketHTTPServer_T server, ServerConnection *conn)
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

  /* HTTP/1.1 Upgrade: h2c (cleartext HTTP/2). */
  if (server_try_h2c_upgrade (server, conn))
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
 * server_process_streaming_body - Handle streaming body callback
 * @server: HTTP server
 * @conn: Connection with streaming body
 * @input: Input buffer pointer
 * @input_len: Input buffer length
 *
 * Returns: Number of requests processed (0 or 1), or -1 on error/close
 *
 * Processes request body in streaming mode, invoking the body callback
 * for each chunk. Returns early if callback aborts or parser fails.
 */
static int
server_process_streaming_body (SocketHTTPServer_T server,
                               ServerConnection *conn,
                               const void *input,
                               size_t input_len)
{
  char temp_buf[HTTPSERVER_RECV_BUFFER_SIZE];
  size_t temp_avail = sizeof (temp_buf);
  size_t consumed, written;
  SocketHTTP1_Result r;

  r = SocketHTTP1_Parser_read_body (conn->parser,
                                    (const char *)input,
                                    input_len,
                                    &consumed,
                                    temp_buf,
                                    temp_avail,
                                    &written);

  SocketBuf_consume (conn->inbuf, consumed);
  conn->body_received += written;

  /* Invoke callback with chunk data */
  if (written > 0)
    {
      int is_final = SocketHTTP1_Parser_body_complete (conn->parser) ? 1 : 0;

      /* Create request context for callback */
      struct SocketHTTPServer_Request req_ctx;
      req_ctx.server = server;
      req_ctx.conn = conn;
      req_ctx.h2_stream = NULL;
      req_ctx.arena = conn->arena;
      req_ctx.start_time_ms = conn->request_start_ms;

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

  if (r == HTTP1_ERROR || r < 0)
    {
      SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_5XX);
      conn->state = CONN_STATE_CLOSED;
      return -1;
    }

  if (SocketHTTP1_Parser_body_complete (conn->parser))
    {
      conn->state = CONN_STATE_HANDLING;
      return server_handle_parsed_request (server, conn);
    }

  return 0;
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
      /* TLS handshake must complete before any application reads. */
      if (conn->state != CONN_STATE_TLS_HANDSHAKE
          && conn->state != CONN_STATE_HTTP2)
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
          int result
              = server_process_streaming_body (server, conn, input, input_len);
          if (result < 0)
            return requests_processed;
          if (result > 0)
            requests_processed = result;
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
                  SocketMetrics_counter_inc (
                      SOCKET_CTR_LIMIT_BODY_SIZE_EXCEEDED);
                  connection_send_error (
                      server, conn, 413, "Payload Too Large");
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

          r = SocketHTTP1_Parser_read_body (conn->parser,
                                            (const char *)input,
                                            input_len,
                                            &consumed,
                                            (char *)write_ptr,
                                            write_avail,
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

          r = SocketHTTP1_Parser_read_body (conn->parser,
                                            (const char *)input,
                                            input_len,
                                            &consumed,
                                            output,
                                            output_avail,
                                            &written);

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
 * SECURITY: Enhanced timeout enforcement to prevent Slowloris attacks
 * - TLS handshake timeout (CONN_STATE_TLS_HANDSHAKE)
 * - HTTP/2 idle connection timeout (CONN_STATE_HTTP2)
 * - Header parsing timeout (CONN_STATE_READING_REQUEST with partial data)
 * - Global connection lifetime limit (defense-in-depth)
 *
 * Returns: 1 if timed out (connection closed), 0 otherwise
 */
static int
server_check_connection_timeout (SocketHTTPServer_T server,
                                 ServerConnection *conn,
                                 int64_t now)
{
  int64_t idle_ms = now - conn->last_activity_ms;
  int64_t connection_age_ms = now - conn->created_at_ms;

  /* SECURITY: Global connection lifetime timeout (defense-in-depth)
   * Protects against any state-based attack where connections are held
   * indefinitely. Applies to all states. Set to 0 to disable. */
  if (server->config.max_connection_lifetime_ms > 0
      && connection_age_ms > server->config.max_connection_lifetime_ms)
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

  /* SECURITY: TLS handshake timeout
   * Prevents slowloris attacks during TLS negotiation phase.
   * Attacker can hold connection indefinitely during handshake without this. */
  if (conn->state == CONN_STATE_TLS_HANDSHAKE
      && server->config.tls_handshake_timeout_ms > 0
      && idle_ms > server->config.tls_handshake_timeout_ms)
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

  /* Check keepalive timeout */
  if (conn->state == CONN_STATE_READING_REQUEST
      && idle_ms > server->config.keepalive_timeout_ms)
    {
      SERVER_METRICS_INC (
          server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT, requests_timeout);
      connection_close (server, conn);
      return 1;
    }

  /* SECURITY: Header parsing timeout
   * Prevents slowloris attacks where headers are sent slowly.
   * Use request_start_ms if set (request started), otherwise use
   * last_activity_ms for connections that haven't started a request yet. */
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

  /* Check request read timeout (body reading) */
  if (conn->state == CONN_STATE_READING_BODY && conn->request_start_ms > 0
      && (now - conn->request_start_ms)
             > server->config.request_read_timeout_ms)
    {
      SERVER_METRICS_INC (
          server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT, requests_timeout);
      connection_close (server, conn);
      return 1;
    }

  /* Check response write timeout */
  if (conn->state == CONN_STATE_STREAMING_RESPONSE
      && conn->response_start_ms > 0
      && (now - conn->response_start_ms)
             > server->config.response_write_timeout_ms)
    {
      SERVER_METRICS_INC (
          server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT, requests_timeout);
      connection_close (server, conn);
      return 1;
    }

  /* SECURITY: HTTP/2 idle connection timeout
   * Prevents resource exhaustion from idle HTTP/2 connections.
   * HTTP/2 connections can be long-lived, but should close if truly idle. */
  if (conn->state == CONN_STATE_HTTP2
      && idle_ms > server->config.keepalive_timeout_ms)
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

/* Process server events. Returns number of requests processed */
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
          /* Skip connections marked for deferred deletion.
           * This can happen when io_uring or other backends return
           * multiple events for the same connection in a single batch,
           * and an earlier event closed the connection. */
          if (conn != NULL && !conn->pending_close)
            {
              requests_processed
                  += server_process_client_event (server, conn, ev->events);
            }
        }
    }

  server_cleanup_timed_out (server);

  /* Free connections that were closed during this event loop iteration.
   * Deferred deletion prevents use-after-free when multiple events
   * for the same connection arrive in a single poll batch. */
  connection_free_pending (server);

  return requests_processed;
}

SocketHTTP_Method
SocketHTTPServer_Request_method (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  if (req->h2_stream != NULL && req->h2_stream->request != NULL)
    return req->h2_stream->request->method;
  if (req->conn->request == NULL)
    return HTTP_METHOD_UNKNOWN;
  return req->conn->request->method;
}

const char *
SocketHTTPServer_Request_path (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  if (req->h2_stream != NULL && req->h2_stream->request != NULL)
    return req->h2_stream->request->path;
  if (req->conn->request == NULL)
    return "/";
  return req->conn->request->path;
}

const char *
SocketHTTPServer_Request_query (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  if (req->h2_stream != NULL && req->h2_stream->request != NULL)
    {
      const char *path = req->h2_stream->request->path;
      const char *q;
      if (path == NULL)
        return NULL;
      q = strchr (path, '?');
      return q ? q + 1 : NULL;
    }
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
  if (req->h2_stream != NULL && req->h2_stream->request != NULL)
    return req->h2_stream->request->headers;
  if (req->conn->request == NULL)
    return NULL;
  return req->conn->request->headers;
}

SocketHTTP_Headers_T
SocketHTTPServer_Request_trailers (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);

  if (req->h2_stream != NULL)
    return req->h2_stream->request_trailers;

  return NULL;
}

const char *
SocketHTTPServer_Request_h2_protocol (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);

  if (req->h2_stream != NULL)
    return req->h2_stream->h2_protocol;

  return NULL;
}

const void *
SocketHTTPServer_Request_body (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);

  if (req->h2_stream != NULL)
    {
      ServerHTTP2Stream *s = req->h2_stream;
      if (s->body_streaming)
        return NULL;
      if (s->body_uses_buf)
        {
          SocketBuf_compact (s->body_buf);
          size_t len;
          return SocketBuf_readptr (s->body_buf, &len);
        }
      return s->body;
    }

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

  if (req->h2_stream != NULL)
    {
      ServerHTTP2Stream *s = req->h2_stream;
      if (s->body_streaming)
        return 0;
      if (s->body_uses_buf)
        return SocketBuf_available (s->body_buf);
      return s->body_len;
    }

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
  if (req->h2_stream != NULL && req->h2_stream->request != NULL)
    return HTTP_VERSION_2;
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


void
SocketHTTPServer_Request_status (SocketHTTPServer_Request_T req, int code)
{
  assert (req != NULL);
  *server_response_status_ptr (req) = code;
}

void
SocketHTTPServer_Request_header (SocketHTTPServer_Request_T req,
                                 const char *name,
                                 const char *value)
{
  SocketHTTP_Headers_T *headers_ptr;
  const char *p;

  assert (req != NULL);
  assert (name != NULL);
  assert (value != NULL);

  /* Reject headers with CRLF characters (injection prevention) */
  for (p = name; *p; p++)
    {
      if (*p == '\r' || *p == '\n')
        {
          SOCKET_LOG_WARN_MSG ("Rejected response header with CRLF characters");
          return;
        }
    }
  for (p = value; *p; p++)
    {
      if (*p == '\r' || *p == '\n')
        {
          SOCKET_LOG_WARN_MSG ("Rejected response header with CRLF characters");
          return;
        }
    }

  headers_ptr = server_response_headers_ptr (req);
  if (*headers_ptr == NULL)
    *headers_ptr = SocketHTTP_Headers_new (req->arena);
  SocketHTTP_Headers_add (*headers_ptr, name, value);
}

int
SocketHTTPServer_Request_trailer (SocketHTTPServer_Request_T req,
                                  const char *name,
                                  const char *value)
{
  assert (req != NULL);
  assert (name != NULL);
  assert (value != NULL);

  if (req->h2_stream == NULL)
    return -1;

  /* RFC 9113 §8.1.3: Pseudo-header fields MUST NOT appear in trailer fields */
  if (name[0] == ':')
    return -1;

  if (req->h2_stream->response_end_stream_sent)
    return -1;

  if (req->h2_stream->response_trailers == NULL)
    req->h2_stream->response_trailers = SocketHTTP_Headers_new (req->arena);
  if (req->h2_stream->response_trailers == NULL)
    return -1;

  SocketHTTP_Headers_add (req->h2_stream->response_trailers, name, value);
  return 0;
}

void
SocketHTTPServer_Request_body_data (SocketHTTPServer_Request_T req,
                                    const void *data,
                                    size_t len)
{
  void **body_ptr;
  size_t *body_len_ptr;
  void *body_copy;

  assert (req != NULL);

  body_ptr = server_response_body_ptr (req);
  body_len_ptr = server_response_body_len_ptr (req);

  if (data == NULL || len == 0)
    {
      *body_ptr = NULL;
      *body_len_ptr = 0;
      return;
    }

  body_copy = Arena_alloc (req->arena, len, __FILE__, __LINE__);
  if (body_copy != NULL)
    {
      memcpy (body_copy, data, len);
      *body_ptr = body_copy;
      *body_len_ptr = len;
    }
}

void
SocketHTTPServer_Request_body_string (SocketHTTPServer_Request_T req,
                                      const char *str)
{
  assert (req != NULL);

  if (str == NULL)
    {
      *server_response_body_ptr (req) = NULL;
      *server_response_body_len_ptr (req) = 0;
      return;
    }

  SocketHTTPServer_Request_body_data (req, str, strlen (str));
}

void
SocketHTTPServer_Request_finish (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  *server_response_finished_ptr (req) = 1;
}


void
SocketHTTPServer_Request_body_stream (SocketHTTPServer_Request_T req,
                                      SocketHTTPServer_BodyCallback callback,
                                      void *userdata)
{
  assert (req != NULL);

  *server_body_callback_ptr (req) = callback;
  *server_body_callback_userdata_ptr (req) = userdata;
  *server_body_streaming_ptr (req) = 1;
}

int64_t
SocketHTTPServer_Request_body_expected (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  if (req->h2_stream != NULL && req->h2_stream->request != NULL)
    return req->h2_stream->request->content_length;
  return SocketHTTP1_Parser_content_length (req->conn->parser);
}

int
SocketHTTPServer_Request_is_chunked (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  if (req->h2_stream != NULL)
    return 0;
  return SocketHTTP1_Parser_body_mode (req->conn->parser) == HTTP1_BODY_CHUNKED;
}


int
SocketHTTPServer_Request_begin_stream (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);

  if (req->h2_stream != NULL)
    {
      ServerHTTP2Stream *s = req->h2_stream;
      SocketHTTP_Response response;

      if (s->response_headers_sent)
        return -1;

      if (s->response_headers == NULL)
        s->response_headers = SocketHTTP_Headers_new (req->arena);

      memset (&response, 0, sizeof (response));
      response.version = HTTP_VERSION_2;
      response.status_code = s->response_status;
      response.headers = s->response_headers;

      if (SocketHTTP2_Stream_send_response (s->stream, &response, 0) < 0)
        return -1;

      s->response_streaming = 1;
      s->response_headers_sent = 1;
      return 0;
    }

  if (req->conn->response_headers_sent)
    return -1;

  /* Add Transfer-Encoding: chunked header */
  SocketHTTP_Headers_set (
      req->conn->response_headers, "Transfer-Encoding", "chunked");

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
                                     const void *data,
                                     size_t len)
{
  assert (req != NULL);

  if (req->h2_stream != NULL)
    {
      ServerHTTP2Stream *s = req->h2_stream;
      const unsigned char *p = (const unsigned char *)data;
      ssize_t accepted;

      if (!s->response_streaming || !s->response_headers_sent)
        return -1;

      if (len == 0)
        return 0;

      accepted = SocketHTTP2_Stream_send_data (s->stream, data, len, 0);
      if (accepted < 0)
        return -1;

      if ((size_t)accepted < len)
        {
          if (s->response_outbuf == NULL)
            s->response_outbuf
                = SocketBuf_new (s->arena, HTTPSERVER_IO_BUFFER_SIZE);
          if (s->response_outbuf == NULL)
            return -1;
          if (!SocketBuf_ensure (s->response_outbuf, len - (size_t)accepted))
            return -1;
          SocketBuf_write (
              s->response_outbuf, p + accepted, len - (size_t)accepted);
        }

      /* Try to flush any buffered remainder immediately. */
      server_http2_flush_stream_output (req->conn, s);

      return 0;
    }

  if (!req->conn->response_streaming || !req->conn->response_headers_sent)
    return -1;

  if (len == 0)
    return 0;

  char chunk_buf[HTTPSERVER_CHUNK_BUFFER_SIZE];
  ssize_t chunk_len
      = SocketHTTP1_chunk_encode (data, len, chunk_buf, sizeof (chunk_buf));
  if (chunk_len < 0)
    return -1;

  return connection_send_data (
      req->server, req->conn, chunk_buf, (size_t)chunk_len);
}

int
SocketHTTPServer_Request_end_stream (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);

  if (req->h2_stream != NULL)
    {
      ServerHTTP2Stream *s = req->h2_stream;

      if (!s->response_streaming)
        return -1;

      s->response_finished = 1;

      /* Try to flush any buffered output and then send END_STREAM. */
      server_http2_flush_stream_output (req->conn, s);

      if (!s->response_end_stream_sent
          && (s->response_outbuf == NULL
              || SocketBuf_available (s->response_outbuf) == 0))
        {
          /* server_http2_flush_stream_output() will send trailers or END_STREAM
           * once all pending output is drained. */
          server_http2_flush_stream_output (req->conn, s);
        }

      return 0;
    }

  if (!req->conn->response_streaming)
    return -1;

  char final_buf[HTTPSERVER_CHUNK_FINAL_BUF_SIZE];
  ssize_t final_len
      = SocketHTTP1_chunk_final (final_buf, sizeof (final_buf), NULL);
  if (final_len < 0)
    return -1;

  if (connection_send_data (
          req->server, req->conn, final_buf, (size_t)final_len)
      < 0)
    return -1;

  connection_finish_request (req->server, req->conn);
  return 0;
}


int
SocketHTTPServer_Request_push (SocketHTTPServer_Request_T req,
                               const char *path,
                               SocketHTTP_Headers_T headers)
{
  assert (req != NULL);
  assert (path != NULL);

  /* Only available for HTTP/2 requests */
  if (req->h2_stream == NULL || req->h2_stream->request == NULL
      || req->conn->http2_conn == NULL)
    return -1;

  /* Peer can disable push via SETTINGS_ENABLE_PUSH=0 */
  if (SocketHTTP2_Conn_get_setting (req->conn->http2_conn,
                                    HTTP2_SETTINGS_ENABLE_PUSH)
      == 0)
    return -1;

  if (path[0] != '/')
    return -1;

  const SocketHTTP_Request *parent_req = req->h2_stream->request;
  const char *scheme = parent_req->scheme ? parent_req->scheme : "https";
  const char *authority = parent_req->authority ? parent_req->authority : "";

  size_t extra = headers ? SocketHTTP_Headers_count (headers) : 0;
  size_t total = HTTP2_REQUEST_PSEUDO_HEADER_COUNT + extra;

  SocketHPACK_Header *hpack
      = Arena_alloc (req->arena, total * sizeof (*hpack), __FILE__, __LINE__);
  if (hpack == NULL)
    return -1;

  memset (hpack, 0, total * sizeof (*hpack));

  /* Pseudo-headers */
  hpack[0].name = ":method";
  hpack[0].name_len = 7;
  hpack[0].value = "GET";
  hpack[0].value_len = 3;

  hpack[1].name = ":scheme";
  hpack[1].name_len = 7;
  hpack[1].value = scheme;
  hpack[1].value_len = strlen (scheme);

  hpack[2].name = ":authority";
  hpack[2].name_len = 10;
  hpack[2].value = authority;
  hpack[2].value_len = strlen (authority);

  hpack[3].name = ":path";
  hpack[3].name_len = 5;
  hpack[3].value = path;
  hpack[3].value_len = strlen (path);

  /* Additional headers */
  size_t out_idx = HTTP2_REQUEST_PSEUDO_HEADER_COUNT;
  if (headers != NULL)
    {
      for (size_t i = 0; i < extra; i++)
        {
          const SocketHTTP_Header *hdr = SocketHTTP_Headers_at (headers, i);
          if (hdr == NULL || hdr->name == NULL || hdr->value == NULL)
            continue;
          if (hdr->name[0] == ':')
            continue; /* disallow pseudo headers from user input */

          hpack[out_idx].name = hdr->name;
          hpack[out_idx].name_len = strlen (hdr->name);
          hpack[out_idx].value = hdr->value;
          hpack[out_idx].value_len = strlen (hdr->value);
          out_idx++;
        }
    }

  total = out_idx;

  SocketHTTP2_Stream_T promised
      = SocketHTTP2_Stream_push_promise (req->h2_stream->stream, hpack, total);
  if (promised == NULL)
    return -1;

  /* Build synthetic request on promised stream and run normal handler pipeline.
   */
  ServerHTTP2Stream *ps
      = server_http2_stream_get_or_create (req->server, req->conn, promised);
  if (ps == NULL)
    return -1;

  if (server_http2_build_request (req->server, ps, hpack, total, 1) < 0)
    return -1;

  ps->request_complete = 1;

  HTTP2ServerCallbackCtx cb;
  cb.server = req->server;
  cb.conn = req->conn;
  server_http2_handle_request (&cb, ps);

  return 0;
}

int
SocketHTTPServer_Request_is_http2 (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  if (req->h2_stream != NULL && req->h2_stream->request != NULL)
    return 1;
  if (req->conn->request == NULL)
    return 0;
  return req->conn->request->version == HTTP_VERSION_2;
}


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
    ws = SocketWS_server_accept (
        req->conn->socket, req->conn->request, ws_config);
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

SocketHTTP2_Stream_T
SocketHTTPServer_Request_accept_websocket_h2 (
    SocketHTTPServer_Request_T req,
    SocketHTTPServer_BodyCallback callback,
    void *userdata)
{
  ServerHTTP2Stream *s;
  const char *version;
  SocketHTTP_Response response;

  assert (req != NULL);

  if (req->h2_stream == NULL || req->h2_stream->request == NULL)
    return NULL;

  if (callback == NULL)
    return NULL;

  s = req->h2_stream;

  /* RFC 8441 Extended CONNECT: :method=CONNECT, :protocol=websocket */
  if (s->request->method != HTTP_METHOD_CONNECT)
    return NULL;
  if (s->h2_protocol == NULL || strcmp (s->h2_protocol, "websocket") != 0)
    return NULL;

  version
      = SocketHTTP_Headers_get (s->request->headers, "Sec-WebSocket-Version");
  if (version != NULL && strcmp (version, "13") != 0)
    return NULL;

  if (s->response_headers_sent)
    return NULL;

  if (s->response_headers == NULL)
    s->response_headers = SocketHTTP_Headers_new (req->arena);
  if (s->response_headers == NULL)
    return NULL;

  s->response_status = 200;

  memset (&response, 0, sizeof (response));
  response.version = HTTP_VERSION_2;
  response.status_code = 200;
  response.headers = s->response_headers;

  TRY
  {
    if (SocketHTTP2_Stream_send_response (s->stream, &response, 0) < 0)
      return NULL;
  }
  EXCEPT (Socket_Failed)
  {
    return NULL;
  }
  EXCEPT (SocketHTTP2_ProtocolError)
  {
    return NULL;
  }
  END_TRY;

  /* Mark as streaming so server won't auto-send a standard HTTP response. */
  s->response_streaming = 1;
  s->response_headers_sent = 1;

  /* Deliver future DATA bytes via callback (WebSocket frames on DATA stream).
   */
  s->body_streaming = 1;
  s->body_callback = callback;
  s->body_callback_userdata = userdata;
  s->ws_over_h2 = 1;

  return s->stream;
}


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


void
SocketHTTPServer_set_validator (SocketHTTPServer_T server,
                                SocketHTTPServer_Validator validator,
                                void *userdata)
{
  assert (server != NULL);
  server->validator = validator;
  server->validator_userdata = userdata;
}


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

  /* For HTTP/2 connections, send GOAWAY so clients stop opening new streams. */
  for (ServerConnection *conn = server->connections; conn != NULL;
       conn = conn->next)
    {
      if (conn->state == CONN_STATE_HTTP2 && conn->http2_conn != NULL)
        {
          TRY
          {
            SocketHTTP2_Conn_goaway (conn->http2_conn, HTTP2_NO_ERROR, NULL, 0);
          }
          EXCEPT (SocketHTTP2_ProtocolError)
          {
            /* Best-effort during drain. */
          }
          EXCEPT (SocketHTTP2_FlowControlError)
          {
            /* Best-effort during drain. */
          }
          END_TRY;
        }
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
              server->drain_callback (
                  server, 1, server->drain_callback_userdata);
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
      stats->total_connections = SocketMetrics_counter_get (
          SOCKET_CTR_HTTP_SERVER_CONNECTIONS_TOTAL);
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

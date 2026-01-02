/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketHTTPServer-http1.c - HTTP/1.1 protocol handling for HTTP server */

#include <assert.h>
#include <string.h>
#include <strings.h>

#include "core/Arena.h"
#include "core/SocketCrypto.h"
#include "core/SocketMetrics.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTPServer-http1.h"
#include "http/SocketHTTPServer-private.h"
#include "poll/SocketPoll.h"
#include "socket/SocketBuf.h"

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTPServer-HTTP1"

#define SERVER_LOG_ERROR(fmt, ...) SOCKET_LOG_ERROR_MSG (fmt, ##__VA_ARGS__)

/* STRLEN_LIT macro for compile-time string length */
#define STRLEN_LIT(s) (sizeof (s) - 1)

/* Buffer sizes */
#define HTTPSERVER_RESPONSE_HEADER_BUFFER_SIZE 8192
#define HTTPSERVER_RECV_BUFFER_SIZE 16384

int
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

int
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
int
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

int
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

  /* Use Headers_get_n with STRLEN_LIT for performance */
  upgrade = SocketHTTP_Headers_get_n (headers, "Upgrade", STRLEN_LIT ("Upgrade"));
  connection = SocketHTTP_Headers_get_n (headers, "Connection", STRLEN_LIT ("Connection"));
  settings_b64 = SocketHTTP_Headers_get_n (headers, "HTTP2-Settings", STRLEN_LIT ("HTTP2-Settings"));

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

/* Forward declarations for functions defined in SocketHTTPServer.c */
extern int server_check_rate_limit (SocketHTTPServer_T server,
                                    ServerConnection *conn);
extern int server_run_validator (SocketHTTPServer_T server,
                                 ServerConnection *conn);

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

int
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

int
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

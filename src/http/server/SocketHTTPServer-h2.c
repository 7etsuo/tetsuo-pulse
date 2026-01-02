/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTPServer-h2.c
 * @brief HTTP/2 stream handling for HTTP server
 *
 * Implements HTTP/2 server-side stream management:
 * - Stream creation and lifecycle
 * - Header and data frame processing
 * - Response sending (streaming and non-streaming)
 * - Flow control integration
 */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include "core/Arena.h"
#include "poll/SocketPoll.h"
#include "core/SocketLog.h"
#include "core/SocketMetrics.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTPServer-private.h"
#include "http/SocketHTTPServer.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTPServer-H2"

#define SERVER_LOG_ERROR(fmt, ...) SOCKET_LOG_ERROR_MSG (fmt, ##__VA_ARGS__)

/* Module exception handling */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTPServer);

ServerHTTP2Stream *
server_http2_stream_get_or_create (SocketHTTPServer_T server,
                                   ServerConnection *conn,
                                   SocketHTTP2_Stream_T stream)
{
  ServerHTTP2Stream *s
      = (ServerHTTP2Stream *)SocketHTTP2_Stream_get_userdata (stream);

  (void)server;

  if (s != NULL)
    return s;

  Arena_T arena = Arena_new ();
  if (arena == NULL)
    return NULL;

  s = Arena_alloc (arena, sizeof (*s), __FILE__, __LINE__);
  if (s == NULL)
    {
      Arena_dispose (&arena);
      return NULL;
    }

  memset (s, 0, sizeof (*s));
  s->arena = arena;
  s->stream = stream;
  s->response_status = 200;
  s->response_headers = SocketHTTP_Headers_new (arena);

  s->next = conn->http2_streams;
  conn->http2_streams = s;

  SocketHTTP2_Stream_set_userdata (stream, s);
  return s;
}

/* Connection header validation uses shared
 * http2_is_connection_header_forbidden() from SocketHTTP2-validate.c via
 * SocketHTTP2-private.h */

int
server_http2_build_request (SocketHTTPServer_T server,
                            ServerHTTP2Stream *s,
                            const SocketHPACK_Header *headers,
                            size_t header_count,
                            int end_stream)
{
  SocketHTTP_Request *req;
  SocketHTTP_Headers_T h;
  const char *scheme = NULL;
  const char *authority = NULL;
  const char *path = NULL;
  const char *protocol = NULL;
  SocketHTTP_Method method = HTTP_METHOD_UNKNOWN;
  int64_t content_length = -1;

  assert (server != NULL);
  assert (s != NULL);
  assert (headers != NULL);

  if (s->request != NULL)
    return 0;

  h = SocketHTTP_Headers_new (s->arena);
  if (h == NULL)
    return -1;

  /* Validate pseudo-headers and extract them */
  int pseudo_headers_seen = 0;
  int has_method = 0, has_scheme = 0, has_authority = 0, has_path = 0;
  int pseudo_section_ended = 0;

  for (size_t i = 0; i < header_count; i++)
    {
      const SocketHPACK_Header *hdr = &headers[i];

      if (hdr->name == NULL || hdr->value == NULL)
        continue;

      if (hdr->name_len > 0 && hdr->name[0] == ':')
        {
          /* Pseudo-headers must appear before regular headers */
          if (pseudo_section_ended)
            {
              SERVER_LOG_ERROR (
                  "Pseudo-header '%.*s' appears after regular headers",
                  (int)hdr->name_len,
                  hdr->name);
              return -1;
            }

          /* Validate pseudo-header name and track required ones */
          if (hdr->name_len == 7 && memcmp (hdr->name, ":method", 7) == 0)
            {
              if (pseudo_headers_seen & (1 << 0))
                {
                  SERVER_LOG_ERROR ("Duplicate :method pseudo-header");
                  return -1;
                }
              pseudo_headers_seen |= (1 << 0);
              has_method = 1;
              method = SocketHTTP_method_parse (hdr->value, hdr->value_len);
              if (method == HTTP_METHOD_UNKNOWN)
                {
                  SERVER_LOG_ERROR (
                      "Invalid HTTP method in :method pseudo-header");
                  return -1;
                }
            }
          else if (hdr->name_len == 7 && memcmp (hdr->name, ":scheme", 7) == 0)
            {
              if (pseudo_headers_seen & (1 << 1))
                {
                  SERVER_LOG_ERROR ("Duplicate :scheme pseudo-header");
                  return -1;
                }
              pseudo_headers_seen |= (1 << 1);
              has_scheme = 1;
              scheme = socket_util_arena_strndup (
                  s->arena, hdr->value, hdr->value_len);
            }
          else if (hdr->name_len == 10
                   && memcmp (hdr->name, ":authority", 10) == 0)
            {
              if (pseudo_headers_seen & (1 << 2))
                {
                  SERVER_LOG_ERROR ("Duplicate :authority pseudo-header");
                  return -1;
                }
              pseudo_headers_seen |= (1 << 2);
              has_authority = 1;
              authority = socket_util_arena_strndup (
                  s->arena, hdr->value, hdr->value_len);
            }
          else if (hdr->name_len == 5 && memcmp (hdr->name, ":path", 5) == 0)
            {
              if (pseudo_headers_seen & (1 << 3))
                {
                  SERVER_LOG_ERROR ("Duplicate :path pseudo-header");
                  return -1;
                }
              pseudo_headers_seen |= (1 << 3);
              has_path = 1;
              path = socket_util_arena_strndup (
                  s->arena, hdr->value, hdr->value_len);
            }
          else if (hdr->name_len == 9
                   && memcmp (hdr->name, ":protocol", 9) == 0)
            {
              if (pseudo_headers_seen & (1 << 4))
                {
                  SERVER_LOG_ERROR ("Duplicate :protocol pseudo-header");
                  return -1;
                }
              pseudo_headers_seen |= (1 << 4);

              /* :protocol requires SETTINGS_ENABLE_CONNECT_PROTOCOL */
              /* Note: We can't easily check this here as we don't have conn
               * access */
              /* The validation happens in http2_validate_headers on the client
               * side */
              protocol = socket_util_arena_strndup (
                  s->arena, hdr->value, hdr->value_len);
            }
          else
            {
              /* Unknown pseudo-header */
              SERVER_LOG_ERROR (
                  "Unknown pseudo-header: %.*s", (int)hdr->name_len, hdr->name);
              return -1;
            }
          continue;
        }

      /* Regular header - pseudo-header section has ended */
      pseudo_section_ended = 1;

      /* Comprehensive RFC 9113 Section 8.2 header validation:
       * - Field name must be lowercase (no uppercase ASCII)
       * - No prohibited characters (NUL/CR/LF) in name or value
       * - No leading/trailing whitespace in value
       * - Not a forbidden connection-specific header
       * - TE header must contain only "trailers" value
       */
      if (http2_validate_regular_header (hdr) != 0)
        {
          SERVER_LOG_ERROR (
              "Invalid HTTP/2 header: %.*s", (int)hdr->name_len, hdr->name);
          return -1;
        }

      SocketHTTP_Headers_add_n (
          h, hdr->name, hdr->name_len, hdr->value, hdr->value_len);
    }

  /* Validate required pseudo-headers for requests */
  if (!has_method)
    {
      SERVER_LOG_ERROR ("Request missing required :method pseudo-header");
      return -1;
    }
  if (!has_scheme && !has_authority)
    {
      SERVER_LOG_ERROR (
          "Request missing required :scheme or :authority pseudo-header");
      return -1;
    }
  if (!has_path)
    {
      SERVER_LOG_ERROR ("Request missing required :path pseudo-header");
      return -1;
    }

  if (path == NULL)
    path = "/";

  {
    int64_t cl = -1;
    if (SocketHTTP_Headers_get_int (h, "Content-Length", &cl) == 0)
      content_length = cl;
    else
      content_length = -1;
  }

  req = Arena_alloc (s->arena, sizeof (*req), __FILE__, __LINE__);
  if (req == NULL)
    return -1;
  memset (req, 0, sizeof (*req));

  req->method = method;
  req->version = HTTP_VERSION_2;
  req->scheme = scheme;
  req->authority = authority;
  req->path = path;
  req->headers = h;
  req->content_length = content_length;
  req->has_body = end_stream ? 0 : 1;

  s->request = req;
  if (protocol != NULL && s->h2_protocol == NULL)
    s->h2_protocol = (char *)protocol;
  s->request_end_stream = end_stream ? 1 : 0;
  if (end_stream)
    s->request_complete = 1;

  if (req->has_body && content_length > 0
      && (server->config.max_body_size == 0
          || (size_t)content_length <= server->config.max_body_size))
    {
      s->body_capacity = (size_t)content_length;
      s->body = Arena_alloc (s->arena, s->body_capacity, __FILE__, __LINE__);
      if (s->body == NULL)
        return -1;
      s->body_uses_buf = 0;
    }

  return 0;
}

void
server_http2_try_dispose_stream (ServerConnection *conn, ServerHTTP2Stream *s)
{
  assert (conn != NULL);
  assert (s != NULL);

  /* Only dispose when we have fully sent our response (END_STREAM queued/sent)
   * and no buffered output remains. */
  if (!s->response_end_stream_sent)
    return;
  if (s->response_outbuf != NULL
      && SocketBuf_available (s->response_outbuf) > 0)
    return;
  if (s->response_body != NULL && s->response_body_sent < s->response_body_len)
    return;

  /* Unlink */
  ServerHTTP2Stream **pp = &conn->http2_streams;
  while (*pp != NULL && *pp != s)
    pp = &(*pp)->next;
  if (*pp == s)
    *pp = s->next;

  SocketHTTP2_Stream_set_userdata (s->stream, NULL);
  if (s->arena != NULL)
    Arena_dispose (&s->arena);
}

void
server_http2_send_end_stream (ServerConnection *conn, ServerHTTP2Stream *s)
{
  assert (conn != NULL);
  assert (s != NULL);

  if (s->response_end_stream_sent)
    return;

  if (s->response_trailers != NULL
      && SocketHTTP_Headers_count (s->response_trailers) > 0)
    {
      size_t total = SocketHTTP_Headers_count (s->response_trailers);
      size_t count = 0;
      SocketHPACK_Header *trailers = NULL;

      /* Count valid (non-pseudo) trailers. */
      for (size_t i = 0; i < total; i++)
        {
          const SocketHTTP_Header *hdr
              = SocketHTTP_Headers_at (s->response_trailers, i);
          if (hdr == NULL || hdr->name == NULL || hdr->value == NULL)
            continue;
          if (hdr->name[0] == ':')
            continue;
          count++;
        }

      if (count > 0)
        {
          trailers = Arena_alloc (
              s->arena, count * sizeof (*trailers), __FILE__, __LINE__);
          if (trailers == NULL)
            {
              SocketHTTP2_Stream_close (s->stream, HTTP2_INTERNAL_ERROR);
              s->response_end_stream_sent = 1;
              server_http2_try_dispose_stream (conn, s);
              return;
            }
          memset (trailers, 0, count * sizeof (*trailers));

          size_t out = 0;
          for (size_t i = 0; i < total; i++)
            {
              const SocketHTTP_Header *hdr
                  = SocketHTTP_Headers_at (s->response_trailers, i);
              if (hdr == NULL || hdr->name == NULL || hdr->value == NULL)
                continue;
              if (hdr->name[0] == ':')
                continue;
              trailers[out].name = hdr->name;
              trailers[out].name_len = strlen (hdr->name);
              trailers[out].value = hdr->value;
              trailers[out].value_len = strlen (hdr->value);
              out++;
            }

          if (SocketHTTP2_Stream_send_trailers (s->stream, trailers, count) < 0)
            SocketHTTP2_Stream_close (s->stream, HTTP2_INTERNAL_ERROR);
        }
    }
  else
    {
      (void)SocketHTTP2_Stream_send_data (s->stream, "", 0, 1);
    }

  s->response_end_stream_sent = 1;
  server_http2_try_dispose_stream (conn, s);
}

void
server_http2_flush_stream_output (ServerConnection *conn, ServerHTTP2Stream *s)
{
  assert (conn != NULL);
  assert (s != NULL);

  /* Flush buffered chunks first */
  while (s->response_outbuf != NULL)
    {
      size_t avail = 0;
      const void *ptr = SocketBuf_readptr (s->response_outbuf, &avail);
      if (avail == 0 || ptr == NULL)
        break;

      ssize_t sent = SocketHTTP2_Stream_send_data (s->stream, ptr, avail, 0);
      if (sent <= 0)
        break;

      SocketBuf_consume (s->response_outbuf, (size_t)sent);
    }

  /* Flush non-streaming body remainder */
  while (s->response_body != NULL
         && s->response_body_sent < s->response_body_len)
    {
      const unsigned char *p = (const unsigned char *)s->response_body;
      size_t remaining = s->response_body_len - s->response_body_sent;
      ssize_t sent = SocketHTTP2_Stream_send_data (
          s->stream, p + s->response_body_sent, remaining, 0);
      if (sent <= 0)
        break;
      s->response_body_sent += (size_t)sent;
    }

  /* If streaming ended and all pending output is flushed, send END_STREAM. */
  if (s->response_streaming && s->response_finished
      && !s->response_end_stream_sent)
    {
      if ((s->response_outbuf == NULL
           || SocketBuf_available (s->response_outbuf) == 0)
          && (s->response_body == NULL
              || s->response_body_sent >= s->response_body_len))
        {
          server_http2_send_end_stream (conn, s);
        }
    }
}

void
server_http2_send_nonstreaming_response (ServerConnection *conn,
                                         ServerHTTP2Stream *s)
{
  SocketHTTP_Response response;
  int end_stream;
  int has_trailers;

  assert (conn != NULL);
  assert (s != NULL);
  assert (s->response_headers != NULL);

  if (s->response_headers_sent)
    return;

  memset (&response, 0, sizeof (response));
  response.version = HTTP_VERSION_2;
  response.status_code = s->response_status;
  response.headers = s->response_headers;

  has_trailers = (s->response_trailers != NULL
                  && SocketHTTP_Headers_count (s->response_trailers) > 0)
                     ? 1
                     : 0;
  end_stream = ((s->response_body == NULL || s->response_body_len == 0)
                && !has_trailers)
                   ? 1
                   : 0;

  if (SocketHTTP2_Stream_send_response (s->stream, &response, end_stream) < 0)
    {
      SocketHTTP2_Stream_close (s->stream, HTTP2_INTERNAL_ERROR);
      return;
    }

  s->response_headers_sent = 1;

  if (end_stream)
    {
      s->response_end_stream_sent = 1;
      server_http2_try_dispose_stream (conn, s);
      return;
    }

  /* No body, but trailers exist: finalize via trailers (END_STREAM). */
  if ((s->response_body == NULL || s->response_body_len == 0) && has_trailers)
    {
      server_http2_send_end_stream (conn, s);
      return;
    }

  /* Queue as much body as possible now; remainder is flushed later. */
  server_http2_flush_stream_output (conn, s);

  if (s->response_body != NULL && s->response_body_sent >= s->response_body_len
      && (s->response_outbuf == NULL
          || SocketBuf_available (s->response_outbuf) == 0))
    {
      server_http2_send_end_stream (conn, s);
    }
}

void
server_http2_handle_request (HTTP2ServerCallbackCtx *ctx, ServerHTTP2Stream *s)
{
  SocketHTTPServer_T server;
  ServerConnection *conn;
  struct SocketHTTPServer_Request req_ctx;
  int reject_status = 0;

  assert (ctx != NULL);
  server = ctx->server;
  conn = ctx->conn;
  assert (server != NULL);
  assert (conn != NULL);
  assert (s != NULL);
  assert (s->request != NULL);

  if (s->handled)
    return;
  s->handled = 1;

  req_ctx.server = server;
  req_ctx.conn = conn;
  req_ctx.h2_stream = s;
  req_ctx.arena = s->arena;
  req_ctx.start_time_ms = Socket_get_monotonic_ms ();

  if (s->request->path == NULL || s->request->path[0] != '/'
      || strlen (s->request->path) > SOCKETHTTP_MAX_URI_LEN)
    {
      s->response_status = 400;
      SocketHTTPServer_Request_body_string (&req_ctx, "Bad Request");
      SocketHTTPServer_Request_finish (&req_ctx);
      return;
    }

  SocketRateLimit_T limiter = find_rate_limiter (server, s->request->path);
  if (limiter != NULL && !SocketRateLimit_try_acquire (limiter, 1))
    {
      SERVER_METRICS_INC (
          server, SOCKET_CTR_HTTP_SERVER_RATE_LIMITED, rate_limited);
      s->response_status = 429;
      SocketHTTPServer_Request_body_string (&req_ctx, "Too Many Requests");
      SocketHTTPServer_Request_finish (&req_ctx);
      return;
    }

  if (server->validator != NULL)
    {
      if (!server->validator (
              &req_ctx, &reject_status, server->validator_userdata))
        {
          if (reject_status == 0)
            reject_status = 403;
          s->response_status = reject_status;
          SocketHTTPServer_Request_body_string (&req_ctx, "Request Rejected");
          SocketHTTPServer_Request_finish (&req_ctx);
          return;
        }
    }

  s->response_status = 200;

  for (MiddlewareEntry *mw = server->middleware_chain; mw != NULL;
       mw = mw->next)
    {
      int result = mw->func (&req_ctx, mw->userdata);
      if (result != 0)
        {
          SERVER_METRICS_INC (
              server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL, requests_total);
          return;
        }
    }

  if (server->handler != NULL)
    server->handler (&req_ctx, server->handler_userdata);

  SERVER_METRICS_INC (
      server, SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL, requests_total);

  /* If the handler didn't opt into streaming, send response now. */
  if (!s->response_streaming)
    server_http2_send_nonstreaming_response (conn, s);
  else
    server_http2_flush_stream_output (conn, s);
}

void
server_http2_stream_cb (SocketHTTP2_Conn_T http2_conn,
                        SocketHTTP2_Stream_T stream,
                        int event,
                        void *userdata)
{
  HTTP2ServerCallbackCtx *ctx = (HTTP2ServerCallbackCtx *)userdata;
  SocketHTTPServer_T server;
  ServerConnection *conn;
  ServerHTTP2Stream *s;

  (void)http2_conn;

  if (ctx == NULL)
    return;
  server = ctx->server;
  conn = ctx->conn;
  if (server == NULL || conn == NULL)
    return;

  s = server_http2_stream_get_or_create (server, conn, stream);
  if (s == NULL)
    return;

  if (event == HTTP2_EVENT_HEADERS_RECEIVED)
    {
      SocketHPACK_Header hdrs[SOCKETHTTP2_MAX_DECODED_HEADERS];
      size_t hdr_count = 0;
      int end_stream = 0;

      if (SocketHTTP2_Stream_recv_headers (stream,
                                           hdrs,
                                           SOCKETHTTP2_MAX_DECODED_HEADERS,
                                           &hdr_count,
                                           &end_stream)
          == 1)
        {
          if (server_http2_build_request (
                  server, s, hdrs, hdr_count, end_stream)
              < 0)
            return;
        }
    }
  else if (event == HTTP2_EVENT_TRAILERS_RECEIVED)
    {
      SocketHPACK_Header trailers[SOCKETHTTP2_MAX_DECODED_HEADERS];
      size_t trailer_count = 0;

      if (SocketHTTP2_Stream_recv_trailers (
              stream, trailers, SOCKETHTTP2_MAX_DECODED_HEADERS, &trailer_count)
          == 1)
        {
          if (s->request_trailers == NULL)
            {
              s->request_trailers = SocketHTTP_Headers_new (s->arena);
              if (s->request_trailers == NULL)
                {
                  SocketHTTP2_Stream_close (stream, HTTP2_INTERNAL_ERROR);
                  return;
                }
            }

          for (size_t i = 0; i < trailer_count; i++)
            {
              const SocketHPACK_Header *hdr = &trailers[i];
              if (hdr->name == NULL || hdr->value == NULL)
                continue;
              /* RFC 9113: trailers must not include pseudo-headers. */
              if (hdr->name_len > 0 && hdr->name[0] == ':')
                continue;
              SocketHTTP_Headers_add_n (s->request_trailers,
                                        hdr->name,
                                        hdr->name_len,
                                        hdr->value,
                                        hdr->value_len);
            }
        }
    }
  else if (event == HTTP2_EVENT_DATA_RECEIVED)
    {
      int end_stream = 0;
      char buf[HTTPSERVER_RECV_BUFFER_SIZE];

      for (;;)
        {
          ssize_t n = SocketHTTP2_Stream_recv_data (
              stream, buf, sizeof (buf), &end_stream);
          if (n <= 0)
            break;

          s->body_received += (size_t)n;

          if (s->body_streaming && s->body_callback)
            {
              struct SocketHTTPServer_Request req_ctx;
              req_ctx.server = server;
              req_ctx.conn = conn;
              req_ctx.h2_stream = s;
              req_ctx.arena = s->arena;
              req_ctx.start_time_ms = Socket_get_monotonic_ms ();

              if (s->body_callback (&req_ctx,
                                    buf,
                                    (size_t)n,
                                    end_stream,
                                    s->body_callback_userdata)
                  != 0)
                {
                  SocketHTTP2_Stream_close (stream, HTTP2_CANCEL);
                  return;
                }
            }
          else
            {
              size_t max_body = server->config.max_body_size;

              if (max_body > 0 && s->body_len + (size_t)n > max_body)
                {
                  SocketHTTP2_Stream_close (stream, HTTP2_CANCEL);
                  return;
                }

              if (!s->body_uses_buf && s->body != NULL)
                {
                  size_t space = s->body_capacity - s->body_len;
                  size_t to_copy = (size_t)n;
                  if (to_copy > space)
                    to_copy = space;
                  memcpy ((char *)s->body + s->body_len, buf, to_copy);
                  s->body_len += to_copy;
                }
              else
                {
                  if (!s->body_uses_buf)
                    {
                      size_t initial_size
                          = HTTPSERVER_CHUNKED_BODY_INITIAL_SIZE;
                      if (max_body > 0 && initial_size > max_body)
                        initial_size = max_body;
                      s->body_buf = SocketBuf_new (s->arena, initial_size);
                      if (s->body_buf == NULL)
                        {
                          SocketHTTP2_Stream_close (stream,
                                                    HTTP2_INTERNAL_ERROR);
                          return;
                        }
                      s->body_uses_buf = 1;
                    }

                  if (!SocketBuf_ensure (s->body_buf, (size_t)n))
                    {
                      SocketHTTP2_Stream_close (stream, HTTP2_INTERNAL_ERROR);
                      return;
                    }
                  SocketBuf_write (s->body_buf, buf, (size_t)n);
                  s->body_len = SocketBuf_available (s->body_buf);
                }
            }

          if (end_stream)
            break;
        }

      if (end_stream)
        s->request_complete = 1;
    }
  else if (event == HTTP2_EVENT_STREAM_END)
    {
      s->request_complete = 1;
    }
  else if (event == HTTP2_EVENT_STREAM_RESET)
    {
      s->request_complete = 1;
    }

  if (event == HTTP2_EVENT_WINDOW_UPDATE)
    {
      server_http2_flush_stream_output (conn, s);
      server_http2_try_dispose_stream (conn, s);
      return;
    }

  if (event == HTTP2_EVENT_STREAM_RESET)
    {
      /* Peer reset: free stream state immediately. */
      /* Unlink + dispose without waiting for pending output. */
      ServerHTTP2Stream **pp = &conn->http2_streams;
      while (*pp != NULL && *pp != s)
        pp = &(*pp)->next;
      if (*pp == s)
        *pp = s->next;
      SocketHTTP2_Stream_set_userdata (s->stream, NULL);
      if (s->arena != NULL)
        Arena_dispose (&s->arena);
      return;
    }

  if (s->request != NULL && s->request_complete)
    server_http2_handle_request (ctx, s);

  if (event == HTTP2_EVENT_STREAM_END)
    {
      server_http2_try_dispose_stream (conn, s);
    }
}

int
server_http2_enable (SocketHTTPServer_T server, ServerConnection *conn)
{
  SocketHTTP2_Config cfg;
  HTTP2ServerCallbackCtx *ctx;

  assert (server != NULL);
  assert (conn != NULL);

  if (conn->http2_conn == NULL)
    {
      SocketHTTP2_config_defaults (&cfg, HTTP2_ROLE_SERVER);

      /* Apply server limits */
      if (server->config.max_concurrent_requests > 0)
        cfg.max_concurrent_streams
            = (uint32_t)server->config.max_concurrent_requests;

      conn->http2_conn = SocketHTTP2_Conn_new (conn->socket, &cfg, conn->arena);
      if (conn->http2_conn == NULL)
        return -1;
    }

  if (conn->http2_callback_set)
    return 0;

  ctx = Arena_alloc (conn->arena, sizeof (*ctx), __FILE__, __LINE__);
  if (ctx == NULL)
    return -1;
  ctx->server = server;
  ctx->conn = conn;

  SocketHTTP2_Conn_set_stream_callback (
      conn->http2_conn, server_http2_stream_cb, ctx);
  conn->http2_callback_set = 1;

  return 0;
}

/**
 * server_process_http2 - Process HTTP/2 connection events
 * @server: HTTP server
 * @conn: HTTP/2 connection
 * @events: Poll events (POLL_READ, POLL_WRITE, etc.)
 *
 * Returns: 0 on success, -1 on error (connection should be closed)
 */
int
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

/**
 * server_try_http2_prior_knowledge - Detect HTTP/2 prior knowledge upgrade
 * @server: HTTP server
 * @conn: Connection to check
 * @events: Poll events
 *
 * Peeks at the socket buffer to detect HTTP/2 client connection preface
 * (prior knowledge upgrade per RFC 9113 §3.4). If detected, enables HTTP/2
 * on the connection.
 *
 * Returns: 1 if HTTP/2 detected and enabled, 0 otherwise
 */
int
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

/**
 * validate_rfc8441_websocket_upgrade - Validate RFC 8441 Extended CONNECT
 * @s: HTTP/2 stream to validate
 *
 * Checks that the request is a valid WebSocket upgrade per RFC 8441:
 * - Method must be CONNECT
 * - :protocol pseudo-header must be "websocket"
 * - Sec-WebSocket-Version must be "13" if present
 *
 * Returns: 1 if valid WebSocket upgrade, 0 otherwise
 */
int
validate_rfc8441_websocket_upgrade (ServerHTTP2Stream *s)
{
  const char *version;

  /* RFC 8441 Extended CONNECT: :method=CONNECT, :protocol=websocket */
  if (s->request->method != HTTP_METHOD_CONNECT)
    return 0;
  if (s->h2_protocol == NULL || strcmp (s->h2_protocol, "websocket") != 0)
    return 0;

  /* Validate WebSocket version if specified */
  version
      = SocketHTTP_Headers_get (s->request->headers, "Sec-WebSocket-Version");
  if (version != NULL && strcmp (version, "13") != 0)
    return 0;

  return 1;
}

/**
 * prepare_h2_websocket_response - Prepare HTTP/2 200 response for WebSocket
 * @req: Request context (provides arena for allocation)
 * @s: HTTP/2 stream
 * @response: Response structure to populate
 *
 * Allocates response headers if needed and populates the response structure.
 *
 * Returns: 0 on success, -1 on failure (headers already sent or alloc failed)
 */
int
prepare_h2_websocket_response (SocketHTTPServer_Request_T req,
                               ServerHTTP2Stream *s,
                               SocketHTTP_Response *response)
{
  if (s->response_headers_sent)
    return -1;

  if (s->response_headers == NULL)
    s->response_headers = SocketHTTP_Headers_new (req->arena);
  if (s->response_headers == NULL)
    return -1;

  s->response_status = 200;

  memset (response, 0, sizeof (*response));
  response->version = HTTP_VERSION_2;
  response->status_code = 200;
  response->headers = s->response_headers;

  return 0;
}

/**
 * setup_ws_over_h2_streaming - Configure stream for WebSocket-over-HTTP/2
 * @s: HTTP/2 stream to configure
 * @callback: Callback for incoming WebSocket frame data
 * @userdata: User context passed to callback
 *
 * Sets streaming flags and registers the callback for DATA frame delivery.
 */
void
setup_ws_over_h2_streaming (ServerHTTP2Stream *s,
                            SocketHTTPServer_BodyCallback callback,
                            void *userdata)
{
  s->response_streaming = 1;
  s->response_headers_sent = 1;
  s->body_streaming = 1;
  s->body_callback = callback;
  s->body_callback_userdata = userdata;
  s->ws_over_h2 = 1;
}

/*
 * HTTP/2 streaming helpers - extracted from SocketHTTPServer.c
 * These provide protocol-specific implementations for the public streaming API.
 */

int
server_h2_begin_stream (ServerConnection *conn, ServerHTTP2Stream *s)
{
  SocketHTTP_Response response;

  (void)conn;

  if (s->response_headers_sent)
    return -1;

  if (s->response_headers == NULL)
    s->response_headers = SocketHTTP_Headers_new (s->arena);

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

int
server_h2_send_chunk (ServerConnection *conn,
                      ServerHTTP2Stream *s,
                      const void *data,
                      size_t len)
{
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

  server_http2_flush_stream_output (conn, s);
  return 0;
}

int
server_h2_end_stream (ServerConnection *conn, ServerHTTP2Stream *s)
{
  if (!s->response_streaming)
    return -1;

  s->response_finished = 1;

  server_http2_flush_stream_output (conn, s);

  if (!s->response_end_stream_sent
      && (s->response_outbuf == NULL
          || SocketBuf_available (s->response_outbuf) == 0))
    {
      server_http2_flush_stream_output (conn, s);
    }

  return 0;
}

/*
 * HTTP/2 server push helpers - extracted from SocketHTTPServer.c
 */

int
server_h2_validate_push (SocketHTTPServer_Request_T req, const char *path)
{
  if (req->h2_stream == NULL || req->h2_stream->request == NULL
      || req->conn->http2_conn == NULL)
    return -1;

  if (SocketHTTP2_Conn_get_setting (req->conn->http2_conn,
                                    HTTP2_SETTINGS_ENABLE_PUSH)
      == 0)
    return -1;

  if (path[0] != '/')
    return -1;

  return 0;
}

SocketHPACK_Header *
server_h2_build_push_headers (Arena_T arena,
                              const SocketHTTP_Request *parent,
                              const char *path,
                              SocketHTTP_Headers_T extra_headers,
                              size_t *out_count)
{
  const char *scheme = parent->scheme ? parent->scheme : "https";
  const char *authority = parent->authority ? parent->authority : "";
  size_t extra = extra_headers ? SocketHTTP_Headers_count (extra_headers) : 0;
  size_t total = HTTP2_REQUEST_PSEUDO_HEADER_COUNT + extra;
  SocketHPACK_Header *hpack;
  size_t out_idx;

  hpack = Arena_alloc (arena, total * sizeof (*hpack), __FILE__, __LINE__);
  if (hpack == NULL)
    return NULL;

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

  /* Additional headers (filter out pseudo-headers from user input) */
  out_idx = HTTP2_REQUEST_PSEUDO_HEADER_COUNT;
  if (extra_headers != NULL)
    {
      for (size_t i = 0; i < extra; i++)
        {
          const SocketHTTP_Header *hdr
              = SocketHTTP_Headers_at (extra_headers, i);
          if (hdr == NULL || hdr->name == NULL || hdr->value == NULL)
            continue;
          if (hdr->name[0] == ':')
            continue;

          hpack[out_idx].name = hdr->name;
          hpack[out_idx].name_len = strlen (hdr->name);
          hpack[out_idx].value = hdr->value;
          hpack[out_idx].value_len = strlen (hdr->value);
          out_idx++;
        }
    }

  *out_count = out_idx;
  return hpack;
}

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketHTTPServer.c - HTTP/1.1 and HTTP/2 server with TLS, rate limiting, and
 * connection pooling */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/SocketRateLimit.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTP2.h"
#include "http/SocketHTTPServer-private.h"
#include "http/SocketHTTPServer.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketWS.h"

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

/**
 * header_contains_crlf - Check if string contains CRLF characters
 * @str: String to check
 *
 * Returns: 1 if CRLF found, 0 otherwise
 */
static int
header_contains_crlf (const char *str)
{
  for (const char *p = str; *p; p++)
    {
      if (*p == '\r' || *p == '\n')
        return 1;
    }
  return 0;
}

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
      size_t len = e->prefix_len;
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

static inline const char *
parse_query_from_path (const char *path)
{
  if (path == NULL)
    return NULL;
  const char *q = strchr (path, '?');
  return q ? q + 1 : NULL;
}

const char *
SocketHTTPServer_Request_query (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  if (req->h2_stream != NULL && req->h2_stream->request != NULL)
    return parse_query_from_path (req->h2_stream->request->path);
  if (req->conn->request == NULL)
    return NULL;
  return parse_query_from_path (req->conn->request->path);
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

  assert (req != NULL);
  assert (name != NULL);
  assert (value != NULL);

  /* Reject headers with CRLF characters (injection prevention) */
  if (header_contains_crlf (name) || header_contains_crlf (value))
    {
      SOCKET_LOG_WARN_MSG ("Rejected response header with CRLF characters");
      return;
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
  return req->h2_stream ? server_h2_begin_stream (req->conn, req->h2_stream)
                        : server_http1_begin_stream (req->server, req->conn);
}

int
SocketHTTPServer_Request_send_chunk (SocketHTTPServer_Request_T req,
                                     const void *data,
                                     size_t len)
{
  assert (req != NULL);
  return req->h2_stream
             ? server_h2_send_chunk (req->conn, req->h2_stream, data, len)
             : server_http1_send_chunk (req->server, req->conn, data, len);
}

int
SocketHTTPServer_Request_end_stream (SocketHTTPServer_Request_T req)
{
  assert (req != NULL);
  return req->h2_stream ? server_h2_end_stream (req->conn, req->h2_stream)
                        : server_http1_end_stream (req->server, req->conn);
}


int
SocketHTTPServer_Request_push (SocketHTTPServer_Request_T req,
                               const char *path,
                               SocketHTTP_Headers_T headers)
{
  SocketHPACK_Header *hpack;
  size_t hcount;
  SocketHTTP2_Stream_T promised;
  ServerHTTP2Stream *ps;
  HTTP2ServerCallbackCtx cb;

  assert (req != NULL);
  assert (path != NULL);

  if (server_h2_validate_push (req, path) < 0)
    return -1;

  hpack = server_h2_build_push_headers (
      req->arena, req->h2_stream->request, path, headers, &hcount);
  if (hpack == NULL)
    return -1;

  promised
      = SocketHTTP2_Stream_push_promise (req->h2_stream->stream, hpack, hcount);
  if (promised == NULL)
    return -1;

  ps = server_http2_stream_get_or_create (req->server, req->conn, promised);
  if (ps == NULL)
    return -1;

  if (server_http2_build_request (req->server, ps, hpack, hcount, 1) < 0)
    return -1;

  ps->request_complete = 1;

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

static int
complete_websocket_handshake (SocketWS_T ws)
{
  int hs_result;

  do
    {
      hs_result = SocketWS_handshake (ws);
      if (hs_result > 0)
        SocketWS_process (ws, POLL_WRITE);
    }
  while (hs_result > 0);

  if (hs_result < 0)
    {
      SocketWS_free (&ws);
      return -1;
    }

  SocketWS_process (ws, POLL_WRITE);
  return 0;
}

SocketWS_T
SocketHTTPServer_Request_upgrade_websocket (
    SocketHTTPServer_Request_T req,
    SocketHTTPServer_BodyCallback callback,
    void *userdata)
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
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);

    if (complete_websocket_handshake (ws) < 0)
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);

    connection_transition_to_websocket (
        req->server, req->conn, ws, callback, userdata);
    return ws;
  }
  EXCEPT (SocketWS_Failed)
  {
    if (ws != NULL)
      SocketWS_free (&ws);
    RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
  }
  END_TRY;

  return NULL;
}

SocketHTTP2_Stream_T
SocketHTTPServer_Request_accept_websocket_h2 (
    SocketHTTPServer_Request_T req,
    SocketHTTPServer_BodyCallback callback,
    void *userdata)
{
  ServerHTTP2Stream *s;
  SocketHTTP_Response response;

  assert (req != NULL);

  if (req->h2_stream == NULL || req->h2_stream->request == NULL)
    return NULL;

  if (callback == NULL)
    return NULL;

  s = req->h2_stream;

  if (!validate_rfc8441_websocket_upgrade (s))
    return NULL;

  if (prepare_h2_websocket_response (req, s, &response) < 0)
    return NULL;

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

  setup_ws_over_h2_streaming (s, callback, userdata);

  return s->stream;
}

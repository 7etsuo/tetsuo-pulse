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
    ws = SocketWS_server_accept (req->conn->socket, req->conn->request,
                                 ws_config);
    if (ws == NULL)
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);

    if (complete_websocket_handshake (ws) < 0)
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);

    connection_transition_to_websocket (req->server, req->conn, ws, callback,
                                        userdata);
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

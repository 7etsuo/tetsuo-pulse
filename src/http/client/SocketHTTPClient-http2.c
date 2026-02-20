/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTPClient-http2.c
 * @brief HTTP/2 request/response handling for HTTP client
 *
 * Implements HTTP/2 protocol:
 * - Request building with pseudo-headers
 * - Stream management
 * - HPACK header parsing
 * - Body reception with flow control
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "http/SocketHTTP2.h"
#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTPClient-private.h"
#include "socket/Socket.h"
#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#endif

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTP2);

/* HTTP/2 pseudo-header constants */
#define PSEUDO_HEADER_STATUS ":status"
#define PSEUDO_HEADER_STATUS_LEN 7

#if SOCKET_HAS_TLS
#define H2_TLS_EXCEPTS(fail_stmt)    \
  EXCEPT (SocketTLS_HandshakeFailed) \
  {                                  \
    fail_stmt;                       \
  }                                  \
  EXCEPT (SocketTLS_VerifyFailed)    \
  {                                  \
    fail_stmt;                       \
  }                                  \
  EXCEPT (SocketTLS_Failed)          \
  {                                  \
    fail_stmt;                       \
  }
#else
#define H2_TLS_EXCEPTS(fail_stmt)
#endif

#define H2_SAFE_CALL(type, init, call) \
  volatile type rc = (init);           \
  TRY                                  \
  {                                    \
    rc = (type)(call);                 \
  }                                    \
  EXCEPT (SocketHTTP2)                 \
  {                                    \
    rc = (init);                       \
  }                                    \
  EXCEPT (Socket_Failed)               \
  {                                    \
    rc = (init);                       \
  }                                    \
  EXCEPT (Socket_Closed)               \
  {                                    \
    rc = (init);                       \
  }                                    \
  H2_TLS_EXCEPTS (rc = (init))         \
  ELSE                                 \
  {                                    \
    rc = (init);                       \
  }                                    \
  END_TRY;                             \
  return rc

static int
httpclient_h2_conn_flush_safe (SocketHTTP2_Conn_T conn)
{
  H2_SAFE_CALL (int, -1, SocketHTTP2_Conn_flush (conn));
}

static int
httpclient_h2_conn_process_safe (SocketHTTP2_Conn_T conn, unsigned events)
{
  H2_SAFE_CALL (int, -1, SocketHTTP2_Conn_process (conn, events));
}

static int
httpclient_h2_stream_send_request_safe (SocketHTTP2_Stream_T stream,
                                        const SocketHTTP_Request *http_req,
                                        int end_stream)
{
  H2_SAFE_CALL (
      int, -1, SocketHTTP2_Stream_send_request (stream, http_req, end_stream));
}

static ssize_t
httpclient_h2_stream_send_data_safe (SocketHTTP2_Stream_T stream,
                                     const void *buf,
                                     size_t len,
                                     int end_stream)
{
  H2_SAFE_CALL (
      ssize_t, -1, SocketHTTP2_Stream_send_data (stream, buf, len, end_stream));
}

static int
httpclient_h2_stream_recv_headers_safe (SocketHTTP2_Stream_T stream,
                                        SocketHPACK_Header *headers,
                                        size_t headers_cap,
                                        size_t *header_count,
                                        int *end_stream)
{
  H2_SAFE_CALL (int,
                -1,
                SocketHTTP2_Stream_recv_headers (
                    stream, headers, headers_cap, header_count, end_stream));
}

static ssize_t
httpclient_h2_stream_recv_data_safe (SocketHTTP2_Stream_T stream,
                                     void *buf,
                                     size_t len,
                                     int *end_stream)
{
  H2_SAFE_CALL (
      ssize_t, -1, SocketHTTP2_Stream_recv_data (stream, buf, len, end_stream));
}

/* stream_close and stream_new have unique patterns — left unwrapped. */

static void
httpclient_h2_stream_close_safe (SocketHTTP2_Stream_T stream, int error_code)
{
  if (stream == NULL)
    return;

  TRY
  {
    SocketHTTP2_Stream_close (stream, error_code);
  }
  EXCEPT (SocketHTTP2)
  {
  }
  EXCEPT (Socket_Failed)
  {
  }
  EXCEPT (Socket_Closed)
  {
  }
#if SOCKET_HAS_TLS
  EXCEPT (SocketTLS_HandshakeFailed)
  {
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
  }
  EXCEPT (SocketTLS_Failed)
  {
  }
#endif
  ELSE
  {
  }
  END_TRY;
}

static SocketHTTP2_Stream_T
httpclient_h2_stream_new_safe (SocketHTTP2_Conn_T conn)
{
  volatile SocketHTTP2_Stream_T stream = NULL;

  TRY
  {
    stream = SocketHTTP2_Stream_new (conn);
  }
  ELSE
  {
    stream = NULL;
  }
  END_TRY;

  return (SocketHTTP2_Stream_T)stream;
}

void
httpclient_http2_build_request (const SocketHTTPClient_Request_T req,
                                SocketHTTP_Request *http_req)
{
  http_req->method = req->method;
  http_req->version = HTTP_VERSION_2;
  http_req->scheme = req->uri.scheme;
  http_req->authority = req->uri.host; /* authority is just host for client */
  /* :path is path + query in HTTP/2; if no path, use "/" */
  http_req->path
      = (req->uri.path && req->uri.path_len > 0) ? req->uri.path : "/";
  http_req->headers = req->headers;
  http_req->has_body = (req->body != NULL && req->body_len > 0);
  http_req->content_length
      = http_req->has_body ? (int64_t)req->body_len : (int64_t)-1;
}

int
httpclient_http2_parse_response_headers (const SocketHPACK_Header *headers,
                                         size_t header_count,
                                         SocketHTTPClient_Response *response,
                                         Arena_T arena)
{
  size_t i;
  int status_found = 0;

  /* Find :status pseudo-header first */
  for (i = 0; i < header_count; i++)
    {
      /* Skip non-status headers */
      if (headers[i].name_len != PSEUDO_HEADER_STATUS_LEN)
        continue;

      if (memcmp (
              headers[i].name, PSEUDO_HEADER_STATUS, PSEUDO_HEADER_STATUS_LEN)
          != 0)
        continue;

      /* Found :status - parse and validate (RFC 9113 §8.3.2) */
      if (http2_parse_status_code (
              headers[i].value, headers[i].value_len, &response->status_code)
          < 0)
        return -1;

      status_found = 1;
      break;
    }

  if (!status_found)
    return -1;

  /* Copy regular headers (skip pseudo-headers) */
  if (response->headers == NULL)
    {
      response->headers = SocketHTTP_Headers_new (arena);
      if (response->headers == NULL)
        return -1;
    }

  for (i = 0; i < header_count; i++)
    {
      if (headers[i].name[0] == ':')
        continue; /* Skip pseudo-headers */

      if (SocketHTTP_Headers_add_n (response->headers,
                                    headers[i].name,
                                    headers[i].name_len,
                                    headers[i].value,
                                    headers[i].value_len)
          != 0)
        return -1;
    }

  return 0;
}

int
httpclient_http2_send_request (SocketHTTP2_Stream_T stream,
                               SocketHTTP2_Conn_T h2conn,
                               const SocketHTTP_Request *http_req,
                               const void *body,
                               size_t body_len)
{
  int has_body = (body != NULL && body_len > 0);

  if (httpclient_h2_stream_send_request_safe (stream, http_req, !has_body) != 0)
    return -1;

  if (has_body)
    {
      ssize_t sent
          = httpclient_h2_stream_send_data_safe (stream, body, body_len, 1);
      if (sent < 0)
        return -1;
    }

  return httpclient_h2_conn_flush_safe (h2conn);
}

int
httpclient_http2_recv_headers (SocketHTTP2_Stream_T stream,
                               SocketHTTP2_Conn_T h2conn,
                               SocketHTTPClient_Response *response,
                               int *end_stream)
{
  /*
   * Stack allocation: ~5KB (128 headers * ~40 bytes per SocketHPACK_Header).
   * This is acceptable for modern systems (Linux default: 8MB stack).
   * Chosen over heap allocation for performance (no malloc overhead).
   * If stack pressure becomes an issue, consider arena allocation.
   */
  SocketHPACK_Header headers[SOCKETHTTP2_MAX_DECODED_HEADERS];
  size_t header_count = 0;
  Arena_T arena;

  *end_stream = 0;

  while (header_count == 0)
    {
      int r = httpclient_h2_stream_recv_headers_safe (
          stream,
          headers,
          SOCKETHTTP2_MAX_DECODED_HEADERS,
          &header_count,
          end_stream);
      if (r < 0)
        return -1;

      if (r == 0 && httpclient_h2_conn_process_safe (h2conn, 0) < 0)
        return -1;
    }

  arena = SocketHTTP2_Conn_arena (h2conn);
  return httpclient_http2_parse_response_headers (
      headers, header_count, response, arena);
}

int
httpclient_http2_recv_body (SocketHTTP2_Stream_T stream,
                            SocketHTTP2_Conn_T h2conn,
                            Arena_T arena,
                            size_t max_response_size,
                            unsigned char **body_out,
                            size_t *body_len_out,
                            int discard_body)
{
  size_t body_cap;
  unsigned char *body_buf;
  unsigned char discard_buf[HTTPCLIENT_BODY_CHUNK_SIZE];
  size_t total_body = 0;
  int end_stream = 0;

  /* Benchmark mode: use stack buffer and discard data */
  if (discard_body)
    {
      body_buf = discard_buf;
      body_cap = sizeof (discard_buf);
    }
  else
    {
      body_cap = (max_response_size > 0) ? max_response_size
                                         : HTTPCLIENT_H2_BODY_INITIAL_CAPACITY;
      body_buf = Arena_alloc (arena, body_cap, __FILE__, __LINE__);
    }

  while (!end_stream)
    {
      size_t recv_offset = discard_body ? 0 : total_body;
      size_t recv_cap = discard_body ? body_cap : (body_cap - total_body);
      ssize_t recv_len = httpclient_h2_stream_recv_data_safe (
          stream, body_buf + recv_offset, recv_cap, &end_stream);

      if (recv_len < 0)
        return -1;

      if (recv_len == 0 && !end_stream)
        {
          if (httpclient_h2_conn_process_safe (h2conn, 0) < 0)
            return -1;
          continue;
        }

      total_body += (size_t)recv_len;

      if (max_response_size > 0 && total_body > max_response_size)
        {
          httpclient_h2_stream_close_safe (stream, HTTP2_CANCEL);
          return -2;
        }

      /* Grow if full and unlimited size (only when not discarding) */
      if (!discard_body && total_body >= body_cap && max_response_size == 0)
        {
          size_t needed = total_body + HTTPCLIENT_BODY_CHUNK_SIZE;
          if (httpclient_grow_body_buffer (arena,
                                           (char **)&body_buf,
                                           &body_cap,
                                           &total_body,
                                           needed,
                                           max_response_size)
              != 0)
            {
              httpclient_h2_stream_close_safe (stream, HTTP2_CANCEL);
              return -1;
            }
        }
    }

  *body_out = discard_body ? NULL : body_buf;
  *body_len_out = total_body;
  return 0;
}

int
httpclient_http2_execute (HTTPPoolEntry *conn,
                          const SocketHTTPClient_Request_T req,
                          SocketHTTPClient_Response *response,
                          size_t max_response_size,
                          int discard_body)
{
  SocketHTTP2_Conn_T h2conn = conn->proto.h2.conn;
  SocketHTTP2_Stream_T stream;
  SocketHTTP_Request http_req;
  int end_stream;
  int result;

  assert (conn != NULL);
  assert (h2conn != NULL);
  assert (req != NULL);
  assert (response != NULL);

  if (SocketHTTP2_Conn_is_closed (h2conn))
    return -1;

  stream = httpclient_h2_stream_new_safe (h2conn);
  if (stream == NULL)
    return -1;

  conn->proto.h2.active_streams++;
  httpclient_http2_build_request (req, &http_req);

  /* Send request */
  if (httpclient_http2_send_request (
          stream, h2conn, &http_req, req->body, req->body_len)
      < 0)
    {
      conn->proto.h2.active_streams--;
      httpclient_h2_stream_close_safe (stream, HTTP2_CANCEL);
      return -1;
    }

  /* Receive headers */
  if (httpclient_http2_recv_headers (stream, h2conn, response, &end_stream) < 0)
    {
      conn->proto.h2.active_streams--;
      return -1;
    }

  /* No body if END_STREAM set on headers */
  if (end_stream)
    {
      response->body = NULL;
      response->body_len = 0;
      conn->proto.h2.active_streams--;
      return 0;
    }

  /* Receive body */
  result = httpclient_http2_recv_body (stream,
                                       h2conn,
                                       SocketHTTP2_Conn_arena (h2conn),
                                       max_response_size,
                                       (unsigned char **)&response->body,
                                       &response->body_len,
                                       discard_body);
  conn->proto.h2.active_streams--;
  return result;
}

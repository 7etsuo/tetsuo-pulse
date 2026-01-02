/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTPClient-http1.c
 * @brief HTTP/1.1 request/response handling for HTTP client
 *
 * Implements HTTP/1.1 protocol:
 * - Request building and serialization
 * - Header and body sending
 * - Response parsing and body reading
 * - Chunked transfer encoding support
 */

#include <assert.h>
#include <string.h>

#include "http/SocketHTTP1.h"
#include "http/SocketHTTPClient-private.h"

void
httpclient_http1_build_request (SocketHTTPClient_Request_T req,
                                SocketHTTP_Request *http_req)
{
  assert (req != NULL);
  assert (http_req != NULL);

  memset (http_req, 0, sizeof (*http_req));

  http_req->method = req->method;
  http_req->version = HTTP_VERSION_1_1;
  http_req->authority = req->uri.host;
  http_req->path = httpclient_get_path_or_root (&req->uri);
  http_req->scheme = req->uri.scheme;
  http_req->headers = req->headers;
  http_req->has_body = (req->body != NULL && req->body_len > 0);
  http_req->content_length = (int64_t)req->body_len;
}

int
httpclient_http1_send_headers (SocketHTTPClient_T client,
                               HTTPPoolEntry *conn,
                               const SocketHTTP_Request *http_req)
{
  char buf[HTTPCLIENT_REQUEST_BUFFER_SIZE];
  ssize_t n;
  volatile ssize_t sent = -1;

  assert (conn != NULL);
  assert (http_req != NULL);

  /* Serialize request */
  n = SocketHTTP1_serialize_request (http_req, buf, sizeof (buf));
  if (n < 0)
    {
      HTTPCLIENT_ERROR_MSG ("Failed to serialize request");
      return -1;
    }

  /* Send request headers */
  sent = httpclient_io_safe_send (
      client, conn, buf, (size_t)n, "send request headers");
  if (sent < 0 || (size_t)sent != (size_t)n)
    {
      HTTPCLIENT_ERROR_FMT (
          "Failed to send request headers (partial write: %zd/%zu)",
          sent,
          (size_t)n);
      return -1;
    }

  return 0;
}

int
httpclient_http1_send_body (SocketHTTPClient_T client,
                            HTTPPoolEntry *conn,
                            const void *body,
                            size_t body_len)
{
  volatile ssize_t sent = -1;

  assert (conn != NULL);

  if (body == NULL || body_len == 0)
    return 0;

  sent = httpclient_io_safe_send (
      client, conn, body, body_len, "send request body");
  if (sent < 0 || (size_t)sent != body_len)
    {
      HTTPCLIENT_ERROR_FMT (
          "Failed to send request body (partial write: %zd/%zu)",
          sent,
          body_len);
      return -1;
    }

  return 0;
}

static int
httpclient_http1_recv_chunk (SocketHTTPClient_T client,
                             HTTPPoolEntry *conn,
                             char *buf,
                             size_t buf_size,
                             ssize_t *bytes_read)
{
  ssize_t recv_n;
  if (httpclient_io_safe_recv (client, conn, buf, buf_size, &recv_n) < 0)
    return -1;

  *bytes_read = recv_n;
  return 0;
}

static int
httpclient_http1_read_body_data (HTTPPoolEntry *conn,
                                 const char *buf,
                                 size_t buf_len,
                                 size_t *consumed,
                                 HTTPBodyAccumulator *acc)
{
  char body_chunk[HTTPCLIENT_BODY_CHUNK_SIZE];
  size_t body_consumed, body_written;
  size_t remaining;
  SocketHTTP1_Result result;
  int acc_result;

  assert (conn != NULL);
  assert (buf != NULL);
  assert (consumed != NULL);
  assert (acc != NULL);

  remaining = buf_len - *consumed;

  while (remaining > 0)
    {
      result = SocketHTTP1_Parser_read_body (conn->proto.h1.parser,
                                             buf + *consumed,
                                             remaining,
                                             &body_consumed,
                                             body_chunk,
                                             sizeof (body_chunk),
                                             &body_written);

      /* HTTP1_INCOMPLETE means more data needed, keep going */
      if (result != HTTP1_OK && result != HTTP1_INCOMPLETE)
        break;

      if (body_written > 0)
        {
          acc_result = httpclient_body_accumulate_chunk (
              acc, body_chunk, body_written);
          if (acc_result < 0)
            return acc_result; /* -1 = memory error, -2 = size limit exceeded
                                */
        }

      *consumed += body_consumed;
      remaining -= body_consumed;
    }

  return 0;
}

static int
httpclient_http1_parse_chunk (HTTPPoolEntry *conn,
                              const char *buf,
                              size_t buf_len,
                              const SocketHTTP_Response **parsed_resp,
                              HTTPBodyAccumulator *acc)
{
  size_t consumed;
  SocketHTTP1_Result result;

  result = SocketHTTP1_Parser_execute (
      conn->proto.h1.parser, buf, buf_len, &consumed);

  if (result == HTTP1_ERROR || result >= HTTP1_ERROR_LINE_TOO_LONG)
    {
      HTTPCLIENT_ERROR_MSG ("HTTP parse error: %s",
                            SocketHTTP1_result_string (result));
      return -1;
    }

  /* Get response once headers are complete */
  if (*parsed_resp == NULL
      && SocketHTTP1_Parser_state (conn->proto.h1.parser) >= HTTP1_STATE_BODY)
    {
      *parsed_resp = SocketHTTP1_Parser_get_response (conn->proto.h1.parser);
    }

  /* Read body if present */
  if (*parsed_resp != NULL
      && SocketHTTP1_Parser_body_mode (conn->proto.h1.parser)
             != HTTP1_BODY_NONE)
    {
      int body_result = httpclient_http1_read_body_data (
          conn, buf, buf_len, &consumed, acc);
      if (body_result < 0)
        return body_result;
    }

  /* Check if complete */
  if (SocketHTTP1_Parser_state (conn->proto.h1.parser) == HTTP1_STATE_COMPLETE)
    return 1;

  return 0;
}

int
httpclient_http1_receive_response (SocketHTTPClient_T client,
                                   HTTPPoolEntry *conn,
                                   SocketHTTPClient_Response *response,
                                   size_t max_response_size,
                                   int discard_body)
{
  char buf[HTTPCLIENT_REQUEST_BUFFER_SIZE];
  ssize_t n;
  Arena_T resp_arena;
  const SocketHTTP_Response *parsed_resp = NULL;
  HTTPBodyAccumulator acc = { NULL, 0, 0, 0, 0, NULL };
  int parse_result;

  assert (conn != NULL);
  assert (response != NULL);

  /* Acquire arena for response from thread-local cache */
  resp_arena = httpclient_acquire_response_arena ();
  if (resp_arena == NULL)
    {
      HTTPCLIENT_ERROR_MSG ("Failed to acquire response arena");
      return -1;
    }

  acc.arena = resp_arena;
  acc.max_size = max_response_size;
  acc.discard_body = discard_body;

  /* Reset parser for response */
  SocketHTTP1_Parser_reset (conn->proto.h1.parser);

  /* Receive and parse response loop */
  while (1)
    {
      if (httpclient_http1_recv_chunk (client, conn, buf, sizeof (buf), &n) < 0)
        break;

      parse_result = httpclient_http1_parse_chunk (
          conn, buf, (size_t)n, &parsed_resp, &acc);
      if (parse_result < 0)
        {
          httpclient_release_response_arena (&resp_arena);
          return parse_result;
        }
      if (parse_result == 1)
        break;
    }

  if (parsed_resp == NULL)
    {
      HTTPCLIENT_ERROR_MSG ("No response received");
      httpclient_release_response_arena (&resp_arena);
      return -1;
    }

  httpclient_body_fill_response (response, parsed_resp, &acc, resp_arena);
  return 0;
}

int
httpclient_http1_execute (HTTPPoolEntry *conn,
                          const SocketHTTPClient_Request_T req,
                          SocketHTTPClient_Response *response,
                          size_t max_response_size,
                          int discard_body)
{
  SocketHTTP_Request http_req;
  SocketHTTPClient_T client = req->client;

  assert (conn != NULL);
  assert (req != NULL);
  assert (response != NULL);

  /* Build request structure */
  httpclient_http1_build_request (req, &http_req);

  /* Send headers */
  if (httpclient_http1_send_headers (client, conn, &http_req) < 0)
    return -1;

  /* Send body if present */
  if (httpclient_http1_send_body (client, conn, req->body, req->body_len) < 0)
    return -1;

  /* Receive and parse response */
  return httpclient_http1_receive_response (
      client, conn, response, max_response_size, discard_body);
}

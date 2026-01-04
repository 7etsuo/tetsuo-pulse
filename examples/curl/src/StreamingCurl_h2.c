/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file StreamingCurl_h2.c
 * @brief HTTP/2 response streaming for curl module.
 *
 * Implements streaming response body handling for HTTP/2:
 * - HEADERS frame parsing
 * - DATA frame streaming with flow control
 * - WINDOW_UPDATE for flow control
 * - Progress callbacks
 * - Response size limits
 */

#include "curl/StreamingCurl-private.h"
#include "curl/StreamingCurl.h"
#include "http/SocketHPACK.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP2.h"
#include "socket/Socket.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Default timeout if none specified (30 seconds) */
#define CURL_H2_DEFAULT_TIMEOUT_MS 30000

/* HTTP/2 constants not in private header */
#define MAX_HEADER_FIELD_SIZE 8192

/* String lengths for header parsing */
#define STATUS_PSEUDO_HEADER_LEN 7  /* ":status" */
#define CONTENT_LENGTH_HEADER_LEN 14 /* "content-length" */
#define MAX_STATUS_STRING_LEN 15

/* Header formatting constants */
#define HEADER_SEPARATOR_LEN 2       /* ": " */
#define HEADER_LINE_TERMINATOR_LEN 2 /* "\r\n" */

/**
 * @brief Parse status code from :status pseudo-header.
 */
static int
parse_status_code (const SocketHPACK_Header *h)
{
  char status_str[MAX_STATUS_STRING_LEN + 1];
  size_t len
      = h->value_len > MAX_STATUS_STRING_LEN ? MAX_STATUS_STRING_LEN : h->value_len;
  memcpy (status_str, h->value, len);
  status_str[len] = '\0';
  return atoi (status_str);
}

/**
 * @brief Check if header is the :status pseudo-header.
 */
static int
is_status_header (const SocketHPACK_Header *h)
{
  return h->name_len == STATUS_PSEUDO_HEADER_LEN
         && strncmp (h->name, ":status", STATUS_PSEUDO_HEADER_LEN) == 0;
}

/**
 * @brief Check if header is a pseudo-header (starts with ':').
 */
static int
is_pseudo_header (const SocketHPACK_Header *h)
{
  return h->name_len > 0 && h->name[0] == ':';
}

/**
 * @brief Check if header field sizes are valid.
 */
static int
is_valid_header_size (const SocketHPACK_Header *h)
{
  return h->name_len <= MAX_HEADER_FIELD_SIZE
         && h->value_len <= MAX_HEADER_FIELD_SIZE;
}

/**
 * @brief Copy a single header to the response headers collection.
 *
 * @return Content-length value if this is that header, -1 otherwise
 */
static int64_t
copy_header_to_response (Arena_T arena, SocketHTTP_Headers_T resp_headers,
                         const SocketHPACK_Header *h)
{
  char *name = ALLOC (arena, h->name_len + 1);
  if (!name)
    return -1;
  memcpy (name, h->name, h->name_len);
  name[h->name_len] = '\0';

  char *value = ALLOC (arena, h->value_len + 1);
  if (!value)
    return -1;
  memcpy (value, h->value, h->value_len);
  value[h->value_len] = '\0';

  SocketHTTP_Headers_set (resp_headers, name, value);

  if (h->name_len == CONTENT_LENGTH_HEADER_LEN
      && strncasecmp (h->name, "content-length", CONTENT_LENGTH_HEADER_LEN) == 0)
    return strtoll (value, NULL, 10);

  return -1;
}

/**
 * @brief Convert HPACK headers to response structure.
 */
static int
curl_h2_headers_to_response (CurlSession_T session,
                             const SocketHPACK_Header *headers, size_t count)
{
  if (!session || !headers)
    return -1;

  Arena_T arena = session->request_arena;
  SocketHTTP_Headers_T resp_headers = SocketHTTP_Headers_new (arena);
  if (!resp_headers)
    return -1;

  int status_code = 0;
  int64_t content_length = -1;

  for (size_t i = 0; i < count; i++)
    {
      const SocketHPACK_Header *h = &headers[i];

      if (is_status_header (h))
        {
          status_code = parse_status_code (h);
          continue;
        }

      if (is_pseudo_header (h) || !is_valid_header_size (h))
        continue;

      int64_t cl = copy_header_to_response (arena, resp_headers, h);
      if (cl >= 0)
        content_length = cl;
    }

  session->response.status_code = status_code;
  session->response.version = HTTP_VERSION_2;
  session->response.headers = resp_headers;
  session->response.content_length = content_length;

  return 0;
}

/**
 * @brief Format header line for callback: "Name: Value\r\n".
 */
static int
format_header_line (Arena_T arena, const SocketHPACK_Header *h,
                    char **out_line, size_t *out_len)
{
  size_t line_len
      = h->name_len + HEADER_SEPARATOR_LEN + h->value_len + HEADER_LINE_TERMINATOR_LEN;
  char *line = ALLOC (arena, line_len + 1);
  if (!line)
    return -1;

  int len = snprintf (line, line_len + 1, "%.*s: %.*s\r\n", (int)h->name_len,
                      h->name, (int)h->value_len, h->value);
  if (len < 0)
    return -1;

  *out_line = line;
  *out_len = (size_t)len;
  return 0;
}

/**
 * @brief Invoke header callback for HTTP/2 response.
 */
static int
curl_h2_invoke_header_callback (CurlSession_T session,
                                const SocketHPACK_Header *headers, size_t count)
{
  if (!session || !session->options.header_callback || !headers)
    return 0;

  for (size_t i = 0; i < count; i++)
    {
      const SocketHPACK_Header *h = &headers[i];

      if (is_pseudo_header (h))
        continue;

      char *line;
      size_t len;
      if (format_header_line (session->request_arena, h, &line, &len) != 0)
        continue;

      size_t written = session->options.header_callback (
          line, 1, len, session->options.header_userdata);

      if (written != len)
        return -1;
    }

  return 0;
}

/**
 * @brief Get effective timeout from session options.
 */
static int
get_timeout_ms (CurlSession_T session)
{
  int timeout_ms = session->options.request_timeout_ms;
  return timeout_ms > 0 ? timeout_ms : CURL_H2_DEFAULT_TIMEOUT_MS;
}

/**
 * @brief Wait for readable and process HTTP/2 frames.
 */
static CurlError
wait_and_process_frames (CurlConnection *conn, int timeout_ms)
{
  int wait_result = curl_wait_readable (conn, timeout_ms);
  if (wait_result < 0)
    return CURL_ERROR_CONNECT;
  if (wait_result == 0)
    return CURL_ERROR_TIMEOUT;

  if (SocketHTTP2_Conn_process (conn->h2_conn, 0) < 0)
    return CURL_ERROR_PROTOCOL;

  return CURL_OK;
}

/**
 * @brief Receive and parse HTTP/2 response headers.
 */
CurlError
curl_receive_h2_headers (CurlSession_T session)
{
  if (!session || !session->conn)
    return CURL_ERROR_CONNECT;

  CurlConnection *conn = session->conn;
  if (!conn->h2_conn || !conn->h2_stream)
    return CURL_ERROR_PROTOCOL;

  int timeout_ms = get_timeout_ms (session);
  session->state = CURL_STATE_READING_HEADERS;

  SocketHPACK_Header headers[CURL_H2_MAX_HEADERS];
  size_t header_count = 0;
  int end_stream = 0;

  while (1)
    {
      CurlError err = wait_and_process_frames (conn, timeout_ms);
      if (err != CURL_OK)
        return err;

      int result = SocketHTTP2_Stream_recv_headers (
          conn->h2_stream, headers, CURL_H2_MAX_HEADERS, &header_count, &end_stream);

      if (result > 0)
        break;
      if (result < 0)
        return CURL_ERROR_PROTOCOL;
    }

  if (curl_h2_headers_to_response (session, headers, header_count) != 0)
    return CURL_ERROR_PROTOCOL;

  if (session->options.header_callback
      && curl_h2_invoke_header_callback (session, headers, header_count) != 0)
    return CURL_ERROR_ABORTED;

  if (end_stream)
    {
      session->state = CURL_STATE_COMPLETE;
      session->download_received = 0;
    }

  return CURL_OK;
}

/**
 * @brief Deliver data to write callback, with optional decompression.
 *
 * @return 0 on success, -1 on callback error, -2 on decompression error
 */
static int
deliver_data (CurlSession_T session, CurlDecompressor *decomp,
              const char *data, size_t len,
              unsigned char *decomp_buf, size_t decomp_buf_size)
{
  if (!session->options.write_callback)
    return 0;

  if (decomp && !curl_decompressor_is_identity (decomp))
    {
      size_t decomp_written = 0;
      if (curl_decompressor_decompress (decomp, (const unsigned char *)data, len,
                                        decomp_buf, decomp_buf_size, &decomp_written)
          != 0)
        return -2;

      if (decomp_written > 0)
        {
          size_t cb_written = session->options.write_callback (
              decomp_buf, 1, decomp_written, session->options.write_userdata);
          if (cb_written != decomp_written)
            return -1;
        }
    }
  else
    {
      size_t cb_written = session->options.write_callback (
          (char *)data, 1, len, session->options.write_userdata);
      if (cb_written != len)
        return -1;
    }

  return 0;
}

/**
 * @brief Invoke progress callback.
 *
 * @return 0 to continue, non-zero if aborted
 */
static int
invoke_progress (CurlSession_T session)
{
  if (!session->options.progress_callback)
    return 0;

  return session->options.progress_callback (
      session->options.progress_userdata, session->download_total,
      session->download_received, session->upload_total, session->upload_sent);
}

/**
 * @brief Check if response has no body.
 */
static int
is_no_body_response (CurlSession_T session)
{
  int status = session->response.status_code;
  return status == CURL_HTTP_STATUS_NO_CONTENT
         || status == CURL_HTTP_STATUS_NOT_MODIFIED
         || session->request_method == HTTP_METHOD_HEAD;
}

/**
 * @brief Stream HTTP/2 response body through callback.
 */
CurlError
curl_receive_h2_body (CurlSession_T session)
{
  if (!session || !session->conn)
    return CURL_ERROR_CONNECT;

  CurlConnection *conn = session->conn;
  if (!conn->h2_conn || !conn->h2_stream)
    return CURL_ERROR_PROTOCOL;

  if (session->state == CURL_STATE_COMPLETE)
    return CURL_OK;

  if (is_no_body_response (session))
    {
      session->state = CURL_STATE_COMPLETE;
      session->download_received = 0;
      return CURL_OK;
    }

  int timeout_ms = get_timeout_ms (session);
  session->state = CURL_STATE_READING_BODY;
  session->download_total = session->response.content_length;

  char data_buf[CURL_H2_DATA_BUFFER_SIZE];
  unsigned char decomp_buf[CURL_H2_DECOMP_BUFFER_SIZE];
  int end_stream = 0;
  CurlError error = CURL_OK;

  CurlDecompressor *decomp = curl_session_create_decompressor (session);

  while (!end_stream)
    {
      error = wait_and_process_frames (conn, timeout_ms);
      if (error != CURL_OK)
        goto cleanup;

      ssize_t nread = SocketHTTP2_Stream_recv_data (conn->h2_stream, data_buf,
                                                    sizeof (data_buf), &end_stream);
      if (nread < 0)
        {
          error = CURL_ERROR_PROTOCOL;
          goto cleanup;
        }

      if (nread > 0)
        {
          SocketHTTP2_Stream_window_update (conn->h2_stream, (uint32_t)nread);
          SocketHTTP2_Conn_window_update (conn->h2_conn, (uint32_t)nread);

          int rc = deliver_data (session, decomp, data_buf, (size_t)nread,
                                 decomp_buf, sizeof (decomp_buf));
          if (rc == -1)
            {
              error = CURL_ERROR_WRITE_CALLBACK;
              goto cleanup;
            }
          if (rc == -2)
            {
              error = CURL_ERROR_PROTOCOL;
              goto cleanup;
            }

          session->download_received += nread;

          if (invoke_progress (session) != 0)
            {
              error = CURL_ERROR_ABORTED;
              goto cleanup;
            }
        }

      SocketHTTP2_Conn_flush (conn->h2_conn);
    }

  /* Finish decompression */
  if (decomp && !curl_decompressor_is_identity (decomp)
      && session->options.write_callback)
    {
      size_t decomp_written = 0;
      if (curl_decompressor_finish (decomp, decomp_buf, sizeof (decomp_buf),
                                    &decomp_written)
              == 0
          && decomp_written > 0)
        {
          session->options.write_callback (decomp_buf, 1, decomp_written,
                                           session->options.write_userdata);
        }
    }

  session->state = CURL_STATE_COMPLETE;

cleanup:
  curl_decompressor_free (&decomp);
  return error;
}

/**
 * @brief Receive complete HTTP/2 response (headers + body).
 */
CurlError
curl_receive_h2_response (CurlSession_T session)
{
  if (!session)
    return CURL_ERROR_CONNECT;

  CurlError err = curl_receive_h2_headers (session);
  if (err != CURL_OK)
    return err;

  return curl_receive_h2_body (session);
}

/**
 * @brief Get HTTP/2 stream state.
 */
int
curl_h2_stream_state (CurlSession_T session)
{
  if (!session || !session->conn || !session->conn->h2_stream)
    return -1;

  return (int)SocketHTTP2_Stream_state (session->conn->h2_stream);
}

/**
 * @brief Close HTTP/2 stream.
 */
void
curl_h2_stream_close (CurlSession_T session, int error_code)
{
  if (!session || !session->conn || !session->conn->h2_stream)
    return;

  SocketHTTP2_Stream_close (session->conn->h2_stream,
                            (SocketHTTP2_ErrorCode)error_code);
}

/**
 * @brief Get current send window for HTTP/2 stream.
 */
int32_t
curl_h2_send_window (CurlSession_T session)
{
  if (!session || !session->conn || !session->conn->h2_stream)
    return 0;

  return SocketHTTP2_Stream_send_window (session->conn->h2_stream);
}

/**
 * @brief Get current receive window for HTTP/2 stream.
 */
int32_t
curl_h2_recv_window (CurlSession_T session)
{
  if (!session || !session->conn || !session->conn->h2_stream)
    return 0;

  return SocketHTTP2_Stream_recv_window (session->conn->h2_stream);
}

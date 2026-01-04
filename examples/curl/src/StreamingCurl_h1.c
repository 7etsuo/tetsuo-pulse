/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file StreamingCurl_h1.c
 * @brief HTTP/1.1 response streaming for curl module.
 *
 * Implements streaming response body handling for HTTP/1.1:
 * - Incremental header parsing
 * - Transparent chunked encoding decoding
 * - Content-Length body handling
 * - Connection-close body handling
 * - Progress callbacks
 * - Response size limits
 */

#include "curl/StreamingCurl-private.h"
#include "curl/StreamingCurl.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Default timeout if none specified (30 seconds) */
#define CURL_H1_DEFAULT_TIMEOUT_MS 30000

/* HTTP header formatting constants */
#define HTTP_HEADER_SEPARATOR_LEN 2  /* ": " */
#define HTTP_HEADER_CRLF_LEN 2       /* "\r\n" */

/* Content-Length limits */
#define CURL_MAX_CONTENT_LENGTH (4294967296LL) /* 4GB */

int
curl_wait_readable (CurlConnection *conn, int timeout_ms)
{
  if (!conn || !conn->socket)
    return -1;

  int fd = Socket_fd (conn->socket);
  if (fd < 0)
    return -1;

  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;

  int ret = poll (&pfd, 1, timeout_ms);

  if (ret < 0)
    {
      if (errno == EINTR)
        return 0; /* Interrupted, treat as timeout for retry */
      return -1;  /* Error */
    }

  if (ret == 0)
    return 0; /* Timeout */

  if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
    return -1; /* Error condition */

  return 1; /* Readable */
}

/**
 * @brief Receive data from connection with timeout.
 *
 * Handles both TLS and plain sockets with proper timeout handling.
 *
 * @param conn Connection
 * @param buf Buffer to receive into
 * @param len Buffer size
 * @param timeout_ms Timeout in milliseconds (0 = use default, -1 = block)
 * @return Bytes received, 0 on EOF, -1 on error, -2 on timeout
 */
static ssize_t
curl_h1_recv_timeout (CurlConnection *conn, void *buf, size_t len,
                      int timeout_ms)
{
  if (!conn || !conn->socket)
    return -1;

  /* Use default timeout if none specified */
  if (timeout_ms == 0)
    timeout_ms = CURL_H1_DEFAULT_TIMEOUT_MS;

  /* Wait for data with timeout */
  int wait_result = curl_wait_readable (conn, timeout_ms);
  if (wait_result < 0)
    return -1; /* Error */
  if (wait_result == 0)
    return -2; /* Timeout */

  volatile ssize_t result = 0;

  TRY { result = Socket_recv (conn->socket, buf, len); }
  EXCEPT (Socket_Failed) { return -1; }
  EXCEPT (Socket_Closed) { return 0; }
  END_TRY;

  return result;
}

/**
 * @brief Invoke header callback for each header.
 *
 * @param session Session with header callback
 * @param headers Response headers
 * @return 0 on success, -1 on abort
 */
static int
curl_h1_invoke_header_callback (CurlSession_T session,
                                SocketHTTP_Headers_T headers)
{
  if (!session || !session->options.header_callback || !headers)
    return 0;

  size_t count = SocketHTTP_Headers_count (headers);

  for (size_t i = 0; i < count; i++)
    {
      const SocketHTTP_Header *h = SocketHTTP_Headers_at (headers, i);
      if (!h)
        continue;

      /* Format header line: "Name: Value\r\n" */
      size_t line_len = h->name_len + HTTP_HEADER_SEPARATOR_LEN + h->value_len + HTTP_HEADER_CRLF_LEN;
      char *line = ALLOC (session->request_arena, line_len + 1);
      if (!line)
        continue; /* Skip this header if allocation fails */

      int len
          = snprintf (line, line_len + 1, "%.*s: %.*s\r\n", (int)h->name_len,
                      h->name, (int)h->value_len, h->value);
      if (len < 0)
        continue;

      size_t written = session->options.header_callback (
          line, 1, (size_t)len, session->options.header_userdata);

      if (written != (size_t)len)
        return -1; /* Callback aborted */
    }

  return 0;
}

/**
 * @brief Get Content-Length header value.
 *
 * @param headers Response headers
 * @return Content-Length or -1 if not set or chunked
 */
static int64_t
curl_h1_get_content_length (SocketHTTP_Headers_T headers)
{
  if (!headers)
    return -1;

  const char *cl = SocketHTTP_Headers_get (headers, "Content-Length");
  if (!cl)
    return -1;

  char *endptr;
  errno = 0;
  long long val = strtoll (cl, &endptr, CURL_DECIMAL_BASE);
  if (*endptr != '\0' || val < 0)
    return -1;
  if (errno == ERANGE)
    return -1;

  /* Enforce upper bound to prevent DoS (4GB limit) */
  if (val > CURL_MAX_CONTENT_LENGTH)
    return -1;

  return (int64_t)val;
}

/**
 * @brief Check if response has Transfer-Encoding: chunked.
 *
 * @param headers Response headers
 * @return 1 if chunked, 0 otherwise
 */
static int
curl_h1_is_chunked (SocketHTTP_Headers_T headers)
{
  if (!headers)
    return 0;

  const char *te = SocketHTTP_Headers_get (headers, "Transfer-Encoding");
  if (!te)
    return 0;

  return (strstr (te, "chunked") != NULL);
}

/**
 * @brief Ensure HTTP/1.1 parser exists and is ready.
 *
 * @param conn Connection
 * @param arena Arena for allocation
 * @return CURL_OK on success, error code on failure
 */
static CurlError
curl_h1_ensure_parser (CurlConnection *conn, Arena_T arena)
{
  if (!conn->h1_parser)
    {
      conn->h1_parser
          = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
      if (!conn->h1_parser)
        return CURL_ERROR_OUT_OF_MEMORY;
    }
  else
    {
      SocketHTTP1_Parser_reset (conn->h1_parser);
    }
  return CURL_OK;
}

/**
 * @brief Get effective timeout value.
 *
 * @param session Session with options
 * @return Timeout in milliseconds
 */
static int
curl_h1_get_timeout (CurlSession_T session)
{
  int timeout_ms = session->options.request_timeout_ms;
  return (timeout_ms > 0) ? timeout_ms : CURL_H1_DEFAULT_TIMEOUT_MS;
}

/**
 * @brief Receive and parse header data until complete.
 *
 * @param conn Connection with parser
 * @param timeout_ms Timeout in milliseconds
 * @return CURL_OK on success, error code on failure
 */
static CurlError
curl_h1_recv_headers_loop (CurlConnection *conn, int timeout_ms)
{
  char buf[CURL_H1_RECV_BUFFER_SIZE];
  size_t consumed;

  while (1)
    {
      ssize_t nread
          = curl_h1_recv_timeout (conn, buf, sizeof (buf), timeout_ms);

      if (nread == -2)
        return CURL_ERROR_TIMEOUT;
      if (nread < 0)
        return CURL_ERROR_CONNECT;
      if (nread == 0)
        return CURL_ERROR_PROTOCOL;

      SocketHTTP1_Result res = SocketHTTP1_Parser_execute (
          conn->h1_parser, buf, (size_t)nread, &consumed);

      if (res == HTTP1_OK)
        return CURL_OK;
      if (res != HTTP1_INCOMPLETE)
        return CURL_ERROR_PROTOCOL;
    }
}

/**
 * @brief Extract response info from parser into session.
 *
 * @param session Session to populate
 * @return CURL_OK on success, error code on failure
 */
static CurlError
curl_h1_extract_response (CurlSession_T session)
{
  const SocketHTTP_Response *resp
      = SocketHTTP1_Parser_get_response (session->conn->h1_parser);
  if (!resp)
    return CURL_ERROR_PROTOCOL;

  session->response.status_code = resp->status_code;
  session->response.version = resp->version;
  session->response.headers = resp->headers;
  session->response.content_length
      = curl_h1_get_content_length (resp->headers);

  return CURL_OK;
}

/**
 * @brief Receive and parse HTTP/1.1 response headers.
 *
 * @param session Session
 * @return CURL_OK on success, error code on failure
 */
CurlError
curl_receive_h1_headers (CurlSession_T session)
{
  if (!session || !session->conn || !session->conn->socket)
    return CURL_ERROR_CONNECT;

  CurlError err = curl_h1_ensure_parser (session->conn, session->request_arena);
  if (err != CURL_OK)
    return err;

  session->state = CURL_STATE_READING_HEADERS;

  err = curl_h1_recv_headers_loop (session->conn, curl_h1_get_timeout (session));
  if (err != CURL_OK)
    return err;

  err = curl_h1_extract_response (session);
  if (err != CURL_OK)
    return err;

  if (session->options.header_callback)
    {
      if (curl_h1_invoke_header_callback (session, session->response.headers)
          != 0)
        return CURL_ERROR_ABORTED;
    }

  return CURL_OK;
}

/**
 * @brief Check if response has no body based on status code or method.
 *
 * @param session Session with response info
 * @return 1 if no body expected, 0 otherwise
 */
static int
curl_h1_is_nobody_response (CurlSession_T session)
{
  int status = session->response.status_code;

  if (status == CURL_HTTP_STATUS_NO_CONTENT
      || status == CURL_HTTP_STATUS_NOT_MODIFIED)
    return 1;

  if (session->request_method == HTTP_METHOD_HEAD)
    return 1;

  if (status >= CURL_HTTP_STATUS_INFORMATIONAL_MIN
      && status < CURL_HTTP_STATUS_INFORMATIONAL_MAX)
    return 1;

  return 0;
}

/**
 * @brief Mark session as complete with no body.
 *
 * @param session Session to mark complete
 */
static void
curl_h1_complete_nobody (CurlSession_T session)
{
  session->state = CURL_STATE_COMPLETE;
  session->download_received = 0;
}

/**
 * @brief Handle EOF during body reception.
 *
 * @param body_mode Current body parsing mode
 * @return CURL_OK if EOF is valid terminator, error otherwise
 */
static CurlError
curl_h1_handle_eof (SocketHTTP1_BodyMode body_mode)
{
  return (body_mode == HTTP1_BODY_UNTIL_CLOSE) ? CURL_OK : CURL_ERROR_PROTOCOL;
}

/**
 * @brief Stream body chunk to write callback.
 *
 * @param session Session with callback
 * @param data Body data
 * @param len Data length
 * @return CURL_OK on success, error code on failure
 */
static CurlError
curl_h1_write_chunk (CurlSession_T session, const void *data, size_t len)
{
  if (!session->options.write_callback || len == 0)
    return CURL_OK;

  size_t written = session->options.write_callback (
      (void *)data, 1, len, session->options.write_userdata);

  return (written == len) ? CURL_OK : CURL_ERROR_WRITE_CALLBACK;
}

/**
 * @brief Invoke progress callback.
 *
 * @param session Session with progress state
 * @return CURL_OK to continue, CURL_ERROR_ABORTED if callback aborts
 */
static CurlError
curl_h1_report_progress (CurlSession_T session)
{
  if (!session->options.progress_callback)
    return CURL_OK;

  int abort = session->options.progress_callback (
      session->options.progress_userdata, session->download_total,
      session->download_received, session->upload_total, session->upload_sent);

  return (abort == 0) ? CURL_OK : CURL_ERROR_ABORTED;
}

/**
 * @brief Receive and process body data loop.
 *
 * @param session Session
 * @param body_mode Body parsing mode
 * @param timeout_ms Timeout in milliseconds
 * @return CURL_OK on success, error code on failure
 */
static CurlError
curl_h1_recv_body_loop (CurlSession_T session, SocketHTTP1_BodyMode body_mode,
                        int timeout_ms)
{
  CurlConnection *conn = session->conn;
  char recv_buf[CURL_H1_RECV_BUFFER_SIZE];
  char body_buf[CURL_H1_BODY_BUFFER_SIZE];
  size_t consumed, written;

  while (!SocketHTTP1_Parser_body_complete (conn->h1_parser))
    {
      ssize_t nread = curl_h1_recv_timeout (conn, recv_buf, sizeof (recv_buf),
                                            timeout_ms);
      if (nread == -2)
        return CURL_ERROR_TIMEOUT;
      if (nread < 0)
        return CURL_ERROR_CONNECT;
      if (nread == 0)
        return curl_h1_handle_eof (body_mode);

      SocketHTTP1_Result res = SocketHTTP1_Parser_read_body (
          conn->h1_parser, recv_buf, (size_t)nread, &consumed, body_buf,
          sizeof (body_buf), &written);

      if (res != HTTP1_OK && res != HTTP1_INCOMPLETE)
        return CURL_ERROR_PROTOCOL;

      CurlError err = curl_h1_write_chunk (session, body_buf, written);
      if (err != CURL_OK)
        return err;

      session->download_received += (int64_t)written;

      err = curl_h1_report_progress (session);
      if (err != CURL_OK)
        return err;
    }

  return CURL_OK;
}

/**
 * @brief Stream HTTP/1.1 response body through callback.
 *
 * @param session Session
 * @return CURL_OK on success, error code on failure
 */
CurlError
curl_receive_h1_body (CurlSession_T session)
{
  if (!session || !session->conn || !session->conn->h1_parser)
    return CURL_ERROR_CONNECT;

  session->state = CURL_STATE_READING_BODY;

  if (curl_h1_is_nobody_response (session))
    {
      curl_h1_complete_nobody (session);
      return CURL_OK;
    }

  SocketHTTP1_BodyMode body_mode
      = SocketHTTP1_Parser_body_mode (session->conn->h1_parser);

  if (body_mode == HTTP1_BODY_NONE)
    {
      curl_h1_complete_nobody (session);
      return CURL_OK;
    }

  session->download_total = session->response.content_length;
  session->download_received = 0;

  CurlError err
      = curl_h1_recv_body_loop (session, body_mode, curl_h1_get_timeout (session));
  if (err != CURL_OK)
    return err;

  session->state = CURL_STATE_COMPLETE;
  return CURL_OK;
}

/**
 * @brief Receive complete HTTP/1.1 response (headers + body).
 *
 * @param session Session
 * @return CURL_OK on success, error code on failure
 */
CurlError
curl_receive_h1_response (CurlSession_T session)
{
  if (!session)
    return CURL_ERROR_CONNECT;

  /* Receive headers */
  CurlError err = curl_receive_h1_headers (session);
  if (err != CURL_OK)
    return err;

  /* Receive body */
  err = curl_receive_h1_body (session);
  if (err != CURL_OK)
    return err;

  return CURL_OK;
}

/**
 * @brief Check if HTTP/1.1 connection should be kept alive.
 *
 * @param session Session after response
 * @return 1 if keep-alive, 0 otherwise
 */
int
curl_h1_should_keepalive (CurlSession_T session)
{
  if (!session || !session->conn || !session->conn->h1_parser)
    return 0;

  return SocketHTTP1_Parser_should_keepalive (session->conn->h1_parser);
}

/**
 * @brief Get trailer headers (for chunked responses).
 *
 * @param session Session after body complete
 * @return Trailer headers or NULL
 */
SocketHTTP_Headers_T
curl_h1_get_trailers (CurlSession_T session)
{
  if (!session || !session->conn || !session->conn->h1_parser)
    return NULL;

  return SocketHTTP1_Parser_get_trailers (session->conn->h1_parser);
}

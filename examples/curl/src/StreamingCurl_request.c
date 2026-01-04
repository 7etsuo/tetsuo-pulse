/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file StreamingCurl_request.c
 * @brief Request building and sending layer for streaming curl module.
 *
 * Implements HTTP request building with:
 * - HTTP/1.1 request serialization (RFC 9112)
 * - HTTP/2 HEADERS frame generation (RFC 9113)
 * - Streaming request body via callbacks
 * - Chunked transfer encoding for HTTP/1.1
 * - DATA frame streaming for HTTP/2
 */

#include "curl/StreamingCurl-private.h"
#include "curl/StreamingCurl.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTP2.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Default timeout if none specified (30 seconds) */
#define CURL_REQUEST_DEFAULT_TIMEOUT_MS 30000

/* Buffer sizes */
#define HOST_PORT_BUFFER_SIZE 16
#define CONTENT_LENGTH_BUFFER_SIZE 32
#define CHUNK_FRAMING_OVERHEAD 64

/* HTTP/1.1 chunked transfer encoding constants */
#define FINAL_CHUNK_SIZE 5 /* Length of "0\r\n\r\n" */

/* HTTP/2 stream processing timeout */
#define H2_PROCESS_TIMEOUT_MS 0

/* HPACK never-index flag for sensitive headers */
#define HPACK_NEVER_INDEX 1

/* Query string separator */
#define QUERY_SEPARATOR_SIZE 1 /* '?' character */

/*
 * Helper macro to add an HPACK header to the headers array.
 * Increments count and respects max_headers limit.
 */
#define ADD_HPACK_HEADER(headers, count, max, n, nlen, v, vlen, sensitive)     \
  do                                                                           \
    {                                                                          \
      if ((count) < (max))                                                     \
        {                                                                      \
          (headers)[(count)].name = (n);                                       \
          (headers)[(count)].name_len = (nlen);                                \
          (headers)[(count)].value = (v);                                      \
          (headers)[(count)].value_len = (vlen);                               \
          (headers)[(count)].never_index = (sensitive);                        \
          (count)++;                                                           \
        }                                                                      \
    }                                                                          \
  while (0)

/**
 * @brief Invoke progress callback if configured.
 * @return Non-zero if abort requested, 0 otherwise.
 */
static int
invoke_progress_callback (CurlSession_T session)
{
  if (!session->options.progress_callback)
    return 0;

  return session->options.progress_callback (
      session->options.progress_userdata, session->download_total,
      session->download_received, session->upload_total, session->upload_sent);
}

/**
 * @brief Get effective timeout from session options.
 */
static int
get_request_timeout (const CurlOptions *options)
{
  return (options->request_timeout_ms > 0) ? options->request_timeout_ms
                                           : CURL_REQUEST_DEFAULT_TIMEOUT_MS;
}

/**
 * @brief Send data with timeout, handling exceptions.
 * @return CURL_OK on success, error code on failure.
 */
static CurlError
send_with_timeout (Socket_T sock, const void *data, size_t len, int timeout_ms)
{
  volatile ssize_t sent = 0;

  TRY { sent = Socket_sendall_timeout (sock, data, len, timeout_ms); }
  EXCEPT (Socket_Failed) { return CURL_ERROR_CONNECT; }
  END_TRY;

  return (sent >= (ssize_t)len) ? CURL_OK : CURL_ERROR_TIMEOUT;
}

/**
 * @brief Build the request path including query string.
 */
static char *
build_request_path (const CurlParsedURL *url, Arena_T arena)
{
  if (!url || !url->path)
    return curl_arena_strdup (arena, "/", 1);

  size_t path_len = url->path_len;
  size_t query_len = url->query ? url->query_len + QUERY_SEPARATOR_SIZE : 0;
  size_t total_len = path_len + query_len;

  char *path = ALLOC (arena, total_len + 1);
  memcpy (path, url->path, path_len);

  if (url->query && url->query_len > 0)
    {
      path[path_len] = '?';
      memcpy (path + path_len + QUERY_SEPARATOR_SIZE, url->query,
              url->query_len);
    }

  path[total_len] = '\0';
  return path;
}

/**
 * @brief Build Host header value.
 */
static char *
build_host_header (const CurlParsedURL *url, Arena_T arena)
{
  if (!url || !url->host)
    return NULL;

  int default_port
      = url->is_secure ? CURL_HTTPS_DEFAULT_PORT : CURL_HTTP_DEFAULT_PORT;
  int port = url->port > 0 ? url->port : default_port;

  if (port == default_port)
    return curl_arena_strdup (arena, url->host, url->host_len);

  size_t buf_size = url->host_len + HOST_PORT_BUFFER_SIZE;
  char *host = ALLOC (arena, buf_size);
  int len
      = snprintf (host, buf_size, "%.*s:%d", (int)url->host_len, url->host,
                  port);

  if (len < 0 || (size_t)len >= buf_size)
    return curl_arena_strdup (arena, url->host, url->host_len);

  return host;
}

/**
 * @brief Add standard request headers.
 */
static int
add_standard_headers (SocketHTTP_Headers_T headers, const CurlParsedURL *url,
                      const CurlOptions *options, Arena_T arena)
{
  char *host = build_host_header (url, arena);
  if (host && SocketHTTP_Headers_set (headers, "Host", host) != 0)
    return -1;

  if (options->user_agent
      && SocketHTTP_Headers_set (headers, "User-Agent", options->user_agent)
             != 0)
    return -1;

  if (SocketHTTP_Headers_set (headers, "Accept", "*/*") != 0)
    return -1;

  if (options->accept_encoding
      && SocketHTTP_Headers_set (headers, "Accept-Encoding",
                                 "gzip, deflate, br")
             != 0)
    return -1;

  if (SocketHTTP_Headers_set (headers, "Connection", "keep-alive") != 0)
    return -1;

  return 0;
}

/**
 * @brief Add custom headers from session.
 */
static int
add_custom_headers (SocketHTTP_Headers_T headers,
                    const CurlCustomHeader *custom)
{
  for (const CurlCustomHeader *h = custom; h; h = h->next)
    {
      if (SocketHTTP_Headers_set (headers, h->name, h->value) != 0)
        return -1;
    }
  return 0;
}

/**
 * @brief Add body-related headers (Content-Length or Transfer-Encoding).
 */
static int
add_body_headers (SocketHTTP_Headers_T headers, size_t body_len,
                  int has_read_callback)
{
  if (body_len > 0)
    {
      char content_len[CONTENT_LENGTH_BUFFER_SIZE];
      snprintf (content_len, sizeof (content_len), "%zu", body_len);
      return SocketHTTP_Headers_set (headers, "Content-Length", content_len);
    }

  if (has_read_callback)
    return SocketHTTP_Headers_set (headers, "Transfer-Encoding", "chunked");

  return 0;
}

/**
 * @brief Build and serialize HTTP/1.1 request.
 */
ssize_t
curl_build_http1_request (CurlSession_T session, SocketHTTP_Method method,
                          const void *body, size_t body_len, char *output,
                          size_t output_size)
{
  if (!session || !output || output_size == 0)
    return -1;

  Arena_T arena = session->request_arena;
  char *path = build_request_path (&session->current_url, arena);

  SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (arena);
  if (!headers)
    return -1;

  if (add_standard_headers (headers, &session->current_url, &session->options,
                            arena)
          != 0
      || add_custom_headers (headers, session->custom_headers) != 0)
    return -1;

  if (session->auth_header
      && SocketHTTP_Headers_set (headers, "Authorization", session->auth_header)
             != 0)
    return -1;

  if (add_body_headers (headers, body_len,
                        session->options.read_callback != NULL)
      != 0)
    return -1;

  SocketHTTP_Request request = { 0 };
  request.method = method;
  request.version = HTTP_VERSION_1_1;
  request.path = path;
  request.headers = headers;
  request.has_body = (body && body_len > 0) || session->options.read_callback;
  request.content_length = (body && body_len > 0) ? (int64_t)body_len : -1;

  return SocketHTTP1_serialize_request (&request, output, output_size);
}

/**
 * @brief Send HTTP/1.1 request with optional body.
 */
CurlError
curl_send_http1_request (CurlSession_T session, SocketHTTP_Method method,
                         const void *body, size_t body_len)
{
  if (!session || !session->conn || !session->conn->socket)
    return CURL_ERROR_CONNECT;

  int timeout_ms = get_request_timeout (&session->options);
  char buffer[CURL_REQUEST_BUFFER_SIZE];

  ssize_t header_len = curl_build_http1_request (session, method, body,
                                                 body_len, buffer,
                                                 sizeof (buffer));
  if (header_len < 0)
    return CURL_ERROR_PROTOCOL;

  Socket_T sock = session->conn->socket;

  CurlError err = send_with_timeout (sock, buffer, (size_t)header_len,
                                     timeout_ms);
  if (err != CURL_OK)
    return err;

  if (body && body_len > 0)
    {
      err = send_with_timeout (sock, body, body_len, timeout_ms);
      if (err != CURL_OK)
        return err;
      session->upload_sent = (int64_t)body_len;
    }
  else if (session->options.read_callback)
    {
      return curl_send_chunked_body (session);
    }

  return CURL_OK;
}

/**
 * @brief Send chunked body using read callback.
 */
CurlError
curl_send_chunked_body (CurlSession_T session)
{
  if (!session || !session->options.read_callback)
    return CURL_ERROR_READ_CALLBACK;

  if (!session->conn || !session->conn->socket)
    return CURL_ERROR_CONNECT;

  int timeout_ms = get_request_timeout (&session->options);
  Socket_T sock = session->conn->socket;
  char data_buf[CURL_CHUNK_BUFFER_SIZE];
  char chunk_buf[CURL_CHUNK_BUFFER_SIZE + CHUNK_FRAMING_OVERHEAD];

  session->upload_sent = 0;

  while (1)
    {
      size_t nread = session->options.read_callback (
          data_buf, 1, sizeof (data_buf), session->options.read_userdata);

      if (nread == CURL_READFUNC_ABORT)
        return CURL_ERROR_ABORTED;

      if (nread == 0)
        {
          CurlError err = send_with_timeout (sock, "0\r\n\r\n", FINAL_CHUNK_SIZE,
                                             timeout_ms);
          if (err != CURL_OK)
            return err;
          break;
        }

      ssize_t chunk_len
          = SocketHTTP1_chunk_encode (data_buf, nread, chunk_buf,
                                      sizeof (chunk_buf));
      if (chunk_len < 0)
        return CURL_ERROR_PROTOCOL;

      CurlError err = send_with_timeout (sock, chunk_buf, (size_t)chunk_len,
                                         timeout_ms);
      if (err != CURL_OK)
        return err;

      session->upload_sent += (int64_t)nread;

      if (invoke_progress_callback (session))
        return CURL_ERROR_ABORTED;
    }

  return CURL_OK;
}

/**
 * @brief Initialize HTTP/2 connection if not already done.
 */
static int
ensure_h2_connection (CurlSession_T session)
{
  if (!session || !session->conn)
    return -1;

  if (session->conn->h2_conn)
    return 0;

  SocketHTTP2_Config config;
  SocketHTTP2_config_defaults (&config, HTTP2_ROLE_CLIENT);

  session->conn->h2_conn
      = SocketHTTP2_Conn_new (session->conn->socket, &config, session->arena);
  if (!session->conn->h2_conn)
    return -1;

  if (SocketHTTP2_Conn_handshake (session->conn->h2_conn) < 0)
    {
      SocketHTTP2_Conn_free (&session->conn->h2_conn);
      return -1;
    }

  return 0;
}

/**
 * @brief Build HTTP/2 pseudo-headers and regular headers.
 */
static int
build_h2_headers (CurlSession_T session, SocketHTTP_Method method,
                  SocketHPACK_Header *headers, size_t max_headers,
                  size_t *header_count)
{
  if (!session || !headers || !header_count)
    return -1;

  Arena_T arena = session->request_arena;
  size_t count = 0;

  /* Pseudo-headers (required) */
  const char *method_str = SocketHTTP_method_name (method);
  if (!method_str)
    method_str = "GET";

  ADD_HPACK_HEADER (headers, count, max_headers, ":method", 7, method_str,
                    strlen (method_str), 0);

  const char *scheme = session->current_url.is_secure ? "https" : "http";
  ADD_HPACK_HEADER (headers, count, max_headers, ":scheme", 7, scheme,
                    strlen (scheme), 0);

  char *authority = build_host_header (&session->current_url, arena);
  if (authority)
    ADD_HPACK_HEADER (headers, count, max_headers, ":authority", 10, authority,
                      strlen (authority), 0);

  char *path = build_request_path (&session->current_url, arena);
  ADD_HPACK_HEADER (headers, count, max_headers, ":path", 5, path,
                    strlen (path), 0);

  /* Regular headers */
  if (session->options.user_agent)
    ADD_HPACK_HEADER (headers, count, max_headers, "user-agent", 10,
                      session->options.user_agent,
                      strlen (session->options.user_agent), 0);

  ADD_HPACK_HEADER (headers, count, max_headers, "accept", 6, "*/*", 3, 0);

  if (session->options.accept_encoding)
    ADD_HPACK_HEADER (headers, count, max_headers, "accept-encoding", 15,
                      "gzip, deflate, br", 17, 0);

  if (session->auth_header)
    ADD_HPACK_HEADER (headers, count, max_headers, "authorization", 13,
                      session->auth_header, strlen (session->auth_header),
                      HPACK_NEVER_INDEX);

  /* Custom headers */
  for (const CurlCustomHeader *h = session->custom_headers; h; h = h->next)
    ADD_HPACK_HEADER (headers, count, max_headers, h->name, strlen (h->name),
                      h->value, strlen (h->value), 0);

  *header_count = count;
  return 0;
}

/**
 * @brief Send HTTP/2 request with optional body.
 */
CurlError
curl_send_http2_request (CurlSession_T session, SocketHTTP_Method method,
                         const void *body, size_t body_len)
{
  if (!session)
    return CURL_ERROR_CONNECT;

  if (ensure_h2_connection (session) != 0)
    return CURL_ERROR_PROTOCOL;

  SocketHTTP2_Stream_T stream
      = SocketHTTP2_Stream_new (session->conn->h2_conn);
  if (!stream)
    return CURL_ERROR_PROTOCOL;

  session->conn->h2_stream = stream;

  SocketHPACK_Header headers[CURL_MAX_HEADER_COUNT_SMALL];
  size_t header_count = 0;

  if (build_h2_headers (session, method, headers, CURL_MAX_HEADER_COUNT_SMALL,
                        &header_count)
      != 0)
    return CURL_ERROR_PROTOCOL;

  int has_body = (body && body_len > 0) || session->options.read_callback;

  if (SocketHTTP2_Stream_send_headers (stream, headers, header_count, !has_body)
      != 0)
    return CURL_ERROR_PROTOCOL;

  SocketHTTP2_Conn_flush (session->conn->h2_conn);

  if (body && body_len > 0)
    return curl_send_h2_data (session, body, body_len, 1);

  if (session->options.read_callback)
    return curl_send_h2_streaming_body (session);

  return CURL_OK;
}

/**
 * @brief Send DATA frame(s) for HTTP/2.
 */
CurlError
curl_send_h2_data (CurlSession_T session, const void *data, size_t len,
                   int end_stream)
{
  if (!session || !session->conn || !session->conn->h2_stream)
    return CURL_ERROR_CONNECT;

  SocketHTTP2_Stream_T stream = session->conn->h2_stream;
  const unsigned char *ptr = (const unsigned char *)data;
  size_t remaining = len;

  while (remaining > 0)
    {
      size_t chunk_size
          = (remaining > CURL_CHUNK_BUFFER_SIZE) ? CURL_CHUNK_BUFFER_SIZE
                                                 : remaining;
      int is_last = (remaining <= CURL_CHUNK_BUFFER_SIZE) && end_stream;

      ssize_t sent
          = SocketHTTP2_Stream_send_data (stream, ptr, chunk_size, is_last);

      if (sent < 0)
        return CURL_ERROR_PROTOCOL;

      if (sent == 0)
        {
          /* Flow control - need to wait */
          SocketHTTP2_Conn_process (session->conn->h2_conn,
                                    H2_PROCESS_TIMEOUT_MS);
          SocketHTTP2_Conn_flush (session->conn->h2_conn);
          continue;
        }

      ptr += sent;
      remaining -= (size_t)sent;
      session->upload_sent += sent;

      if (invoke_progress_callback (session))
        return CURL_ERROR_ABORTED;
    }

  SocketHTTP2_Conn_flush (session->conn->h2_conn);
  return CURL_OK;
}

/**
 * @brief Send streaming body for HTTP/2 using read callback.
 */
CurlError
curl_send_h2_streaming_body (CurlSession_T session)
{
  if (!session || !session->options.read_callback)
    return CURL_ERROR_READ_CALLBACK;

  if (!session->conn || !session->conn->h2_stream)
    return CURL_ERROR_CONNECT;

  char data_buf[CURL_CHUNK_BUFFER_SIZE];
  session->upload_sent = 0;

  while (1)
    {
      size_t nread = session->options.read_callback (
          data_buf, 1, sizeof (data_buf), session->options.read_userdata);

      if (nread == CURL_READFUNC_ABORT)
        return CURL_ERROR_ABORTED;

      if (nread == 0)
        {
          SocketHTTP2_Stream_send_data (session->conn->h2_stream, NULL, 0, 1);
          SocketHTTP2_Conn_flush (session->conn->h2_conn);
          break;
        }

      CurlError err = curl_send_h2_data (session, data_buf, nread, 0);
      if (err != CURL_OK)
        return err;
    }

  return CURL_OK;
}

/**
 * @brief Send request using appropriate protocol.
 */
CurlError
curl_send_request (CurlSession_T session, SocketHTTP_Method method,
                   const void *body, size_t body_len)
{
  if (!session || !session->conn)
    return CURL_ERROR_CONNECT;

  session->state = CURL_STATE_SENDING_REQUEST;
  session->request_method = method;

  /* Initialize transfer state */
  session->upload_total = body_len > 0 ? (int64_t)body_len : -1;
  session->upload_sent = 0;
  session->download_total = -1;
  session->download_received = 0;

  CurlError result = curl_connection_is_http2 (session->conn)
                         ? curl_send_http2_request (session, method, body,
                                                    body_len)
                         : curl_send_http1_request (session, method, body,
                                                    body_len);

  session->state = (result == CURL_OK) ? CURL_STATE_READING_HEADERS
                                       : CURL_STATE_ERROR;
  if (result != CURL_OK)
    session->last_error = result;

  return result;
}

/**
 * @brief Build request headers for a session.
 */
int
curl_build_request_headers (CurlSession_T session, SocketHTTP_Method method,
                            const char *content_type, size_t body_len)
{
  if (!session)
    return -1;

  (void)method; /* Reserved for future use */

  Arena_T arena = session->request_arena;

  session->request_headers = SocketHTTP_Headers_new (arena);
  if (!session->request_headers)
    return -1;

  if (add_standard_headers (session->request_headers, &session->current_url,
                            &session->options, arena)
          != 0
      || add_custom_headers (session->request_headers, session->custom_headers)
             != 0)
    return -1;

  if (content_type
      && SocketHTTP_Headers_set (session->request_headers, "Content-Type",
                                 content_type)
             != 0)
    return -1;

  /* Add Content-Length or Transfer-Encoding */
  if (body_len > 0)
    {
      char len_str[CONTENT_LENGTH_BUFFER_SIZE];
      snprintf (len_str, sizeof (len_str), "%zu", body_len);
      if (SocketHTTP_Headers_set (session->request_headers, "Content-Length",
                                  len_str)
          != 0)
        return -1;
    }
  else if (session->options.read_callback
           && (!session->conn || !curl_connection_is_http2 (session->conn)))
    {
      if (SocketHTTP_Headers_set (session->request_headers, "Transfer-Encoding",
                                  "chunked")
          != 0)
        return -1;
    }

  return 0;
}

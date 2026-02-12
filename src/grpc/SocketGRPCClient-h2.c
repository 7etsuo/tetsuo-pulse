/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketGRPCClient-h2.c
 * @brief Unary gRPC client transport integration over HTTP/2.
 */

#include "grpc/SocketGRPC-private.h"
#include "grpc/SocketGRPCWire.h"
#include "deflate/SocketDeflate.h"
#include "core/SocketUtil/Timeout.h"
#include "http/SocketHTTPClient-private.h"
#include "http/SocketHTTP2-private.h"

#include "core/SocketCrypto.h"
#include "socket/Socket.h"
#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#define GRPC_CONTENT_TYPE "application/grpc"
#define GRPC_TIMEOUT_HEADER_MAX 32U
#define GRPC_RESPONSE_CHUNK 4096U
#define GRPC_STREAM_RECV_BUFFER_INITIAL 4096U
#define GRPC_ACCEPT_ENCODING_VALUE "identity,gzip"
#define GRPC_ENCODING_GZIP "gzip"
#define GRPC_ENCODING_IDENTITY "identity"

typedef enum
{
  GRPC_COMPRESSION_IDENTITY = 0,
  GRPC_COMPRESSION_GZIP = 1,
  GRPC_COMPRESSION_UNSUPPORTED = 2
} SocketGRPC_Compression;

typedef struct
{
  SocketHTTPClient_T http_client;
  SocketHTTPClient_Request_T request;
  HTTPPoolEntry *conn;
  SocketHTTP2_Conn_T h2conn;
  SocketHTTP2_Stream_T stream;
  SocketHTTPClient_Response response;
  unsigned char *recv_buffer;
  size_t recv_len;
  size_t recv_cap;
  int headers_received;
  int remote_end_stream;
  int status_finalized;
  int active_stream_counted;
  int http_status_code;
  int64_t deadline_ms;
  Arena_T compression_arena;
  SocketDeflate_Deflater_T request_deflater;
  SocketDeflate_Inflater_T response_inflater;
  SocketGRPC_Compression request_compression;
  SocketGRPC_Compression response_compression;
} SocketGRPC_H2CallStream;

struct SocketGRPC_ClientUnaryInterceptorEntry
{
  SocketGRPC_ClientUnaryInterceptor interceptor;
  void *userdata;
  SocketGRPC_ClientUnaryInterceptorEntry *next;
};

struct SocketGRPC_ClientStreamInterceptorEntry
{
  SocketGRPC_ClientStreamInterceptor interceptor;
  void *userdata;
  SocketGRPC_ClientStreamInterceptorEntry *next;
};

static int
grpc_h2_conn_process_safe (SocketHTTP2_Conn_T conn, unsigned events)
{
  volatile int rc = -1;

  TRY
  {
    rc = SocketHTTP2_Conn_process (conn, events);
  }
  EXCEPT (SocketHTTP2)
  {
    rc = -1;
  }
  EXCEPT (Socket_Failed)
  {
    rc = -1;
  }
  EXCEPT (Socket_Closed)
  {
    rc = -1;
  }
#if SOCKET_HAS_TLS
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    rc = -1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    rc = -1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    rc = -1;
  }
#endif
  ELSE
  {
    rc = -1;
  }
  END_TRY;

  return rc;
}

static int
grpc_h2_conn_flush_safe (SocketHTTP2_Conn_T conn)
{
  volatile int rc = -1;

  TRY
  {
    rc = SocketHTTP2_Conn_flush (conn);
  }
  EXCEPT (SocketHTTP2)
  {
    rc = -1;
  }
  EXCEPT (Socket_Failed)
  {
    rc = -1;
  }
  EXCEPT (Socket_Closed)
  {
    rc = -1;
  }
#if SOCKET_HAS_TLS
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    rc = -1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    rc = -1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    rc = -1;
  }
#endif
  ELSE
  {
    rc = -1;
  }
  END_TRY;

  return rc;
}

static int
grpc_h2_stream_send_request_safe (SocketHTTP2_Stream_T stream,
                                  const SocketHTTP_Request *http_req,
                                  int end_stream)
{
  volatile int rc = -1;

  TRY
  {
    rc = SocketHTTP2_Stream_send_request (stream, http_req, end_stream);
  }
  EXCEPT (SocketHTTP2)
  {
    rc = -1;
  }
  EXCEPT (Socket_Failed)
  {
    rc = -1;
  }
  EXCEPT (Socket_Closed)
  {
    rc = -1;
  }
#if SOCKET_HAS_TLS
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    rc = -1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    rc = -1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    rc = -1;
  }
#endif
  ELSE
  {
    rc = -1;
  }
  END_TRY;

  return rc;
}

static ssize_t
grpc_h2_stream_send_data_safe (SocketHTTP2_Stream_T stream,
                               const void *buf,
                               size_t len,
                               int end_stream)
{
  volatile ssize_t rc = -1;

  TRY
  {
    rc = SocketHTTP2_Stream_send_data (stream, buf, len, end_stream);
  }
  EXCEPT (SocketHTTP2)
  {
    rc = -1;
  }
  EXCEPT (Socket_Failed)
  {
    rc = -1;
  }
  EXCEPT (Socket_Closed)
  {
    rc = -1;
  }
#if SOCKET_HAS_TLS
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    rc = -1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    rc = -1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    rc = -1;
  }
#endif
  ELSE
  {
    rc = -1;
  }
  END_TRY;

  return rc;
}

static int
grpc_h2_stream_send_headers_safe (SocketHTTP2_Stream_T stream,
                                  const SocketHPACK_Header *headers,
                                  size_t header_count,
                                  int end_stream)
{
  volatile int rc = -1;

  TRY
  {
    rc = SocketHTTP2_Stream_send_headers (
        stream, headers, header_count, end_stream);
  }
  EXCEPT (SocketHTTP2)
  {
    rc = -1;
  }
  EXCEPT (Socket_Failed)
  {
    rc = -1;
  }
  EXCEPT (Socket_Closed)
  {
    rc = -1;
  }
#if SOCKET_HAS_TLS
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    rc = -1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    rc = -1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    rc = -1;
  }
#endif
  ELSE
  {
    rc = -1;
  }
  END_TRY;

  return rc;
}

static void
grpc_h2_stream_cancel_safe (SocketHTTP2_Stream_T stream)
{
  if (stream == NULL)
    return;

  TRY
  {
    SocketHTTP2_Stream_close (stream, HTTP2_CANCEL);
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

static ssize_t
grpc_h2_stream_recv_data_safe (SocketHTTP2_Stream_T stream,
                               void *buf,
                               size_t len,
                               int *end_stream)
{
  volatile ssize_t rc = -1;

  TRY
  {
    rc = SocketHTTP2_Stream_recv_data (stream, buf, len, end_stream);
  }
  EXCEPT (SocketHTTP2)
  {
    rc = -1;
  }
  EXCEPT (Socket_Failed)
  {
    rc = -1;
  }
  EXCEPT (Socket_Closed)
  {
    rc = -1;
  }
#if SOCKET_HAS_TLS
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    rc = -1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    rc = -1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    rc = -1;
  }
#endif
  ELSE
  {
    rc = -1;
  }
  END_TRY;

  return rc;
}

static int
grpc_h2_stream_recv_trailers_safe (SocketHTTP2_Stream_T stream,
                                   SocketHPACK_Header *trailers,
                                   size_t trailers_cap,
                                   size_t *trailer_count)
{
  volatile int rc = -1;

  TRY
  {
    rc = SocketHTTP2_Stream_recv_trailers (
        stream, trailers, trailers_cap, trailer_count);
  }
  EXCEPT (SocketHTTP2)
  {
    rc = -1;
  }
  EXCEPT (Socket_Failed)
  {
    rc = -1;
  }
  EXCEPT (Socket_Closed)
  {
    rc = -1;
  }
#if SOCKET_HAS_TLS
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    rc = -1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    rc = -1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    rc = -1;
  }
#endif
  ELSE
  {
    rc = -1;
  }
  END_TRY;

  return rc;
}

static void
grpc_release_connection_safe (SocketHTTPClient_T http_client,
                              HTTPPoolEntry *conn,
                              int success)
{
  if (http_client == NULL || conn == NULL)
    return;

  TRY
  {
    httpclient_release_connection (http_client, conn, success);
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

static int
str_has_prefix (const char *str, const char *prefix)
{
  size_t prefix_len;
  if (str == NULL || prefix == NULL)
    return 0;
  prefix_len = strlen (prefix);
  return strncmp (str, prefix, prefix_len) == 0;
}

static SocketGRPC_StatusCode
grpc_map_httpclient_error (SocketHTTPClient_Error error)
{
  switch (error)
    {
    case HTTPCLIENT_ERROR_TIMEOUT:
      return SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED;
    case HTTPCLIENT_ERROR_DNS:
    case HTTPCLIENT_ERROR_CONNECT:
      return SOCKET_GRPC_STATUS_UNAVAILABLE;
    case HTTPCLIENT_ERROR_TLS:
      return SOCKET_GRPC_STATUS_UNAUTHENTICATED;
    case HTTPCLIENT_ERROR_RESPONSE_TOO_LARGE:
    case HTTPCLIENT_ERROR_LIMIT_EXCEEDED:
      return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
    case HTTPCLIENT_ERROR_CANCELLED:
      return SOCKET_GRPC_STATUS_CANCELLED;
    case HTTPCLIENT_ERROR_PROTOCOL:
    case HTTPCLIENT_ERROR_TOO_MANY_REDIRECTS:
      return SOCKET_GRPC_STATUS_INTERNAL;
    case HTTPCLIENT_ERROR_OUT_OF_MEMORY:
      return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
    default:
      return SOCKET_GRPC_STATUS_UNKNOWN;
    }
}

static void
grpc_call_status_set (SocketGRPC_Call_T call,
                      SocketGRPC_StatusCode code,
                      const char *message)
{
  SocketGRPC_status_set (&call->last_status, code, message);
}

static int
grpc_status_code_valid (SocketGRPC_StatusCode code)
{
  return code >= SOCKET_GRPC_STATUS_OK
         && code <= SOCKET_GRPC_STATUS_UNAUTHENTICATED;
}

static int
grpc_apply_interceptor_stop (SocketGRPC_Call_T call,
                             SocketGRPC_Status status,
                             int mark_stream_failed)
{
  const char *message = status.message;
  SocketGRPC_StatusCode code = status.code;

  if (call == NULL)
    return -1;
  if (!grpc_status_code_valid (code) || code == SOCKET_GRPC_STATUS_OK)
    {
      code = SOCKET_GRPC_STATUS_INTERNAL;
      message = "Interceptor returned invalid status";
    }
  if (message == NULL || message[0] == '\0')
    message = SocketGRPC_status_default_message (code);

  if (call->response_trailers != NULL)
    {
      SocketGRPC_Trailers_clear (call->response_trailers);
      (void)SocketGRPC_Trailers_set_status (call->response_trailers, code);
      if (message[0] != '\0')
        (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                               message);
    }
  grpc_call_status_set (call, code, message);

  if (mark_stream_failed)
    call->h2_stream_state = GRPC_CALL_STREAM_FAILED;
  return -1;
}

static int
grpc_run_client_unary_interceptors (SocketGRPC_Call_T call,
                                    const uint8_t *request_payload,
                                    size_t request_payload_len)
{
  SocketGRPC_ClientUnaryInterceptorEntry *entry;

  if (call == NULL)
    return -1;

  entry = call->unary_interceptors;
  while (entry != NULL)
    {
      SocketGRPC_Status status
          = { SOCKET_GRPC_STATUS_OK,
              SocketGRPC_status_default_message (SOCKET_GRPC_STATUS_OK) };
      int action = entry->interceptor (
          call, request_payload, request_payload_len, &status, entry->userdata);

      if (action == SOCKET_GRPC_INTERCEPT_CONTINUE)
        {
          entry = entry->next;
          continue;
        }
      if (action != SOCKET_GRPC_INTERCEPT_STOP)
        {
          status.code = SOCKET_GRPC_STATUS_INTERNAL;
          status.message = "Interceptor returned invalid action";
        }
      return grpc_apply_interceptor_stop (call, status, 0);
    }

  return 0;
}

static int
grpc_has_metadata_slot (SocketGRPC_Call_T call)
{
  SocketGRPC_Metadata_T metadata;

  if (call == NULL || call->response_trailers == NULL || call->channel == NULL)
    return 0;
  metadata = SocketGRPC_Trailers_metadata (call->response_trailers);
  if (metadata == NULL)
    return 0;
  return SocketGRPC_Metadata_count (metadata)
         < call->channel->config.max_metadata_entries;
}

static int
grpc_token_equals_ci (const char *value, size_t value_len, const char *token)
{
  size_t token_len;

  if (value == NULL || token == NULL)
    return 0;

  while (value_len > 0 && isspace ((unsigned char)value[0]))
    {
      value++;
      value_len--;
    }
  while (value_len > 0 && isspace ((unsigned char)value[value_len - 1U]))
    value_len--;

  token_len = strlen (token);
  if (value_len != token_len)
    return 0;
  return strncasecmp (value, token, token_len) == 0;
}

static SocketGRPC_Compression
grpc_parse_compression_value (const char *value, size_t value_len)
{
  if (grpc_token_equals_ci (value, value_len, GRPC_ENCODING_IDENTITY))
    return GRPC_COMPRESSION_IDENTITY;
  if (grpc_token_equals_ci (value, value_len, GRPC_ENCODING_GZIP))
    return GRPC_COMPRESSION_GZIP;
  return GRPC_COMPRESSION_UNSUPPORTED;
}

static SocketGRPC_Compression
grpc_response_compression_from_headers (SocketHTTP_Headers_T headers)
{
  size_t i;
  SocketGRPC_Compression compression = GRPC_COMPRESSION_IDENTITY;
  int seen = 0;

  if (headers == NULL)
    return GRPC_COMPRESSION_IDENTITY;

  for (i = 0; i < SocketHTTP_Headers_count (headers); i++)
    {
      const SocketHTTP_Header *h = SocketHTTP_Headers_at (headers, i);
      SocketGRPC_Compression parsed;
      if (h == NULL || h->name == NULL || h->value == NULL)
        continue;
      if (h->name_len != strlen ("grpc-encoding")
          || strncasecmp (h->name, "grpc-encoding", h->name_len) != 0)
        continue;

      parsed = grpc_parse_compression_value (h->value, h->value_len);
      if (parsed == GRPC_COMPRESSION_UNSUPPORTED)
        return GRPC_COMPRESSION_UNSUPPORTED;
      if (seen && parsed != compression)
        return GRPC_COMPRESSION_UNSUPPORTED;
      compression = parsed;
      seen = 1;
    }

  return compression;
}

static int
grpc_grow_heap_buffer_limited (unsigned char **buffer,
                               size_t *capacity,
                               size_t min_capacity,
                               size_t max_capacity)
{
  size_t new_capacity;
  unsigned char *tmp;

  if (buffer == NULL || capacity == NULL || *buffer == NULL
      || min_capacity > max_capacity)
    return -1;

  new_capacity = (*capacity == 0) ? 256U : *capacity;
  if (new_capacity > max_capacity)
    new_capacity = max_capacity;
  while (new_capacity < min_capacity)
    {
      size_t next;
      if (new_capacity >= max_capacity)
        break;
      next = new_capacity * 2U;
      if (next <= new_capacity || next > max_capacity)
        next = max_capacity;
      new_capacity = next;
    }
  if (new_capacity < min_capacity)
    return -1;

  tmp = (unsigned char *)realloc (*buffer, new_capacity);
  if (tmp == NULL)
    return -1;
  *buffer = tmp;
  *capacity = new_capacity;
  return 0;
}

static size_t
grpc_write_gzip_header (uint8_t *output, size_t output_len)
{
  if (output == NULL || output_len < GZIP_HEADER_MIN_SIZE)
    return 0;

  output[0] = GZIP_MAGIC_0;
  output[1] = GZIP_MAGIC_1;
  output[2] = GZIP_METHOD_DEFLATE;
  output[3] = 0;
  output[4] = 0;
  output[5] = 0;
  output[6] = 0;
  output[7] = 0;
  output[8] = 0;
  output[9] = GZIP_OS_UNKNOWN;
  return GZIP_HEADER_MIN_SIZE;
}

static size_t
grpc_write_gzip_trailer (uint8_t *output,
                         size_t output_len,
                         uint32_t crc,
                         uint32_t size)
{
  if (output == NULL || output_len < GZIP_TRAILER_SIZE)
    return 0;

  output[0] = (uint8_t)(crc & 0xFFU);
  output[1] = (uint8_t)((crc >> 8) & 0xFFU);
  output[2] = (uint8_t)((crc >> 16) & 0xFFU);
  output[3] = (uint8_t)((crc >> 24) & 0xFFU);
  output[4] = (uint8_t)(size & 0xFFU);
  output[5] = (uint8_t)((size >> 8) & 0xFFU);
  output[6] = (uint8_t)((size >> 16) & 0xFFU);
  output[7] = (uint8_t)((size >> 24) & 0xFFU);
  return GZIP_TRAILER_SIZE;
}

static int
grpc_stream_context_init_compression (SocketGRPC_Call_T call,
                                      SocketGRPC_H2CallStream *ctx)
{
  int need_request_compression;
  int need_response_decompression;

  if (call == NULL || call->channel == NULL || ctx == NULL)
    return -1;

  need_request_compression
      = call->channel->config.enable_request_compression ? 1 : 0;
  need_response_decompression
      = call->channel->config.enable_response_decompression ? 1 : 0;

  ctx->request_compression = need_request_compression
                                 ? GRPC_COMPRESSION_GZIP
                                 : GRPC_COMPRESSION_IDENTITY;
  ctx->response_compression = GRPC_COMPRESSION_IDENTITY;

  if (!need_request_compression && !need_response_decompression)
    return 0;

  ctx->compression_arena = Arena_new ();
  if (ctx->compression_arena == NULL)
    return -1;

  if (need_request_compression)
    {
      ctx->request_deflater = SocketDeflate_Deflater_new (
          ctx->compression_arena, DEFLATE_LEVEL_DEFAULT);
      if (ctx->request_deflater == NULL)
        return -1;
    }

  if (need_response_decompression)
    {
      ctx->response_inflater = SocketDeflate_Inflater_new (
          ctx->compression_arena,
          call->channel->config.max_decompressed_message_bytes);
      if (ctx->response_inflater == NULL)
        return -1;
    }

  return 0;
}

static int
grpc_gzip_compress_payload (SocketDeflate_Deflater_T deflater,
                            const uint8_t *input,
                            size_t input_len,
                            unsigned char **output_out,
                            size_t *output_len_out)
{
  unsigned char *output;
  size_t output_cap;
  size_t output_len = 0;
  const uint8_t *in_ptr = input;
  size_t in_remaining = input_len;
  SocketDeflate_Result res;
  uint32_t crc;

  if (deflater == NULL || output_out == NULL || output_len_out == NULL
      || (input == NULL && input_len != 0))
    return -1;

  output_cap = SocketDeflate_compress_bound (input_len);
  if (output_cap > SIZE_MAX - (GZIP_HEADER_MIN_SIZE + GZIP_TRAILER_SIZE))
    return -1;
  output_cap += GZIP_HEADER_MIN_SIZE + GZIP_TRAILER_SIZE;
  output = (unsigned char *)malloc (output_cap);
  if (output == NULL)
    return -1;

  if (grpc_write_gzip_header (output, output_cap) == 0)
    {
      free (output);
      return -1;
    }
  output_len = GZIP_HEADER_MIN_SIZE;
  SocketDeflate_Deflater_reset (deflater);

  while (in_remaining > 0)
    {
      size_t consumed = 0;
      size_t written = 0;
      res = SocketDeflate_Deflater_deflate (deflater,
                                            in_ptr,
                                            in_remaining,
                                            &consumed,
                                            output + output_len,
                                            output_cap - output_len,
                                            &written);
      output_len += written;
      in_ptr += consumed;
      in_remaining -= consumed;

      if (res == DEFLATE_OUTPUT_FULL)
        {
          if (grpc_grow_heap_buffer_limited (
                  &output, &output_cap, output_len + 1U, SIZE_MAX)
              != 0)
            {
              free (output);
              return -1;
            }
          continue;
        }
      if (res != DEFLATE_OK)
        {
          free (output);
          return -1;
        }
      if (in_remaining > 0 && consumed == 0 && written == 0)
        {
          if (grpc_grow_heap_buffer_limited (
                  &output, &output_cap, output_len + 1U, SIZE_MAX)
              != 0)
            {
              free (output);
              return -1;
            }
        }
    }

  for (;;)
    {
      size_t written = 0;
      res = SocketDeflate_Deflater_finish (
          deflater, output + output_len, output_cap - output_len, &written);
      output_len += written;
      if (res == DEFLATE_OUTPUT_FULL)
        {
          if (grpc_grow_heap_buffer_limited (
                  &output, &output_cap, output_len + 1U, SIZE_MAX)
              != 0)
            {
              free (output);
              return -1;
            }
          continue;
        }
      if (res != DEFLATE_OK)
        {
          free (output);
          return -1;
        }
      break;
    }

  if (output_cap - output_len < GZIP_TRAILER_SIZE
      && grpc_grow_heap_buffer_limited (
             &output, &output_cap, output_len + GZIP_TRAILER_SIZE, SIZE_MAX)
             != 0)
    {
      free (output);
      return -1;
    }

  crc = SocketDeflate_crc32 (0, input, input_len);
  if (grpc_write_gzip_trailer (output + output_len,
                               output_cap - output_len,
                               crc,
                               (uint32_t)input_len)
      == 0)
    {
      free (output);
      return -1;
    }
  output_len += GZIP_TRAILER_SIZE;

  *output_out = output;
  *output_len_out = output_len;
  return 0;
}

static SocketGRPC_StatusCode
grpc_gzip_decompress_payload (SocketGRPC_Call_T call,
                              SocketDeflate_Inflater_T inflater,
                              const uint8_t *input,
                              size_t input_len,
                              unsigned char **output_out,
                              size_t *output_len_out,
                              const char **message_out)
{
  SocketDeflate_GzipHeader header;
  SocketDeflate_Result res;
  const uint8_t *deflate_input;
  size_t deflate_input_len;
  const uint8_t *trailer;
  unsigned char *output = NULL;
  size_t output_cap;
  size_t output_len = 0;
  size_t consumed = 0;
  size_t written = 0;
  size_t max_output;
  size_t total_in;
  size_t total_out;
  uint32_t crc;

  if (output_out == NULL || output_len_out == NULL || message_out == NULL
      || call == NULL || call->channel == NULL || inflater == NULL
      || (input == NULL && input_len != 0))
    {
      return SOCKET_GRPC_STATUS_INTERNAL;
    }

  *output_out = NULL;
  *output_len_out = 0;
  *message_out = "Malformed compressed gRPC response frame";

  res = SocketDeflate_gzip_parse_header (input, input_len, &header);
  if (res != DEFLATE_OK)
    return SOCKET_GRPC_STATUS_INTERNAL;
  if (header.header_size > input_len
      || input_len - header.header_size < GZIP_TRAILER_SIZE)
    return SOCKET_GRPC_STATUS_INTERNAL;

  deflate_input = input + header.header_size;
  deflate_input_len = input_len - header.header_size - GZIP_TRAILER_SIZE;
  trailer = input + input_len - GZIP_TRAILER_SIZE;

  max_output = call->channel->config.max_decompressed_message_bytes;
  if (max_output == 0)
    max_output = call->channel->config.max_inbound_message_bytes;
  if (max_output == 0)
    return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;

  output_cap = max_output;
  if (output_cap == 0)
    output_cap = 1U;
  output = (unsigned char *)malloc (output_cap);
  if (output == NULL)
    return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;

  SocketDeflate_Inflater_reset (inflater);

  res = SocketDeflate_Inflater_inflate (inflater,
                                        deflate_input,
                                        deflate_input_len,
                                        &consumed,
                                        output,
                                        output_cap,
                                        &written);
  output_len = written;
  if (res == DEFLATE_ERROR_BOMB || res == DEFLATE_OUTPUT_FULL
      || (res == DEFLATE_INCOMPLETE && output_len >= max_output))
    {
      free (output);
      *message_out = "Compressed response exceeds decompression limits";
      return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
    }
  if (res != DEFLATE_OK || consumed != deflate_input_len)
    {
      free (output);
      return SOCKET_GRPC_STATUS_INTERNAL;
    }

  crc = SocketDeflate_crc32 (0, output, output_len);
  if (SocketDeflate_gzip_verify_trailer (trailer, crc, (uint32_t)output_len)
      != DEFLATE_OK)
    {
      free (output);
      return SOCKET_GRPC_STATUS_INTERNAL;
    }

  if (call->channel->config.max_decompression_ratio > 0.0)
    {
      total_in = SocketDeflate_Inflater_total_in (inflater);
      total_out = SocketDeflate_Inflater_total_out (inflater);
      if ((total_in == 0 && total_out > 0)
          || (total_in > 0
              && ((double)total_out / (double)total_in)
                     > call->channel->config.max_decompression_ratio))
        {
          free (output);
          *message_out = "Compressed response exceeded decompression ratio";
          return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
        }
    }

  *output_out = output;
  *output_len_out = output_len;
  return SOCKET_GRPC_STATUS_OK;
}

static SocketGRPC_StatusCode
grpc_decode_frame_payload (SocketGRPC_Call_T call,
                           SocketGRPC_Compression response_compression,
                           SocketDeflate_Inflater_T inflater,
                           Arena_T arena,
                           const SocketGRPC_FrameView *frame,
                           uint8_t **payload_out,
                           size_t *payload_len_out,
                           const char **message_out)
{
  if (call == NULL || call->channel == NULL || arena == NULL || frame == NULL
      || payload_out == NULL || payload_len_out == NULL || message_out == NULL)
    return SOCKET_GRPC_STATUS_INTERNAL;

  *payload_out = NULL;
  *payload_len_out = 0;
  *message_out = "Malformed gRPC response frame";

  if (frame->compressed == 0)
    {
      if (frame->payload_len > call->channel->config.max_inbound_message_bytes)
        {
          *message_out = "Response message exceeds configured limit";
          return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
        }
      if (frame->payload_len > 0)
        {
          uint8_t *copy = (uint8_t *)ALLOC (arena, frame->payload_len);
          if (copy == NULL)
            return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
          memcpy (copy, frame->payload, frame->payload_len);
          *payload_out = copy;
          *payload_len_out = frame->payload_len;
        }
      return SOCKET_GRPC_STATUS_OK;
    }

  if (!call->channel->config.enable_response_decompression)
    {
      *message_out = "Response decompression is disabled";
      return SOCKET_GRPC_STATUS_INTERNAL;
    }
  if (response_compression != GRPC_COMPRESSION_GZIP)
    {
      *message_out = "Unsupported response compression encoding";
      return SOCKET_GRPC_STATUS_INTERNAL;
    }
  if (inflater == NULL)
    {
      *message_out = "Response inflater unavailable";
      return SOCKET_GRPC_STATUS_INTERNAL;
    }

  {
    unsigned char *decoded = NULL;
    size_t decoded_len = 0;
    SocketGRPC_StatusCode decode_status
        = grpc_gzip_decompress_payload (call,
                                        inflater,
                                        frame->payload,
                                        frame->payload_len,
                                        &decoded,
                                        &decoded_len,
                                        message_out);
    if (decode_status != SOCKET_GRPC_STATUS_OK)
      return decode_status;
    if (decoded_len > 0)
      {
        uint8_t *copy = (uint8_t *)ALLOC (arena, decoded_len);
        if (copy == NULL)
          {
            free (decoded);
            return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
          }
        memcpy (copy, decoded, decoded_len);
        *payload_out = copy;
        *payload_len_out = decoded_len;
      }
    free (decoded);
  }

  return SOCKET_GRPC_STATUS_OK;
}

static char *
grpc_build_call_url (SocketGRPC_Call_T call, Arena_T arena)
{
  const char *target = call->channel->target;
  const char *path = call->full_method;
  const char *base = NULL;
  const char *scheme = NULL;
  size_t base_len;
  size_t path_len;
  size_t trim_len;
  size_t add_slash;
  char *url;

  if (target == NULL || path == NULL)
    return NULL;

  if (str_has_prefix (target, "http://") || str_has_prefix (target, "https://"))
    {
      base = target;
    }
  else if (str_has_prefix (target, "dns:///"))
    {
      base = target + strlen ("dns:///");
      if (base[0] == '\0')
        return NULL;
      scheme = call->channel->config.allow_http2_cleartext ? "http://"
                                                           : "https://";
    }
  else
    {
      base = target;
      scheme = call->channel->config.allow_http2_cleartext ? "http://"
                                                           : "https://";
    }

  base_len = strlen (base);
  trim_len = base_len;
  while (trim_len > 0 && base[trim_len - 1U] == '/')
    trim_len--;

  path_len = strlen (path);
  add_slash = (path_len > 0 && path[0] == '/') ? 0U : 1U;

  if (scheme != NULL)
    {
      size_t scheme_len = strlen (scheme);
      url = (char *)ALLOC (arena,
                           scheme_len + trim_len + add_slash + path_len + 1U);
      if (url == NULL)
        return NULL;
      memcpy (url, scheme, scheme_len);
      memcpy (url + scheme_len, base, trim_len);
      if (add_slash)
        url[scheme_len + trim_len] = '/';
      memcpy (url + scheme_len + trim_len + add_slash, path, path_len);
      url[scheme_len + trim_len + add_slash + path_len] = '\0';
      return url;
    }

  url = (char *)ALLOC (arena, trim_len + add_slash + path_len + 1U);
  if (url == NULL)
    return NULL;
  memcpy (url, base, trim_len);
  if (add_slash)
    url[trim_len] = '/';
  memcpy (url + trim_len + add_slash, path, path_len);
  url[trim_len + add_slash + path_len] = '\0';
  return url;
}

static int
grpc_request_add_metadata (SocketGRPC_Call_T call,
                           SocketHTTPClient_Request_T req,
                           SocketGRPC_Metadata_T metadata)
{
  size_t i;
  size_t count;

  if (call == NULL || call->channel == NULL || req == NULL || metadata == NULL)
    return 0;

  count = SocketGRPC_Metadata_count (metadata);
  if (count > call->channel->config.max_metadata_entries)
    return -1;

  for (i = 0; i < count; i++)
    {
      const SocketGRPC_MetadataEntry *entry
          = SocketGRPC_Metadata_at (metadata, i);
      if (entry == NULL || entry->key == NULL)
        continue;

      if (entry->is_binary)
        {
          size_t encoded_cap
              = SocketCrypto_base64_encoded_size (entry->value_len);
          char *encoded = (char *)malloc (encoded_cap);
          ssize_t encoded_len;
          if (encoded == NULL)
            return -1;
          encoded_len = SocketCrypto_base64_encode (
              entry->value, entry->value_len, encoded, encoded_cap);
          if (encoded_len < 0)
            {
              free (encoded);
              return -1;
            }
          if (SocketHTTPClient_Request_header (req, entry->key, encoded) != 0)
            {
              free (encoded);
              return -1;
            }
          free (encoded);
        }
      else
        {
          char *value = (char *)malloc (entry->value_len + 1U);
          if (value == NULL)
            return -1;
          if (entry->value_len > 0)
            memcpy (value, entry->value, entry->value_len);
          value[entry->value_len] = '\0';
          if (SocketHTTPClient_Request_header (req, entry->key, value) != 0)
            {
              free (value);
              return -1;
            }
          free (value);
        }
    }
  return 0;
}

static int
grpc_request_add_required_headers (SocketGRPC_Call_T call,
                                   SocketHTTPClient_Request_T req)
{
  char timeout_buf[GRPC_TIMEOUT_HEADER_MAX];
  char attempt_buf[16];

  if (SocketHTTPClient_Request_header (req, "content-type", GRPC_CONTENT_TYPE)
      != 0)
    return -1;
  if (SocketHTTPClient_Request_header (req, "te", "trailers") != 0)
    return -1;
  if (SocketHTTPClient_Request_header (
          req, "grpc-accept-encoding", GRPC_ACCEPT_ENCODING_VALUE)
      != 0)
    return -1;
  if (call->channel != NULL && call->channel->config.enable_request_compression
      && SocketHTTPClient_Request_header (
             req, "grpc-encoding", GRPC_ENCODING_GZIP)
             != 0)
    return -1;
  if (call->channel->user_agent != NULL
      && SocketHTTPClient_Request_header (
             req, "user-agent", call->channel->user_agent)
             != 0)
    return -1;
  if (call->channel->authority_override != NULL
      && SocketHTTPClient_Request_header (
             req, "host", call->channel->authority_override)
             != 0)
    return -1;

  if (call->config.deadline_ms > 0)
    {
      if (SocketGRPC_Timeout_format ((int64_t)call->config.deadline_ms,
                                     timeout_buf,
                                     sizeof (timeout_buf))
          != 0)
        return -1;
      if (SocketHTTPClient_Request_header (req, "grpc-timeout", timeout_buf)
          != 0)
        return -1;
    }

  if (call->retry_attempt > 0)
    {
      int n = snprintf (
          attempt_buf, sizeof (attempt_buf), "%u", call->retry_attempt);
      if (n <= 0 || (size_t)n >= sizeof (attempt_buf))
        return -1;
      if (SocketHTTPClient_Request_header (
              req, "grpc-previous-rpc-attempts", attempt_buf)
          != 0)
        return -1;
    }

  return grpc_request_add_metadata (call, req, call->request_metadata);
}

static int
grpc_decode_base64 (const char *value,
                    size_t value_len,
                    uint8_t **decoded_out,
                    size_t *decoded_len_out)
{
  size_t decoded_cap;
  uint8_t *decoded;
  ssize_t decoded_len;

  if (value == NULL || decoded_out == NULL || decoded_len_out == NULL)
    return -1;

  decoded_cap = SocketCrypto_base64_decoded_size (value_len);
  decoded = (uint8_t *)malloc (decoded_cap > 0 ? decoded_cap : 1U);
  if (decoded == NULL)
    return -1;

  decoded_len = SocketCrypto_base64_decode (
      value, value_len, decoded, decoded_cap > 0 ? decoded_cap : 1U);
  if (decoded_len < 0)
    {
      free (decoded);
      return -1;
    }

  *decoded_out = decoded;
  *decoded_len_out = (size_t)decoded_len;
  return 0;
}

static int
grpc_trailer_ingest_kv (SocketGRPC_Call_T call,
                        const char *name,
                        size_t name_len,
                        const char *value,
                        size_t value_len)
{
  SocketGRPC_Trailers_T trailers;
  char *lower_name;
  size_t i;

  if (call == NULL || call->response_trailers == NULL || name == NULL
      || value == NULL)
    return -1;
  trailers = call->response_trailers;

  lower_name = (char *)malloc (name_len + 1U);
  if (lower_name == NULL)
    return -1;
  for (i = 0; i < name_len; i++)
    lower_name[i] = (char)tolower ((unsigned char)name[i]);
  lower_name[name_len] = '\0';

  if (strcmp (lower_name, "grpc-status") == 0)
    {
      int status = 0;
      for (i = 0; i < value_len; i++)
        {
          if (!isdigit ((unsigned char)value[i]))
            {
              free (lower_name);
              return -1;
            }
          status = status * 10 + (int)(value[i] - '0');
        }
      free (lower_name);
      return SocketGRPC_Trailers_set_status (trailers, status)
                     == SOCKET_GRPC_WIRE_OK
                 ? 0
                 : -1;
    }
  if (strcmp (lower_name, "grpc-message") == 0)
    {
      char *message = (char *)malloc (value_len + 1U);
      int rc;
      if (message == NULL)
        {
          free (lower_name);
          return -1;
        }
      memcpy (message, value, value_len);
      message[value_len] = '\0';
      rc = (SocketGRPC_Trailers_set_message (trailers, message)
            == SOCKET_GRPC_WIRE_OK)
               ? 0
               : -1;
      free (message);
      free (lower_name);
      return rc;
    }
  if (strcmp (lower_name, "grpc-status-details-bin") == 0)
    {
      uint8_t *decoded = NULL;
      size_t decoded_len = 0;
      int ok = grpc_decode_base64 (value, value_len, &decoded, &decoded_len);
      int rc;
      if (ok != 0)
        {
          free (lower_name);
          return -1;
        }
      rc = (SocketGRPC_Trailers_set_status_details_bin (
                trailers, decoded, decoded_len)
            == SOCKET_GRPC_WIRE_OK)
               ? 0
               : -1;
      free (decoded);
      free (lower_name);
      return rc;
    }

  if (name_len >= 4 && strcmp (lower_name + (name_len - 4), "-bin") == 0)
    {
      uint8_t *decoded = NULL;
      size_t decoded_len = 0;
      int rc;
      if (!grpc_has_metadata_slot (call))
        {
          free (lower_name);
          return -1;
        }
      if (grpc_decode_base64 (value, value_len, &decoded, &decoded_len) != 0)
        {
          free (lower_name);
          return -1;
        }
      rc = (SocketGRPC_Metadata_add_binary (
                SocketGRPC_Trailers_metadata (trailers),
                lower_name,
                decoded,
                decoded_len)
            == SOCKET_GRPC_WIRE_OK)
               ? 0
               : -1;
      free (decoded);
      free (lower_name);
      return rc;
    }
  else
    {
      char *ascii = (char *)malloc (value_len + 1U);
      int rc;
      if (!grpc_has_metadata_slot (call))
        {
          free (lower_name);
          return -1;
        }
      if (ascii == NULL)
        {
          free (lower_name);
          return -1;
        }
      memcpy (ascii, value, value_len);
      ascii[value_len] = '\0';
      rc = (SocketGRPC_Metadata_add_ascii (
                SocketGRPC_Trailers_metadata (trailers), lower_name, ascii)
            == SOCKET_GRPC_WIRE_OK)
               ? 0
               : -1;
      free (ascii);
      free (lower_name);
      return rc;
    }
}

static int
grpc_ingest_response_headers (SocketGRPC_Call_T call,
                              SocketHTTP_Headers_T headers,
                              int allow_reserved)
{
  size_t i;
  for (i = 0; i < SocketHTTP_Headers_count (headers); i++)
    {
      const SocketHTTP_Header *h = SocketHTTP_Headers_at (headers, i);
      if (h == NULL || h->name == NULL || h->value == NULL)
        continue;
      if (h->name_len > 0 && h->name[0] == ':')
        continue;
      if (!allow_reserved
          && (strncasecmp (h->name, "grpc-status", h->name_len) == 0
              || strncasecmp (h->name, "grpc-message", h->name_len) == 0
              || strncasecmp (h->name, "grpc-status-details-bin", h->name_len)
                     == 0))
        continue;

      if (grpc_trailer_ingest_kv (
              call, h->name, h->name_len, h->value, h->value_len)
          != 0)
        return -1;
    }
  return 0;
}

static int
grpc_ingest_stream_trailers (SocketGRPC_Call_T call,
                             const SocketHPACK_Header *trailers,
                             size_t trailer_count)
{
  size_t i;
  for (i = 0; i < trailer_count; i++)
    {
      if (trailers[i].name == NULL || trailers[i].value == NULL)
        continue;
      if (trailers[i].name_len > 0 && trailers[i].name[0] == ':')
        continue;
      if (grpc_trailer_ingest_kv (call,
                                  trailers[i].name,
                                  trailers[i].name_len,
                                  trailers[i].value,
                                  trailers[i].value_len)
          != 0)
        return -1;
    }
  return 0;
}

static int
grpc_receive_body_and_trailers (SocketGRPC_Call_T call,
                                SocketHTTP2_Stream_T stream,
                                SocketHTTP2_Conn_T conn,
                                unsigned char **body_out,
                                size_t *body_len_out,
                                SocketGRPC_StatusCode *error_status,
                                const char **error_message)
{
  unsigned char *body = NULL;
  size_t total = 0;
  size_t cap = 0;

  if (body_out == NULL || body_len_out == NULL || error_status == NULL
      || error_message == NULL)
    return -1;

  *error_status = SOCKET_GRPC_STATUS_UNAVAILABLE;
  *error_message = "Failed to receive response body";

  for (;;)
    {
      unsigned char chunk[GRPC_RESPONSE_CHUNK];
      int end_stream = 0;
      ssize_t n = grpc_h2_stream_recv_data_safe (
          stream, chunk, sizeof (chunk), &end_stream);
      if (n < 0)
        {
          free (body);
          *error_status = SOCKET_GRPC_STATUS_UNAVAILABLE;
          *error_message = "Failed to receive response body";
          return -1;
        }

      if (n > 0)
        {
          size_t needed = total + (size_t)n;
          if (needed > call->channel->config.max_cumulative_inflight_bytes)
            {
              free (body);
              *error_status = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
              *error_message = "Response exceeds configured inflight limit";
              return -1;
            }
          if (needed > cap)
            {
              size_t new_cap = cap == 0 ? GRPC_RESPONSE_CHUNK : cap * 2U;
              unsigned char *tmp;
              while (new_cap < needed)
                new_cap *= 2U;
              tmp = (unsigned char *)realloc (body, new_cap);
              if (tmp == NULL)
                {
                  free (body);
                  *error_status = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
                  *error_message = "Out of memory receiving response body";
                  return -1;
                }
              body = tmp;
              cap = new_cap;
            }
          memcpy (body + total, chunk, (size_t)n);
          total += (size_t)n;
        }

      {
        SocketHPACK_Header trailers[SOCKETHTTP2_MAX_DECODED_HEADERS];
        size_t trailer_count = 0;
        int tr = grpc_h2_stream_recv_trailers_safe (
            stream, trailers, SOCKETHTTP2_MAX_DECODED_HEADERS, &trailer_count);
        if (tr < 0)
          {
            free (body);
            *error_status = SOCKET_GRPC_STATUS_UNAVAILABLE;
            *error_message = "Failed to receive response trailers";
            return -1;
          }
        if (tr == 1 && trailer_count > 0)
          {
            if (grpc_ingest_stream_trailers (call, trailers, trailer_count)
                != 0)
              {
                free (body);
                *error_status = SOCKET_GRPC_STATUS_INTERNAL;
                *error_message = "Invalid response trailers";
                return -1;
              }
          }
      }

      if (end_stream)
        break;

      if (n == 0 && grpc_h2_conn_process_safe (conn, 0) < 0)
        {
          free (body);
          *error_status = SOCKET_GRPC_STATUS_UNAVAILABLE;
          *error_message = "Failed to advance response stream";
          return -1;
        }
    }

  *body_out = body;
  *body_len_out = total;
  return 0;
}

static char *
grpc_build_call_url_heap (SocketGRPC_Call_T call)
{
  const char *target;
  const char *path;
  const char *base = NULL;
  const char *scheme = NULL;
  size_t base_len;
  size_t trim_len;
  size_t path_len;
  size_t add_slash;
  size_t total;
  size_t offset = 0;
  char *url;

  if (call == NULL || call->channel == NULL || call->channel->target == NULL
      || call->full_method == NULL)
    return NULL;

  target = call->channel->target;
  path = call->full_method;

  if (str_has_prefix (target, "http://") || str_has_prefix (target, "https://"))
    {
      base = target;
    }
  else if (str_has_prefix (target, "dns:///"))
    {
      base = target + strlen ("dns:///");
      if (base[0] == '\0')
        return NULL;
      scheme = call->channel->config.allow_http2_cleartext ? "http://"
                                                           : "https://";
    }
  else
    {
      base = target;
      scheme = call->channel->config.allow_http2_cleartext ? "http://"
                                                           : "https://";
    }

  base_len = strlen (base);
  trim_len = base_len;
  while (trim_len > 0 && base[trim_len - 1U] == '/')
    trim_len--;

  path_len = strlen (path);
  add_slash = (path_len > 0 && path[0] == '/') ? 0U : 1U;
  total = (scheme != NULL ? strlen (scheme) : 0U) + trim_len + add_slash
          + path_len + 1U;

  url = (char *)malloc (total);
  if (url == NULL)
    return NULL;

  if (scheme != NULL)
    {
      size_t scheme_len = strlen (scheme);
      memcpy (url + offset, scheme, scheme_len);
      offset += scheme_len;
    }
  memcpy (url + offset, base, trim_len);
  offset += trim_len;
  if (add_slash)
    url[offset++] = '/';
  memcpy (url + offset, path, path_len);
  offset += path_len;
  url[offset] = '\0';
  return url;
}

static void
grpc_stream_context_cleanup (SocketGRPC_Call_T call,
                             int success,
                             int cancel_stream)
{
  SocketGRPC_H2CallStream *ctx;

  if (call == NULL)
    return;

  ctx = (SocketGRPC_H2CallStream *)call->h2_stream_ctx;
  if (ctx == NULL)
    return;

  if (ctx->conn != NULL && ctx->stream != NULL && ctx->active_stream_counted)
    {
      if (ctx->conn->proto.h2.active_streams > 0)
        ctx->conn->proto.h2.active_streams--;
      ctx->active_stream_counted = 0;
    }

  if (cancel_stream && ctx->stream != NULL)
    grpc_h2_stream_cancel_safe (ctx->stream);

  if (ctx->conn != NULL)
    grpc_release_connection_safe (ctx->http_client, ctx->conn, success);

  free (ctx->recv_buffer);
  ctx->recv_buffer = NULL;
  ctx->recv_cap = 0;
  ctx->recv_len = 0;
  if (ctx->compression_arena != NULL)
    Arena_dispose (&ctx->compression_arena);
  ctx->request_deflater = NULL;
  ctx->response_inflater = NULL;

  SocketHTTPClient_Response_free (&ctx->response);
  SocketHTTPClient_Request_free (&ctx->request);
  SocketHTTPClient_free (&ctx->http_client);

  free (ctx);
  call->h2_stream_ctx = NULL;
  call->h2_stream_state
      = success ? GRPC_CALL_STREAM_CLOSED : GRPC_CALL_STREAM_FAILED;
}

void
SocketGRPC_Call_h2_stream_abort (SocketGRPC_Call_T call)
{
  if (call == NULL)
    return;
  grpc_stream_context_cleanup (call, 0, 1);
}

static int
grpc_stream_fail (SocketGRPC_Call_T call,
                  SocketGRPC_StatusCode status,
                  const char *message,
                  int cancel_stream)
{
  if (call == NULL)
    return -1;

  if (call->response_trailers != NULL
      && !SocketGRPC_Trailers_has_status (call->response_trailers))
    {
      (void)SocketGRPC_Trailers_set_status (call->response_trailers, status);
    }
  if (call->response_trailers != NULL && message != NULL && message[0] != '\0'
      && SocketGRPC_Trailers_message (call->response_trailers) == NULL)
    {
      (void)SocketGRPC_Trailers_set_message (call->response_trailers, message);
    }

  grpc_call_status_set (call, status, message);
  grpc_stream_context_cleanup (call, 0, cancel_stream);
  return -1;
}

static int
grpc_run_client_stream_interceptors (SocketGRPC_Call_T call,
                                     SocketGRPC_StreamInterceptEvent event,
                                     const uint8_t *payload,
                                     size_t payload_len)
{
  SocketGRPC_ClientStreamInterceptorEntry *entry;

  if (call == NULL)
    return -1;

  entry = call->stream_interceptors;
  while (entry != NULL)
    {
      SocketGRPC_Status status
          = { SOCKET_GRPC_STATUS_OK,
              SocketGRPC_status_default_message (SOCKET_GRPC_STATUS_OK) };
      int action = entry->interceptor (
          call, event, payload, payload_len, &status, entry->userdata);

      if (action == SOCKET_GRPC_INTERCEPT_CONTINUE)
        {
          entry = entry->next;
          continue;
        }

      if (action != SOCKET_GRPC_INTERCEPT_STOP)
        {
          status.code = SOCKET_GRPC_STATUS_INTERNAL;
          status.message = "Interceptor returned invalid action";
        }

      if (call->h2_stream_ctx != NULL)
        {
          SocketGRPC_StatusCode code = status.code;
          const char *message = status.message;
          if (!grpc_status_code_valid (code) || code == SOCKET_GRPC_STATUS_OK)
            {
              code = SOCKET_GRPC_STATUS_INTERNAL;
              message = "Interceptor returned invalid status";
            }
          return grpc_stream_fail (call, code, message, 1);
        }

      return grpc_apply_interceptor_stop (call, status, 1);
    }

  return 0;
}

static void
grpc_stream_finalize_status (SocketGRPC_Call_T call, int http_status_code)
{
  SocketGRPC_StatusCode status_code;

  if (call == NULL || call->response_trailers == NULL)
    return;

  if (!SocketGRPC_Trailers_has_status (call->response_trailers))
    {
      status_code = SocketGRPC_http_status_to_grpc (http_status_code);
      (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                            status_code);
    }

  status_code = (SocketGRPC_StatusCode)SocketGRPC_Trailers_status (
      call->response_trailers);
  grpc_call_status_set (
      call, status_code, SocketGRPC_Trailers_message (call->response_trailers));
}

static SocketGRPC_H2CallStream *
grpc_stream_open_if_needed (SocketGRPC_Call_T call)
{
  SocketGRPC_H2CallStream *ctx;
  SocketHTTPClient_Config cfg;
  SocketHTTP_Request http_req;
  char *url = NULL;

  if (call == NULL || call->channel == NULL)
    return NULL;

  ctx = (SocketGRPC_H2CallStream *)call->h2_stream_ctx;
  if (ctx != NULL)
    return ctx;

  ctx = (SocketGRPC_H2CallStream *)calloc (1, sizeof (*ctx));
  if (ctx == NULL)
    return NULL;
  if (grpc_stream_context_init_compression (call, ctx) != 0)
    goto fail;

  SocketHTTPClient_config_defaults (&cfg);
  cfg.max_version = HTTP_VERSION_2;
  cfg.allow_http2_cleartext = call->channel->config.allow_http2_cleartext;
  cfg.verify_ssl = call->channel->config.verify_peer;
  cfg.tls_context = call->channel->config.tls_context;
  cfg.request_timeout_ms = call->config.deadline_ms;
  cfg.max_response_size = call->channel->config.max_cumulative_inflight_bytes;

  ctx->http_client = SocketHTTPClient_new (&cfg);
  if (ctx->http_client == NULL)
    goto fail;

  url = grpc_build_call_url_heap (call);
  if (url == NULL)
    goto fail;

  ctx->request
      = SocketHTTPClient_Request_new (ctx->http_client, HTTP_METHOD_POST, url);
  free (url);
  url = NULL;
  if (ctx->request == NULL)
    goto fail;

  SocketHTTPClient_Request_timeout (ctx->request, call->config.deadline_ms);
  if (grpc_request_add_required_headers (call, ctx->request) != 0)
    goto fail;

  ctx->conn = httpclient_connect (ctx->http_client, &ctx->request->uri);
  if (ctx->conn == NULL)
    goto fail;

  httpclient_headers_prepare_request (ctx->http_client, ctx->request);
  if (ctx->conn->version != HTTP_VERSION_2 || ctx->conn->proto.h2.conn == NULL)
    goto fail;

  ctx->h2conn = ctx->conn->proto.h2.conn;
  ctx->stream = SocketHTTP2_Stream_new (ctx->h2conn);
  if (ctx->stream == NULL)
    goto fail;

  ctx->conn->proto.h2.active_streams++;
  ctx->active_stream_counted = 1;

  httpclient_http2_build_request (ctx->request, &http_req);
  if (grpc_h2_stream_send_request_safe (ctx->stream, &http_req, 0) != 0)
    goto fail;
  if (grpc_h2_conn_flush_safe (ctx->h2conn) != 0)
    goto fail;

  SocketGRPC_Trailers_clear (call->response_trailers);
  grpc_call_status_set (call, SOCKET_GRPC_STATUS_OK, NULL);

  ctx->http_status_code = HTTP_STATUS_OK;
  ctx->deadline_ms = SocketTimeout_deadline_ms (call->config.deadline_ms);
  call->h2_stream_ctx = ctx;
  call->h2_stream_state = GRPC_CALL_STREAM_OPEN;
  return ctx;

fail:
  if (url != NULL)
    free (url);
  if (ctx != NULL)
    {
      if (ctx->conn != NULL && ctx->stream != NULL
          && ctx->active_stream_counted)
        {
          if (ctx->conn->proto.h2.active_streams > 0)
            ctx->conn->proto.h2.active_streams--;
          ctx->active_stream_counted = 0;
        }
      if (ctx->stream != NULL)
        grpc_h2_stream_cancel_safe (ctx->stream);
      if (ctx->conn != NULL)
        grpc_release_connection_safe (ctx->http_client, ctx->conn, 0);
      SocketHTTPClient_Response_free (&ctx->response);
      SocketHTTPClient_Request_free (&ctx->request);
      SocketHTTPClient_free (&ctx->http_client);
      free (ctx->recv_buffer);
      if (ctx->compression_arena != NULL)
        Arena_dispose (&ctx->compression_arena);
      free (ctx);
    }
  return NULL;
}

static int
grpc_stream_send_frame (SocketGRPC_Call_T call,
                        SocketGRPC_H2CallStream *ctx,
                        const unsigned char *frame,
                        size_t frame_len,
                        int close_send)
{
  size_t offset = 0;
  int idle_spins = 0;

  if (call == NULL || ctx == NULL || frame == NULL)
    return -1;

  while (offset < frame_len)
    {
      if (SocketTimeout_expired (ctx->deadline_ms))
        {
          return grpc_stream_fail (call,
                                   SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
                                   "Deadline exceeded",
                                   1);
        }

      if (grpc_h2_conn_flush_safe (ctx->h2conn) != 0)
        {
          return grpc_stream_fail (call,
                                   SOCKET_GRPC_STATUS_UNAVAILABLE,
                                   "Failed to flush stream send",
                                   1);
        }

      ssize_t n = grpc_h2_stream_send_data_safe (
          ctx->stream, frame + offset, frame_len - offset, close_send);
      if (n < 0)
        {
          return grpc_stream_fail (call,
                                   SOCKET_GRPC_STATUS_UNAVAILABLE,
                                   "Failed to send stream frame",
                                   1);
        }
      if (n == 0)
        {
          if (SocketTimeout_expired (ctx->deadline_ms))
            {
              return grpc_stream_fail (call,
                                       SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
                                       "Deadline exceeded",
                                       1);
            }
          if (grpc_h2_conn_process_safe (ctx->h2conn, 0) < 0
              || ++idle_spins > 2048)
            {
              return grpc_stream_fail (call,
                                       SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
                                       "Stream send stalled under flow control",
                                       1);
            }
          continue;
        }

      idle_spins = 0;
      offset += (size_t)n;
    }

  if (grpc_h2_conn_flush_safe (ctx->h2conn) != 0)
    {
      return grpc_stream_fail (call,
                               SOCKET_GRPC_STATUS_UNAVAILABLE,
                               "Failed to flush stream send",
                               1);
    }

  if (close_send)
    {
      call->h2_stream_state
          = (call->h2_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_REMOTE)
                ? GRPC_CALL_STREAM_CLOSED
                : GRPC_CALL_STREAM_HALF_CLOSED_LOCAL;
    }

  return 0;
}

static int
grpc_stream_append_recv (SocketGRPC_Call_T call,
                         SocketGRPC_H2CallStream *ctx,
                         const unsigned char *chunk,
                         size_t chunk_len)
{
  size_t max_buffer;
  size_t needed;

  if (call == NULL || ctx == NULL || (chunk == NULL && chunk_len != 0))
    return -1;
  if (chunk_len == 0)
    return 0;

  max_buffer = call->channel->config.max_cumulative_inflight_bytes;
  if (max_buffer < SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE)
    max_buffer = SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE;
  needed = ctx->recv_len + chunk_len;
  if (needed > max_buffer)
    return -1;

  if (needed > ctx->recv_cap)
    {
      size_t new_cap = ctx->recv_cap == 0 ? GRPC_STREAM_RECV_BUFFER_INITIAL
                                          : ctx->recv_cap;
      unsigned char *tmp;
      while (new_cap < needed)
        new_cap *= 2U;
      tmp = (unsigned char *)realloc (ctx->recv_buffer, new_cap);
      if (tmp == NULL)
        return -1;
      ctx->recv_buffer = tmp;
      ctx->recv_cap = new_cap;
    }

  memcpy (ctx->recv_buffer + ctx->recv_len, chunk, chunk_len);
  ctx->recv_len += chunk_len;
  return 0;
}

static int
grpc_stream_try_parse_message (SocketGRPC_Call_T call,
                               SocketGRPC_H2CallStream *ctx,
                               Arena_T arena,
                               uint8_t **response_payload,
                               size_t *response_payload_len,
                               SocketGRPC_StatusCode *error_status,
                               const char **error_message,
                               int *has_message)
{
  SocketGRPC_FrameView frame;
  size_t consumed = 0;
  size_t max_frame_payload;
  SocketGRPC_WireResult rc;
  SocketGRPC_StatusCode decode_status;
  const char *decode_message = "Malformed streaming response frame";

  if (call == NULL || ctx == NULL || arena == NULL || response_payload == NULL
      || response_payload_len == NULL || has_message == NULL
      || error_status == NULL || error_message == NULL)
    return -1;

  *error_status = SOCKET_GRPC_STATUS_INTERNAL;
  *error_message = "Malformed streaming response frame";
  *has_message = 0;
  if (ctx->recv_len == 0)
    return 0;

  max_frame_payload = call->channel->config.max_cumulative_inflight_bytes;
  if (max_frame_payload == 0)
    max_frame_payload = call->channel->config.max_inbound_message_bytes;

  rc = SocketGRPC_Frame_parse (
      ctx->recv_buffer, ctx->recv_len, max_frame_payload, &frame, &consumed);
  if (rc == SOCKET_GRPC_WIRE_INCOMPLETE)
    return 0;
  if (rc != SOCKET_GRPC_WIRE_OK)
    {
      if (rc == SOCKET_GRPC_WIRE_LENGTH_EXCEEDED)
        {
          *error_status = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
          *error_message
              = "Streaming response exceeds configured inflight limit";
        }
      return -1;
    }

  decode_status = grpc_decode_frame_payload (call,
                                             ctx->response_compression,
                                             ctx->response_inflater,
                                             arena,
                                             &frame,
                                             response_payload,
                                             response_payload_len,
                                             &decode_message);
  if (decode_status != SOCKET_GRPC_STATUS_OK)
    {
      *error_status = decode_status;
      *error_message = decode_message;
      return -1;
    }

  if (consumed < ctx->recv_len)
    {
      memmove (ctx->recv_buffer,
               ctx->recv_buffer + consumed,
               ctx->recv_len - consumed);
    }
  ctx->recv_len -= consumed;
  *has_message = 1;
  return 0;
}

int
SocketGRPC_Call_send_message (SocketGRPC_Call_T call,
                              const uint8_t *request_payload,
                              size_t request_payload_len)
{
  SocketGRPC_H2CallStream *ctx;
  unsigned char *framed;
  unsigned char *compressed_payload = NULL;
  const uint8_t *wire_payload = request_payload;
  size_t wire_payload_len = request_payload_len;
  size_t framed_len = 0;
  size_t framed_cap;
  int compressed_flag = 0;
  int rc;

  if (call == NULL || (request_payload == NULL && request_payload_len != 0))
    return -1;
  if (call->h2_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_LOCAL
      || call->h2_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_REMOTE
      || call->h2_stream_state == GRPC_CALL_STREAM_FAILED)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_FAILED_PRECONDITION,
                            "Send direction already closed");
      return -1;
    }
  if (request_payload_len > call->channel->config.max_outbound_message_bytes
      || request_payload_len > (size_t)UINT32_MAX)
    {
      grpc_call_status_set (call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL);
      return -1;
    }
  if (grpc_run_client_stream_interceptors (call,
                                           SOCKET_GRPC_STREAM_INTERCEPT_SEND,
                                           request_payload,
                                           request_payload_len)
      != 0)
    {
      return -1;
    }

  ctx = grpc_stream_open_if_needed (call);
  if (ctx == NULL)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to initialize stream");
      return -1;
    }

  if (ctx->request_compression == GRPC_COMPRESSION_GZIP)
    {
      if (ctx->request_deflater == NULL
          || grpc_gzip_compress_payload (ctx->request_deflater,
                                         request_payload,
                                         request_payload_len,
                                         &compressed_payload,
                                         &wire_payload_len)
                 != 0)
        {
          return grpc_stream_fail (call,
                                   SOCKET_GRPC_STATUS_INTERNAL,
                                   "Failed to compress streaming request",
                                   1);
        }
      wire_payload = compressed_payload;
      compressed_flag = 1;
    }

  if (wire_payload_len > (size_t)UINT32_MAX
      || wire_payload_len > (SIZE_MAX - SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE))
    {
      free (compressed_payload);
      return grpc_stream_fail (
          call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL, 1);
    }

  framed_cap = SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE + wire_payload_len;
  framed = (unsigned char *)malloc (framed_cap);
  if (framed == NULL)
    {
      free (compressed_payload);
      return grpc_stream_fail (call,
                               SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED,
                               "Out of memory framing message",
                               1);
    }

  if (SocketGRPC_Frame_encode (compressed_flag,
                               wire_payload,
                               (uint32_t)wire_payload_len,
                               framed,
                               framed_cap,
                               &framed_len)
      != SOCKET_GRPC_WIRE_OK)
    {
      free (framed);
      free (compressed_payload);
      return grpc_stream_fail (call,
                               SOCKET_GRPC_STATUS_INTERNAL,
                               "Failed to frame streaming request",
                               1);
    }

  rc = grpc_stream_send_frame (call, ctx, framed, framed_len, 0);
  free (framed);
  free (compressed_payload);
  return rc;
}

int
SocketGRPC_Call_close_send (SocketGRPC_Call_T call)
{
  SocketGRPC_H2CallStream *ctx;

  if (call == NULL)
    return -1;
  if (call->h2_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_LOCAL
      || call->h2_stream_state == GRPC_CALL_STREAM_CLOSED)
    return 0;
  if (call->h2_stream_state == GRPC_CALL_STREAM_FAILED)
    return -1;

  ctx = grpc_stream_open_if_needed (call);
  if (ctx == NULL)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to initialize stream");
      return -1;
    }

  if (grpc_h2_stream_send_headers_safe (ctx->stream, NULL, 0, 1) != 0
      || grpc_h2_conn_flush_safe (ctx->h2conn) != 0)
    {
      return grpc_stream_fail (call,
                               SOCKET_GRPC_STATUS_UNAVAILABLE,
                               "Failed to close send direction",
                               1);
    }

  call->h2_stream_state
      = (call->h2_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_REMOTE)
            ? GRPC_CALL_STREAM_CLOSED
            : GRPC_CALL_STREAM_HALF_CLOSED_LOCAL;
  return 0;
}

int
SocketGRPC_Call_recv_message (SocketGRPC_Call_T call,
                              Arena_T arena,
                              uint8_t **response_payload,
                              size_t *response_payload_len,
                              int *done)
{
  SocketGRPC_H2CallStream *ctx;

  if (call == NULL || arena == NULL || response_payload == NULL
      || response_payload_len == NULL || done == NULL)
    return -1;

  *response_payload = NULL;
  *response_payload_len = 0;
  *done = 0;

  if (call->h2_stream_ctx == NULL)
    {
      if (call->h2_stream_state == GRPC_CALL_STREAM_CLOSED)
        {
          *done = 1;
          return 0;
        }
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_FAILED_PRECONDITION, "Stream not started");
      return -1;
    }

  if (call->h2_stream_state == GRPC_CALL_STREAM_FAILED)
    return -1;

  ctx = (SocketGRPC_H2CallStream *)call->h2_stream_ctx;

  if (!ctx->headers_received)
    {
      int end_stream = 0;
      if (httpclient_http2_recv_headers (
              ctx->stream, ctx->h2conn, &ctx->response, &end_stream)
          < 0)
        {
          return grpc_stream_fail (call,
                                   SOCKET_GRPC_STATUS_UNAVAILABLE,
                                   "Failed to receive stream headers",
                                   1);
        }
      if (grpc_ingest_response_headers (call, ctx->response.headers, end_stream)
          != 0)
        {
          return grpc_stream_fail (call,
                                   SOCKET_GRPC_STATUS_INTERNAL,
                                   "Invalid streaming response headers",
                                   1);
        }
      ctx->headers_received = 1;
      ctx->http_status_code = ctx->response.status_code;
      ctx->response_compression
          = grpc_response_compression_from_headers (ctx->response.headers);
      if (ctx->response_compression == GRPC_COMPRESSION_UNSUPPORTED)
        {
          return grpc_stream_fail (call,
                                   SOCKET_GRPC_STATUS_INTERNAL,
                                   "Unsupported response compression encoding",
                                   1);
        }
      if (ctx->response_compression == GRPC_COMPRESSION_GZIP
          && !call->channel->config.enable_response_decompression)
        {
          return grpc_stream_fail (call,
                                   SOCKET_GRPC_STATUS_INTERNAL,
                                   "Response decompression is disabled",
                                   1);
        }
      if (end_stream)
        ctx->remote_end_stream = 1;
    }

  for (;;)
    {
      if (SocketTimeout_expired (ctx->deadline_ms))
        {
          return grpc_stream_fail (call,
                                   SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
                                   "Deadline exceeded",
                                   1);
        }

      int has_message = 0;
      SocketGRPC_StatusCode parse_error_status = SOCKET_GRPC_STATUS_INTERNAL;
      const char *parse_error_message = "Malformed streaming response frame";
      if (grpc_stream_try_parse_message (call,
                                         ctx,
                                         arena,
                                         response_payload,
                                         response_payload_len,
                                         &parse_error_status,
                                         &parse_error_message,
                                         &has_message)
          != 0)
        {
          return grpc_stream_fail (
              call, parse_error_status, parse_error_message, 1);
        }
      if (has_message)
        {
          if (grpc_run_client_stream_interceptors (
                  call,
                  SOCKET_GRPC_STREAM_INTERCEPT_RECV,
                  *response_payload,
                  *response_payload_len)
              != 0)
            {
              *response_payload = NULL;
              *response_payload_len = 0;
              return -1;
            }
          return 0;
        }

      if (ctx->remote_end_stream)
        {
          if (ctx->recv_len != 0)
            {
              return grpc_stream_fail (call,
                                       SOCKET_GRPC_STATUS_INTERNAL,
                                       "Incomplete gRPC frame at end of stream",
                                       1);
            }
          if (!ctx->status_finalized)
            {
              grpc_stream_finalize_status (call, ctx->http_status_code);
              ctx->status_finalized = 1;
            }
          grpc_stream_context_cleanup (call, 1, 0);
          *done = 1;
          return 0;
        }

      {
        unsigned char chunk[GRPC_RESPONSE_CHUNK];
        int end_stream = 0;
        ssize_t n = grpc_h2_stream_recv_data_safe (
            ctx->stream, chunk, sizeof (chunk), &end_stream);
        if (n < 0)
          {
            return grpc_stream_fail (call,
                                     SOCKET_GRPC_STATUS_UNAVAILABLE,
                                     "Failed to receive stream body",
                                     1);
          }
        if (n > 0 && grpc_stream_append_recv (call, ctx, chunk, (size_t)n) != 0)
          {
            return grpc_stream_fail (call,
                                     SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED,
                                     "Streaming response exceeds limit",
                                     1);
          }

        {
          SocketHPACK_Header trailers[SOCKETHTTP2_MAX_DECODED_HEADERS];
          size_t trailer_count = 0;
          int tr = grpc_h2_stream_recv_trailers_safe (
              ctx->stream,
              trailers,
              SOCKETHTTP2_MAX_DECODED_HEADERS,
              &trailer_count);
          if (tr < 0)
            {
              return grpc_stream_fail (call,
                                       SOCKET_GRPC_STATUS_UNAVAILABLE,
                                       "Failed to receive stream trailers",
                                       1);
            }
          if (tr == 1 && trailer_count > 0
              && grpc_ingest_stream_trailers (call, trailers, trailer_count)
                     != 0)
            {
              return grpc_stream_fail (call,
                                       SOCKET_GRPC_STATUS_INTERNAL,
                                       "Invalid streaming response trailers",
                                       1);
            }
        }

        if (end_stream)
          {
            call->h2_stream_state
                = (call->h2_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_LOCAL)
                      ? GRPC_CALL_STREAM_CLOSED
                      : GRPC_CALL_STREAM_HALF_CLOSED_REMOTE;
            ctx->remote_end_stream = 1;
          }

        if (n == 0 && !ctx->remote_end_stream
            && grpc_h2_conn_process_safe (ctx->h2conn, 0) < 0)
          {
            return grpc_stream_fail (call,
                                     SOCKET_GRPC_STATUS_UNAVAILABLE,
                                     "Failed to advance stream state",
                                     1);
          }
      }
    }
}

int
SocketGRPC_Call_metadata_add_ascii (SocketGRPC_Call_T call,
                                    const char *key,
                                    const char *value)
{
  if (call == NULL || key == NULL || value == NULL
      || call->request_metadata == NULL)
    return -1;
  if (SocketGRPC_Metadata_count (call->request_metadata)
      >= call->channel->config.max_metadata_entries)
    return -1;
  return SocketGRPC_Metadata_add_ascii (call->request_metadata, key, value)
                 == SOCKET_GRPC_WIRE_OK
             ? 0
             : -1;
}

int
SocketGRPC_Call_metadata_add_binary (SocketGRPC_Call_T call,
                                     const char *key,
                                     const uint8_t *value,
                                     size_t value_len)
{
  if (call == NULL || key == NULL || (value == NULL && value_len != 0)
      || call->request_metadata == NULL)
    return -1;
  if (SocketGRPC_Metadata_count (call->request_metadata)
      >= call->channel->config.max_metadata_entries)
    return -1;
  return SocketGRPC_Metadata_add_binary (
             call->request_metadata, key, value, value_len)
                 == SOCKET_GRPC_WIRE_OK
             ? 0
             : -1;
}

void
SocketGRPC_Call_metadata_clear (SocketGRPC_Call_T call)
{
  if (call == NULL || call->request_metadata == NULL)
    return;
  SocketGRPC_Metadata_clear (call->request_metadata);
}

SocketGRPC_Trailers_T
SocketGRPC_Call_trailers (SocketGRPC_Call_T call)
{
  if (call == NULL)
    return NULL;
  return call->response_trailers;
}

SocketGRPC_Status
SocketGRPC_Call_status (SocketGRPC_Call_T call)
{
  SocketGRPC_Status status
      = { SOCKET_GRPC_STATUS_INTERNAL, "Status unavailable" };
  if (call == NULL)
    return status;
  return call->last_status;
}

int
SocketGRPC_Call_cancel (SocketGRPC_Call_T call)
{
  if (call == NULL)
    return -1;

  if (call->response_trailers != NULL
      && !SocketGRPC_Trailers_has_status (call->response_trailers))
    {
      (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                            SOCKET_GRPC_STATUS_CANCELLED);
      (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                             "Call cancelled");
    }

  grpc_call_status_set (call, SOCKET_GRPC_STATUS_CANCELLED, "Call cancelled");

  if (call->h2_stream_ctx != NULL)
    grpc_stream_context_cleanup (call, 0, 1);

  return 0;
}

static int
grpc_call_unary_h2_single_attempt (SocketGRPC_Call_T call,
                                   const uint8_t *request_payload,
                                   size_t request_payload_len,
                                   Arena_T arena,
                                   uint8_t **response_payload,
                                   size_t *response_payload_len)
{
  SocketHTTPClient_Config cfg;
  SocketHTTPClient_T http_client = NULL;
  SocketHTTPClient_Request_T req = NULL;
  SocketHTTPClient_Response response = { 0 };
  HTTPPoolEntry *conn = NULL;
  SocketHTTP_Request http_req;
  SocketHTTP2_Conn_T h2conn;
  SocketHTTP2_Stream_T stream = NULL;
  unsigned char *framed = NULL;
  unsigned char *compressed_request = NULL;
  const uint8_t *wire_request_payload = request_payload;
  size_t wire_request_payload_len = request_payload_len;
  size_t framed_cap = 0;
  size_t framed_len = 0;
  unsigned char *raw_response = NULL;
  size_t raw_response_len = 0;
  char *url = NULL;
  int status_code = -1;
  int transport_success = 0;
  int64_t call_deadline_ms = 0;
  Arena_T compression_arena = NULL;
  SocketDeflate_Deflater_T request_deflater = NULL;
  SocketDeflate_Inflater_T response_inflater = NULL;
  SocketGRPC_Compression response_compression = GRPC_COMPRESSION_IDENTITY;
  SocketGRPC_StatusCode recv_error_status = SOCKET_GRPC_STATUS_UNAVAILABLE;
  const char *recv_error_message = "Failed to receive response body";
  int request_frame_compressed = 0;

  if (call == NULL || request_payload == NULL || arena == NULL
      || response_payload == NULL || response_payload_len == NULL)
    return -1;
  if (call->h2_stream_ctx != NULL)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_FAILED_PRECONDITION,
                            "Cannot run unary call while stream is active");
      return -1;
    }
  if (request_payload_len > call->channel->config.max_outbound_message_bytes
      || request_payload_len > (size_t)UINT32_MAX
      || request_payload_len > (SIZE_MAX - SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE))
    {
      grpc_call_status_set (call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL);
      return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
    }

  request_frame_compressed
      = call->channel->config.enable_request_compression ? 1 : 0;
  if (request_frame_compressed
      || call->channel->config.enable_response_decompression)
    {
      compression_arena = Arena_new ();
      if (compression_arena == NULL)
        {
          grpc_call_status_set (
              call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL);
          return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
        }

      if (request_frame_compressed)
        {
          request_deflater = SocketDeflate_Deflater_new (compression_arena,
                                                         DEFLATE_LEVEL_DEFAULT);
          if (request_deflater == NULL
              || grpc_gzip_compress_payload (request_deflater,
                                             request_payload,
                                             request_payload_len,
                                             &compressed_request,
                                             &wire_request_payload_len)
                     != 0)
            {
              grpc_call_status_set (call,
                                    SOCKET_GRPC_STATUS_INTERNAL,
                                    "Failed to compress request payload");
              goto cleanup;
            }
          wire_request_payload = compressed_request;
        }

      if (call->channel->config.enable_response_decompression)
        {
          response_inflater = SocketDeflate_Inflater_new (
              compression_arena,
              call->channel->config.max_decompressed_message_bytes);
          if (response_inflater == NULL)
            {
              grpc_call_status_set (
                  call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL);
              goto cleanup;
            }
        }
    }

  if (wire_request_payload_len > (size_t)UINT32_MAX
      || wire_request_payload_len
             > (SIZE_MAX - SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE))
    {
      grpc_call_status_set (call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL);
      status_code = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
      goto cleanup;
    }

  call_deadline_ms = SocketTimeout_deadline_ms (call->config.deadline_ms);
  framed_cap = SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE + wire_request_payload_len;

  *response_payload = NULL;
  *response_payload_len = 0;
  SocketGRPC_Trailers_clear (call->response_trailers);

  url = grpc_build_call_url (call, arena);
  if (url == NULL)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INVALID_ARGUMENT, "Invalid channel target");
      goto cleanup;
    }

  SocketHTTPClient_config_defaults (&cfg);
  cfg.max_version = HTTP_VERSION_2;
  cfg.allow_http2_cleartext = call->channel->config.allow_http2_cleartext;
  cfg.verify_ssl = call->channel->config.verify_peer;
  cfg.tls_context = call->channel->config.tls_context;
  cfg.request_timeout_ms = call->config.deadline_ms;
  cfg.max_response_size = call->channel->config.max_cumulative_inflight_bytes;

  http_client = SocketHTTPClient_new (&cfg);
  if (http_client == NULL)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INTERNAL, "HTTP client allocation failed");
      goto cleanup;
    }

  req = SocketHTTPClient_Request_new (http_client, HTTP_METHOD_POST, url);
  if (req == NULL)
    {
      grpc_call_status_set (
          call,
          grpc_map_httpclient_error (SocketHTTPClient_last_error (http_client)),
          "Request initialization failed");
      goto cleanup;
    }

  SocketHTTPClient_Request_timeout (req, call->config.deadline_ms);
  if (grpc_request_add_required_headers (call, req) != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INTERNAL, "Failed to set request headers");
      goto cleanup;
    }

  framed = (unsigned char *)malloc (framed_cap);
  if (framed == NULL)
    {
      grpc_call_status_set (call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL);
      goto cleanup;
    }
  if (SocketGRPC_Frame_encode (request_frame_compressed,
                               wire_request_payload,
                               (uint32_t)wire_request_payload_len,
                               framed,
                               framed_cap,
                               &framed_len)
      != SOCKET_GRPC_WIRE_OK)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INTERNAL, "Failed to frame request payload");
      goto cleanup;
    }

  if (SocketHTTPClient_Request_body (req, framed, framed_len) != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INTERNAL, "Failed to attach request body");
      goto cleanup;
    }

  conn = httpclient_connect (http_client, &req->uri);
  if (conn == NULL)
    {
      grpc_call_status_set (
          call,
          grpc_map_httpclient_error (SocketHTTPClient_last_error (http_client)),
          "Connection failed");
      goto cleanup;
    }

  httpclient_headers_prepare_request (http_client, req);

  if (conn->version != HTTP_VERSION_2 || conn->proto.h2.conn == NULL)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INTERNAL, "HTTP/2 transport not negotiated");
      goto cleanup;
    }

  h2conn = conn->proto.h2.conn;
  stream = SocketHTTP2_Stream_new (h2conn);
  if (stream == NULL)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INTERNAL, "Failed to open HTTP/2 stream");
      goto cleanup;
    }
  conn->proto.h2.active_streams++;

  httpclient_http2_build_request (req, &http_req);
  if (httpclient_http2_send_request (
          stream, h2conn, &http_req, req->body, req->body_len)
      < 0)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_UNAVAILABLE,
                            "Failed to send HTTP/2 request");
      goto cleanup;
    }

  {
    int end_stream = 0;
    if (httpclient_http2_recv_headers (stream, h2conn, &response, &end_stream)
        < 0)
      {
        grpc_call_status_set (call,
                              SOCKET_GRPC_STATUS_UNAVAILABLE,
                              "Failed to receive response headers");
        goto cleanup;
      }

    if (grpc_ingest_response_headers (call, response.headers, end_stream) != 0)
      {
        grpc_call_status_set (call,
                              SOCKET_GRPC_STATUS_INTERNAL,
                              "Invalid response header metadata");
        goto cleanup;
      }

    response_compression
        = grpc_response_compression_from_headers (response.headers);
    if (response_compression == GRPC_COMPRESSION_UNSUPPORTED)
      {
        status_code = SOCKET_GRPC_STATUS_INTERNAL;
        (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                              status_code);
        if (SocketGRPC_Trailers_message (call->response_trailers) == NULL)
          {
            (void)SocketGRPC_Trailers_set_message (
                call->response_trailers,
                "Unsupported response compression encoding");
          }
        grpc_call_status_set (call,
                              SOCKET_GRPC_STATUS_INTERNAL,
                              "Unsupported response compression encoding");
        goto cleanup;
      }
    if (response_compression == GRPC_COMPRESSION_GZIP
        && !call->channel->config.enable_response_decompression)
      {
        status_code = SOCKET_GRPC_STATUS_INTERNAL;
        (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                              status_code);
        if (SocketGRPC_Trailers_message (call->response_trailers) == NULL)
          {
            (void)SocketGRPC_Trailers_set_message (
                call->response_trailers, "Response decompression is disabled");
          }
        grpc_call_status_set (call,
                              SOCKET_GRPC_STATUS_INTERNAL,
                              "Response decompression is disabled");
        goto cleanup;
      }

    if (!end_stream)
      {
        if (grpc_receive_body_and_trailers (call,
                                            stream,
                                            h2conn,
                                            &raw_response,
                                            &raw_response_len,
                                            &recv_error_status,
                                            &recv_error_message)
            != 0)
          {
            status_code = recv_error_status;
            (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                                  recv_error_status);
            if (recv_error_message != NULL
                && SocketGRPC_Trailers_message (call->response_trailers)
                       == NULL)
              {
                (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                                       recv_error_message);
              }
            grpc_call_status_set (call, recv_error_status, recv_error_message);
            goto cleanup;
          }
      }
  }

  if (SocketTimeout_expired (call_deadline_ms))
    {
      int existing_status
          = SocketGRPC_Trailers_has_status (call->response_trailers)
                ? SocketGRPC_Trailers_status (call->response_trailers)
                : SOCKET_GRPC_STATUS_OK;
      if (existing_status == SOCKET_GRPC_STATUS_OK)
        {
          (void)SocketGRPC_Trailers_set_status (
              call->response_trailers, SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED);
          if (SocketGRPC_Trailers_message (call->response_trailers) == NULL)
            {
              (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                                     "Deadline exceeded");
            }
        }
    }

  if (!SocketGRPC_Trailers_has_status (call->response_trailers))
    {
      SocketGRPC_StatusCode mapped
          = SocketGRPC_http_status_to_grpc (response.status_code);
      (void)SocketGRPC_Trailers_set_status (call->response_trailers, mapped);
    }

  status_code = SocketGRPC_Trailers_status (call->response_trailers);
  grpc_call_status_set (call,
                        (SocketGRPC_StatusCode)status_code,
                        SocketGRPC_Trailers_message (call->response_trailers));

  if (status_code == SOCKET_GRPC_STATUS_OK && raw_response != NULL
      && raw_response_len > 0)
    {
      SocketGRPC_FrameView frame;
      size_t consumed = 0;
      size_t max_frame_payload
          = call->channel->config.max_cumulative_inflight_bytes;
      SocketGRPC_WireResult parse_rc;
      SocketGRPC_StatusCode decode_status;
      const char *decode_message = "Malformed gRPC response frame";

      if (max_frame_payload == 0)
        max_frame_payload = call->channel->config.max_inbound_message_bytes;

      parse_rc = SocketGRPC_Frame_parse (
          raw_response, raw_response_len, max_frame_payload, &frame, &consumed);
      if (parse_rc != SOCKET_GRPC_WIRE_OK || consumed != raw_response_len)
        {
          decode_status = parse_rc == SOCKET_GRPC_WIRE_LENGTH_EXCEEDED
                              ? SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED
                              : SOCKET_GRPC_STATUS_INTERNAL;
          if (parse_rc == SOCKET_GRPC_WIRE_LENGTH_EXCEEDED)
            decode_message = "Response exceeds configured inflight limit";
        }
      else
        {
          decode_status = grpc_decode_frame_payload (call,
                                                     response_compression,
                                                     response_inflater,
                                                     arena,
                                                     &frame,
                                                     response_payload,
                                                     response_payload_len,
                                                     &decode_message);
        }

      if (decode_status != SOCKET_GRPC_STATUS_OK)
        {
          (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                                decode_status);
          if (decode_message != NULL
              && SocketGRPC_Trailers_message (call->response_trailers) == NULL)
            {
              (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                                    decode_status);
              (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                                     decode_message);
            }
          grpc_call_status_set (call, decode_status, decode_message);
          status_code = decode_status;
          goto cleanup;
        }
    }
  else
    {
      *response_payload = NULL;
      *response_payload_len = 0;
    }

  transport_success = 1;

cleanup:
  if (conn != NULL && stream != NULL)
    {
      conn->proto.h2.active_streams--;
      if (!transport_success)
        grpc_h2_stream_cancel_safe (stream);
    }
  if (conn != NULL)
    grpc_release_connection_safe (http_client, conn, transport_success);
  free (raw_response);
  free (framed);
  free (compressed_request);
  if (compression_arena != NULL)
    Arena_dispose (&compression_arena);
  SocketHTTPClient_Response_free (&response);
  SocketHTTPClient_Request_free (&req);
  SocketHTTPClient_free (&http_client);

  return status_code;
}

static int
grpc_retry_status_is_retryable (const SocketGRPC_RetryPolicy *policy,
                                int status_code)
{
  if (policy == NULL || status_code < 0 || status_code >= 32)
    return 0;
  return (policy->retryable_status_mask & (1U << (unsigned int)status_code))
         != 0;
}

static int64_t
grpc_retry_jittered_backoff_ms (const SocketGRPC_RetryPolicy *policy,
                                int64_t base_backoff_ms)
{
  int64_t wait_ms;
  int64_t jitter;
  int64_t delta = 0;

  if (policy == NULL || base_backoff_ms <= 0)
    return 0;

  wait_ms = base_backoff_ms;
  jitter = (wait_ms * policy->jitter_percent) / 100;
  if (jitter > 0)
    {
      int span = (int)(jitter * 2 + 1);
      delta = (int64_t)(rand () % span) - jitter;
    }

  wait_ms += delta;
  return wait_ms > 0 ? wait_ms : 0;
}

static int64_t
grpc_retry_next_backoff_ms (const SocketGRPC_RetryPolicy *policy,
                            int64_t current_backoff_ms)
{
  int64_t next;

  if (policy == NULL || current_backoff_ms <= 0)
    return 0;

  next = (int64_t)((double)current_backoff_ms * policy->backoff_multiplier);
  if (policy->max_backoff_ms > 0 && next > policy->max_backoff_ms)
    next = policy->max_backoff_ms;
  return next > 0 ? next : 0;
}

static void
grpc_retry_sleep_ms (int64_t delay_ms)
{
  struct timespec req;
  struct timespec rem;

  if (delay_ms <= 0)
    return;
  if (delay_ms > INT_MAX)
    delay_ms = INT_MAX;

  req.tv_sec = (time_t)(delay_ms / 1000);
  req.tv_nsec = (long)((delay_ms % 1000) * 1000000);

  while (nanosleep (&req, &rem) == -1)
    {
      if (errno != EINTR)
        break;
      req = rem;
    }
}

int
SocketGRPC_Call_unary_h2 (SocketGRPC_Call_T call,
                          const uint8_t *request_payload,
                          size_t request_payload_len,
                          Arena_T arena,
                          uint8_t **response_payload,
                          size_t *response_payload_len)
{
  SocketGRPC_RetryPolicy policy;
  int max_attempts;
  int attempt;
  int rc = -1;
  int64_t call_deadline_ms;
  int64_t backoff_ms;
  int original_deadline_ms;

  if (call == NULL || request_payload == NULL || arena == NULL
      || response_payload == NULL || response_payload_len == NULL)
    return -1;

  *response_payload = NULL;
  *response_payload_len = 0;
  if (grpc_run_client_unary_interceptors (
          call, request_payload, request_payload_len)
      != 0)
    {
      return (int)SocketGRPC_Call_status (call).code;
    }

  policy = call->config.retry_policy;
  if (SocketGRPC_RetryPolicy_validate (&policy) != 0)
    SocketGRPC_RetryPolicy_defaults (&policy);

  max_attempts = 1;
  if (call->channel != NULL && call->channel->client != NULL
      && call->channel->client->config.enable_retry && !call->retry_in_progress)
    {
      max_attempts = policy.max_attempts;
    }

  if (max_attempts <= 1)
    return grpc_call_unary_h2_single_attempt (call,
                                              request_payload,
                                              request_payload_len,
                                              arena,
                                              response_payload,
                                              response_payload_len);

  original_deadline_ms = call->config.deadline_ms;
  call_deadline_ms = SocketTimeout_deadline_ms (original_deadline_ms);
  backoff_ms = policy.initial_backoff_ms;
  call->retry_in_progress = 1;
  call->retry_attempt = 0;

  for (attempt = 1; attempt <= max_attempts; attempt++)
    {
      int status_code;

      if (SocketTimeout_expired (call_deadline_ms))
        {
          rc = SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED;
          grpc_call_status_set (
              call, SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED, "Deadline exceeded");
          (void)SocketGRPC_Trailers_set_status (
              call->response_trailers, SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED);
          (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                                 "Deadline exceeded");
          break;
        }

      if (call_deadline_ms > 0)
        {
          int64_t remaining = SocketTimeout_remaining_ms (call_deadline_ms);
          if (remaining <= 0)
            {
              rc = SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED;
              grpc_call_status_set (call,
                                    SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
                                    "Deadline exceeded");
              (void)SocketGRPC_Trailers_set_status (
                  call->response_trailers,
                  SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED);
              (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                                     "Deadline exceeded");
              break;
            }
          call->config.deadline_ms
              = (remaining > INT_MAX) ? INT_MAX : (int)remaining;
        }
      else
        {
          call->config.deadline_ms = original_deadline_ms;
        }

      call->retry_attempt = (uint32_t)(attempt - 1);
      rc = grpc_call_unary_h2_single_attempt (call,
                                              request_payload,
                                              request_payload_len,
                                              arena,
                                              response_payload,
                                              response_payload_len);
      status_code = (rc >= 0) ? rc : (int)SocketGRPC_Call_status (call).code;

      if (attempt >= max_attempts)
        break;
      if (status_code == SOCKET_GRPC_STATUS_CANCELLED
          || status_code == SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED)
        break;
      if (!grpc_retry_status_is_retryable (&policy, status_code))
        break;

      {
        int64_t wait_ms = grpc_retry_jittered_backoff_ms (&policy, backoff_ms);
        if (call_deadline_ms > 0)
          {
            int64_t remaining = SocketTimeout_remaining_ms (call_deadline_ms);
            if (remaining <= 0)
              {
                rc = SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED;
                grpc_call_status_set (call,
                                      SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
                                      "Deadline exceeded");
                break;
              }
            if (wait_ms > remaining)
              wait_ms = remaining;
          }

        if (wait_ms > 0)
          grpc_retry_sleep_ms (wait_ms);
      }

      backoff_ms = grpc_retry_next_backoff_ms (&policy, backoff_ms);
    }

  if (rc == SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED)
    {
      (void)SocketGRPC_Trailers_set_status (
          call->response_trailers, SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED);
      (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                             "Deadline exceeded");
    }

  call->config.deadline_ms = original_deadline_ms;
  call->retry_attempt = 0;
  call->retry_in_progress = 0;
  return rc;
}

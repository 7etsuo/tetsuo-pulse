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
#include "http/SocketHTTPClient-private.h"
#include "http/SocketHTTP2-private.h"

#include "core/SocketCrypto.h"
#include "socket/Socket.h"
#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define GRPC_CONTENT_TYPE "application/grpc"
#define GRPC_TIMEOUT_HEADER_MAX 32U
#define GRPC_RESPONSE_CHUNK 4096U
#define GRPC_STREAM_RECV_BUFFER_INITIAL 4096U

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
} SocketGRPC_H2CallStream;

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
      scheme = call->channel->config.allow_http2_cleartext ? "http://" : "https://";
    }
  else
    {
      base = target;
      scheme = call->channel->config.allow_http2_cleartext ? "http://" : "https://";
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
      url = (char *)ALLOC (arena, scheme_len + trim_len + add_slash + path_len + 1U);
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
      const SocketGRPC_MetadataEntry *entry = SocketGRPC_Metadata_at (metadata, i);
      if (entry == NULL || entry->key == NULL)
        continue;

      if (entry->is_binary)
        {
          size_t encoded_cap = SocketCrypto_base64_encoded_size (entry->value_len);
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

  if (SocketHTTPClient_Request_header (req, "content-type", GRPC_CONTENT_TYPE)
      != 0)
    return -1;
  if (SocketHTTPClient_Request_header (req, "te", "trailers") != 0)
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
      int len
          = snprintf (timeout_buf, sizeof (timeout_buf), "%dm", call->config.deadline_ms);
      if (len <= 0 || (size_t)len >= sizeof (timeout_buf))
        return -1;
      if (SocketHTTPClient_Request_header (req, "grpc-timeout", timeout_buf) != 0)
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
      return SocketGRPC_Trailers_set_status (trailers, status) == SOCKET_GRPC_WIRE_OK ? 0 : -1;
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
                                size_t *body_len_out)
{
  unsigned char *body = NULL;
  size_t total = 0;
  size_t cap = 0;

  if (body_out == NULL || body_len_out == NULL)
    return -1;

  for (;;)
    {
      unsigned char chunk[GRPC_RESPONSE_CHUNK];
      int end_stream = 0;
      ssize_t n = grpc_h2_stream_recv_data_safe (
          stream, chunk, sizeof (chunk), &end_stream);
      if (n < 0)
        {
          free (body);
          return -1;
        }

      if (n > 0)
        {
          size_t needed = total + (size_t)n;
          if (needed > call->channel->config.max_inbound_message_bytes)
            {
              free (body);
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
            return -1;
          }
        if (tr == 1 && trailer_count > 0)
          {
            if (grpc_ingest_stream_trailers (call, trailers, trailer_count) != 0)
              {
                free (body);
                return -1;
              }
          }
      }

      if (end_stream)
        break;

      if (n == 0 && grpc_h2_conn_process_safe (conn, 0) < 0)
        {
          free (body);
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
      scheme = call->channel->config.allow_http2_cleartext ? "http://" : "https://";
    }
  else
    {
      base = target;
      scheme = call->channel->config.allow_http2_cleartext ? "http://" : "https://";
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
grpc_stream_context_cleanup (SocketGRPC_Call_T call, int success, int cancel_stream)
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

static void
grpc_stream_finalize_status (SocketGRPC_Call_T call, int http_status_code)
{
  SocketGRPC_StatusCode status_code;

  if (call == NULL || call->response_trailers == NULL)
    return;

  if (!SocketGRPC_Trailers_has_status (call->response_trailers))
    {
      status_code
          = SocketGRPC_http_status_to_grpc (http_status_code);
      (void)SocketGRPC_Trailers_set_status (call->response_trailers, status_code);
    }

  status_code
      = (SocketGRPC_StatusCode)SocketGRPC_Trailers_status (call->response_trailers);
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

  SocketHTTPClient_config_defaults (&cfg);
  cfg.max_version = HTTP_VERSION_2;
  cfg.allow_http2_cleartext = call->channel->config.allow_http2_cleartext;
  cfg.verify_ssl = call->channel->config.verify_peer;
  cfg.tls_context = call->channel->config.tls_context;
  cfg.request_timeout_ms = call->config.deadline_ms;
  cfg.max_response_size = call->channel->config.max_inbound_message_bytes;

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
  call->h2_stream_ctx = ctx;
  call->h2_stream_state = GRPC_CALL_STREAM_OPEN;
  return ctx;

fail:
  if (url != NULL)
    free (url);
  if (ctx != NULL)
    {
      if (ctx->conn != NULL && ctx->stream != NULL && ctx->active_stream_counted)
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
      if (grpc_h2_conn_flush_safe (ctx->h2conn) != 0)
        {
          return grpc_stream_fail (
              call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to flush stream send", 1);
        }

      ssize_t n = grpc_h2_stream_send_data_safe (
          ctx->stream, frame + offset, frame_len - offset, close_send);
      if (n < 0)
        {
          return grpc_stream_fail (
              call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to send stream frame", 1);
        }
      if (n == 0)
        {
          if (grpc_h2_conn_process_safe (ctx->h2conn, 0) < 0 || ++idle_spins > 2048)
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
      return grpc_stream_fail (
          call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to flush stream send", 1);
    }

  if (close_send)
    {
      call->h2_stream_state = (call->h2_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_REMOTE)
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

  max_buffer = call->channel->config.max_inbound_message_bytes
               + SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE;
  needed = ctx->recv_len + chunk_len;
  if (needed > max_buffer)
    return -1;

  if (needed > ctx->recv_cap)
    {
      size_t new_cap
          = ctx->recv_cap == 0 ? GRPC_STREAM_RECV_BUFFER_INITIAL : ctx->recv_cap;
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
                               int *has_message)
{
  SocketGRPC_FrameView frame;
  size_t consumed = 0;
  SocketGRPC_WireResult rc;

  if (call == NULL || ctx == NULL || arena == NULL || response_payload == NULL
      || response_payload_len == NULL || has_message == NULL)
    return -1;

  *has_message = 0;
  if (ctx->recv_len == 0)
    return 0;

  rc = SocketGRPC_Frame_parse (ctx->recv_buffer,
                               ctx->recv_len,
                               call->channel->config.max_inbound_message_bytes,
                               &frame,
                               &consumed);
  if (rc == SOCKET_GRPC_WIRE_INCOMPLETE)
    return 0;
  if (rc != SOCKET_GRPC_WIRE_OK)
    return -1;
  if (frame.compressed != 0)
    return -1;

  if (frame.payload_len > 0)
    {
      uint8_t *out = (uint8_t *)ALLOC (arena, frame.payload_len);
      if (out == NULL)
        return -1;
      memcpy (out, frame.payload, frame.payload_len);
      *response_payload = out;
      *response_payload_len = frame.payload_len;
    }
  else
    {
      *response_payload = NULL;
      *response_payload_len = 0;
    }

  if (consumed < ctx->recv_len)
    {
      memmove (ctx->recv_buffer, ctx->recv_buffer + consumed, ctx->recv_len - consumed);
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
  size_t framed_len = 0;
  size_t framed_cap;
  int rc;

  if (call == NULL || (request_payload == NULL && request_payload_len != 0))
    return -1;
  if (call->h2_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_LOCAL
      || call->h2_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_REMOTE
      || call->h2_stream_state == GRPC_CALL_STREAM_FAILED)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_FAILED_PRECONDITION, "Send direction already closed");
      return -1;
    }
  if (request_payload_len > call->channel->config.max_outbound_message_bytes
      || request_payload_len > (size_t)UINT32_MAX)
    {
      grpc_call_status_set (call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL);
      return -1;
    }

  ctx = grpc_stream_open_if_needed (call);
  if (ctx == NULL)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to initialize stream");
      return -1;
    }

  framed_cap = SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE + request_payload_len;
  framed = (unsigned char *)malloc (framed_cap);
  if (framed == NULL)
    {
      return grpc_stream_fail (
          call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, "Out of memory framing message", 1);
    }

  if (SocketGRPC_Frame_encode (0,
                               request_payload,
                               (uint32_t)request_payload_len,
                               framed,
                               framed_cap,
                               &framed_len)
      != SOCKET_GRPC_WIRE_OK)
    {
      free (framed);
      return grpc_stream_fail (
          call, SOCKET_GRPC_STATUS_INTERNAL, "Failed to frame streaming request", 1);
    }

  rc = grpc_stream_send_frame (call, ctx, framed, framed_len, 0);
  free (framed);
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
      return grpc_stream_fail (
          call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to close send direction", 1);
    }

  call->h2_stream_state = (call->h2_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_REMOTE)
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
      if (httpclient_http2_recv_headers (ctx->stream, ctx->h2conn, &ctx->response, &end_stream)
          < 0)
        {
          return grpc_stream_fail (
              call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to receive stream headers", 1);
        }
      if (grpc_ingest_response_headers (call, ctx->response.headers, end_stream) != 0)
        {
          return grpc_stream_fail (
              call, SOCKET_GRPC_STATUS_INTERNAL, "Invalid streaming response headers", 1);
        }
      ctx->headers_received = 1;
      ctx->http_status_code = ctx->response.status_code;
      if (end_stream)
        ctx->remote_end_stream = 1;
    }

  for (;;)
    {
      int has_message = 0;
      if (grpc_stream_try_parse_message (call,
                                         ctx,
                                         arena,
                                         response_payload,
                                         response_payload_len,
                                         &has_message)
          != 0)
        {
          return grpc_stream_fail (
              call, SOCKET_GRPC_STATUS_INTERNAL, "Malformed streaming response frame", 1);
        }
      if (has_message)
        return 0;

      if (ctx->remote_end_stream)
        {
          if (ctx->recv_len != 0)
            {
              return grpc_stream_fail (
                  call,
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
            return grpc_stream_fail (
                call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to receive stream body", 1);
          }
        if (n > 0
            && grpc_stream_append_recv (call, ctx, chunk, (size_t)n) != 0)
          {
            return grpc_stream_fail (
                call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, "Streaming response exceeds limit", 1);
          }

        {
          SocketHPACK_Header trailers[SOCKETHTTP2_MAX_DECODED_HEADERS];
          size_t trailer_count = 0;
          int tr = grpc_h2_stream_recv_trailers_safe (
              ctx->stream, trailers, SOCKETHTTP2_MAX_DECODED_HEADERS, &trailer_count);
          if (tr < 0)
            {
              return grpc_stream_fail (call,
                                       SOCKET_GRPC_STATUS_UNAVAILABLE,
                                       "Failed to receive stream trailers",
                                       1);
            }
          if (tr == 1 && trailer_count > 0
              && grpc_ingest_stream_trailers (call, trailers, trailer_count) != 0)
            {
              return grpc_stream_fail (
                  call, SOCKET_GRPC_STATUS_INTERNAL, "Invalid streaming response trailers", 1);
            }
        }

        if (end_stream)
          {
            call->h2_stream_state = (call->h2_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_LOCAL)
                                        ? GRPC_CALL_STREAM_CLOSED
                                        : GRPC_CALL_STREAM_HALF_CLOSED_REMOTE;
            ctx->remote_end_stream = 1;
          }

        if (n == 0 && !ctx->remote_end_stream
            && grpc_h2_conn_process_safe (ctx->h2conn, 0) < 0)
          {
            return grpc_stream_fail (
                call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to advance stream state", 1);
          }
      }
    }
}

int
SocketGRPC_Call_metadata_add_ascii (SocketGRPC_Call_T call,
                                    const char *key,
                                    const char *value)
{
  if (call == NULL || key == NULL || value == NULL || call->request_metadata == NULL)
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
  SocketGRPC_Status status = { SOCKET_GRPC_STATUS_INTERNAL, "Status unavailable" };
  if (call == NULL)
    return status;
  return call->last_status;
}

int
SocketGRPC_Call_unary_h2 (SocketGRPC_Call_T call,
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
  size_t framed_cap = 0;
  size_t framed_len = 0;
  unsigned char *raw_response = NULL;
  size_t raw_response_len = 0;
  char *url = NULL;
  int status_code = -1;
  int transport_success = 0;

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
  framed_cap = SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE + request_payload_len;

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
  cfg.max_response_size = call->channel->config.max_inbound_message_bytes;

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

  framed = (unsigned char *)ALLOC (arena, framed_cap);
  if (framed == NULL)
    {
      grpc_call_status_set (call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL);
      goto cleanup;
    }
  if (SocketGRPC_Frame_encode (0,
                               request_payload,
                               (uint32_t)request_payload_len,
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
      grpc_call_status_set (call,
                            grpc_map_httpclient_error (
                                SocketHTTPClient_last_error (http_client)),
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
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to send HTTP/2 request");
      goto cleanup;
    }

  {
    int end_stream = 0;
    if (httpclient_http2_recv_headers (stream, h2conn, &response, &end_stream)
        < 0)
      {
        grpc_call_status_set (
            call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to receive response headers");
        goto cleanup;
      }

    if (grpc_ingest_response_headers (call, response.headers, end_stream) != 0)
      {
        grpc_call_status_set (
            call, SOCKET_GRPC_STATUS_INTERNAL, "Invalid response header metadata");
        goto cleanup;
      }

    if (!end_stream)
      {
        if (grpc_receive_body_and_trailers (
                call, stream, h2conn, &raw_response, &raw_response_len)
            != 0)
          {
            grpc_call_status_set (
                call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to receive response body");
            goto cleanup;
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
  grpc_call_status_set (
      call,
      (SocketGRPC_StatusCode)status_code,
      SocketGRPC_Trailers_message (call->response_trailers));

  if (raw_response != NULL && raw_response_len > 0)
    {
      SocketGRPC_FrameView frame;
      size_t consumed = 0;
      if (SocketGRPC_Frame_parse (raw_response,
                                  raw_response_len,
                                  call->channel->config.max_inbound_message_bytes,
                                  &frame,
                                  &consumed)
          != SOCKET_GRPC_WIRE_OK
          || consumed != raw_response_len || frame.compressed != 0)
        {
          if (status_code == SOCKET_GRPC_STATUS_OK)
            {
              (void)SocketGRPC_Trailers_set_status (
                  call->response_trailers, SOCKET_GRPC_STATUS_INTERNAL);
              (void)SocketGRPC_Trailers_set_message (
                  call->response_trailers, "Malformed gRPC response frame");
              grpc_call_status_set (
                  call,
                  SOCKET_GRPC_STATUS_INTERNAL,
                  "Malformed gRPC response frame");
              status_code = SOCKET_GRPC_STATUS_INTERNAL;
            }
          goto cleanup;
        }
      if (frame.payload_len > 0)
        {
          uint8_t *out = (uint8_t *)ALLOC (arena, frame.payload_len);
          if (out == NULL)
            {
              grpc_call_status_set (
                  call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL);
              status_code = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
              goto cleanup;
            }
          memcpy (out, frame.payload, frame.payload_len);
          *response_payload = out;
          *response_payload_len = frame.payload_len;
        }
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
  SocketHTTPClient_Response_free (&response);
  SocketHTTPClient_Request_free (&req);
  SocketHTTPClient_free (&http_client);

  return status_code;
}

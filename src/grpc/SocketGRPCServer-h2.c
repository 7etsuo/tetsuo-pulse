/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketGRPCServer-h2.c
 * @brief Unary gRPC server dispatch over HTTP/2.
 */

#include "grpc/SocketGRPC-private.h"
#include "grpc/SocketGRPCWire.h"
#include "core/SocketCrypto.h"
#include "core/SocketUtil/Timeout.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define GRPC_CONTENT_TYPE_PREFIX "application/grpc"
#define GRPC_TRAILER_STATUS "grpc-status"
#define GRPC_TRAILER_MESSAGE "grpc-message"
#define GRPC_TRAILER_STATUS_DETAILS "grpc-status-details-bin"

typedef enum
{
  GRPC_SERVER_HANDLER_RETURN_CODE = 0,
  GRPC_SERVER_HANDLER_EXCEPTION = 1
} SocketGRPC_ServerHandlerKind;

struct SocketGRPC_ServerMethod
{
  char *full_method;
  SocketGRPC_ServerUnaryHandler handler;
  SocketGRPC_ServerUnaryHandlerExcept handler_except;
  void *userdata;
  SocketGRPC_ServerHandlerKind kind;
  SocketGRPC_ServerMethod *next;
};

struct SocketGRPC_ServerContext
{
  SocketGRPC_Server_T server;
  SocketHTTPServer_Request_T req;
  Arena_T arena;
  const char *peer;
  const char *full_method;
  const char *service;
  const char *method;
  SocketGRPC_Metadata_T metadata;
  SocketGRPC_Trailers_T trailers;
  SocketGRPC_Status status;
  int status_explicit;
  int cancelled;
  int64_t deadline_ms;
};

static int
grpc_status_code_valid (int code)
{
  return code >= SOCKET_GRPC_STATUS_OK
         && code <= SOCKET_GRPC_STATUS_UNAUTHENTICATED;
}

static const char *
grpc_arena_strdup (Arena_T arena, const char *src)
{
  char *dst;
  size_t len;

  if (arena == NULL || src == NULL)
    return NULL;

  len = strlen (src);
  dst = Arena_alloc (arena, len + 1, __FILE__, __LINE__);
  if (dst == NULL)
    return NULL;

  memcpy (dst, src, len + 1);
  return dst;
}

static const char *
grpc_arena_strndup (Arena_T arena, const char *src, size_t len)
{
  char *dst;

  if (arena == NULL || src == NULL)
    return NULL;

  dst = Arena_alloc (arena, len + 1, __FILE__, __LINE__);
  if (dst == NULL)
    return NULL;

  memcpy (dst, src, len);
  dst[len] = '\0';
  return dst;
}

static int
grpc_split_method_path (const char *full_method,
                        const char **service_out,
                        size_t *service_len_out,
                        const char **method_out,
                        size_t *method_len_out)
{
  const char *slash;

  if (full_method == NULL || full_method[0] != '/' || full_method[1] == '\0')
    return -1;
  if (strchr (full_method, '?') != NULL || strchr (full_method, '#') != NULL)
    return -1;

  slash = strchr (full_method + 1, '/');
  if (slash == NULL || slash == full_method + 1 || slash[1] == '\0')
    return -1;
  if (strchr (slash + 1, '/') != NULL)
    return -1;

  if (service_out != NULL)
    *service_out = full_method + 1;
  if (service_len_out != NULL)
    *service_len_out = (size_t)(slash - (full_method + 1));
  if (method_out != NULL)
    *method_out = slash + 1;
  if (method_len_out != NULL)
    *method_len_out = strlen (slash + 1);

  return 0;
}

static int
grpc_content_type_is_valid (const char *value)
{
  const char *suffix;
  size_t prefix_len = strlen (GRPC_CONTENT_TYPE_PREFIX);

  if (value == NULL)
    return 0;
  if (strncasecmp (value, GRPC_CONTENT_TYPE_PREFIX, prefix_len) != 0)
    return 0;

  suffix = value + prefix_len;
  return (*suffix == '\0' || *suffix == ';' || *suffix == '+');
}

static int
grpc_header_token_contains (const char *value, const char *token)
{
  const char *p;
  size_t token_len;

  if (value == NULL || token == NULL)
    return 0;

  token_len = strlen (token);
  p = value;

  while (*p != '\0')
    {
      while (*p == ' ' || *p == '\t' || *p == ',')
        p++;

      if (strncasecmp (p, token, token_len) == 0)
        {
          char next = p[token_len];
          if (next == '\0' || next == ',' || next == ' ' || next == '\t')
            return 1;
        }

      while (*p != '\0' && *p != ',')
        p++;
    }

  return 0;
}

static SocketGRPC_ServerMethod *
grpc_server_find_method (SocketGRPC_Server_T server, const char *full_method)
{
  SocketGRPC_ServerMethod *it;

  if (server == NULL || full_method == NULL)
    return NULL;

  for (it = server->methods; it != NULL; it = it->next)
    {
      if (strcmp (it->full_method, full_method) == 0)
        return it;
    }

  return NULL;
}

void
SocketGRPC_server_methods_clear (SocketGRPC_Server_T server)
{
  SocketGRPC_ServerMethod *it;
  SocketGRPC_ServerMethod *next;

  if (server == NULL)
    return;

  it = server->methods;
  while (it != NULL)
    {
      next = it->next;
      free (it->full_method);
      it->full_method = NULL;
      free (it);
      it = next;
    }

  server->methods = NULL;
  server->method_count = 0;
  server->inflight_calls = 0;
}

static int
grpc_server_register_unary_internal (SocketGRPC_Server_T server,
                                     const char *full_method,
                                     SocketGRPC_ServerUnaryHandler handler,
                                     SocketGRPC_ServerUnaryHandlerExcept
                                         handler_except,
                                     SocketGRPC_ServerHandlerKind kind,
                                     void *userdata)
{
  SocketGRPC_ServerMethod *method;

  if (server == NULL || full_method == NULL)
    return -1;
  if (kind == GRPC_SERVER_HANDLER_RETURN_CODE && handler == NULL)
    return -1;
  if (kind == GRPC_SERVER_HANDLER_EXCEPTION && handler_except == NULL)
    return -1;
  if (grpc_split_method_path (full_method, NULL, NULL, NULL, NULL) != 0)
    return -1;
  if (grpc_server_find_method (server, full_method) != NULL)
    return -1;

  method = calloc (1, sizeof (*method));
  if (method == NULL)
    return -1;

  method->full_method = strdup (full_method);
  if (method->full_method == NULL)
    {
      free (method);
      return -1;
    }

  method->handler = handler;
  method->handler_except = handler_except;
  method->kind = kind;
  method->userdata = userdata;
  method->next = server->methods;
  server->methods = method;
  server->method_count++;

  return 0;
}

int
SocketGRPC_Server_register_unary (SocketGRPC_Server_T server,
                                  const char *full_method,
                                  SocketGRPC_ServerUnaryHandler handler,
                                  void *userdata)
{
  return grpc_server_register_unary_internal (server,
                                              full_method,
                                              handler,
                                              NULL,
                                              GRPC_SERVER_HANDLER_RETURN_CODE,
                                              userdata);
}

int
SocketGRPC_Server_register_unary_except (
    SocketGRPC_Server_T server,
    const char *full_method,
    SocketGRPC_ServerUnaryHandlerExcept handler,
    void *userdata)
{
  return grpc_server_register_unary_internal (server,
                                              full_method,
                                              NULL,
                                              handler,
                                              GRPC_SERVER_HANDLER_EXCEPTION,
                                              userdata);
}

void
SocketGRPC_Server_begin_shutdown (SocketGRPC_Server_T server)
{
  if (server == NULL)
    return;

  server->shutting_down = 1;
}

uint32_t
SocketGRPC_Server_inflight_calls (SocketGRPC_Server_T server)
{
  if (server == NULL)
    return 0;

  return server->inflight_calls;
}

void
SocketGRPC_Server_bind_http2 (SocketGRPC_Server_T server,
                              SocketHTTPServer_T http_server)
{
  if (server == NULL || http_server == NULL)
    return;

  SocketHTTPServer_set_handler (
      http_server, SocketGRPC_Server_handle_http2, server);
}

SocketGRPC_Metadata_T
SocketGRPC_ServerContext_metadata (SocketGRPC_ServerContext_T ctx)
{
  if (ctx == NULL)
    return NULL;
  return ctx->metadata;
}

const char *
SocketGRPC_ServerContext_peer (SocketGRPC_ServerContext_T ctx)
{
  if (ctx == NULL)
    return NULL;
  return ctx->peer;
}

const char *
SocketGRPC_ServerContext_full_method (SocketGRPC_ServerContext_T ctx)
{
  if (ctx == NULL)
    return NULL;
  return ctx->full_method;
}

const char *
SocketGRPC_ServerContext_service (SocketGRPC_ServerContext_T ctx)
{
  if (ctx == NULL)
    return NULL;
  return ctx->service;
}

const char *
SocketGRPC_ServerContext_method (SocketGRPC_ServerContext_T ctx)
{
  if (ctx == NULL)
    return NULL;
  return ctx->method;
}

int
SocketGRPC_ServerContext_is_cancelled (SocketGRPC_ServerContext_T ctx)
{
  if (ctx == NULL)
    return 1;
  if (ctx->deadline_ms > 0 && SocketTimeout_expired (ctx->deadline_ms))
    ctx->cancelled = 1;
  return ctx->cancelled;
}

int
SocketGRPC_ServerContext_set_status (SocketGRPC_ServerContext_T ctx,
                                     SocketGRPC_StatusCode code,
                                     const char *message)
{
  const char *stored = NULL;

  if (ctx == NULL)
    return -1;
  if (!grpc_status_code_valid ((int)code))
    return -1;

  if (message != NULL && message[0] != '\0')
    {
      stored = grpc_arena_strdup (ctx->arena, message);
      if (stored == NULL)
        return -1;
    }

  SocketGRPC_status_set (&ctx->status, code, stored);
  ctx->status_explicit = 1;
  return 0;
}

int
SocketGRPC_ServerContext_set_status_details_bin (SocketGRPC_ServerContext_T ctx,
                                                 const uint8_t *details,
                                                 size_t details_len)
{
  if (ctx == NULL || ctx->trailers == NULL || (details == NULL && details_len != 0))
    return -1;

  return SocketGRPC_Trailers_set_status_details_bin (
             ctx->trailers, details, details_len)
         == SOCKET_GRPC_WIRE_OK
             ? 0
             : -1;
}

int
SocketGRPC_ServerContext_add_trailing_metadata_ascii (
    SocketGRPC_ServerContext_T ctx,
    const char *key,
    const char *value)
{
  SocketGRPC_Metadata_T metadata;

  if (ctx == NULL || ctx->trailers == NULL || key == NULL || value == NULL)
    return -1;

  metadata = SocketGRPC_Trailers_metadata (ctx->trailers);
  if (metadata == NULL)
    return -1;

  return SocketGRPC_Metadata_add_ascii (metadata, key, value)
         == SOCKET_GRPC_WIRE_OK
             ? 0
             : -1;
}

int
SocketGRPC_ServerContext_add_trailing_metadata_binary (
    SocketGRPC_ServerContext_T ctx,
    const char *key,
    const uint8_t *value,
    size_t value_len)
{
  SocketGRPC_Metadata_T metadata;

  if (ctx == NULL || ctx->trailers == NULL || key == NULL
      || (value == NULL && value_len != 0))
    return -1;

  metadata = SocketGRPC_Trailers_metadata (ctx->trailers);
  if (metadata == NULL)
    return -1;

  return SocketGRPC_Metadata_add_binary (metadata, key, value, value_len)
         == SOCKET_GRPC_WIRE_OK
             ? 0
             : -1;
}

static int
grpc_decode_base64_value (const char *value,
                          size_t value_len,
                          uint8_t **decoded_out,
                          size_t *decoded_len_out)
{
  size_t cap;
  uint8_t *decoded;
  ssize_t decoded_len;

  if (value == NULL || decoded_out == NULL || decoded_len_out == NULL)
    return -1;

  cap = SocketCrypto_base64_decoded_size (value_len);
  decoded = malloc (cap > 0 ? cap : 1);
  if (decoded == NULL)
    return -1;

  decoded_len = SocketCrypto_base64_decode (
      value, value_len, decoded, cap > 0 ? cap : 1);
  if (decoded_len < 0)
    {
      free (decoded);
      return -1;
    }

  *decoded_out = decoded;
  *decoded_len_out = (size_t)decoded_len;
  return 0;
}

static char *
grpc_encode_base64_value (const uint8_t *value, size_t value_len)
{
  size_t cap;
  char *encoded;
  ssize_t encoded_len;

  cap = SocketCrypto_base64_encoded_size (value_len);
  encoded = malloc (cap + 1);
  if (encoded == NULL)
    return NULL;

  encoded_len
      = SocketCrypto_base64_encode (value, value_len, encoded, cap + 1);
  if (encoded_len < 0)
    {
      free (encoded);
      return NULL;
    }

  encoded[encoded_len] = '\0';
  return encoded;
}

static int
grpc_header_name_lower (const char *name,
                        size_t name_len,
                        char *out,
                        size_t out_cap)
{
  size_t i;

  if (name == NULL || out == NULL || out_cap == 0 || name_len + 1 > out_cap)
    return -1;

  for (i = 0; i < name_len; i++)
    out[i] = (char)tolower ((unsigned char)name[i]);
  out[name_len] = '\0';

  return 0;
}

static int
grpc_header_reserved (const char *name)
{
  if (name == NULL)
    return 1;
  if (name[0] == ':')
    return 1;
  if (strcmp (name, "content-type") == 0)
    return 1;
  if (strcmp (name, "te") == 0)
    return 1;
  if (strcmp (name, "grpc-timeout") == 0)
    return 1;
  if (strcmp (name, "grpc-encoding") == 0)
    return 1;
  if (strcmp (name, "grpc-accept-encoding") == 0)
    return 1;
  if (strcmp (name, "grpc-message-type") == 0)
    return 1;
  if (strcmp (name, "user-agent") == 0)
    return 1;
  if (strcmp (name, "host") == 0)
    return 1;
  if (strncmp (name, "grpc-", 5) == 0)
    return 1;

  return 0;
}

static int
grpc_metadata_ingest (SocketGRPC_Metadata_T metadata,
                      const char *name,
                      size_t name_len,
                      const char *value,
                      size_t value_len)
{
  char lower_name[SOCKETHTTP_MAX_HEADER_NAME + 1];

  if (metadata == NULL || name == NULL || value == NULL || name_len == 0)
    return -1;
  if (name_len > SOCKETHTTP_MAX_HEADER_NAME)
    return -1;

  if (grpc_header_name_lower (name, name_len, lower_name, sizeof (lower_name))
      != 0)
    return -1;

  if (grpc_header_reserved (lower_name))
    return 0;

  if (SocketGRPC_Metadata_count (metadata) >= SOCKET_GRPC_DEFAULT_MAX_METADATA_ENTRIES)
    return -1;

  if (name_len >= 4 && strcmp (lower_name + name_len - 4, "-bin") == 0)
    {
      uint8_t *decoded = NULL;
      size_t decoded_len = 0;
      SocketGRPC_WireResult rc;

      if (grpc_decode_base64_value (value, value_len, &decoded, &decoded_len)
          != 0)
        return -1;

      rc = SocketGRPC_Metadata_add_binary (
          metadata, lower_name, decoded, decoded_len);
      free (decoded);
      return rc == SOCKET_GRPC_WIRE_OK ? 0 : -1;
    }
  else
    {
      char *ascii;
      SocketGRPC_WireResult rc;

      ascii = malloc (value_len + 1);
      if (ascii == NULL)
        return -1;
      if (value_len > 0)
        memcpy (ascii, value, value_len);
      ascii[value_len] = '\0';

      rc = SocketGRPC_Metadata_add_ascii (metadata, lower_name, ascii);
      free (ascii);
      return rc == SOCKET_GRPC_WIRE_OK ? 0 : -1;
    }
}

static int
grpc_collect_metadata_headers (SocketGRPC_Metadata_T metadata,
                               SocketHTTP_Headers_T headers)
{
  size_t i;
  size_t count;

  if (headers == NULL)
    return 0;

  count = SocketHTTP_Headers_count (headers);
  for (i = 0; i < count; i++)
    {
      const SocketHTTP_Header *hdr = SocketHTTP_Headers_at (headers, i);
      if (hdr == NULL || hdr->name == NULL || hdr->value == NULL)
        continue;
      if (grpc_metadata_ingest (
              metadata, hdr->name, hdr->name_len, hdr->value, hdr->value_len)
          != 0)
        return -1;
    }

  return 0;
}

static int
grpc_context_parse_deadline (SocketGRPC_ServerContext_T ctx,
                             SocketHTTP_Headers_T headers)
{
  const char *timeout_header;
  int64_t timeout_ms = 0;

  if (ctx == NULL || headers == NULL)
    return 0;

  timeout_header = SocketHTTP_Headers_get (headers, "grpc-timeout");
  if (timeout_header == NULL || timeout_header[0] == '\0')
    return 0;

  if (SocketGRPC_Timeout_parse (timeout_header, &timeout_ms) != 0)
    return -1;
  if (timeout_ms <= 0)
    timeout_ms = 1;

  ctx->deadline_ms = SocketTimeout_now_ms () + timeout_ms;
  return 0;
}

static int
grpc_context_init (SocketGRPC_ServerContext_T ctx,
                   SocketGRPC_Server_T server,
                   SocketHTTPServer_Request_T req,
                   const char *full_method)
{
  const char *service = NULL;
  const char *method = NULL;
  size_t service_len = 0;
  size_t method_len = 0;

  if (ctx == NULL || server == NULL || req == NULL || full_method == NULL)
    return -1;

  memset (ctx, 0, sizeof (*ctx));
  ctx->server = server;
  ctx->req = req;
  ctx->arena = SocketHTTPServer_Request_arena (req);
  ctx->peer = SocketHTTPServer_Request_client_addr (req);
  ctx->full_method = full_method;
  ctx->cancelled = 0;
  ctx->deadline_ms = 0;

  if (ctx->arena == NULL)
    return -1;

  ctx->metadata = SocketGRPC_Metadata_new (ctx->arena);
  ctx->trailers = SocketGRPC_Trailers_new (ctx->arena);
  if (ctx->metadata == NULL || ctx->trailers == NULL)
    return -1;

  if (grpc_split_method_path (full_method,
                              &service,
                              &service_len,
                              &method,
                              &method_len)
      != 0)
    return -1;

  ctx->service = grpc_arena_strndup (ctx->arena, service, service_len);
  ctx->method = grpc_arena_strndup (ctx->arena, method, method_len);
  if (ctx->service == NULL || ctx->method == NULL)
    return -1;

  SocketGRPC_status_set (&ctx->status, SOCKET_GRPC_STATUS_OK, NULL);

  if (grpc_collect_metadata_headers (
          ctx->metadata, SocketHTTPServer_Request_headers (req))
      != 0)
    return -1;
  if (grpc_context_parse_deadline (
          ctx, SocketHTTPServer_Request_headers (req))
      != 0)
    return -1;
  if (grpc_collect_metadata_headers (
          ctx->metadata, SocketHTTPServer_Request_trailers (req))
      != 0)
    return -1;

  return 0;
}

static int
grpc_add_ascii_trailer (SocketHTTPServer_Request_T req,
                        const char *key,
                        const char *value,
                        size_t value_len)
{
  char *buf;
  int rc;

  if (req == NULL || key == NULL || value == NULL)
    return -1;

  buf = malloc (value_len + 1);
  if (buf == NULL)
    return -1;

  if (value_len > 0)
    memcpy (buf, value, value_len);
  buf[value_len] = '\0';

  rc = SocketHTTPServer_Request_trailer (req, key, buf);
  free (buf);
  return rc;
}

static void
grpc_emit_custom_trailing_metadata (SocketHTTPServer_Request_T req,
                                    SocketGRPC_Trailers_T trailers)
{
  SocketGRPC_Metadata_T metadata;
  size_t i;
  size_t count;

  if (req == NULL || trailers == NULL)
    return;

  metadata = SocketGRPC_Trailers_metadata (trailers);
  if (metadata == NULL)
    return;

  count = SocketGRPC_Metadata_count (metadata);
  for (i = 0; i < count; i++)
    {
      const SocketGRPC_MetadataEntry *entry = SocketGRPC_Metadata_at (metadata, i);
      if (entry == NULL || entry->key == NULL || entry->value == NULL)
        continue;

      if (entry->is_binary)
        {
          char *encoded = grpc_encode_base64_value (entry->value, entry->value_len);
          if (encoded == NULL)
            continue;
          (void)SocketHTTPServer_Request_trailer (req, entry->key, encoded);
          free (encoded);
        }
      else
        {
          (void)grpc_add_ascii_trailer (
              req, entry->key, (const char *)entry->value, entry->value_len);
        }
    }
}

static void
grpc_emit_status_trailers (SocketHTTPServer_Request_T req,
                           SocketGRPC_StatusCode status,
                           const char *message,
                           SocketGRPC_Trailers_T extra_trailers)
{
  char status_buf[16];
  int n;

  if (req == NULL)
    return;

  n = snprintf (status_buf, sizeof (status_buf), "%d", (int)status);
  if (n > 0 && (size_t)n < sizeof (status_buf))
    (void)SocketHTTPServer_Request_trailer (req, GRPC_TRAILER_STATUS, status_buf);

  if (message != NULL && message[0] != '\0')
    (void)SocketHTTPServer_Request_trailer (req, GRPC_TRAILER_MESSAGE, message);

  if (extra_trailers != NULL)
    {
      size_t details_len = 0;
      const uint8_t *details
          = SocketGRPC_Trailers_status_details_bin (extra_trailers, &details_len);
      if (details != NULL && details_len > 0)
        {
          char *encoded = grpc_encode_base64_value (details, details_len);
          if (encoded != NULL)
            {
              (void)SocketHTTPServer_Request_trailer (
                  req, GRPC_TRAILER_STATUS_DETAILS, encoded);
              free (encoded);
            }
        }

      grpc_emit_custom_trailing_metadata (req, extra_trailers);
    }
}

static void
grpc_send_unary_response (SocketHTTPServer_Request_T req,
                          int http_status,
                          const uint8_t *response_payload,
                          size_t response_payload_len,
                          SocketGRPC_StatusCode grpc_status,
                          const char *grpc_message,
                          SocketGRPC_Trailers_T extra_trailers)
{
  uint8_t *framed = NULL;
  size_t framed_len = 0;
  size_t framed_cap = 0;
  Arena_T arena;

  if (req == NULL)
    return;

  SocketHTTPServer_Request_status (req, http_status);
  SocketHTTPServer_Request_header (req, "content-type", GRPC_CONTENT_TYPE_PREFIX);
  SocketHTTPServer_Request_header (req, "grpc-encoding", "identity");

  if (grpc_status == SOCKET_GRPC_STATUS_OK)
    {
      if (response_payload == NULL && response_payload_len != 0)
        {
          grpc_status = SOCKET_GRPC_STATUS_INTERNAL;
          grpc_message = "Unary handler returned invalid response payload";
        }
      else if (response_payload_len > SOCKET_GRPC_DEFAULT_MAX_OUTBOUND_MESSAGE_BYTES
               || response_payload_len > (size_t)UINT32_MAX)
        {
          grpc_status = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
          grpc_message = "Unary response exceeds configured limit";
        }
      else
        {
          arena = SocketHTTPServer_Request_arena (req);
          framed_cap = SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE + response_payload_len;
          framed = Arena_alloc (arena, framed_cap, __FILE__, __LINE__);
          if (framed == NULL
              || SocketGRPC_Frame_encode (0,
                                          response_payload,
                                          (uint32_t)response_payload_len,
                                          framed,
                                          framed_cap,
                                          &framed_len)
                     != SOCKET_GRPC_WIRE_OK)
            {
              grpc_status = SOCKET_GRPC_STATUS_INTERNAL;
              grpc_message = "Failed to frame unary response";
            }
          else if (framed_len > 0)
            {
              SocketHTTPServer_Request_body_data (req, framed, framed_len);
            }
        }
    }

  grpc_emit_status_trailers (
      req, grpc_status, grpc_message, extra_trailers);
  SocketHTTPServer_Request_finish (req);
}

static void
grpc_send_plain_http_error (SocketHTTPServer_Request_T req,
                            int http_status,
                            const char *message)
{
  if (req == NULL)
    return;

  SocketHTTPServer_Request_status (req, http_status);
  SocketHTTPServer_Request_header (req, "content-type", "text/plain");
  if (message != NULL)
    SocketHTTPServer_Request_body_string (req, message);
  SocketHTTPServer_Request_finish (req);
}

static int
grpc_parse_unary_request_payload (SocketHTTPServer_Request_T req,
                                  const uint8_t **payload_out,
                                  size_t *payload_len_out,
                                  int *compressed_out)
{
  const uint8_t *raw;
  size_t raw_len;
  SocketGRPC_FrameView frame;
  size_t consumed = 0;

  if (req == NULL || payload_out == NULL || payload_len_out == NULL
      || compressed_out == NULL)
    return -1;

  raw = SocketHTTPServer_Request_body (req);
  raw_len = SocketHTTPServer_Request_body_len (req);
  if (raw == NULL || raw_len == 0)
    return -1;

  if (SocketGRPC_Frame_parse (raw,
                              raw_len,
                              SOCKET_GRPC_DEFAULT_MAX_INBOUND_MESSAGE_BYTES,
                              &frame,
                              &consumed)
      != SOCKET_GRPC_WIRE_OK)
    return -1;
  if (consumed != raw_len)
    return -1;

  *payload_out = frame.payload;
  *payload_len_out = frame.payload_len;
  *compressed_out = frame.compressed;
  return 0;
}

static int
grpc_invoke_handler (SocketGRPC_ServerMethod *method,
                     SocketGRPC_ServerContext_T ctx,
                     const uint8_t *request_payload,
                     size_t request_payload_len,
                     uint8_t **response_payload,
                     size_t *response_payload_len)
{
  volatile int rc = SOCKET_GRPC_STATUS_INTERNAL;

  if (method == NULL || ctx == NULL || response_payload == NULL
      || response_payload_len == NULL)
    return SOCKET_GRPC_STATUS_INTERNAL;

  TRY
  {
    if (method->kind == GRPC_SERVER_HANDLER_RETURN_CODE)
      {
        rc = method->handler (ctx,
                              request_payload,
                              request_payload_len,
                              ctx->arena,
                              response_payload,
                              response_payload_len,
                              method->userdata);
      }
    else
      {
        method->handler_except (ctx,
                                request_payload,
                                request_payload_len,
                                ctx->arena,
                                response_payload,
                                response_payload_len,
                                method->userdata);
        rc = SOCKET_GRPC_STATUS_OK;
      }
  }
  ELSE
  {
    rc = SOCKET_GRPC_STATUS_INTERNAL;
    if (!ctx->status_explicit)
      {
        if (Except_frame.exception != NULL
            && Except_frame.exception->reason != NULL)
          {
            (void)SocketGRPC_ServerContext_set_status (
                ctx,
                SOCKET_GRPC_STATUS_INTERNAL,
                Except_frame.exception->reason);
          }
        else
          {
            (void)SocketGRPC_ServerContext_set_status (
                ctx,
                SOCKET_GRPC_STATUS_INTERNAL,
                "Unhandled exception in unary handler");
          }
      }
  }
  END_TRY;

  return (int)rc;
}

static SocketGRPC_StatusCode
grpc_resolve_final_status (SocketGRPC_ServerContext_T ctx,
                           int handler_rc,
                           const char **message_out)
{
  if (message_out != NULL)
    *message_out = NULL;

  if (ctx != NULL && ctx->status_explicit)
    {
      if (message_out != NULL)
        *message_out = ctx->status.message;
      return ctx->status.code;
    }

  if (grpc_status_code_valid (handler_rc))
    return (SocketGRPC_StatusCode)handler_rc;

  if (message_out != NULL)
    *message_out = "Unary handler returned invalid status code";
  return SOCKET_GRPC_STATUS_INTERNAL;
}

void
SocketGRPC_Server_handle_http2 (SocketHTTPServer_Request_T req, void *userdata)
{
  SocketGRPC_Server_T server = (SocketGRPC_Server_T)userdata;
  SocketHTTP_Headers_T headers;
  const char *full_method;
  const char *content_type;
  const char *te_header;
  SocketGRPC_ServerMethod *method;
  struct SocketGRPC_ServerContext ctx;
  const uint8_t *request_payload = NULL;
  size_t request_payload_len = 0;
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  int compressed = 0;
  int handler_rc;
  SocketGRPC_StatusCode grpc_status;
  const char *grpc_message = NULL;

  if (req == NULL)
    return;

  if (server == NULL)
    {
      grpc_send_plain_http_error (
          req, HTTP_STATUS_INTERNAL_ERROR, "gRPC server context unavailable");
      return;
    }

  if (!SocketHTTPServer_Request_is_http2 (req))
    {
      grpc_send_plain_http_error (
          req, HTTP_STATUS_VERSION_NOT_SUPPORTED, "Unary gRPC requires HTTP/2");
      return;
    }

  if (server->shutting_down)
    {
      grpc_send_unary_response (req,
                                HTTP_STATUS_OK,
                                NULL,
                                0,
                                SOCKET_GRPC_STATUS_UNAVAILABLE,
                                "Server is shutting down",
                                NULL);
      return;
    }

  if (SocketHTTPServer_Request_method (req) != HTTP_METHOD_POST)
    {
      grpc_send_unary_response (req,
                                HTTP_STATUS_OK,
                                NULL,
                                0,
                                SOCKET_GRPC_STATUS_UNIMPLEMENTED,
                                "Unary gRPC requires POST",
                                NULL);
      return;
    }

  full_method = SocketHTTPServer_Request_path (req);
  if (grpc_split_method_path (full_method, NULL, NULL, NULL, NULL) != 0)
    {
      grpc_send_unary_response (req,
                                HTTP_STATUS_OK,
                                NULL,
                                0,
                                SOCKET_GRPC_STATUS_UNIMPLEMENTED,
                                "Invalid gRPC method path",
                                NULL);
      return;
    }

  headers = SocketHTTPServer_Request_headers (req);
  content_type = SocketHTTP_Headers_get (headers, "content-type");
  if (!grpc_content_type_is_valid (content_type))
    {
      grpc_send_plain_http_error (
          req, HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE, "Invalid content-type for gRPC");
      return;
    }

  te_header = SocketHTTP_Headers_get (headers, "te");
  if (te_header != NULL && !grpc_header_token_contains (te_header, "trailers"))
    {
      grpc_send_plain_http_error (
          req, HTTP_STATUS_BAD_REQUEST, "Invalid te header for gRPC request");
      return;
    }

  method = grpc_server_find_method (server, full_method);
  if (method == NULL)
    {
      grpc_send_unary_response (req,
                                HTTP_STATUS_OK,
                                NULL,
                                0,
                                SOCKET_GRPC_STATUS_UNIMPLEMENTED,
                                "Unknown gRPC method",
                                NULL);
      return;
    }

  if (grpc_parse_unary_request_payload (
          req, &request_payload, &request_payload_len, &compressed)
      != 0)
    {
      grpc_send_plain_http_error (
          req, HTTP_STATUS_BAD_REQUEST, "Malformed unary gRPC request frame");
      return;
    }

  if (compressed != 0)
    {
      grpc_send_plain_http_error (
          req, HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE, "Compressed gRPC requests unsupported");
      return;
    }

  if (grpc_context_init (&ctx, server, req, full_method) != 0)
    {
      grpc_send_unary_response (req,
                                HTTP_STATUS_OK,
                                NULL,
                                0,
                                SOCKET_GRPC_STATUS_INTERNAL,
                                "Failed to initialize unary server context",
                                NULL);
      return;
    }

  if (SocketGRPC_ServerContext_is_cancelled (&ctx))
    {
      grpc_send_unary_response (req,
                                HTTP_STATUS_OK,
                                NULL,
                                0,
                                SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
                                "Deadline exceeded",
                                ctx.trailers);
      return;
    }

  response_payload = NULL;
  response_payload_len = 0;

  server->inflight_calls++;
  handler_rc = grpc_invoke_handler (method,
                                    &ctx,
                                    request_payload,
                                    request_payload_len,
                                    &response_payload,
                                    &response_payload_len);
  if (server->inflight_calls > 0)
    server->inflight_calls--;

  grpc_status = grpc_resolve_final_status (&ctx, handler_rc, &grpc_message);
  if (grpc_status == SOCKET_GRPC_STATUS_OK
      && SocketGRPC_ServerContext_is_cancelled (&ctx))
    {
      grpc_status = SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED;
      grpc_message = "Deadline exceeded";
    }

  if (grpc_status != SOCKET_GRPC_STATUS_OK)
    {
      response_payload = NULL;
      response_payload_len = 0;
    }

  grpc_send_unary_response (req,
                            HTTP_STATUS_OK,
                            response_payload,
                            response_payload_len,
                            grpc_status,
                            grpc_message,
                            ctx.trailers);
}

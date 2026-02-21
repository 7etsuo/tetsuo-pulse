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
#include "core/SocketMetrics.h"
#include "core/SocketUtil.h"
#if SOCKET_HAS_TLS
#include "http/SocketHTTP3-server.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define GRPC_CONTENT_TYPE_PREFIX "application/grpc"
#define GRPC_TRAILER_STATUS "grpc-status"
#define GRPC_TRAILER_MESSAGE "grpc-message"
#define GRPC_TRAILER_STATUS_DETAILS "grpc-status-details-bin"
#define GRPC_MAX_INTERCEPTORS 64U
#define GRPC_H3_BODY_CHUNK 4096U

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

struct SocketGRPC_ServerUnaryInterceptorEntry
{
  SocketGRPC_ServerUnaryInterceptor interceptor;
  void *userdata;
  SocketGRPC_ServerUnaryInterceptorEntry *next;
};

struct SocketGRPC_ServerContext
{
  SocketGRPC_Server_T server;
  SocketHTTPServer_Request_T req;
  const char *authority;
  Arena_T arena;
  int owns_arena;
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
grpc_server_observability_enabled (SocketGRPC_Server_T server)
{
  return server != NULL && server->config.enable_observability;
}

static const char *
grpc_server_request_authority (SocketHTTPServer_Request_T req)
{
  SocketHTTP_Headers_T headers;
  const char *authority;

  if (req == NULL)
    return NULL;

  headers = SocketHTTPServer_Request_headers (req);
  authority = SocketHTTP_Headers_get_n (
      headers, ":authority", STRLEN_LIT (":authority"));
  if (authority != NULL && authority[0] != '\0')
    return authority;

  authority = SocketHTTP_Headers_get_n (headers, "host", STRLEN_LIT ("host"));
  if (authority != NULL && authority[0] != '\0')
    return authority;
  return NULL;
}

static SocketCounterMetric
grpc_server_status_counter_metric (SocketGRPC_StatusCode code)
{
  SocketGRPC_StatusCode normalized = grpc_normalize_status_code (code);
  return (SocketCounterMetric)(SOCKET_CTR_GRPC_SERVER_STATUS_OK
                               + (int)normalized);
}

static void
grpc_server_emit_observability_event (SocketGRPC_Server_T server,
                                      SocketHTTPServer_Request_T req,
                                      const char *full_method,
                                      SocketGRPC_LogEventType type,
                                      SocketGRPC_StatusCode status_code,
                                      const char *status_message,
                                      size_t payload_len,
                                      int64_t duration_ms)
{
  SocketGRPC_LogEvent event;
  SocketGRPC_StatusCode code;
  const char *message;

  if (!grpc_server_observability_enabled (server))
    return;
  if (server == NULL || server->observability_hook == NULL || req == NULL)
    return;

  code = grpc_normalize_status_code (status_code);
  message = (status_message != NULL && status_message[0] != '\0')
                ? status_message
                : SocketGRPC_status_default_message (code);

  event.type = type;
  event.full_method = full_method;
  event.status_code = code;
  event.status_message = message;
  event.payload_len = payload_len;
  event.attempt = 1U;
  event.peer = SocketHTTPServer_Request_client_addr (req);
  event.authority = grpc_server_request_authority (req);
  event.duration_ms = duration_ms;
  server->observability_hook (&event, server->observability_hook_userdata);
}

static int
grpc_server_observability_call_started (SocketGRPC_Server_T server,
                                        SocketHTTPServer_Request_T req,
                                        const char *full_method,
                                        size_t request_payload_len,
                                        int64_t *started_ms_out)
{
  if (started_ms_out != NULL)
    *started_ms_out = 0;
  if (!grpc_server_observability_enabled (server))
    return 0;

  if (started_ms_out != NULL)
    *started_ms_out = SocketTimeout_now_ms ();
  SocketMetrics_counter_inc (SOCKET_CTR_GRPC_SERVER_CALLS_STARTED);
  if (request_payload_len > 0)
    {
      SocketMetrics_counter_add (SOCKET_CTR_GRPC_SERVER_BYTES_RECEIVED,
                                 (uint64_t)request_payload_len);
    }
  grpc_server_emit_observability_event (server,
                                        req,
                                        full_method,
                                        SOCKET_GRPC_LOG_EVENT_SERVER_CALL_START,
                                        SOCKET_GRPC_STATUS_OK,
                                        NULL,
                                        request_payload_len,
                                        -1);
  return 1;
}

static void
grpc_server_observability_call_finished (SocketGRPC_Server_T server,
                                         SocketHTTPServer_Request_T req,
                                         const char *full_method,
                                         int started,
                                         int *finished_io,
                                         int64_t started_ms,
                                         SocketGRPC_StatusCode status_code,
                                         const char *status_message,
                                         size_t response_payload_len)
{
  SocketGRPC_StatusCode code;
  const char *message;
  int64_t duration_ms = -1;

  if (!started)
    return;
  if (finished_io != NULL && *finished_io)
    return;
  if (finished_io != NULL)
    *finished_io = 1;
  if (!grpc_server_observability_enabled (server))
    return;

  code = grpc_normalize_status_code (status_code);
  message = (status_message != NULL && status_message[0] != '\0')
                ? status_message
                : SocketGRPC_status_default_message (code);
  if (started_ms > 0)
    {
      duration_ms = SocketTimeout_elapsed_ms (started_ms);
      if (duration_ms < 0)
        duration_ms = 0;
      SocketMetrics_histogram_observe (SOCKET_HIST_GRPC_SERVER_CALL_LATENCY_MS,
                                       (double)duration_ms);
    }
  if (response_payload_len > 0)
    {
      SocketMetrics_counter_add (SOCKET_CTR_GRPC_SERVER_BYTES_SENT,
                                 (uint64_t)response_payload_len);
    }

  SocketMetrics_counter_inc (SOCKET_CTR_GRPC_SERVER_CALLS_COMPLETED);
  SocketMetrics_counter_inc (grpc_server_status_counter_metric (code));
  grpc_server_emit_observability_event (
      server,
      req,
      full_method,
      SOCKET_GRPC_LOG_EVENT_SERVER_CALL_FINISH,
      code,
      message,
      response_payload_len,
      duration_ms);
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

void
SocketGRPC_server_interceptors_clear (SocketGRPC_Server_T server)
{
  SocketGRPC_ServerUnaryInterceptorEntry *it;
  SocketGRPC_ServerUnaryInterceptorEntry *next;

  if (server == NULL)
    return;

  it = server->unary_interceptors;
  while (it != NULL)
    {
      next = it->next;
      free (it);
      it = next;
    }

  server->unary_interceptors = NULL;
  server->unary_interceptors_tail = NULL;
  server->unary_interceptor_count = 0;
}

static int
grpc_server_register_unary_internal (
    SocketGRPC_Server_T server,
    const char *full_method,
    SocketGRPC_ServerUnaryHandler handler,
    SocketGRPC_ServerUnaryHandlerExcept handler_except,
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

int
SocketGRPC_Server_add_unary_interceptor (
    SocketGRPC_Server_T server,
    SocketGRPC_ServerUnaryInterceptor interceptor,
    void *userdata)
{
  SocketGRPC_ServerUnaryInterceptorEntry *entry;

  if (server == NULL || interceptor == NULL)
    return -1;
  if (server->unary_interceptor_count >= GRPC_MAX_INTERCEPTORS)
    return -1;

  entry = (SocketGRPC_ServerUnaryInterceptorEntry *)calloc (1, sizeof (*entry));
  if (entry == NULL)
    return -1;

  entry->interceptor = interceptor;
  entry->userdata = userdata;
  if (server->unary_interceptors_tail == NULL)
    {
      server->unary_interceptors = entry;
      server->unary_interceptors_tail = entry;
    }
  else
    {
      server->unary_interceptors_tail->next = entry;
      server->unary_interceptors_tail = entry;
    }
  server->unary_interceptor_count++;
  return 0;
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
  if (ctx == NULL || ctx->trailers == NULL
      || (details == NULL && details_len != 0))
    return -1;

  return SocketGRPC_Trailers_set_status_details_bin (
             ctx->trailers, details, details_len)
                 == SOCKET_GRPC_WIRE_OK
             ? 0
             : -1;
}

int
SocketGRPC_ServerContext_add_trailing_metadata_ascii (
    SocketGRPC_ServerContext_T ctx, const char *key, const char *value)
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

static void
grpc_interceptor_status_set (SocketGRPC_Status *status,
                             SocketGRPC_StatusCode code,
                             const char *message)
{
  if (status == NULL)
    return;
  SocketGRPC_status_set (status, code, message);
}

static const SocketGRPC_MetadataEntry *
grpc_context_find_ascii_metadata (SocketGRPC_ServerContext_T ctx,
                                  const char *key)
{
  SocketGRPC_Metadata_T metadata;
  size_t i;
  size_t count;

  if (ctx == NULL || key == NULL)
    return NULL;
  metadata = SocketGRPC_ServerContext_metadata (ctx);
  if (metadata == NULL)
    return NULL;

  count = SocketGRPC_Metadata_count (metadata);
  for (i = 0; i < count; i++)
    {
      const SocketGRPC_MetadataEntry *entry
          = SocketGRPC_Metadata_at (metadata, i);
      if (entry == NULL || entry->key == NULL || entry->value == NULL
          || entry->is_binary)
        {
          continue;
        }
      if (strcasecmp (entry->key, key) == 0)
        return entry;
    }

  return NULL;
}

int
SocketGRPC_Interceptor_server_auth_token_validator (
    SocketGRPC_ServerContext_T ctx,
    const uint8_t *request_payload,
    size_t request_payload_len,
    SocketGRPC_Status *status_io,
    void *userdata)
{
  const SocketGRPC_AuthTokenValidatorConfig *cfg
      = (const SocketGRPC_AuthTokenValidatorConfig *)userdata;
  const SocketGRPC_MetadataEntry *token_entry;
  const char *metadata_key = "authorization";
  int valid = 0;

  (void)request_payload;
  (void)request_payload_len;

  if (ctx == NULL || cfg == NULL || cfg->validator == NULL)
    {
      grpc_interceptor_status_set (
          status_io,
          SOCKET_GRPC_STATUS_INTERNAL,
          "Invalid auth token validator interceptor config");
      return SOCKET_GRPC_INTERCEPT_STOP;
    }
  if (cfg->metadata_key != NULL && cfg->metadata_key[0] != '\0')
    metadata_key = cfg->metadata_key;

  token_entry = grpc_context_find_ascii_metadata (ctx, metadata_key);
  if (token_entry == NULL)
    {
      grpc_interceptor_status_set (status_io,
                                   SOCKET_GRPC_STATUS_UNAUTHENTICATED,
                                   "Missing authorization token");
      return SOCKET_GRPC_INTERCEPT_STOP;
    }

  valid = cfg->validator (
      ctx, token_entry->value, token_entry->value_len, cfg->validator_userdata);
  if (!valid)
    {
      grpc_interceptor_status_set (status_io,
                                   SOCKET_GRPC_STATUS_UNAUTHENTICATED,
                                   "Invalid authorization token");
      return SOCKET_GRPC_INTERCEPT_STOP;
    }

  return SOCKET_GRPC_INTERCEPT_CONTINUE;
}

int
SocketGRPC_Interceptor_server_logging (SocketGRPC_ServerContext_T ctx,
                                       const uint8_t *request_payload,
                                       size_t request_payload_len,
                                       SocketGRPC_Status *status_io,
                                       void *userdata)
{
  const SocketGRPC_LogHookConfig *cfg
      = (const SocketGRPC_LogHookConfig *)userdata;
  SocketGRPC_LogEvent event;

  (void)request_payload;
  if (cfg == NULL || cfg->hook == NULL)
    return SOCKET_GRPC_INTERCEPT_CONTINUE;

  event.type = SOCKET_GRPC_LOG_EVENT_SERVER_UNARY;
  event.full_method = SocketGRPC_ServerContext_full_method (ctx);
  event.status_code
      = status_io != NULL ? status_io->code : SOCKET_GRPC_STATUS_OK;
  event.status_message = status_io != NULL ? status_io->message : NULL;
  event.payload_len = request_payload_len;
  event.attempt = 0U;
  event.peer = SocketGRPC_ServerContext_peer (ctx);
  event.authority = (ctx != NULL) ? ctx->authority : NULL;
  event.duration_ms = -1;
  cfg->hook (&event, cfg->hook_userdata);
  return SOCKET_GRPC_INTERCEPT_CONTINUE;
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

  encoded_len = SocketCrypto_base64_encode (value, value_len, encoded, cap + 1);
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

  if (SocketGRPC_Metadata_count (metadata)
      >= SOCKET_GRPC_DEFAULT_MAX_METADATA_ENTRIES)
    return -1;

  if (name_len >= 4 && strcmp (lower_name + name_len - 4, "-bin") == 0)
    {
      uint8_t *decoded = NULL;
      size_t decoded_len = 0;
      SocketGRPC_WireResult rc;

      if (grpc_decode_base64 (value, value_len, &decoded, &decoded_len) != 0)
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

  timeout_header = SocketHTTP_Headers_get_n (
      headers, "grpc-timeout", STRLEN_LIT ("grpc-timeout"));
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
  ctx->authority = grpc_server_request_authority (req);
  ctx->arena = SocketHTTPServer_Request_arena (req);
  ctx->owns_arena = 0;
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

  if (grpc_split_method_path (
          full_method, &service, &service_len, &method, &method_len)
      != 0)
    return -1;

  ctx->service = grpc_arena_strndup (ctx->arena, service, service_len);
  ctx->method = grpc_arena_strndup (ctx->arena, method, method_len);
  if (ctx->service == NULL || ctx->method == NULL)
    return -1;

  SocketGRPC_status_set (&ctx->status, SOCKET_GRPC_STATUS_OK, NULL);

  if (grpc_collect_metadata_headers (ctx->metadata,
                                     SocketHTTPServer_Request_headers (req))
      != 0)
    return -1;
  if (grpc_context_parse_deadline (ctx, SocketHTTPServer_Request_headers (req))
      != 0)
    return -1;
  if (grpc_collect_metadata_headers (ctx->metadata,
                                     SocketHTTPServer_Request_trailers (req))
      != 0)
    return -1;

  return 0;
}

#if SOCKET_HAS_TLS
static int
grpc_context_init_h3 (SocketGRPC_ServerContext_T ctx,
                      SocketGRPC_Server_T server,
                      SocketHTTP3_Request_T req,
                      const SocketHTTP_Headers_T headers,
                      const char *full_method)
{
  const char *service = NULL;
  const char *method = NULL;
  size_t service_len = 0;
  size_t method_len = 0;
  const char *authority = NULL;
  SocketHTTP_Headers_T req_trailers = NULL;

  if (ctx == NULL || server == NULL || req == NULL || headers == NULL
      || full_method == NULL)
    return -1;

  memset (ctx, 0, sizeof (*ctx));
  ctx->server = server;
  ctx->req = NULL;
  ctx->arena = Arena_new ();
  ctx->owns_arena = 1;
  ctx->cancelled = 0;
  ctx->deadline_ms = 0;
  ctx->full_method = full_method;

  if (ctx->arena == NULL)
    return -1;

  authority = SocketHTTP_Headers_get_n (
      headers, ":authority", STRLEN_LIT (":authority"));
  if (authority == NULL || authority[0] == '\0')
    authority = SocketHTTP_Headers_get_n (headers, "host", STRLEN_LIT ("host"));
  if (authority != NULL && authority[0] != '\0')
    {
      ctx->authority = grpc_arena_strdup (ctx->arena, authority);
      ctx->peer = ctx->authority;
    }
  else
    {
      ctx->authority = grpc_arena_strdup (ctx->arena, "unknown");
      ctx->peer = grpc_arena_strdup (ctx->arena, "http3-peer");
    }

  ctx->metadata = SocketGRPC_Metadata_new (ctx->arena);
  ctx->trailers = SocketGRPC_Trailers_new (ctx->arena);
  if (ctx->metadata == NULL || ctx->trailers == NULL || ctx->authority == NULL
      || ctx->peer == NULL)
    return -1;

  if (grpc_split_method_path (
          full_method, &service, &service_len, &method, &method_len)
      != 0)
    return -1;

  ctx->service = grpc_arena_strndup (ctx->arena, service, service_len);
  ctx->method = grpc_arena_strndup (ctx->arena, method, method_len);
  if (ctx->service == NULL || ctx->method == NULL)
    return -1;

  SocketGRPC_status_set (&ctx->status, SOCKET_GRPC_STATUS_OK, NULL);

  if (grpc_collect_metadata_headers (ctx->metadata,
                                     (SocketHTTP_Headers_T)headers)
      != 0)
    return -1;
  if (grpc_context_parse_deadline (ctx, (SocketHTTP_Headers_T)headers) != 0)
    return -1;

  if (SocketHTTP3_Request_recv_trailers (req, &req_trailers) == 0
      && req_trailers != NULL)
    {
      if (grpc_collect_metadata_headers (ctx->metadata, req_trailers) != 0)
        return -1;
    }

  return 0;
}
#endif

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
      const SocketGRPC_MetadataEntry *entry
          = SocketGRPC_Metadata_at (metadata, i);
      if (entry == NULL || entry->key == NULL || entry->value == NULL)
        continue;

      if (entry->is_binary)
        {
          char *encoded
              = grpc_encode_base64_value (entry->value, entry->value_len);
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

#if SOCKET_HAS_TLS
static void
grpc_emit_custom_trailing_metadata_h3 (SocketHTTP_Headers_T trailer_headers,
                                       SocketGRPC_Trailers_T trailers)
{
  SocketGRPC_Metadata_T metadata;
  size_t i;
  size_t count;

  if (trailer_headers == NULL || trailers == NULL)
    return;

  metadata = SocketGRPC_Trailers_metadata (trailers);
  if (metadata == NULL)
    return;

  count = SocketGRPC_Metadata_count (metadata);
  for (i = 0; i < count; i++)
    {
      const SocketGRPC_MetadataEntry *entry
          = SocketGRPC_Metadata_at (metadata, i);
      if (entry == NULL || entry->key == NULL || entry->value == NULL)
        continue;

      if (entry->is_binary)
        {
          char *encoded
              = grpc_encode_base64_value (entry->value, entry->value_len);
          if (encoded == NULL)
            continue;
          (void)SocketHTTP_Headers_add_n (trailer_headers,
                                          entry->key,
                                          strlen (entry->key),
                                          encoded,
                                          strlen (encoded));
          free (encoded);
        }
      else
        {
          (void)SocketHTTP_Headers_add_n (trailer_headers,
                                          entry->key,
                                          strlen (entry->key),
                                          (const char *)entry->value,
                                          entry->value_len);
        }
    }
}

static void
grpc_emit_status_trailers_h3 (SocketHTTP3_Request_T req,
                              SocketGRPC_StatusCode status,
                              const char *message,
                              SocketGRPC_Trailers_T extra_trailers)
{
  Arena_T arena;
  SocketHTTP_Headers_T trailer_headers;
  char status_buf[16];
  int n;

  if (req == NULL)
    return;

  arena = Arena_new ();
  if (arena == NULL)
    return;

  trailer_headers = SocketHTTP_Headers_new (arena);
  if (trailer_headers == NULL)
    {
      Arena_dispose (&arena);
      return;
    }

  n = snprintf (status_buf, sizeof (status_buf), "%d", (int)status);
  if (n > 0 && (size_t)n < sizeof (status_buf))
    {
      (void)SocketHTTP_Headers_add_n (trailer_headers,
                                      GRPC_TRAILER_STATUS,
                                      strlen (GRPC_TRAILER_STATUS),
                                      status_buf,
                                      (size_t)n);
    }

  if (message != NULL && message[0] != '\0')
    {
      (void)SocketHTTP_Headers_add_n (trailer_headers,
                                      GRPC_TRAILER_MESSAGE,
                                      strlen (GRPC_TRAILER_MESSAGE),
                                      message,
                                      strlen (message));
    }

  if (extra_trailers != NULL)
    {
      size_t details_len = 0;
      const uint8_t *details = SocketGRPC_Trailers_status_details_bin (
          extra_trailers, &details_len);
      if (details != NULL && details_len > 0)
        {
          char *encoded = grpc_encode_base64_value (details, details_len);
          if (encoded != NULL)
            {
              (void)SocketHTTP_Headers_add_n (
                  trailer_headers,
                  GRPC_TRAILER_STATUS_DETAILS,
                  strlen (GRPC_TRAILER_STATUS_DETAILS),
                  encoded,
                  strlen (encoded));
              free (encoded);
            }
        }

      grpc_emit_custom_trailing_metadata_h3 (trailer_headers, extra_trailers);
    }

  (void)SocketHTTP3_Request_send_trailers (req, trailer_headers);
  Arena_dispose (&arena);
}

static void
grpc_send_unary_response_h3 (SocketHTTP3_Request_T req,
                             int http_status,
                             const uint8_t *response_payload,
                             size_t response_payload_len,
                             SocketGRPC_StatusCode grpc_status,
                             const char *grpc_message,
                             SocketGRPC_Trailers_T extra_trailers)
{
  Arena_T arena;
  SocketHTTP_Headers_T headers;
  uint8_t *framed = NULL;
  size_t framed_len = 0;
  size_t framed_cap = 0;
  char status_code_buf[4];
  int n;

  if (req == NULL)
    return;

  arena = Arena_new ();
  if (arena == NULL)
    return;

  headers = SocketHTTP_Headers_new (arena);
  if (headers == NULL)
    {
      Arena_dispose (&arena);
      return;
    }

  n = snprintf (status_code_buf, sizeof (status_code_buf), "%03d", http_status);
  if (n <= 0 || (size_t)n >= sizeof (status_code_buf)
      || SocketHTTP_Headers_add_pseudo_n (
             headers, ":status", 7, status_code_buf, 3)
             != 0
      || SocketHTTP_Headers_add (
             headers, "content-type", GRPC_CONTENT_TYPE_PREFIX)
             != 0
      || SocketHTTP_Headers_add (headers, "grpc-encoding", "identity") != 0
      || SocketHTTP3_Request_send_headers (req, headers, 0) != 0)
    {
      Arena_dispose (&arena);
      return;
    }

  if (grpc_status == SOCKET_GRPC_STATUS_OK)
    {
      if (response_payload == NULL && response_payload_len != 0)
        {
          grpc_status = SOCKET_GRPC_STATUS_INTERNAL;
          grpc_message = "Unary handler returned invalid response payload";
        }
      else if (response_payload_len
                   > SOCKET_GRPC_DEFAULT_MAX_OUTBOUND_MESSAGE_BYTES
               || response_payload_len > (size_t)UINT32_MAX)
        {
          grpc_status = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
          grpc_message = "Unary response exceeds configured limit";
        }
      else
        {
          framed_cap
              = SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE + response_payload_len;
          framed = Arena_alloc (arena, framed_cap, __FILE__, __LINE__);
          if (framed == NULL
              || SocketGRPC_Frame_encode (0,
                                          response_payload,
                                          (uint32_t)response_payload_len,
                                          framed,
                                          framed_cap,
                                          &framed_len)
                     != SOCKET_GRPC_WIRE_OK
              || SocketHTTP3_Request_send_data (req, framed, framed_len, 0)
                     != 0)
            {
              grpc_status = SOCKET_GRPC_STATUS_INTERNAL;
              grpc_message = "Failed to frame unary response";
            }
        }
    }

  grpc_emit_status_trailers_h3 (req, grpc_status, grpc_message, extra_trailers);
  Arena_dispose (&arena);
}

static void
grpc_send_plain_http_error_h3 (SocketHTTP3_Request_T req,
                               int http_status,
                               const char *message)
{
  Arena_T arena;
  SocketHTTP_Headers_T headers;
  char status_code_buf[4];
  int n;

  if (req == NULL)
    return;

  arena = Arena_new ();
  if (arena == NULL)
    return;

  headers = SocketHTTP_Headers_new (arena);
  if (headers == NULL)
    {
      Arena_dispose (&arena);
      return;
    }

  n = snprintf (status_code_buf, sizeof (status_code_buf), "%03d", http_status);
  if (n <= 0 || (size_t)n >= sizeof (status_code_buf)
      || SocketHTTP_Headers_add_pseudo_n (
             headers, ":status", 7, status_code_buf, 3)
             != 0
      || SocketHTTP_Headers_add (headers, "content-type", "text/plain") != 0
      || SocketHTTP3_Request_send_headers (req, headers, 0) != 0)
    {
      Arena_dispose (&arena);
      return;
    }

  if (message != NULL)
    (void)SocketHTTP3_Request_send_data (req, message, strlen (message), 1);
  else
    (void)SocketHTTP3_Request_send_data (req, NULL, 0, 1);

  Arena_dispose (&arena);
}

static int
grpc_parse_unary_request_payload_h3 (const uint8_t *raw,
                                     size_t raw_len,
                                     const uint8_t **payload_out,
                                     size_t *payload_len_out,
                                     int *compressed_out)
{
  SocketGRPC_FrameView frame;
  size_t consumed = 0;

  if (raw == NULL || raw_len == 0 || payload_out == NULL
      || payload_len_out == NULL || compressed_out == NULL)
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
#endif

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
    (void)SocketHTTPServer_Request_trailer (
        req, GRPC_TRAILER_STATUS, status_buf);

  if (message != NULL && message[0] != '\0')
    (void)SocketHTTPServer_Request_trailer (req, GRPC_TRAILER_MESSAGE, message);

  if (extra_trailers != NULL)
    {
      size_t details_len = 0;
      const uint8_t *details = SocketGRPC_Trailers_status_details_bin (
          extra_trailers, &details_len);
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
  SocketHTTPServer_Request_header (
      req, "content-type", GRPC_CONTENT_TYPE_PREFIX);
  SocketHTTPServer_Request_header (req, "grpc-encoding", "identity");

  if (grpc_status == SOCKET_GRPC_STATUS_OK)
    {
      if (response_payload == NULL && response_payload_len != 0)
        {
          grpc_status = SOCKET_GRPC_STATUS_INTERNAL;
          grpc_message = "Unary handler returned invalid response payload";
        }
      else if (response_payload_len
                   > SOCKET_GRPC_DEFAULT_MAX_OUTBOUND_MESSAGE_BYTES
               || response_payload_len > (size_t)UINT32_MAX)
        {
          grpc_status = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
          grpc_message = "Unary response exceeds configured limit";
        }
      else
        {
          arena = SocketHTTPServer_Request_arena (req);
          framed_cap
              = SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE + response_payload_len;
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

  grpc_emit_status_trailers (req, grpc_status, grpc_message, extra_trailers);
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

static int
grpc_run_server_unary_interceptors (SocketGRPC_Server_T server,
                                    SocketGRPC_ServerContext_T ctx,
                                    const uint8_t *request_payload,
                                    size_t request_payload_len,
                                    SocketGRPC_StatusCode *status_out,
                                    const char **message_out)
{
  SocketGRPC_ServerUnaryInterceptorEntry *entry;

  if (status_out != NULL)
    *status_out = SOCKET_GRPC_STATUS_OK;
  if (message_out != NULL)
    *message_out = NULL;

  if (server == NULL || ctx == NULL)
    return -1;

  entry = server->unary_interceptors;
  while (entry != NULL)
    {
      SocketGRPC_Status interceptor_status
          = { SOCKET_GRPC_STATUS_OK,
              SocketGRPC_status_default_message (SOCKET_GRPC_STATUS_OK) };
      int action = entry->interceptor (ctx,
                                       request_payload,
                                       request_payload_len,
                                       &interceptor_status,
                                       entry->userdata);

      if (action == SOCKET_GRPC_INTERCEPT_CONTINUE)
        {
          entry = entry->next;
          continue;
        }

      if (action != SOCKET_GRPC_INTERCEPT_STOP)
        {
          interceptor_status.code = SOCKET_GRPC_STATUS_INTERNAL;
          interceptor_status.message = "Interceptor returned invalid action";
        }
      else if (!grpc_status_code_valid ((int)interceptor_status.code)
               || interceptor_status.code == SOCKET_GRPC_STATUS_OK)
        {
          interceptor_status.code = SOCKET_GRPC_STATUS_INTERNAL;
          interceptor_status.message = "Interceptor returned invalid status";
        }

      if (SocketGRPC_ServerContext_set_status (
              ctx, interceptor_status.code, interceptor_status.message)
          != 0)
        {
          SocketGRPC_status_set (&ctx->status,
                                 SOCKET_GRPC_STATUS_INTERNAL,
                                 "Failed to set interceptor status");
          ctx->status_explicit = 1;
        }

      if (status_out != NULL)
        *status_out = ctx->status.code;
      if (message_out != NULL)
        *message_out = ctx->status.message;
      return 1;
    }

  return 0;
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

static SocketGRPC_ServerMethod *
grpc_h2_validate_request (SocketHTTPServer_Request_T req,
                          SocketGRPC_Server_T server,
                          const char **full_method_out)
{
  SocketHTTP_Headers_T headers;
  const char *full_method;
  const char *content_type;
  const char *te_header;
  SocketGRPC_ServerMethod *method;

  if (server == NULL)
    {
      grpc_send_plain_http_error (
          req, HTTP_STATUS_INTERNAL_ERROR, "gRPC server context unavailable");
      return NULL;
    }

  if (!SocketHTTPServer_Request_is_http2 (req))
    {
      grpc_send_plain_http_error (
          req, HTTP_STATUS_VERSION_NOT_SUPPORTED, "Unary gRPC requires HTTP/2");
      return NULL;
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
      return NULL;
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
      return NULL;
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
      return NULL;
    }

  headers = SocketHTTPServer_Request_headers (req);
  content_type = SocketHTTP_Headers_get_n (
      headers, "content-type", STRLEN_LIT ("content-type"));
  if (!grpc_content_type_is_valid (content_type))
    {
      grpc_send_plain_http_error (req,
                                  HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE,
                                  "Invalid content-type for gRPC");
      return NULL;
    }

  te_header = SocketHTTP_Headers_get_n (headers, "te", STRLEN_LIT ("te"));
  if (te_header != NULL && !grpc_header_token_contains (te_header, "trailers"))
    {
      grpc_send_plain_http_error (
          req, HTTP_STATUS_BAD_REQUEST, "Invalid te header for gRPC request");
      return NULL;
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
      return NULL;
    }

  if (full_method_out != NULL)
    *full_method_out = full_method;
  return method;
}

static int
grpc_h2_parse_and_validate_payload (SocketHTTPServer_Request_T req,
                                    const uint8_t **request_payload_out,
                                    size_t *request_payload_len_out)
{
  const uint8_t *request_payload = NULL;
  size_t request_payload_len = 0;
  int compressed = 0;

  if (grpc_parse_unary_request_payload (
          req, &request_payload, &request_payload_len, &compressed)
      != 0)
    {
      grpc_send_plain_http_error (
          req, HTTP_STATUS_BAD_REQUEST, "Malformed unary gRPC request frame");
      return -1;
    }

  if (compressed != 0)
    {
      grpc_send_plain_http_error (req,
                                  HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE,
                                  "Compressed gRPC requests unsupported");
      return -1;
    }

  *request_payload_out = request_payload;
  *request_payload_len_out = request_payload_len;
  return 0;
}

static void
grpc_h2_dispatch_unary (SocketHTTPServer_Request_T req,
                        SocketGRPC_Server_T server,
                        SocketGRPC_ServerMethod *method,
                        struct SocketGRPC_ServerContext *ctx,
                        const char *full_method,
                        const uint8_t *request_payload,
                        size_t request_payload_len)
{
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  int handler_rc;
  SocketGRPC_StatusCode grpc_status;
  const char *grpc_message = NULL;
  int observability_started = 0;
  int observability_finished = 0;
  int64_t observability_started_ms = 0;

  observability_started = grpc_server_observability_call_started (
      server, req, full_method, request_payload_len, &observability_started_ms);

  if (SocketGRPC_ServerContext_is_cancelled (ctx))
    {
      grpc_server_observability_call_finished (
          server,
          req,
          full_method,
          observability_started,
          &observability_finished,
          observability_started_ms,
          SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
          "Deadline exceeded",
          0);
      grpc_send_unary_response (req,
                                HTTP_STATUS_OK,
                                NULL,
                                0,
                                SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
                                "Deadline exceeded",
                                ctx->trailers);
      return;
    }

  if (grpc_run_server_unary_interceptors (server,
                                          ctx,
                                          request_payload,
                                          request_payload_len,
                                          &grpc_status,
                                          &grpc_message)
      != 0)
    {
      grpc_server_observability_call_finished (server,
                                               req,
                                               full_method,
                                               observability_started,
                                               &observability_finished,
                                               observability_started_ms,
                                               grpc_status,
                                               grpc_message,
                                               0);
      grpc_send_unary_response (req,
                                HTTP_STATUS_OK,
                                NULL,
                                0,
                                grpc_status,
                                grpc_message,
                                ctx->trailers);
      return;
    }

  server->inflight_calls++;
  if (grpc_server_observability_enabled (server))
    SocketMetrics_gauge_inc (SOCKET_GAU_GRPC_SERVER_ACTIVE_CALLS);
  handler_rc = grpc_invoke_handler (method,
                                    ctx,
                                    request_payload,
                                    request_payload_len,
                                    &response_payload,
                                    &response_payload_len);
  if (server->inflight_calls > 0)
    server->inflight_calls--;
  if (grpc_server_observability_enabled (server))
    SocketMetrics_gauge_dec (SOCKET_GAU_GRPC_SERVER_ACTIVE_CALLS);

  grpc_status = grpc_resolve_final_status (ctx, handler_rc, &grpc_message);
  if (grpc_status == SOCKET_GRPC_STATUS_OK
      && SocketGRPC_ServerContext_is_cancelled (ctx))
    {
      grpc_status = SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED;
      grpc_message = "Deadline exceeded";
    }

  if (grpc_status != SOCKET_GRPC_STATUS_OK)
    {
      response_payload = NULL;
      response_payload_len = 0;
    }

  grpc_server_observability_call_finished (server,
                                           req,
                                           full_method,
                                           observability_started,
                                           &observability_finished,
                                           observability_started_ms,
                                           grpc_status,
                                           grpc_message,
                                           response_payload_len);

  grpc_send_unary_response (req,
                            HTTP_STATUS_OK,
                            response_payload,
                            response_payload_len,
                            grpc_status,
                            grpc_message,
                            ctx->trailers);
}

void
SocketGRPC_Server_handle_http2 (SocketHTTPServer_Request_T req, void *userdata)
{
  SocketGRPC_Server_T server = (SocketGRPC_Server_T)userdata;
  const char *full_method = NULL;
  SocketGRPC_ServerMethod *method;
  struct SocketGRPC_ServerContext ctx;
  const uint8_t *request_payload = NULL;
  size_t request_payload_len = 0;

  if (req == NULL)
    return;

  method = grpc_h2_validate_request (req, server, &full_method);
  if (method == NULL)
    return;

  if (grpc_h2_parse_and_validate_payload (
          req, &request_payload, &request_payload_len)
      != 0)
    return;

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

  grpc_h2_dispatch_unary (req,
                          server,
                          method,
                          &ctx,
                          full_method,
                          request_payload,
                          request_payload_len);
}

#if SOCKET_HAS_TLS
static int
grpc_server_observability_call_started_h3 (SocketGRPC_Server_T server,
                                           const char *peer,
                                           const char *authority,
                                           const char *full_method,
                                           size_t request_payload_len,
                                           int64_t *started_ms_out)
{
  SocketGRPC_LogEvent event;

  if (started_ms_out != NULL)
    *started_ms_out = 0;
  if (!grpc_server_observability_enabled (server))
    return 0;

  if (started_ms_out != NULL)
    *started_ms_out = SocketTimeout_now_ms ();
  SocketMetrics_counter_inc (SOCKET_CTR_GRPC_SERVER_CALLS_STARTED);
  if (request_payload_len > 0)
    {
      SocketMetrics_counter_add (SOCKET_CTR_GRPC_SERVER_BYTES_RECEIVED,
                                 (uint64_t)request_payload_len);
    }

  if (server == NULL || server->observability_hook == NULL)
    return 1;

  event.type = SOCKET_GRPC_LOG_EVENT_SERVER_CALL_START;
  event.full_method = full_method;
  event.status_code = SOCKET_GRPC_STATUS_OK;
  event.status_message
      = SocketGRPC_status_default_message (SOCKET_GRPC_STATUS_OK);
  event.payload_len = request_payload_len;
  event.attempt = 1U;
  event.peer = peer;
  event.authority = authority;
  event.duration_ms = -1;
  server->observability_hook (&event, server->observability_hook_userdata);
  return 1;
}

static void
grpc_server_observability_call_finished_h3 (SocketGRPC_Server_T server,
                                            const char *peer,
                                            const char *authority,
                                            const char *full_method,
                                            int started,
                                            int *finished_io,
                                            int64_t started_ms,
                                            SocketGRPC_StatusCode status_code,
                                            const char *status_message,
                                            size_t response_payload_len)
{
  SocketGRPC_StatusCode code;
  const char *message;
  int64_t duration_ms = -1;
  SocketGRPC_LogEvent event;

  if (!started)
    return;
  if (finished_io != NULL && *finished_io)
    return;
  if (finished_io != NULL)
    *finished_io = 1;
  if (!grpc_server_observability_enabled (server))
    return;

  code = grpc_normalize_status_code (status_code);
  message = (status_message != NULL && status_message[0] != '\0')
                ? status_message
                : SocketGRPC_status_default_message (code);

  if (started_ms > 0)
    {
      duration_ms = SocketTimeout_elapsed_ms (started_ms);
      if (duration_ms < 0)
        duration_ms = 0;
      SocketMetrics_histogram_observe (SOCKET_HIST_GRPC_SERVER_CALL_LATENCY_MS,
                                       (double)duration_ms);
    }
  if (response_payload_len > 0)
    {
      SocketMetrics_counter_add (SOCKET_CTR_GRPC_SERVER_BYTES_SENT,
                                 (uint64_t)response_payload_len);
    }

  SocketMetrics_counter_inc (SOCKET_CTR_GRPC_SERVER_CALLS_COMPLETED);
  SocketMetrics_counter_inc (grpc_server_status_counter_metric (code));

  if (server == NULL || server->observability_hook == NULL)
    return;

  event.type = SOCKET_GRPC_LOG_EVENT_SERVER_CALL_FINISH;
  event.full_method = full_method;
  event.status_code = code;
  event.status_message = message;
  event.payload_len = response_payload_len;
  event.attempt = 1U;
  event.peer = peer;
  event.authority = authority;
  event.duration_ms = duration_ms;
  server->observability_hook (&event, server->observability_hook_userdata);
}

static SocketGRPC_ServerMethod *
grpc_h3_validate_request (SocketHTTP3_Request_T req,
                          SocketGRPC_Server_T server,
                          SocketHTTP_Headers_T request_headers,
                          const char **full_method_out)
{
  const char *method_header;
  const char *full_method;
  const char *content_type;
  const char *te_header;
  SocketGRPC_ServerMethod *method;

  if (server == NULL)
    {
      grpc_send_plain_http_error_h3 (
          req, HTTP_STATUS_INTERNAL_ERROR, "gRPC server context unavailable");
      return NULL;
    }

  if (server->shutting_down)
    {
      grpc_send_unary_response_h3 (req,
                                   HTTP_STATUS_OK,
                                   NULL,
                                   0,
                                   SOCKET_GRPC_STATUS_UNAVAILABLE,
                                   "Server is shutting down",
                                   NULL);
      return NULL;
    }

  method_header = SocketHTTP_Headers_get_n (
      request_headers, ":method", STRLEN_LIT (":method"));
  if (method_header == NULL || strcmp (method_header, "POST") != 0)
    {
      grpc_send_unary_response_h3 (req,
                                   HTTP_STATUS_OK,
                                   NULL,
                                   0,
                                   SOCKET_GRPC_STATUS_UNIMPLEMENTED,
                                   "Unary gRPC requires POST",
                                   NULL);
      return NULL;
    }

  full_method = SocketHTTP_Headers_get_n (
      request_headers, ":path", STRLEN_LIT (":path"));
  if (grpc_split_method_path (full_method, NULL, NULL, NULL, NULL) != 0)
    {
      grpc_send_unary_response_h3 (req,
                                   HTTP_STATUS_OK,
                                   NULL,
                                   0,
                                   SOCKET_GRPC_STATUS_UNIMPLEMENTED,
                                   "Invalid gRPC method path",
                                   NULL);
      return NULL;
    }

  content_type = SocketHTTP_Headers_get_n (
      request_headers, "content-type", STRLEN_LIT ("content-type"));
  if (!grpc_content_type_is_valid (content_type))
    {
      grpc_send_plain_http_error_h3 (req,
                                     HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE,
                                     "Invalid content-type for gRPC");
      return NULL;
    }

  te_header
      = SocketHTTP_Headers_get_n (request_headers, "te", STRLEN_LIT ("te"));
  if (te_header != NULL && !grpc_header_token_contains (te_header, "trailers"))
    {
      grpc_send_plain_http_error_h3 (
          req, HTTP_STATUS_BAD_REQUEST, "Invalid te header for gRPC request");
      return NULL;
    }

  method = grpc_server_find_method (server, full_method);
  if (method == NULL)
    {
      grpc_send_unary_response_h3 (req,
                                   HTTP_STATUS_OK,
                                   NULL,
                                   0,
                                   SOCKET_GRPC_STATUS_UNIMPLEMENTED,
                                   "Unknown gRPC method",
                                   NULL);
      return NULL;
    }

  if (full_method_out != NULL)
    *full_method_out = full_method;
  return method;
}

static int
grpc_h3_recv_body (SocketHTTP3_Request_T req,
                   unsigned char **raw_body_out,
                   size_t *raw_body_len_out)
{
  unsigned char *raw_body = NULL;
  size_t raw_body_len = 0;
  size_t raw_body_cap = 0;

  for (;;)
    {
      unsigned char chunk[GRPC_H3_BODY_CHUNK];
      int end_stream = 0;
      ssize_t n = SocketHTTP3_Request_recv_data (
          req, chunk, sizeof (chunk), &end_stream);

      if (n < 0)
        {
          grpc_send_plain_http_error_h3 (req,
                                         HTTP_STATUS_BAD_REQUEST,
                                         "Malformed unary gRPC request body");
          free (raw_body);
          return -1;
        }

      if (n > 0)
        {
          size_t needed = raw_body_len + (size_t)n;
          unsigned char *tmp;
          if (needed > SOCKET_GRPC_DEFAULT_MAX_INBOUND_MESSAGE_BYTES)
            {
              grpc_send_unary_response_h3 (
                  req,
                  HTTP_STATUS_OK,
                  NULL,
                  0,
                  SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED,
                  "Unary request exceeds configured limit",
                  NULL);
              free (raw_body);
              return -1;
            }
          if (needed > raw_body_cap)
            {
              size_t new_cap = raw_body_cap == 0 ? 1024U : raw_body_cap;
              while (new_cap < needed)
                new_cap *= 2U;
              tmp = (unsigned char *)realloc (raw_body, new_cap);
              if (tmp == NULL)
                {
                  grpc_send_unary_response_h3 (
                      req,
                      HTTP_STATUS_OK,
                      NULL,
                      0,
                      SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED,
                      "Out of memory receiving request body",
                      NULL);
                  free (raw_body);
                  return -1;
                }
              raw_body = tmp;
              raw_body_cap = new_cap;
            }
          memcpy (raw_body + raw_body_len, chunk, (size_t)n);
          raw_body_len += (size_t)n;
        }

      if (end_stream)
        break;
      if (n == 0)
        {
          grpc_send_unary_response_h3 (req,
                                       HTTP_STATUS_OK,
                                       NULL,
                                       0,
                                       SOCKET_GRPC_STATUS_UNAVAILABLE,
                                       "Incomplete unary gRPC request body",
                                       NULL);
          free (raw_body);
          return -1;
        }
    }

  *raw_body_out = raw_body;
  *raw_body_len_out = raw_body_len;
  return 0;
}

static int
grpc_h3_parse_and_validate_payload (SocketHTTP3_Request_T req,
                                    const unsigned char *raw_body,
                                    size_t raw_body_len,
                                    const uint8_t **request_payload_out,
                                    size_t *request_payload_len_out)
{
  const uint8_t *request_payload = NULL;
  size_t request_payload_len = 0;
  int compressed = 0;

  if (grpc_parse_unary_request_payload_h3 (raw_body,
                                           raw_body_len,
                                           &request_payload,
                                           &request_payload_len,
                                           &compressed)
      != 0)
    {
      grpc_send_plain_http_error_h3 (
          req, HTTP_STATUS_BAD_REQUEST, "Malformed unary gRPC request frame");
      return -1;
    }

  if (compressed != 0)
    {
      grpc_send_plain_http_error_h3 (req,
                                     HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE,
                                     "Compressed gRPC requests unsupported");
      return -1;
    }

  *request_payload_out = request_payload;
  *request_payload_len_out = request_payload_len;
  return 0;
}

static void
grpc_h3_dispatch_unary (SocketHTTP3_Request_T req,
                        SocketGRPC_Server_T server,
                        SocketGRPC_ServerMethod *method,
                        struct SocketGRPC_ServerContext *ctx,
                        const char *full_method,
                        const uint8_t *request_payload,
                        size_t request_payload_len)
{
  uint8_t *response_payload = NULL;
  size_t response_payload_len = 0;
  int handler_rc;
  SocketGRPC_StatusCode grpc_status;
  const char *grpc_message = NULL;
  int observability_started = 0;
  int observability_finished = 0;
  int64_t observability_started_ms = 0;

  observability_started
      = grpc_server_observability_call_started_h3 (server,
                                                   ctx->peer,
                                                   ctx->authority,
                                                   full_method,
                                                   request_payload_len,
                                                   &observability_started_ms);

  if (SocketGRPC_ServerContext_is_cancelled (ctx))
    {
      grpc_server_observability_call_finished_h3 (
          server,
          ctx->peer,
          ctx->authority,
          full_method,
          observability_started,
          &observability_finished,
          observability_started_ms,
          SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
          "Deadline exceeded",
          0);
      grpc_send_unary_response_h3 (req,
                                   HTTP_STATUS_OK,
                                   NULL,
                                   0,
                                   SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
                                   "Deadline exceeded",
                                   ctx->trailers);
      return;
    }

  if (grpc_run_server_unary_interceptors (server,
                                          ctx,
                                          request_payload,
                                          request_payload_len,
                                          &grpc_status,
                                          &grpc_message)
      != 0)
    {
      grpc_server_observability_call_finished_h3 (server,
                                                  ctx->peer,
                                                  ctx->authority,
                                                  full_method,
                                                  observability_started,
                                                  &observability_finished,
                                                  observability_started_ms,
                                                  grpc_status,
                                                  grpc_message,
                                                  0);
      grpc_send_unary_response_h3 (req,
                                   HTTP_STATUS_OK,
                                   NULL,
                                   0,
                                   grpc_status,
                                   grpc_message,
                                   ctx->trailers);
      return;
    }

  server->inflight_calls++;
  if (grpc_server_observability_enabled (server))
    SocketMetrics_gauge_inc (SOCKET_GAU_GRPC_SERVER_ACTIVE_CALLS);
  handler_rc = grpc_invoke_handler (method,
                                    ctx,
                                    request_payload,
                                    request_payload_len,
                                    &response_payload,
                                    &response_payload_len);
  if (server->inflight_calls > 0)
    server->inflight_calls--;
  if (grpc_server_observability_enabled (server))
    SocketMetrics_gauge_dec (SOCKET_GAU_GRPC_SERVER_ACTIVE_CALLS);

  grpc_status = grpc_resolve_final_status (ctx, handler_rc, &grpc_message);
  if (grpc_status == SOCKET_GRPC_STATUS_OK
      && SocketGRPC_ServerContext_is_cancelled (ctx))
    {
      grpc_status = SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED;
      grpc_message = "Deadline exceeded";
    }

  if (grpc_status != SOCKET_GRPC_STATUS_OK)
    {
      response_payload = NULL;
      response_payload_len = 0;
    }

  grpc_server_observability_call_finished_h3 (server,
                                              ctx->peer,
                                              ctx->authority,
                                              full_method,
                                              observability_started,
                                              &observability_finished,
                                              observability_started_ms,
                                              grpc_status,
                                              grpc_message,
                                              response_payload_len);

  grpc_send_unary_response_h3 (req,
                               HTTP_STATUS_OK,
                               response_payload,
                               response_payload_len,
                               grpc_status,
                               grpc_message,
                               ctx->trailers);
}

void
SocketGRPC_Server_bind_http3 (SocketGRPC_Server_T server,
                              SocketHTTP3_Server_T http3_server)
{
  if (server == NULL || http3_server == NULL)
    return;

  SocketHTTP3_Server_on_request (
      http3_server, SocketGRPC_Server_handle_http3, server);
}

void
SocketGRPC_Server_handle_http3 (SocketHTTP3_Request_T req,
                                const SocketHTTP_Headers_T headers,
                                void *userdata)
{
  SocketGRPC_Server_T server = (SocketGRPC_Server_T)userdata;
  SocketHTTP_Headers_T request_headers = (SocketHTTP_Headers_T)headers;
  const char *full_method = NULL;
  SocketGRPC_ServerMethod *method;
  struct SocketGRPC_ServerContext ctx;
  const uint8_t *request_payload = NULL;
  size_t request_payload_len = 0;
  unsigned char *raw_body = NULL;
  size_t raw_body_len = 0;
  int ctx_initialized = 0;

  memset (&ctx, 0, sizeof (ctx));

  if (req == NULL)
    return;

  if (request_headers == NULL
      && SocketHTTP3_Request_recv_headers (req, &request_headers, NULL) != 0)
    {
      grpc_send_plain_http_error_h3 (
          req, HTTP_STATUS_BAD_REQUEST, "Malformed HTTP/3 request headers");
      return;
    }

  method
      = grpc_h3_validate_request (req, server, request_headers, &full_method);
  if (method == NULL)
    return;

  if (grpc_h3_recv_body (req, &raw_body, &raw_body_len) != 0)
    return;

  if (grpc_h3_parse_and_validate_payload (
          req, raw_body, raw_body_len, &request_payload, &request_payload_len)
      != 0)
    goto cleanup;

  if (grpc_context_init_h3 (&ctx, server, req, request_headers, full_method)
      != 0)
    {
      grpc_send_unary_response_h3 (req,
                                   HTTP_STATUS_OK,
                                   NULL,
                                   0,
                                   SOCKET_GRPC_STATUS_INTERNAL,
                                   "Failed to initialize unary server context",
                                   NULL);
      goto cleanup;
    }
  ctx_initialized = 1;

  grpc_h3_dispatch_unary (req,
                          server,
                          method,
                          &ctx,
                          full_method,
                          request_payload,
                          request_payload_len);

cleanup:
  free (raw_body);
  if (ctx_initialized && ctx.owns_arena && ctx.arena != NULL)
    Arena_dispose (&ctx.arena);
}
#endif

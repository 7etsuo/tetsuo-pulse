/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketGRPCClient-h3.c
 * @brief gRPC client transport integration over HTTP/3.
 */

#ifdef SOCKET_HAS_TLS

#include "grpc/SocketGRPC-private.h"
#include "grpc/SocketGRPCWire.h"
#include "core/SocketCrypto.h"
#include "core/SocketMetrics.h"
#include "core/SocketUtil/Timeout.h"
#include "http/SocketHTTP3-client.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define GRPC_CONTENT_TYPE "application/grpc"
#define GRPC_TIMEOUT_HEADER_MAX 32U
#define GRPC_RESPONSE_CHUNK 4096U
#define GRPC_STREAM_RECV_BUFFER_INITIAL 4096U
#define GRPC_ACCEPT_ENCODING_VALUE "identity,gzip"
#define GRPC_ENCODING_IDENTITY "identity"
#define GRPC_ENCODING_GZIP "gzip"

typedef enum
{
  GRPC_COMPRESSION_IDENTITY = 0,
  GRPC_COMPRESSION_GZIP = 1,
  GRPC_COMPRESSION_UNSUPPORTED = 2
} SocketGRPC_Compression;

typedef struct
{
  Arena_T arena;
  SocketHTTP3_Client_T http3_client;
  SocketHTTP3_Request_T request;
  unsigned char *recv_buffer;
  size_t recv_len;
  size_t recv_cap;
  int headers_received;
  int remote_end_stream;
  int trailers_ingested;
  int status_finalized;
  int http_status_code;
  int64_t deadline_ms;
  int64_t opened_at_ms;
  int metrics_stream_active;
  int observability_started;
  SocketGRPC_Compression response_compression;
} SocketGRPC_H3CallStream;

struct SocketGRPC_ClientUnaryInterceptorEntry
{
  SocketGRPC_ClientUnaryInterceptor interceptor;
  void *userdata;
  struct SocketGRPC_ClientUnaryInterceptorEntry *next;
};

struct SocketGRPC_ClientStreamInterceptorEntry
{
  SocketGRPC_ClientStreamInterceptor interceptor;
  void *userdata;
  struct SocketGRPC_ClientStreamInterceptorEntry *next;
};

static int
str_has_prefix (const char *str, const char *prefix)
{
  size_t prefix_len;

  if (str == NULL || prefix == NULL)
    return 0;
  prefix_len = strlen (prefix);
  return strncmp (str, prefix, prefix_len) == 0;
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

static SocketGRPC_StatusCode
grpc_normalize_status_code (SocketGRPC_StatusCode code)
{
  return grpc_status_code_valid (code) ? code : SOCKET_GRPC_STATUS_UNKNOWN;
}

static int
grpc_client_observability_enabled (SocketGRPC_Call_T call)
{
  return call != NULL && call->channel != NULL && call->channel->client != NULL
         && call->channel->client->config.enable_observability;
}

static const char *
grpc_client_event_peer (SocketGRPC_Call_T call)
{
  if (call == NULL || call->channel == NULL)
    return NULL;
  return call->channel->target;
}

static const char *
grpc_client_event_authority (SocketGRPC_Call_T call)
{
  if (call == NULL || call->channel == NULL)
    return NULL;
  if (call->channel->authority_override != NULL)
    return call->channel->authority_override;
  return call->channel->target;
}

static SocketCounterMetric
grpc_client_status_counter_metric (SocketGRPC_StatusCode code)
{
  SocketGRPC_StatusCode normalized = grpc_normalize_status_code (code);
  return (SocketCounterMetric)(SOCKET_CTR_GRPC_CLIENT_STATUS_OK
                               + (int)normalized);
}

static void
grpc_client_emit_observability_event (SocketGRPC_Call_T call,
                                      SocketGRPC_LogEventType type,
                                      SocketGRPC_StatusCode status_code,
                                      const char *status_message,
                                      size_t payload_len,
                                      uint32_t attempt,
                                      int64_t duration_ms)
{
  SocketGRPC_Client_T client;
  SocketGRPC_LogEvent event;

  if (!grpc_client_observability_enabled (call))
    return;
  if (call == NULL || call->channel == NULL || call->channel->client == NULL)
    return;

  client = call->channel->client;
  if (client->observability_hook == NULL)
    return;

  event.type = type;
  event.full_method = call->full_method;
  event.status_code = grpc_normalize_status_code (status_code);
  event.status_message
      = (status_message != NULL && status_message[0] != '\0')
            ? status_message
            : SocketGRPC_status_default_message (event.status_code);
  event.payload_len = payload_len;
  event.attempt = attempt;
  event.peer = grpc_client_event_peer (call);
  event.authority = grpc_client_event_authority (call);
  event.duration_ms = duration_ms;
  client->observability_hook (&event, client->observability_hook_userdata);
}

static void
grpc_client_observability_call_started (SocketGRPC_Call_T call,
                                        size_t payload_len,
                                        uint32_t attempt)
{
  if (!grpc_client_observability_enabled (call))
    return;

  SocketMetrics_counter_inc (SOCKET_CTR_GRPC_CLIENT_CALLS_STARTED);
  grpc_client_emit_observability_event (call,
                                        SOCKET_GRPC_LOG_EVENT_CLIENT_CALL_START,
                                        SOCKET_GRPC_STATUS_OK,
                                        NULL,
                                        payload_len,
                                        attempt,
                                        -1);
}

static void
grpc_client_observability_call_retry (SocketGRPC_Call_T call, uint32_t attempt)
{
  if (!grpc_client_observability_enabled (call))
    return;

  SocketMetrics_counter_inc (SOCKET_CTR_GRPC_CLIENT_RETRIES);
  grpc_client_emit_observability_event (call,
                                        SOCKET_GRPC_LOG_EVENT_CLIENT_RETRY,
                                        SOCKET_GRPC_STATUS_UNAVAILABLE,
                                        "Retrying call",
                                        0,
                                        attempt,
                                        -1);
}

static void
grpc_client_observability_call_finished (SocketGRPC_Call_T call,
                                         int64_t started_at_ms,
                                         size_t payload_len,
                                         uint32_t attempt)
{
  SocketGRPC_Status status;
  SocketGRPC_StatusCode code;
  int64_t duration_ms = -1;
  const char *message;

  if (!grpc_client_observability_enabled (call))
    return;
  if (call == NULL)
    return;

  status = SocketGRPC_Call_status (call);
  code = grpc_normalize_status_code (status.code);
  message = (status.message != NULL && status.message[0] != '\0')
                ? status.message
                : SocketGRPC_status_default_message (code);
  if (started_at_ms > 0)
    {
      duration_ms = SocketTimeout_elapsed_ms (started_at_ms);
      if (duration_ms < 0)
        duration_ms = 0;
      SocketMetrics_histogram_observe (SOCKET_HIST_GRPC_CLIENT_CALL_LATENCY_MS,
                                       (double)duration_ms);
    }

  SocketMetrics_counter_inc (SOCKET_CTR_GRPC_CLIENT_CALLS_COMPLETED);
  SocketMetrics_counter_inc (grpc_client_status_counter_metric (code));
  grpc_client_emit_observability_event (
      call,
      SOCKET_GRPC_LOG_EVENT_CLIENT_CALL_FINISH,
      code,
      message,
      payload_len,
      attempt,
      duration_ms);
}

static void
grpc_client_metrics_bytes_sent (SocketGRPC_Call_T call, size_t payload_len)
{
  if (!grpc_client_observability_enabled (call) || payload_len == 0)
    return;

  SocketMetrics_counter_add (SOCKET_CTR_GRPC_CLIENT_BYTES_SENT,
                             (uint64_t)payload_len);
}

static void
grpc_client_metrics_bytes_received (SocketGRPC_Call_T call, size_t payload_len)
{
  if (!grpc_client_observability_enabled (call) || payload_len == 0)
    return;

  SocketMetrics_counter_add (SOCKET_CTR_GRPC_CLIENT_BYTES_RECEIVED,
                             (uint64_t)payload_len);
}

static void
grpc_client_stream_observability_started (SocketGRPC_Call_T call,
                                          SocketGRPC_H3CallStream *ctx)
{
  if (ctx == NULL || ctx->observability_started)
    return;
  if (!grpc_client_observability_enabled (call))
    return;

  ctx->opened_at_ms = SocketTimeout_now_ms ();
  ctx->observability_started = 1;
  ctx->metrics_stream_active = 1;
  SocketMetrics_counter_inc (SOCKET_CTR_GRPC_CLIENT_CALLS_STARTED);
  SocketMetrics_gauge_inc (SOCKET_GAU_GRPC_CLIENT_ACTIVE_STREAMS);
  grpc_client_emit_observability_event (call,
                                        SOCKET_GRPC_LOG_EVENT_CLIENT_CALL_START,
                                        SOCKET_GRPC_STATUS_OK,
                                        NULL,
                                        0,
                                        1U,
                                        -1);
}

static void
grpc_client_stream_observability_finished (SocketGRPC_Call_T call,
                                           SocketGRPC_H3CallStream *ctx)
{
  SocketGRPC_Status status;
  SocketGRPC_StatusCode code;
  const char *message;
  int64_t duration_ms = -1;

  if (ctx == NULL)
    return;

  if (ctx->metrics_stream_active)
    {
      SocketMetrics_gauge_dec (SOCKET_GAU_GRPC_CLIENT_ACTIVE_STREAMS);
      ctx->metrics_stream_active = 0;
    }

  if (!ctx->observability_started)
    return;
  if (!grpc_client_observability_enabled (call))
    {
      ctx->observability_started = 0;
      return;
    }

  status = SocketGRPC_Call_status (call);
  code = grpc_normalize_status_code (status.code);
  message = (status.message != NULL && status.message[0] != '\0')
                ? status.message
                : SocketGRPC_status_default_message (code);
  if (ctx->opened_at_ms > 0)
    {
      duration_ms = SocketTimeout_elapsed_ms (ctx->opened_at_ms);
      if (duration_ms < 0)
        duration_ms = 0;
      SocketMetrics_histogram_observe (
          SOCKET_HIST_GRPC_CLIENT_STREAM_OPEN_DURATION_MS, (double)duration_ms);
      SocketMetrics_histogram_observe (SOCKET_HIST_GRPC_CLIENT_CALL_LATENCY_MS,
                                       (double)duration_ms);
    }

  SocketMetrics_counter_inc (SOCKET_CTR_GRPC_CLIENT_CALLS_COMPLETED);
  SocketMetrics_counter_inc (grpc_client_status_counter_metric (code));
  grpc_client_emit_observability_event (
      call,
      SOCKET_GRPC_LOG_EVENT_CLIENT_CALL_FINISH,
      code,
      message,
      0,
      1U,
      duration_ms);
  ctx->observability_started = 0;
}

static int
grpc_parse_port_str (const char *value, int *port_out)
{
  char *end = NULL;
  long parsed;

  if (value == NULL || value[0] == '\0' || port_out == NULL)
    return -1;

  errno = 0;
  parsed = strtol (value, &end, 10);
  if (errno != 0 || end == value || end == NULL || *end != '\0')
    return -1;
  if (parsed <= 0 || parsed > 65535)
    return -1;

  *port_out = (int)parsed;
  return 0;
}

static int
grpc_h3_parse_target (const char *target,
                      char *host,
                      size_t host_cap,
                      int *port_out)
{
  const char *base;
  size_t base_len;
  char authority[320];
  char *host_part;
  char *port_part;

  if (target == NULL || host == NULL || host_cap == 0 || port_out == NULL)
    return -1;

  if (str_has_prefix (target, "https://"))
    base = target + strlen ("https://");
  else if (str_has_prefix (target, "http://"))
    return -1;
  else if (str_has_prefix (target, "dns:///"))
    base = target + strlen ("dns:///");
  else
    base = target;

  if (base[0] == '\0')
    return -1;

  base_len = strcspn (base, "/");
  if (base_len == 0 || base_len >= sizeof (authority))
    return -1;

  memcpy (authority, base, base_len);
  authority[base_len] = '\0';

  host_part = authority;
  port_part = NULL;

  if (host_part[0] == '[')
    {
      char *close = strchr (host_part, ']');
      size_t hlen;

      if (close == NULL)
        return -1;
      hlen = (size_t)(close - host_part - 1);
      if (hlen == 0 || hlen >= host_cap)
        return -1;

      memcpy (host, host_part + 1, hlen);
      host[hlen] = '\0';

      if (close[1] == ':' && close[2] != '\0')
        port_part = close + 2;
      else if (close[1] != '\0')
        return -1;
    }
  else
    {
      char *first_colon = strchr (host_part, ':');
      char *last_colon = strrchr (host_part, ':');

      if (first_colon != NULL && first_colon == last_colon)
        {
          *first_colon = '\0';
          port_part = first_colon + 1;
        }

      if (host_part[0] == '\0' || strlen (host_part) >= host_cap)
        return -1;
      memcpy (host, host_part, strlen (host_part) + 1);
    }

  if (port_part != NULL)
    {
      if (grpc_parse_port_str (port_part, port_out) != 0)
        return -1;
    }
  else
    {
      *port_out = 443;
    }

  return 0;
}

static int
grpc_h3_build_authority (SocketGRPC_Call_T call,
                         const char *host,
                         int port,
                         char *authority_out,
                         size_t authority_out_cap)
{
  int has_colon;

  if (call == NULL || host == NULL || authority_out == NULL
      || authority_out_cap == 0)
    return -1;

  if (call->channel != NULL && call->channel->authority_override != NULL)
    {
      size_t len = strlen (call->channel->authority_override);
      if (len == 0 || len >= authority_out_cap)
        return -1;
      memcpy (authority_out, call->channel->authority_override, len + 1);
      return 0;
    }

  has_colon = strchr (host, ':') != NULL;
  if (port == 443)
    {
      if (has_colon)
        {
          int n = snprintf (authority_out, authority_out_cap, "[%s]", host);
          if (n <= 0 || (size_t)n >= authority_out_cap)
            return -1;
        }
      else
        {
          size_t len = strlen (host);
          if (len >= authority_out_cap)
            return -1;
          memcpy (authority_out, host, len + 1);
        }
      return 0;
    }

  {
    int n;
    if (has_colon)
      n = snprintf (authority_out, authority_out_cap, "[%s]:%d", host, port);
    else
      n = snprintf (authority_out, authority_out_cap, "%s:%d", host, port);
    if (n <= 0 || (size_t)n >= authority_out_cap)
      return -1;
  }

  return 0;
}

static const char *
grpc_h3_method_path (SocketGRPC_Call_T call, char *buf, size_t cap)
{
  size_t method_len;

  if (call == NULL || call->full_method == NULL || buf == NULL || cap == 0)
    return NULL;

  if (call->full_method[0] == '/')
    return call->full_method;

  method_len = strlen (call->full_method);
  if (method_len + 2 > cap)
    return NULL;

  buf[0] = '/';
  memcpy (buf + 1, call->full_method, method_len + 1);
  return buf;
}

static int
grpc_h3_add_metadata_headers (SocketGRPC_Call_T call,
                              SocketHTTP_Headers_T headers,
                              SocketGRPC_Metadata_T metadata)
{
  size_t count;
  size_t i;

  if (call == NULL || headers == NULL || metadata == NULL)
    return -1;

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
          size_t encoded_cap
              = SocketCrypto_base64_encoded_size (entry->value_len);
          char *encoded = (char *)malloc (encoded_cap);
          ssize_t encoded_len;
          if (encoded == NULL)
            return -1;
          encoded_len = SocketCrypto_base64_encode (
              entry->value, entry->value_len, encoded, encoded_cap);
          if (encoded_len < 0
              || SocketHTTP_Headers_add_n (headers,
                                           entry->key,
                                           strlen (entry->key),
                                           encoded,
                                           (size_t)encoded_len)
                     != 0)
            {
              free (encoded);
              return -1;
            }
          free (encoded);
        }
      else
        {
          if (SocketHTTP_Headers_add_n (headers,
                                        entry->key,
                                        strlen (entry->key),
                                        (const char *)entry->value,
                                        entry->value_len)
              != 0)
            {
              return -1;
            }
        }
    }

  return 0;
}

static int
grpc_h3_build_request_headers (SocketGRPC_Call_T call,
                               Arena_T arena,
                               const char *host,
                               int port,
                               SocketHTTP_Headers_T *headers_out)
{
  SocketHTTP_Headers_T headers;
  char path_buf[512];
  const char *path;
  char authority[320];
  char timeout_buf[GRPC_TIMEOUT_HEADER_MAX];
  char attempt_buf[16];

  if (call == NULL || arena == NULL || host == NULL || headers_out == NULL)
    return -1;

  *headers_out = NULL;
  headers = SocketHTTP_Headers_new (arena);
  if (headers == NULL)
    return -1;

  if (grpc_h3_build_authority (call, host, port, authority, sizeof (authority))
          != 0
      || SocketHTTP_Headers_add_pseudo_n (headers, ":method", 7, "POST", 4)
             != 0
      || SocketHTTP_Headers_add_pseudo_n (headers, ":scheme", 7, "https", 5)
             != 0)
    {
      return -1;
    }

  path = grpc_h3_method_path (call, path_buf, sizeof (path_buf));
  if (path == NULL
      || SocketHTTP_Headers_add_pseudo_n (
             headers, ":authority", 10, authority, strlen (authority))
             != 0
      || SocketHTTP_Headers_add_pseudo_n (headers, ":path", 5, path, strlen (path))
             != 0
      || SocketHTTP_Headers_add (headers, "content-type", GRPC_CONTENT_TYPE)
             != 0
      || SocketHTTP_Headers_add (headers, "te", "trailers") != 0
      || SocketHTTP_Headers_add (
             headers, "grpc-accept-encoding", GRPC_ACCEPT_ENCODING_VALUE)
             != 0)
    {
      return -1;
    }

  if (call->channel->config.enable_request_compression
      && SocketHTTP_Headers_add (headers, "grpc-encoding", GRPC_ENCODING_GZIP)
             != 0)
    return -1;

  if (call->channel->user_agent != NULL
      && SocketHTTP_Headers_add (headers, "user-agent", call->channel->user_agent)
             != 0)
    return -1;

  if (call->config.deadline_ms > 0)
    {
      if (SocketGRPC_Timeout_format ((int64_t)call->config.deadline_ms,
                                     timeout_buf,
                                     sizeof (timeout_buf))
              != 0
          || SocketHTTP_Headers_add (headers, "grpc-timeout", timeout_buf) != 0)
        {
          return -1;
        }
    }

  if (call->retry_attempt > 0)
    {
      int n = snprintf (
          attempt_buf, sizeof (attempt_buf), "%u", call->retry_attempt);
      if (n <= 0 || (size_t)n >= sizeof (attempt_buf)
          || SocketHTTP_Headers_add (
                 headers, "grpc-previous-rpc-attempts", attempt_buf)
                 != 0)
        {
          return -1;
        }
    }

  if (grpc_h3_add_metadata_headers (call, headers, call->request_metadata) != 0)
    return -1;

  *headers_out = headers;
  return 0;
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

  if (call == NULL || headers == NULL)
    return -1;

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
        {
          continue;
        }
      if (grpc_trailer_ingest_kv (
              call, h->name, h->name_len, h->value, h->value_len)
          != 0)
        return -1;
    }

  return 0;
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
grpc_h3_buffer_append (unsigned char **buffer,
                       size_t *len,
                       size_t *cap,
                       const unsigned char *chunk,
                       size_t chunk_len,
                       size_t max_cap)
{
  size_t needed;

  if (buffer == NULL || len == NULL || cap == NULL
      || (chunk == NULL && chunk_len != 0))
    return -1;
  if (chunk_len == 0)
    return 0;

  needed = *len + chunk_len;
  if (needed > max_cap)
    return -1;

  if (needed > *cap)
    {
      size_t new_cap = (*cap == 0) ? GRPC_STREAM_RECV_BUFFER_INITIAL : *cap;
      unsigned char *tmp;
      while (new_cap < needed)
        {
          if (new_cap > max_cap / 2U)
            {
              new_cap = max_cap;
              break;
            }
          new_cap *= 2U;
        }
      if (new_cap < needed)
        return -1;
      tmp = (unsigned char *)realloc (*buffer, new_cap);
      if (tmp == NULL)
        return -1;
      *buffer = tmp;
      *cap = new_cap;
    }

  memcpy (*buffer + *len, chunk, chunk_len);
  *len += chunk_len;
  return 0;
}

static int
grpc_h3_poll_until_data (SocketHTTP3_Client_T client, int64_t deadline_ms)
{
  int timeout_ms = 25;

  if (deadline_ms > 0)
    {
      int64_t remaining = SocketTimeout_remaining_ms (deadline_ms);
      if (remaining <= 0)
        return -1;
      if (remaining < timeout_ms)
        timeout_ms = (int)remaining;
      if (timeout_ms <= 0)
        timeout_ms = 1;
    }

  return SocketHTTP3_Client_poll (client, timeout_ms) >= 0 ? 0 : -1;
}

static void
grpc_h3_stream_context_cleanup (SocketGRPC_Call_T call,
                                int success,
                                int cancel_stream)
{
  SocketGRPC_H3CallStream *ctx;

  if (call == NULL)
    return;

  ctx = (SocketGRPC_H3CallStream *)call->h3_stream_ctx;
  if (ctx == NULL)
    return;

  grpc_client_stream_observability_finished (call, ctx);

  if (cancel_stream && ctx->request != NULL)
    (void)SocketHTTP3_Request_cancel (ctx->request);

  if (ctx->http3_client != NULL)
    (void)SocketHTTP3_Client_close (ctx->http3_client);

  free (ctx->recv_buffer);
  ctx->recv_buffer = NULL;
  ctx->recv_len = 0;
  ctx->recv_cap = 0;

  if (ctx->arena != NULL)
    Arena_dispose (&ctx->arena);

  free (ctx);
  call->h3_stream_ctx = NULL;
  call->h3_stream_state
      = success ? GRPC_CALL_STREAM_CLOSED : GRPC_CALL_STREAM_FAILED;
}

void
SocketGRPC_Call_h3_stream_abort (SocketGRPC_Call_T call)
{
  if (call == NULL)
    return;
  grpc_h3_stream_context_cleanup (call, 0, 1);
}

static int
grpc_h3_stream_fail (SocketGRPC_Call_T call,
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
  grpc_h3_stream_context_cleanup (call, 0, cancel_stream);
  return -1;
}

static int
grpc_h3_stream_finalize_status (SocketGRPC_Call_T call, int http_status_code)
{
  SocketGRPC_StatusCode status_code;

  if (call == NULL || call->response_trailers == NULL)
    return -1;

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
  return 0;
}

static int
grpc_h3_stream_ingest_trailers_if_ready (SocketGRPC_Call_T call,
                                         SocketGRPC_H3CallStream *ctx)
{
  SocketHTTP_Headers_T trailers = NULL;

  if (call == NULL || ctx == NULL || ctx->trailers_ingested)
    return 0;

  if (SocketHTTP3_Request_recv_trailers (ctx->request, &trailers) == 0
      && trailers != NULL)
    {
      if (grpc_ingest_response_headers (call, trailers, 1) != 0)
        return -1;
      ctx->trailers_ingested = 1;
    }

  return 0;
}

static SocketGRPC_H3CallStream *
grpc_h3_stream_open_if_needed (SocketGRPC_Call_T call)
{
  SocketGRPC_H3CallStream *ctx;
  SocketHTTP3_ClientConfig cfg;
  char host[256];
  int port;
  SocketHTTP_Headers_T headers = NULL;
  const char *fail_message = "Failed to initialize HTTP/3 stream";

  if (call == NULL || call->channel == NULL)
    return NULL;

  ctx = (SocketGRPC_H3CallStream *)call->h3_stream_ctx;
  if (ctx != NULL)
    return ctx;

  if (grpc_h3_parse_target (call->channel->target, host, sizeof (host), &port)
      != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INVALID_ARGUMENT, "Invalid channel target");
      return NULL;
    }

  ctx = (SocketGRPC_H3CallStream *)calloc (1, sizeof (*ctx));
  if (ctx == NULL)
    return NULL;

  ctx->arena = Arena_new ();
  if (ctx->arena == NULL)
    {
      fail_message = "Failed to allocate stream arena";
      goto fail;
    }

  SocketHTTP3_ClientConfig_defaults (&cfg);
  cfg.request_timeout_ms
      = call->config.deadline_ms > 0 ? (uint32_t)call->config.deadline_ms : 0U;
  cfg.verify_peer = call->channel->config.verify_peer;
  cfg.ca_file = call->channel->config.ca_file;

  ctx->http3_client = SocketHTTP3_Client_new (ctx->arena, &cfg);
  if (ctx->http3_client == NULL)
    {
      fail_message = "HTTP/3 client allocation failed";
      goto fail;
    }

  if (SocketHTTP3_Client_connect (ctx->http3_client, host, port) != 0)
    {
      fail_message = "HTTP/3 connect failed";
      goto fail;
    }

  ctx->request = SocketHTTP3_Client_new_request (ctx->http3_client);
  if (ctx->request == NULL)
    {
      fail_message = "HTTP/3 stream request allocation failed";
      goto fail;
    }

  if (grpc_h3_build_request_headers (call, ctx->arena, host, port, &headers) != 0)
    {
      fail_message = "Failed to build HTTP/3 request headers";
      goto fail;
    }
  if (SocketHTTP3_Request_send_headers (ctx->request, headers, 0) != 0
      || SocketHTTP3_Client_flush (ctx->http3_client) != 0)
    {
      fail_message = "Failed to send HTTP/3 stream headers";
      goto fail;
    }

  ctx->http_status_code = HTTP_STATUS_OK;
  ctx->deadline_ms = SocketTimeout_deadline_ms (call->config.deadline_ms);
  ctx->response_compression = GRPC_COMPRESSION_IDENTITY;
  call->h3_stream_ctx = ctx;
  call->h3_stream_state = GRPC_CALL_STREAM_OPEN;

  SocketGRPC_Trailers_clear (call->response_trailers);
  grpc_call_status_set (call, SOCKET_GRPC_STATUS_OK, NULL);
  grpc_client_stream_observability_started (call, ctx);
  return ctx;

fail:
  if (ctx != NULL)
    {
      if (ctx->http3_client != NULL)
        (void)SocketHTTP3_Client_close (ctx->http3_client);
      if (ctx->arena != NULL)
        Arena_dispose (&ctx->arena);
      free (ctx);
    }
  grpc_call_status_set (call, SOCKET_GRPC_STATUS_UNAVAILABLE, fail_message);
  return NULL;
}

static int
grpc_h3_stream_try_parse_message (SocketGRPC_Call_T call,
                                  SocketGRPC_H3CallStream *ctx,
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

  if (frame.compressed != 0)
    {
      *error_status = SOCKET_GRPC_STATUS_INTERNAL;
      *error_message = "Compressed streaming responses unsupported over HTTP/3";
      return -1;
    }

  if (frame.payload_len > call->channel->config.max_inbound_message_bytes)
    {
      *error_status = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
      *error_message = "Response message exceeds configured limit";
      return -1;
    }

  if (frame.payload_len > 0)
    {
      uint8_t *copy = (uint8_t *)ALLOC (arena, frame.payload_len);
      if (copy == NULL)
        {
          *error_status = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
          *error_message = "Out of memory decoding response frame";
          return -1;
        }
      memcpy (copy, frame.payload, frame.payload_len);
      *response_payload = copy;
      *response_payload_len = frame.payload_len;
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

      if (!grpc_status_code_valid (status.code)
          || status.code == SOCKET_GRPC_STATUS_OK)
        {
          status.code = SOCKET_GRPC_STATUS_INTERNAL;
          status.message = "Interceptor returned invalid status";
        }

      return grpc_h3_stream_fail (call, status.code, status.message, 1);
    }

  return 0;
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

      if (!grpc_status_code_valid (status.code)
          || status.code == SOCKET_GRPC_STATUS_OK)
        {
          status.code = SOCKET_GRPC_STATUS_INTERNAL;
          status.message = "Interceptor returned invalid status";
        }

      if (call->response_trailers != NULL)
        {
          SocketGRPC_Trailers_clear (call->response_trailers);
          (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                                status.code);
          (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                                 status.message);
        }
      grpc_call_status_set (call, status.code, status.message);
      return -1;
    }

  return 0;
}

int
SocketGRPC_Call_h3_send_message (SocketGRPC_Call_T call,
                                 const uint8_t *request_payload,
                                 size_t request_payload_len)
{
  SocketGRPC_H3CallStream *ctx;
  unsigned char *framed;
  size_t framed_len = 0;
  size_t framed_cap;

  if (call == NULL || (request_payload == NULL && request_payload_len != 0))
    return -1;

  if (call->channel == NULL || call->channel->config.channel_mode != SOCKET_GRPC_CHANNEL_MODE_HTTP3)
    return -1;

  if (call->h3_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_LOCAL
      || call->h3_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_REMOTE
      || call->h3_stream_state == GRPC_CALL_STREAM_FAILED)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_FAILED_PRECONDITION,
                            "Send direction already closed");
      return -1;
    }

  if (call->channel->config.enable_request_compression)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_INTERNAL,
                            "Request compression over HTTP/3 not supported");
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

  ctx = grpc_h3_stream_open_if_needed (call);
  if (ctx == NULL)
    return -1;

  framed_cap = SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE + request_payload_len;
  framed = (unsigned char *)malloc (framed_cap);
  if (framed == NULL)
    {
      return grpc_h3_stream_fail (call,
                                  SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED,
                                  "Out of memory framing message",
                                  1);
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
      return grpc_h3_stream_fail (call,
                                  SOCKET_GRPC_STATUS_INTERNAL,
                                  "Failed to frame streaming request",
                                  1);
    }

  if (SocketHTTP3_Request_send_data (ctx->request, framed, framed_len, 0) != 0
      || SocketHTTP3_Client_flush (ctx->http3_client) != 0)
    {
      free (framed);
      return grpc_h3_stream_fail (call,
                                  SOCKET_GRPC_STATUS_UNAVAILABLE,
                                  "Failed to send HTTP/3 stream frame",
                                  1);
    }

  free (framed);
  grpc_client_metrics_bytes_sent (call, request_payload_len);
  return 0;
}

int
SocketGRPC_Call_h3_close_send (SocketGRPC_Call_T call)
{
  SocketGRPC_H3CallStream *ctx;

  if (call == NULL)
    return -1;
  if (call->channel == NULL || call->channel->config.channel_mode != SOCKET_GRPC_CHANNEL_MODE_HTTP3)
    return -1;
  if (call->h3_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_LOCAL
      || call->h3_stream_state == GRPC_CALL_STREAM_CLOSED)
    return 0;
  if (call->h3_stream_state == GRPC_CALL_STREAM_FAILED)
    return -1;

  ctx = grpc_h3_stream_open_if_needed (call);
  if (ctx == NULL)
    return -1;

  if (SocketHTTP3_Request_send_data (ctx->request, NULL, 0, 1) != 0
      || SocketHTTP3_Client_flush (ctx->http3_client) != 0)
    {
      return grpc_h3_stream_fail (call,
                                  SOCKET_GRPC_STATUS_UNAVAILABLE,
                                  "Failed to close send direction",
                                  1);
    }

  call->h3_stream_state
      = (call->h3_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_REMOTE)
            ? GRPC_CALL_STREAM_CLOSED
            : GRPC_CALL_STREAM_HALF_CLOSED_LOCAL;
  return 0;
}

int
SocketGRPC_Call_h3_recv_message (SocketGRPC_Call_T call,
                                 Arena_T arena,
                                 uint8_t **response_payload,
                                 size_t *response_payload_len,
                                 int *done)
{
  SocketGRPC_H3CallStream *ctx;

  if (call == NULL || arena == NULL || response_payload == NULL
      || response_payload_len == NULL || done == NULL)
    return -1;

  *response_payload = NULL;
  *response_payload_len = 0;
  *done = 0;

  if (call->h3_stream_ctx == NULL)
    {
      if (call->h3_stream_state == GRPC_CALL_STREAM_CLOSED)
        {
          *done = 1;
          return 0;
        }
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_FAILED_PRECONDITION, "Stream not started");
      return -1;
    }

  if (call->h3_stream_state == GRPC_CALL_STREAM_FAILED)
    return -1;

  ctx = (SocketGRPC_H3CallStream *)call->h3_stream_ctx;

  if (!ctx->headers_received)
    {
      SocketHTTP_Headers_T headers = NULL;
      int status_code = 0;

      while (SocketHTTP3_Request_recv_headers (ctx->request, &headers, &status_code)
             != 0)
        {
          if (SocketTimeout_expired (ctx->deadline_ms))
            {
              return grpc_h3_stream_fail (call,
                                          SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
                                          "Deadline exceeded",
                                          1);
            }
          if (grpc_h3_poll_until_data (ctx->http3_client, ctx->deadline_ms) != 0)
            {
              return grpc_h3_stream_fail (call,
                                          SOCKET_GRPC_STATUS_UNAVAILABLE,
                                          "Failed to receive stream headers",
                                          1);
            }
        }

      if (grpc_ingest_response_headers (call, headers, 0) != 0)
        {
          return grpc_h3_stream_fail (call,
                                      SOCKET_GRPC_STATUS_INTERNAL,
                                      "Invalid streaming response headers",
                                      1);
        }

      ctx->headers_received = 1;
      ctx->http_status_code = status_code;
      ctx->response_compression = grpc_response_compression_from_headers (headers);
      if (ctx->response_compression == GRPC_COMPRESSION_UNSUPPORTED)
        {
          return grpc_h3_stream_fail (call,
                                      SOCKET_GRPC_STATUS_INTERNAL,
                                      "Unsupported response compression encoding",
                                      1);
        }
      if (ctx->response_compression == GRPC_COMPRESSION_GZIP)
        {
          return grpc_h3_stream_fail (call,
                                      SOCKET_GRPC_STATUS_INTERNAL,
                                      "Compressed streaming responses unsupported over HTTP/3",
                                      1);
        }
    }

  for (;;)
    {
      int has_message = 0;
      SocketGRPC_StatusCode parse_error_status = SOCKET_GRPC_STATUS_INTERNAL;
      const char *parse_error_message = "Malformed streaming response frame";

      if (grpc_h3_stream_try_parse_message (call,
                                            ctx,
                                            arena,
                                            response_payload,
                                            response_payload_len,
                                            &parse_error_status,
                                            &parse_error_message,
                                            &has_message)
          != 0)
        {
          return grpc_h3_stream_fail (
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
          grpc_client_metrics_bytes_received (call, *response_payload_len);
          return 0;
        }

      if (ctx->remote_end_stream)
        {
          if (ctx->recv_len != 0)
            {
              return grpc_h3_stream_fail (call,
                                          SOCKET_GRPC_STATUS_INTERNAL,
                                          "Incomplete gRPC frame at end of stream",
                                          1);
            }
          if (!ctx->status_finalized)
            {
              if (grpc_h3_stream_ingest_trailers_if_ready (call, ctx) != 0)
                {
                  return grpc_h3_stream_fail (call,
                                              SOCKET_GRPC_STATUS_INTERNAL,
                                              "Invalid stream trailers",
                                              1);
                }
              grpc_h3_stream_finalize_status (call, ctx->http_status_code);
              ctx->status_finalized = 1;
            }
          grpc_h3_stream_context_cleanup (call, 1, 0);
          *done = 1;
          return 0;
        }

      {
        unsigned char chunk[GRPC_RESPONSE_CHUNK];
        int end_stream = 0;
        ssize_t n
            = SocketHTTP3_Request_recv_data (ctx->request, chunk, sizeof (chunk), &end_stream);

        if (n < 0)
          {
            return grpc_h3_stream_fail (call,
                                        SOCKET_GRPC_STATUS_UNAVAILABLE,
                                        "Failed to receive stream body",
                                        1);
          }

        if (n > 0
            && grpc_h3_buffer_append (&ctx->recv_buffer,
                                      &ctx->recv_len,
                                      &ctx->recv_cap,
                                      chunk,
                                      (size_t)n,
                                      call->channel->config.max_cumulative_inflight_bytes)
                   != 0)
          {
            return grpc_h3_stream_fail (call,
                                        SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED,
                                        "Streaming response exceeds limit",
                                        1);
          }

        if (end_stream)
          {
            call->h3_stream_state
                = (call->h3_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_LOCAL)
                      ? GRPC_CALL_STREAM_CLOSED
                      : GRPC_CALL_STREAM_HALF_CLOSED_REMOTE;
            ctx->remote_end_stream = 1;
            if (grpc_h3_stream_ingest_trailers_if_ready (call, ctx) != 0)
              {
                return grpc_h3_stream_fail (call,
                                            SOCKET_GRPC_STATUS_INTERNAL,
                                            "Invalid stream trailers",
                                            1);
              }
          }

        if (n == 0 && !ctx->remote_end_stream)
          {
            if (SocketTimeout_expired (ctx->deadline_ms))
              {
                return grpc_h3_stream_fail (call,
                                            SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
                                            "Deadline exceeded",
                                            1);
              }
            if (grpc_h3_poll_until_data (ctx->http3_client, ctx->deadline_ms)
                != 0)
              {
                return grpc_h3_stream_fail (call,
                                            SOCKET_GRPC_STATUS_UNAVAILABLE,
                                            "Failed to advance stream state",
                                            1);
              }
          }
      }
    }
}

int
SocketGRPC_Call_h3_cancel (SocketGRPC_Call_T call)
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

  if (call->h3_stream_ctx != NULL)
    grpc_h3_stream_context_cleanup (call, 0, 1);

  return 0;
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

static int
grpc_call_unary_h3_single_attempt (SocketGRPC_Call_T call,
                                   const uint8_t *request_payload,
                                   size_t request_payload_len,
                                   Arena_T arena,
                                   uint8_t **response_payload,
                                   size_t *response_payload_len)
{
  SocketHTTP3_ClientConfig cfg;
  SocketHTTP3_Client_T client = NULL;
  SocketHTTP3_Request_T req = NULL;
  SocketHTTP_Headers_T headers = NULL;
  SocketHTTP_Headers_T response_headers = NULL;
  SocketHTTP_Headers_T response_trailers = NULL;
  Arena_T transport_arena = NULL;
  unsigned char *framed = NULL;
  size_t framed_cap;
  size_t framed_len = 0;
  unsigned char *raw_response = NULL;
  size_t raw_response_len = 0;
  size_t raw_response_cap = 0;
  char host[256];
  int port;
  int status_code = -1;
  int64_t deadline_ms = 0;

  if (call == NULL || request_payload == NULL || arena == NULL
      || response_payload == NULL || response_payload_len == NULL)
    return -1;

  if (call->h2_stream_ctx != NULL || call->h3_stream_ctx != NULL)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_FAILED_PRECONDITION,
                            "Cannot run unary call while stream is active");
      return -1;
    }

  if (call->channel == NULL || call->channel->config.channel_mode != SOCKET_GRPC_CHANNEL_MODE_HTTP3)
    return -1;

  if (call->channel->config.enable_request_compression)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_INTERNAL,
                            "Request compression over HTTP/3 not supported");
      return SOCKET_GRPC_STATUS_INTERNAL;
    }

  if (request_payload_len > call->channel->config.max_outbound_message_bytes
      || request_payload_len > (size_t)UINT32_MAX
      || request_payload_len > (SIZE_MAX - SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE))
    {
      grpc_call_status_set (call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL);
      return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
    }

  if (grpc_h3_parse_target (call->channel->target, host, sizeof (host), &port)
      != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INVALID_ARGUMENT, "Invalid channel target");
      return SOCKET_GRPC_STATUS_INVALID_ARGUMENT;
    }

  *response_payload = NULL;
  *response_payload_len = 0;
  SocketGRPC_Trailers_clear (call->response_trailers);
  deadline_ms = SocketTimeout_deadline_ms (call->config.deadline_ms);

  transport_arena = Arena_new ();
  if (transport_arena == NULL)
    {
      grpc_call_status_set (call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL);
      return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
    }

  SocketHTTP3_ClientConfig_defaults (&cfg);
  cfg.request_timeout_ms
      = call->config.deadline_ms > 0 ? (uint32_t)call->config.deadline_ms : 0U;
  cfg.verify_peer = call->channel->config.verify_peer;
  cfg.ca_file = call->channel->config.ca_file;

  client = SocketHTTP3_Client_new (transport_arena, &cfg);
  if (client == NULL)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INTERNAL, "HTTP/3 client allocation failed");
      status_code = SOCKET_GRPC_STATUS_INTERNAL;
      goto cleanup;
    }

  if (SocketHTTP3_Client_connect (client, host, port) != 0)
    {
      grpc_call_status_set (call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Connection failed");
      status_code = SOCKET_GRPC_STATUS_UNAVAILABLE;
      goto cleanup;
    }

  req = SocketHTTP3_Client_new_request (client);
  if (req == NULL)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INTERNAL, "Request initialization failed");
      status_code = SOCKET_GRPC_STATUS_INTERNAL;
      goto cleanup;
    }

  if (grpc_h3_build_request_headers (call, transport_arena, host, port, &headers)
      != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INTERNAL, "Failed to set request headers");
      status_code = SOCKET_GRPC_STATUS_INTERNAL;
      goto cleanup;
    }

  if (SocketHTTP3_Request_send_headers (req, headers, 0) != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to send request headers");
      status_code = SOCKET_GRPC_STATUS_UNAVAILABLE;
      goto cleanup;
    }

  framed_cap = SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE + request_payload_len;
  framed = (unsigned char *)malloc (framed_cap);
  if (framed == NULL)
    {
      grpc_call_status_set (call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL);
      status_code = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
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
      status_code = SOCKET_GRPC_STATUS_INTERNAL;
      goto cleanup;
    }

  if (SocketHTTP3_Request_send_data (req, framed, framed_len, 1) != 0
      || SocketHTTP3_Client_flush (client) != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to send request body");
      status_code = SOCKET_GRPC_STATUS_UNAVAILABLE;
      goto cleanup;
    }

  for (;;)
    {
      if (SocketHTTP3_Request_recv_state (req) == H3_REQ_RECV_COMPLETE)
        break;
      if (call->config.deadline_ms > 0
          && SocketTimeout_expired (deadline_ms))
        {
          grpc_call_status_set (
              call, SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED, "Deadline exceeded");
          status_code = SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED;
          goto cleanup;
        }
      if (grpc_h3_poll_until_data (client, deadline_ms) != 0)
        {
          grpc_call_status_set (call,
                                SOCKET_GRPC_STATUS_UNAVAILABLE,
                                "Failed to receive response");
          status_code = SOCKET_GRPC_STATUS_UNAVAILABLE;
          goto cleanup;
        }
    }

  if (SocketHTTP3_Request_recv_headers (req, &response_headers, &status_code) != 0
      || response_headers == NULL)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_UNAVAILABLE,
                            "Failed to receive response headers");
      status_code = SOCKET_GRPC_STATUS_UNAVAILABLE;
      goto cleanup;
    }

  if (grpc_ingest_response_headers (call, response_headers, 1) != 0)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_INTERNAL,
                            "Invalid response header metadata");
      status_code = SOCKET_GRPC_STATUS_INTERNAL;
      goto cleanup;
    }

  if (grpc_response_compression_from_headers (response_headers)
      == GRPC_COMPRESSION_UNSUPPORTED)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_INTERNAL,
                            "Unsupported response compression encoding");
      status_code = SOCKET_GRPC_STATUS_INTERNAL;
      goto cleanup;
    }

  if (grpc_response_compression_from_headers (response_headers)
      == GRPC_COMPRESSION_GZIP)
    {
      grpc_call_status_set (
          call,
          SOCKET_GRPC_STATUS_INTERNAL,
          "Compressed responses unsupported over HTTP/3");
      status_code = SOCKET_GRPC_STATUS_INTERNAL;
      goto cleanup;
    }

  for (;;)
    {
      unsigned char chunk[GRPC_RESPONSE_CHUNK];
      int end_stream = 0;
      ssize_t n = SocketHTTP3_Request_recv_data (req, chunk, sizeof (chunk), &end_stream);
      if (n < 0)
        {
          grpc_call_status_set (call,
                                SOCKET_GRPC_STATUS_UNAVAILABLE,
                                "Failed to receive response body");
          status_code = SOCKET_GRPC_STATUS_UNAVAILABLE;
          goto cleanup;
        }

      if (n > 0
          && grpc_h3_buffer_append (&raw_response,
                                    &raw_response_len,
                                    &raw_response_cap,
                                    chunk,
                                    (size_t)n,
                                    call->channel->config.max_cumulative_inflight_bytes)
                 != 0)
        {
          grpc_call_status_set (call,
                                SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED,
                                "Response exceeds configured inflight limit");
          status_code = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
          goto cleanup;
        }

      if (end_stream)
        break;
      if (n == 0 && grpc_h3_poll_until_data (client, deadline_ms) != 0)
        {
          grpc_call_status_set (call,
                                SOCKET_GRPC_STATUS_UNAVAILABLE,
                                "Failed to advance response stream");
          status_code = SOCKET_GRPC_STATUS_UNAVAILABLE;
          goto cleanup;
        }
    }

  if (SocketHTTP3_Request_recv_trailers (req, &response_trailers) == 0
      && response_trailers != NULL)
    {
      if (grpc_ingest_response_headers (call, response_trailers, 1) != 0)
        {
          grpc_call_status_set (call,
                                SOCKET_GRPC_STATUS_INTERNAL,
                                "Invalid response trailers");
          status_code = SOCKET_GRPC_STATUS_INTERNAL;
          goto cleanup;
        }
    }

  if (!SocketGRPC_Trailers_has_status (call->response_trailers))
    {
      SocketGRPC_StatusCode mapped = SocketGRPC_http_status_to_grpc (status_code);
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
      const char *decode_message = NULL;
      SocketGRPC_WireResult parse_rc;

      if (max_frame_payload == 0)
        max_frame_payload = call->channel->config.max_inbound_message_bytes;

      parse_rc = SocketGRPC_Frame_parse (
          raw_response, raw_response_len, max_frame_payload, &frame, &consumed);
      if (parse_rc != SOCKET_GRPC_WIRE_OK || consumed != raw_response_len)
        {
          decode_message = parse_rc == SOCKET_GRPC_WIRE_LENGTH_EXCEEDED
                               ? "Response exceeds configured inflight limit"
                               : "Malformed gRPC response frame";
          status_code = parse_rc == SOCKET_GRPC_WIRE_LENGTH_EXCEEDED
                            ? SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED
                            : SOCKET_GRPC_STATUS_INTERNAL;
          grpc_call_status_set (call, status_code, decode_message);
          (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                                status_code);
          (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                                 decode_message);
          goto cleanup;
        }

      if (frame.compressed != 0)
        {
          status_code = SOCKET_GRPC_STATUS_INTERNAL;
          decode_message = "Compressed responses unsupported over HTTP/3";
          grpc_call_status_set (call, status_code, decode_message);
          (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                                status_code);
          (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                                 decode_message);
          goto cleanup;
        }

      if (frame.payload_len > call->channel->config.max_inbound_message_bytes)
        {
          status_code = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
          decode_message = "Response message exceeds configured limit";
          grpc_call_status_set (call, status_code, decode_message);
          (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                                status_code);
          (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                                 decode_message);
          goto cleanup;
        }

      if (frame.payload_len > 0)
        {
          uint8_t *copy = (uint8_t *)ALLOC (arena, frame.payload_len);
          if (copy == NULL)
            {
              status_code = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
              grpc_call_status_set (call, status_code, NULL);
              (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                                    status_code);
              goto cleanup;
            }
          memcpy (copy, frame.payload, frame.payload_len);
          *response_payload = copy;
          *response_payload_len = frame.payload_len;
        }
    }
  else
    {
      *response_payload = NULL;
      *response_payload_len = 0;
    }

cleanup:
  free (raw_response);
  free (framed);
  if (client != NULL)
    (void)SocketHTTP3_Client_close (client);
  if (transport_arena != NULL)
    Arena_dispose (&transport_arena);

  return status_code;
}

int
SocketGRPC_Call_unary_h3 (SocketGRPC_Call_T call,
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
  int64_t call_started_ms;
  uint32_t finish_attempt = 1U;
  int observability_started = 0;

  if (call == NULL || request_payload == NULL || arena == NULL
      || response_payload == NULL || response_payload_len == NULL)
    return -1;

  *response_payload = NULL;
  *response_payload_len = 0;
  call_started_ms = SocketTimeout_now_ms ();
  observability_started = grpc_client_observability_enabled (call);
  grpc_client_observability_call_started (call, request_payload_len, 1U);

  if (grpc_run_client_unary_interceptors (
          call, request_payload, request_payload_len)
      != 0)
    {
      rc = (int)SocketGRPC_Call_status (call).code;
      goto finish;
    }
  grpc_client_metrics_bytes_sent (call, request_payload_len);

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
    {
      rc = grpc_call_unary_h3_single_attempt (call,
                                              request_payload,
                                              request_payload_len,
                                              arena,
                                              response_payload,
                                              response_payload_len);
      goto finish;
    }

  original_deadline_ms = call->config.deadline_ms;
  call_deadline_ms = SocketTimeout_deadline_ms (original_deadline_ms);
  backoff_ms = policy.initial_backoff_ms;
  call->retry_in_progress = 1;
  call->retry_attempt = 0;

  for (attempt = 1; attempt <= max_attempts; attempt++)
    {
      int status_code;
      finish_attempt = (uint32_t)attempt;

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
      rc = grpc_call_unary_h3_single_attempt (call,
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

        grpc_client_observability_call_retry (call, (uint32_t)(attempt + 1));
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

finish:
  if (rc == SOCKET_GRPC_STATUS_OK && *response_payload_len > 0)
    grpc_client_metrics_bytes_received (call, *response_payload_len);
  if (observability_started)
    {
      grpc_client_observability_call_finished (
          call, call_started_ms, *response_payload_len, finish_attempt);
    }
  return rc;
}

#endif /* SOCKET_HAS_TLS */

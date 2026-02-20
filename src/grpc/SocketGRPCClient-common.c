/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketGRPCClient-common.c
 * @brief Shared helpers for gRPC client H2/H3 transports.
 *
 * Functions in this file were previously duplicated across
 * SocketGRPCClient-h2.c and SocketGRPCClient-h3.c.
 */

#include "grpc/SocketGRPC-private.h"
#include "grpc/SocketGRPCWire.h"
#include "core/SocketCrypto.h"
#include "core/SocketMetrics.h"
#include "core/SocketUtil/Timeout.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

int
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

int
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

int
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
        continue;

      if (grpc_trailer_ingest_kv (
              call, h->name, h->name_len, h->value, h->value_len)
          != 0)
        return -1;
    }

  return 0;
}

SocketGRPC_Compression
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

int
grpc_client_observability_enabled (SocketGRPC_Call_T call)
{
  return call != NULL && call->channel != NULL && call->channel->client != NULL
         && call->channel->client->config.enable_observability;
}

const char *
grpc_client_event_peer (SocketGRPC_Call_T call)
{
  if (call == NULL || call->channel == NULL)
    return NULL;
  return call->channel->target;
}

const char *
grpc_client_event_authority (SocketGRPC_Call_T call)
{
  if (call == NULL || call->channel == NULL)
    return NULL;
  if (call->channel->authority_override != NULL)
    return call->channel->authority_override;
  return call->channel->target;
}

SocketCounterMetric
grpc_client_status_counter_metric (SocketGRPC_StatusCode code)
{
  SocketGRPC_StatusCode normalized = grpc_normalize_status_code (code);
  return (SocketCounterMetric)(SOCKET_CTR_GRPC_CLIENT_STATUS_OK
                               + (int)normalized);
}

void
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

void
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

void
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

void
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

void
grpc_client_metrics_bytes_sent (SocketGRPC_Call_T call, size_t payload_len)
{
  if (!grpc_client_observability_enabled (call) || payload_len == 0)
    return;

  SocketMetrics_counter_add (SOCKET_CTR_GRPC_CLIENT_BYTES_SENT,
                             (uint64_t)payload_len);
}

void
grpc_client_metrics_bytes_received (SocketGRPC_Call_T call, size_t payload_len)
{
  if (!grpc_client_observability_enabled (call) || payload_len == 0)
    return;

  SocketMetrics_counter_add (SOCKET_CTR_GRPC_CLIENT_BYTES_RECEIVED,
                             (uint64_t)payload_len);
}

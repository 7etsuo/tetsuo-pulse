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

#define GRPC_MAX_PATH_LEN 512
#define GRPC_MAX_AUTHORITY_LEN 320
#define GRPC_MAX_HOST_LEN 256

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
  if (parsed <= 0 || parsed > SOCKET_MAX_PORT)
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
  char authority[GRPC_MAX_AUTHORITY_LEN];
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
      *port_out = SOCKET_DEFAULT_HTTPS_PORT;
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
  if (port == SOCKET_DEFAULT_HTTPS_PORT)
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
grpc_h3_add_pseudo_headers (SocketGRPC_Call_T call,
                            SocketHTTP_Headers_T headers,
                            const char *host,
                            int port)
{
  char path_buf[GRPC_MAX_PATH_LEN];
  const char *path;
  char authority[GRPC_MAX_AUTHORITY_LEN];

  if (grpc_h3_build_authority (call, host, port, authority, sizeof (authority))
          != 0
      || SocketHTTP_Headers_add_pseudo_n (headers, ":method", 7, "POST", 4) != 0
      || SocketHTTP_Headers_add_pseudo_n (headers, ":scheme", 7, "https", 5)
             != 0)
    return -1;

  path = grpc_h3_method_path (call, path_buf, sizeof (path_buf));
  if (path == NULL
      || SocketHTTP_Headers_add_pseudo_n (
             headers, ":authority", 10, authority, strlen (authority))
             != 0
      || SocketHTTP_Headers_add_pseudo_n (
             headers, ":path", 5, path, strlen (path))
             != 0
      || SocketHTTP_Headers_add (headers, "content-type", GRPC_CONTENT_TYPE)
             != 0
      || SocketHTTP_Headers_add (headers, "te", "trailers") != 0
      || SocketHTTP_Headers_add (
             headers, "grpc-accept-encoding", GRPC_ACCEPT_ENCODING_VALUE)
             != 0)
    return -1;

  return 0;
}

static int
grpc_h3_add_optional_headers (SocketGRPC_Call_T call,
                              SocketHTTP_Headers_T headers)
{
  char timeout_buf[GRPC_TIMEOUT_HEADER_MAX];
  char attempt_buf[16];

  if (call->channel->config.enable_request_compression
      && SocketHTTP_Headers_add (headers, "grpc-encoding", GRPC_ENCODING_GZIP)
             != 0)
    return -1;

  if (call->channel->user_agent != NULL
      && SocketHTTP_Headers_add (
             headers, "user-agent", call->channel->user_agent)
             != 0)
    return -1;

  if (call->config.deadline_ms > 0)
    {
      if (SocketGRPC_Timeout_format ((int64_t)call->config.deadline_ms,
                                     timeout_buf,
                                     sizeof (timeout_buf))
              != 0
          || SocketHTTP_Headers_add (headers, "grpc-timeout", timeout_buf) != 0)
        return -1;
    }

  if (call->retry_attempt > 0)
    {
      int n = snprintf (
          attempt_buf, sizeof (attempt_buf), "%u", call->retry_attempt);
      if (n <= 0 || (size_t)n >= sizeof (attempt_buf)
          || SocketHTTP_Headers_add (
                 headers, "grpc-previous-rpc-attempts", attempt_buf)
                 != 0)
        return -1;
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

  if (call == NULL || arena == NULL || host == NULL || headers_out == NULL)
    return -1;

  *headers_out = NULL;
  headers = SocketHTTP_Headers_new (arena);
  if (headers == NULL)
    return -1;

  if (grpc_h3_add_pseudo_headers (call, headers, host, port) != 0)
    return -1;
  if (grpc_h3_add_optional_headers (call, headers) != 0)
    return -1;
  if (grpc_h3_add_metadata_headers (call, headers, call->request_metadata) != 0)
    return -1;

  *headers_out = headers;
  return 0;
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
  char host[GRPC_MAX_HOST_LEN];
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

  if (grpc_h3_build_request_headers (call, ctx->arena, host, port, &headers)
      != 0)
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
grpc_h3_validate_frame (const SocketGRPC_FrameView *frame,
                        size_t max_inbound_bytes,
                        SocketGRPC_StatusCode *error_status,
                        const char **error_message)
{
  if (frame->compressed != 0)
    {
      *error_status = SOCKET_GRPC_STATUS_INTERNAL;
      *error_message = "Compressed streaming responses unsupported over HTTP/3";
      return -1;
    }
  if (frame->payload_len > max_inbound_bytes)
    {
      *error_status = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
      *error_message = "Response message exceeds configured limit";
      return -1;
    }
  return 0;
}

static int
grpc_h3_copy_frame_payload (Arena_T arena,
                            const SocketGRPC_FrameView *frame,
                            uint8_t **response_payload,
                            size_t *response_payload_len,
                            SocketGRPC_StatusCode *error_status,
                            const char **error_message)
{
  uint8_t *copy;

  if (frame->payload_len == 0)
    return 0;

  copy = (uint8_t *)ALLOC (arena, frame->payload_len);
  if (copy == NULL)
    {
      *error_status = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
      *error_message = "Out of memory decoding response frame";
      return -1;
    }
  memcpy (copy, frame->payload, frame->payload_len);
  *response_payload = copy;
  *response_payload_len = frame->payload_len;
  return 0;
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

  if (grpc_h3_validate_frame (&frame,
                              call->channel->config.max_inbound_message_bytes,
                              error_status,
                              error_message)
      != 0)
    return -1;

  if (grpc_h3_copy_frame_payload (arena,
                                  &frame,
                                  response_payload,
                                  response_payload_len,
                                  error_status,
                                  error_message)
      != 0)
    return -1;

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

static int
grpc_h3_send_validate_preconditions (SocketGRPC_Call_T call,
                                     const uint8_t *request_payload,
                                     size_t request_payload_len)
{
  if (call == NULL || (request_payload == NULL && request_payload_len != 0))
    return -1;

  if (call->channel == NULL
      || call->channel->config.channel_mode != SOCKET_GRPC_CHANNEL_MODE_HTTP3)
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

  return 0;
}

static int
grpc_h3_frame_and_send (SocketGRPC_Call_T call,
                        SocketGRPC_H3CallStream *ctx,
                        const uint8_t *request_payload,
                        size_t request_payload_len)
{
  size_t framed_cap = SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE + request_payload_len;
  unsigned char *framed = (unsigned char *)malloc (framed_cap);
  size_t framed_len = 0;

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
  return 0;
}

int
SocketGRPC_Call_h3_send_message (SocketGRPC_Call_T call,
                                 const uint8_t *request_payload,
                                 size_t request_payload_len)
{
  SocketGRPC_H3CallStream *ctx;

  if (grpc_h3_send_validate_preconditions (
          call, request_payload, request_payload_len)
      != 0)
    return -1;

  if (grpc_run_client_stream_interceptors (call,
                                           SOCKET_GRPC_STREAM_INTERCEPT_SEND,
                                           request_payload,
                                           request_payload_len)
      != 0)
    return -1;

  ctx = grpc_h3_stream_open_if_needed (call);
  if (ctx == NULL)
    return -1;

  if (grpc_h3_frame_and_send (call, ctx, request_payload, request_payload_len)
      != 0)
    return -1;

  grpc_client_metrics_bytes_sent (call, request_payload_len);
  return 0;
}

int
SocketGRPC_Call_h3_close_send (SocketGRPC_Call_T call)
{
  SocketGRPC_H3CallStream *ctx;

  if (call == NULL)
    return -1;
  if (call->channel == NULL
      || call->channel->config.channel_mode != SOCKET_GRPC_CHANNEL_MODE_HTTP3)
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

static int
grpc_h3_recv_await_headers (SocketGRPC_Call_T call,
                            SocketGRPC_H3CallStream *ctx)
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
      return grpc_h3_stream_fail (
          call,
          SOCKET_GRPC_STATUS_INTERNAL,
          "Compressed streaming responses unsupported over HTTP/3",
          1);
    }

  return 0;
}

static int
grpc_h3_recv_handle_end_of_stream (SocketGRPC_Call_T call,
                                   SocketGRPC_H3CallStream *ctx,
                                   int *done)
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
          return grpc_h3_stream_fail (
              call, SOCKET_GRPC_STATUS_INTERNAL, "Invalid stream trailers", 1);
        }
      grpc_h3_stream_finalize_status (call, ctx->http_status_code);
      ctx->status_finalized = 1;
    }

  grpc_h3_stream_context_cleanup (call, 1, 0);
  *done = 1;
  return 0;
}

static int
grpc_h3_recv_read_chunk (SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx)
{
  unsigned char chunk[GRPC_RESPONSE_CHUNK];
  int end_stream = 0;
  ssize_t n = SocketHTTP3_Request_recv_data (
      ctx->request, chunk, sizeof (chunk), &end_stream);

  if (n < 0)
    {
      return grpc_h3_stream_fail (call,
                                  SOCKET_GRPC_STATUS_UNAVAILABLE,
                                  "Failed to receive stream body",
                                  1);
    }

  if (n > 0
      && grpc_h3_buffer_append (
             &ctx->recv_buffer,
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
          return grpc_h3_stream_fail (
              call, SOCKET_GRPC_STATUS_INTERNAL, "Invalid stream trailers", 1);
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
      if (grpc_h3_poll_until_data (ctx->http3_client, ctx->deadline_ms) != 0)
        {
          return grpc_h3_stream_fail (call,
                                      SOCKET_GRPC_STATUS_UNAVAILABLE,
                                      "Failed to advance stream state",
                                      1);
        }
    }

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

  if (!ctx->headers_received && grpc_h3_recv_await_headers (call, ctx) != 0)
    return -1;

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
        return grpc_h3_recv_handle_end_of_stream (call, ctx, done);

      if (grpc_h3_recv_read_chunk (call, ctx) != 0)
        return -1;
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
grpc_h3_unary_validate_preconditions (SocketGRPC_Call_T call,
                                      size_t request_payload_len,
                                      char *host,
                                      size_t host_cap,
                                      int *port)
{
  if (call->h2_stream_ctx != NULL || call->h3_stream_ctx != NULL)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_FAILED_PRECONDITION,
                            "Cannot run unary call while stream is active");
      return -1;
    }

  if (call->channel == NULL
      || call->channel->config.channel_mode != SOCKET_GRPC_CHANNEL_MODE_HTTP3)
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

  if (grpc_h3_parse_target (call->channel->target, host, host_cap, port) != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INVALID_ARGUMENT, "Invalid channel target");
      return SOCKET_GRPC_STATUS_INVALID_ARGUMENT;
    }

  return 0;
}

static int
grpc_h3_unary_setup_transport (SocketGRPC_Call_T call,
                               Arena_T transport_arena,
                               const char *host,
                               int port,
                               SocketHTTP3_Client_T *client_out,
                               SocketHTTP3_Request_T *req_out)
{
  SocketHTTP3_ClientConfig cfg;
  SocketHTTP3_Client_T client;
  SocketHTTP3_Request_T req;

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
      return SOCKET_GRPC_STATUS_INTERNAL;
    }

  if (SocketHTTP3_Client_connect (client, host, port) != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Connection failed");
      *client_out = client;
      return SOCKET_GRPC_STATUS_UNAVAILABLE;
    }

  req = SocketHTTP3_Client_new_request (client);
  if (req == NULL)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INTERNAL, "Request initialization failed");
      *client_out = client;
      return SOCKET_GRPC_STATUS_INTERNAL;
    }

  *client_out = client;
  *req_out = req;
  return 0;
}

static int
grpc_h3_unary_send_request (SocketGRPC_Call_T call,
                            Arena_T transport_arena,
                            SocketHTTP3_Client_T client,
                            SocketHTTP3_Request_T req,
                            const char *host,
                            int port,
                            const uint8_t *request_payload,
                            size_t request_payload_len,
                            unsigned char **framed_out)
{
  SocketHTTP_Headers_T headers = NULL;
  unsigned char *framed;
  size_t framed_cap;
  size_t framed_len = 0;

  if (grpc_h3_build_request_headers (
          call, transport_arena, host, port, &headers)
      != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INTERNAL, "Failed to set request headers");
      return SOCKET_GRPC_STATUS_INTERNAL;
    }

  if (SocketHTTP3_Request_send_headers (req, headers, 0) != 0)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_UNAVAILABLE,
                            "Failed to send request headers");
      return SOCKET_GRPC_STATUS_UNAVAILABLE;
    }

  framed_cap = SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE + request_payload_len;
  framed = (unsigned char *)malloc (framed_cap);
  if (framed == NULL)
    {
      grpc_call_status_set (call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL);
      return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
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
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INTERNAL, "Failed to frame request payload");
      return SOCKET_GRPC_STATUS_INTERNAL;
    }

  *framed_out = framed;

  if (SocketHTTP3_Request_send_data (req, framed, framed_len, 1) != 0
      || SocketHTTP3_Client_flush (client) != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to send request body");
      return SOCKET_GRPC_STATUS_UNAVAILABLE;
    }

  return 0;
}

static int
grpc_h3_unary_await_response (SocketGRPC_Call_T call,
                              SocketHTTP3_Client_T client,
                              SocketHTTP3_Request_T req,
                              int64_t deadline_ms)
{
  for (;;)
    {
      if (SocketHTTP3_Request_recv_state (req) == H3_REQ_RECV_COMPLETE)
        break;
      if (call->config.deadline_ms > 0 && SocketTimeout_expired (deadline_ms))
        {
          grpc_call_status_set (
              call, SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED, "Deadline exceeded");
          return SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED;
        }
      if (grpc_h3_poll_until_data (client, deadline_ms) != 0)
        {
          grpc_call_status_set (call,
                                SOCKET_GRPC_STATUS_UNAVAILABLE,
                                "Failed to receive response");
          return SOCKET_GRPC_STATUS_UNAVAILABLE;
        }
    }
  return 0;
}

static int
grpc_h3_unary_validate_response_headers (SocketGRPC_Call_T call,
                                         SocketHTTP3_Request_T req,
                                         SocketHTTP_Headers_T *headers_out,
                                         int *status_code)
{
  SocketHTTP_Headers_T response_headers = NULL;
  SocketGRPC_Compression comp;

  if (SocketHTTP3_Request_recv_headers (req, &response_headers, status_code)
          != 0
      || response_headers == NULL)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_UNAVAILABLE,
                            "Failed to receive response headers");
      return SOCKET_GRPC_STATUS_UNAVAILABLE;
    }

  if (grpc_ingest_response_headers (call, response_headers, 1) != 0)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_INTERNAL,
                            "Invalid response header metadata");
      return SOCKET_GRPC_STATUS_INTERNAL;
    }

  comp = grpc_response_compression_from_headers (response_headers);

  if (comp == GRPC_COMPRESSION_UNSUPPORTED)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_INTERNAL,
                            "Unsupported response compression encoding");
      return SOCKET_GRPC_STATUS_INTERNAL;
    }

  if (comp == GRPC_COMPRESSION_GZIP)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_INTERNAL,
                            "Compressed responses unsupported over HTTP/3");
      return SOCKET_GRPC_STATUS_INTERNAL;
    }

  *headers_out = response_headers;
  return 0;
}

static int
grpc_h3_unary_recv_body (SocketGRPC_Call_T call,
                         SocketHTTP3_Client_T client,
                         SocketHTTP3_Request_T req,
                         int64_t deadline_ms,
                         unsigned char **raw_response,
                         size_t *raw_response_len,
                         size_t *raw_response_cap)
{
  for (;;)
    {
      unsigned char chunk[GRPC_RESPONSE_CHUNK];
      int end_stream = 0;
      ssize_t n = SocketHTTP3_Request_recv_data (
          req, chunk, sizeof (chunk), &end_stream);
      if (n < 0)
        {
          grpc_call_status_set (call,
                                SOCKET_GRPC_STATUS_UNAVAILABLE,
                                "Failed to receive response body");
          return SOCKET_GRPC_STATUS_UNAVAILABLE;
        }

      if (n > 0
          && grpc_h3_buffer_append (
                 raw_response,
                 raw_response_len,
                 raw_response_cap,
                 chunk,
                 (size_t)n,
                 call->channel->config.max_cumulative_inflight_bytes)
                 != 0)
        {
          grpc_call_status_set (call,
                                SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED,
                                "Response exceeds configured inflight limit");
          return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
        }

      if (end_stream)
        break;
      if (n == 0 && grpc_h3_poll_until_data (client, deadline_ms) != 0)
        {
          grpc_call_status_set (call,
                                SOCKET_GRPC_STATUS_UNAVAILABLE,
                                "Failed to advance response stream");
          return SOCKET_GRPC_STATUS_UNAVAILABLE;
        }
    }
  return 0;
}

static int
grpc_h3_unary_process_trailers (SocketGRPC_Call_T call,
                                SocketHTTP3_Request_T req,
                                int status_code)
{
  SocketHTTP_Headers_T response_trailers = NULL;

  if (SocketHTTP3_Request_recv_trailers (req, &response_trailers) == 0
      && response_trailers != NULL)
    {
      if (grpc_ingest_response_headers (call, response_trailers, 1) != 0)
        {
          grpc_call_status_set (
              call, SOCKET_GRPC_STATUS_INTERNAL, "Invalid response trailers");
          return SOCKET_GRPC_STATUS_INTERNAL;
        }
    }

  if (!SocketGRPC_Trailers_has_status (call->response_trailers))
    {
      SocketGRPC_StatusCode mapped
          = SocketGRPC_http_status_to_grpc (status_code);
      (void)SocketGRPC_Trailers_set_status (call->response_trailers, mapped);
    }

  status_code = SocketGRPC_Trailers_status (call->response_trailers);
  grpc_call_status_set (call,
                        (SocketGRPC_StatusCode)status_code,
                        SocketGRPC_Trailers_message (call->response_trailers));

  return status_code;
}

static int
grpc_h3_unary_decode_response_frame (SocketGRPC_Call_T call,
                                     Arena_T arena,
                                     const unsigned char *raw_response,
                                     size_t raw_response_len,
                                     uint8_t **response_payload,
                                     size_t *response_payload_len)
{
  SocketGRPC_FrameView frame;
  size_t consumed = 0;
  size_t max_frame_payload
      = call->channel->config.max_cumulative_inflight_bytes;
  const char *decode_message = NULL;
  SocketGRPC_WireResult parse_rc;
  int status_code;

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
      return status_code;
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
      return status_code;
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
      return status_code;
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
          return status_code;
        }
      memcpy (copy, frame.payload, frame.payload_len);
      *response_payload = copy;
      *response_payload_len = frame.payload_len;
    }

  return SOCKET_GRPC_STATUS_OK;
}

static int
grpc_call_unary_h3_single_attempt (SocketGRPC_Call_T call,
                                   const uint8_t *request_payload,
                                   size_t request_payload_len,
                                   Arena_T arena,
                                   uint8_t **response_payload,
                                   size_t *response_payload_len)
{
  SocketHTTP3_Client_T client = NULL;
  SocketHTTP3_Request_T req = NULL;
  SocketHTTP_Headers_T response_headers = NULL;
  Arena_T transport_arena = NULL;
  unsigned char *framed = NULL;
  unsigned char *raw_response = NULL;
  size_t raw_response_len = 0;
  size_t raw_response_cap = 0;
  char host[GRPC_MAX_HOST_LEN];
  int port;
  int status_code = -1;
  int http_status = 0;
  int64_t deadline_ms = 0;
  int rc;

  if (call == NULL || request_payload == NULL || arena == NULL
      || response_payload == NULL || response_payload_len == NULL)
    return -1;

  rc = grpc_h3_unary_validate_preconditions (
      call, request_payload_len, host, sizeof (host), &port);
  if (rc != 0)
    return rc;

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

  status_code = grpc_h3_unary_setup_transport (
      call, transport_arena, host, port, &client, &req);
  if (status_code != 0)
    goto cleanup;

  status_code = grpc_h3_unary_send_request (call,
                                            transport_arena,
                                            client,
                                            req,
                                            host,
                                            port,
                                            request_payload,
                                            request_payload_len,
                                            &framed);
  if (status_code != 0)
    goto cleanup;

  status_code = grpc_h3_unary_await_response (call, client, req, deadline_ms);
  if (status_code != 0)
    goto cleanup;

  status_code = grpc_h3_unary_validate_response_headers (
      call, req, &response_headers, &http_status);
  if (status_code != 0)
    goto cleanup;

  status_code = grpc_h3_unary_recv_body (call,
                                         client,
                                         req,
                                         deadline_ms,
                                         &raw_response,
                                         &raw_response_len,
                                         &raw_response_cap);
  if (status_code != 0)
    goto cleanup;

  status_code = grpc_h3_unary_process_trailers (call, req, http_status);

  if (status_code == SOCKET_GRPC_STATUS_OK && raw_response != NULL
      && raw_response_len > 0)
    {
      status_code = grpc_h3_unary_decode_response_frame (call,
                                                         arena,
                                                         raw_response,
                                                         raw_response_len,
                                                         response_payload,
                                                         response_payload_len);
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

static void
grpc_h3_set_deadline_exceeded (SocketGRPC_Call_T call)
{
  grpc_call_status_set (
      call, SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED, "Deadline exceeded");
  (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                        SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED);
  (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                         "Deadline exceeded");
}

static int
grpc_h3_retry_update_deadline (SocketGRPC_Call_T call,
                               int64_t call_deadline_ms,
                               int original_deadline_ms)
{
  if (call_deadline_ms > 0)
    {
      int64_t remaining = SocketTimeout_remaining_ms (call_deadline_ms);
      if (remaining <= 0)
        return -1;
      call->config.deadline_ms
          = (remaining > INT_MAX) ? INT_MAX : (int)remaining;
    }
  else
    {
      call->config.deadline_ms = original_deadline_ms;
    }
  return 0;
}

static int
grpc_h3_retry_wait_and_backoff (SocketGRPC_Call_T call,
                                const SocketGRPC_RetryPolicy *policy,
                                int64_t call_deadline_ms,
                                int64_t *backoff_ms,
                                int attempt)
{
  int64_t wait_ms = grpc_retry_jittered_backoff_ms (policy, *backoff_ms);

  if (call_deadline_ms > 0)
    {
      int64_t remaining = SocketTimeout_remaining_ms (call_deadline_ms);
      if (remaining <= 0)
        return -1;
      if (wait_ms > remaining)
        wait_ms = remaining;
    }

  grpc_client_observability_call_retry (call, (uint32_t)(attempt + 1));
  if (wait_ms > 0)
    grpc_retry_sleep_ms (wait_ms);

  *backoff_ms = grpc_retry_next_backoff_ms (policy, *backoff_ms);
  return 0;
}

static int
grpc_h3_retry_loop (SocketGRPC_Call_T call,
                    const SocketGRPC_RetryPolicy *policy,
                    int max_attempts,
                    const uint8_t *request_payload,
                    size_t request_payload_len,
                    Arena_T arena,
                    uint8_t **response_payload,
                    size_t *response_payload_len,
                    uint32_t *finish_attempt)
{
  int original_deadline_ms = call->config.deadline_ms;
  int64_t call_deadline_ms = SocketTimeout_deadline_ms (original_deadline_ms);
  int64_t backoff_ms = policy->initial_backoff_ms;
  int rc = -1;
  int attempt;

  call->retry_in_progress = 1;
  call->retry_attempt = 0;

  for (attempt = 1; attempt <= max_attempts; attempt++)
    {
      int status_code;
      *finish_attempt = (uint32_t)attempt;

      if (SocketTimeout_expired (call_deadline_ms))
        {
          rc = SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED;
          grpc_h3_set_deadline_exceeded (call);
          break;
        }

      if (grpc_h3_retry_update_deadline (
              call, call_deadline_ms, original_deadline_ms)
          != 0)
        {
          rc = SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED;
          grpc_h3_set_deadline_exceeded (call);
          break;
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
      if (!grpc_retry_status_is_retryable (policy, status_code))
        break;

      if (grpc_h3_retry_wait_and_backoff (
              call, policy, call_deadline_ms, &backoff_ms, attempt)
          != 0)
        {
          rc = SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED;
          break;
        }
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
  int rc = -1;
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
    max_attempts = policy.max_attempts;

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

  rc = grpc_h3_retry_loop (call,
                           &policy,
                           max_attempts,
                           request_payload,
                           request_payload_len,
                           arena,
                           response_payload,
                           response_payload_len,
                           &finish_attempt);

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

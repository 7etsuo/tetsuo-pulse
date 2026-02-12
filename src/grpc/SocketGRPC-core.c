/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketGRPC-core.c
 * @brief Phase-0 gRPC lifecycle and status helper implementation.
 */

#include "grpc/SocketGRPC-private.h"
#include "grpc/SocketGRPCWire.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const Except_T SocketGRPC_Failed
    = { &SocketGRPC_Failed, "gRPC operation failed" };
const Except_T SocketGRPC_InvalidArgument
    = { &SocketGRPC_InvalidArgument, "gRPC invalid argument" };
const Except_T SocketGRPC_OutOfMemory
    = { &SocketGRPC_OutOfMemory, "gRPC out of memory" };

static const char *grpc_status_code_names[]
    = { "OK",
        "CANCELLED",
        "UNKNOWN",
        "INVALID_ARGUMENT",
        "DEADLINE_EXCEEDED",
        "NOT_FOUND",
        "ALREADY_EXISTS",
        "PERMISSION_DENIED",
        "RESOURCE_EXHAUSTED",
        "FAILED_PRECONDITION",
        "ABORTED",
        "OUT_OF_RANGE",
        "UNIMPLEMENTED",
        "INTERNAL",
        "UNAVAILABLE",
        "DATA_LOSS",
        "UNAUTHENTICATED" };

static const char *grpc_status_default_messages[]
    = { "Success",
        "Operation cancelled",
        "Unknown error",
        "Invalid argument",
        "Deadline exceeded",
        "Requested entity was not found",
        "Entity already exists",
        "Permission denied",
        "Resource exhausted",
        "Operation rejected due to current system state",
        "Operation aborted",
        "Operation out of range",
        "Operation not implemented",
        "Internal error",
        "Service unavailable",
        "Unrecoverable data loss",
        "Unauthenticated request" };

_Static_assert (sizeof (grpc_status_code_names)
                        / sizeof (grpc_status_code_names[0])
                    == SOCKET_GRPC_STATUS_UNAUTHENTICATED + 1,
                "grpc_status_code_names must map all canonical gRPC codes");

_Static_assert (sizeof (grpc_status_default_messages)
                        / sizeof (grpc_status_default_messages[0])
                    == SOCKET_GRPC_STATUS_UNAUTHENTICATED + 1,
                "grpc_status_default_messages must map all canonical gRPC "
                "codes");

static int
grpc_status_is_valid (SocketGRPC_StatusCode code)
{
  return code >= SOCKET_GRPC_STATUS_OK
         && code <= SOCKET_GRPC_STATUS_UNAUTHENTICATED;
}

const char *
SocketGRPC_status_default_message (SocketGRPC_StatusCode code)
{
  if (grpc_status_is_valid (code))
    return grpc_status_default_messages[code];
  return "Unknown gRPC status code";
}

void
SocketGRPC_status_set (SocketGRPC_Status *status,
                       SocketGRPC_StatusCode code,
                       const char *message)
{
  if (status == NULL)
    return;

  status->code = code;
  if (message != NULL && message[0] != '\0')
    status->message = message;
  else
    status->message = SocketGRPC_status_default_message (code);
}

SocketGRPC_StatusCode
SocketGRPC_Status_code (const SocketGRPC_Status *status)
{
  if (status == NULL)
    return SOCKET_GRPC_STATUS_INTERNAL;
  return status->code;
}

const char *
SocketGRPC_Status_message (const SocketGRPC_Status *status)
{
  if (status == NULL)
    return "Status unavailable";

  if (status->message != NULL && status->message[0] != '\0')
    return status->message;

  return SocketGRPC_status_default_message (status->code);
}

int
SocketGRPC_Timeout_format (int64_t timeout_ms, char *out, size_t out_len)
{
  int written;

  if (out == NULL || out_len == 0 || timeout_ms <= 0)
    return -1;

  written = snprintf (out, out_len, "%lldm", (long long)timeout_ms);
  if (written <= 0 || (size_t)written >= out_len)
    return -1;
  return 0;
}

int
SocketGRPC_Timeout_parse (const char *value, int64_t *timeout_ms_out)
{
  size_t len;
  size_t i;
  int64_t num = 0;
  char unit;

  if (value == NULL || timeout_ms_out == NULL)
    return -1;

  len = strlen (value);
  if (len < 2 || len > 9)
    return -1;

  unit = value[len - 1];
  for (i = 0; i < len - 1; i++)
    {
      if (!isdigit ((unsigned char)value[i]))
        return -1;
      if (num > (INT64_MAX - 9) / 10)
        return -1;
      num = (num * 10) + (value[i] - '0');
    }
  if (num <= 0)
    return -1;

  switch (unit)
    {
    case 'H':
      if (num > INT64_MAX / (60LL * 60LL * 1000LL))
        return -1;
      *timeout_ms_out = num * 60LL * 60LL * 1000LL;
      return 0;
    case 'M':
      if (num > INT64_MAX / (60LL * 1000LL))
        return -1;
      *timeout_ms_out = num * 60LL * 1000LL;
      return 0;
    case 'S':
      if (num > INT64_MAX / 1000LL)
        return -1;
      *timeout_ms_out = num * 1000LL;
      return 0;
    case 'm':
      *timeout_ms_out = num;
      return 0;
    case 'u':
      *timeout_ms_out = (num + 999LL) / 1000LL;
      if (*timeout_ms_out <= 0)
        *timeout_ms_out = 1;
      return 0;
    case 'n':
      *timeout_ms_out = (num + 999999LL) / 1000000LL;
      if (*timeout_ms_out <= 0)
        *timeout_ms_out = 1;
      return 0;
    default:
      return -1;
    }
}

void
SocketGRPC_RetryPolicy_defaults (SocketGRPC_RetryPolicy *policy)
{
  if (policy == NULL)
    return;

  policy->max_attempts = SOCKET_GRPC_DEFAULT_RETRY_MAX_ATTEMPTS;
  policy->initial_backoff_ms = SOCKET_GRPC_DEFAULT_RETRY_INITIAL_BACKOFF_MS;
  policy->max_backoff_ms = SOCKET_GRPC_DEFAULT_RETRY_MAX_BACKOFF_MS;
  policy->backoff_multiplier = SOCKET_GRPC_DEFAULT_RETRY_BACKOFF_MULTIPLIER;
  policy->jitter_percent = SOCKET_GRPC_DEFAULT_RETRY_JITTER_PERCENT;
  policy->retryable_status_mask = SOCKET_GRPC_DEFAULT_RETRYABLE_STATUS_MASK;
}

int
SocketGRPC_RetryPolicy_validate (const SocketGRPC_RetryPolicy *policy)
{
  if (policy == NULL)
    return -1;
  if (policy->max_attempts < 1 || policy->max_attempts > 10)
    return -1;
  if (policy->initial_backoff_ms < 0 || policy->max_backoff_ms < 0)
    return -1;
  if (policy->max_backoff_ms > 0
      && policy->initial_backoff_ms > policy->max_backoff_ms)
    return -1;
  if (!isfinite (policy->backoff_multiplier)
      || policy->backoff_multiplier < 1.0
      || policy->backoff_multiplier > 10.0)
    return -1;
  if (policy->jitter_percent < 0 || policy->jitter_percent > 100)
    return -1;
  if (policy->max_attempts > 1 && policy->retryable_status_mask == 0)
    return -1;
  return 0;
}

static int
grpc_status_name_to_code (const char *name, SocketGRPC_StatusCode *code_out)
{
  int i;

  if (name == NULL || code_out == NULL)
    return -1;

  for (i = SOCKET_GRPC_STATUS_OK; i <= SOCKET_GRPC_STATUS_UNAUTHENTICATED; i++)
    {
      if (strcmp (name, grpc_status_code_names[i]) == 0)
        {
          *code_out = (SocketGRPC_StatusCode)i;
          return 0;
        }
    }

  return -1;
}

static char *
grpc_trim_ascii (char *s)
{
  char *end;
  if (s == NULL)
    return NULL;
  while (*s != '\0' && isspace ((unsigned char)*s))
    s++;
  end = s + strlen (s);
  while (end > s && isspace ((unsigned char)end[-1]))
    end--;
  *end = '\0';
  return s;
}

static int
grpc_parse_int_strict (const char *value, int *out)
{
  char *end = NULL;
  long parsed;

  if (value == NULL || out == NULL || value[0] == '\0')
    return -1;

  errno = 0;
  parsed = strtol (value, &end, 10);
  if (errno != 0 || end == value || end == NULL || *end != '\0')
    return -1;
  if (parsed < INT_MIN || parsed > INT_MAX)
    return -1;

  *out = (int)parsed;
  return 0;
}

static int
grpc_parse_double_strict (const char *value, double *out)
{
  char *end = NULL;
  double parsed;

  if (value == NULL || out == NULL || value[0] == '\0')
    return -1;

  errno = 0;
  parsed = strtod (value, &end);
  if (errno != 0 || end == value || end == NULL || *end != '\0')
    return -1;

  *out = parsed;
  return 0;
}

int
SocketGRPC_RetryPolicy_parse_service_config (const char *spec,
                                             SocketGRPC_RetryPolicy *policy)
{
  char *copy;
  char *token;
  char *saveptr = NULL;

  if (spec == NULL || policy == NULL)
    return -1;

  SocketGRPC_RetryPolicy_defaults (policy);
  copy = strdup (spec);
  if (copy == NULL)
    return -1;

  token = strtok_r (copy, ",", &saveptr);
  while (token != NULL)
    {
      char *eq = strchr (token, '=');
      char *key;
      char *value;

      if (eq == NULL)
        {
          free (copy);
          return -1;
        }
      *eq = '\0';
      key = grpc_trim_ascii (token);
      value = grpc_trim_ascii (eq + 1);
      if (key == NULL || value == NULL || key[0] == '\0' || value[0] == '\0')
        {
          free (copy);
          return -1;
        }

      if (strcmp (key, "max_attempts") == 0)
        {
          if (grpc_parse_int_strict (value, &policy->max_attempts) != 0)
            {
              free (copy);
              return -1;
            }
        }
      else if (strcmp (key, "initial_backoff_ms") == 0)
        {
          if (grpc_parse_int_strict (value, &policy->initial_backoff_ms) != 0)
            {
              free (copy);
              return -1;
            }
        }
      else if (strcmp (key, "max_backoff_ms") == 0)
        {
          if (grpc_parse_int_strict (value, &policy->max_backoff_ms) != 0)
            {
              free (copy);
              return -1;
            }
        }
      else if (strcmp (key, "multiplier") == 0)
        {
          if (grpc_parse_double_strict (value, &policy->backoff_multiplier) != 0)
            {
              free (copy);
              return -1;
            }
        }
      else if (strcmp (key, "jitter_percent") == 0)
        {
          if (grpc_parse_int_strict (value, &policy->jitter_percent) != 0)
            {
              free (copy);
              return -1;
            }
        }
      else if (strcmp (key, "retryable_codes") == 0)
        {
          char *list_copy = strdup (value);
          char *code_tok;
          char *code_save = NULL;
          uint32_t mask = 0;

          if (list_copy == NULL)
            {
              free (copy);
              return -1;
            }

          code_tok = strtok_r (list_copy, "|", &code_save);
          while (code_tok != NULL)
            {
              SocketGRPC_StatusCode code;
              char *trimmed = grpc_trim_ascii (code_tok);
              if (grpc_status_name_to_code (trimmed, &code) != 0)
                {
                  free (list_copy);
                  free (copy);
                  return -1;
                }
              if ((int)code >= 0 && (int)code < 32)
                mask |= (1U << (unsigned int)code);
              code_tok = strtok_r (NULL, "|", &code_save);
            }

          free (list_copy);
          policy->retryable_status_mask = mask;
        }
      else
        {
          free (copy);
          return -1;
        }

      token = strtok_r (NULL, ",", &saveptr);
    }

  free (copy);
  return SocketGRPC_RetryPolicy_validate (policy);
}

const char *
SocketGRPC_Status_code_name (SocketGRPC_StatusCode code)
{
  if (grpc_status_is_valid (code))
    return grpc_status_code_names[code];
  return "UNKNOWN_CODE";
}

void
SocketGRPC_ClientConfig_defaults (SocketGRPC_ClientConfig *config)
{
  if (config == NULL)
    return;

  config->max_concurrent_channels = SOCKET_GRPC_DEFAULT_MAX_CONCURRENT_CHANNELS;
  config->max_outstanding_calls = SOCKET_GRPC_DEFAULT_MAX_OUTSTANDING_CALLS;
  config->enable_retry = SOCKET_GRPC_DEFAULT_ENABLE_RETRY;
}

void
SocketGRPC_ServerConfig_defaults (SocketGRPC_ServerConfig *config)
{
  if (config == NULL)
    return;

  config->max_concurrent_connections
      = SOCKET_GRPC_DEFAULT_MAX_CONCURRENT_CONNECTIONS;
  config->max_outstanding_calls = SOCKET_GRPC_DEFAULT_MAX_OUTSTANDING_CALLS;
}

void
SocketGRPC_ChannelConfig_defaults (SocketGRPC_ChannelConfig *config)
{
  if (config == NULL)
    return;

  config->max_inbound_message_bytes
      = SOCKET_GRPC_DEFAULT_MAX_INBOUND_MESSAGE_BYTES;
  config->max_outbound_message_bytes
      = SOCKET_GRPC_DEFAULT_MAX_OUTBOUND_MESSAGE_BYTES;
  config->max_metadata_entries = SOCKET_GRPC_DEFAULT_MAX_METADATA_ENTRIES;
  config->authority_override = NULL;
  config->user_agent = SOCKET_GRPC_DEFAULT_USER_AGENT;
  config->tls_context = NULL;
  config->verify_peer = SOCKET_GRPC_DEFAULT_VERIFY_PEER;
  config->allow_http2_cleartext = SOCKET_GRPC_DEFAULT_ALLOW_HTTP2_CLEARTEXT;
  config->enable_response_decompression
      = SOCKET_GRPC_DEFAULT_ENABLE_RESPONSE_DECOMPRESSION;
  config->enable_request_compression
      = SOCKET_GRPC_DEFAULT_ENABLE_REQUEST_COMPRESSION;
  config->max_decompressed_message_bytes
      = SOCKET_GRPC_DEFAULT_MAX_DECOMPRESSED_MESSAGE_BYTES;
  config->max_cumulative_inflight_bytes
      = SOCKET_GRPC_DEFAULT_MAX_CUMULATIVE_INFLIGHT_BYTES;
  config->max_decompression_ratio
      = SOCKET_GRPC_DEFAULT_MAX_DECOMPRESSION_RATIO;
}

void
SocketGRPC_CallConfig_defaults (SocketGRPC_CallConfig *config)
{
  if (config == NULL)
    return;

  config->deadline_ms = SOCKET_GRPC_DEFAULT_DEADLINE_MS;
  config->wait_for_ready = SOCKET_GRPC_DEFAULT_WAIT_FOR_READY;
  SocketGRPC_RetryPolicy_defaults (&config->retry_policy);
}

static void
grpc_sanitize_client_config (SocketGRPC_ClientConfig *config)
{
  if (config->max_concurrent_channels == 0)
    config->max_concurrent_channels = SOCKET_GRPC_DEFAULT_MAX_CONCURRENT_CHANNELS;
  if (config->max_outstanding_calls == 0)
    config->max_outstanding_calls = SOCKET_GRPC_DEFAULT_MAX_OUTSTANDING_CALLS;
  config->enable_retry = config->enable_retry ? 1 : 0;
}

static void
grpc_sanitize_server_config (SocketGRPC_ServerConfig *config)
{
  if (config->max_concurrent_connections == 0)
    config->max_concurrent_connections
        = SOCKET_GRPC_DEFAULT_MAX_CONCURRENT_CONNECTIONS;
  if (config->max_outstanding_calls == 0)
    config->max_outstanding_calls = SOCKET_GRPC_DEFAULT_MAX_OUTSTANDING_CALLS;
}

static void
grpc_sanitize_channel_config (SocketGRPC_ChannelConfig *config)
{
  if (config->max_inbound_message_bytes == 0)
    config->max_inbound_message_bytes
        = SOCKET_GRPC_DEFAULT_MAX_INBOUND_MESSAGE_BYTES;
  if (config->max_outbound_message_bytes == 0)
    config->max_outbound_message_bytes
        = SOCKET_GRPC_DEFAULT_MAX_OUTBOUND_MESSAGE_BYTES;
  if (config->max_metadata_entries == 0)
    config->max_metadata_entries = SOCKET_GRPC_DEFAULT_MAX_METADATA_ENTRIES;
  if (config->user_agent == NULL || config->user_agent[0] == '\0')
    config->user_agent = SOCKET_GRPC_DEFAULT_USER_AGENT;
  config->verify_peer = config->verify_peer ? 1 : 0;
  config->allow_http2_cleartext = config->allow_http2_cleartext ? 1 : 0;
  config->enable_response_decompression
      = config->enable_response_decompression ? 1 : 0;
  config->enable_request_compression
      = config->enable_request_compression ? 1 : 0;
  if (config->max_decompressed_message_bytes == 0)
    config->max_decompressed_message_bytes
        = SOCKET_GRPC_DEFAULT_MAX_DECOMPRESSED_MESSAGE_BYTES;
  if (config->max_cumulative_inflight_bytes == 0)
    config->max_cumulative_inflight_bytes
        = SOCKET_GRPC_DEFAULT_MAX_CUMULATIVE_INFLIGHT_BYTES;
  if (config->max_decompression_ratio < 0.0)
    config->max_decompression_ratio = 0.0;
  else if (config->max_decompression_ratio > 0.0
           && config->max_decompression_ratio < 1.0)
    config->max_decompression_ratio = 1.0;
}

static void
grpc_sanitize_call_config (SocketGRPC_CallConfig *config)
{
  if (config->deadline_ms < 0)
    config->deadline_ms = SOCKET_GRPC_DEFAULT_DEADLINE_MS;
  config->wait_for_ready = config->wait_for_ready ? 1 : 0;
  if (SocketGRPC_RetryPolicy_validate (&config->retry_policy) != 0)
    SocketGRPC_RetryPolicy_defaults (&config->retry_policy);
}

static char *
grpc_strdup_required (const char *src)
{
  if (src == NULL || src[0] == '\0')
    return NULL;
  return strdup (src);
}

static char *
grpc_strdup_optional (const char *src)
{
  if (src == NULL || src[0] == '\0')
    return NULL;
  return strdup (src);
}

SocketGRPC_Client_T
SocketGRPC_Client_new (const SocketGRPC_ClientConfig *config)
{
  SocketGRPC_Client_T client = calloc (1, sizeof (*client));
  if (client == NULL)
    return NULL;

  if (config != NULL)
    client->config = *config;
  else
    SocketGRPC_ClientConfig_defaults (&client->config);

  grpc_sanitize_client_config (&client->config);
  SocketGRPC_status_set (
      &client->last_status, SOCKET_GRPC_STATUS_OK, "Client initialized");
  return client;
}

void
SocketGRPC_Client_free (SocketGRPC_Client_T *client)
{
  if (client == NULL || *client == NULL)
    return;

  memset (*client, 0, sizeof (**client));
  free (*client);
  *client = NULL;
}

SocketGRPC_Server_T
SocketGRPC_Server_new (const SocketGRPC_ServerConfig *config)
{
  SocketGRPC_Server_T server = calloc (1, sizeof (*server));
  if (server == NULL)
    return NULL;

  if (config != NULL)
    server->config = *config;
  else
    SocketGRPC_ServerConfig_defaults (&server->config);

  grpc_sanitize_server_config (&server->config);
  SocketGRPC_status_set (
      &server->last_status, SOCKET_GRPC_STATUS_OK, "Server initialized");
  return server;
}

void
SocketGRPC_Server_free (SocketGRPC_Server_T *server)
{
  if (server == NULL || *server == NULL)
    return;

  SocketGRPC_server_methods_clear (*server);
  memset (*server, 0, sizeof (**server));
  free (*server);
  *server = NULL;
}

SocketGRPC_Channel_T
SocketGRPC_Channel_new (SocketGRPC_Client_T client,
                        const char *target,
                        const SocketGRPC_ChannelConfig *config)
{
  SocketGRPC_Channel_T channel;

  if (client == NULL || target == NULL || target[0] == '\0')
    return NULL;

  channel = calloc (1, sizeof (*channel));
  if (channel == NULL)
    return NULL;

  channel->target = grpc_strdup_required (target);
  if (channel->target == NULL)
    {
      free (channel);
      return NULL;
    }

  if (config != NULL)
    channel->config = *config;
  else
    SocketGRPC_ChannelConfig_defaults (&channel->config);

  grpc_sanitize_channel_config (&channel->config);
  channel->authority_override
      = grpc_strdup_optional (channel->config.authority_override);
  if (channel->config.authority_override != NULL
      && channel->authority_override == NULL)
    {
      free (channel->target);
      free (channel);
      return NULL;
    }

  channel->user_agent = grpc_strdup_required (channel->config.user_agent);
  if (channel->user_agent == NULL)
    {
      free (channel->authority_override);
      free (channel->target);
      free (channel);
      return NULL;
    }

  channel->client = client;
  SocketGRPC_status_set (
      &channel->last_status, SOCKET_GRPC_STATUS_OK, "Channel initialized");
  return channel;
}

void
SocketGRPC_Channel_free (SocketGRPC_Channel_T *channel)
{
  if (channel == NULL || *channel == NULL)
    return;

  free ((*channel)->user_agent);
  (*channel)->user_agent = NULL;
  free ((*channel)->authority_override);
  (*channel)->authority_override = NULL;
  free ((*channel)->target);
  (*channel)->target = NULL;
  memset (*channel, 0, sizeof (**channel));
  free (*channel);
  *channel = NULL;
}

SocketGRPC_Call_T
SocketGRPC_Call_new (SocketGRPC_Channel_T channel,
                     const char *full_method,
                     const SocketGRPC_CallConfig *config)
{
  SocketGRPC_Call_T call;

  if (channel == NULL || full_method == NULL || full_method[0] == '\0')
    return NULL;

  call = calloc (1, sizeof (*call));
  if (call == NULL)
    return NULL;

  call->full_method = grpc_strdup_required (full_method);
  if (call->full_method == NULL)
    {
      free (call);
      return NULL;
    }

  if (config != NULL)
    call->config = *config;
  else
    SocketGRPC_CallConfig_defaults (&call->config);

  grpc_sanitize_call_config (&call->config);
  call->channel = channel;
  call->request_metadata = SocketGRPC_Metadata_new (NULL);
  call->response_trailers = SocketGRPC_Trailers_new (NULL);
  call->h2_stream_ctx = NULL;
  call->h2_stream_state = GRPC_CALL_STREAM_IDLE;
  call->retry_in_progress = 0;
  call->retry_attempt = 0;
  if (call->request_metadata == NULL || call->response_trailers == NULL)
    {
      SocketGRPC_Metadata_free (&call->request_metadata);
      SocketGRPC_Trailers_free (&call->response_trailers);
      free (call->full_method);
      free (call);
      return NULL;
    }

  SocketGRPC_status_set (
      &call->last_status, SOCKET_GRPC_STATUS_OK, "Call initialized");
  return call;
}

void
SocketGRPC_Call_free (SocketGRPC_Call_T *call)
{
  if (call == NULL || *call == NULL)
    return;

  SocketGRPC_Call_h2_stream_abort (*call);
  SocketGRPC_Metadata_free (&(*call)->request_metadata);
  SocketGRPC_Trailers_free (&(*call)->response_trailers);
  free ((*call)->full_method);
  (*call)->full_method = NULL;
  memset (*call, 0, sizeof (**call));
  free (*call);
  *call = NULL;
}

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
}

void
SocketGRPC_CallConfig_defaults (SocketGRPC_CallConfig *config)
{
  if (config == NULL)
    return;

  config->deadline_ms = SOCKET_GRPC_DEFAULT_DEADLINE_MS;
  config->wait_for_ready = SOCKET_GRPC_DEFAULT_WAIT_FOR_READY;
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
}

static void
grpc_sanitize_call_config (SocketGRPC_CallConfig *config)
{
  if (config->deadline_ms < 0)
    config->deadline_ms = SOCKET_GRPC_DEFAULT_DEADLINE_MS;
  config->wait_for_ready = config->wait_for_ready ? 1 : 0;
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

  SocketGRPC_Metadata_free (&(*call)->request_metadata);
  SocketGRPC_Trailers_free (&(*call)->response_trailers);
  free ((*call)->full_method);
  (*call)->full_method = NULL;
  memset (*call, 0, sizeof (**call));
  free (*call);
  *call = NULL;
}

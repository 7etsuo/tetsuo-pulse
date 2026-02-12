/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketGRPC-private.h
 * @brief Internal gRPC scaffolding structures.
 *
 * Not part of the public API stability contract.
 */

#ifndef SOCKETGRPC_PRIVATE_INCLUDED
#define SOCKETGRPC_PRIVATE_INCLUDED

#include "grpc/SocketGRPC.h"

typedef struct SocketGRPC_ServerMethod SocketGRPC_ServerMethod;

struct SocketGRPC_Client
{
  SocketGRPC_ClientConfig config;
  SocketGRPC_Status last_status;
};

struct SocketGRPC_Server
{
  SocketGRPC_ServerConfig config;
  SocketGRPC_Status last_status;
  SocketGRPC_ServerMethod *methods;
  uint32_t method_count;
  uint32_t inflight_calls;
  int shutting_down;
};

struct SocketGRPC_Channel
{
  SocketGRPC_Client_T client;
  SocketGRPC_ChannelConfig config;
  char *target;
  char *authority_override;
  char *user_agent;
  SocketGRPC_Status last_status;
};

struct SocketGRPC_Call
{
  SocketGRPC_Channel_T channel;
  SocketGRPC_CallConfig config;
  char *full_method;
  SocketGRPC_Metadata_T request_metadata;
  SocketGRPC_Trailers_T response_trailers;
  SocketGRPC_Status last_status;
};

extern void SocketGRPC_status_set (SocketGRPC_Status *status,
                                   SocketGRPC_StatusCode code,
                                   const char *message);

extern const char *
SocketGRPC_status_default_message (SocketGRPC_StatusCode code);

extern void SocketGRPC_server_methods_clear (SocketGRPC_Server_T server);

#endif /* SOCKETGRPC_PRIVATE_INCLUDED */

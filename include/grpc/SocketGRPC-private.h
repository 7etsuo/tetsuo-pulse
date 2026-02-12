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

struct SocketGRPC_Client
{
  SocketGRPC_ClientConfig config;
  SocketGRPC_Status last_status;
};

struct SocketGRPC_Server
{
  SocketGRPC_ServerConfig config;
  SocketGRPC_Status last_status;
};

struct SocketGRPC_Channel
{
  SocketGRPC_Client_T client;
  SocketGRPC_ChannelConfig config;
  char *target;
  SocketGRPC_Status last_status;
};

struct SocketGRPC_Call
{
  SocketGRPC_Channel_T channel;
  SocketGRPC_CallConfig config;
  char *full_method;
  SocketGRPC_Status last_status;
};

extern void SocketGRPC_status_set (SocketGRPC_Status *status,
                                   SocketGRPC_StatusCode code,
                                   const char *message);

extern const char *
SocketGRPC_status_default_message (SocketGRPC_StatusCode code);

#endif /* SOCKETGRPC_PRIVATE_INCLUDED */

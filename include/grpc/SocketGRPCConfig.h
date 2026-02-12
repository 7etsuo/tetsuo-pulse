/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketGRPCConfig.h
 * @brief Compile-time defaults and runtime config structs for gRPC scaffolding.
 * @ingroup grpc
 */

#ifndef SOCKETGRPCCONFIG_INCLUDED
#define SOCKETGRPCCONFIG_INCLUDED

#include <stddef.h>
#include <stdint.h>

#ifndef SOCKET_GRPC_DEFAULT_MAX_CONCURRENT_CHANNELS
#define SOCKET_GRPC_DEFAULT_MAX_CONCURRENT_CHANNELS 64U
#endif

#ifndef SOCKET_GRPC_DEFAULT_MAX_OUTSTANDING_CALLS
#define SOCKET_GRPC_DEFAULT_MAX_OUTSTANDING_CALLS 512U
#endif

#ifndef SOCKET_GRPC_DEFAULT_MAX_CONCURRENT_CONNECTIONS
#define SOCKET_GRPC_DEFAULT_MAX_CONCURRENT_CONNECTIONS 1024U
#endif

#ifndef SOCKET_GRPC_DEFAULT_MAX_INBOUND_MESSAGE_BYTES
#define SOCKET_GRPC_DEFAULT_MAX_INBOUND_MESSAGE_BYTES (4U * 1024U * 1024U)
#endif

#ifndef SOCKET_GRPC_DEFAULT_MAX_OUTBOUND_MESSAGE_BYTES
#define SOCKET_GRPC_DEFAULT_MAX_OUTBOUND_MESSAGE_BYTES (4U * 1024U * 1024U)
#endif

#ifndef SOCKET_GRPC_DEFAULT_MAX_METADATA_ENTRIES
#define SOCKET_GRPC_DEFAULT_MAX_METADATA_ENTRIES 64U
#endif

#ifndef SOCKET_GRPC_DEFAULT_ENABLE_RETRY
#define SOCKET_GRPC_DEFAULT_ENABLE_RETRY 0
#endif

#ifndef SOCKET_GRPC_DEFAULT_DEADLINE_MS
#define SOCKET_GRPC_DEFAULT_DEADLINE_MS 30000
#endif

#ifndef SOCKET_GRPC_DEFAULT_WAIT_FOR_READY
#define SOCKET_GRPC_DEFAULT_WAIT_FOR_READY 0
#endif

/**
 * @brief Runtime client configuration for future channel/call management.
 */
typedef struct
{
  uint32_t max_concurrent_channels;
  uint32_t max_outstanding_calls;
  int enable_retry;
} SocketGRPC_ClientConfig;

/**
 * @brief Runtime server configuration for listener/dispatch scaffolding.
 */
typedef struct
{
  uint32_t max_concurrent_connections;
  uint32_t max_outstanding_calls;
} SocketGRPC_ServerConfig;

/**
 * @brief Runtime channel configuration.
 */
typedef struct
{
  size_t max_inbound_message_bytes;
  size_t max_outbound_message_bytes;
  uint32_t max_metadata_entries;
} SocketGRPC_ChannelConfig;

/**
 * @brief Runtime per-call configuration.
 */
typedef struct
{
  int deadline_ms;
  int wait_for_ready;
} SocketGRPC_CallConfig;

/**
 * @brief Populate client config with default values.
 * @threadsafe Yes
 */
extern void SocketGRPC_ClientConfig_defaults (SocketGRPC_ClientConfig *config);

/**
 * @brief Populate server config with default values.
 * @threadsafe Yes
 */
extern void SocketGRPC_ServerConfig_defaults (SocketGRPC_ServerConfig *config);

/**
 * @brief Populate channel config with default values.
 * @threadsafe Yes
 */
extern void
SocketGRPC_ChannelConfig_defaults (SocketGRPC_ChannelConfig *config);

/**
 * @brief Populate call config with default values.
 * @threadsafe Yes
 */
extern void SocketGRPC_CallConfig_defaults (SocketGRPC_CallConfig *config);

#endif /* SOCKETGRPCCONFIG_INCLUDED */

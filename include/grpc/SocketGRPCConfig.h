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

#if SOCKET_HAS_TLS
#include "tls/SocketTLSContext.h"
#else
typedef struct SocketTLSContext_T *SocketTLSContext_T;
#endif

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

#ifndef SOCKET_GRPC_DEFAULT_VERIFY_PEER
#define SOCKET_GRPC_DEFAULT_VERIFY_PEER 1
#endif

#ifndef SOCKET_GRPC_DEFAULT_ALLOW_HTTP2_CLEARTEXT
#define SOCKET_GRPC_DEFAULT_ALLOW_HTTP2_CLEARTEXT 0
#endif

#ifndef SOCKET_GRPC_DEFAULT_USER_AGENT
#define SOCKET_GRPC_DEFAULT_USER_AGENT "tetsuo-grpc/0.1"
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

#ifndef SOCKET_GRPC_DEFAULT_RETRY_MAX_ATTEMPTS
#define SOCKET_GRPC_DEFAULT_RETRY_MAX_ATTEMPTS 1
#endif

#ifndef SOCKET_GRPC_DEFAULT_RETRY_INITIAL_BACKOFF_MS
#define SOCKET_GRPC_DEFAULT_RETRY_INITIAL_BACKOFF_MS 100
#endif

#ifndef SOCKET_GRPC_DEFAULT_RETRY_MAX_BACKOFF_MS
#define SOCKET_GRPC_DEFAULT_RETRY_MAX_BACKOFF_MS 1000
#endif

#ifndef SOCKET_GRPC_DEFAULT_RETRY_BACKOFF_MULTIPLIER
#define SOCKET_GRPC_DEFAULT_RETRY_BACKOFF_MULTIPLIER 2.0
#endif

#ifndef SOCKET_GRPC_DEFAULT_RETRY_JITTER_PERCENT
#define SOCKET_GRPC_DEFAULT_RETRY_JITTER_PERCENT 20
#endif

#ifndef SOCKET_GRPC_DEFAULT_RETRYABLE_STATUS_MASK
#define SOCKET_GRPC_DEFAULT_RETRYABLE_STATUS_MASK (1U << 14)
#endif

/**
 * @brief Runtime retry/backoff policy for unary calls.
 */
typedef struct
{
  int max_attempts;
  int initial_backoff_ms;
  int max_backoff_ms;
  double backoff_multiplier;
  int jitter_percent;
  uint32_t retryable_status_mask;
} SocketGRPC_RetryPolicy;

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
  const char *authority_override;
  const char *user_agent;
  SocketTLSContext_T tls_context;
  int verify_peer;
  int allow_http2_cleartext;
} SocketGRPC_ChannelConfig;

/**
 * @brief Runtime per-call configuration.
 */
typedef struct
{
  int deadline_ms;
  int wait_for_ready;
  SocketGRPC_RetryPolicy retry_policy;
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

/**
 * @brief Populate retry policy with conservative defaults.
 */
extern void SocketGRPC_RetryPolicy_defaults (SocketGRPC_RetryPolicy *policy);

/**
 * @brief Validate retry policy values.
 *
 * @return 0 if valid, -1 if any field is out of range.
 */
extern int SocketGRPC_RetryPolicy_validate (
    const SocketGRPC_RetryPolicy *policy);

/**
 * @brief Parse a service-config retry policy subset string.
 *
 * Supported comma-separated keys:
 * `max_attempts`, `initial_backoff_ms`, `max_backoff_ms`, `multiplier`,
 * `jitter_percent`, `retryable_codes`.
 *
 * `retryable_codes` accepts `|`-separated canonical gRPC names
 * (e.g. `UNAVAILABLE|RESOURCE_EXHAUSTED`).
 *
 * @return 0 on success, -1 on parse/validation error.
 */
extern int SocketGRPC_RetryPolicy_parse_service_config (
    const char *spec,
    SocketGRPC_RetryPolicy *policy);

#endif /* SOCKETGRPCCONFIG_INCLUDED */

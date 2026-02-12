/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @defgroup grpc gRPC Module
 * @brief gRPC public API scaffolding and status model.
 * @{
 */

/**
 * @file SocketGRPC.h
 * @ingroup grpc
 * @brief Public gRPC API surface for client, server, channel, and call types.
 *
 * Phase-0 guarantees:
 * - Stable opaque handles for gRPC object lifecycles.
 * - Canonical gRPC status codes and message helpers.
 * - No global mutable runtime state.
 *
 * Behavior in this phase is intentionally minimal; transport, protobuf, and
 * streaming semantics land in follow-up phases.
 */

#ifndef SOCKETGRPC_INCLUDED
#define SOCKETGRPC_INCLUDED

#include "core/Except.h"
#include "grpc/SocketGRPCConfig.h"

/**
 * @brief Module-level exception for fatal gRPC runtime failures.
 */
extern const Except_T SocketGRPC_Failed;

/**
 * @brief Exception for invalid API usage (NULL/invalid parameters).
 */
extern const Except_T SocketGRPC_InvalidArgument;

/**
 * @brief Exception for memory allocation failures in gRPC helpers.
 */
extern const Except_T SocketGRPC_OutOfMemory;

/**
 * @brief Canonical gRPC status codes (grpc-status values).
 *
 * Matches gRPC core status space exactly (0-16).
 */
typedef enum
{
  SOCKET_GRPC_STATUS_OK = 0,
  SOCKET_GRPC_STATUS_CANCELLED = 1,
  SOCKET_GRPC_STATUS_UNKNOWN = 2,
  SOCKET_GRPC_STATUS_INVALID_ARGUMENT = 3,
  SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED = 4,
  SOCKET_GRPC_STATUS_NOT_FOUND = 5,
  SOCKET_GRPC_STATUS_ALREADY_EXISTS = 6,
  SOCKET_GRPC_STATUS_PERMISSION_DENIED = 7,
  SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED = 8,
  SOCKET_GRPC_STATUS_FAILED_PRECONDITION = 9,
  SOCKET_GRPC_STATUS_ABORTED = 10,
  SOCKET_GRPC_STATUS_OUT_OF_RANGE = 11,
  SOCKET_GRPC_STATUS_UNIMPLEMENTED = 12,
  SOCKET_GRPC_STATUS_INTERNAL = 13,
  SOCKET_GRPC_STATUS_UNAVAILABLE = 14,
  SOCKET_GRPC_STATUS_DATA_LOSS = 15,
  SOCKET_GRPC_STATUS_UNAUTHENTICATED = 16
} SocketGRPC_StatusCode;

/**
 * @brief gRPC status payload used by simple/non-throwing APIs.
 *
 * message may reference static storage or module-owned memory.
 */
typedef struct
{
  SocketGRPC_StatusCode code;
  const char *message;
} SocketGRPC_Status;

/** Opaque gRPC client handle. */
typedef struct SocketGRPC_Client *SocketGRPC_Client_T;

/** Opaque gRPC server handle. */
typedef struct SocketGRPC_Server *SocketGRPC_Server_T;

/** Opaque gRPC channel handle. */
typedef struct SocketGRPC_Channel *SocketGRPC_Channel_T;

/** Opaque gRPC call handle. */
typedef struct SocketGRPC_Call *SocketGRPC_Call_T;

/**
 * @brief Create a gRPC client object.
 *
 * @param config Optional runtime configuration (NULL for defaults).
 * @return Client handle or NULL on error.
 *
 * @threadsafe Yes
 */
extern SocketGRPC_Client_T
SocketGRPC_Client_new (const SocketGRPC_ClientConfig *config);

/**
 * @brief Destroy a gRPC client object.
 *
 * Safe to call with NULL or *client == NULL.
 *
 * @param client Pointer to client handle; set to NULL on return.
 * @threadsafe No
 */
extern void SocketGRPC_Client_free (SocketGRPC_Client_T *client);

/**
 * @brief Create a gRPC server object.
 *
 * @param config Optional runtime configuration (NULL for defaults).
 * @return Server handle or NULL on error.
 *
 * @threadsafe Yes
 */
extern SocketGRPC_Server_T
SocketGRPC_Server_new (const SocketGRPC_ServerConfig *config);

/**
 * @brief Destroy a gRPC server object.
 *
 * Safe to call with NULL or *server == NULL.
 *
 * @param server Pointer to server handle; set to NULL on return.
 * @threadsafe No
 */
extern void SocketGRPC_Server_free (SocketGRPC_Server_T *server);

/**
 * @brief Create a logical channel owned by a client.
 *
 * @param client Parent client (required).
 * @param target Authority/endpoint target string (required).
 * @param config Optional channel configuration (NULL for defaults).
 * @return Channel handle or NULL on error.
 *
 * @threadsafe Yes
 */
extern SocketGRPC_Channel_T
SocketGRPC_Channel_new (SocketGRPC_Client_T client,
                        const char *target,
                        const SocketGRPC_ChannelConfig *config);

/**
 * @brief Destroy a channel.
 *
 * Safe to call with NULL or *channel == NULL.
 *
 * @param channel Pointer to channel handle; set to NULL on return.
 * @threadsafe No
 */
extern void SocketGRPC_Channel_free (SocketGRPC_Channel_T *channel);

/**
 * @brief Create a call bound to a channel and fully qualified method path.
 *
 * @param channel Parent channel (required).
 * @param full_method Method path, e.g. "/pkg.Service/Method" (required).
 * @param config Optional call configuration (NULL for defaults).
 * @return Call handle or NULL on error.
 *
 * @threadsafe Yes
 */
extern SocketGRPC_Call_T
SocketGRPC_Call_new (SocketGRPC_Channel_T channel,
                     const char *full_method,
                     const SocketGRPC_CallConfig *config);

/**
 * @brief Destroy a call.
 *
 * Safe to call with NULL or *call == NULL.
 *
 * @param call Pointer to call handle; set to NULL on return.
 * @threadsafe No
 */
extern void SocketGRPC_Call_free (SocketGRPC_Call_T *call);

/**
 * @brief Extract numeric status code from a status payload.
 *
 * NULL-safe: returns INTERNAL for a NULL status pointer.
 *
 * @param status Status payload pointer.
 * @return gRPC status code.
 * @threadsafe Yes
 */
extern SocketGRPC_StatusCode
SocketGRPC_Status_code (const SocketGRPC_Status *status);

/**
 * @brief Extract human-readable status message.
 *
 * If status->message is NULL/empty, a canonical default message is returned.
 *
 * @param status Status payload pointer.
 * @return Static or owned string, never NULL.
 * @threadsafe Yes
 */
extern const char *SocketGRPC_Status_message (const SocketGRPC_Status *status);

/**
 * @brief Convert status code to symbolic constant name.
 *
 * @param code gRPC status code.
 * @return Static string (e.g., "UNAVAILABLE"), or "UNKNOWN_CODE".
 * @threadsafe Yes
 */
extern const char *SocketGRPC_Status_code_name (SocketGRPC_StatusCode code);

/** @} */

#endif /* SOCKETGRPC_INCLUDED */

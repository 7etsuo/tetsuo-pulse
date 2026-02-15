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
#include <string.h>

/* Common gRPC protocol constants shared between H2 and H3 implementations */
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

typedef struct SocketGRPC_ServerMethod SocketGRPC_ServerMethod;
typedef struct SocketGRPC_ServerUnaryInterceptorEntry
    SocketGRPC_ServerUnaryInterceptorEntry;
typedef struct SocketGRPC_ClientUnaryInterceptorEntry
    SocketGRPC_ClientUnaryInterceptorEntry;
typedef struct SocketGRPC_ClientStreamInterceptorEntry
    SocketGRPC_ClientStreamInterceptorEntry;

typedef enum
{
  GRPC_CALL_STREAM_IDLE = 0,
  GRPC_CALL_STREAM_OPEN,
  GRPC_CALL_STREAM_HALF_CLOSED_LOCAL,
  GRPC_CALL_STREAM_HALF_CLOSED_REMOTE,
  GRPC_CALL_STREAM_CLOSED,
  GRPC_CALL_STREAM_FAILED
} SocketGRPC_CallStreamState;

struct SocketGRPC_Client
{
  SocketGRPC_ClientConfig config;
  SocketGRPC_Status last_status;
  SocketGRPC_LogHook observability_hook;
  void *observability_hook_userdata;
};

struct SocketGRPC_Server
{
  SocketGRPC_ServerConfig config;
  SocketGRPC_Status last_status;
  SocketGRPC_LogHook observability_hook;
  void *observability_hook_userdata;
  SocketGRPC_ServerMethod *methods;
  SocketGRPC_ServerUnaryInterceptorEntry *unary_interceptors;
  SocketGRPC_ServerUnaryInterceptorEntry *unary_interceptors_tail;
  uint32_t unary_interceptor_count;
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
  char *ca_file;
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
  SocketGRPC_ClientUnaryInterceptorEntry *unary_interceptors;
  SocketGRPC_ClientUnaryInterceptorEntry *unary_interceptors_tail;
  SocketGRPC_ClientStreamInterceptorEntry *stream_interceptors;
  SocketGRPC_ClientStreamInterceptorEntry *stream_interceptors_tail;
  uint32_t unary_interceptor_count;
  uint32_t stream_interceptor_count;
  void *h2_stream_ctx;
  SocketGRPC_CallStreamState h2_stream_state;
  void *h3_stream_ctx;
  SocketGRPC_CallStreamState h3_stream_state;
  int retry_in_progress;
  uint32_t retry_attempt;
};

extern void SocketGRPC_status_set (SocketGRPC_Status *status,
                                   SocketGRPC_StatusCode code,
                                   const char *message);

extern const char *
SocketGRPC_status_default_message (SocketGRPC_StatusCode code);

/* Common helper functions for gRPC client implementations */
static inline int
str_has_prefix (const char *str, const char *prefix)
{
  size_t prefix_len;

  if (str == NULL || prefix == NULL)
    return 0;
  prefix_len = strlen (prefix);
  return strncmp (str, prefix, prefix_len) == 0;
}

static inline void
grpc_call_status_set (SocketGRPC_Call_T call,
                      SocketGRPC_StatusCode code,
                      const char *message)
{
  SocketGRPC_status_set (&call->last_status, code, message);
}

static inline int
grpc_status_code_valid (SocketGRPC_StatusCode code)
{
  return code >= SOCKET_GRPC_STATUS_OK
         && code <= SOCKET_GRPC_STATUS_UNAUTHENTICATED;
}

static inline SocketGRPC_StatusCode
grpc_normalize_status_code (SocketGRPC_StatusCode code)
{
  return grpc_status_code_valid (code) ? code : SOCKET_GRPC_STATUS_UNKNOWN;
}

/* Helper macro for TLS exception handlers */
#if SOCKET_HAS_TLS
#define SOCKET_TLS_EXCEPT(action) \
  EXCEPT (SocketTLS_HandshakeFailed) { action } \
  EXCEPT (SocketTLS_VerifyFailed) { action } \
  EXCEPT (SocketTLS_Failed) { action }
#else
#define SOCKET_TLS_EXCEPT(action)
#endif

/* Macro to wrap gRPC H2 operations that can throw exceptions
 * Returns error_val on any exception */
#define GRPC_H2_SAFE_CALL_INT(call_expr, error_val) \
  do { \
    volatile int rc = (error_val); \
    TRY { \
      rc = (call_expr); \
    } \
    EXCEPT (SocketHTTP2) { rc = (error_val); } \
    EXCEPT (Socket_Failed) { rc = (error_val); } \
    EXCEPT (Socket_Closed) { rc = (error_val); } \
    SOCKET_TLS_EXCEPT(rc = (error_val);) \
    ELSE { rc = (error_val); } \
    END_TRY; \
    return rc; \
  } while (0)

/* Similar macro for ssize_t return type */
#define GRPC_H2_SAFE_CALL_SSIZE(call_expr, error_val) \
  do { \
    volatile ssize_t rc = (error_val); \
    TRY { \
      rc = (call_expr); \
    } \
    EXCEPT (SocketHTTP2) { rc = (error_val); } \
    EXCEPT (Socket_Failed) { rc = (error_val); } \
    EXCEPT (Socket_Closed) { rc = (error_val); } \
    SOCKET_TLS_EXCEPT(rc = (error_val);) \
    ELSE { rc = (error_val); } \
    END_TRY; \
    return rc; \
  } while (0)

/* Macro for void functions that swallow all exceptions */
#define GRPC_H2_SAFE_CALL_VOID(call_expr) \
  do { \
    TRY { \
      call_expr; \
    } \
    EXCEPT (SocketHTTP2) { } \
    EXCEPT (Socket_Failed) { } \
    EXCEPT (Socket_Closed) { } \
    SOCKET_TLS_EXCEPT() \
    ELSE { } \
    END_TRY; \
  } while (0)

extern void SocketGRPC_server_methods_clear (SocketGRPC_Server_T server);
extern void SocketGRPC_server_interceptors_clear (SocketGRPC_Server_T server);

extern void SocketGRPC_Call_h2_stream_abort (SocketGRPC_Call_T call);
#if SOCKET_HAS_TLS
extern void SocketGRPC_Call_h3_stream_abort (SocketGRPC_Call_T call);
extern int SocketGRPC_Call_h3_send_message (SocketGRPC_Call_T call,
                                            const uint8_t *request_payload,
                                            size_t request_payload_len);
extern int SocketGRPC_Call_h3_close_send (SocketGRPC_Call_T call);
extern int SocketGRPC_Call_h3_recv_message (SocketGRPC_Call_T call,
                                            Arena_T arena,
                                            uint8_t **response_payload,
                                            size_t *response_payload_len,
                                            int *done);
extern int SocketGRPC_Call_h3_cancel (SocketGRPC_Call_T call);
#endif

#endif /* SOCKETGRPC_PRIVATE_INCLUDED */

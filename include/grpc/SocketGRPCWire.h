/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketGRPCWire.h
 * @brief Transport-agnostic gRPC wire framing, metadata, and trailers.
 * @ingroup grpc
 */

#ifndef SOCKETGRPC_WIRE_INCLUDED
#define SOCKETGRPC_WIRE_INCLUDED

#include "core/Arena.h"
#include "grpc/SocketGRPC.h"

#include <stddef.h>
#include <stdint.h>

/** gRPC message prefix size: 1 byte compressed flag + 4 byte length. */
#define SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE 5U

/** Default max gRPC payload accepted by frame parser. */
#ifndef SOCKET_GRPC_WIRE_DEFAULT_MAX_MESSAGE_SIZE
#define SOCKET_GRPC_WIRE_DEFAULT_MAX_MESSAGE_SIZE (4U * 1024U * 1024U)
#endif

/**
 * @brief Result codes for gRPC wire operations.
 */
typedef enum
{
  SOCKET_GRPC_WIRE_OK = 0,
  SOCKET_GRPC_WIRE_INCOMPLETE,
  SOCKET_GRPC_WIRE_BUFFER_TOO_SMALL,
  SOCKET_GRPC_WIRE_INVALID_ARGUMENT,
  SOCKET_GRPC_WIRE_INVALID_FRAME,
  SOCKET_GRPC_WIRE_LENGTH_EXCEEDED,
  SOCKET_GRPC_WIRE_INVALID_METADATA_KEY,
  SOCKET_GRPC_WIRE_INVALID_METADATA_VALUE,
  SOCKET_GRPC_WIRE_INVALID_TRAILER,
  SOCKET_GRPC_WIRE_OUT_OF_MEMORY
} SocketGRPC_WireResult;

/**
 * @brief Zero-copy parsed frame view.
 */
typedef struct
{
  int compressed;
  const uint8_t *payload;
  uint32_t payload_len;
} SocketGRPC_FrameView;

/**
 * @brief Metadata entry.
 *
 * `is_binary` indicates `-bin` semantics. For binary entries, `value` contains
 * decoded bytes. For ASCII entries, `value` contains raw bytes without NUL.
 */
typedef struct
{
  char *key;
  uint8_t *value;
  size_t value_len;
  int is_binary;
} SocketGRPC_MetadataEntry;

/** Opaque metadata collection. */
typedef struct SocketGRPC_Metadata *SocketGRPC_Metadata_T;

/** Opaque trailer payload model. */
typedef struct SocketGRPC_Trailers *SocketGRPC_Trailers_T;

extern const char *SocketGRPC_Wire_result_string (SocketGRPC_WireResult result);

extern SocketGRPC_WireResult SocketGRPC_Frame_encode (int compressed,
                                                      const uint8_t *payload,
                                                      uint32_t payload_len,
                                                      uint8_t *out,
                                                      size_t out_len,
                                                      size_t *written);

extern SocketGRPC_WireResult
SocketGRPC_Frame_parse (const uint8_t *data,
                        size_t len,
                        size_t max_message_size,
                        SocketGRPC_FrameView *frame,
                        size_t *consumed);

extern SocketGRPC_Metadata_T SocketGRPC_Metadata_new (Arena_T arena);
extern void SocketGRPC_Metadata_free (SocketGRPC_Metadata_T *metadata);
extern void SocketGRPC_Metadata_clear (SocketGRPC_Metadata_T metadata);
extern size_t SocketGRPC_Metadata_count (const SocketGRPC_Metadata_T metadata);
extern const SocketGRPC_MetadataEntry *
SocketGRPC_Metadata_at (const SocketGRPC_Metadata_T metadata, size_t index);

extern SocketGRPC_WireResult
SocketGRPC_Metadata_add_ascii (SocketGRPC_Metadata_T metadata,
                               const char *key,
                               const char *value);
extern SocketGRPC_WireResult
SocketGRPC_Metadata_add_binary (SocketGRPC_Metadata_T metadata,
                                const char *key,
                                const uint8_t *value,
                                size_t value_len);

extern SocketGRPC_WireResult
SocketGRPC_Metadata_serialize (const SocketGRPC_Metadata_T metadata,
                               uint8_t *out,
                               size_t out_len,
                               size_t *written);
extern SocketGRPC_WireResult
SocketGRPC_Metadata_parse (SocketGRPC_Metadata_T metadata,
                           const uint8_t *data,
                           size_t len);

extern SocketGRPC_Trailers_T SocketGRPC_Trailers_new (Arena_T arena);
extern void SocketGRPC_Trailers_free (SocketGRPC_Trailers_T *trailers);
extern void SocketGRPC_Trailers_clear (SocketGRPC_Trailers_T trailers);

extern SocketGRPC_WireResult
SocketGRPC_Trailers_set_status (SocketGRPC_Trailers_T trailers,
                                int grpc_status);
extern SocketGRPC_WireResult
SocketGRPC_Trailers_set_message (SocketGRPC_Trailers_T trailers,
                                 const char *grpc_message);
extern SocketGRPC_WireResult
SocketGRPC_Trailers_set_status_details_bin (SocketGRPC_Trailers_T trailers,
                                            const uint8_t *data,
                                            size_t len);

extern int
SocketGRPC_Trailers_has_status (const SocketGRPC_Trailers_T trailers);
extern int SocketGRPC_Trailers_status (const SocketGRPC_Trailers_T trailers);
extern const char *
SocketGRPC_Trailers_message (const SocketGRPC_Trailers_T trailers);
extern const uint8_t *
SocketGRPC_Trailers_status_details_bin (const SocketGRPC_Trailers_T trailers,
                                        size_t *len);
extern SocketGRPC_Metadata_T
SocketGRPC_Trailers_metadata (const SocketGRPC_Trailers_T trailers);

extern SocketGRPC_WireResult
SocketGRPC_Trailers_serialize (const SocketGRPC_Trailers_T trailers,
                               uint8_t *out,
                               size_t out_len,
                               size_t *written);
extern SocketGRPC_WireResult
SocketGRPC_Trailers_parse (SocketGRPC_Trailers_T trailers,
                           const uint8_t *data,
                           size_t len);

extern SocketGRPC_StatusCode SocketGRPC_http_status_to_grpc (int http_status);

#endif /* SOCKETGRPC_WIRE_INCLUDED */

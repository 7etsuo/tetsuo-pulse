/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketProto.h
 * @brief Protobuf wire/runtime primitives for gRPC payloads.
 * @ingroup grpc
 */

#ifndef SOCKETPROTO_INCLUDED
#define SOCKETPROTO_INCLUDED

#include "core/Arena.h"

#include <stddef.h>
#include <stdint.h>

/** Maximum varint width in bytes for protobuf uint64 values. */
#define SOCKET_PROTO_MAX_VARINT_LEN 10U

/** Maximum allowed protobuf field number (29 bits). */
#define SOCKET_PROTO_MAX_FIELD_NUMBER 0x1FFFFFFFU

/** Default parser guardrail: max message size in bytes. */
#ifndef SOCKET_PROTO_DEFAULT_MAX_MESSAGE_SIZE
#define SOCKET_PROTO_DEFAULT_MAX_MESSAGE_SIZE (4U * 1024U * 1024U)
#endif

/** Default parser guardrail: max decoded fields per message. */
#ifndef SOCKET_PROTO_DEFAULT_MAX_FIELDS
#define SOCKET_PROTO_DEFAULT_MAX_FIELDS 1024U
#endif

/** Default parser guardrail: max nested message depth. */
#ifndef SOCKET_PROTO_DEFAULT_MAX_NESTING_DEPTH
#define SOCKET_PROTO_DEFAULT_MAX_NESTING_DEPTH 16U
#endif

/**
 * @brief Result codes for protobuf runtime operations.
 */
typedef enum
{
  SOCKET_PROTO_OK = 0,
  SOCKET_PROTO_INCOMPLETE,
  SOCKET_PROTO_OVERFLOW,
  SOCKET_PROTO_INVALID_ARGUMENT,
  SOCKET_PROTO_INVALID_TAG,
  SOCKET_PROTO_INVALID_WIRE_TYPE,
  SOCKET_PROTO_TYPE_MISMATCH,
  SOCKET_PROTO_LIMIT_MESSAGE_SIZE,
  SOCKET_PROTO_LIMIT_FIELD_COUNT,
  SOCKET_PROTO_LIMIT_NESTING_DEPTH,
  SOCKET_PROTO_BUFFER_TOO_SMALL,
  SOCKET_PROTO_MALFORMED
} SocketProto_Result;

/**
 * @brief Wire types from protobuf encoding.
 */
typedef enum
{
  SOCKET_PROTO_WIRE_VARINT = 0,
  SOCKET_PROTO_WIRE_FIXED64 = 1,
  SOCKET_PROTO_WIRE_LENGTH_DELIMITED = 2,
  SOCKET_PROTO_WIRE_START_GROUP = 3,
  SOCKET_PROTO_WIRE_END_GROUP = 4,
  SOCKET_PROTO_WIRE_FIXED32 = 5
} SocketProto_WireType;

/**
 * @brief Schema-level field kinds for descriptor validation.
 */
typedef enum
{
  SOCKET_PROTO_KIND_VARINT = 0,
  SOCKET_PROTO_KIND_FIXED64,
  SOCKET_PROTO_KIND_LENGTH_DELIMITED,
  SOCKET_PROTO_KIND_FIXED32,
  SOCKET_PROTO_KIND_MESSAGE
} SocketProto_FieldKind;

struct SocketProto_Schema;

/**
 * @brief Descriptor for one protobuf field in a schema.
 */
typedef struct
{
  uint32_t field_number;
  SocketProto_FieldKind kind;
  const struct SocketProto_Schema *message_schema;
} SocketProto_SchemaField;

/**
 * @brief Schema descriptor table for validation/classification.
 */
typedef struct SocketProto_Schema
{
  const SocketProto_SchemaField *fields;
  size_t field_count;
} SocketProto_Schema;

/**
 * @brief Parser/encoder limits used for fail-closed behavior.
 */
typedef struct
{
  size_t max_message_size;
  size_t max_fields;
  size_t max_nesting_depth;
} SocketProto_Limits;

/**
 * @brief Parsed field view with raw payload/encoding spans.
 *
 * `encoded` preserves the exact bytes for roundtrip emission.
 */
typedef struct
{
  uint32_t field_number;
  uint8_t wire_type;
  const uint8_t *value;
  size_t value_len;
  const uint8_t *encoded;
  size_t encoded_len;
  int known;
} SocketProto_Field;

/** Opaque decoded message handle. */
typedef struct SocketProto_Message *SocketProto_Message_T;

/**
 * @brief Convert result code to human-readable constant string.
 * @threadsafe Yes
 */
extern const char *SocketProto_result_string (SocketProto_Result result);

/**
 * @brief Populate protobuf limits with secure defaults.
 * @threadsafe Yes
 */
extern void SocketProto_limits_defaults (SocketProto_Limits *limits);

/**
 * @brief Find a field descriptor by number in a schema.
 * @return Pointer to descriptor, or NULL if not declared.
 * @threadsafe Yes
 */
extern const SocketProto_SchemaField *
SocketProto_Schema_find_field (const SocketProto_Schema *schema,
                               uint32_t field_number);

/**
 * @brief Encode/decode unsigned varints.
 */
extern SocketProto_Result SocketProto_varint_encode_u64 (uint64_t value,
                                                         uint8_t *out,
                                                         size_t out_len,
                                                         size_t *written);
extern SocketProto_Result SocketProto_varint_decode_u64 (const uint8_t *in,
                                                         size_t in_len,
                                                         uint64_t *value,
                                                         size_t *consumed);
extern SocketProto_Result SocketProto_varint_encode_u32 (uint32_t value,
                                                         uint8_t *out,
                                                         size_t out_len,
                                                         size_t *written);
extern SocketProto_Result SocketProto_varint_decode_u32 (const uint8_t *in,
                                                         size_t in_len,
                                                         uint32_t *value,
                                                         size_t *consumed);

/**
 * @brief ZigZag conversions for signed protobuf integers.
 */
extern uint64_t SocketProto_zigzag_encode_s64 (int64_t value);
extern int64_t SocketProto_zigzag_decode_s64 (uint64_t value);
extern uint32_t SocketProto_zigzag_encode_s32 (int32_t value);
extern int32_t SocketProto_zigzag_decode_s32 (uint32_t value);

/**
 * @brief fixed32/fixed64 little-endian encode/decode.
 */
extern SocketProto_Result
SocketProto_fixed32_encode (uint32_t value, uint8_t *out, size_t out_len);
extern SocketProto_Result
SocketProto_fixed32_decode (const uint8_t *in, size_t in_len, uint32_t *value);
extern SocketProto_Result
SocketProto_fixed64_encode (uint64_t value, uint8_t *out, size_t out_len);
extern SocketProto_Result
SocketProto_fixed64_decode (const uint8_t *in, size_t in_len, uint64_t *value);

/**
 * @brief Wire-level helpers.
 */
extern SocketProto_Result SocketProto_wire_make_tag (uint32_t field_number,
                                                     uint8_t wire_type,
                                                     uint64_t *tag);
extern SocketProto_Result SocketProto_wire_write_tag (uint32_t field_number,
                                                      uint8_t wire_type,
                                                      uint8_t *out,
                                                      size_t out_len,
                                                      size_t *written);
extern SocketProto_Result
SocketProto_wire_write_length_delimited (uint32_t field_number,
                                         const uint8_t *value,
                                         size_t value_len,
                                         uint8_t *out,
                                         size_t out_len,
                                         size_t *written);
extern SocketProto_Result SocketProto_wire_read_field (const uint8_t *data,
                                                       size_t len,
                                                       SocketProto_Field *field,
                                                       size_t *consumed);

/**
 * @brief Create/destroy message handle.
 *
 * If `arena` is NULL, the message allocates an internal arena and owns it.
 */
extern SocketProto_Message_T
SocketProto_Message_new (Arena_T arena,
                         const SocketProto_Limits *limits,
                         const SocketProto_Schema *schema);
extern void SocketProto_Message_free (SocketProto_Message_T *message);
extern void SocketProto_Message_clear (SocketProto_Message_T message);

/**
 * @brief Parse/encode whole messages while preserving unknown fields.
 */
extern SocketProto_Result
SocketProto_Message_parse (SocketProto_Message_T message,
                           const uint8_t *data,
                           size_t len);
extern SocketProto_Result
SocketProto_Message_encode (const SocketProto_Message_T message,
                            uint8_t *out,
                            size_t out_len,
                            size_t *written);

/**
 * @brief Validate wire payload against limits/schema without storing fields.
 */
extern SocketProto_Result
SocketProto_Message_validate (const uint8_t *data,
                              size_t len,
                              const SocketProto_Schema *schema,
                              const SocketProto_Limits *limits);

/**
 * @brief Field accessors.
 */
extern size_t
SocketProto_Message_field_count (const SocketProto_Message_T message);
extern const SocketProto_Field *
SocketProto_Message_field_at (const SocketProto_Message_T message,
                              size_t index);
extern size_t
SocketProto_Message_unknown_count (const SocketProto_Message_T message);
extern const SocketProto_Field *
SocketProto_Message_unknown_at (const SocketProto_Message_T message,
                                size_t index);

/**
 * @brief Message builders.
 */
extern SocketProto_Result
SocketProto_Message_append_varint (SocketProto_Message_T message,
                                   uint32_t field_number,
                                   uint64_t value);
extern SocketProto_Result
SocketProto_Message_append_sint64 (SocketProto_Message_T message,
                                   uint32_t field_number,
                                   int64_t value);
extern SocketProto_Result
SocketProto_Message_append_fixed32 (SocketProto_Message_T message,
                                    uint32_t field_number,
                                    uint32_t value);
extern SocketProto_Result
SocketProto_Message_append_fixed64 (SocketProto_Message_T message,
                                    uint32_t field_number,
                                    uint64_t value);
extern SocketProto_Result
SocketProto_Message_append_bytes (SocketProto_Message_T message,
                                  uint32_t field_number,
                                  const uint8_t *value,
                                  size_t value_len);
extern SocketProto_Result
SocketProto_Message_append_embedded (SocketProto_Message_T message,
                                     uint32_t field_number,
                                     const uint8_t *encoded_message,
                                     size_t encoded_len);

/**
 * @brief Decode typed values from parsed fields.
 */
extern SocketProto_Result
SocketProto_Field_decode_u64 (const SocketProto_Field *field, uint64_t *value);
extern SocketProto_Result
SocketProto_Field_decode_s64 (const SocketProto_Field *field, int64_t *value);
extern SocketProto_Result
SocketProto_Field_decode_fixed32 (const SocketProto_Field *field,
                                  uint32_t *value);
extern SocketProto_Result
SocketProto_Field_decode_fixed64 (const SocketProto_Field *field,
                                  uint64_t *value);

#endif /* SOCKETPROTO_INCLUDED */

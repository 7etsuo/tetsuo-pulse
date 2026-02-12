/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketProto-varint.c
 * @brief Protobuf varint/zigzag/fixed primitives.
 */

#include "grpc/SocketProto-private.h"

#include <limits.h>

static const char *socketproto_result_names[]
    = { "SOCKET_PROTO_OK",
        "SOCKET_PROTO_INCOMPLETE",
        "SOCKET_PROTO_OVERFLOW",
        "SOCKET_PROTO_INVALID_ARGUMENT",
        "SOCKET_PROTO_INVALID_TAG",
        "SOCKET_PROTO_INVALID_WIRE_TYPE",
        "SOCKET_PROTO_TYPE_MISMATCH",
        "SOCKET_PROTO_LIMIT_MESSAGE_SIZE",
        "SOCKET_PROTO_LIMIT_FIELD_COUNT",
        "SOCKET_PROTO_LIMIT_NESTING_DEPTH",
        "SOCKET_PROTO_BUFFER_TOO_SMALL",
        "SOCKET_PROTO_MALFORMED" };

_Static_assert (sizeof (socketproto_result_names)
                        / sizeof (socketproto_result_names[0])
                    == SOCKET_PROTO_MALFORMED + 1,
                "socketproto_result_names must map all result codes");

const char *
SocketProto_result_string (SocketProto_Result result)
{
  if (result < SOCKET_PROTO_OK || result > SOCKET_PROTO_MALFORMED)
    return "SOCKET_PROTO_UNKNOWN_RESULT";
  return socketproto_result_names[result];
}

SocketProto_Result
SocketProto_varint_encode_u64 (uint64_t value,
                               uint8_t *out,
                               size_t out_len,
                               size_t *written)
{
  size_t pos = 0;

  if (out == NULL || written == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;

  while (value >= 0x80U)
    {
      if (pos >= out_len)
        return SOCKET_PROTO_BUFFER_TOO_SMALL;
      out[pos++] = (uint8_t)((value & 0x7FU) | 0x80U);
      value >>= 7;
    }

  if (pos >= out_len)
    return SOCKET_PROTO_BUFFER_TOO_SMALL;

  out[pos++] = (uint8_t)value;
  *written = pos;
  return SOCKET_PROTO_OK;
}

SocketProto_Result
SocketProto_varint_decode_u64 (const uint8_t *in,
                               size_t in_len,
                               uint64_t *value,
                               size_t *consumed)
{
  uint64_t result = 0;

  if (in == NULL || value == NULL || consumed == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;

  for (size_t i = 0; i < in_len && i < SOCKET_PROTO_MAX_VARINT_LEN; i++)
    {
      uint8_t byte = in[i];
      uint64_t payload = (uint64_t)(byte & 0x7FU);
      unsigned shift = (unsigned)(i * 7U);

      if (i == SOCKET_PROTO_MAX_VARINT_LEN - 1 && (byte & 0xFEU) != 0)
        return SOCKET_PROTO_OVERFLOW;

      result |= (payload << shift);

      if ((byte & 0x80U) == 0)
        {
          *value = result;
          *consumed = i + 1;
          return SOCKET_PROTO_OK;
        }
    }

  if (in_len < SOCKET_PROTO_MAX_VARINT_LEN)
    return SOCKET_PROTO_INCOMPLETE;

  return SOCKET_PROTO_OVERFLOW;
}

SocketProto_Result
SocketProto_varint_encode_u32 (uint32_t value,
                               uint8_t *out,
                               size_t out_len,
                               size_t *written)
{
  return SocketProto_varint_encode_u64 ((uint64_t)value, out, out_len, written);
}

SocketProto_Result
SocketProto_varint_decode_u32 (const uint8_t *in,
                               size_t in_len,
                               uint32_t *value,
                               size_t *consumed)
{
  uint64_t decoded = 0;
  SocketProto_Result rc
      = SocketProto_varint_decode_u64 (in, in_len, &decoded, consumed);
  if (rc != SOCKET_PROTO_OK)
    return rc;
  if (decoded > UINT32_MAX)
    return SOCKET_PROTO_OVERFLOW;
  *value = (uint32_t)decoded;
  return SOCKET_PROTO_OK;
}

uint64_t
SocketProto_zigzag_encode_s64 (int64_t value)
{
  return (((uint64_t)value) << 1) ^ (uint64_t)(value >> 63);
}

int64_t
SocketProto_zigzag_decode_s64 (uint64_t value)
{
  return (int64_t)((value >> 1) ^ (uint64_t)(-(int64_t)(value & 1U)));
}

uint32_t
SocketProto_zigzag_encode_s32 (int32_t value)
{
  return (((uint32_t)value) << 1) ^ (uint32_t)(value >> 31);
}

int32_t
SocketProto_zigzag_decode_s32 (uint32_t value)
{
  return (int32_t)((value >> 1) ^ (uint32_t)(-(int32_t)(value & 1U)));
}

SocketProto_Result
SocketProto_fixed32_encode (uint32_t value, uint8_t *out, size_t out_len)
{
  if (out == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;
  if (out_len < 4)
    return SOCKET_PROTO_BUFFER_TOO_SMALL;

  out[0] = (uint8_t)(value & 0xFFU);
  out[1] = (uint8_t)((value >> 8) & 0xFFU);
  out[2] = (uint8_t)((value >> 16) & 0xFFU);
  out[3] = (uint8_t)((value >> 24) & 0xFFU);
  return SOCKET_PROTO_OK;
}

SocketProto_Result
SocketProto_fixed32_decode (const uint8_t *in, size_t in_len, uint32_t *value)
{
  if (in == NULL || value == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;
  if (in_len < 4)
    return SOCKET_PROTO_INCOMPLETE;

  *value = (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16)
           | ((uint32_t)in[3] << 24);
  return SOCKET_PROTO_OK;
}

SocketProto_Result
SocketProto_fixed64_encode (uint64_t value, uint8_t *out, size_t out_len)
{
  if (out == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;
  if (out_len < 8)
    return SOCKET_PROTO_BUFFER_TOO_SMALL;

  out[0] = (uint8_t)(value & 0xFFU);
  out[1] = (uint8_t)((value >> 8) & 0xFFU);
  out[2] = (uint8_t)((value >> 16) & 0xFFU);
  out[3] = (uint8_t)((value >> 24) & 0xFFU);
  out[4] = (uint8_t)((value >> 32) & 0xFFU);
  out[5] = (uint8_t)((value >> 40) & 0xFFU);
  out[6] = (uint8_t)((value >> 48) & 0xFFU);
  out[7] = (uint8_t)((value >> 56) & 0xFFU);
  return SOCKET_PROTO_OK;
}

SocketProto_Result
SocketProto_fixed64_decode (const uint8_t *in, size_t in_len, uint64_t *value)
{
  if (in == NULL || value == NULL)
    return SOCKET_PROTO_INVALID_ARGUMENT;
  if (in_len < 8)
    return SOCKET_PROTO_INCOMPLETE;

  *value = (uint64_t)in[0] | ((uint64_t)in[1] << 8)
           | ((uint64_t)in[2] << 16) | ((uint64_t)in[3] << 24)
           | ((uint64_t)in[4] << 32) | ((uint64_t)in[5] << 40)
           | ((uint64_t)in[6] << 48) | ((uint64_t)in[7] << 56);
  return SOCKET_PROTO_OK;
}

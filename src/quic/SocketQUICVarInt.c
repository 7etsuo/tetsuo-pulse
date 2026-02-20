/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQUICVarInt.c - QUIC Variable-Length Integer Encoding (RFC 9000 §16)
 *
 * Implements encoding/decoding of QUIC variable-length integers with
 * 2-bit prefix length encoding in network byte order.
 */

#include <assert.h>

#include "quic/SocketQUICVarInt.h"

/* 2-bit prefix values (in top 2 bits of first byte) */
#define VARINT_PREFIX_MASK 0xC0
#define VARINT_PREFIX_1BYTE 0x00 /* 00xxxxxx */
#define VARINT_PREFIX_2BYTE 0x40 /* 01xxxxxx */
#define VARINT_PREFIX_4BYTE 0x80 /* 10xxxxxx */
#define VARINT_PREFIX_8BYTE 0xC0 /* 11xxxxxx */

/* Value masks for extracting data bits from first byte */
#define VARINT_VALUE_MASK_1BYTE 0x3F /* 6 bits */
#define VARINT_VALUE_MASK_2BYTE 0x3F /* 14 bits total */
#define VARINT_VALUE_MASK_4BYTE 0x3F /* 30 bits total */
#define VARINT_VALUE_MASK_8BYTE 0x3F /* 62 bits total */

/* Maximum values per encoding length */
#define VARINT_MAX_1BYTE 63ULL         /* (1ULL << 6) - 1 = 63 */
#define VARINT_MAX_2BYTE 16383ULL      /* (1ULL << 14) - 1 = 16383 */
#define VARINT_MAX_4BYTE 1073741823ULL /* (1ULL << 30) - 1 = 1073741823 */
#define VARINT_MAX_8BYTE \
  SOCKETQUICVARINT_MAX /* (1ULL << 62) - 1 = 4611686018427387903 */

const Except_T SocketQUICVarInt_Error
    = { &SocketQUICVarInt_Error, "QUIC VarInt encoding error" };

static const char *result_strings[] = {
  [QUIC_VARINT_OK] = "OK",
  [QUIC_VARINT_INCOMPLETE] = "Incomplete - need more data",
  [QUIC_VARINT_ERROR_OVERFLOW] = "Value exceeds maximum (2^62-1)",
  [QUIC_VARINT_ERROR_BUFFER] = "Output buffer too small",
  [QUIC_VARINT_ERROR_NULL] = "NULL pointer argument",
};

/* Compile-time check: ensure array size matches enum count */
_Static_assert (sizeof (result_strings) / sizeof (result_strings[0])
                    == QUIC_VARINT_ERROR_NULL + 1,
                "result_strings array size must match enum count");

const char *
SocketQUICVarInt_result_string (SocketQUICVarInt_Result result)
{
  const size_t num_results
      = sizeof (result_strings) / sizeof (result_strings[0]);

  if (result < 0 || (size_t)result >= num_results)
    return "Unknown error";

  return result_strings[result];
}

SocketQUICVarInt_Result
SocketQUICVarInt_decode (const uint8_t *data,
                         size_t len,
                         uint64_t *value,
                         size_t *consumed)
{
  uint8_t prefix;
  size_t required_len;

  if (data == NULL || value == NULL || consumed == NULL)
    return QUIC_VARINT_ERROR_NULL;

  if (len == 0)
    return QUIC_VARINT_INCOMPLETE;

  prefix = data[0] & VARINT_PREFIX_MASK;

  switch (prefix)
    {
    case VARINT_PREFIX_1BYTE:
      required_len = 1;
      break;
    case VARINT_PREFIX_2BYTE:
      required_len = 2;
      break;
    case VARINT_PREFIX_4BYTE:
      required_len = 4;
      break;
    case VARINT_PREFIX_8BYTE:
      required_len = 8;
      break;
    default:
      /* Unreachable - prefix is masked to 2 bits (only 4 possible values) */
      assert (0 && "Unreachable: prefix masked to 2 bits");
      return QUIC_VARINT_INCOMPLETE;
    }

  if (len < required_len)
    return QUIC_VARINT_INCOMPLETE;

  switch (prefix)
    {
    case VARINT_PREFIX_1BYTE:
      *value = (uint64_t)(data[0] & VARINT_VALUE_MASK_1BYTE);
      break;

    case VARINT_PREFIX_2BYTE:
      *value = ((uint64_t)(data[0] & VARINT_VALUE_MASK_2BYTE) << 8)
               | (uint64_t)data[1];
      break;

    case VARINT_PREFIX_4BYTE:
      *value = ((uint64_t)(data[0] & VARINT_VALUE_MASK_4BYTE) << 24)
               | ((uint64_t)data[1] << 16) | ((uint64_t)data[2] << 8)
               | (uint64_t)data[3];
      break;

    case VARINT_PREFIX_8BYTE:
      *value = ((uint64_t)(data[0] & VARINT_VALUE_MASK_8BYTE) << 56)
               | ((uint64_t)data[1] << 48) | ((uint64_t)data[2] << 40)
               | ((uint64_t)data[3] << 32) | ((uint64_t)data[4] << 24)
               | ((uint64_t)data[5] << 16) | ((uint64_t)data[6] << 8)
               | (uint64_t)data[7];
      break;
    }

  *consumed = required_len;
  return QUIC_VARINT_OK;
}

size_t
SocketQUICVarInt_size (uint64_t value)
{
  if (value <= VARINT_MAX_1BYTE)
    return 1;
  if (value <= VARINT_MAX_2BYTE)
    return 2;
  if (value <= VARINT_MAX_4BYTE)
    return 4;
  if (value <= VARINT_MAX_8BYTE)
    return 8;

  /* Value exceeds maximum representable value */
  return 0;
}

size_t
SocketQUICVarInt_encode (uint64_t value, uint8_t *output, size_t output_size)
{
  size_t required_size;

  if (output == NULL)
    return 0;

  required_size = SocketQUICVarInt_size (value);
  if (required_size == 0)
    return 0; /* Value too large */

  if (output_size < required_size)
    return 0; /* Buffer too small */

  switch (required_size)
    {
    case 1:
      output[0] = (uint8_t)(VARINT_PREFIX_1BYTE | (value & 0x3F));
      break;

    case 2:
      output[0] = (uint8_t)(VARINT_PREFIX_2BYTE | ((value >> 8) & 0x3F));
      output[1] = (uint8_t)(value & 0xFF);
      break;

    case 4:
      output[0] = (uint8_t)(VARINT_PREFIX_4BYTE | ((value >> 24) & 0x3F));
      output[1] = (uint8_t)((value >> 16) & 0xFF);
      output[2] = (uint8_t)((value >> 8) & 0xFF);
      output[3] = (uint8_t)(value & 0xFF);
      break;

    case 8:
      output[0] = (uint8_t)(VARINT_PREFIX_8BYTE | ((value >> 56) & 0x3F));
      output[1] = (uint8_t)((value >> 48) & 0xFF);
      output[2] = (uint8_t)((value >> 40) & 0xFF);
      output[3] = (uint8_t)((value >> 32) & 0xFF);
      output[4] = (uint8_t)((value >> 24) & 0xFF);
      output[5] = (uint8_t)((value >> 16) & 0xFF);
      output[6] = (uint8_t)((value >> 8) & 0xFF);
      output[7] = (uint8_t)(value & 0xFF);
      break;
    }

  return required_size;
}

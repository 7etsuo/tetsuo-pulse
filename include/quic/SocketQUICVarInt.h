/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICVarInt.h
 * @brief QUIC Variable-Length Integer encoding/decoding (RFC 9000 Section 16).
 *
 * Implements the QUIC variable-length integer encoding scheme. The 2 most
 * significant bits of the first byte encode the length of the integer:
 *   - 00: 1 byte  (6-bit value, max 63)
 *   - 01: 2 bytes (14-bit value, max 16383)
 *   - 10: 4 bytes (30-bit value, max 1073741823)
 *   - 11: 8 bytes (62-bit value, max 4611686018427387903)
 *
 * All multi-byte values are stored in network byte order (big-endian).
 *
 * Thread Safety: All functions are thread-safe (no shared state).
 *
 * @defgroup quic_varint QUIC Variable-Length Integer Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9000#section-16
 */

#ifndef SOCKETQUICVARINT_INCLUDED
#define SOCKETQUICVARINT_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Except.h"

/**
 * @brief Maximum value representable in QUIC variable-length integer.
 *
 * QUIC varints can represent values up to 2^62-1 (4611686018427387903).
 */
#define SOCKETQUICVARINT_MAX ((uint64_t)4611686018427387903ULL)

/**
 * @brief Maximum encoded size in bytes.
 */
#define SOCKETQUICVARINT_MAX_SIZE 8

/**
 * @brief Exception raised on encoding/decoding errors.
 *
 * Raised when:
 * - Decoding truncated input
 * - Encoding value exceeds maximum
 * - Output buffer too small
 */
extern const Except_T SocketQUICVarInt_Error;

/**
 * @brief Result codes for QUIC variable-length integer operations.
 */
typedef enum
{
  QUIC_VARINT_OK = 0,         /**< Operation succeeded */
  QUIC_VARINT_INCOMPLETE,     /**< Need more input data */
  QUIC_VARINT_ERROR_OVERFLOW, /**< Value exceeds maximum (2^62-1) */
  QUIC_VARINT_ERROR_BUFFER,   /**< Output buffer too small */
  QUIC_VARINT_ERROR_NULL      /**< NULL pointer argument */
} SocketQUICVarInt_Result;

/**
 * @brief Decode a QUIC variable-length integer.
 *
 * Decodes a variable-length integer from the given buffer according to
 * RFC 9000 Section 16. The 2 most significant bits of the first byte
 * determine the total length.
 *
 * @param data     Input buffer containing encoded integer.
 * @param len      Size of input buffer in bytes.
 * @param value    Output: decoded integer value.
 * @param consumed Output: number of bytes consumed from input.
 *
 * @return QUIC_VARINT_OK on success, error code otherwise.
 *
 * @retval QUIC_VARINT_OK         Successfully decoded.
 * @retval QUIC_VARINT_INCOMPLETE Input truncated (need more bytes).
 * @retval QUIC_VARINT_ERROR_NULL NULL pointer argument.
 *
 * Example:
 * @code
 * const uint8_t data[] = {0x40, 0x25}; // Encodes 37
 * uint64_t value;
 * size_t consumed;
 * SocketQUICVarInt_Result res = SocketQUICVarInt_decode(data, 2, &value, &consumed);
 * // value = 37, consumed = 2
 * @endcode
 */
extern SocketQUICVarInt_Result SocketQUICVarInt_decode (const uint8_t *data,
                                                        size_t len,
                                                        uint64_t *value,
                                                        size_t *consumed);

/**
 * @brief Encode a value as QUIC variable-length integer.
 *
 * Encodes the given value using the minimum number of bytes required.
 * Values 0-63 use 1 byte, 64-16383 use 2 bytes, etc.
 *
 * @param value       Value to encode (must be <= SOCKETQUICVARINT_MAX).
 * @param output      Output buffer for encoded bytes.
 * @param output_size Size of output buffer in bytes.
 *
 * @return Number of bytes written on success, 0 on error.
 *
 * Example:
 * @code
 * uint8_t buf[8];
 * size_t len = SocketQUICVarInt_encode(16384, buf, sizeof(buf));
 * // len = 4, buf = {0x80, 0x00, 0x40, 0x00}
 * @endcode
 */
extern size_t SocketQUICVarInt_encode (uint64_t value, uint8_t *output,
                                       size_t output_size);

/**
 * @brief Calculate encoded size for a value.
 *
 * Returns the number of bytes needed to encode the given value.
 *
 * @param value Value to calculate size for.
 *
 * @return 1, 2, 4, or 8 for valid values; 0 if value > SOCKETQUICVARINT_MAX.
 *
 * @note This is useful for pre-allocating buffers or calculating packet sizes.
 */
extern size_t SocketQUICVarInt_size (uint64_t value);

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code to convert.
 *
 * @return Human-readable string describing the result.
 */
extern const char *
SocketQUICVarInt_result_string (SocketQUICVarInt_Result result);

/** @} */

#endif /* SOCKETQUICVARINT_INCLUDED */

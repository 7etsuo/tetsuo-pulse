/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-private.h
 * @brief Internal QPACK header compression structures and constants.
 * @internal
 *
 * Private implementation for QPACK (RFC 9204). Use SocketQPACK.h for public
 * API.
 */

#ifndef SOCKETQPACK_PRIVATE_INCLUDED
#define SOCKETQPACK_PRIVATE_INCLUDED

#include "http/SocketQPACK.h"
#include <stdint.h>

/**
 * @defgroup qpack_private_constants Internal Constants
 * @{
 */

/**
 * Maximum size of integer encoding buffer.
 * Per QPACK variable-length integer encoding, we need at most:
 * 1 prefix byte + 10 continuation bytes = 11 bytes for 64-bit values.
 * Round up to 16 for alignment and safety.
 */
#define QPACK_INT_BUF_SIZE 16

/**
 * DeltaBase prefix bits per RFC 9204 Section 4.5.1.2.
 * The Sign bit occupies the high bit, leaving 7 bits for the prefix.
 */
#define QPACK_DELTABASE_PREFIX_BITS 7

/**
 * Sign bit mask for DeltaBase encoding.
 * Bit 7 (0x80) indicates the sign: 0 = positive delta, 1 = negative delta.
 */
#define QPACK_SIGN_BIT_MASK 0x80

/**
 * Maximum continuation bytes for variable-length integer decoding.
 * Prevents DoS via oversized integer encodings.
 * RFC 9204 uses same encoding as QPACK/HPACK (RFC 7541 Section 5.1).
 */
#define QPACK_MAX_INT_CONTINUATION_BYTES 10

/**
 * Maximum safe shift for integer decoding to prevent overflow.
 * 64 bits - 8 bits (last byte payload) = 56 bits max shift.
 */
#define QPACK_MAX_SAFE_SHIFT 56

/**
 * Integer continuation bit mask (high bit indicates more bytes follow).
 */
#define QPACK_INT_CONTINUATION_MASK 0x80

/**
 * Integer payload mask (lower 7 bits carry the value).
 */
#define QPACK_INT_PAYLOAD_MASK 0x7F

/** @} */

/**
 * @defgroup qpack_private_decoder Decoder State
 * @{
 */

/**
 * QPACK decoder state structure.
 *
 * Maintains state for decoding QPACK-compressed header fields including
 * the dynamic table, Base calculation, and security limits.
 */
struct SocketQPACK_Decoder_State
{
  SocketQPACK_Base_T base_calc;  /**< Current Base calculation */
  uint32_t known_received_count; /**< Known Received Count for blocking */
  uint32_t max_entries;          /**< Maximum dynamic table entries */
  uint32_t insert_count;         /**< Current dynamic table insert count */
};

/** @} */

/**
 * @defgroup qpack_private_funcs Internal Functions
 * @{
 */

/**
 * Decode a variable-length integer with given prefix bits.
 *
 * Implements RFC 9204 variable-length integer decoding (same as RFC 7541).
 *
 * @param input       Input buffer
 * @param input_len   Length of input buffer
 * @param prefix_bits Number of prefix bits (1-8)
 * @param value       Output: decoded integer value
 * @param consumed    Output: number of bytes consumed
 *
 * @return QPACK_OK on success, QPACK_INCOMPLETE if more data needed,
 *         QPACK_ERROR_INTEGER on overflow
 */
extern SocketQPACK_Result qpack_int_decode (const unsigned char *input,
                                            size_t input_len,
                                            int prefix_bits,
                                            uint64_t *value,
                                            size_t *consumed);

/**
 * Encode a variable-length integer with given prefix bits.
 *
 * @param value       Value to encode
 * @param prefix_bits Number of prefix bits (1-8)
 * @param output      Output buffer
 * @param output_size Size of output buffer
 *
 * @return Number of bytes written, or 0 on error
 */
extern size_t qpack_int_encode (uint64_t value,
                                int prefix_bits,
                                unsigned char *output,
                                size_t output_size);

/** @} */

#endif /* SOCKETQPACK_PRIVATE_INCLUDED */

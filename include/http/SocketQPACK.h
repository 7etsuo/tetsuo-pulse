/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK.h
 * @brief QPACK header compression/decompression for HTTP/3 (RFC 9204).
 *
 * Implements QPACK algorithm for HTTP/3 header compression with dynamic table,
 * field section prefix encoding, and Base calculation for indexed references.
 *
 * Thread Safety: Encoder/decoder instances are NOT thread-safe. One instance
 * per connection/thread recommended. Static functions are thread-safe.
 *
 * @defgroup qpack QPACK Header Compression Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9204
 */

#ifndef SOCKETQPACK_INCLUDED
#define SOCKETQPACK_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/Except.h"

/**
 * @defgroup qpack_result QPACK Result Codes
 * @{
 */

/**
 * QPACK operation result codes.
 */
typedef enum
{
  QPACK_OK = 0,                    /**< Operation succeeded */
  QPACK_INCOMPLETE,                /**< Need more data to complete operation */
  QPACK_ERROR,                     /**< Generic error */
  QPACK_ERROR_INVALID_BASE,        /**< Invalid Base calculation (negative or
                                      constraint violation) */
  QPACK_ERROR_INVALID_INDEX,       /**< Invalid table index */
  QPACK_ERROR_INTEGER,             /**< Integer overflow or encoding error */
  QPACK_ERROR_HEADER_SIZE,         /**< Header too large */
  QPACK_ERROR_DECOMPRESSION_FAILED /**< Decompression failure */
} SocketQPACK_Result;

/** @} */

/**
 * @defgroup qpack_exception QPACK Exceptions
 * @{
 */

/**
 * QPACK decoding error exception.
 * Raised when decoding operations fail due to protocol violations.
 */
extern const Except_T SocketQPACK_DecodeError;

/** @} */

/**
 * @defgroup qpack_base Base Encoding (RFC 9204 Section 4.5.1.2)
 * @{
 */

/**
 * Base calculation state for QPACK field section.
 *
 * The Base value is used to resolve relative indices in the dynamic table.
 * It is computed from the Required Insert Count and Delta Base in the
 * field section prefix.
 *
 * @see RFC 9204 Section 4.5.1.2
 */
typedef struct
{
  uint32_t req_insert_count; /**< Required Insert Count from field prefix */
  int32_t delta_base;        /**< Delta Base (variable-length integer) */
  int sign;                  /**< Sign bit: 0 = forward, 1 = backward */
  int32_t base;              /**< Calculated Base value */
} SocketQPACK_Base_T;

/**
 * Calculate Base from Sign bit, Required Insert Count, and Delta Base.
 *
 * Implements RFC 9204 Section 4.5.1.2:
 * - If Sign == 0: Base = ReqInsertCount + DeltaBase
 * - If Sign == 1: Base = ReqInsertCount - DeltaBase - 1
 *
 * @param req_insert_count Required Insert Count from field section prefix
 * @param delta_base       Delta Base value (non-negative integer)
 * @param sign             Sign bit (0 or 1)
 * @param base_out         Output: calculated Base value
 *
 * @return QPACK_OK on success, QPACK_ERROR_INVALID_BASE on failure
 *
 * @note When Sign=1, ReqInsertCount MUST be greater than DeltaBase
 * @note The resulting Base MUST be non-negative
 */
extern SocketQPACK_Result SocketQPACK_calculate_base (uint32_t req_insert_count,
                                                      int32_t delta_base,
                                                      int sign,
                                                      int32_t *base_out);

/**
 * Validate Base calculation constraints.
 *
 * Checks that:
 * - Base is non-negative
 * - Sign bit constraints are satisfied (Sign=1 requires ReqInsertCount >
 * DeltaBase)
 *
 * @param req_insert_count Required Insert Count
 * @param delta_base       Delta Base value
 * @param sign             Sign bit (0 or 1)
 *
 * @return QPACK_OK if valid, QPACK_ERROR_INVALID_BASE if constraints violated
 */
extern SocketQPACK_Result SocketQPACK_validate_base (uint32_t req_insert_count,
                                                     int32_t delta_base,
                                                     int sign);

/**
 * Parse Base prefix from encoded field section.
 *
 * Parses the Sign bit and DeltaBase from the field section prefix after
 * the Required Insert Count has been decoded. The DeltaBase uses a 7-bit
 * prefix variable-length integer encoding.
 *
 * @param input            Input buffer containing encoded prefix
 * @param input_len        Length of input buffer
 * @param req_insert_count Required Insert Count (decoded separately)
 * @param base_out         Output: populated Base calculation structure
 * @param consumed         Output: number of bytes consumed from input
 *
 * @return QPACK_OK on success, QPACK_INCOMPLETE if more data needed,
 *         QPACK_ERROR_INVALID_BASE on constraint violation,
 *         QPACK_ERROR_INTEGER on decoding error
 *
 * @see RFC 9204 Section 4.5.1.2
 */
extern SocketQPACK_Result
SocketQPACK_parse_base_prefix (const unsigned char *input,
                               size_t input_len,
                               uint32_t req_insert_count,
                               SocketQPACK_Base_T *base_out,
                               size_t *consumed);

/**
 * Encode Base prefix into field section.
 *
 * Encodes the Sign bit and DeltaBase for the field section prefix.
 * The DeltaBase uses a 7-bit prefix variable-length integer encoding.
 *
 * @param base        Desired Base value
 * @param req_insert_count Required Insert Count for this field section
 * @param output      Output buffer for encoded prefix
 * @param output_size Size of output buffer
 *
 * @return Number of bytes written, or -1 on error
 */
extern int SocketQPACK_encode_base_prefix (int32_t base,
                                           uint32_t req_insert_count,
                                           unsigned char *output,
                                           size_t output_size);

/**
 * Get string description for QPACK result code.
 *
 * @param result QPACK result code
 * @return Human-readable description string
 */
extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/** @} */

/** @} */ /* qpack group */

#endif /* SOCKETQPACK_INCLUDED */

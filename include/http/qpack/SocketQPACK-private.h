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

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "core/Arena.h"

/**
 * @brief QPACK result codes for operations.
 */
typedef enum
{
  QPACK_OK = 0,
  QPACK_INCOMPLETE,             /* Need more data */
  QPACK_ERROR,                  /* Generic error */
  QPACK_ERROR_INTEGER_OVERFLOW, /* Integer value too large */
  QPACK_ERROR_INVALID_REQUIRED_INSERT_COUNT,
  QPACK_ERROR_INVALID_BASE,
  QPACK_ERROR_BUFFER_TOO_SMALL,
} SocketQPACK_Result;

/**
 * @brief Decoded field section prefix (RFC 9204 Section 4.5.1).
 *
 * The prefix appears at the start of each encoded field section and provides:
 * - Required Insert Count: Minimum dynamic table insertions needed to decode
 * - Delta Base: Relative value for computing the absolute Base index
 * - Base: Computed absolute index for relative references in the field section
 */
typedef struct
{
  size_t required_insert_count; /* Minimum inserts needed to decode */
  int64_t delta_base;           /* Signed relative value from wire */
  size_t base;                  /* Computed absolute base index */
} SocketQPACK_FieldSectionPrefix;

/**
 * @brief Result of prefix decoding operation.
 */
typedef struct
{
  int status;                            /* 0 = success, <0 = error code */
  size_t consumed;                       /* Bytes consumed from input */
  SocketQPACK_FieldSectionPrefix prefix; /* Decoded prefix values */
} SocketQPACK_DecodePrefixResult;

/* ============================================================================
 * Integer Encoding/Decoding (RFC 9204 Section 4.1.1)
 * ============================================================================
 */

/**
 * @brief Encode an integer using QPACK integer representation.
 *
 * RFC 9204 Section 4.1.1 specifies integer encoding identical to HPACK
 * (RFC 7541 Section 5.1), using a variable-length encoding with a prefix.
 *
 * @param value       Value to encode
 * @param prefix_bits Number of bits available in first byte (1-8)
 * @param output      Output buffer
 * @param output_size Size of output buffer
 *
 * @return Number of bytes written, or 0 on error
 */
extern size_t socketqpack_encode_integer (uint64_t value,
                                          int prefix_bits,
                                          unsigned char *output,
                                          size_t output_size);

/**
 * @brief Decode an integer using QPACK integer representation.
 *
 * @param input       Input buffer
 * @param input_len   Length of input buffer
 * @param prefix_bits Number of bits available in first byte (1-8)
 * @param value       [out] Decoded value
 * @param consumed    [out] Number of bytes consumed
 *
 * @return QPACK_OK on success, error code otherwise
 */
extern SocketQPACK_Result
socketqpack_decode_integer (const unsigned char *input,
                            size_t input_len,
                            int prefix_bits,
                            uint64_t *value,
                            size_t *consumed);

/* ============================================================================
 * Field Section Prefix (RFC 9204 Section 4.5.1)
 * ============================================================================
 */

/**
 * @brief Encode a field section prefix.
 *
 * Encodes Required Insert Count (8-bit prefix) followed by Delta Base
 * with sign bit (7-bit prefix).
 *
 * @param required_insert_count Required Insert Count value
 * @param base                  Absolute Base index
 * @param max_entries           Maximum entries in dynamic table
 * @param output                Output buffer
 * @param output_size           Size of output buffer
 *
 * @return Number of bytes written, or negative error code
 */
extern ssize_t socketqpack_encode_prefix (size_t required_insert_count,
                                          size_t base,
                                          size_t max_entries,
                                          unsigned char *output,
                                          size_t output_size);

/**
 * @brief Decode a field section prefix.
 *
 * Decodes Required Insert Count and Delta Base, computes absolute Base,
 * and validates against dynamic table state.
 *
 * @param input         Input buffer
 * @param input_len     Length of input buffer
 * @param max_entries   Maximum entries in dynamic table
 * @param total_inserts Total insertions into dynamic table so far
 *
 * @return Decode result with status, consumed bytes, and prefix values
 */
extern SocketQPACK_DecodePrefixResult
socketqpack_decode_prefix (const unsigned char *input,
                           size_t input_len,
                           size_t max_entries,
                           size_t total_inserts);

/**
 * @brief Validate a decoded prefix against dynamic table state.
 *
 * Checks that Required Insert Count does not exceed total_inserts and
 * that Base is within valid range.
 *
 * @param prefix        Decoded prefix to validate
 * @param total_inserts Total insertions into dynamic table so far
 *
 * @return QPACK_OK if valid, error code otherwise
 */
extern SocketQPACK_Result
socketqpack_validate_prefix (const SocketQPACK_FieldSectionPrefix *prefix,
                             size_t total_inserts);

/**
 * @brief Get string representation of QPACK result code.
 *
 * @param result Result code to convert
 *
 * @return Static string describing the result
 */
extern const char *socketqpack_result_string (SocketQPACK_Result result);

#endif /* SOCKETQPACK_PRIVATE_INCLUDED */

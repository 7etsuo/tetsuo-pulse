/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK.h
 * @brief QPACK header compression for HTTP/3 (RFC 9204).
 *
 * Implements QPACK encoding/decoding primitives (Section 4.1) and field line
 * representations for HTTP/3 header compression.
 *
 * Key features:
 * - Integer encoding/decoding with variable prefix sizes (3-8 bits)
 * - String literal encoding/decoding with optional Huffman compression
 * - Literal Field Line with Literal Name (Section 4.5.6)
 *
 * QPACK uses the same Huffman table as HPACK (RFC 7541 Appendix B) but
 * supports additional prefix sizes for various instruction types.
 *
 * Thread Safety: All functions are thread-safe (no shared state).
 *
 * @defgroup qpack QPACK Header Compression Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9204
 */

#ifndef SOCKETQPACK_INCLUDED
#define SOCKETQPACK_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/**
 * @brief Maximum integer value representable in QPACK (RFC 9204).
 *
 * QPACK integers can represent values up to 2^62-1 (4,611,686,018,427,387,903).
 */
#define SOCKETQPACK_INT_MAX ((uint64_t)4611686018427387903ULL)

/**
 * @brief Minimum valid prefix size for QPACK integers.
 */
#define SOCKETQPACK_PREFIX_MIN 3

/**
 * @brief Maximum valid prefix size for QPACK integers.
 */
#define SOCKETQPACK_PREFIX_MAX 8

/**
 * @brief RFC 9204 Section 4.5.6: Pattern bits for Literal Field Line with
 *        Literal Name.
 *
 * Wire format: 0 0 1 N H NameLen(3+) | NameString | H ValueLen(7+) |
 * ValueString The first 3 bits are '001' (0x20 mask after shifting).
 */
#define SOCKETQPACK_LITERAL_LITERAL_PATTERN 0x20

/**
 * @brief Mask for pattern bits (top 3 bits).
 */
#define SOCKETQPACK_LITERAL_LITERAL_MASK 0xE0

/**
 * @brief Never-indexed bit position in Literal Field Line with Literal Name.
 *
 * RFC 9204 Section 4.5.6: The N bit (bit 4) indicates sensitive data that
 * must not be added to the dynamic table.
 */
#define SOCKETQPACK_NEVER_INDEXED_BIT 0x10

/**
 * @brief Huffman flag bit for name in Literal Field Line with Literal Name.
 *
 * RFC 9204 Section 4.5.6: Bit 3 indicates if the name is Huffman-encoded.
 */
#define SOCKETQPACK_NAME_HUFFMAN_BIT 0x08

/**
 * @brief Name length prefix size for Literal Field Line with Literal Name.
 *
 * RFC 9204 Section 4.5.6: 3-bit prefix for name length encoding.
 */
#define SOCKETQPACK_LITERAL_NAME_PREFIX 3

/**
 * @brief Value length prefix size for Literal Field Line with Literal Name.
 *
 * RFC 9204 Section 4.5.6: 7-bit prefix for value length encoding.
 */
#define SOCKETQPACK_LITERAL_VALUE_PREFIX 7

/**
 * @brief Result codes for QPACK operations.
 */
typedef enum
{
  QPACK_OK = 0,        /**< Operation succeeded */
  QPACK_ERROR,         /**< Generic error */
  QPACK_INCOMPLETE,    /**< Need more input data */
  QPACK_ERROR_INTEGER, /**< Integer overflow or invalid encoding */
  QPACK_ERROR_HUFFMAN, /**< Huffman encoding/decoding error */
  QPACK_ERROR_BUFFER,  /**< Output buffer too small */
  QPACK_ERROR_PREFIX,  /**< Invalid prefix bits (must be 3-8) */
  QPACK_ERROR_NULL,    /**< NULL pointer argument */
  QPACK_ERROR_PATTERN  /**< Invalid pattern bits for field line type */
} SocketQPACK_Result;

/**
 * @brief Decoded Literal Field Line with Literal Name structure.
 *
 * RFC 9204 Section 4.5.6: Contains the decoded field name and value
 * along with metadata flags.
 */
typedef struct
{
  const unsigned char *name;  /**< Field name (not null-terminated) */
  size_t name_len;            /**< Length of name in bytes */
  const unsigned char *value; /**< Field value (not null-terminated) */
  size_t value_len;           /**< Length of value in bytes */
  int never_indexed;          /**< N bit: 1=sensitive, 0=can be indexed */
} SocketQPACK_LiteralLiteral_T;

/* ============================================================================
 * Integer Encoding/Decoding (RFC 9204 Section 4.1.1)
 * ============================================================================
 */

/**
 * @brief Encode a prefixed integer (RFC 9204 Section 4.1.1).
 *
 * Encodes an integer value using the QPACK/HPACK integer encoding scheme.
 * The prefix_bits parameter specifies how many bits of the first byte are
 * available for the integer value.
 *
 * @param value       Integer value to encode (0 to 2^62-1).
 * @param prefix_bits Number of bits available in first byte (3-8).
 * @param output      Output buffer for encoded bytes.
 * @param output_size Size of output buffer in bytes.
 *
 * @return Number of bytes written on success, -1 on error.
 */
extern ssize_t SocketQPACK_int_encode (uint64_t value,
                                       int prefix_bits,
                                       unsigned char *output,
                                       size_t output_size);

/**
 * @brief Decode a prefixed integer (RFC 9204 Section 4.1.1).
 *
 * Decodes an integer value from QPACK/HPACK encoding.
 *
 * @param input       Input buffer containing encoded integer.
 * @param input_len   Size of input buffer in bytes.
 * @param prefix_bits Number of bits used for integer in first byte (3-8).
 * @param value       Output: decoded integer value.
 * @param consumed    Output: number of bytes consumed from input.
 *
 * @return QPACK_OK on success, error code otherwise.
 */
extern SocketQPACK_Result SocketQPACK_int_decode (const unsigned char *input,
                                                  size_t input_len,
                                                  int prefix_bits,
                                                  uint64_t *value,
                                                  size_t *consumed);

/**
 * @brief Calculate encoded size for an integer value.
 *
 * @param value       Value to calculate size for.
 * @param prefix_bits Number of bits in prefix (3-8).
 *
 * @return Number of bytes needed, or 0 if invalid.
 */
extern size_t SocketQPACK_int_size (uint64_t value, int prefix_bits);

/* ============================================================================
 * String Encoding/Decoding (RFC 9204 Section 4.1.2)
 * ============================================================================
 */

/**
 * @brief Encode a string literal (RFC 9204 Section 4.1.2).
 *
 * Encodes a string using optional Huffman compression (RFC 7541 Appendix B).
 *
 * @param input       Input string data.
 * @param input_len   Length of input string in bytes.
 * @param use_huffman 1 to enable Huffman compression, 0 for plain text.
 * @param prefix_bits Number of bits for length prefix (3-8).
 * @param output      Output buffer for encoded bytes.
 * @param output_size Size of output buffer in bytes.
 *
 * @return Number of bytes written on success, -1 on error.
 */
extern ssize_t SocketQPACK_string_encode (const unsigned char *input,
                                          size_t input_len,
                                          int use_huffman,
                                          int prefix_bits,
                                          unsigned char *output,
                                          size_t output_size);

/**
 * @brief Decode a string literal (RFC 9204 Section 4.1.2).
 *
 * @param input       Input buffer containing encoded string.
 * @param input_len   Size of input buffer in bytes.
 * @param prefix_bits Number of bits for length prefix (3-8).
 * @param output      Output buffer for decoded string.
 * @param output_size Size of output buffer in bytes.
 * @param decoded_len Output: actual length of decoded string.
 * @param consumed    Output: number of bytes consumed from input.
 *
 * @return QPACK_OK on success, error code otherwise.
 */
extern SocketQPACK_Result SocketQPACK_string_decode (const unsigned char *input,
                                                     size_t input_len,
                                                     int prefix_bits,
                                                     unsigned char *output,
                                                     size_t output_size,
                                                     size_t *decoded_len,
                                                     size_t *consumed);

/**
 * @brief Calculate encoded size for a string.
 *
 * @param input       Input string data.
 * @param input_len   Length of input string.
 * @param use_huffman 1 for Huffman encoding, 0 for plain.
 * @param prefix_bits Number of bits for length prefix (3-8).
 *
 * @return Number of bytes needed, or 0 on error.
 */
extern size_t SocketQPACK_string_size (const unsigned char *input,
                                       size_t input_len,
                                       int use_huffman,
                                       int prefix_bits);

/* ============================================================================
 * Literal Field Line with Literal Name (RFC 9204 Section 4.5.6)
 * ============================================================================
 */

/**
 * @brief Encode a Literal Field Line with Literal Name (RFC 9204
 * Section 4.5.6).
 *
 * Encodes a header field where both name and value are literal strings.
 * This is the most general encoding form in QPACK.
 *
 * Wire format:
 *   0 0 1 N H NameLen(3+) | NameString | H ValueLen(7+) | ValueString
 *
 * @param name          Field name (case-sensitive, lowercase recommended).
 * @param name_len      Length of field name in bytes.
 * @param value         Field value.
 * @param value_len     Length of field value in bytes.
 * @param never_indexed 1 for sensitive data (N bit), 0 for normal.
 * @param use_huffman   1 to enable Huffman compression, 0 for plain.
 * @param output        Output buffer for encoded field line.
 * @param output_size   Size of output buffer in bytes.
 *
 * @return Number of bytes written on success, -1 on error.
 *
 * Example:
 * @code
 * unsigned char buf[256];
 * ssize_t len = SocketQPACK_literal_literal_encode(
 *     (const unsigned char *)"content-type", 12,
 *     (const unsigned char *)"application/json", 16,
 *     0, 1, buf, sizeof(buf));
 * @endcode
 */
extern ssize_t SocketQPACK_literal_literal_encode (const unsigned char *name,
                                                   size_t name_len,
                                                   const unsigned char *value,
                                                   size_t value_len,
                                                   int never_indexed,
                                                   int use_huffman,
                                                   unsigned char *output,
                                                   size_t output_size);

/**
 * @brief Decode a Literal Field Line with Literal Name (RFC 9204
 * Section 4.5.6).
 *
 * Decodes a header field where both name and value are literal strings.
 * The caller must provide output buffers for name and value.
 *
 * @param input         Input buffer containing encoded field line.
 * @param input_len     Size of input buffer in bytes.
 * @param name_out      Output buffer for decoded name.
 * @param name_out_size Size of name output buffer.
 * @param value_out     Output buffer for decoded value.
 * @param value_out_size Size of value output buffer.
 * @param result        Output: decoded field line structure.
 * @param consumed      Output: number of bytes consumed from input.
 *
 * @return QPACK_OK on success, error code otherwise.
 *
 * @retval QPACK_OK           Successfully decoded.
 * @retval QPACK_INCOMPLETE   Input truncated.
 * @retval QPACK_ERROR_PATTERN First byte does not have '001' pattern.
 * @retval QPACK_ERROR_HUFFMAN Huffman decoding failed.
 * @retval QPACK_ERROR_BUFFER Output buffer too small.
 * @retval QPACK_ERROR_NULL   NULL pointer argument.
 */
extern SocketQPACK_Result
SocketQPACK_literal_literal_decode (const unsigned char *input,
                                    size_t input_len,
                                    unsigned char *name_out,
                                    size_t name_out_size,
                                    unsigned char *value_out,
                                    size_t value_out_size,
                                    SocketQPACK_LiteralLiteral_T *result,
                                    size_t *consumed);

/**
 * @brief Calculate encoded size for a Literal Field Line with Literal Name.
 *
 * @param name        Field name.
 * @param name_len    Length of field name.
 * @param value       Field value.
 * @param value_len   Length of field value.
 * @param use_huffman 1 for Huffman encoding, 0 for plain.
 *
 * @return Number of bytes needed, or 0 on error.
 */
extern size_t SocketQPACK_literal_literal_size (const unsigned char *name,
                                                size_t name_len,
                                                const unsigned char *value,
                                                size_t value_len,
                                                int use_huffman);

/**
 * @brief Validate pattern bits for Literal Field Line with Literal Name.
 *
 * RFC 9204 Section 4.5.6: Pattern bits must be '001' (bits 7-5).
 *
 * @param first_byte First byte of encoded field line.
 *
 * @return 1 if pattern is valid ('001'), 0 otherwise.
 */
static inline int
SocketQPACK_is_literal_literal (unsigned char first_byte)
{
  return (first_byte & SOCKETQPACK_LITERAL_LITERAL_MASK)
         == SOCKETQPACK_LITERAL_LITERAL_PATTERN;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code to convert.
 *
 * @return Human-readable string describing the result.
 */
extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/** @} */

#endif /* SOCKETQPACK_INCLUDED */

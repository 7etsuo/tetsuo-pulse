/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK.h
 * @brief QPACK Primitives for HTTP/3 header compression (RFC 9204 Section 4.1).
 *
 * Implements the primitive encoding/decoding functions for QPACK:
 * - Integer encoding/decoding with variable prefix sizes (3-8 bits)
 * - String literal encoding/decoding with optional Huffman compression
 *
 * QPACK uses the same Huffman table as HPACK (RFC 7541 Appendix B) but
 * supports additional prefix sizes for various instruction types.
 *
 * Thread Safety: All functions are thread-safe (no shared state).
 *
 * @defgroup qpack QPACK Header Compression Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-4.1
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
 * @brief Result codes for QPACK primitive operations.
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
  QPACK_ERROR_NULL     /**< NULL pointer argument */
} SocketQPACK_Result;

/**
 * @brief Huffman encoding mode for string literals.
 */
typedef enum
{
  QPACK_HUFFMAN_PLAIN = 0,  /**< Plain text encoding (no compression) */
  QPACK_HUFFMAN_ENCODED = 1 /**< Huffman-compressed encoding */
} SocketQPACK_Huffman_T;

/**
 * @brief Encode a prefixed integer (RFC 9204 Section 4.1.1).
 *
 * Encodes an integer value using the QPACK/HPACK integer encoding scheme.
 * The prefix_bits parameter specifies how many bits of the first byte are
 * available for the integer value.
 *
 * QPACK-specific prefix sizes by instruction type:
 * - 8 bits: Required Insert Count
 * - 7 bits: Section Ack, Delta Base
 * - 6 bits: Insert Name Reference, Stream Cancel, Insert Count Increment,
 *           Indexed Field Line
 * - 5 bits: Set Dynamic Table Capacity, Insert Literal Name, Duplicate
 * - 4 bits: Post-Base Indexed, Literal Name Reference
 * - 3 bits: Post-Base Name Reference, Literal Name
 *
 * @param value       Integer value to encode (0 to 2^62-1).
 * @param prefix_bits Number of bits available in first byte (3-8).
 * @param output      Output buffer for encoded bytes.
 * @param output_size Size of output buffer in bytes.
 *
 * @return Number of bytes written on success, -1 on error.
 *
 * @note The first byte's high bits (above prefix_bits) are preserved
 *       and should be set by the caller for instruction type flags.
 *
 * Example:
 * @code
 * unsigned char buf[16];
 * // Encode value 1337 with 5-bit prefix
 * ssize_t len = SocketQPACK_int_encode(1337, 5, buf, sizeof(buf));
 * // len = 3, buf = {0x1f, 0x9a, 0x0a}
 * @endcode
 */
extern ssize_t SocketQPACK_int_encode (uint64_t value,
                                       int prefix_bits,
                                       unsigned char *output,
                                       size_t output_size);

/**
 * @brief Decode a prefixed integer (RFC 9204 Section 4.1.1).
 *
 * Decodes an integer value from QPACK/HPACK encoding. The prefix_bits
 * parameter specifies how many bits of the first byte contain the
 * integer value (the rest are instruction flags).
 *
 * @param input       Input buffer containing encoded integer.
 * @param input_len   Size of input buffer in bytes.
 * @param prefix_bits Number of bits used for integer in first byte (3-8).
 * @param value       Output: decoded integer value.
 * @param consumed    Output: number of bytes consumed from input.
 *
 * @return QPACK_OK on success, error code otherwise.
 *
 * @retval QPACK_OK           Successfully decoded.
 * @retval QPACK_INCOMPLETE   Input truncated (need more bytes).
 * @retval QPACK_ERROR_PREFIX Invalid prefix_bits (must be 3-8).
 * @retval QPACK_ERROR_INTEGER Integer overflow (value > 2^62-1).
 * @retval QPACK_ERROR_NULL   NULL pointer argument.
 *
 * Example:
 * @code
 * const unsigned char data[] = {0x1f, 0x9a, 0x0a};
 * uint64_t value;
 * size_t consumed;
 * SocketQPACK_Result res = SocketQPACK_int_decode(data, 3, 5, &value,
 * &consumed);
 * // value = 1337, consumed = 3
 * @endcode
 */
extern SocketQPACK_Result SocketQPACK_int_decode (const unsigned char *input,
                                                  size_t input_len,
                                                  int prefix_bits,
                                                  uint64_t *value,
                                                  size_t *consumed);

/**
 * @brief Encode a string literal (RFC 9204 Section 4.1.2).
 *
 * Encodes a string using optional Huffman compression (RFC 7541 Appendix B).
 * The first byte contains:
 * - Bit 7 (in position prefix_bits-1): Huffman flag (1=compressed, 0=plain)
 * - Remaining bits: length prefix
 *
 * QPACK string prefix sizes depend on the instruction context:
 * - 7 bits: Most common (same as HPACK)
 * - Other sizes: Used in specific QPACK instructions
 *
 * @param input       Input string data.
 * @param input_len   Length of input string in bytes.
 * @param use_huffman 1 to enable Huffman compression, 0 for plain text.
 * @param prefix_bits Number of bits for length prefix (3-8).
 * @param output      Output buffer for encoded bytes.
 * @param output_size Size of output buffer in bytes.
 *
 * @return Number of bytes written on success, -1 on error.
 *
 * @note When use_huffman is 1, the function will encode using Huffman
 *       only if it reduces the size; otherwise plain encoding is used.
 *
 * Example:
 * @code
 * unsigned char buf[256];
 * const char *str = "www.example.org";
 * ssize_t len = SocketQPACK_string_encode(
 *     (const unsigned char *)str, strlen(str), 1, 7, buf, sizeof(buf));
 * // Returns encoded length with Huffman compression
 * @endcode
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
 * Decodes a string from QPACK encoding, handling both plain and
 * Huffman-compressed representations.
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
 *
 * @retval QPACK_OK           Successfully decoded.
 * @retval QPACK_INCOMPLETE   Input truncated (need more bytes).
 * @retval QPACK_ERROR_PREFIX Invalid prefix_bits (must be 3-8).
 * @retval QPACK_ERROR_HUFFMAN Huffman decoding failed.
 * @retval QPACK_ERROR_BUFFER Output buffer too small.
 * @retval QPACK_ERROR_NULL   NULL pointer argument.
 *
 * Example:
 * @code
 * const unsigned char encoded[] = {...};
 * unsigned char decoded[256];
 * size_t decoded_len, consumed;
 * SocketQPACK_Result res = SocketQPACK_string_decode(
 *     encoded, sizeof(encoded), 7, decoded, sizeof(decoded),
 *     &decoded_len, &consumed);
 * @endcode
 */
extern SocketQPACK_Result SocketQPACK_string_decode (const unsigned char *input,
                                                     size_t input_len,
                                                     int prefix_bits,
                                                     unsigned char *output,
                                                     size_t output_size,
                                                     size_t *decoded_len,
                                                     size_t *consumed);

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code to convert.
 *
 * @return Human-readable string describing the result.
 */
extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/**
 * @brief Calculate encoded size for an integer value.
 *
 * Returns the number of bytes needed to encode the given value
 * with the specified prefix size.
 *
 * @param value       Value to calculate size for.
 * @param prefix_bits Number of bits in prefix (3-8).
 *
 * @return Number of bytes needed, or 0 if value exceeds maximum
 *         or prefix_bits is invalid.
 */
extern size_t SocketQPACK_int_size (uint64_t value, int prefix_bits);

/**
 * @brief Calculate encoded size for a string.
 *
 * Returns the number of bytes needed to encode the string
 * with the specified settings.
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

/** @} */

#endif /* SOCKETQPACK_INCLUDED */

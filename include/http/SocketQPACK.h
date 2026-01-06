/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK.h
 * @brief QPACK header compression/decompression for HTTP/3 (RFC 9204).
 *
 * Implements QPACK algorithm with static table (99 entries), dynamic table
 * (FIFO eviction), and Huffman encoding. This is based on HPACK (RFC 7541)
 * but designed for the out-of-order delivery characteristics of QUIC.
 *
 * This implementation focuses on Section 4.5.4 - Literal Field Line with
 * Name Reference, which encodes a field line using a name reference from
 * the static or dynamic table with a literal value.
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
#include <sys/types.h>

#include "core/Arena.h"
#include "core/Except.h"

/* ============================================================================
 * Configuration Constants
 * ============================================================================
 */

#ifndef SOCKETQPACK_DEFAULT_TABLE_SIZE
#define SOCKETQPACK_DEFAULT_TABLE_SIZE 4096
#endif

#ifndef SOCKETQPACK_MAX_TABLE_SIZE
#define SOCKETQPACK_MAX_TABLE_SIZE (64 * 1024)
#endif

#ifndef SOCKETQPACK_MAX_HEADER_SIZE
#define SOCKETQPACK_MAX_HEADER_SIZE (8 * 1024)
#endif

#ifndef SOCKETQPACK_MAX_HEADER_LIST_SIZE
#define SOCKETQPACK_MAX_HEADER_LIST_SIZE (64 * 1024)
#endif

/** RFC 9204 Appendix A - Static Table has 99 entries (indices 0-98) */
#define SOCKETQPACK_STATIC_TABLE_SIZE 99

/** RFC 9204 Section 3.2.1 - Entry overhead is 32 bytes */
#define SOCKETQPACK_ENTRY_OVERHEAD 32

/* ============================================================================
 * Exception and Result Types
 * ============================================================================
 */

/**
 * @brief Exception raised on QPACK compression/decompression errors.
 */
extern const Except_T SocketQPACK_Error;

/**
 * @brief Result codes for QPACK operations.
 */
typedef enum
{
  QPACK_OK = 0,               /**< Operation succeeded */
  QPACK_INCOMPLETE,           /**< Need more data */
  QPACK_ERROR,                /**< Generic error */
  QPACK_ERROR_INVALID_INDEX,  /**< Invalid table index */
  QPACK_ERROR_HUFFMAN,        /**< Huffman decoding error */
  QPACK_ERROR_INTEGER,        /**< Integer encoding/decoding error */
  QPACK_ERROR_TABLE_SIZE,     /**< Invalid dynamic table size */
  QPACK_ERROR_HEADER_SIZE,    /**< Header too large */
  QPACK_ERROR_LIST_SIZE,      /**< Header list too large */
  QPACK_ERROR_INVALID_PATTERN /**< Invalid field line pattern */
} SocketQPACK_Result;

/* ============================================================================
 * Data Structures
 * ============================================================================
 */

/**
 * @brief Decoded header field.
 */
typedef struct
{
  const char *name;  /**< Header name (null-terminated) */
  size_t name_len;   /**< Header name length */
  const char *value; /**< Header value (null-terminated) */
  size_t value_len;  /**< Header value length */
  int never_index;   /**< N bit: 1 to prevent intermediary caching */
} SocketQPACK_Header;

/**
 * @brief Literal Field Line with Name Reference (RFC 9204 Section 4.5.4).
 *
 * Wire format:
 *     0   1   2   3   4   5   6   7
 *   +---+---+---+---+---+---+---+---+
 *   | 0 | 1 | N | T |Name Index (4+)|
 *   +---+---+---+---+---------------+
 *   | H |     Value Length (7+)     |
 *   +---+---------------------------+
 *   |  Value String (Length bytes)  |
 *   +-------------------------------+
 *
 * - Bits 7-6: Pattern = 01 (literal with name reference)
 * - Bit 5: N = Never-indexed bit (0=can cache, 1=must not cache)
 * - Bit 4: T = Table selection (0=dynamic, 1=static)
 * - Bits 3-0: First 4 bits of name index
 */
typedef struct
{
  uint32_t name_index; /**< Table index for name */
  int is_static;       /**< T bit: 1 for static, 0 for dynamic table */
  int never_indexed;   /**< N bit: 1 to prevent intermediary caching */
  const char *value;   /**< Decoded value string */
  size_t value_len;    /**< Value length */
  int huffman_encoded; /**< H bit: 1 if value was Huffman-encoded */
} SocketQPACK_LiteralFieldLine;

/**
 * @brief Opaque dynamic table type.
 */
typedef struct SocketQPACK_Table *SocketQPACK_Table_T;

/* ============================================================================
 * Dynamic Table Functions
 * ============================================================================
 */

/**
 * @brief Create dynamic table with FIFO eviction (RFC 9204 Section 3.2).
 *
 * @param max_size Maximum table size in bytes
 * @param arena    Memory arena for allocations
 * @return New table instance
 */
extern SocketQPACK_Table_T
SocketQPACK_Table_new (size_t max_size, Arena_T arena);

/**
 * @brief Free dynamic table resources.
 *
 * @param table Pointer to table (set to NULL after)
 */
extern void SocketQPACK_Table_free (SocketQPACK_Table_T *table);

/**
 * @brief Update maximum table size, evicting entries if necessary.
 *
 * @param table    Table instance
 * @param max_size New maximum size
 */
extern void
SocketQPACK_Table_set_max_size (SocketQPACK_Table_T table, size_t max_size);

/**
 * @brief Get current table size (sum of entry sizes).
 *
 * @param table Table instance
 * @return Current size in bytes
 */
extern size_t SocketQPACK_Table_size (SocketQPACK_Table_T table);

/**
 * @brief Get number of entries in table.
 *
 * @param table Table instance
 * @return Entry count
 */
extern size_t SocketQPACK_Table_count (SocketQPACK_Table_T table);

/**
 * @brief Get maximum table size.
 *
 * @param table Table instance
 * @return Maximum size in bytes
 */
extern size_t SocketQPACK_Table_max_size (SocketQPACK_Table_T table);

/**
 * @brief Get entry by absolute index.
 *
 * @param table  Table instance
 * @param index  Absolute index (starting from 0)
 * @param header Output header data
 * @return QPACK_OK on success, QPACK_ERROR_INVALID_INDEX if out of bounds
 */
extern SocketQPACK_Result SocketQPACK_Table_get (SocketQPACK_Table_T table,
                                                 size_t index,
                                                 SocketQPACK_Header *header);

/**
 * @brief Add entry to dynamic table.
 *
 * May evict oldest entries if table exceeds max_size.
 *
 * @param table     Table instance
 * @param name      Header name
 * @param name_len  Name length
 * @param value     Header value
 * @param value_len Value length
 * @return QPACK_OK on success
 */
extern SocketQPACK_Result SocketQPACK_Table_add (SocketQPACK_Table_T table,
                                                 const char *name,
                                                 size_t name_len,
                                                 const char *value,
                                                 size_t value_len);

/**
 * @brief Find entry in dynamic table.
 *
 * @param table     Table instance
 * @param name      Header name to find
 * @param name_len  Name length
 * @param value     Header value (NULL for name-only match)
 * @param value_len Value length
 * @return Positive for exact match (1-based index), negative for name-only
 *         match, 0 if not found
 */
extern int SocketQPACK_Table_find (SocketQPACK_Table_T table,
                                   const char *name,
                                   size_t name_len,
                                   const char *value,
                                   size_t value_len);

/* ============================================================================
 * Static Table Functions (RFC 9204 Appendix A)
 * ============================================================================
 */

/**
 * @brief Get entry from static table by index (0-98).
 *
 * @param index  Static table index
 * @param header Output header data
 * @return QPACK_OK on success, QPACK_ERROR_INVALID_INDEX if out of bounds
 */
extern SocketQPACK_Result
SocketQPACK_static_get (size_t index, SocketQPACK_Header *header);

/**
 * @brief Find entry in static table.
 *
 * @param name      Header name to find
 * @param name_len  Name length
 * @param value     Header value (NULL for name-only match)
 * @param value_len Value length
 * @return Positive index for exact match, negative index for name-only match,
 *         0 if not found
 */
extern int SocketQPACK_static_find (const char *name,
                                    size_t name_len,
                                    const char *value,
                                    size_t value_len);

/* ============================================================================
 * Integer Encoding/Decoding (RFC 9204 Section 5.1)
 * ============================================================================
 */

/**
 * @brief Encode integer with prefix (RFC 9204 Section 5.1).
 *
 * @param value       Value to encode
 * @param prefix_bits Number of prefix bits (1-8)
 * @param output      Output buffer
 * @param output_size Output buffer size
 * @return Bytes written, or 0 on error
 */
extern size_t SocketQPACK_int_encode (uint64_t value,
                                      int prefix_bits,
                                      unsigned char *output,
                                      size_t output_size);

/**
 * @brief Decode integer with prefix (RFC 9204 Section 5.1).
 *
 * @param input       Input buffer
 * @param input_len   Input length
 * @param prefix_bits Number of prefix bits (1-8)
 * @param value       Output value
 * @param consumed    Bytes consumed
 * @return QPACK_OK on success
 */
extern SocketQPACK_Result SocketQPACK_int_decode (const unsigned char *input,
                                                  size_t input_len,
                                                  int prefix_bits,
                                                  uint64_t *value,
                                                  size_t *consumed);

/* ============================================================================
 * Literal Field Line with Name Reference (RFC 9204 Section 4.5.4)
 * ============================================================================
 */

/**
 * @brief Check if byte starts a Literal Field Line with Name Reference.
 *
 * Pattern 01xx xxxx (bits 7-6 = 01) indicates this field line type.
 *
 * @param byte First byte of encoded field line
 * @return 1 if pattern matches, 0 otherwise
 */
extern int SocketQPACK_is_literal_name_ref (unsigned char byte);

/**
 * @brief Encode a Literal Field Line with Name Reference.
 *
 * Encodes a header field using a name from the static or dynamic table
 * with a literal value.
 *
 * @param name_index    Index of name in table
 * @param is_static     1 for static table, 0 for dynamic table
 * @param never_indexed N bit - 1 to prevent caching at intermediaries
 * @param value         Value string to encode
 * @param value_len     Value length
 * @param use_huffman   1 to Huffman-encode value
 * @param output        Output buffer
 * @param output_size   Output buffer size
 * @return Bytes written, or -1 on error
 */
extern ssize_t SocketQPACK_encode_literal_name_ref (uint32_t name_index,
                                                    int is_static,
                                                    int never_indexed,
                                                    const char *value,
                                                    size_t value_len,
                                                    int use_huffman,
                                                    unsigned char *output,
                                                    size_t output_size);

/**
 * @brief Decode a Literal Field Line with Name Reference.
 *
 * Decodes a header field encoded with pattern 01NT.
 *
 * @param input       Input buffer (must start with 01xx xxxx byte)
 * @param input_len   Input length
 * @param field       Output field line structure
 * @param consumed    Bytes consumed
 * @param arena       Memory arena for value allocation
 * @return QPACK_OK on success
 */
extern SocketQPACK_Result
SocketQPACK_decode_literal_name_ref (const unsigned char *input,
                                     size_t input_len,
                                     SocketQPACK_LiteralFieldLine *field,
                                     size_t *consumed,
                                     Arena_T arena);

/**
 * @brief Validate name index against table bounds.
 *
 * @param name_index       Index to validate
 * @param is_static        1 for static table, 0 for dynamic table
 * @param dynamic_count    Number of entries in dynamic table
 * @return QPACK_OK if valid, QPACK_ERROR_INVALID_INDEX otherwise
 */
extern SocketQPACK_Result
SocketQPACK_validate_name_index (uint32_t name_index,
                                 int is_static,
                                 size_t dynamic_count);

/**
 * @brief Resolve name from static or dynamic table.
 *
 * @param name_index    Index in table
 * @param is_static     1 for static table, 0 for dynamic table
 * @param dynamic_table Dynamic table instance (may be NULL if is_static=1)
 * @param header        Output header (only name/name_len populated)
 * @return QPACK_OK on success
 */
extern SocketQPACK_Result
SocketQPACK_resolve_name (uint32_t name_index,
                          int is_static,
                          SocketQPACK_Table_T dynamic_table,
                          SocketQPACK_Header *header);

/* ============================================================================
 * Huffman Encoding/Decoding
 * ============================================================================
 */

/**
 * @brief Huffman encode string (RFC 7541 Appendix B - same as HPACK).
 *
 * @param input       Input string
 * @param input_len   Input length
 * @param output      Output buffer
 * @param output_size Output buffer size
 * @return Bytes written, or -1 on error
 */
extern ssize_t SocketQPACK_huffman_encode (const unsigned char *input,
                                           size_t input_len,
                                           unsigned char *output,
                                           size_t output_size);

/**
 * @brief Huffman decode string.
 *
 * @param input       Input buffer
 * @param input_len   Input length
 * @param output      Output buffer
 * @param output_size Output buffer size
 * @return Bytes decoded, or -1 on error
 */
extern ssize_t SocketQPACK_huffman_decode (const unsigned char *input,
                                           size_t input_len,
                                           unsigned char *output,
                                           size_t output_size);

/**
 * @brief Calculate Huffman encoded size.
 *
 * @param input     Input string
 * @param input_len Input length
 * @return Encoded size in bytes
 */
extern size_t
SocketQPACK_huffman_encoded_size (const unsigned char *input, size_t input_len);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Get human-readable string for result code.
 *
 * @param result Result code
 * @return String description
 */
extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/** @} */

#endif /* SOCKETQPACK_INCLUDED */

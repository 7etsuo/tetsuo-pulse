/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK.h
 * @brief QPACK header compression for HTTP/3 (RFC 9204).
 *
 * Implements QPACK algorithm with static table (99 entries), dynamic table
 * (ring buffer), and Huffman encoding. Based on HPACK but with out-of-order
 * delivery support for QUIC streams.
 *
 * Thread Safety: Encoder/decoder instances are NOT thread-safe. One instance
 * per connection recommended.
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
 * Constants (RFC 9204)
 * ============================================================================
 */

/** Default dynamic table size (RFC 9204) */
#ifndef SOCKETQPACK_DEFAULT_TABLE_SIZE
#define SOCKETQPACK_DEFAULT_TABLE_SIZE 4096
#endif

/** Maximum dynamic table size */
#ifndef SOCKETQPACK_MAX_TABLE_SIZE
#define SOCKETQPACK_MAX_TABLE_SIZE (64 * 1024)
#endif

/** Maximum header size */
#ifndef SOCKETQPACK_MAX_HEADER_SIZE
#define SOCKETQPACK_MAX_HEADER_SIZE (8 * 1024)
#endif

/** Maximum header list size */
#ifndef SOCKETQPACK_MAX_HEADER_LIST_SIZE
#define SOCKETQPACK_MAX_HEADER_LIST_SIZE (64 * 1024)
#endif

/** Static table size (RFC 9204 Appendix A) */
#define SOCKETQPACK_STATIC_TABLE_SIZE 99

/** Entry overhead per dynamic table entry (name_len + value_len + 32) */
#define SOCKETQPACK_ENTRY_OVERHEAD 32

/* ============================================================================
 * Exception
 * ============================================================================
 */

/** Exception raised on QPACK errors */
extern const Except_T SocketQPACK_Error;

/* ============================================================================
 * Result Codes
 * ============================================================================
 */

typedef enum
{
  QPACK_OK = 0,
  QPACK_INCOMPLETE,
  QPACK_ERROR,
  QPACK_ERROR_INVALID_INDEX,
  QPACK_ERROR_HUFFMAN,
  QPACK_ERROR_INTEGER,
  QPACK_ERROR_TABLE_SIZE,
  QPACK_ERROR_HEADER_SIZE,
  QPACK_ERROR_LIST_SIZE,
  QPACK_ERROR_BOMB,
  QPACK_ERROR_DECOMPRESSION_FAILED
} SocketQPACK_Result;

/* ============================================================================
 * Data Structures
 * ============================================================================
 */

/**
 * @brief QPACK header structure
 */
typedef struct
{
  const char *name;
  size_t name_len;
  const char *value;
  size_t value_len;
  int never_index;
} SocketQPACK_Header;

/**
 * @brief Insert with Literal Name instruction (RFC 9204 Section 4.3.3)
 *
 * Used when the header name is not in the static table and must be
 * encoded as a literal string.
 */
typedef struct
{
  const unsigned char *name;
  size_t name_len;
  const unsigned char *value;
  size_t value_len;
  int name_huffman;  /**< Use Huffman encoding for name */
  int value_huffman; /**< Use Huffman encoding for value */
} SocketQPACK_InsertLiteralInstruction;

/* ============================================================================
 * Dynamic Table
 * ============================================================================
 */

typedef struct SocketQPACK_DynamicTable *SocketQPACK_DynamicTable_T;

/**
 * @brief Create a new QPACK dynamic table.
 *
 * @param max_size Maximum table size in bytes
 * @param arena    Memory arena for allocations
 * @return New dynamic table instance
 */
extern SocketQPACK_DynamicTable_T
SocketQPACK_DynamicTable_new (size_t max_size, Arena_T arena);

/**
 * @brief Free dynamic table resources.
 *
 * @param table Pointer to table (set to NULL after)
 */
extern void SocketQPACK_DynamicTable_free (SocketQPACK_DynamicTable_T *table);

/**
 * @brief Insert a header into the dynamic table.
 *
 * @param table     Dynamic table
 * @param name      Header name
 * @param name_len  Name length
 * @param value     Header value
 * @param value_len Value length
 * @return QPACK_OK on success, error code otherwise
 */
extern SocketQPACK_Result
SocketQPACK_DynamicTable_insert (SocketQPACK_DynamicTable_T table,
                                 const char *name,
                                 size_t name_len,
                                 const char *value,
                                 size_t value_len);

/**
 * @brief Get entry by absolute index.
 *
 * @param table  Dynamic table
 * @param index  Absolute index (0 = first inserted)
 * @param header Output header structure
 * @return QPACK_OK on success, error code otherwise
 */
extern SocketQPACK_Result
SocketQPACK_DynamicTable_get (SocketQPACK_DynamicTable_T table,
                              size_t index,
                              SocketQPACK_Header *header);

/**
 * @brief Get current table size in bytes.
 */
extern size_t SocketQPACK_DynamicTable_size (SocketQPACK_DynamicTable_T table);

/**
 * @brief Get number of entries in table.
 */
extern size_t SocketQPACK_DynamicTable_count (SocketQPACK_DynamicTable_T table);

/**
 * @brief Get maximum table size.
 */
extern size_t
SocketQPACK_DynamicTable_max_size (SocketQPACK_DynamicTable_T table);

/**
 * @brief Set maximum table size (may trigger evictions).
 */
extern void
SocketQPACK_DynamicTable_set_max_size (SocketQPACK_DynamicTable_T table,
                                       size_t max_size);

/**
 * @brief Get the insert count (number of entries ever inserted).
 *
 * Used for tracking required insert count in QPACK.
 */
extern size_t
SocketQPACK_DynamicTable_insert_count (SocketQPACK_DynamicTable_T table);

/* ============================================================================
 * Integer Encoding/Decoding (RFC 9204 Section 4.1.1)
 * ============================================================================
 */

/**
 * @brief Encode integer with prefix.
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
 * @brief Decode integer with prefix.
 *
 * @param input       Input buffer
 * @param input_len   Input buffer length
 * @param prefix_bits Number of prefix bits (1-8)
 * @param value       Output value
 * @param consumed    Bytes consumed
 * @return QPACK_OK on success, error code otherwise
 */
extern SocketQPACK_Result SocketQPACK_int_decode (const unsigned char *input,
                                                  size_t input_len,
                                                  int prefix_bits,
                                                  uint64_t *value,
                                                  size_t *consumed);

/* ============================================================================
 * String Encoding/Decoding (RFC 9204 Section 4.1.2)
 * ============================================================================
 */

/**
 * @brief Encode string with optional Huffman compression.
 *
 * @param str         String to encode
 * @param len         String length
 * @param prefix_bits Number of prefix bits for length (5 or 7)
 * @param use_huffman Enable Huffman compression
 * @param output      Output buffer
 * @param output_size Output buffer size
 * @return Bytes written, or -1 on error
 */
extern ssize_t SocketQPACK_string_encode (const char *str,
                                          size_t len,
                                          int prefix_bits,
                                          int use_huffman,
                                          unsigned char *output,
                                          size_t output_size);

/**
 * @brief Decode string (with optional Huffman).
 *
 * @param input       Input buffer
 * @param input_len   Input buffer length
 * @param prefix_bits Number of prefix bits for length
 * @param str_out     Output string (allocated from arena)
 * @param str_len_out Output string length
 * @param consumed    Bytes consumed
 * @param arena       Memory arena for allocation
 * @return QPACK_OK on success, error code otherwise
 */
extern SocketQPACK_Result SocketQPACK_string_decode (const unsigned char *input,
                                                     size_t input_len,
                                                     int prefix_bits,
                                                     char **str_out,
                                                     size_t *str_len_out,
                                                     size_t *consumed,
                                                     Arena_T arena);

/* ============================================================================
 * Encoder Stream Instructions (RFC 9204 Section 4.3)
 * ============================================================================
 */

/**
 * @brief Encode "Insert with Literal Name" instruction (RFC 9204 Section
 * 4.3.3).
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 1 | H | Name Length (5+)  |
 * +---+---+---+---+---+---+---+---+
 * |  Name String (Length bytes)   |
 * +---+---------------------------+
 * | H |     Value Length (7+)     |
 * +---+---------------------------+
 * |  Value String (Length bytes)  |
 * +-------------------------------+
 *
 * @param instr       Instruction parameters
 * @param output      Output buffer
 * @param output_size Output buffer size
 * @return Bytes written, or -1 on error
 */
extern ssize_t SocketQPACK_encode_insert_literal_name (
    const SocketQPACK_InsertLiteralInstruction *instr,
    unsigned char *output,
    size_t output_size);

/**
 * @brief Decode "Insert with Literal Name" instruction.
 *
 * @param input       Input buffer (starting at instruction)
 * @param input_len   Input buffer length
 * @param name_out    Output name string
 * @param name_len    Output name length
 * @param value_out   Output value string
 * @param value_len   Output value length
 * @param consumed    Bytes consumed
 * @param arena       Memory arena for string allocation
 * @return QPACK_OK on success, error code otherwise
 */
extern SocketQPACK_Result
SocketQPACK_decode_insert_literal_name (const unsigned char *input,
                                        size_t input_len,
                                        char **name_out,
                                        size_t *name_len,
                                        char **value_out,
                                        size_t *value_len,
                                        size_t *consumed,
                                        Arena_T arena);

/**
 * @brief Process "Insert with Literal Name" and add to dynamic table.
 *
 * This is a convenience function that decodes the instruction and
 * inserts the result into the dynamic table.
 *
 * @param table       Dynamic table
 * @param input       Input buffer
 * @param input_len   Input buffer length
 * @param consumed    Bytes consumed
 * @param arena       Memory arena
 * @return QPACK_OK on success, error code otherwise
 */
extern SocketQPACK_Result
SocketQPACK_process_insert_literal_name (SocketQPACK_DynamicTable_T table,
                                         const unsigned char *input,
                                         size_t input_len,
                                         size_t *consumed,
                                         Arena_T arena);

/* ============================================================================
 * Static Table (RFC 9204 Appendix A)
 * ============================================================================
 */

/**
 * @brief Get entry from static table by index (0-98).
 *
 * @param index  Static table index (0-based)
 * @param header Output header structure
 * @return QPACK_OK on success, QPACK_ERROR_INVALID_INDEX if out of range
 */
extern SocketQPACK_Result
SocketQPACK_static_get (size_t index, SocketQPACK_Header *header);

/**
 * @brief Find entry in static table.
 *
 * @param name      Header name
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
 * Huffman Encoding/Decoding (RFC 9204 Section 4.1.2)
 * ============================================================================
 */

/**
 * @brief Huffman encode string.
 *
 * Uses the same Huffman table as HPACK (RFC 7541 Appendix B).
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
 * @param input       Input (Huffman-encoded)
 * @param input_len   Input length
 * @param output      Output buffer
 * @param output_size Output buffer size
 * @return Bytes written, or -1 on error
 */
extern ssize_t SocketQPACK_huffman_decode (const unsigned char *input,
                                           size_t input_len,
                                           unsigned char *output,
                                           size_t output_size);

/**
 * @brief Calculate Huffman-encoded size for a string.
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
 * @brief Get string description of result code.
 */
extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/** @} */

#endif /* SOCKETQPACK_INCLUDED */

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK.h
 * @brief QPACK header compression for HTTP/3 (RFC 9204).
 *
 * Implements QPACK algorithm with static table (99 entries), dynamic table,
 * encoder stream instructions, and decoder stream acknowledgments.
 * This initial implementation covers the Duplicate instruction (Section 4.3.4).
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

/** Default dynamic table capacity in bytes (RFC 9204 recommends 0 initially).
 */
#ifndef SOCKETQPACK_DEFAULT_TABLE_CAPACITY
#define SOCKETQPACK_DEFAULT_TABLE_CAPACITY 4096
#endif

/** Maximum dynamic table capacity in bytes. */
#ifndef SOCKETQPACK_MAX_TABLE_CAPACITY
#define SOCKETQPACK_MAX_TABLE_CAPACITY (64 * 1024)
#endif

/** Maximum allowed blocked streams (RFC 9204 transport parameter). */
#ifndef SOCKETQPACK_MAX_BLOCKED_STREAMS
#define SOCKETQPACK_MAX_BLOCKED_STREAMS 100
#endif

/** Entry overhead: 32 bytes per RFC 9204 Section 3.2.1. */
#define SOCKETQPACK_ENTRY_OVERHEAD 32

/** Number of entries in the QPACK static table (RFC 9204 Appendix A). */
#define SOCKETQPACK_STATIC_TABLE_SIZE 99

/* ============================================================================
 * Wire Format Constants (RFC 9204 Section 4.3)
 * ============================================================================
 */

/** Duplicate instruction pattern: 000xxxxx (Section 4.3.4). */
#define QPACK_DUPLICATE_PATTERN 0x00

/** Duplicate instruction prefix bits for relative index. */
#define QPACK_DUPLICATE_PREFIX 5

/** Mask for duplicate instruction detection (top 3 bits). */
#define QPACK_DUPLICATE_MASK 0xE0

/* ============================================================================
 * Exception and Result Types
 * ============================================================================
 */

/** Exception raised on QPACK encoding/decoding errors. */
extern const Except_T SocketQPACK_Error;

/**
 * @brief Result codes for QPACK operations.
 */
typedef enum
{
  QPACK_OK = 0,               /**< Operation succeeded */
  QPACK_INCOMPLETE,           /**< Need more input data */
  QPACK_ERROR,                /**< Generic error */
  QPACK_ERROR_INVALID_INDEX,  /**< Relative index out of bounds */
  QPACK_ERROR_TABLE_FULL,     /**< Dynamic table capacity exhausted */
  QPACK_ERROR_PARSE,          /**< Malformed wire format */
  QPACK_ERROR_ENCODER_STREAM, /**< Encoder stream error */
  QPACK_ERROR_DECODER_STREAM  /**< Decoder stream error */
} SocketQPACK_Result;

/* ============================================================================
 * Data Structures
 * ============================================================================
 */

/**
 * @brief Field line (name-value pair) as stored in tables.
 */
typedef struct
{
  const char *name;  /**< Header field name. */
  size_t name_len;   /**< Length of name in bytes. */
  const char *value; /**< Header field value. */
  size_t value_len;  /**< Length of value in bytes. */
  int never_index;   /**< Never-indexed flag. */
} SocketQPACK_FieldLine;

/**
 * @brief Dynamic table entry with absolute index tracking.
 */
typedef struct QPACK_DynamicEntry
{
  char *name;       /**< Allocated field name. */
  size_t name_len;  /**< Length of name. */
  char *value;      /**< Allocated field value. */
  size_t value_len; /**< Length of value. */
  size_t abs_index; /**< Absolute index assigned at insertion. */
} QPACK_DynamicEntry;

/** Forward declaration for dynamic table. */
typedef struct SocketQPACK_Table *SocketQPACK_Table_T;

/* ============================================================================
 * Dynamic Table API
 * ============================================================================
 */

/**
 * @brief Create a new QPACK dynamic table.
 *
 * @param max_capacity  Maximum table capacity in bytes.
 * @param arena         Arena for memory allocation.
 *
 * @return New table instance.
 * @raises SocketQPACK_Error on allocation failure.
 */
extern SocketQPACK_Table_T
SocketQPACK_Table_new (size_t max_capacity, Arena_T arena);

/**
 * @brief Free a dynamic table (sets pointer to NULL).
 *
 * @param table  Pointer to table to free.
 */
extern void SocketQPACK_Table_free (SocketQPACK_Table_T *table);

/**
 * @brief Get current table size in bytes.
 *
 * @param table  Table instance.
 * @return Current size (sum of entry sizes with overhead).
 */
extern size_t SocketQPACK_Table_size (SocketQPACK_Table_T table);

/**
 * @brief Get current entry count.
 *
 * @param table  Table instance.
 * @return Number of entries in table.
 */
extern size_t SocketQPACK_Table_count (SocketQPACK_Table_T table);

/**
 * @brief Get maximum table capacity.
 *
 * @param table  Table instance.
 * @return Maximum capacity in bytes.
 */
extern size_t SocketQPACK_Table_max_capacity (SocketQPACK_Table_T table);

/**
 * @brief Get the current insertion count (absolute index for next entry).
 *
 * @param table  Table instance.
 * @return Number of entries ever inserted (used for absolute indexing).
 */
extern size_t SocketQPACK_Table_insertion_count (SocketQPACK_Table_T table);

/**
 * @brief Update maximum table capacity.
 *
 * Evicts oldest entries if new capacity is smaller.
 *
 * @param table         Table instance.
 * @param max_capacity  New maximum capacity in bytes.
 */
extern void
SocketQPACK_Table_set_capacity (SocketQPACK_Table_T table, size_t max_capacity);

/**
 * @brief Get entry by relative index (RFC 9204 Section 3.2.4).
 *
 * Relative index 0 = newest entry, higher = older toward eviction.
 *
 * @param table       Table instance.
 * @param rel_index   Relative index (0 = newest).
 * @param field_line  Output: field line data (pointers into table).
 *
 * @return QPACK_OK on success, QPACK_ERROR_INVALID_INDEX if out of bounds.
 */
extern SocketQPACK_Result
SocketQPACK_Table_get (SocketQPACK_Table_T table,
                       size_t rel_index,
                       SocketQPACK_FieldLine *field_line);

/**
 * @brief Add entry to table (RFC 9204 Section 3.2.2).
 *
 * Evicts oldest entries if needed to fit. Entry is assigned the next
 * absolute index. If entry is larger than capacity, table is cleared.
 *
 * @param table      Table instance.
 * @param name       Field name.
 * @param name_len   Length of name.
 * @param value      Field value.
 * @param value_len  Length of value.
 *
 * @return QPACK_OK on success, QPACK_ERROR on allocation failure.
 */
extern SocketQPACK_Result SocketQPACK_Table_add (SocketQPACK_Table_T table,
                                                 const char *name,
                                                 size_t name_len,
                                                 const char *value,
                                                 size_t value_len);

/* ============================================================================
 * Duplicate Instruction API (RFC 9204 Section 4.3.4)
 * ============================================================================
 */

/**
 * @brief Encode a duplicate instruction.
 *
 * Encodes the 3-bit pattern (000) followed by 5-bit prefix relative index.
 *
 * @param rel_index    Relative index of entry to duplicate (0 = newest).
 * @param output       Output buffer for encoded instruction.
 * @param output_size  Size of output buffer.
 *
 * @return Number of bytes written, or 0 on error (buffer too small).
 */
extern size_t SocketQPACK_encode_duplicate (size_t rel_index,
                                            uint8_t *output,
                                            size_t output_size);

/**
 * @brief Decode a duplicate instruction.
 *
 * Parses the 5-bit prefix integer encoding for relative index.
 *
 * @param input      Input buffer containing encoded instruction.
 * @param input_len  Length of input buffer.
 * @param rel_index  Output: decoded relative index.
 * @param consumed   Output: bytes consumed from input.
 *
 * @return QPACK_OK on success, error code otherwise.
 */
extern SocketQPACK_Result SocketQPACK_decode_duplicate (const uint8_t *input,
                                                        size_t input_len,
                                                        size_t *rel_index,
                                                        size_t *consumed);

/**
 * @brief Process a duplicate instruction on the dynamic table.
 *
 * Retrieves the entry at relative index, copies it, and inserts the copy
 * at the end of the table with a new absolute index.
 *
 * @param table      Dynamic table to operate on.
 * @param rel_index  Relative index of entry to duplicate (0 = newest).
 *
 * @return QPACK_OK on success, error code otherwise.
 *   - QPACK_ERROR_INVALID_INDEX: relative index >= table count
 *   - QPACK_ERROR: allocation or insertion failure
 */
extern SocketQPACK_Result
SocketQPACK_process_duplicate (SocketQPACK_Table_T table, size_t rel_index);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Calculate entry size with overhead (RFC 9204 Section 3.2.1).
 *
 * @param name_len   Length of field name.
 * @param value_len  Length of field value.
 *
 * @return Entry size = name_len + value_len + 32, or SIZE_MAX on overflow.
 */
extern size_t SocketQPACK_entry_size (size_t name_len, size_t value_len);

/**
 * @brief Get string representation of result code.
 *
 * @param result  Result code to convert.
 * @return Human-readable string describing the result.
 */
extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/* ============================================================================
 * Integer Encoding (RFC 9204 Section 4.1.1, derived from HPACK RFC 7541)
 * ============================================================================
 */

/**
 * @brief Encode integer with N-bit prefix (RFC 7541 Section 5.1).
 *
 * @param value        Value to encode.
 * @param prefix_bits  Number of bits in prefix (1-8).
 * @param output       Output buffer.
 * @param output_size  Size of output buffer.
 *
 * @return Number of bytes written, or 0 on error.
 */
extern size_t SocketQPACK_int_encode (uint64_t value,
                                      int prefix_bits,
                                      uint8_t *output,
                                      size_t output_size);

/**
 * @brief Decode integer with N-bit prefix (RFC 7541 Section 5.1).
 *
 * @param input        Input buffer.
 * @param input_len    Length of input buffer.
 * @param prefix_bits  Number of bits in prefix (1-8).
 * @param value        Output: decoded value.
 * @param consumed     Output: bytes consumed.
 *
 * @return QPACK_OK on success, error code otherwise.
 */
extern SocketQPACK_Result SocketQPACK_int_decode (const uint8_t *input,
                                                  size_t input_len,
                                                  int prefix_bits,
                                                  uint64_t *value,
                                                  size_t *consumed);

/** @} */

#endif /* SOCKETQPACK_INCLUDED */

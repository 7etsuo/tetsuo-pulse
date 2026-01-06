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
 * (FIFO eviction), and encoder/decoder instructions. QPACK is designed for
 * HTTP/3 over QUIC, addressing the head-of-line blocking issues of HPACK.
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
 * Constants (RFC 9204)
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

/** QPACK static table size (RFC 9204 Appendix A) */
#define SOCKETQPACK_STATIC_TABLE_SIZE 99

/** Entry overhead per RFC 9204 Section 3.2.1 (same as HPACK: 32 bytes) */
#define SOCKETQPACK_ENTRY_OVERHEAD 32

/* ============================================================================
 * Error Codes
 * ============================================================================
 */

extern const Except_T SocketQPACK_Error;

/**
 * @brief QPACK operation result codes.
 *
 * Error codes for QPACK operations. RFC 9204 defines specific error types
 * for encoder stream and decoder stream operations.
 */
typedef enum
{
  QPACK_OK = 0,               /**< Operation succeeded */
  QPACK_INCOMPLETE,           /**< Need more data */
  QPACK_ERROR,                /**< Generic error */
  QPACK_ERROR_INVALID_INDEX,  /**< Invalid table index */
  QPACK_ERROR_HUFFMAN,        /**< Huffman decoding error */
  QPACK_ERROR_INTEGER,        /**< Integer overflow */
  QPACK_ERROR_TABLE_SIZE,     /**< Invalid dynamic table size */
  QPACK_ERROR_HEADER_SIZE,    /**< Header too large */
  QPACK_ERROR_LIST_SIZE,      /**< Header list too large */
  QPACK_ERROR_NOT_FOUND,      /**< Entry not found in static table */
  QPACK_ENCODER_STREAM_ERROR, /**< RFC 9204 Section 4.3 error */
  QPACK_DECODER_STREAM_ERROR, /**< RFC 9204 Section 4.4 error */
  QPACK_DECOMPRESSION_FAILED  /**< Decompression failed */
} SocketQPACK_Result;

/* ============================================================================
 * Encoder Instruction Types (RFC 9204 Section 4.3)
 * ============================================================================
 */

/**
 * @brief QPACK encoder instruction types (RFC 9204 Section 4.3).
 *
 * Encoder instructions are sent on the encoder stream to update the
 * decoder's dynamic table state.
 */
typedef enum
{
  /** Insert with name reference (Section 4.3.2) - pattern 1xxxxxxx */
  QPACK_INSTR_INSERT_REF_NAME,
  /** Insert with literal name (Section 4.3.3) - pattern 01xxxxxx */
  QPACK_INSTR_INSERT_LITERAL_NAME,
  /** Duplicate (Section 4.3.4) - pattern 000xxxxx */
  QPACK_INSTR_DUPLICATE,
  /** Set Dynamic Table Capacity (Section 4.3.1) - pattern 001xxxxx */
  QPACK_INSTR_SET_CAPACITY
} QPACK_InstructionType;

/**
 * @brief QPACK encoder instruction representation.
 *
 * Union type for all encoder instruction data. The instruction type
 * field determines which union member contains valid data.
 */
typedef struct
{
  QPACK_InstructionType type; /**< Instruction type */
  union
  {
    struct
    {
      size_t capacity; /**< New capacity value */
    } set_capacity;    /**< Set Dynamic Table Capacity data */

    struct
    {
      size_t name_index; /**< Name reference index */
      int is_static;     /**< True if referencing static table */
      const char *value; /**< Header value */
      size_t value_len;  /**< Header value length */
    } insert_ref_name;   /**< Insert with Name Reference data */

    struct
    {
      const char *name;    /**< Header name */
      size_t name_len;     /**< Header name length */
      const char *value;   /**< Header value */
      size_t value_len;    /**< Header value length */
    } insert_literal_name; /**< Insert with Literal Name data */

    struct
    {
      size_t index; /**< Index to duplicate */
    } duplicate;    /**< Duplicate data */
  } data;
} QPACK_Instruction;

/* ============================================================================
 * Dynamic Table (RFC 9204 Section 3.2)
 * ============================================================================
 */

typedef struct SocketQPACK_Table *SocketQPACK_Table_T;

/**
 * @brief Create a new QPACK dynamic table.
 *
 * Creates a dynamic table with the specified maximum capacity for use with
 * QPACK encoding/decoding. The table uses a circular buffer internally with
 * FIFO eviction when capacity is exceeded.
 *
 * @param max_size Maximum table capacity in bytes.
 * @param arena Arena for memory allocation.
 * @return New table instance.
 * @throws SocketQPACK_Error if allocation fails.
 */
extern SocketQPACK_Table_T
SocketQPACK_Table_new (size_t max_size, Arena_T arena);

/**
 * @brief Free a QPACK dynamic table.
 *
 * @param table Pointer to table to free. Set to NULL on return.
 */
extern void SocketQPACK_Table_free (SocketQPACK_Table_T *table);

/**
 * @brief Set the maximum capacity of the dynamic table.
 *
 * Updates the table capacity and evicts entries if necessary. This function
 * implements the Set Dynamic Table Capacity instruction (RFC 9204 Section
 * 4.3.1) when applied after decoding.
 *
 * @param table The dynamic table.
 * @param max_size New maximum capacity in bytes.
 */
extern void
SocketQPACK_Table_set_max_size (SocketQPACK_Table_T table, size_t max_size);

/**
 * @brief Get current size of the dynamic table.
 *
 * @param table The dynamic table.
 * @return Current size in bytes.
 */
extern size_t SocketQPACK_Table_size (SocketQPACK_Table_T table);

/**
 * @brief Get entry count in the dynamic table.
 *
 * @param table The dynamic table.
 * @return Number of entries.
 */
extern size_t SocketQPACK_Table_count (SocketQPACK_Table_T table);

/**
 * @brief Get maximum capacity of the dynamic table.
 *
 * @param table The dynamic table.
 * @return Maximum capacity in bytes.
 */
extern size_t SocketQPACK_Table_max_size (SocketQPACK_Table_T table);

/* ============================================================================
 * Set Dynamic Table Capacity (RFC 9204 Section 4.3.1)
 * ============================================================================
 */

/**
 * @brief Encode a Set Dynamic Table Capacity instruction.
 *
 * Encodes the Set Capacity instruction to wire format per RFC 9204 Section
 * 4.3.1. The instruction uses the 3-bit pattern 001 (0x20 mask) with a 5-bit
 * prefix integer for the capacity value.
 *
 * Wire format:
 * @code
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 | 1 |   Capacity (5+)   |
 * +---+---+---+-------------------+
 * @endcode
 *
 * @param capacity The new capacity value to encode.
 * @param output Output buffer for encoded instruction.
 * @param output_size Size of output buffer.
 * @return Number of bytes written, or 0 on error.
 *
 * @note This function does NOT validate against maximum capacity - that
 *       validation happens when the instruction is applied. The encoder
 *       should ensure it doesn't send values exceeding negotiated limits.
 */
extern size_t SocketQPACK_encode_set_capacity (size_t capacity,
                                               unsigned char *output,
                                               size_t output_size);

/**
 * @brief Decode a Set Dynamic Table Capacity instruction.
 *
 * Decodes the Set Capacity instruction from wire format per RFC 9204 Section
 * 4.3.1. The first byte must have the pattern 001 (checked via 0xE0 mask
 * yielding 0x20).
 *
 * @param input Input buffer containing the encoded instruction.
 * @param input_len Length of input buffer.
 * @param capacity Output: decoded capacity value.
 * @param consumed Output: number of bytes consumed from input.
 * @return QPACK_OK on success, QPACK_INCOMPLETE if more data needed,
 *         or error code on failure.
 *
 * @note This function only decodes - use SocketQPACK_apply_set_capacity()
 *       to apply the decoded value to a dynamic table.
 */
extern SocketQPACK_Result
SocketQPACK_decode_set_capacity (const unsigned char *input,
                                 size_t input_len,
                                 size_t *capacity,
                                 size_t *consumed);

/**
 * @brief Apply a Set Dynamic Table Capacity instruction to a table.
 *
 * Validates and applies a capacity change to the dynamic table per RFC 9204
 * Section 4.3.1. If the new capacity is less than the current table size,
 * entries are evicted until the size fits. Zero capacity clears all entries.
 *
 * @param table The dynamic table to update.
 * @param capacity The new capacity value.
 * @param max_capacity The maximum allowed capacity (from transport params).
 * @return QPACK_OK on success, QPACK_ENCODER_STREAM_ERROR if capacity
 *         exceeds maximum.
 */
extern SocketQPACK_Result
SocketQPACK_apply_set_capacity (SocketQPACK_Table_T table,
                                size_t capacity,
                                size_t max_capacity);

/* ============================================================================
 * Integer Encoding/Decoding (RFC 7541 Section 5.1, used by QPACK)
 * ============================================================================
 */

/**
 * @brief Encode integer with prefix (RFC 7541 Section 5.1).
 *
 * QPACK uses the same integer encoding as HPACK. The value is encoded
 * starting with prefix_bits of data in the first byte.
 *
 * @param value Value to encode.
 * @param prefix_bits Number of bits in first byte (1-8).
 * @param output Output buffer.
 * @param output_size Output buffer size.
 * @return Number of bytes written, or 0 on error.
 */
extern size_t SocketQPACK_int_encode (uint64_t value,
                                      int prefix_bits,
                                      unsigned char *output,
                                      size_t output_size);

/**
 * @brief Decode integer with prefix (RFC 7541 Section 5.1).
 *
 * @param input Input buffer.
 * @param input_len Input buffer length.
 * @param prefix_bits Number of bits in first byte (1-8).
 * @param value Output: decoded value.
 * @param consumed Output: bytes consumed.
 * @return QPACK_OK on success, QPACK_INCOMPLETE if more data needed,
 *         QPACK_ERROR_INTEGER on overflow.
 */
extern SocketQPACK_Result SocketQPACK_int_decode (const unsigned char *input,
                                                  size_t input_len,
                                                  int prefix_bits,
                                                  uint64_t *value,
                                                  size_t *consumed);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Get string description of result code.
 *
 * @param result Result code.
 * @return Static string describing the result.
 */
extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/* ============================================================================
 * Static Table (RFC 9204 Section 3.1, Appendix A)
 * ============================================================================
 */

/**
 * @brief Get static table entry by index.
 *
 * Retrieves the name and value for the given static table index.
 * RFC 9204 Appendix A defines 99 entries (indices 0-98).
 *
 * @param index     Static table index (0-98).
 * @param[out] name Output: pointer to entry name (not NUL-terminated).
 * @param[out] name_len Output: length of entry name.
 * @param[out] value Output: pointer to entry value (not NUL-terminated).
 * @param[out] value_len Output: length of entry value.
 * @return QPACK_OK on success,
 *         QPACK_ERROR_INVALID_INDEX if index >= 99,
 *         QPACK_ERROR if any output pointer is NULL.
 *
 * @note Thread-safe: Static table is read-only.
 * @note Strings point to static memory; do not free.
 */
extern SocketQPACK_Result SocketQPACK_static_get (size_t index,
                                                  const char **name,
                                                  size_t *name_len,
                                                  const char **value,
                                                  size_t *value_len);

/**
 * @brief Find static table entry by name and value.
 *
 * Searches the static table for an entry matching the given name and value.
 * Name comparison is case-insensitive per RFC 7230 Section 3.2.
 *
 * @param name      Header name to search for.
 * @param name_len  Length of name.
 * @param value     Header value to search for.
 * @param value_len Length of value.
 * @param[out] index Output: index of matching entry (0-98).
 * @return QPACK_OK on exact match found,
 *         QPACK_ERROR_NOT_FOUND if no match,
 *         QPACK_ERROR if name or index is NULL.
 *
 * @note Thread-safe: Static table is read-only.
 */
extern SocketQPACK_Result SocketQPACK_static_find (const char *name,
                                                   size_t name_len,
                                                   const char *value,
                                                   size_t value_len,
                                                   size_t *index);

/**
 * @brief Find static table entry by name only.
 *
 * Searches the static table for an entry matching the given header name.
 * Returns the first matching entry. Name comparison is case-insensitive
 * per RFC 7230 Section 3.2.
 *
 * @param name      Header name to search for.
 * @param name_len  Length of name.
 * @param[out] index Output: index of first matching entry (0-98).
 * @return QPACK_OK if name found,
 *         QPACK_ERROR_NOT_FOUND if no match,
 *         QPACK_ERROR if name or index is NULL.
 *
 * @note Thread-safe: Static table is read-only.
 */
extern SocketQPACK_Result SocketQPACK_static_find_name (const char *name,
                                                        size_t name_len,
                                                        size_t *index);

/**
 * @brief Get name length for static table entry.
 *
 * @param index Static table index (0-98).
 * @return Name length, or 0 if index is invalid.
 *
 * @note Thread-safe: Static table is read-only.
 */
extern size_t SocketQPACK_static_name_len (size_t index);

/**
 * @brief Get value length for static table entry.
 *
 * @param index Static table index (0-98).
 * @return Value length, or 0 if index is invalid.
 *
 * @note Thread-safe: Static table is read-only.
 */
extern size_t SocketQPACK_static_value_len (size_t index);

/** @} */

#endif /* SOCKETQPACK_INCLUDED */

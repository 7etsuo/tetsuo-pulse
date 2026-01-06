/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK.h
 * @brief QPACK field compression for HTTP/3 (RFC 9204).
 *
 * Implements QPACK algorithm with static table (99 entries), dynamic table
 * with out-of-order delivery support, and Huffman encoding. Uses 0-based
 * indexing (unlike HPACK's 1-based indexing).
 *
 * Thread Safety: Encoder/decoder instances are NOT thread-safe. One instance
 * per connection/thread recommended. Static table functions are thread-safe.
 *
 * @defgroup qpack QPACK Field Compression Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9204
 */

#ifndef SOCKETQPACK_INCLUDED
#define SOCKETQPACK_INCLUDED

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Number of entries in the QPACK static table.
 *
 * RFC 9204 Section 3.1 and Appendix A define exactly 99 predefined field line
 * entries with indices 0-98.
 */
#define SOCKETQPACK_STATIC_TABLE_SIZE 99

/**
 * @brief QPACK entry overhead (per RFC 9204 Section 3.2.1).
 *
 * Each entry has an overhead of 32 bytes for the entry structure,
 * in addition to the name and value lengths.
 */
#define SOCKETQPACK_ENTRY_OVERHEAD 32

/**
 * @brief Result codes for QPACK operations.
 */
typedef enum
{
  SOCKETQPACK_OK = 0,              /**< Operation succeeded */
  SOCKETQPACK_ERROR_INVALID_INDEX, /**< Index out of valid range */
  SOCKETQPACK_ERROR_NOT_FOUND      /**< No matching entry found */
} SocketQPACK_Result;

/**
 * @brief Static table entry structure.
 *
 * Contains the field name and value with precomputed lengths for efficient
 * lookup. All entries are immutable and have fixed indices per RFC 9204.
 */
typedef struct
{
  const char *name;  /**< Field name (case-insensitive per RFC 7230) */
  size_t name_len;   /**< Length of name string */
  const char *value; /**< Field value (may be empty string) */
  size_t value_len;  /**< Length of value string */
} SocketQPACK_StaticEntry;

/**
 * @brief Retrieve a static table entry by 0-based index.
 *
 * RFC 9204 Section 3.1: Static table uses 0-based indexing with 99 entries
 * (indices 0-98). The entries are predefined and immutable.
 *
 * @param index     0-based index into static table (0-98 valid)
 * @param entry_out Output pointer to receive the entry (must not be NULL)
 * @return SOCKETQPACK_OK on success
 * @return SOCKETQPACK_ERROR_INVALID_INDEX if index >= 99 or entry_out is NULL
 */
extern SocketQPACK_Result
SocketQPACK_static_get (size_t index, SocketQPACK_StaticEntry *entry_out);

/**
 * @brief Find static table entry matching name and value.
 *
 * Searches the static table for an entry with matching field name and value.
 * Name comparison is case-insensitive per RFC 7230.
 *
 * @param name      Field name to match
 * @param name_len  Length of name
 * @param value     Field value to match (NULL to match name only)
 * @param value_len Length of value (ignored if value is NULL)
 * @return Index of matching entry (0-98) on exact match
 * @return -1 if no match found
 *
 * @note For name-only matching, pass NULL for value parameter.
 */
extern int SocketQPACK_static_find (const char *name,
                                    size_t name_len,
                                    const char *value,
                                    size_t value_len);

/**
 * @brief Find static table entry matching name only.
 *
 * Searches the static table for the first entry with matching field name.
 * Name comparison is case-insensitive per RFC 7230.
 *
 * @param name     Field name to match
 * @param name_len Length of name
 * @return Index of first matching entry (0-98) on match
 * @return -1 if no match found
 */
extern int SocketQPACK_static_find_name (const char *name, size_t name_len);

/**
 * @brief Get the length of a static table entry's name.
 *
 * Optimization function to retrieve name length without copying the entry.
 *
 * @param index 0-based index into static table (0-98 valid)
 * @return Name length, or 0 if index is invalid
 */
extern size_t SocketQPACK_static_name_len (size_t index);

/**
 * @brief Get the length of a static table entry's value.
 *
 * Optimization function to retrieve value length without copying the entry.
 *
 * @param index 0-based index into static table (0-98 valid)
 * @return Value length, or 0 if index is invalid
 */
extern size_t SocketQPACK_static_value_len (size_t index);

/**
 * @brief Convert QPACK result code to string description.
 *
 * @param result Result code to convert
 * @return Human-readable string describing the result
 */
extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/** @} */

#endif /* SOCKETQPACK_INCLUDED */

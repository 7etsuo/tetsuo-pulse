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
 * with absolute indexing, and Huffman encoding. Provides encoder/decoder
 * instances for HTTP/3 header compression.
 *
 * Key differences from HPACK (RFC 7541):
 * - Absolute indexing: Dynamic table entries are numbered starting from 0
 *   at the oldest entry, incrementing with each insertion
 * - Encoder/decoder streams: Separate unidirectional streams for table updates
 * - Required Insert Count: Tracks which entries the decoder has received
 * - Blocked streams: Headers can reference entries not yet received
 *
 * Thread Safety: Encoder/decoder instances are NOT thread-safe. One instance
 * per connection recommended. Static functions are thread-safe.
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

/** RFC 9204 Appendix A: QPACK static table has 99 entries (indices 0-98) */
#define SOCKETQPACK_STATIC_TABLE_SIZE 99

/** RFC 9204 Section 3.2.1: Dynamic table entry overhead is 32 bytes */
#define SOCKETQPACK_ENTRY_OVERHEAD 32

/* ============================================================================
 * Encoder instruction bit patterns (RFC 9204 Section 4.3)
 * ============================================================================
 */

/**
 * @brief Insert with Name Reference instruction pattern
 *
 * First byte format: 1T NNNNNN
 * - Bit 7 (0x80): Always 1 for Insert with Name Reference
 * - Bit 6 (0x40): T bit - 1 for static table, 0 for dynamic table
 * - Bits 5-0: Start of 6-bit prefix integer for name index
 *
 * RFC 9204 Section 4.3.2
 */
#define QPACK_INSTR_INSERT_NAMEREF_MASK 0x80
#define QPACK_INSTR_INSERT_NAMEREF_STATIC 0xC0  /* 11xxxxxx */
#define QPACK_INSTR_INSERT_NAMEREF_DYNAMIC 0x80 /* 10xxxxxx */
#define QPACK_INSTR_INSERT_NAMEREF_PREFIX 6

/** String literal prefix for value encoding (7-bit prefix) */
#define QPACK_STRING_PREFIX 7

/** Huffman flag in string literal encoding */
#define QPACK_STRING_HUFFMAN_FLAG 0x80

/* ============================================================================
 * Result Codes
 * ============================================================================
 */

extern const Except_T SocketQPACK_Error;

typedef enum
{
  QPACK_OK = 0,
  QPACK_INCOMPLETE,           /**< Need more data to decode */
  QPACK_ERROR,                /**< Generic error */
  QPACK_ERROR_INVALID_INDEX,  /**< Name index out of bounds */
  QPACK_ERROR_HUFFMAN,        /**< Huffman encoding/decoding error */
  QPACK_ERROR_INTEGER,        /**< Integer overflow/encoding error */
  QPACK_ERROR_TABLE_SIZE,     /**< Dynamic table size exceeded */
  QPACK_ERROR_HEADER_SIZE,    /**< Individual header too large */
  QPACK_ERROR_ENCODER_STREAM, /**< Encoder stream error (RFC 9204 Section 7) */
  QPACK_ERROR_DECODER_STREAM, /**< Decoder stream error */
  QPACK_ERROR_DECOMPRESSION,  /**< Decompression failure */
} SocketQPACK_Result;

/* ============================================================================
 * Header Type
 * ============================================================================
 */

/**
 * @brief Header name-value pair
 */
typedef struct
{
  const char *name;
  size_t name_len;
  const char *value;
  size_t value_len;
  int never_index; /**< Header should never be indexed (sensitive) */
} SocketQPACK_Header;

/* ============================================================================
 * Dynamic Table (RFC 9204 Section 3.2)
 * ============================================================================
 */

typedef struct SocketQPACK_DynamicTable *SocketQPACK_DynamicTable_T;

/**
 * @brief Create dynamic table with FIFO eviction (RFC 9204 Section 3.2).
 *
 * @param max_size Maximum table size in bytes
 * @param arena Memory arena for allocations
 * @return New dynamic table instance
 */
extern SocketQPACK_DynamicTable_T
SocketQPACK_DynamicTable_new (size_t max_size, Arena_T arena);

/**
 * @brief Free dynamic table resources.
 * @param table Pointer to table (set to NULL after)
 */
extern void SocketQPACK_DynamicTable_free (SocketQPACK_DynamicTable_T *table);

/**
 * @brief Update maximum table size, evicting entries if necessary.
 * @param table Dynamic table
 * @param max_size New maximum size in bytes
 */
extern void
SocketQPACK_DynamicTable_set_max_size (SocketQPACK_DynamicTable_T table,
                                       size_t max_size);

/**
 * @brief Get current table size in bytes.
 */
extern size_t SocketQPACK_DynamicTable_size (SocketQPACK_DynamicTable_T table);

/**
 * @brief Get number of entries in table.
 */
extern size_t SocketQPACK_DynamicTable_count (SocketQPACK_DynamicTable_T table);

/**
 * @brief Get maximum table size in bytes.
 */
extern size_t
SocketQPACK_DynamicTable_max_size (SocketQPACK_DynamicTable_T table);

/**
 * @brief Get insertion count (total entries ever inserted).
 *
 * This is the absolute index of the next entry to be inserted.
 * Used for required insert count calculations.
 */
extern uint64_t
SocketQPACK_DynamicTable_insertion_count (SocketQPACK_DynamicTable_T table);

/**
 * @brief Get entry by absolute index.
 *
 * QPACK uses absolute indexing: older entries have lower indices.
 * Index 0 is the first entry ever inserted.
 *
 * @param table Dynamic table
 * @param absolute_index Absolute index (0-based from first insertion)
 * @param header Output header (name/value pointers valid until table modified)
 * @return QPACK_OK on success, QPACK_ERROR_INVALID_INDEX if out of range
 */
extern SocketQPACK_Result
SocketQPACK_DynamicTable_get (SocketQPACK_DynamicTable_T table,
                              uint64_t absolute_index,
                              SocketQPACK_Header *header);

/**
 * @brief Insert entry at front of dynamic table.
 *
 * May evict oldest entries to make room. If entry is larger than max_size,
 * the table is emptied but the entry is not added.
 *
 * @param table Dynamic table
 * @param name Header name
 * @param name_len Name length
 * @param value Header value
 * @param value_len Value length
 * @return QPACK_OK on success
 */
extern SocketQPACK_Result
SocketQPACK_DynamicTable_insert (SocketQPACK_DynamicTable_T table,
                                 const char *name,
                                 size_t name_len,
                                 const char *value,
                                 size_t value_len);

/* ============================================================================
 * Static Table (RFC 9204 Appendix A)
 * ============================================================================
 */

/**
 * @brief Get entry from static table by index (0-98).
 *
 * @param index Static table index (0-based)
 * @param header Output header
 * @return QPACK_OK on success, QPACK_ERROR_INVALID_INDEX if out of range
 */
extern SocketQPACK_Result
SocketQPACK_static_get (size_t index, SocketQPACK_Header *header);

/**
 * @brief Find entry in static table.
 *
 * @param name Header name to find
 * @param name_len Name length
 * @param value Header value (or NULL for name-only match)
 * @param value_len Value length
 * @return Positive index+1 for exact match, negative -(index+1) for name match,
 *         0 if not found
 */
extern int SocketQPACK_static_find (const char *name,
                                    size_t name_len,
                                    const char *value,
                                    size_t value_len);

/* ============================================================================
 * Integer Encoding (RFC 9204 Section 4.1.1, similar to RFC 7541)
 * ============================================================================
 */

/**
 * @brief Encode integer with prefix (RFC 7541 Section 5.1).
 *
 * QPACK uses the same integer encoding as HPACK.
 *
 * @param value Value to encode
 * @param prefix_bits Number of prefix bits (1-8)
 * @param output Output buffer
 * @param output_size Output buffer size
 * @return Number of bytes written, or 0 on error
 */
extern size_t SocketQPACK_int_encode (uint64_t value,
                                      int prefix_bits,
                                      unsigned char *output,
                                      size_t output_size);

/**
 * @brief Decode integer with prefix (RFC 7541 Section 5.1).
 *
 * @param input Input buffer
 * @param input_len Input buffer length
 * @param prefix_bits Number of prefix bits (1-8)
 * @param value Output value
 * @param consumed Output bytes consumed
 * @return QPACK_OK on success
 */
extern SocketQPACK_Result SocketQPACK_int_decode (const unsigned char *input,
                                                  size_t input_len,
                                                  int prefix_bits,
                                                  uint64_t *value,
                                                  size_t *consumed);

/* ============================================================================
 * String Encoding (RFC 9204 Section 4.1.2)
 * ============================================================================
 */

/**
 * @brief Encode string literal with optional Huffman compression.
 *
 * @param str String to encode
 * @param len String length
 * @param use_huffman Whether to attempt Huffman encoding
 * @param output Output buffer
 * @param output_size Output buffer size
 * @return Number of bytes written, or -1 on error
 */
extern ssize_t SocketQPACK_string_encode (const char *str,
                                          size_t len,
                                          int use_huffman,
                                          unsigned char *output,
                                          size_t output_size);

/**
 * @brief Decode string literal from buffer.
 *
 * @param input Input buffer
 * @param input_len Input buffer length
 * @param str_out Output string pointer (arena-allocated)
 * @param str_len_out Output string length
 * @param consumed Output bytes consumed
 * @param arena Memory arena for allocation
 * @return QPACK_OK on success
 */
extern SocketQPACK_Result SocketQPACK_string_decode (const unsigned char *input,
                                                     size_t input_len,
                                                     char **str_out,
                                                     size_t *str_len_out,
                                                     size_t *consumed,
                                                     Arena_T arena);

/* ============================================================================
 * Insert with Name Reference (RFC 9204 Section 4.3.2)
 * ============================================================================
 */

/**
 * @brief Context for Insert with Name Reference instruction.
 */
typedef struct
{
  int is_static;              /**< T bit: 1 for static table, 0 for dynamic */
  size_t name_index;          /**< Name index (within respective table) */
  const unsigned char *value; /**< Value bytes */
  size_t value_len;           /**< Value length */
  int use_huffman;            /**< Use Huffman encoding for value */
} SocketQPACK_InsertNameRef;

/**
 * @brief Validate name reference index.
 *
 * Checks that the name index is valid for the specified table.
 *
 * @param is_static True for static table, false for dynamic
 * @param name_index Index to validate
 * @param table Dynamic table (only used if is_static is false)
 * @return QPACK_OK if valid, QPACK_ERROR_INVALID_INDEX otherwise
 */
extern SocketQPACK_Result
SocketQPACK_validate_nameref_index (int is_static,
                                    size_t name_index,
                                    SocketQPACK_DynamicTable_T table);

/**
 * @brief Encode Insert with Name Reference instruction.
 *
 * Encodes the instruction to bytes suitable for the encoder stream.
 * The instruction references a name from the static or dynamic table
 * and provides a new value.
 *
 * Wire format:
 *   1T NNNNNN  - First byte (T=table, N=6-bit prefix for name index)
 *   [name_index continuation bytes if needed]
 *   H VVVVVVV  - Value string (H=Huffman, V=7-bit prefix for length)
 *   [value bytes]
 *
 * @param instr Instruction parameters
 * @param table Dynamic table (for validation if referencing dynamic entry)
 * @param output Output buffer
 * @param output_size Output buffer size
 * @return Number of bytes written, or -1 on error
 */
extern ssize_t
SocketQPACK_encode_insert_nameref (const SocketQPACK_InsertNameRef *instr,
                                   SocketQPACK_DynamicTable_T table,
                                   unsigned char *output,
                                   size_t output_size);

/**
 * @brief Decode Insert with Name Reference instruction.
 *
 * Decodes the instruction from encoder stream bytes and inserts
 * the resulting entry into the dynamic table.
 *
 * @param input Input buffer (starting at instruction byte)
 * @param input_len Input buffer length
 * @param table Dynamic table to insert into
 * @param consumed Output bytes consumed
 * @param arena Memory arena for string allocations
 * @return QPACK_OK on success, error code otherwise
 */
extern SocketQPACK_Result
SocketQPACK_decode_insert_nameref (const unsigned char *input,
                                   size_t input_len,
                                   SocketQPACK_DynamicTable_T table,
                                   size_t *consumed,
                                   Arena_T arena);

/* ============================================================================
 * Result String
 * ============================================================================
 */

/**
 * @brief Get human-readable string for result code.
 */
extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/** @} */

#endif /* SOCKETQPACK_INCLUDED */

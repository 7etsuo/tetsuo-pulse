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
 * with absolute indexing, and three index conversion schemes as per RFC 9204
 * Sections 3.2.4-3.2.6.
 *
 * Index Schemes (RFC 9204 Section 3.2):
 * - Absolute Indexing: Global, monotonically increasing (0 = first insertion)
 * - Encoder Relative Indexing: Relative to Insert Count (encoder stream)
 * - Field Section Indexing: Relative to Base (field sections), includes
 *   post-base for entries inserted during encoding
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/Except.h"

/* ============================================================================
 * COMPILER ATTRIBUTES
 * ============================================================================
 */

#if defined(__GNUC__) || defined(__clang__)
#define QPACK_WARN_UNUSED __attribute__ ((warn_unused_result))
#else
#define QPACK_WARN_UNUSED
#endif

/* ============================================================================
 * CONFIGURATION CONSTANTS
 * ============================================================================
 */

#ifndef SOCKETQPACK_DEFAULT_TABLE_SIZE
#define SOCKETQPACK_DEFAULT_TABLE_SIZE 4096
#endif

#ifndef SOCKETQPACK_MAX_TABLE_SIZE
#define SOCKETQPACK_MAX_TABLE_SIZE (64 * 1024)
#endif

#ifndef SOCKETQPACK_MAX_BLOCKED_STREAMS
#define SOCKETQPACK_MAX_BLOCKED_STREAMS 100
#endif

/** RFC 9204 Section 3.2: Entry overhead is 32 bytes (same as HPACK) */
#define SOCKETQPACK_ENTRY_OVERHEAD 32

/** RFC 9204 Appendix A: Static table has 99 entries */
#define SOCKETQPACK_STATIC_TABLE_SIZE 99

/* ============================================================================
 * ERROR CODES
 * ============================================================================
 */

/**
 * @brief QPACK operation result codes.
 *
 * RFC 9204 Section 2.2.3 specifies error handling requirements.
 */
typedef enum
{
  QPACK_OK = 0,            /**< Operation successful */
  QPACK_INCOMPLETE,        /**< Need more data to complete operation */
  QPACK_ERR_INVALID_INDEX, /**< Index out of valid range */
  QPACK_ERR_EVICTED_INDEX, /**< Referenced entry has been evicted */
  QPACK_ERR_FUTURE_INDEX,  /**< Index references not-yet-inserted entry */
  QPACK_ERR_BASE_OVERFLOW, /**< Base would exceed Insert Count */
  QPACK_ERR_TABLE_SIZE,    /**< Dynamic table size limit exceeded */
  QPACK_ERR_HEADER_SIZE,   /**< Individual header size limit exceeded */
  QPACK_ERR_HUFFMAN,       /**< Huffman decoding error */
  QPACK_ERR_INTEGER,       /**< Integer decoding error */
  QPACK_ERR_DECOMPRESSION, /**< Decompression failed (bomb protection) */
  QPACK_ERR_NULL_PARAM,    /**< NULL parameter passed to function */
  QPACK_ERR_INTERNAL,      /**< Internal error */
  QPACK_ERR_INVALID_BASE   /**< Invalid Base calculation (Section 4.5.1.2) */
} SocketQPACK_Result;

/* ============================================================================
 * OPAQUE TYPES
 * ============================================================================
 */

/**
 * @brief Opaque type for QPACK dynamic table.
 *
 * Manages entries with absolute indexing as per RFC 9204 Section 3.2.1-3.2.3.
 */
typedef struct SocketQPACK_Table *SocketQPACK_Table_T;

/* ============================================================================
 * INDEX CONVERSION FUNCTIONS (RFC 9204 Sections 3.2.4-3.2.6)
 * ============================================================================
 */

/**
 * @brief Convert absolute index to encoder-relative index.
 *
 * RFC 9204 Section 3.2.5: Encoder instructions reference dynamic table entries
 * using a relative index. The relative index starts at 0 for the most recently
 * inserted entry.
 *
 * Formula: relative = insert_count - abs_index - 1
 *
 * @param insert_count Current Insert Count (total entries ever inserted)
 * @param abs_index    Absolute index to convert
 * @param[out] rel_out Output: resulting relative index (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if rel_out is NULL,
 *         QPACK_ERR_INVALID_INDEX if abs_index >= insert_count
 *
 * @note abs_index must be < insert_count (cannot reference future entries)
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_abs_to_relative_encoder (uint64_t insert_count,
                                     uint64_t abs_index,
                                     uint64_t *rel_out);

/**
 * @brief Convert encoder-relative index to absolute index.
 *
 * RFC 9204 Section 3.2.5: Converts from encoder stream relative indexing
 * to the canonical absolute index.
 *
 * Formula: absolute = insert_count - relative - 1
 *
 * @param insert_count Current Insert Count
 * @param rel_index    Relative index to convert
 * @param[out] abs_out Output: resulting absolute index (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if abs_out is NULL,
 *         QPACK_ERR_INVALID_INDEX if rel_index >= insert_count
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_relative_to_abs_encoder (uint64_t insert_count,
                                     uint64_t rel_index,
                                     uint64_t *abs_out);

/**
 * @brief Convert absolute index to field-relative index.
 *
 * RFC 9204 Section 3.2.5: Field section references use a relative index
 * computed from the Base value. Relative index 0 references the entry
 * at Base - 1.
 *
 * Formula: relative = base - abs_index - 1
 *
 * @param base      Base value for the field section
 * @param abs_index Absolute index to convert (must be < base)
 * @param[out] rel_out Output: resulting relative index (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if rel_out is NULL,
 *         QPACK_ERR_INVALID_INDEX if abs_index >= base or base == 0
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result SocketQPACK_abs_to_relative_field (
    uint64_t base, uint64_t abs_index, uint64_t *rel_out);

/**
 * @brief Convert field-relative index to absolute index.
 *
 * RFC 9204 Section 3.2.5: Converts from field section relative indexing
 * to the canonical absolute index.
 *
 * Formula: absolute = base - relative - 1
 *
 * @param base      Base value for the field section
 * @param rel_index Relative index to convert (must be < base)
 * @param[out] abs_out Output: resulting absolute index (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if abs_out is NULL,
 *         QPACK_ERR_INVALID_INDEX if rel_index >= base or base == 0
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result SocketQPACK_relative_to_abs_field (
    uint64_t base, uint64_t rel_index, uint64_t *abs_out);

/**
 * @brief Convert absolute index to post-base index.
 *
 * RFC 9204 Section 3.2.6: Post-base indexing allows field sections to
 * reference entries inserted during encoding (abs_index >= base).
 * Post-base index 0 references the entry at Base.
 *
 * Formula: post_base = abs_index - base
 *
 * @param base      Base value for the field section
 * @param abs_index Absolute index to convert (must be >= base)
 * @param[out] pb_out Output: resulting post-base index (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if pb_out is NULL,
 *         QPACK_ERR_INVALID_INDEX if abs_index < base
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result SocketQPACK_abs_to_postbase (
    uint64_t base, uint64_t abs_index, uint64_t *pb_out);

/**
 * @brief Convert post-base index to absolute index.
 *
 * RFC 9204 Section 3.2.6: Converts from post-base indexing to the canonical
 * absolute index.
 *
 * Formula: absolute = base + post_base
 *
 * @param base     Base value for the field section
 * @param pb_index Post-base index to convert
 * @param[out] abs_out Output: resulting absolute index (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if abs_out is NULL,
 *         QPACK_ERR_INVALID_INDEX if overflow would occur
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result SocketQPACK_postbase_to_abs (
    uint64_t base, uint64_t pb_index, uint64_t *abs_out);

/* ============================================================================
 * INDEX VALIDATION FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Validate encoder-relative index against eviction bounds.
 *
 * RFC 9204 Section 3.2.5: An encoder-relative index is valid if:
 * 1. rel_index < insert_count (not a future reference)
 * 2. The corresponding absolute index >= dropped_count (not evicted)
 *
 * @param insert_count  Current Insert Count
 * @param dropped_count Number of entries evicted (absolute index of oldest
 * valid)
 * @param rel_index     Relative index to validate
 * @return QPACK_OK if valid, appropriate error code otherwise
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_is_valid_relative_encoder (uint64_t insert_count,
                                       uint64_t dropped_count,
                                       uint64_t rel_index);

/**
 * @brief Validate field-relative index against Base and eviction bounds.
 *
 * RFC 9204 Section 3.2.5: A field-relative index is valid if:
 * 1. rel_index < base (in valid range)
 * 2. The corresponding absolute index >= dropped_count (not evicted)
 *
 * @param base          Base value for the field section
 * @param dropped_count Number of entries evicted
 * @param rel_index     Relative index to validate
 * @return QPACK_OK if valid, appropriate error code otherwise
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_is_valid_relative_field (uint64_t base,
                                     uint64_t dropped_count,
                                     uint64_t rel_index);

/**
 * @brief Validate post-base index against Insert Count bounds.
 *
 * RFC 9204 Section 3.2.6: A post-base index is valid if:
 * 1. base + pb_index < insert_count (not a future reference)
 *
 * @param base         Base value for the field section
 * @param insert_count Current Insert Count
 * @param pb_index     Post-base index to validate
 * @return QPACK_OK if valid, QPACK_ERR_FUTURE_INDEX otherwise
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result SocketQPACK_is_valid_postbase (
    uint64_t base, uint64_t insert_count, uint64_t pb_index);

/**
 * @brief Validate absolute index against table bounds.
 *
 * Checks that an absolute index is within the valid range [dropped_count,
 * insert_count).
 *
 * @param insert_count  Current Insert Count
 * @param dropped_count Number of entries evicted
 * @param abs_index     Absolute index to validate
 * @return QPACK_OK if valid, appropriate error code otherwise
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result SocketQPACK_is_valid_absolute (
    uint64_t insert_count, uint64_t dropped_count, uint64_t abs_index);

/* ============================================================================
 * SET DYNAMIC TABLE CAPACITY (RFC 9204 Section 4.3.1)
 * ============================================================================
 */

/**
 * @brief Encode Set Dynamic Table Capacity instruction.
 *
 * RFC 9204 Section 4.3.1: Encodes the instruction to set dynamic table
 * capacity. Uses 3-bit pattern 001 (0x20 mask) with 5-bit prefix integer.
 *
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 | 1 |   Capacity (5+)   |
 * +---+---+---+-------------------+
 *
 * @param capacity     Capacity value to encode
 * @param output       Output buffer (must not be NULL)
 * @param output_size  Size of output buffer
 * @param[out] written Output: number of bytes written (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if output or written is NULL,
 *         QPACK_ERR_TABLE_SIZE if output buffer too small
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_encode_set_capacity (uint64_t capacity,
                                 unsigned char *output,
                                 size_t output_size,
                                 size_t *written);

/**
 * @brief Decode Set Dynamic Table Capacity instruction.
 *
 * RFC 9204 Section 4.3.1: Decodes the capacity instruction from the encoder
 * stream. The first byte must have bits 7-5 equal to 001 (0x20 mask).
 *
 * @param input        Input buffer (must not be NULL if input_len > 0)
 * @param input_len    Length of input buffer
 * @param[out] capacity Output: decoded capacity value (must not be NULL)
 * @param[out] consumed Output: number of bytes consumed (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if capacity or consumed is NULL,
 *         QPACK_INCOMPLETE if more data needed,
 *         QPACK_ERR_INTEGER if integer decoding failed
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_decode_set_capacity (const unsigned char *input,
                                 size_t input_len,
                                 uint64_t *capacity,
                                 size_t *consumed);

/**
 * @brief Apply Set Dynamic Table Capacity to a table.
 *
 * RFC 9204 Section 4.3.1: Updates the dynamic table capacity. If the new
 * capacity is smaller than the current size, entries are evicted (FIFO order)
 * until the size fits within the new capacity.
 *
 * @param table        Dynamic table to update (must not be NULL)
 * @param capacity     New capacity in bytes
 * @param max_capacity Maximum allowed capacity (decoder-advertised limit)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if table is NULL,
 *         QPACK_ERR_TABLE_SIZE if capacity exceeds max_capacity
 *
 * @note Setting capacity to 0 evicts all entries and effectively disables
 *       the dynamic table.
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result SocketQPACK_apply_set_capacity (
    SocketQPACK_Table_T table, uint64_t capacity, uint64_t max_capacity);

/* ============================================================================
 * DYNAMIC TABLE MANAGEMENT (RFC 9204 Section 3.2)
 * ============================================================================
 */

/**
 * @brief Create a new QPACK dynamic table.
 *
 * Allocates a dynamic table with specified maximum size. The table uses
 * a ring buffer internally for FIFO eviction.
 *
 * @param arena    Memory arena for allocations (must not be NULL)
 * @param max_size Maximum table size in bytes
 * @return New table instance, or NULL on allocation failure
 *
 * @since 1.0.0
 */
extern SocketQPACK_Table_T
SocketQPACK_Table_new (Arena_T arena, size_t max_size);

/**
 * @brief Get the current size of the dynamic table in bytes.
 *
 * @param table Dynamic table (must not be NULL)
 * @return Current size in bytes, or 0 if table is NULL
 *
 * @since 1.0.0
 */
extern size_t SocketQPACK_Table_size (SocketQPACK_Table_T table);

/**
 * @brief Get the current number of entries in the dynamic table.
 *
 * @param table Dynamic table (must not be NULL)
 * @return Number of entries, or 0 if table is NULL
 *
 * @since 1.0.0
 */
extern size_t SocketQPACK_Table_count (SocketQPACK_Table_T table);

/**
 * @brief Get the maximum size of the dynamic table in bytes.
 *
 * @param table Dynamic table (must not be NULL)
 * @return Maximum size in bytes, or 0 if table is NULL
 *
 * @since 1.0.0
 */
extern size_t SocketQPACK_Table_max_size (SocketQPACK_Table_T table);

/**
 * @brief Get the Insert Count (total entries ever inserted).
 *
 * @param table Dynamic table (must not be NULL)
 * @return Insert Count, or 0 if table is NULL
 *
 * @since 1.0.0
 */
extern uint64_t SocketQPACK_Table_insert_count (SocketQPACK_Table_T table);

/**
 * @brief Get the number of entries that have been evicted.
 *
 * @param table Dynamic table (must not be NULL)
 * @return Dropped count, or 0 if table is NULL
 *
 * @since 1.0.0
 */
extern uint64_t SocketQPACK_Table_dropped_count (SocketQPACK_Table_T table);

/**
 * @brief Set the maximum size of the dynamic table.
 *
 * Evicts entries if the new max size is smaller than current size.
 *
 * @param table    Dynamic table (must not be NULL)
 * @param max_size New maximum size in bytes
 *
 * @since 1.0.0
 */
extern void
SocketQPACK_Table_set_max_size (SocketQPACK_Table_T table, size_t max_size);

/**
 * @brief Insert a literal name-value entry into the dynamic table.
 *
 * @param table     Dynamic table
 * @param name      Header name
 * @param name_len  Length of name
 * @param value     Header value
 * @param value_len Length of value
 * @return QPACK_OK on success, error code on failure
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_Table_insert_literal (SocketQPACK_Table_T table,
                                  const char *name,
                                  size_t name_len,
                                  const char *value,
                                  size_t value_len);

/**
 * @brief Get an entry from the dynamic table by absolute index.
 *
 * @param table     Dynamic table
 * @param abs_index Absolute index of entry
 * @param[out] name      Output: pointer to name
 * @param[out] name_len  Output: name length
 * @param[out] value     Output: pointer to value
 * @param[out] value_len Output: value length
 * @return QPACK_OK on success, error code on failure
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_Table_get (SocketQPACK_Table_T table,
                       uint64_t abs_index,
                       const char **name,
                       size_t *name_len,
                       const char **value,
                       size_t *value_len);

/* ============================================================================
 * INSERT WITH LITERAL NAME (RFC 9204 Section 4.3.3)
 * ============================================================================
 */

/**
 * @brief Encode Insert With Literal Name instruction.
 *
 * RFC 9204 Section 4.3.3: Encodes an instruction to insert a new entry
 * with both name and value as literals into the dynamic table.
 *
 * @param buf           Output buffer
 * @param buf_size      Size of output buffer
 * @param name          Header name
 * @param name_len      Length of name
 * @param name_huffman  Whether to use Huffman encoding for name
 * @param value         Header value
 * @param value_len     Length of value
 * @param value_huffman Whether to use Huffman encoding for value
 * @param[out] bytes_written Output: number of bytes written
 * @return QPACK_OK on success, error code on failure
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_encode_insert_literal_name (unsigned char *buf,
                                        size_t buf_size,
                                        const unsigned char *name,
                                        size_t name_len,
                                        bool name_huffman,
                                        const unsigned char *value,
                                        size_t value_len,
                                        bool value_huffman,
                                        size_t *bytes_written);

/**
 * @brief Decode Insert With Literal Name instruction.
 *
 * RFC 9204 Section 4.3.3: Decodes an instruction to insert a new entry
 * with both name and value as literals.
 *
 * @param buf            Input buffer
 * @param buf_len        Length of input buffer
 * @param table          Dynamic table for insertion (may be NULL)
 * @param name_out       Output buffer for decoded name
 * @param name_out_size  Size of name output buffer
 * @param[out] name_len_out  Output: actual name length
 * @param value_out      Output buffer for decoded value
 * @param value_out_size Size of value output buffer
 * @param[out] value_len_out Output: actual value length
 * @param[out] bytes_consumed Output: bytes consumed
 * @return QPACK_OK on success, error code on failure
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_decode_insert_literal_name (const unsigned char *buf,
                                        size_t buf_len,
                                        SocketQPACK_Table_T table,
                                        unsigned char *name_out,
                                        size_t name_out_size,
                                        size_t *name_len_out,
                                        unsigned char *value_out,
                                        size_t value_out_size,
                                        size_t *value_len_out,
                                        size_t *bytes_consumed);

/* ============================================================================
 * FIELD SECTION PREFIX (RFC 9204 Section 4.5.1)
 * ============================================================================
 */

/**
 * @brief Decoded Field Section Prefix.
 *
 * RFC 9204 Section 4.5.1: The Field Section Prefix is transmitted before
 * encoded field sections and contains Required Insert Count and Base.
 */
typedef struct
{
  uint64_t required_insert_count; /**< Required Insert Count (RIC) */
  int64_t delta_base;             /**< Signed delta base value */
  uint64_t base;                  /**< Computed absolute base */
} SocketQPACK_FieldSectionPrefix;

/**
 * @brief Encode Field Section Prefix.
 *
 * RFC 9204 Section 4.5.1: Encodes the Required Insert Count and Base
 * into the Field Section Prefix format.
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * |   Required Insert Count (8+)  |
 * +---+---+---+---+---+---+---+---+
 * | S |      Delta Base (7+)      |
 * +---+---------------------------+
 *
 * @param required_insert_count Required Insert Count for this field section
 * @param base                  Base value for relative indexing
 * @param max_entries           MaxEntries = MaxTableCapacity / 32
 * @param output                Output buffer (must not be NULL)
 * @param output_size           Size of output buffer
 * @param[out] bytes_written    Number of bytes written (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if output or bytes_written is NULL,
 *         QPACK_ERR_TABLE_SIZE if buffer too small or max_entries is 0,
 *         QPACK_ERR_INTEGER if integer encoding failed
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_encode_prefix (uint64_t required_insert_count,
                           uint64_t base,
                           uint64_t max_entries,
                           unsigned char *output,
                           size_t output_size,
                           size_t *bytes_written);

/**
 * @brief Decode Field Section Prefix.
 *
 * RFC 9204 Section 4.5.1: Decodes the Required Insert Count and Base
 * from the Field Section Prefix. Validates that Required Insert Count
 * does not exceed the decoder's current Insert Count.
 *
 * @param input               Input buffer (must not be NULL if input_len > 0)
 * @param input_len           Length of input buffer
 * @param max_entries         MaxEntries = MaxTableCapacity / 32
 * @param total_insert_count  Decoder's current total Insert Count
 * @param[out] prefix         Decoded prefix values (must not be NULL)
 * @param[out] bytes_consumed Number of bytes consumed (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if prefix or bytes_consumed is NULL,
 *         QPACK_INCOMPLETE if more data needed,
 *         QPACK_ERR_TABLE_SIZE if max_entries is 0,
 *         QPACK_ERR_INTEGER if integer decoding failed,
 *         QPACK_ERR_DECOMPRESSION if RIC > total_insert_count or invalid
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_decode_prefix (const unsigned char *input,
                           size_t input_len,
                           uint64_t max_entries,
                           uint64_t total_insert_count,
                           SocketQPACK_FieldSectionPrefix *prefix,
                           size_t *bytes_consumed);

/**
 * @brief Validate Field Section Prefix.
 *
 * RFC 9204 Section 4.5.1: Validates that the prefix values are consistent
 * and within valid bounds. Checks Required Insert Count against total
 * insertions and verifies Base computation.
 *
 * @param prefix              Prefix to validate (must not be NULL)
 * @param total_insert_count  Decoder's current total Insert Count
 * @return QPACK_OK if valid,
 *         QPACK_ERR_NULL_PARAM if prefix is NULL,
 *         QPACK_ERR_DECOMPRESSION if RIC > total_insert_count,
 *         QPACK_ERR_BASE_OVERFLOW if Base computation is invalid
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result SocketQPACK_validate_prefix (
    const SocketQPACK_FieldSectionPrefix *prefix, uint64_t total_insert_count);

/**
 * @brief Compute MaxEntries from maximum table capacity.
 *
 * RFC 9204 Section 4.5.1.1: MaxEntries is derived from the maximum
 * dynamic table capacity advertised by the decoder.
 *
 *   MaxEntries = floor(MaxTableCapacity / 32)
 *
 * @param max_table_capacity Maximum table capacity in bytes
 * @return MaxEntries value for use in prefix encoding/decoding
 *
 * @since 1.0.0
 */
extern uint64_t SocketQPACK_compute_max_entries (uint64_t max_table_capacity);

/**
 * @brief Alias for SocketQPACK_compute_max_entries.
 *
 * Provided for symmetry with RFC 9204 Section 4.5.1.1 naming.
 *
 * @param max_table_capacity Maximum table capacity in bytes
 * @return MaxEntries = floor(MaxTableCapacity / 32)
 *
 * @since 1.0.0
 */
extern uint64_t SocketQPACK_max_entries (uint64_t max_table_capacity);

/* ============================================================================
 * REQUIRED INSERT COUNT ENCODING (RFC 9204 Section 4.5.1.1)
 * ============================================================================
 */

/**
 * @brief Encode Required Insert Count for Field Section Prefix.
 *
 * RFC 9204 Section 4.5.1.1: Encodes the Required Insert Count (RIC) using
 * modular arithmetic to reduce the encoded value's size.
 *
 * Algorithm:
 *   - If RIC == 0: EncodedRIC = 0
 *   - Otherwise: EncodedRIC = (RIC mod (2 * MaxEntries)) + 1
 *
 * where MaxEntries = floor(MaxTableCapacity / 32).
 *
 * @param required_insert_count Required Insert Count to encode
 * @param max_entries           MaxEntries value (from max table capacity / 32)
 * @param[out] encoded_ric      Output: encoded value (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if encoded_ric is NULL,
 *         QPACK_ERR_TABLE_SIZE if max_entries is 0 and RIC is non-zero
 *
 * @note The encoded value is suitable for QPACK integer encoding with an
 *       8-bit prefix.
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_encode_required_insert_count (uint64_t required_insert_count,
                                          uint64_t max_entries,
                                          uint64_t *encoded_ric);

/**
 * @brief Decode Required Insert Count from Field Section Prefix.
 *
 * RFC 9204 Section 4.5.1.1: Decodes the Required Insert Count (RIC) from
 * its encoded form using the wrap-around recovery algorithm.
 *
 * Algorithm:
 *   - If EncodedRIC == 0: RIC = 0
 *   - Otherwise:
 *       FullRange = 2 * MaxEntries
 *       MaxValue = TotalNumberOfInserts + MaxEntries
 *       MaxWrapped = floor(MaxValue / FullRange) * FullRange
 *       RIC = MaxWrapped + EncodedRIC - 1
 *       If RIC > MaxValue:
 *         If RIC <= FullRange: ERROR (invalid)
 *         RIC -= FullRange
 *       If RIC == 0: ERROR (invalid state)
 *
 * @param encoded_ric             Encoded Required Insert Count value
 * @param max_entries             MaxEntries value (from max table capacity /
 * 32)
 * @param total_insert_count      Decoder's current total Insert Count
 * @param[out] required_insert_count Output: decoded RIC (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if required_insert_count is NULL,
 *         QPACK_ERR_TABLE_SIZE if max_entries is 0 and encoded_ric is non-zero,
 *         QPACK_ERR_DECOMPRESSION if:
 *           - EncodedRIC > FullRange (invalid encoding)
 *           - Decoded RIC == 0 after unwrapping (invalid state)
 *           - RIC > MaxValue but RIC <= FullRange (impossible wrap)
 *           - RIC > total_insert_count (references future entries)
 *
 * @note This function performs full validation per RFC 9204 Section 4.5.1.1.
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_decode_required_insert_count (uint64_t encoded_ric,
                                          uint64_t max_entries,
                                          uint64_t total_insert_count,
                                          uint64_t *required_insert_count);

/* ============================================================================
 * BASE ENCODING (RFC 9204 Section 4.5.1.2)
 * ============================================================================
 */

/**
 * @brief Calculate Base from Sign bit, Required Insert Count, and Delta Base.
 *
 * RFC 9204 Section 4.5.1.2: Computes the Base value used for relative
 * indexing in field sections. The formula depends on the Sign bit:
 *
 *   - Sign = 0 (positive): Base = ReqInsertCount + DeltaBase
 *   - Sign = 1 (negative): Base = ReqInsertCount - DeltaBase - 1
 *
 * @param sign              Sign bit (0 or 1)
 * @param req_insert_count  Required Insert Count from prefix
 * @param delta_base        Delta Base value (7-bit prefix variable integer)
 * @param[out] base_out     Output: computed Base value (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if base_out is NULL,
 *         QPACK_ERR_INVALID_BASE if Sign=1 and ReqInsertCount <= DeltaBase,
 *         QPACK_ERR_BASE_OVERFLOW if overflow would occur
 *
 * @note For Sign=1 (negative delta), ReqInsertCount MUST be > DeltaBase
 *       to ensure Base >= 0.
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_calculate_base (int sign,
                            uint64_t req_insert_count,
                            uint64_t delta_base,
                            uint64_t *base_out);

/**
 * @brief Validate Base calculation constraints.
 *
 * RFC 9204 Section 4.5.1.2: Validates that the Sign bit and Delta Base
 * values are consistent with the Required Insert Count, ensuring the
 * resulting Base value is non-negative.
 *
 * Validation rules:
 *   - If Sign = 1 (negative delta): ReqInsertCount MUST be > DeltaBase
 *   - Base value MUST be non-negative (always true for uint64_t)
 *   - No overflow in Base calculation
 *
 * @param sign              Sign bit (0 or 1)
 * @param req_insert_count  Required Insert Count from prefix
 * @param delta_base        Delta Base value
 * @return QPACK_OK if valid,
 *         QPACK_ERR_INVALID_BASE if constraints violated
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result SocketQPACK_validate_base (
    int sign, uint64_t req_insert_count, uint64_t delta_base);

/**
 * @brief Encode Base as Delta Base with Sign bit for field section prefix.
 *
 * RFC 9204 Section 4.5.1.2: Computes the Sign bit and Delta Base value
 * that will encode the given Base relative to Required Insert Count.
 *
 * Encoding rules:
 *   - If Base >= ReqInsertCount: Sign = 0, DeltaBase = Base - ReqInsertCount
 *   - If Base < ReqInsertCount: Sign = 1, DeltaBase = ReqInsertCount - Base - 1
 *
 * @param req_insert_count  Required Insert Count for the field section
 * @param base              Absolute Base value to encode
 * @param[out] sign_out     Output: Sign bit (0 or 1, must not be NULL)
 * @param[out] delta_out    Output: Delta Base value (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if sign_out or delta_out is NULL
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_encode_base (uint64_t req_insert_count,
                         uint64_t base,
                         int *sign_out,
                         uint64_t *delta_out);

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Get human-readable string for QPACK result code.
 *
 * @param result Result code to describe
 * @return Static string describing the result (never NULL)
 *
 * @since 1.0.0
 */
extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/**
 * @brief Calculate required table capacity for a given max size.
 *
 * Estimates the number of entries based on average entry size
 * and rounds up to a power of 2 for efficient ring buffer operations.
 *
 * @param max_size Maximum table size in bytes
 * @return Recommended capacity (power of 2, minimum 16)
 *
 * @since 1.0.0
 */
extern size_t SocketQPACK_estimate_capacity (size_t max_size);

/** @} */

#endif /* SOCKETQPACK_INCLUDED */

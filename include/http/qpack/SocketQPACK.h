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
 * HTTP/3 SETTINGS IDENTIFIERS (RFC 9204 Section 5)
 * ============================================================================
 */

/**
 * @brief SETTINGS_QPACK_MAX_TABLE_CAPACITY identifier (0x01).
 *
 * RFC 9204 Section 5: Maximum size of the dynamic table in bytes.
 * Default is 0 (no dynamic table). Sent in HTTP/3 SETTINGS frame.
 */
#define SETTINGS_QPACK_MAX_TABLE_CAPACITY 0x01

/**
 * @brief SETTINGS_QPACK_BLOCKED_STREAMS identifier (0x07).
 *
 * RFC 9204 Section 5: Maximum number of streams that can be blocked.
 * Default is 0 (no blocking allowed). Sent in HTTP/3 SETTINGS frame.
 */
#define SETTINGS_QPACK_BLOCKED_STREAMS 0x07

/**
 * @brief QPACK settings structure.
 *
 * RFC 9204 Section 5: Connection-level QPACK configuration parameters
 * negotiated via HTTP/3 SETTINGS frame.
 */
typedef struct
{
  uint64_t max_table_capacity; /**< SETTINGS_QPACK_MAX_TABLE_CAPACITY */
  uint64_t blocked_streams;    /**< SETTINGS_QPACK_BLOCKED_STREAMS */
} SocketQPACK_Settings;

/**
 * @brief QPACK configuration state.
 *
 * Tracks local and peer settings for a QPACK encoder/decoder pair.
 * Used for settings negotiation and 0-RTT resumption.
 */
typedef struct SocketQPACK_Config *SocketQPACK_Config_T;

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
 * INDEXED FIELD LINE (RFC 9204 Section 4.5.2)
 * ============================================================================
 */

/**
 * @brief Encode an Indexed Field Line.
 *
 * RFC 9204 Section 4.5.2: Encodes a reference to a field line in either
 * the static table or dynamic table using the Indexed Field Line format.
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 1 | T |      Index (6+)       |
 * +---+---+-----------------------+
 *
 * @param output        Output buffer (must not be NULL)
 * @param output_size   Size of output buffer
 * @param index         Table index (static: 0-98, dynamic: relative to Base)
 * @param is_static     1 for static table, 0 for dynamic table
 * @param[out] bytes_written Number of bytes written (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if output or bytes_written is NULL,
 *         QPACK_ERR_TABLE_SIZE if buffer too small,
 *         QPACK_ERR_INVALID_INDEX if static index > 98,
 *         QPACK_ERR_INTEGER if integer encoding failed
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_encode_indexed_field (unsigned char *output,
                                  size_t output_size,
                                  uint64_t index,
                                  int is_static,
                                  size_t *bytes_written);

/**
 * @brief Decode an Indexed Field Line.
 *
 * RFC 9204 Section 4.5.2: Decodes an Indexed Field Line to extract the
 * table type (static/dynamic) and index value.
 *
 * @param input          Input buffer (must not be NULL if input_len > 0)
 * @param input_len      Length of input buffer
 * @param[out] index     Decoded index value (must not be NULL)
 * @param[out] is_static 1 if static table, 0 if dynamic (must not be NULL)
 * @param[out] bytes_consumed Number of bytes consumed (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if output parameters are NULL,
 *         QPACK_INCOMPLETE if more data needed,
 *         QPACK_ERR_INTEGER if integer decoding failed,
 *         QPACK_ERR_INVALID_INDEX if static index > 98,
 *         QPACK_ERR_INTERNAL if not an indexed field line pattern
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_decode_indexed_field (const unsigned char *input,
                                  size_t input_len,
                                  uint64_t *index,
                                  int *is_static,
                                  size_t *bytes_consumed);

/**
 * @brief Resolve an Indexed Field Line to absolute index.
 *
 * RFC 9204 Section 4.5.2: Converts a decoded indexed field line to an
 * absolute index suitable for table lookup. For static table references,
 * validates the index range. For dynamic table references, converts from
 * relative (Base-relative) indexing to absolute indexing.
 *
 * @param index         Decoded index from SocketQPACK_decode_indexed_field
 * @param is_static     Table type (1=static, 0=dynamic)
 * @param base          Base value from Field Section Prefix (for dynamic)
 * @param dropped_count Number of evicted entries (for dynamic validation)
 * @param[out] abs_index Resulting absolute index (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if abs_index is NULL,
 *         QPACK_ERR_INVALID_INDEX if index out of range,
 *         QPACK_ERR_EVICTED_INDEX if dynamic entry was evicted
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_resolve_indexed_field (uint64_t index,
                                   int is_static,
                                   uint64_t base,
                                   uint64_t dropped_count,
                                   uint64_t *abs_index);

/**
 * @brief Check if a byte indicates an Indexed Field Line.
 *
 * RFC 9204 Section 4.5.2: An Indexed Field Line starts with bit pattern 1x.
 *
 * @param byte First byte of a potential Indexed Field Line
 * @return Non-zero if byte matches Indexed Field Line pattern, 0 otherwise
 *
 * @since 1.0.0
 */
extern int SocketQPACK_is_indexed_field_line (unsigned char byte);

/* ============================================================================
 * INDEXED FIELD LINE WITH POST-BASE INDEX (RFC 9204 Section 4.5.3)
 * ============================================================================
 */

/**
 * @brief Encode Indexed Field Line with Post-Base Index.
 *
 * RFC 9204 Section 4.5.3: Encodes a field line that references a dynamic
 * table entry using a post-base index. The entry must have been inserted
 * at or after the Base value for this field section.
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 | 0 | 1 |  Index (4+)   |
 * +---+---+---+---+---------------+
 *
 * @param post_base_index  Post-base index to encode (0 = entry at Base)
 * @param output           Output buffer (must not be NULL)
 * @param output_size      Size of output buffer
 * @param[out] bytes_written Number of bytes written (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if output or bytes_written is NULL,
 *         QPACK_ERR_TABLE_SIZE if output buffer too small,
 *         QPACK_ERR_INTEGER if integer encoding failed
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_encode_indexed_postbase (uint64_t post_base_index,
                                     unsigned char *output,
                                     size_t output_size,
                                     size_t *bytes_written);

/**
 * @brief Decode Indexed Field Line with Post-Base Index.
 *
 * RFC 9204 Section 4.5.3: Decodes a field line that references a dynamic
 * table entry using a post-base index. The caller must verify the pattern
 * bits (0001) before calling this function.
 *
 * @param input             Input buffer (must not be NULL if input_len > 0)
 * @param input_len         Length of input buffer
 * @param[out] post_base_index Output: decoded post-base index (must not be
 * NULL)
 * @param[out] bytes_consumed  Output: bytes consumed from input (must not be
 * NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if output params are NULL,
 *         QPACK_INCOMPLETE if more data needed,
 *         QPACK_ERR_INVALID_INDEX if pattern bits are not 0001,
 *         QPACK_ERR_INTEGER if integer decoding failed
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_decode_indexed_postbase (const unsigned char *input,
                                     size_t input_len,
                                     uint64_t *post_base_index,
                                     size_t *bytes_consumed);

/**
 * @brief Validate post-base index for indexed field line.
 *
 * RFC 9204 Section 4.5.3: Validates that a post-base index is within
 * the valid range. The absolute index (base + post_base_index) must be
 * less than the current Insert Count.
 *
 * @param base             Base value for the field section
 * @param insert_count     Current Insert Count (total entries inserted)
 * @param post_base_index  Post-base index to validate
 * @return QPACK_OK if valid,
 *         QPACK_ERR_INVALID_INDEX if overflow would occur,
 *         QPACK_ERR_FUTURE_INDEX if absolute index >= insert_count
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_validate_indexed_postbase (uint64_t base,
                                       uint64_t insert_count,
                                       uint64_t post_base_index);

/**
 * @brief Convert post-base index to absolute index.
 *
 * RFC 9204 Section 3.2.6: Converts a post-base index to the corresponding
 * absolute index in the dynamic table.
 *
 * Formula: absolute = base + post_base_index
 *
 * @param base               Base value for the field section
 * @param post_base_index    Post-base index to convert
 * @param[out] absolute_index Output: resulting absolute index (must not be
 * NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if absolute_index is NULL,
 *         QPACK_ERR_INVALID_INDEX if overflow would occur
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_indexed_postbase_to_absolute (uint64_t base,
                                          uint64_t post_base_index,
                                          uint64_t *absolute_index);

/**
 * @brief Look up dynamic table entry using post-base index.
 *
 * RFC 9204 Section 4.5.3: High-level function that validates the post-base
 * index, converts it to an absolute index, and retrieves the corresponding
 * entry from the dynamic table.
 *
 * @param table             Dynamic table (must not be NULL)
 * @param base              Base value for the field section
 * @param post_base_index   Post-base index to look up
 * @param[out] name         Output: pointer to name (must not be NULL)
 * @param[out] name_len     Output: name length (must not be NULL)
 * @param[out] value        Output: pointer to value (must not be NULL)
 * @param[out] value_len    Output: value length (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if any parameter is NULL,
 *         QPACK_ERR_FUTURE_INDEX if post-base index >= (insert_count - base),
 *         QPACK_ERR_INVALID_INDEX if index out of range,
 *         QPACK_ERR_EVICTED_INDEX if entry has been evicted
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_lookup_indexed_postbase (SocketQPACK_Table_T table,
                                     uint64_t base,
                                     uint64_t post_base_index,
                                     const char **name,
                                     size_t *name_len,
                                     const char **value,
                                     size_t *value_len);

/**
 * @brief Check if first byte matches Indexed Field Line with Post-Base Index.
 *
 * RFC 9204 Section 4.5.3: Identifies the pattern 0001xxxx in the first byte.
 *
 * @param first_byte First byte of the encoded field line
 * @return true if pattern matches 0001xxxx, false otherwise
 *
 * @since 1.0.0
 */
extern bool SocketQPACK_is_indexed_postbase (uint8_t first_byte);

/* ============================================================================
 * LITERAL FIELD LINE WITH NAME REFERENCE (RFC 9204 Section 4.5.4)
 * ============================================================================
 */

/**
 * @brief Decoded Literal Field Line with Name Reference.
 *
 * RFC 9204 Section 4.5.4: Represents a field line where the name is
 * referenced from the static or dynamic table, and the value is provided
 * as a literal.
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 1 | N | T |Name Index (4+)|
 * +---+---+---+---+---------------+
 * | H |     Value Length (7+)     |
 * +---+---------------------------+
 * |  Value String (Length bytes)  |
 * +-------------------------------+
 */
typedef struct
{
  uint64_t name_index; /**< Index into static or dynamic table */
  bool is_static;      /**< T bit: true for static table, false for dynamic */
  bool never_indexed;  /**< N bit: true to prevent intermediary caching */
  bool value_huffman;  /**< H bit: true if value was Huffman-encoded */
  const char *value;   /**< Decoded value string */
  size_t value_len;    /**< Length of value string */
} SocketQPACK_LiteralNameRef;

/**
 * @brief Encode Literal Field Line with Name Reference.
 *
 * RFC 9204 Section 4.5.4: Encodes a field line where the name is referenced
 * from the static or dynamic table, and the value is provided as a literal.
 * The name index uses field-relative indexing for dynamic table references.
 *
 * @param output        Output buffer (must not be NULL)
 * @param output_size   Size of output buffer
 * @param is_static     True to reference static table, false for dynamic
 * @param name_index    Index for name lookup (static index or field-relative)
 * @param never_indexed True to set N bit (prevent intermediary caching)
 * @param value         Value string (may be NULL if value_len == 0)
 * @param value_len     Length of value string
 * @param use_huffman   True to Huffman-encode the value (if beneficial)
 * @param[out] bytes_written Number of bytes written (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if output or bytes_written is NULL,
 *         QPACK_ERR_TABLE_SIZE if output buffer too small,
 *         QPACK_ERR_INTEGER if integer encoding failed,
 *         QPACK_ERR_HUFFMAN if Huffman encoding failed
 *
 * @note For static table: name_index is 0-98 (RFC 9204 Appendix A)
 * @note For dynamic table: name_index is field-relative (0 = Base - 1)
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_encode_literal_name_ref (unsigned char *output,
                                     size_t output_size,
                                     bool is_static,
                                     uint64_t name_index,
                                     bool never_indexed,
                                     const unsigned char *value,
                                     size_t value_len,
                                     bool use_huffman,
                                     size_t *bytes_written);

/**
 * @brief Decode Literal Field Line with Name Reference.
 *
 * RFC 9204 Section 4.5.4: Decodes a field line with name reference from
 * an encoded field section. Validates the bit pattern and extracts the
 * name index, N bit, T bit, and value.
 *
 * @param input         Input buffer containing the encoded field line
 * @param input_len     Length of input buffer
 * @param[out] result   Decoded field line (must not be NULL)
 * @param[out] consumed Number of bytes consumed from input (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if result or consumed is NULL,
 *         QPACK_INCOMPLETE if more data needed,
 *         QPACK_ERR_INTEGER if integer decoding failed,
 *         QPACK_ERR_HUFFMAN if Huffman decoding failed
 *
 * @note The value pointer in result points into the input buffer for
 *       literal values, or to dynamically decoded data for Huffman values.
 *       For Huffman values, the caller must provide an arena for allocation.
 * @note First byte must match pattern 01xx (bits 7-6 = 01)
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_decode_literal_name_ref (const unsigned char *input,
                                     size_t input_len,
                                     SocketQPACK_LiteralNameRef *result,
                                     size_t *consumed);

/**
 * @brief Decode Literal Field Line with Name Reference (with Huffman support).
 *
 * RFC 9204 Section 4.5.4: Extended version that provides arena for Huffman
 * decoding of the value string.
 *
 * @param input         Input buffer containing the encoded field line
 * @param input_len     Length of input buffer
 * @param arena         Memory arena for Huffman decoding (must not be NULL)
 * @param[out] result   Decoded field line (must not be NULL)
 * @param[out] consumed Number of bytes consumed from input (must not be NULL)
 * @return QPACK_OK on success, error code on failure
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_decode_literal_name_ref_arena (const unsigned char *input,
                                           size_t input_len,
                                           Arena_T arena,
                                           SocketQPACK_LiteralNameRef *result,
                                           size_t *consumed);

/**
 * @brief Validate name index for Literal Field Line with Name Reference.
 *
 * RFC 9204 Section 4.5.4: Validates that a name index is valid for use
 * in a Literal Field Line with Name Reference instruction.
 *
 * @param is_static       True if referencing static table
 * @param name_index      Index to validate (static or field-relative)
 * @param base            Base value for field-relative indexing
 * @param dropped_count   Number of evicted entries (for dynamic table)
 * @return QPACK_OK if index is valid,
 *         QPACK_ERR_INVALID_INDEX if static index >= 99,
 *         QPACK_ERR_INVALID_INDEX if dynamic index is out of bounds,
 *         QPACK_ERR_EVICTED_INDEX if dynamic entry has been evicted
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_validate_literal_name_ref_index (bool is_static,
                                             uint64_t name_index,
                                             uint64_t base,
                                             uint64_t dropped_count);

/**
 * @brief Resolve name from Literal Field Line with Name Reference.
 *
 * RFC 9204 Section 4.5.4: Looks up the name string from the static or
 * dynamic table based on the decoded name index.
 *
 * @param is_static    True if name is in static table
 * @param name_index   Index from decoded field line (static or field-relative)
 * @param base         Base value for field-relative indexing
 * @param table        Dynamic table (may be NULL if is_static is true)
 * @param[out] name    Output: pointer to name string (must not be NULL)
 * @param[out] name_len Output: length of name string (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if name or name_len is NULL,
 *         QPACK_ERR_INVALID_INDEX if index is out of bounds,
 *         QPACK_ERR_EVICTED_INDEX if dynamic entry has been evicted
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_resolve_literal_name_ref (bool is_static,
                                      uint64_t name_index,
                                      uint64_t base,
                                      SocketQPACK_Table_T table,
                                      const char **name,
                                      size_t *name_len);

/* ============================================================================
 * LITERAL FIELD LINE WITH LITERAL NAME (RFC 9204 Section 4.5.6)
 * ============================================================================
 */

/**
 * @brief Decoded Literal Field Line with Literal Name.
 *
 * RFC 9204 Section 4.5.6: Represents the decoded form of a field line
 * where both name and value are encoded as string literals.
 */
typedef struct
{
  const unsigned char *name;  /**< Field name (points into decoded buffer) */
  size_t name_len;            /**< Length of name string */
  const unsigned char *value; /**< Field value (points into decoded buffer) */
  size_t value_len;           /**< Length of value string */
  bool never_indexed; /**< N bit: field must not be added to dynamic table */
} SocketQPACK_LiteralFieldLine;

/**
 * @brief Encode Literal Field Line with Literal Name.
 *
 * RFC 9204 Section 4.5.6: Encodes a field line where both the field name
 * and value are represented as string literals. This is the most general
 * encoding form in QPACK.
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 | 1 | N | H |NameLen(3+)|
 * +---+---+---+---+---+-----------+
 * |  Name String (Length bytes)   |
 * +---+---------------------------+
 * | H |     Value Length (7+)     |
 * +---+---------------------------+
 * |  Value String (Length bytes)  |
 * +-------------------------------+
 *
 * @param output         Output buffer (must not be NULL)
 * @param output_size    Size of output buffer
 * @param name           Field name (must not be NULL if name_len > 0)
 * @param name_len       Length of name string
 * @param name_huffman   true to Huffman-encode the name (if beneficial)
 * @param value          Field value (must not be NULL if value_len > 0)
 * @param value_len      Length of value string
 * @param value_huffman  true to Huffman-encode the value (if beneficial)
 * @param never_indexed  true if field must not be added to dynamic table
 * @param[out] bytes_written Number of bytes written (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if required parameter is NULL,
 *         QPACK_ERR_TABLE_SIZE if output buffer is too small,
 *         QPACK_ERR_HUFFMAN if Huffman encoding failed,
 *         QPACK_ERR_INTEGER if integer encoding failed
 *
 * @note The N bit (never_indexed) is critical for sensitive headers like
 *       passwords, tokens, and cookies. When set, the field MUST NOT be
 *       added to the dynamic table.
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_encode_literal_field_literal_name (unsigned char *output,
                                               size_t output_size,
                                               const unsigned char *name,
                                               size_t name_len,
                                               bool name_huffman,
                                               const unsigned char *value,
                                               size_t value_len,
                                               bool value_huffman,
                                               bool never_indexed,
                                               size_t *bytes_written);

/**
 * @brief Decode Literal Field Line with Literal Name.
 *
 * RFC 9204 Section 4.5.6: Decodes a field line where both name and value
 * are encoded as string literals. The decoded strings are written to the
 * provided output buffers.
 *
 * @param input           Input buffer (must not be NULL if input_len > 0)
 * @param input_len       Length of input buffer
 * @param name_out        Output buffer for decoded name (must not be NULL)
 * @param name_out_size   Size of name output buffer
 * @param[out] name_len   Output: actual name length (must not be NULL)
 * @param value_out       Output buffer for decoded value (must not be NULL)
 * @param value_out_size  Size of value output buffer
 * @param[out] value_len  Output: actual value length (must not be NULL)
 * @param[out] never_indexed Output: N bit value (must not be NULL)
 * @param[out] bytes_consumed Number of bytes consumed (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if required parameter is NULL,
 *         QPACK_INCOMPLETE if more data needed,
 *         QPACK_ERR_HUFFMAN if Huffman decoding failed,
 *         QPACK_ERR_INTEGER if integer decoding failed,
 *         QPACK_ERR_HEADER_SIZE if output buffer is too small
 *
 * @note The first byte must have pattern 001xxxxx (bits 7-5).
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_decode_literal_field_literal_name (const unsigned char *input,
                                               size_t input_len,
                                               unsigned char *name_out,
                                               size_t name_out_size,
                                               size_t *name_len,
                                               unsigned char *value_out,
                                               size_t value_out_size,
                                               size_t *value_len,
                                               bool *never_indexed,
                                               size_t *bytes_consumed);

/**
 * @brief Validate Literal Field Line with Literal Name pattern.
 *
 * RFC 9204 Section 4.5.6: Checks if the first byte has the correct
 * pattern bits (001) for a Literal Field Line with Literal Name instruction.
 *
 * @param first_byte First byte of the instruction
 * @return true if pattern matches 001xxxxx, false otherwise
 *
 * @since 1.0.0
 */
extern bool SocketQPACK_is_literal_field_literal_name (uint8_t first_byte);

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

/* ============================================================================
 * LITERAL FIELD LINE WITH POST-BASE NAME REFERENCE (RFC 9204 Section 4.5.5)
 * ============================================================================
 */

/**
 * @brief Decoded Literal Field Line with Post-Base Name Reference.
 *
 * RFC 9204 Section 4.5.5: Represents a literal field line where the name
 * is taken from a post-base dynamic table entry (an entry inserted during
 * the encoding of the current field section, after the Base index).
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 | 0 | 0 | N |NameIdx(3+)|
 * +---+---+---+---+---+-----------+
 * | H |     Value Length (7+)     |
 * +---+---------------------------+
 * |  Value String (Length bytes)  |
 * +-------------------------------+
 */
typedef struct
{
  uint64_t name_index;        /**< Post-base index (3-bit prefix) */
  int never_index;            /**< N bit: 1 = never index this field */
  int value_huffman;          /**< H bit: 1 = value is Huffman-encoded */
  const unsigned char *value; /**< Value string (points into input buffer) */
  size_t value_len;           /**< Length of value string */
} SocketQPACK_LiteralPostBaseName;

/**
 * @brief Encode Literal Field Line with Post-Base Name Reference.
 *
 * RFC 9204 Section 4.5.5: Encodes a literal field line where the name
 * is referenced from a post-base dynamic table entry (an entry with
 * absolute index >= Base).
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 | 0 | 0 | N |NameIdx(3+)|
 * +---+---+---+---+---+-----------+
 * | H |     Value Length (7+)     |
 * +---+---------------------------+
 * |  Value String (Length bytes)  |
 * +-------------------------------+
 *
 * @param output        Output buffer (must not be NULL)
 * @param output_size   Size of output buffer
 * @param name_index    Post-base index (relative to Base)
 * @param never_index   N bit: 1 to indicate this field should never be indexed
 * @param value         Value string (may be NULL if value_len == 0)
 * @param value_len     Length of value string
 * @param use_huffman   True to Huffman-encode the value
 * @param[out] bytes_written Number of bytes written (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if output or bytes_written is NULL,
 *         QPACK_ERR_INTEGER if integer encoding failed,
 *         QPACK_ERR_HUFFMAN if Huffman encoding failed,
 *         QPACK_ERR_TABLE_SIZE if output buffer is too small
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_encode_literal_postbase_name (unsigned char *output,
                                          size_t output_size,
                                          uint64_t name_index,
                                          int never_index,
                                          const unsigned char *value,
                                          size_t value_len,
                                          int use_huffman,
                                          size_t *bytes_written);

/**
 * @brief Decode Literal Field Line with Post-Base Name Reference.
 *
 * RFC 9204 Section 4.5.5: Decodes a literal field line with post-base
 * name reference from the input buffer.
 *
 * @param input         Input buffer (must not be NULL if input_len > 0)
 * @param input_len     Length of input buffer
 * @param arena         Memory arena for Huffman decoding (must not be NULL)
 * @param[out] result   Decoded field line (must not be NULL)
 * @param[out] consumed Number of bytes consumed (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if required parameters are NULL,
 *         QPACK_INCOMPLETE if more data needed,
 *         QPACK_ERR_INTEGER if integer decoding failed,
 *         QPACK_ERR_HUFFMAN if Huffman decoding failed
 *
 * @note The first byte must have pattern 0000xxxx (bits 7-4 = 0)
 * @note The value pointer is valid until arena is disposed
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_decode_literal_postbase_name (
    const unsigned char *input,
    size_t input_len,
    Arena_T arena,
    SocketQPACK_LiteralPostBaseName *result,
    size_t *consumed);

/**
 * @brief Validate post-base name index for Literal Field Line.
 *
 * RFC 9204 Section 4.5.5: Validates that a post-base name index is valid
 * for use in a Literal Field Line with Post-Base Name Reference.
 *
 * For a post-base reference to be valid:
 * 1. The absolute index (base + post_base_index) must be < insert_count
 * 2. The post_base_index must not cause integer overflow when added to base
 *
 * @param base          Base value from the field section prefix
 * @param insert_count  Current Insert Count (total entries inserted)
 * @param post_base_idx Post-base index to validate
 * @return QPACK_OK if valid,
 *         QPACK_ERR_FUTURE_INDEX if index references a not-yet-inserted entry,
 *         QPACK_ERR_INVALID_INDEX if integer overflow would occur
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_validate_literal_postbase_index (uint64_t base,
                                             uint64_t insert_count,
                                             uint64_t post_base_idx);

/**
 * @brief Resolve post-base name reference to header name.
 *
 * RFC 9204 Section 4.5.5: Resolves a post-base name index to the actual
 * header name by looking up the dynamic table entry.
 *
 * @param table         Dynamic table (must not be NULL)
 * @param base          Base value from field section prefix
 * @param post_base_idx Post-base index from the literal field line
 * @param[out] name     Output: pointer to name string (must not be NULL)
 * @param[out] name_len Output: length of name string (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if any required parameter is NULL,
 *         QPACK_ERR_FUTURE_INDEX if index references future entry,
 *         QPACK_ERR_EVICTED_INDEX if entry has been evicted
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_resolve_postbase_name (SocketQPACK_Table_T table,
                                   uint64_t base,
                                   uint64_t post_base_idx,
                                   const char **name,
                                   size_t *name_len);

/* ============================================================================
 * BLOCKED STREAM MANAGEMENT (RFC 9204 Sections 2.1.2, 2.2.1)
 * ============================================================================
 */

/**
 * @brief Opaque type for blocked stream manager.
 *
 * RFC 9204 Section 2.2.1: Manages blocked field sections for a QPACK decoder.
 */
typedef struct SocketQPACK_BlockedManager *SocketQPACK_BlockedManager_T;

/**
 * @brief Blocked stream management result codes.
 *
 * Extended result codes specific to blocked stream operations.
 */
typedef enum
{
  QPACK_BLOCKED_OK = 0,          /**< Operation successful */
  QPACK_BLOCKED_WOULD_BLOCK,     /**< Reserved: stream would block (RIC > IC) */
  QPACK_BLOCKED_LIMIT_STREAMS,   /**< max_blocked_streams limit exceeded */
  QPACK_BLOCKED_LIMIT_BYTES,     /**< max_blocked_bytes limit exceeded */
  QPACK_BLOCKED_ERR_NULL_PARAM,  /**< NULL parameter passed */
  QPACK_BLOCKED_ERR_NOT_FOUND,   /**< Stream not found in blocked queue */
  QPACK_BLOCKED_ERR_INTERNAL,    /**< Internal error (allocation, callback) */
  QPACK_BLOCKED_ERR_INVALID_RIC, /**< Invalid Required Insert Count */
  QPACK_BLOCKED_ERR_SECTION_LIMIT /**< Per-stream section limit exceeded */
} SocketQPACK_BlockedResult;

/**
 * @brief Configuration for blocked stream manager.
 *
 * RFC 9204 Section 5: Configuration limits for blocked stream management.
 */
typedef struct
{
  size_t
      max_blocked_streams; /**< SETTINGS_QPACK_BLOCKED_STREAMS (default: 100) */
  size_t max_blocked_bytes; /**< Max total bytes in blocked queues */
} SocketQPACK_BlockedConfig;

/**
 * @brief Callback for processing unblocked field sections.
 *
 * Called when a blocked field section becomes unblocked due to the
 * dynamic table insert count advancing.
 *
 * @param stream_id  HTTP/3 stream ID of the unblocked field section
 * @param data       Compressed field section data
 * @param data_len   Length of compressed data
 * @param ric        Required Insert Count for this section
 * @param user_data  User-provided callback context
 * @return 0 on success, non-zero to stop processing further sections
 */
typedef int (*SocketQPACK_UnblockCallback) (uint64_t stream_id,
                                            const unsigned char *data,
                                            size_t data_len,
                                            uint64_t ric,
                                            void *user_data);

/**
 * @brief Create a new blocked stream manager.
 *
 * RFC 9204 Section 2.2.1: Creates a manager for tracking blocked streams
 * in a QPACK decoder. The manager handles queueing, unblocking, and
 * resource limits.
 *
 * @param arena  Memory arena for allocations (must not be NULL)
 * @param config Configuration for limits (NULL for defaults)
 * @return New blocked manager instance, or NULL on allocation failure
 *
 * @since 1.0.0
 */
extern SocketQPACK_BlockedManager_T
SocketQPACK_BlockedManager_new (Arena_T arena,
                                const SocketQPACK_BlockedConfig *config);

/**
 * @brief Test if a field section would block.
 *
 * RFC 9204 Section 2.2.1: Determines if decoding a field section with
 * the given Required Insert Count would block, based on the current
 * Insert Count.
 *
 * @param required_insert_count RIC from field section prefix
 * @param current_insert_count  Decoder's current Insert Count
 * @return true if RIC > current_insert_count (would block), false otherwise
 *
 * @since 1.0.0
 */
extern bool SocketQPACK_would_block (uint64_t required_insert_count,
                                     uint64_t current_insert_count);

/**
 * @brief Queue a field section for a blocked stream.
 *
 * RFC 9204 Section 2.2.1: Queues compressed field section data when the
 * Required Insert Count > Insert Count. The data is copied and stored
 * until the insert count advances sufficiently.
 *
 * @param manager    Blocked stream manager (must not be NULL)
 * @param stream_id  HTTP/3 stream ID for this field section
 * @param ric        Required Insert Count from prefix
 * @param data       Compressed field section data (must not be NULL if len > 0)
 * @param data_len   Length of compressed data
 * @return QPACK_BLOCKED_OK on success,
 *         QPACK_BLOCKED_LIMIT_STREAMS if max_blocked_streams exceeded,
 *         QPACK_BLOCKED_LIMIT_BYTES if max_blocked_bytes exceeded,
 *         QPACK_BLOCKED_ERR_NULL_PARAM if manager is NULL,
 *         QPACK_BLOCKED_ERR_INTERNAL on allocation failure
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_BlockedResult
SocketQPACK_queue_blocked (SocketQPACK_BlockedManager_T manager,
                           uint64_t stream_id,
                           uint64_t ric,
                           const unsigned char *data,
                           size_t data_len);

/**
 * @brief Process all unblocked streams.
 *
 * RFC 9204 Section 2.2.1: Checks all blocked streams and processes those
 * whose Required Insert Count is now <= the current Insert Count. Invokes
 * the callback for each unblocked field section in FIFO order per stream.
 *
 * @param manager              Blocked stream manager (must not be NULL)
 * @param current_insert_count Decoder's current Insert Count
 * @param callback             Callback for processing unblocked sections
 * @param user_data            User context passed to callback
 * @param[out] unblocked_count Output: number of sections unblocked (may be
 * NULL)
 * @return QPACK_BLOCKED_OK on success,
 *         QPACK_BLOCKED_ERR_NULL_PARAM if manager or callback is NULL,
 *         QPACK_BLOCKED_ERR_INTERNAL on callback failure
 *
 * @note This function should be called after each dynamic table insert
 *       to trigger automatic unblocking.
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_BlockedResult
SocketQPACK_process_unblocked (SocketQPACK_BlockedManager_T manager,
                               uint64_t current_insert_count,
                               SocketQPACK_UnblockCallback callback,
                               void *user_data,
                               size_t *unblocked_count);

/**
 * @brief Cancel a blocked stream.
 *
 * RFC 9204 Section 4.4.2: Removes all queued field sections for a stream.
 * Called when an HTTP/3 stream is cancelled or reset.
 *
 * @param manager   Blocked stream manager (must not be NULL)
 * @param stream_id HTTP/3 stream ID to cancel
 * @return QPACK_BLOCKED_OK on success (even if stream was not blocked),
 *         QPACK_BLOCKED_ERR_NULL_PARAM if manager is NULL
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_BlockedResult
SocketQPACK_cancel_blocked_stream (SocketQPACK_BlockedManager_T manager,
                                   uint64_t stream_id);

/**
 * @brief Get the current count of blocked streams.
 *
 * @param manager Blocked stream manager
 * @return Number of streams currently blocked, 0 if manager is NULL
 *
 * @since 1.0.0
 */
extern size_t
SocketQPACK_get_blocked_stream_count (SocketQPACK_BlockedManager_T manager);

/**
 * @brief Get the total bytes queued across all blocked streams.
 *
 * @param manager Blocked stream manager
 * @return Total bytes in blocked queues, 0 if manager is NULL
 *
 * @since 1.0.0
 */
extern size_t
SocketQPACK_get_blocked_bytes (SocketQPACK_BlockedManager_T manager);

/**
 * @brief Get the peak blocked stream count (for monitoring).
 *
 * @param manager Blocked stream manager
 * @return Peak number of simultaneously blocked streams, 0 if manager is NULL
 *
 * @since 1.0.0
 */
extern uint64_t
SocketQPACK_get_peak_blocked_count (SocketQPACK_BlockedManager_T manager);

/**
 * @brief Get the total unblock count (for monitoring).
 *
 * @param manager Blocked stream manager
 * @return Total number of field sections unblocked, 0 if manager is NULL
 *
 * @since 1.0.0
 */
extern uint64_t
SocketQPACK_get_total_unblock_count (SocketQPACK_BlockedManager_T manager);

/**
 * @brief Check if a specific stream is currently blocked.
 *
 * @param manager   Blocked stream manager
 * @param stream_id HTTP/3 stream ID to check
 * @return true if stream has queued blocked sections, false otherwise
 *
 * @since 1.0.0
 */
extern bool SocketQPACK_is_stream_blocked (SocketQPACK_BlockedManager_T manager,
                                           uint64_t stream_id);

/**
 * @brief Get the minimum Required Insert Count across all blocked streams.
 *
 * Used to determine the earliest insert count that would unblock at least
 * one stream.
 *
 * @param manager Blocked stream manager
 * @return Minimum RIC across all blocked sections, or 0 if no streams blocked
 *
 * @since 1.0.0
 */
extern uint64_t
SocketQPACK_get_min_blocked_ric (SocketQPACK_BlockedManager_T manager);

/**
 * @brief Get human-readable string for blocked result code.
 *
 * @param result Result code to describe
 * @return Static string describing the result (never NULL)
 *
 * @since 1.0.0
 */
extern const char *
SocketQPACK_blocked_result_string (SocketQPACK_BlockedResult result);

/* ============================================================================
 * QPACK ENCODER (RFC 9204 Section 2.1.4)
 *
 * Encoder state management with Known Received Count tracking. The encoder
 * tracks which dynamic table entries have been acknowledged by the decoder.
 * ============================================================================
 */

/**
 * @brief Opaque type for QPACK encoder state.
 *
 * RFC 9204 Section 2.1.4: The encoder maintains the Known Received Count (KRC)
 * to track which dynamic table entries are safe to reference. Entries with
 * absolute index < KRC can be safely used in non-blocking representations.
 */
typedef struct SocketQPACK_Encoder *SocketQPACK_Encoder_T;

/**
 * @brief Create a new QPACK encoder.
 *
 * Allocates encoder state including dynamic table and acknowledgment tracking.
 *
 * @param arena          Memory arena for allocations (must not be NULL)
 * @param max_table_size Maximum dynamic table size in bytes
 * @return New encoder instance, or NULL on allocation failure
 *
 * @since 1.0.0
 */
extern SocketQPACK_Encoder_T
SocketQPACK_Encoder_new (Arena_T arena, size_t max_table_size);

/**
 * @brief Get the current Known Received Count.
 *
 * RFC 9204 Section 2.1.4: The Known Received Count is the maximum insert count
 * that the encoder knows the decoder has received and processed.
 *
 * @param encoder Encoder state (must not be NULL)
 * @return Current KRC value, or 0 if encoder is NULL
 *
 * @since 1.0.0
 */
extern uint64_t
SocketQPACK_Encoder_known_received_count (SocketQPACK_Encoder_T encoder);

/**
 * @brief Check if an absolute index is acknowledged (safe to reference).
 *
 * RFC 9204 Section 2.1.4: An entry with absolute_index < KRC can be safely
 * referenced in non-blocking representation because the encoder knows the
 * decoder has received the corresponding insertion instruction.
 *
 * @param encoder       Encoder state
 * @param absolute_index Absolute index to check
 * @return true if index < KRC (safe to reference), false otherwise
 *
 * @since 1.0.0
 */
extern bool SocketQPACK_Encoder_is_acknowledged (SocketQPACK_Encoder_T encoder,
                                                 uint64_t absolute_index);

/**
 * @brief Process Section Acknowledgment from decoder.
 *
 * RFC 9204 Section 4.4.1: When the decoder processes a field section with
 * non-zero Required Insert Count, it sends a Section Acknowledgment. This
 * updates the encoder's Known Received Count.
 *
 * @param encoder   Encoder state (must not be NULL)
 * @param stream_id Stream ID from Section Acknowledgment instruction
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if encoder is NULL,
 *         QPACK_ERR_INVALID_INDEX if stream has no pending acknowledgment
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result SocketQPACK_Encoder_on_section_ack (
    SocketQPACK_Encoder_T encoder, uint64_t stream_id);

/**
 * @brief Process Insert Count Increment from decoder.
 *
 * RFC 9204 Section 4.4.3: The decoder can directly increment the encoder's
 * Known Received Count to signal that it has received dynamic table entries.
 *
 * @param encoder   Encoder state (must not be NULL)
 * @param increment Number of entries to add to KRC (must be > 0)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if encoder is NULL,
 *         QPACK_ERR_INVALID_INDEX if increment is 0 or would exceed
 * insert_count
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_Encoder_on_insert_count_inc (SocketQPACK_Encoder_T encoder,
                                         uint64_t increment);

/**
 * @brief Process Stream Cancellation from decoder.
 *
 * RFC 9204 Section 4.4.2: When the decoder cancels a stream, the encoder
 * removes any pending acknowledgment for that stream without updating KRC.
 *
 * @param encoder   Encoder state (must not be NULL)
 * @param stream_id Stream ID from Stream Cancellation instruction
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if encoder is NULL
 *
 * @note Cancelling an unknown stream is not an error (idempotent)
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_Encoder_on_stream_cancel (SocketQPACK_Encoder_T encoder,
                                      uint64_t stream_id);

/**
 * @brief Register a field section for acknowledgment tracking.
 *
 * Called when encoding a field section that references dynamic table entries.
 * The encoder tracks the Required Insert Count for each stream to update
 * Known Received Count when the Section Acknowledgment is received.
 *
 * @param encoder               Encoder state (must not be NULL)
 * @param stream_id             Stream ID carrying the field section
 * @param required_insert_count Required Insert Count for this field section
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if encoder is NULL,
 *         QPACK_ERR_TABLE_SIZE if pending tracking limit exceeded
 *
 * @note Only sections with RIC > 0 need to be registered
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_Encoder_register_section (SocketQPACK_Encoder_T encoder,
                                      uint64_t stream_id,
                                      uint64_t required_insert_count);

/**
 * @brief Get the encoder's dynamic table.
 *
 * @param encoder Encoder state
 * @return Dynamic table, or NULL if encoder is NULL
 *
 * @since 1.0.0
 */
extern SocketQPACK_Table_T
SocketQPACK_Encoder_get_table (SocketQPACK_Encoder_T encoder);

/**
 * @brief Get the current Insert Count.
 *
 * RFC 9204 Section 3.2.4: The Insert Count is the total number of entries
 * ever inserted into the dynamic table (monotonically increasing).
 *
 * @param encoder Encoder state
 * @return Current insert count, or 0 if encoder is NULL
 *
 * @since 1.0.0
 */
extern uint64_t
SocketQPACK_Encoder_insert_count (SocketQPACK_Encoder_T encoder);

/* ============================================================================
 * QPACK CONFIGURATION (RFC 9204 Section 5)
 * ============================================================================
 */

/**
 * @brief Initialize settings to RFC 9204 defaults.
 *
 * RFC 9204 Section 5: Both settings default to 0.
 *
 * @param[out] settings Settings structure to initialize
 * @return QPACK_OK on success, QPACK_ERR_NULL_PARAM if settings is NULL
 *
 * @since 1.0.0
 */
extern SocketQPACK_Result
SocketQPACK_settings_defaults (SocketQPACK_Settings *settings);

/**
 * @brief Validate received settings values.
 *
 * RFC 9204 Section 5: Validates settings are within acceptable bounds.
 * All valid uint64_t values are accepted per RFC (no upper limit specified).
 *
 * @param settings Settings to validate
 * @return QPACK_OK if valid, QPACK_ERR_NULL_PARAM if settings is NULL
 *
 * @since 1.0.0
 */
extern SocketQPACK_Result
SocketQPACK_settings_validate (const SocketQPACK_Settings *settings);

/**
 * @brief Create new QPACK configuration.
 *
 * Creates configuration with default local settings (0, 0).
 *
 * @param arena Memory arena for allocations (must not be NULL)
 * @return New config instance, or NULL on failure
 *
 * @since 1.0.0
 */
extern SocketQPACK_Config_T SocketQPACK_Config_new (Arena_T arena);

/**
 * @brief Set local settings (what we advertise to peer).
 *
 * @param config Configuration instance (must not be NULL)
 * @param settings Local settings to set (must not be NULL)
 * @return QPACK_OK on success, QPACK_ERR_NULL_PARAM if parameters are NULL
 *
 * @since 1.0.0
 */
extern SocketQPACK_Result
SocketQPACK_Config_set_local (SocketQPACK_Config_T config,
                              const SocketQPACK_Settings *settings);

/**
 * @brief Get local settings.
 *
 * @param config Configuration instance (must not be NULL)
 * @param[out] settings Output for local settings (must not be NULL)
 * @return QPACK_OK on success, QPACK_ERR_NULL_PARAM if parameters are NULL
 *
 * @since 1.0.0
 */
extern SocketQPACK_Result
SocketQPACK_Config_get_local (SocketQPACK_Config_T config,
                              SocketQPACK_Settings *settings);

/**
 * @brief Apply received peer settings.
 *
 * RFC 9204 Section 5: Validates and applies peer's settings.
 * Updates encoder's max table capacity and decoder's blocked stream limit.
 *
 * @param config Configuration instance (must not be NULL)
 * @param settings Peer's settings from SETTINGS frame (must not be NULL)
 * @return QPACK_OK on success, QPACK_ERR_NULL_PARAM if parameters are NULL
 *
 * @since 1.0.0
 */
extern SocketQPACK_Result
SocketQPACK_Config_apply_peer (SocketQPACK_Config_T config,
                               const SocketQPACK_Settings *settings);

/**
 * @brief Get peer settings.
 *
 * @param config Configuration instance (must not be NULL)
 * @param[out] settings Output for peer settings (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if parameters are NULL,
 *         QPACK_ERR_INTERNAL if peer settings not yet received
 *
 * @since 1.0.0
 */
extern SocketQPACK_Result
SocketQPACK_Config_get_peer (SocketQPACK_Config_T config,
                             SocketQPACK_Settings *settings);

/**
 * @brief Check if peer settings have been received.
 *
 * @param config Configuration instance
 * @return true if apply_peer has been called, false otherwise or if NULL
 *
 * @since 1.0.0
 */
extern bool SocketQPACK_Config_has_peer_settings (SocketQPACK_Config_T config);

/**
 * @brief Store settings for 0-RTT resumption.
 *
 * RFC 9204 Section 3.2.3: Saves settings for use with early data encoding.
 *
 * @param config Configuration instance (must not be NULL)
 * @param settings Settings to store for resumption (must not be NULL)
 * @return QPACK_OK on success, QPACK_ERR_NULL_PARAM if parameters are NULL
 *
 * @since 1.0.0
 */
extern SocketQPACK_Result
SocketQPACK_Config_store_for_0rtt (SocketQPACK_Config_T config,
                                   const SocketQPACK_Settings *settings);

/**
 * @brief Get stored 0-RTT settings.
 *
 * RFC 9204 Section 3.2.3: Retrieves settings for early data encoding.
 *
 * @param config Configuration instance (must not be NULL)
 * @param[out] settings Output for stored settings (must not be NULL)
 * @return QPACK_OK on success,
 *         QPACK_ERR_NULL_PARAM if parameters are NULL,
 *         QPACK_ERR_INTERNAL if no 0-RTT settings stored
 *
 * @since 1.0.0
 */
extern SocketQPACK_Result
SocketQPACK_Config_get_0rtt (SocketQPACK_Config_T config,
                             SocketQPACK_Settings *settings);

/**
 * @brief Validate 0-RTT settings after handshake.
 *
 * RFC 9204 Section 3.2.3: If stored 0-RTT max_table_capacity > 0,
 * peer MUST send the same value. Returns error if mismatch.
 *
 * @param config Configuration instance (must not be NULL)
 * @param peer_settings Peer's actual settings after handshake (must not be
 * NULL)
 * @return QPACK_OK if valid (no 0-RTT stored, or values match, or 0-RTT was 0),
 *         QPACK_ERR_NULL_PARAM if parameters are NULL,
 *         QPACK_ERR_INTERNAL if 0-RTT max_table_capacity > 0 and peer differs
 *
 * @since 1.0.0
 */
extern SocketQPACK_Result
SocketQPACK_Config_validate_0rtt (SocketQPACK_Config_T config,
                                  const SocketQPACK_Settings *peer_settings);

/**
 * @brief Get human-readable string for settings identifier.
 *
 * @param setting_id SETTINGS identifier (0x01 or 0x07)
 * @return Static string describing the setting, or "UNKNOWN" if invalid
 *
 * @since 1.0.0
 */
extern const char *SocketQPACK_settings_id_string (uint64_t setting_id);

/** @} */

#endif /* SOCKETQPACK_INCLUDED */

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
#define QPACK_WARN_UNUSED __attribute__((warn_unused_result))
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
  QPACK_ERR_INTERNAL       /**< Internal error */
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
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_abs_to_relative_field (uint64_t base,
                                   uint64_t abs_index,
                                   uint64_t *rel_out);

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
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_relative_to_abs_field (uint64_t base,
                                   uint64_t rel_index,
                                   uint64_t *abs_out);

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
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_abs_to_postbase (uint64_t base,
                             uint64_t abs_index,
                             uint64_t *pb_out);

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
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_postbase_to_abs (uint64_t base,
                             uint64_t pb_index,
                             uint64_t *abs_out);

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
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_is_valid_postbase (uint64_t base,
                               uint64_t insert_count,
                               uint64_t pb_index);

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
extern QPACK_WARN_UNUSED SocketQPACK_Result
SocketQPACK_is_valid_absolute (uint64_t insert_count,
                               uint64_t dropped_count,
                               uint64_t abs_index);

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

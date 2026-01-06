/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-private.h
 * @brief Internal QPACK header compression structures (RFC 9204).
 * @internal
 *
 * Private implementation for QPACK field line representations.
 * QPACK is used for HTTP/3 header compression over QUIC.
 */

#ifndef SOCKETQPACK_PRIVATE_INCLUDED
#define SOCKETQPACK_PRIVATE_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "core/Arena.h"

/* ============================================================================
 * QPACK Constants (RFC 9204)
 * ============================================================================
 */

/** QPACK static table size (0-98 inclusive, RFC 9204 Appendix A) */
#define QPACK_STATIC_TABLE_SIZE 99

/** Minimum static index (RFC 9204 Section 3.1) */
#define QPACK_STATIC_INDEX_MIN 0

/** Maximum static index (RFC 9204 Section 3.1) */
#define QPACK_STATIC_INDEX_MAX 98

/** Indexed Field Line bit pattern: 1T followed by 6-bit index */
#define QPACK_INDEXED_FIELD_MASK 0x80

/** Type bit for static table in Indexed Field Line */
#define QPACK_INDEXED_STATIC_BIT 0x40

/** Prefix bits for indexed field index (6-bit prefix) */
#define QPACK_INDEXED_PREFIX_BITS 6

/* ============================================================================
 * QPACK Error Codes
 * ============================================================================
 */

typedef enum
{
  QPACK_OK = 0,
  QPACK_INCOMPLETE,
  QPACK_ERROR,
  QPACK_ERROR_INVALID_INDEX,
  QPACK_ERROR_INDEX_OUT_OF_RANGE_STATIC,
  QPACK_ERROR_INDEX_OUT_OF_RANGE_DYNAMIC,
  QPACK_ERROR_BASE_NOT_SET,
  QPACK_ERROR_INTEGER_OVERFLOW
} QPACK_Result;

/* ============================================================================
 * QPACK Representation Types (RFC 9204 Section 4.5)
 * ============================================================================
 */

typedef enum
{
  QPACK_REP_INDEXED = 0,          /**< Indexed Field Line (Section 4.5.2) */
  QPACK_REP_LITERAL_NAME = 1,     /**< Literal with name reference */
  QPACK_REP_LITERAL_VALUE = 2,    /**< Literal with literal name */
  QPACK_REP_INDEXED_POST_BASE = 3 /**< Indexed with post-base index */
} QPACK_RepresentationType;

/* ============================================================================
 * QPACK Representation Structure
 * ============================================================================
 */

/**
 * @brief QPACK field line representation.
 *
 * Represents a decoded QPACK field line with its type, index information,
 * and table reference type.
 */
typedef struct QPACK_Representation_T *QPACK_Representation_T;

struct QPACK_Representation_T
{
  QPACK_RepresentationType type; /**< Representation type */
  uint32_t index; /**< Static table index (0-98) or relative dynamic index */
  int is_static;  /**< 1 if static table, 0 if dynamic table */
  uint32_t absolute_idx; /**< Absolute index after Base conversion (dynamic) */
};

/* ============================================================================
 * QPACK Decoder Context
 * ============================================================================
 */

/**
 * @brief QPACK decoder context for field section decoding.
 *
 * Contains state needed for decoding field sections, including the Base
 * index for converting relative dynamic indices to absolute indices.
 */
typedef struct
{
  uint32_t required_insert_count; /**< Required Insert Count from prefix */
  uint32_t base;        /**< Base index for dynamic table (RFC 9204 3.2.4) */
  uint32_t max_dynamic; /**< Maximum dynamic table entries available */
  int base_is_set;      /**< Whether Base has been initialized */
} QPACK_DecoderContext;

/* ============================================================================
 * QPACK Static Table Entry
 * ============================================================================
 */

/**
 * @brief Static table entry (RFC 9204 Appendix A).
 */
typedef struct
{
  const char *name;
  const char *value;
  uint8_t name_len;
  uint8_t value_len;
} QPACK_StaticEntry;

/* ============================================================================
 * Static Table (RFC 9204 Appendix A)
 * ============================================================================
 */

extern const QPACK_StaticEntry qpack_static_table[QPACK_STATIC_TABLE_SIZE];

/* ============================================================================
 * QPACK Indexed Field Line Functions (RFC 9204 Section 4.5.2)
 * ============================================================================
 */

/**
 * @brief Encode a static table index as Indexed Field Line.
 *
 * Encodes a field from the static table using the Indexed Field Line
 * representation (pattern 1T with T=1 for static).
 *
 * @param index      Static table index (0-98)
 * @param output     Output buffer
 * @param output_len Output buffer length
 * @return Bytes written, or -1 on error
 */
ssize_t qpack_encode_indexed_static (uint32_t index,
                                     unsigned char *output,
                                     size_t output_len);

/**
 * @brief Encode a dynamic table relative index as Indexed Field Line.
 *
 * Encodes a field from the dynamic table using the Indexed Field Line
 * representation (pattern 1T with T=0 for dynamic).
 *
 * @param relative_index Relative index in dynamic table
 * @param output         Output buffer
 * @param output_len     Output buffer length
 * @return Bytes written, or -1 on error
 */
ssize_t qpack_encode_indexed_dynamic (uint32_t relative_index,
                                      unsigned char *output,
                                      size_t output_len);

/**
 * @brief Decode an Indexed Field Line representation.
 *
 * Decodes the wire format for Indexed Field Line (RFC 9204 Section 4.5.2).
 * First byte must match pattern 1T (high bit set).
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 1 | T |      Index (6+)       |
 * +---+---+-----------------------+
 *
 * @param input        Input buffer (first byte must be 0x80 or higher)
 * @param input_len    Input buffer length
 * @param ctx          Decoder context with Base for dynamic table
 * @param rep          Output representation structure
 * @param consumed     Output: bytes consumed from input
 * @return QPACK_OK on success, error code otherwise
 */
QPACK_Result qpack_decode_indexed_field (const unsigned char *input,
                                         size_t input_len,
                                         const QPACK_DecoderContext *ctx,
                                         struct QPACK_Representation_T *rep,
                                         size_t *consumed);

/**
 * @brief Validate a static table index.
 *
 * @param index Index to validate (must be 0-98)
 * @return QPACK_OK if valid, QPACK_ERROR_INDEX_OUT_OF_RANGE_STATIC otherwise
 */
QPACK_Result qpack_validate_static_index (uint32_t index);

/**
 * @brief Convert dynamic table relative index to absolute index.
 *
 * Per RFC 9204 Section 3.2.4:
 *   absolute_index = Base - 1 - relative_index
 *
 * @param relative_index Relative index from wire format
 * @param ctx            Decoder context with Base
 * @param absolute_out   Output: absolute index
 * @return QPACK_OK on success, error code otherwise
 */
QPACK_Result qpack_apply_base_offset (uint32_t relative_index,
                                      const QPACK_DecoderContext *ctx,
                                      uint32_t *absolute_out);

/**
 * @brief Get static table entry by index.
 *
 * @param index  Static table index (0-98)
 * @param entry  Output: pointer to static entry (not a copy)
 * @return QPACK_OK on success, QPACK_ERROR_INDEX_OUT_OF_RANGE_STATIC otherwise
 */
QPACK_Result qpack_static_get (uint32_t index, const QPACK_StaticEntry **entry);

/**
 * @brief Get result string for QPACK result code.
 *
 * @param result QPACK result code
 * @return Human-readable string for the result
 */
const char *qpack_result_string (QPACK_Result result);

#endif /* SOCKETQPACK_PRIVATE_INCLUDED */

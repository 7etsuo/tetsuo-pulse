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
 * (FIFO eviction), and Huffman encoding. Provides encoder/decoder instances
 * with support for:
 * - Literal Field Line with Post-Base Name Reference (Section 4.5.5)
 * - Field Section Prefix encoding/decoding (Section 4.4.3)
 * - Dynamic table indexing and management (Section 3)
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

/** RFC 9204: Static table has 99 entries (indices 0-98) */
#define SOCKETQPACK_STATIC_TABLE_SIZE 99

/** RFC 9204: Each dynamic table entry has 32-byte overhead */
#define SOCKETQPACK_ENTRY_OVERHEAD 32

/* ============================================================================
 * Result Codes
 * ============================================================================
 */

extern const Except_T SocketQPACK_Error;

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
  QPACK_ERROR_POSTBASE_INDEX /**< Post-base index >= insert_count */
} SocketQPACK_Result;

/* ============================================================================
 * Data Structures
 * ============================================================================
 */

/**
 * @brief Header representation.
 */
typedef struct
{
  const char *name;
  size_t name_len;
  const char *value;
  size_t value_len;
  int never_index; /**< If set, do not add to dynamic table */
} SocketQPACK_Header;

/**
 * @brief Field Section Prefix (RFC 9204 Section 4.4.3).
 *
 * Contains metadata for interpreting indices within a field section.
 */
typedef struct
{
  uint32_t required_insert_count; /**< Required Insert Count (RIC) */
  int32_t delta_base;             /**< Delta Base (signed) */
  uint32_t base;                  /**< Computed Base = RIC + delta_base */
  int sign_bit;                   /**< Sign bit for delta_base */
} SocketQPACK_FieldPrefix;

/**
 * @brief Literal representation for post-base/pre-base references.
 */
typedef struct
{
  int name_indexed;     /**< N=1: name-only (never index), N=0: may index */
  uint32_t name_index;  /**< Index in post-base space */
  int value_huffman;    /**< H=1: Huffman encoded, H=0: plain */
  const uint8_t *value; /**< Value bytes */
  size_t value_len;     /**< Value length */
} SocketQPACK_Literal;

/* ============================================================================
 * Dynamic Table
 * ============================================================================
 */

typedef struct SocketQPACK_Table *SocketQPACK_Table_T;

/** Create dynamic table with FIFO eviction (RFC 9204 Section 3). */
extern SocketQPACK_Table_T
SocketQPACK_Table_new (size_t max_size, Arena_T arena);

extern void SocketQPACK_Table_free (SocketQPACK_Table_T *table);

/** Update max size, evicting oldest entries if necessary. */
extern void
SocketQPACK_Table_set_max_size (SocketQPACK_Table_T table, size_t max_size);

extern size_t SocketQPACK_Table_size (SocketQPACK_Table_T table);
extern size_t SocketQPACK_Table_count (SocketQPACK_Table_T table);
extern size_t SocketQPACK_Table_max_size (SocketQPACK_Table_T table);

/** Get total insertion count (monotonically increasing). */
extern uint32_t SocketQPACK_Table_insert_count (SocketQPACK_Table_T table);

/**
 * Get entry by absolute index.
 * @param table Dynamic table
 * @param abs_index Absolute index (0 = first inserted entry)
 * @param header Output header (name/value pointers valid until table modified)
 * @return QPACK_OK on success, QPACK_ERROR_INVALID_INDEX if out of range
 */
extern SocketQPACK_Result
SocketQPACK_Table_get_absolute (SocketQPACK_Table_T table,
                                uint32_t abs_index,
                                SocketQPACK_Header *header);

/**
 * Add entry to dynamic table.
 * @return QPACK_OK on success
 */
extern SocketQPACK_Result SocketQPACK_Table_add (SocketQPACK_Table_T table,
                                                 const char *name,
                                                 size_t name_len,
                                                 const char *value,
                                                 size_t value_len);

/* ============================================================================
 * Encoder
 * ============================================================================
 */

typedef struct SocketQPACK_Encoder *SocketQPACK_Encoder_T;

typedef struct
{
  size_t max_table_size;
  int huffman_encode;
  int use_indexing;
} SocketQPACK_EncoderConfig;

extern void
SocketQPACK_encoder_config_defaults (SocketQPACK_EncoderConfig *config);

extern SocketQPACK_Encoder_T
SocketQPACK_Encoder_new (const SocketQPACK_EncoderConfig *config,
                         Arena_T arena);

extern void SocketQPACK_Encoder_free (SocketQPACK_Encoder_T *encoder);

extern SocketQPACK_Table_T
SocketQPACK_Encoder_get_table (SocketQPACK_Encoder_T encoder);

/* ============================================================================
 * Decoder
 * ============================================================================
 */

typedef struct SocketQPACK_Decoder *SocketQPACK_Decoder_T;

typedef struct
{
  size_t max_table_size;
  size_t max_header_size;
  size_t max_header_list_size;
  double max_expansion_ratio;
  size_t max_output_bytes;
} SocketQPACK_DecoderConfig;

extern void
SocketQPACK_decoder_config_defaults (SocketQPACK_DecoderConfig *config);

extern SocketQPACK_Decoder_T
SocketQPACK_Decoder_new (const SocketQPACK_DecoderConfig *config,
                         Arena_T arena);

extern void SocketQPACK_Decoder_free (SocketQPACK_Decoder_T *decoder);

extern SocketQPACK_Table_T
SocketQPACK_Decoder_get_table (SocketQPACK_Decoder_T decoder);

/* ============================================================================
 * Post-Base Name Reference Functions (RFC 9204 Section 4.5.5)
 * ============================================================================
 */

/**
 * Convert post-base index to absolute index.
 *
 * @param base Base value from field section prefix
 * @param post_base_index Post-base index (relative to base)
 * @param abs_index Output absolute index
 * @return QPACK_OK on success, QPACK_ERROR_INTEGER on overflow
 */
extern SocketQPACK_Result
SocketQPACK_postbase_to_absolute (uint32_t base,
                                  uint32_t post_base_index,
                                  uint32_t *abs_index);

/**
 * Validate post-base index against insert count.
 *
 * @param abs_index Absolute index computed from base + post_base_index
 * @param insert_count Total insertions so far
 * @return QPACK_OK if valid, QPACK_ERROR_POSTBASE_INDEX if invalid
 */
extern SocketQPACK_Result
SocketQPACK_validate_postbase_index (uint32_t abs_index, uint32_t insert_count);

/**
 * Encode literal field line with post-base name reference.
 *
 * Wire format: 0000 N xxx (4-bit pattern + N bit + 3-bit prefix)
 * Followed by: string literal value
 *
 * @param post_base_index Post-base index for name reference
 * @param never_index N=1: never index, N=0: may index
 * @param value Value string
 * @param value_len Value length
 * @param use_huffman 1 to use Huffman encoding for value
 * @param output Output buffer
 * @param output_size Output buffer size
 * @return Bytes written, or -1 on error
 */
extern ssize_t
SocketQPACK_encode_literal_postbase_name (uint32_t post_base_index,
                                          int never_index,
                                          const char *value,
                                          size_t value_len,
                                          int use_huffman,
                                          unsigned char *output,
                                          size_t output_size);

/**
 * Decode literal field line with post-base name reference.
 *
 * Expects input starting with 0000 N pattern byte.
 *
 * @param input Input buffer (starting at pattern byte)
 * @param input_len Input buffer length
 * @param prefix Field section prefix (provides base, insert_count)
 * @param table Dynamic table for name lookup
 * @param header Output header structure
 * @param consumed Output: bytes consumed from input
 * @param arena Arena for string allocation
 * @return QPACK_OK on success, error code on failure
 */
extern SocketQPACK_Result
SocketQPACK_decode_literal_postbase_name (const unsigned char *input,
                                          size_t input_len,
                                          const SocketQPACK_FieldPrefix *prefix,
                                          SocketQPACK_Table_T table,
                                          SocketQPACK_Header *header,
                                          size_t *consumed,
                                          Arena_T arena);

/* ============================================================================
 * Integer Encoding (RFC 9204 Section 4.1.1 - same as RFC 7541 Section 5.1)
 * ============================================================================
 */

/**
 * Encode integer with prefix.
 * @param value Value to encode
 * @param prefix_bits Number of prefix bits (1-8)
 * @param output Output buffer
 * @param output_size Output buffer size
 * @return Bytes written, or 0 on error
 */
extern size_t SocketQPACK_int_encode (uint64_t value,
                                      int prefix_bits,
                                      unsigned char *output,
                                      size_t output_size);

/**
 * Decode integer with prefix.
 * @param input Input buffer
 * @param input_len Input buffer length
 * @param prefix_bits Number of prefix bits (1-8)
 * @param value Output value
 * @param consumed Output: bytes consumed
 * @return QPACK_OK on success, error code on failure
 */
extern SocketQPACK_Result SocketQPACK_int_decode (const unsigned char *input,
                                                  size_t input_len,
                                                  int prefix_bits,
                                                  uint64_t *value,
                                                  size_t *consumed);

/* ============================================================================
 * String Literal Encoding (RFC 9204 Section 4.1.2)
 * ============================================================================
 */

/** Huffman encode string. Returns -1 on error. */
extern ssize_t SocketQPACK_huffman_encode (const unsigned char *input,
                                           size_t input_len,
                                           unsigned char *output,
                                           size_t output_size);

/** Huffman decode string. Returns -1 on error. */
extern ssize_t SocketQPACK_huffman_decode (const unsigned char *input,
                                           size_t input_len,
                                           unsigned char *output,
                                           size_t output_size);

extern size_t
SocketQPACK_huffman_encoded_size (const unsigned char *input, size_t input_len);

/* ============================================================================
 * Static Table (RFC 9204 Appendix A)
 * ============================================================================
 */

/** Get entry from static table by index (0-98). */
extern SocketQPACK_Result
SocketQPACK_static_get (size_t index, SocketQPACK_Header *header);

/** Find entry in static table. Returns index or -1 if not found. */
extern int SocketQPACK_static_find (const char *name,
                                    size_t name_len,
                                    const char *value,
                                    size_t value_len);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/** @} */

#endif /* SOCKETQPACK_INCLUDED */

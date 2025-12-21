/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHPACK.h
 * @brief HPACK header compression/decompression for HTTP/2 (RFC 7541).
 *
 * Implements HPACK algorithm with static table (61 entries), dynamic table
 * (FIFO eviction), and Huffman encoding. Provides encoder/decoder instances
 * with security limits and decompression bomb protection.
 *
 * Thread Safety: Encoder/decoder instances are NOT thread-safe. One instance
 * per connection/thread recommended. Static functions are thread-safe.
 *
 * @defgroup hpack HPACK Header Compression Module
 * @{
 * @see https://tools.ietf.org/html/rfc7541
 */

#ifndef SOCKETHPACK_INCLUDED
#define SOCKETHPACK_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "core/Arena.h"
#include "core/Except.h"

/**
 * @brief Default dynamic table size in bytes (RFC 7541 default).
 */
#ifndef SOCKETHPACK_DEFAULT_TABLE_SIZE
#define SOCKETHPACK_DEFAULT_TABLE_SIZE 4096
#endif

/**
 * @brief Maximum allowable dynamic table size in bytes.
 */
#ifndef SOCKETHPACK_MAX_TABLE_SIZE
#define SOCKETHPACK_MAX_TABLE_SIZE (64 * 1024)
#endif

/**
 * @brief Maximum size for individual header (name + value) in bytes.
 */
#ifndef SOCKETHPACK_MAX_HEADER_SIZE
#define SOCKETHPACK_MAX_HEADER_SIZE (8 * 1024)
#endif

/**
 * @brief Maximum total size for decoded header list in bytes.
 */
#ifndef SOCKETHPACK_MAX_HEADER_LIST_SIZE
#define SOCKETHPACK_MAX_HEADER_LIST_SIZE (64 * 1024)
#endif

/**
 * @brief Maximum allowed dynamic table size updates per header block.
 */
#ifndef SOCKETHPACK_MAX_TABLE_UPDATES
#define SOCKETHPACK_MAX_TABLE_UPDATES 2
#endif

/**
 * @brief Size of the static table (RFC 7541 Appendix A).
 */
#define SOCKETHPACK_STATIC_TABLE_SIZE 61

/**
 * @brief Overhead bytes per dynamic table entry (RFC 7541 Section 4.1).
 */
#define SOCKETHPACK_ENTRY_OVERHEAD 32

/**
 * @brief SocketHPACK_Error - HPACK operation failure (invalid encoding, size
 * limits, decompression bombs).
 */
extern const Except_T SocketHPACK_Error;

/**
 * @brief HPACK operation result codes.
 */
typedef enum
{
  HPACK_OK = 0,              /**< Success */
  HPACK_INCOMPLETE,          /**< Need more data */
  HPACK_ERROR,               /**< Generic error */
  HPACK_ERROR_INVALID_INDEX, /**< Index out of range */
  HPACK_ERROR_HUFFMAN,       /**< Huffman decoding error */
  HPACK_ERROR_INTEGER,       /**< Integer overflow */
  HPACK_ERROR_TABLE_SIZE,    /**< Dynamic table size update invalid */
  HPACK_ERROR_HEADER_SIZE,   /**< Individual header too large */
  HPACK_ERROR_LIST_SIZE,     /**< Total header list too large */
  HPACK_ERROR_BOMB           /**< HPACK bomb detected */
} SocketHPACK_Result;

/**
 * @brief HPACK header field with optional never_index flag for sensitive data.
 */
typedef struct
{
  const char *name;  /**< Header name */
  size_t name_len;   /**< Name length in bytes */
  const char *value; /**< Header value */
  size_t value_len;  /**< Value length in bytes */
  int never_index;   /**< Sensitive - never add to dynamic table */
} SocketHPACK_Header;

/**
 * @brief HPACK dynamic table (opaque type).
 */
typedef struct SocketHPACK_Table *SocketHPACK_Table_T;

/**
 * @brief Create dynamic table for header compression (RFC 7541).
 *
 * Uses circular buffer with FIFO eviction when size limits reached.
 * All allocations are arena-managed.
 *
 * @param max_size Maximum table size in bytes (includes 32-byte overhead per
 * entry). Must be 0 <= max_size <= SOCKETHPACK_MAX_TABLE_SIZE.
 * @param arena Arena for all allocations.
 * @return New dynamic table instance.
 * @throws SocketHPACK_Error If max_size invalid.
 * @throws Arena_Failed If allocation fails.
 * @threadsafe Yes (arena must be synchronized if shared).
 * @see https://tools.ietf.org/html/rfc7541#section-4
 */
extern SocketHPACK_Table_T SocketHPACK_Table_new (size_t max_size,
                                                  Arena_T arena);

/**
 * @brief Free dynamic table and set pointer to NULL.
 *
 * @param table Pointer to table (safe to call on NULL).
 * @threadsafe No
 */
extern void SocketHPACK_Table_free (SocketHPACK_Table_T *table);

/**
 * @brief Update table maximum size, evicting oldest entries if necessary.
 *
 * Typically triggered by HTTP/2 SETTINGS frame.
 *
 * @param table Dynamic table.
 * @param max_size New maximum size in bytes (must be <= SOCKETHPACK_MAX_TABLE_SIZE).
 * @throws SocketHPACK_Error If max_size invalid.
 * @threadsafe No
 */
extern void SocketHPACK_Table_set_max_size (SocketHPACK_Table_T table,
                                            size_t max_size);

/**
 * @brief Get current table size in bytes (includes 32-byte overhead per entry).
 *
 * @param table Dynamic table.
 * @return Current size (RFC 7541 Section 4.1).
 * @threadsafe No
 */
extern size_t SocketHPACK_Table_size (SocketHPACK_Table_T table);

/**
 * @brief Get number of entries.
 * @param table Dynamic table.
 * @return Number of entries.
 * @threadsafe No
 */
extern size_t SocketHPACK_Table_count (SocketHPACK_Table_T table);

/**
 * @brief Get maximum table size.
 * @param table Dynamic table.
 * @return Maximum size in bytes.
 * @threadsafe No
 */
extern size_t SocketHPACK_Table_max_size (SocketHPACK_Table_T table);

/**
 * @brief Get entry by 1-based index (1 = most recent).
 * @param table Dynamic table.
 * @param index Entry index.
 * @param header Output header.
 * @return HPACK_OK on success, HPACK_ERROR_INVALID_INDEX if out of range.
 * @threadsafe No
 */
extern SocketHPACK_Result SocketHPACK_Table_get (SocketHPACK_Table_T table,
                                                 size_t index,
                                                 SocketHPACK_Header *header);

/**
 * @brief Add entry to table (may evict older entries if size limit exceeded).
 * @param table Dynamic table.
 * @param name Header name.
 * @param name_len Name length.
 * @param value Header value.
 * @param value_len Value length.
 * @return HPACK_OK on success.
 * @threadsafe No
 */
extern SocketHPACK_Result
SocketHPACK_Table_add (SocketHPACK_Table_T table, const char *name,
                       size_t name_len, const char *value, size_t value_len);

/**
 * @brief HPACK encoder (opaque type).
 */
typedef struct SocketHPACK_Encoder *SocketHPACK_Encoder_T;

/**
 * @brief Encoder configuration (table size, Huffman, indexing).
 */
typedef struct
{
  size_t max_table_size; /**< Maximum dynamic table size */
  int huffman_encode;    /**< Use Huffman encoding (default: 1) */
  int use_indexing;      /**< Add headers to dynamic table (default: 1) */
} SocketHPACK_EncoderConfig;

/**
 * @brief Initialize encoder config with defaults.
 * @param config Configuration structure.
 * @threadsafe Yes
 */
extern void
SocketHPACK_encoder_config_defaults (SocketHPACK_EncoderConfig *config);

/**
 * @brief Create encoder instance.
 * @param config Configuration (NULL for defaults).
 * @param arena Memory arena.
 * @return New encoder.
 * @throws SocketHPACK_Error on allocation failure.
 * @threadsafe Yes (arena must be thread-safe or thread-local).
 */
extern SocketHPACK_Encoder_T
SocketHPACK_Encoder_new (const SocketHPACK_EncoderConfig *config,
                         Arena_T arena);

/**
 * @brief Free encoder.
 * @param encoder Pointer to encoder (set to NULL).
 * @threadsafe No
 */
extern void SocketHPACK_Encoder_free (SocketHPACK_Encoder_T *encoder);

/**
 * @brief Encode header block.
 * @param encoder Encoder.
 * @param headers Headers to encode.
 * @param count Number of headers.
 * @param output Output buffer.
 * @param output_size Buffer size.
 * @return Bytes written, or -1 on error.
 * @threadsafe No
 */
extern ssize_t SocketHPACK_Encoder_encode (SocketHPACK_Encoder_T encoder,
                                           const SocketHPACK_Header *headers,
                                           size_t count, unsigned char *output,
                                           size_t output_size);

/**
 * @brief Signal table size change (emits update in next header block).
 * @param encoder Encoder.
 * @param max_size New maximum size.
 * @threadsafe No
 */
extern void SocketHPACK_Encoder_set_table_size (SocketHPACK_Encoder_T encoder,
                                                size_t max_size);

/**
 * @brief Get encoder's dynamic table.
 * @param encoder Encoder.
 * @return Dynamic table.
 * @threadsafe No
 */
extern SocketHPACK_Table_T
SocketHPACK_Encoder_get_table (SocketHPACK_Encoder_T encoder);

/**
 * @brief HPACK decoder (opaque type).
 */
typedef struct SocketHPACK_Decoder *SocketHPACK_Decoder_T;

/**
 * @brief Decoder configuration (security limits, decompression bomb
 * prevention).
 */
typedef struct
{
  size_t max_table_size;       /**< Maximum dynamic table size */
  size_t max_header_size;      /**< Maximum individual header size */
  size_t max_header_list_size; /**< Maximum total decoded size */
  double max_expansion_ratio;  /**< Max decoded/encoded ratio to prevent
                                  decompression bombs (default: 10.0) */

} SocketHPACK_DecoderConfig;

/**
 * @brief Initialize decoder config with defaults.
 * @param config Configuration structure.
 * @threadsafe Yes
 */
extern void
SocketHPACK_decoder_config_defaults (SocketHPACK_DecoderConfig *config);

/**
 * @brief Create decoder instance.
 * @param config Configuration (NULL for defaults).
 * @param arena Memory arena.
 * @return New decoder.
 * @throws SocketHPACK_Error on allocation failure.
 * @threadsafe Yes (arena must be thread-safe or thread-local).
 */
extern SocketHPACK_Decoder_T
SocketHPACK_Decoder_new (const SocketHPACK_DecoderConfig *config,
                         Arena_T arena);

/**
 * @brief Free decoder.
 * @param decoder Pointer to decoder (set to NULL).
 * @threadsafe No
 */
extern void SocketHPACK_Decoder_free (SocketHPACK_Decoder_T *decoder);

/**
 * @brief Decode HPACK header block (RFC 7541 Section 6).
 *
 * Single-pass decompression with validation against config limits. Supports
 * indexed headers, literals (with/without indexing), and table updates.
 * Strings are null-terminated and arena-allocated.
 *
 * @param decoder Decoder with security configuration.
 * @param input Encoded HPACK block.
 * @param input_len Input size.
 * @param headers Pre-allocated output array.
 * @param max_headers Array capacity.
 * @param header_count Number of decoded headers written.
 * @param arena Arena for string allocations.
 * @return HPACK_OK on success, HPACK_INCOMPLETE for partial input,
 * HPACK_ERROR_* on failure.
 * @throws SocketHPACK_Error On validation failures or limit violations.
 * @throws Arena_Failed If allocations exceed capacity.
 * @threadsafe No (modifies decoder state).
 * @see https://tools.ietf.org/html/rfc7541#section-6
 */
extern SocketHPACK_Result
SocketHPACK_Decoder_decode (SocketHPACK_Decoder_T decoder,
                            const unsigned char *input, size_t input_len,
                            SocketHPACK_Header *headers, size_t max_headers,
                            size_t *header_count, Arena_T arena);

/**
 * @brief Handle SETTINGS table size update.
 * @param decoder Decoder.
 * @param max_size New maximum size from SETTINGS frame.
 * @threadsafe No
 */
extern void SocketHPACK_Decoder_set_table_size (SocketHPACK_Decoder_T decoder,
                                                size_t max_size);

/**
 * @brief Get decoder's dynamic table.
 * @param decoder Decoder.
 * @return Dynamic table.
 * @threadsafe No
 */
extern SocketHPACK_Table_T
SocketHPACK_Decoder_get_table (SocketHPACK_Decoder_T decoder);

/**
 * @brief Huffman encode string (RFC 7541 Appendix B).
 * @param input Input string.
 * @param input_len Input length.
 * @param output Output buffer.
 * @param output_size Buffer size.
 * @return Encoded length, or -1 on error.
 * @threadsafe Yes
 */
extern ssize_t SocketHPACK_huffman_encode (const unsigned char *input,
                                           size_t input_len,
                                           unsigned char *output,
                                           size_t output_size);

/**
 * @brief Huffman decode string (DFA-based, validates padding).
 * @param input Encoded input.
 * @param input_len Input length.
 * @param output Output buffer.
 * @param output_size Buffer size.
 * @return Decoded length, or -1 on error.
 * @threadsafe Yes
 */
extern ssize_t SocketHPACK_huffman_decode (const unsigned char *input,
                                           size_t input_len,
                                           unsigned char *output,
                                           size_t output_size);

/**
 * @brief Calculate Huffman encoded size.
 * @param input Input string.
 * @param input_len Input length.
 * @return Encoded size in bytes.
 * @threadsafe Yes
 */
extern size_t SocketHPACK_huffman_encoded_size (const unsigned char *input,
                                                size_t input_len);

/**
 * @brief Encode integer with prefix (RFC 7541 Section 5.1).
 * @param value Integer value.
 * @param prefix_bits Prefix bits (1-8).
 * @param output Output buffer.
 * @param output_size Buffer size.
 * @return Bytes written.
 * @threadsafe Yes
 */
extern size_t SocketHPACK_int_encode (uint64_t value, int prefix_bits,
                                      unsigned char *output,
                                      size_t output_size);

/**
 * @brief Decode integer with prefix (RFC 7541 Section 5.1).
 * @param input Input buffer.
 * @param input_len Input length.
 * @param prefix_bits Prefix bits (1-8).
 * @param value Output value.
 * @param consumed Bytes consumed.
 * @return Result code.
 * @threadsafe Yes
 */
extern SocketHPACK_Result
SocketHPACK_int_decode (const unsigned char *input, size_t input_len,
                        int prefix_bits, uint64_t *value, size_t *consumed);

/**
 * @brief Get entry from static table by index (1-61).
 * @param index Entry index.
 * @param header Output header.
 * @return HPACK_OK on success, HPACK_ERROR_INVALID_INDEX if out of range.
 * @threadsafe Yes
 */
extern SocketHPACK_Result SocketHPACK_static_get (size_t index,
                                                  SocketHPACK_Header *header);

/**
 * @brief Find entry in static table.
 * @param name Header name.
 * @param name_len Name length.
 * @param value Header value (NULL to match name only).
 * @param value_len Value length.
 * @return Index (1-61) on exact match, negative if name-only match, 0 if not
 * found.
 * @threadsafe Yes
 */
extern int SocketHPACK_static_find (const char *name, size_t name_len,
                                    const char *value, size_t value_len);

/**
 * @brief Get error description for result code.
 * @param result Result code.
 * @return Static string.
 * @threadsafe Yes
 */
extern const char *SocketHPACK_result_string (SocketHPACK_Result result);

/** @} */

#endif /* SOCKETHPACK_INCLUDED */

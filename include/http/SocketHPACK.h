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

#ifndef SOCKETHPACK_DEFAULT_TABLE_SIZE
#define SOCKETHPACK_DEFAULT_TABLE_SIZE 4096
#endif

#ifndef SOCKETHPACK_MAX_TABLE_SIZE
#define SOCKETHPACK_MAX_TABLE_SIZE (64 * 1024)
#endif

#ifndef SOCKETHPACK_MAX_HEADER_SIZE
#define SOCKETHPACK_MAX_HEADER_SIZE (8 * 1024)
#endif

#ifndef SOCKETHPACK_MAX_HEADER_LIST_SIZE
#define SOCKETHPACK_MAX_HEADER_LIST_SIZE (64 * 1024)
#endif

#ifndef SOCKETHPACK_MAX_TABLE_UPDATES
#define SOCKETHPACK_MAX_TABLE_UPDATES 2
#endif

#define SOCKETHPACK_STATIC_TABLE_SIZE 61
#define SOCKETHPACK_ENTRY_OVERHEAD 32

extern const Except_T SocketHPACK_Error;

typedef enum
{
  HPACK_OK = 0,
  HPACK_INCOMPLETE,
  HPACK_ERROR,
  HPACK_ERROR_INVALID_INDEX,
  HPACK_ERROR_HUFFMAN,
  HPACK_ERROR_INTEGER,
  HPACK_ERROR_TABLE_SIZE,
  HPACK_ERROR_HEADER_SIZE,
  HPACK_ERROR_LIST_SIZE,
  HPACK_ERROR_BOMB
} SocketHPACK_Result;

typedef struct
{
  const char *name;
  size_t name_len;
  const char *value;
  size_t value_len;
  int never_index;
} SocketHPACK_Header;

typedef struct SocketHPACK_Table *SocketHPACK_Table_T;

/** Create dynamic table with FIFO eviction (RFC 7541 Section 4). */
extern SocketHPACK_Table_T
SocketHPACK_Table_new (size_t max_size, Arena_T arena);

extern void SocketHPACK_Table_free (SocketHPACK_Table_T *table);

/** Update max size, evicting oldest entries if necessary. */
extern void
SocketHPACK_Table_set_max_size (SocketHPACK_Table_T table, size_t max_size);

extern size_t SocketHPACK_Table_size (SocketHPACK_Table_T table);
extern size_t SocketHPACK_Table_count (SocketHPACK_Table_T table);
extern size_t SocketHPACK_Table_max_size (SocketHPACK_Table_T table);

/** Get entry by 1-based index (1 = most recent). */
extern SocketHPACK_Result SocketHPACK_Table_get (SocketHPACK_Table_T table,
                                                 size_t index,
                                                 SocketHPACK_Header *header);

extern SocketHPACK_Result SocketHPACK_Table_add (SocketHPACK_Table_T table,
                                                 const char *name,
                                                 size_t name_len,
                                                 const char *value,
                                                 size_t value_len);

typedef struct SocketHPACK_Encoder *SocketHPACK_Encoder_T;

typedef struct
{
  size_t max_table_size;
  int huffman_encode;
  int use_indexing;
} SocketHPACK_EncoderConfig;

extern void
SocketHPACK_encoder_config_defaults (SocketHPACK_EncoderConfig *config);

extern SocketHPACK_Encoder_T
SocketHPACK_Encoder_new (const SocketHPACK_EncoderConfig *config,
                         Arena_T arena);

extern void SocketHPACK_Encoder_free (SocketHPACK_Encoder_T *encoder);

/** Encode header block. Returns bytes written, or -1 on error. */
extern ssize_t SocketHPACK_Encoder_encode (SocketHPACK_Encoder_T encoder,
                                           const SocketHPACK_Header *headers,
                                           size_t count,
                                           unsigned char *output,
                                           size_t output_size);

extern void SocketHPACK_Encoder_set_table_size (SocketHPACK_Encoder_T encoder,
                                                size_t max_size);

extern SocketHPACK_Table_T
SocketHPACK_Encoder_get_table (SocketHPACK_Encoder_T encoder);

typedef struct SocketHPACK_Decoder *SocketHPACK_Decoder_T;

typedef struct
{
  size_t max_table_size;
  size_t max_header_size;
  size_t max_header_list_size;
  double max_expansion_ratio;
  size_t max_output_bytes; /* Absolute decompression output limit */
} SocketHPACK_DecoderConfig;

extern void
SocketHPACK_decoder_config_defaults (SocketHPACK_DecoderConfig *config);

extern SocketHPACK_Decoder_T
SocketHPACK_Decoder_new (const SocketHPACK_DecoderConfig *config,
                         Arena_T arena);

extern void SocketHPACK_Decoder_free (SocketHPACK_Decoder_T *decoder);

/** Decode HPACK header block (RFC 7541 Section 6). */
extern SocketHPACK_Result
SocketHPACK_Decoder_decode (SocketHPACK_Decoder_T decoder,
                            const unsigned char *input,
                            size_t input_len,
                            SocketHPACK_Header *headers,
                            size_t max_headers,
                            size_t *header_count,
                            Arena_T arena);

extern void SocketHPACK_Decoder_set_table_size (SocketHPACK_Decoder_T decoder,
                                                size_t max_size);

extern SocketHPACK_Table_T
SocketHPACK_Decoder_get_table (SocketHPACK_Decoder_T decoder);

/** Huffman encode string (RFC 7541 Appendix B). Returns -1 on error. */
extern ssize_t SocketHPACK_huffman_encode (const unsigned char *input,
                                           size_t input_len,
                                           unsigned char *output,
                                           size_t output_size);

/** Huffman decode string. Returns -1 on error. */
extern ssize_t SocketHPACK_huffman_decode (const unsigned char *input,
                                           size_t input_len,
                                           unsigned char *output,
                                           size_t output_size);

extern size_t
SocketHPACK_huffman_encoded_size (const unsigned char *input, size_t input_len);

/** Encode integer with prefix (RFC 7541 Section 5.1). */
extern size_t SocketHPACK_int_encode (uint64_t value,
                                      int prefix_bits,
                                      unsigned char *output,
                                      size_t output_size);

/** Decode integer with prefix (RFC 7541 Section 5.1). */
extern SocketHPACK_Result SocketHPACK_int_decode (const unsigned char *input,
                                                  size_t input_len,
                                                  int prefix_bits,
                                                  uint64_t *value,
                                                  size_t *consumed);

/** Get entry from static table by index (1-61). */
extern SocketHPACK_Result
SocketHPACK_static_get (size_t index, SocketHPACK_Header *header);

/** Find entry in static table. Returns index or 0 if not found. */
extern int SocketHPACK_static_find (const char *name,
                                    size_t name_len,
                                    const char *value,
                                    size_t value_len);

extern const char *SocketHPACK_result_string (SocketHPACK_Result result);

/** @} */

#endif /* SOCKETHPACK_INCLUDED */

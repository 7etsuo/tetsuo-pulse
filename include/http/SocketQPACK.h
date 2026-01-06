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
 * (FIFO eviction), and per-stream reference tracking. Based on HPACK (RFC 7541)
 * with modifications for QUIC's out-of-order delivery.
 *
 * Thread Safety: Encoder/decoder instances are NOT thread-safe. One instance
 * per connection recommended.
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

/* Default configuration values */
#ifndef SOCKETQPACK_DEFAULT_TABLE_SIZE
#define SOCKETQPACK_DEFAULT_TABLE_SIZE 4096
#endif

#ifndef SOCKETQPACK_MAX_TABLE_SIZE
#define SOCKETQPACK_MAX_TABLE_SIZE (64 * 1024)
#endif

#ifndef SOCKETQPACK_MAX_BLOCKED_STREAMS
#define SOCKETQPACK_MAX_BLOCKED_STREAMS 100
#endif

/* Static table size (RFC 9204 Appendix A) */
#define SOCKETQPACK_STATIC_TABLE_SIZE 99

/* Entry overhead: 32 bytes per RFC 9204 Section 3.2.1 */
#define SOCKETQPACK_ENTRY_OVERHEAD 32

/* Maximum number of streams to track references for */
#ifndef SOCKETQPACK_MAX_STREAM_REFS
#define SOCKETQPACK_MAX_STREAM_REFS 256
#endif

/* Maximum entries in dynamic table */
#ifndef SOCKETQPACK_MAX_DYNAMIC_ENTRIES
#define SOCKETQPACK_MAX_DYNAMIC_ENTRIES 128
#endif

/* ============================================================================
 * Decoder Stream Instruction Patterns (RFC 9204 Section 4.4)
 * ============================================================================
 */

/* Section Acknowledgement: 1xxxxxxx (prefix 1) */
#define QPACK_DECODER_SECTION_ACK_MASK 0x80
#define QPACK_DECODER_SECTION_ACK_PREFIX 7

/* Stream Cancellation: 01xxxxxx (prefix 01) */
#define QPACK_DECODER_STREAM_CANCEL_MASK 0xC0
#define QPACK_DECODER_STREAM_CANCEL_VAL 0x40
#define QPACK_DECODER_STREAM_CANCEL_PREFIX 6

/* Insert Count Increment: 00xxxxxx (prefix 00) */
#define QPACK_DECODER_INSERT_COUNT_MASK 0xC0
#define QPACK_DECODER_INSERT_COUNT_VAL 0x00
#define QPACK_DECODER_INSERT_COUNT_PREFIX 6

/* ============================================================================
 * Exception Definition
 * ============================================================================
 */

extern const Except_T SocketQPACK_Error;
extern const Except_T SocketQPACK_DecompressionFailed;

/* ============================================================================
 * Result Codes
 * ============================================================================
 */

typedef enum
{
  QPACK_OK = 0,
  QPACK_INCOMPLETE,           /* Need more data */
  QPACK_ERROR,                /* Generic error */
  QPACK_ERROR_INVALID_INDEX,  /* Invalid table index */
  QPACK_ERROR_HUFFMAN,        /* Huffman decoding error */
  QPACK_ERROR_INTEGER,        /* Integer overflow */
  QPACK_ERROR_TABLE_SIZE,     /* Invalid dynamic table size */
  QPACK_ERROR_HEADER_SIZE,    /* Header too large */
  QPACK_ERROR_LIST_SIZE,      /* Header list too large */
  QPACK_ERROR_STREAM_ID,      /* Invalid stream ID */
  QPACK_ERROR_DECODER_STREAM, /* Decoder stream error */
  QPACK_ERROR_ENCODER_STREAM  /* Encoder stream error */
} SocketQPACK_Result;

/* ============================================================================
 * Header Structure
 * ============================================================================
 */

typedef struct
{
  const char *name;
  size_t name_len;
  const char *value;
  size_t value_len;
  int never_index;
} SocketQPACK_Header;

/* ============================================================================
 * Stream Reference Tracking
 * ============================================================================
 *
 * QPACK requires tracking which streams reference which dynamic table entries.
 * When a stream is cancelled, all its references must be released.
 */

/**
 * Entry reference from a specific stream.
 */
typedef struct SocketQPACK_EntryRef
{
  uint64_t stream_id;                /* Stream that holds this reference */
  struct SocketQPACK_EntryRef *next; /* Next ref for this entry */
} SocketQPACK_EntryRef;

/**
 * Dynamic table entry with reference tracking.
 */
typedef struct
{
  char *name;
  size_t name_len;
  char *value;
  size_t value_len;
  int ref_count;              /* Total number of references */
  SocketQPACK_EntryRef *refs; /* List of streams referencing this entry */
} SocketQPACK_DynamicEntry;

/**
 * Stream reference tracking for fast cancellation lookup.
 */
typedef struct SocketQPACK_StreamRef
{
  uint64_t stream_id;                 /* Stream identifier */
  int *entry_indices;                 /* Array of entry indices referenced */
  int entry_count;                    /* Number of entries referenced */
  int entry_capacity;                 /* Capacity of entry_indices array */
  struct SocketQPACK_StreamRef *next; /* Hash collision chain */
} SocketQPACK_StreamRef;

/* ============================================================================
 * Dynamic Table
 * ============================================================================
 */

typedef struct SocketQPACK_Table *SocketQPACK_Table_T;

struct SocketQPACK_Table
{
  SocketQPACK_DynamicEntry *entries;
  size_t capacity;       /* Number of entry slots */
  size_t head;           /* Insert position (newest) */
  size_t tail;           /* Oldest entry position */
  size_t count;          /* Number of entries */
  size_t size;           /* Current size in bytes */
  size_t max_size;       /* Maximum size from settings */
  uint64_t insert_count; /* Absolute insert count for QPACK */
  Arena_T arena;
};

/** Create dynamic table with FIFO eviction (RFC 9204 Section 3.2). */
extern SocketQPACK_Table_T
SocketQPACK_Table_new (size_t max_size, Arena_T arena);

extern void SocketQPACK_Table_free (SocketQPACK_Table_T *table);

/** Update max size, evicting oldest entries if necessary. */
extern void
SocketQPACK_Table_set_max_size (SocketQPACK_Table_T table, size_t max_size);

extern size_t SocketQPACK_Table_size (SocketQPACK_Table_T table);
extern size_t SocketQPACK_Table_count (SocketQPACK_Table_T table);
extern size_t SocketQPACK_Table_max_size (SocketQPACK_Table_T table);
extern uint64_t SocketQPACK_Table_insert_count (SocketQPACK_Table_T table);

/** Get entry by absolute index. */
extern SocketQPACK_Result SocketQPACK_Table_get (SocketQPACK_Table_T table,
                                                 size_t index,
                                                 SocketQPACK_Header *header);

extern SocketQPACK_Result SocketQPACK_Table_add (SocketQPACK_Table_T table,
                                                 const char *name,
                                                 size_t name_len,
                                                 const char *value,
                                                 size_t value_len);

/* ============================================================================
 * Decoder
 * ============================================================================
 */

typedef struct SocketQPACK_Decoder *SocketQPACK_Decoder_T;

typedef struct
{
  size_t max_table_size;
  size_t max_blocked_streams;
  size_t max_header_size;
  size_t max_header_list_size;
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
 * Stream Cancellation (RFC 9204 Section 4.4.2)
 * ============================================================================
 *
 * When a stream is cancelled or reset, the decoder sends a Stream Cancellation
 * instruction to notify the encoder that all dynamic table references held by
 * that stream can be released.
 */

/**
 * Decode Stream Cancellation instruction from decoder stream.
 *
 * Wire format (RFC 9204 Section 4.4.2):
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 1 |     Stream ID (6+)    |
 * +---+---+-----------------------+
 *
 * @param decoder   QPACK decoder instance
 * @param input     Input buffer containing instruction
 * @param input_len Length of input buffer
 * @param consumed  Output: bytes consumed from input
 * @param stream_id Output: cancelled stream ID (if successful)
 *
 * @return QPACK_OK on success, error code otherwise
 */
extern SocketQPACK_Result
SocketQPACK_decode_stream_cancel (SocketQPACK_Decoder_T decoder,
                                  const unsigned char *input,
                                  size_t input_len,
                                  size_t *consumed,
                                  uint64_t *stream_id);

/**
 * Release all dynamic table references held by a stream.
 *
 * Called internally by SocketQPACK_decode_stream_cancel after parsing
 * the stream ID, or can be called directly when a stream is reset.
 *
 * @param decoder   QPACK decoder instance
 * @param stream_id Stream ID to release references for
 *
 * @return QPACK_OK on success, or appropriate error code
 */
extern SocketQPACK_Result
SocketQPACK_stream_cancel_release_refs (SocketQPACK_Decoder_T decoder,
                                        uint64_t stream_id);

/**
 * Validate stream ID for cancellation.
 *
 * @param stream_id Stream ID to validate
 *
 * @return QPACK_OK if valid, QPACK_ERROR_STREAM_ID if invalid
 */
extern SocketQPACK_Result
SocketQPACK_stream_cancel_validate_id (uint64_t stream_id);

/**
 * Add a reference from a stream to a dynamic table entry.
 *
 * @param decoder     QPACK decoder instance
 * @param stream_id   Stream holding the reference
 * @param entry_index Dynamic table entry index (0-based)
 *
 * @return QPACK_OK on success
 */
extern SocketQPACK_Result
SocketQPACK_add_stream_reference (SocketQPACK_Decoder_T decoder,
                                  uint64_t stream_id,
                                  size_t entry_index);

/**
 * Check if a byte represents a Stream Cancellation instruction.
 *
 * @param byte First byte of potential instruction
 *
 * @return 1 if this is a Stream Cancellation, 0 otherwise
 */
extern int SocketQPACK_is_stream_cancel_instruction (unsigned char byte);

/* ============================================================================
 * Integer Encoding/Decoding (RFC 7541 Section 5.1)
 * ============================================================================
 *
 * QPACK uses the same integer encoding as HPACK.
 */

/** Encode integer with prefix (RFC 7541 Section 5.1). */
extern size_t SocketQPACK_int_encode (uint64_t value,
                                      int prefix_bits,
                                      unsigned char *output,
                                      size_t output_size);

/** Decode integer with prefix (RFC 7541 Section 5.1). */
extern SocketQPACK_Result SocketQPACK_int_decode (const unsigned char *input,
                                                  size_t input_len,
                                                  int prefix_bits,
                                                  uint64_t *value,
                                                  size_t *consumed);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/** @} */

#endif /* SOCKETQPACK_INCLUDED */

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDeflate.h
 * @brief RFC 1951 DEFLATE compression/decompression.
 *
 * Native DEFLATE implementation for this socket library. Provides
 * static tables, inflate/deflate APIs, and integration with HTTP
 * Content-Encoding and WebSocket permessage-deflate.
 *
 * @defgroup deflate DEFLATE Compression Module
 * @{
 * @see https://tools.ietf.org/html/rfc1951
 */

#ifndef SOCKETDEFLATE_INCLUDED
#define SOCKETDEFLATE_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/Except.h"

/* RFC 1951 Limits */
#define DEFLATE_MAX_BITS 15    /* Maximum Huffman code length */
#define DEFLATE_WINDOW_SIZE 32768 /* 32KB sliding window */
#define DEFLATE_MIN_MATCH 3    /* Minimum match length */
#define DEFLATE_MAX_MATCH 258  /* Maximum match length */

/* Alphabet sizes */
#define DEFLATE_LITLEN_CODES 288   /* 0-287 (286-287 reserved) */
#define DEFLATE_DIST_CODES 32      /* 0-31 (30-31 reserved) */
#define DEFLATE_CODELEN_CODES 19   /* 0-18 for code lengths */

/* Length code range */
#define DEFLATE_LENGTH_CODE_MIN 257 /* First length code */
#define DEFLATE_LENGTH_CODE_MAX 285 /* Last valid length code */
#define DEFLATE_LENGTH_CODES 29     /* Number of length codes (257-285) */

/* Distance code range */
#define DEFLATE_DISTANCE_CODE_MIN 0  /* First distance code */
#define DEFLATE_DISTANCE_CODE_MAX 29 /* Last valid distance code */
#define DEFLATE_DISTANCE_CODES 30    /* Number of distance codes (0-29) */

/* Decoding limits (for validation) */
#define DEFLATE_LITLEN_MAX_DECODE 285 /* Codes 286-287 invalid */
#define DEFLATE_DIST_MAX_DECODE 29    /* Codes 30-31 invalid */

/* Special symbols */
#define DEFLATE_END_OF_BLOCK 256 /* End-of-block symbol */

/**
 * Block types (RFC 1951 Section 3.2.3).
 * Stored in 2 bits following BFINAL bit.
 */
typedef enum
{
  DEFLATE_BLOCK_STORED = 0,  /* BTYPE=00: No compression */
  DEFLATE_BLOCK_FIXED = 1,   /* BTYPE=01: Fixed Huffman codes */
  DEFLATE_BLOCK_DYNAMIC = 2, /* BTYPE=10: Dynamic Huffman codes */
  DEFLATE_BLOCK_RESERVED = 3 /* BTYPE=11: Reserved (error) */
} SocketDeflate_BlockType;

/**
 * Result codes for DEFLATE operations.
 */
typedef enum
{
  DEFLATE_OK = 0,
  DEFLATE_INCOMPLETE,
  DEFLATE_ERROR,
  DEFLATE_ERROR_INVALID_BTYPE,
  DEFLATE_ERROR_INVALID_CODE,
  DEFLATE_ERROR_INVALID_DISTANCE,
  DEFLATE_ERROR_DISTANCE_TOO_FAR,
  DEFLATE_ERROR_HUFFMAN_TREE,
  DEFLATE_ERROR_BOMB
} SocketDeflate_Result;

/** Exception raised on DEFLATE errors. */
extern const Except_T SocketDeflate_Failed;

/**
 * Static table entry for length/distance codes.
 * Combines base value and extra bits count for cache-friendly lookup.
 */
typedef struct
{
  uint16_t base;      /* Base value */
  uint8_t extra_bits; /* Number of extra bits to read */
} SocketDeflate_CodeEntry;

/*
 * Static Tables (defined in SocketDeflate-static.c)
 *
 * These tables are derived from RFC 1951 Section 3.2.5 and 3.2.6.
 */

/** Length code table: maps code 257-285 to length 3-258. */
extern const SocketDeflate_CodeEntry deflate_length_table[DEFLATE_LENGTH_CODES];

/** Distance code table: maps code 0-29 to distance 1-32768. */
extern const SocketDeflate_CodeEntry
    deflate_distance_table[DEFLATE_DISTANCE_CODES];

/** Fixed Huffman code lengths for literal/length alphabet (RFC 1951 3.2.6). */
extern const uint8_t deflate_fixed_litlen_lengths[DEFLATE_LITLEN_CODES];

/** Fixed Huffman code lengths for distance alphabet (all 5 bits). */
extern const uint8_t deflate_fixed_dist_lengths[DEFLATE_DIST_CODES];

/** Code length alphabet order for dynamic blocks (RFC 1951 3.2.7). */
extern const uint8_t deflate_codelen_order[DEFLATE_CODELEN_CODES];

/*
 * Validation Functions
 *
 * These functions check if a code is valid for use in compressed data.
 * RFC 1951 specifies that certain codes (286-287 for litlen, 30-31 for
 * distance) participate in code construction but never appear in data.
 */

/**
 * Check if a literal/length code is valid for decoding.
 *
 * @param code The code to validate (0-287 range expected)
 * @return 1 if valid (0-285), 0 if invalid (286-287 or out of range)
 */
extern int SocketDeflate_is_valid_litlen_code (unsigned int code);

/**
 * Check if a distance code is valid for decoding.
 *
 * @param code The code to validate (0-31 range expected)
 * @return 1 if valid (0-29), 0 if invalid (30-31 or out of range)
 */
extern int SocketDeflate_is_valid_distance_code (unsigned int code);

/*
 * Extra Bits Query Functions
 *
 * These functions return the number of extra bits needed for a given code.
 * Use these to determine how many bits to read from the stream before decoding.
 */

/**
 * Get the number of extra bits for a length code.
 *
 * @param code        Length code (257-285)
 * @param extra_out   Output: number of extra bits (0-5)
 * @return DEFLATE_OK on success, DEFLATE_ERROR_INVALID_CODE if code invalid
 */
extern SocketDeflate_Result
SocketDeflate_get_length_extra_bits (unsigned int code,
                                     unsigned int *extra_out);

/**
 * Get the number of extra bits for a distance code.
 *
 * @param code        Distance code (0-29)
 * @param extra_out   Output: number of extra bits (0-13)
 * @return DEFLATE_OK on success, DEFLATE_ERROR_INVALID_DISTANCE if code invalid
 */
extern SocketDeflate_Result
SocketDeflate_get_distance_extra_bits (unsigned int code,
                                       unsigned int *extra_out);

/*
 * Decode Functions
 *
 * These functions decode length and distance values from codes and extra bits.
 * The extra bits value is masked to the valid range for the code, preventing
 * overflow from malformed input.
 */

/**
 * Decode a length value from a length code and extra bits.
 *
 * @param code       Length code (257-285)
 * @param extra      Extra bits value (masked to valid range for code)
 * @param length_out Output: decoded length (3-258)
 * @return DEFLATE_OK on success, DEFLATE_ERROR_INVALID_CODE if code invalid
 */
extern SocketDeflate_Result
SocketDeflate_decode_length (unsigned int code, unsigned int extra,
                             unsigned int *length_out);

/**
 * Decode a distance value from a distance code and extra bits.
 *
 * @param code         Distance code (0-29)
 * @param extra        Extra bits value (masked to valid range for code)
 * @param distance_out Output: decoded distance (1-32768)
 * @return DEFLATE_OK on success, DEFLATE_ERROR_INVALID_DISTANCE if invalid
 */
extern SocketDeflate_Result
SocketDeflate_decode_distance (unsigned int code, unsigned int extra,
                               unsigned int *distance_out);

/*
 * Bit Stream Reader (RFC 1951 Section 3.1.1)
 *
 * DEFLATE uses LSB-first bit ordering:
 * - Within a byte: bits packed starting with LSB (bit 0)
 * - Non-Huffman data: packed starting with LSB of data element
 * - Huffman codes: packed starting with MSB of code (bit-reversed)
 *
 * The bit reader handles this ordering transparently, providing a simple
 * interface for reading bits from a DEFLATE stream.
 */

/** Maximum bits that can be read in a single operation. */
#define DEFLATE_MAX_BITS_READ 25 /* 15-bit code + 13-bit extra max */

/** Opaque bit reader type. */
typedef struct SocketDeflate_BitReader *SocketDeflate_BitReader_T;

/**
 * Create a new bit reader.
 *
 * @param arena Arena for allocation (reader lifetime tied to arena)
 * @return New bit reader instance
 */
extern SocketDeflate_BitReader_T SocketDeflate_BitReader_new (Arena_T arena);

/**
 * Initialize bit reader with input data.
 *
 * @param reader The bit reader
 * @param data   Input data buffer
 * @param size   Size of input data in bytes
 */
extern void SocketDeflate_BitReader_init (SocketDeflate_BitReader_T reader,
                                          const uint8_t *data, size_t size);

/**
 * Read N bits from the stream (LSB-first for non-Huffman data).
 *
 * Reads bits in the order they appear in the DEFLATE stream.
 * For regular data (extra bits, lengths), this gives the correct value.
 * For Huffman codes, the bits are naturally bit-reversed.
 *
 * @param reader The bit reader
 * @param n      Number of bits to read (1-25)
 * @param value  Output: the read value, LSB-aligned
 * @return DEFLATE_OK on success, DEFLATE_INCOMPLETE if not enough data
 */
extern SocketDeflate_Result SocketDeflate_BitReader_read (
    SocketDeflate_BitReader_T reader, unsigned int n, uint32_t *value);

/**
 * Peek N bits without consuming them.
 *
 * Used by Huffman decoder to look up code, then consume only bits used.
 *
 * @param reader The bit reader
 * @param n      Number of bits to peek (1-25)
 * @param value  Output: the peeked value, LSB-aligned
 * @return DEFLATE_OK on success, DEFLATE_INCOMPLETE if not enough data
 */
extern SocketDeflate_Result SocketDeflate_BitReader_peek (
    SocketDeflate_BitReader_T reader, unsigned int n, uint32_t *value);

/**
 * Consume N bits after a peek operation.
 *
 * @param reader The bit reader
 * @param n      Number of bits to consume (must be <= previously peeked)
 */
extern void SocketDeflate_BitReader_consume (SocketDeflate_BitReader_T reader,
                                             unsigned int n);

/**
 * Skip to next byte boundary.
 *
 * Required before reading raw bytes for stored blocks (BTYPE=00).
 * Discards any remaining bits in the current byte.
 *
 * @param reader The bit reader
 */
extern void SocketDeflate_BitReader_align (SocketDeflate_BitReader_T reader);

/**
 * Read raw bytes from the stream.
 *
 * Typically called after align() for stored block data. First consumes
 * any complete bytes from the bit accumulator, then reads remaining
 * bytes directly from input.
 *
 * @param reader The bit reader
 * @param dest   Destination buffer
 * @param count  Number of bytes to read (0 returns immediately with OK)
 * @return DEFLATE_OK on success, DEFLATE_INCOMPLETE if not enough data
 */
extern SocketDeflate_Result
SocketDeflate_BitReader_read_bytes (SocketDeflate_BitReader_T reader,
                                    uint8_t *dest, size_t count);

/**
 * Get number of bits available in the stream.
 *
 * @param reader The bit reader
 * @return Number of bits that can still be read
 */
extern size_t
SocketDeflate_BitReader_bits_available (SocketDeflate_BitReader_T reader);

/**
 * Get number of complete bytes remaining in input.
 *
 * @param reader The bit reader
 * @return Number of unread bytes in input buffer
 */
extern size_t
SocketDeflate_BitReader_bytes_remaining (SocketDeflate_BitReader_T reader);

/**
 * Check if all input has been consumed.
 *
 * @param reader The bit reader
 * @return 1 if at end of input, 0 otherwise
 */
extern int SocketDeflate_BitReader_at_end (SocketDeflate_BitReader_T reader);

/**
 * Reverse bits in a value.
 *
 * Huffman codes in DEFLATE are stored MSB-first in the RFC tables but
 * appear LSB-first in the bit stream. This helper converts between them.
 *
 * @param value  Value to reverse
 * @param nbits  Number of bits to reverse (1-15)
 * @return Bit-reversed value
 */
extern uint32_t SocketDeflate_reverse_bits (uint32_t value, unsigned int nbits);

/*
 * Huffman Decoder (RFC 1951 Section 3.2.2)
 *
 * Builds canonical Huffman decode tables from code lengths.
 * Uses a two-level lookup table:
 * - Primary table (9 bits): Direct lookup for codes <= 9 bits
 * - Secondary tables: For codes > 9 bits (up to 15)
 *
 * DEFLATE Huffman codes are canonical:
 * - All codes of given length have lexicographically consecutive values
 * - Shorter codes precede longer codes
 * - Codes are stored MSB-first in RFC but appear LSB-first in stream
 */

/** Opaque Huffman table type. */
typedef struct SocketDeflate_HuffmanTable *SocketDeflate_HuffmanTable_T;

/**
 * Create a new Huffman table.
 *
 * @param arena Arena for allocation (table lifetime tied to arena)
 * @return New table instance
 */
extern SocketDeflate_HuffmanTable_T
SocketDeflate_HuffmanTable_new (Arena_T arena);

/**
 * Build Huffman table from code lengths (RFC 1951 §3.2.2).
 *
 * Generates canonical Huffman codes and builds lookup tables.
 * Validates that the tree is neither over-subscribed nor incomplete
 * (except for single-code trees per RFC 1951 §3.2.7).
 *
 * @param table      The table to build
 * @param lengths    Array of code lengths (0 = symbol not used)
 * @param count      Number of symbols in alphabet
 * @param max_bits   Maximum allowed code length (must be ≤ 15)
 * @return DEFLATE_OK on success, DEFLATE_ERROR_HUFFMAN_TREE on invalid tree
 */
extern SocketDeflate_Result
SocketDeflate_HuffmanTable_build (SocketDeflate_HuffmanTable_T table,
                                  const uint8_t *lengths, unsigned int count,
                                  unsigned int max_bits);

/**
 * Decode one symbol from the bit stream.
 *
 * Uses the prebuilt lookup tables for fast decoding.
 * Peeks bits from the stream, looks up the symbol, and consumes
 * only the bits actually used by the code.
 *
 * @param table   The Huffman table
 * @param reader  Bit reader with input data
 * @param symbol  Output: decoded symbol
 * @return DEFLATE_OK on success, DEFLATE_INCOMPLETE if not enough bits,
 *         DEFLATE_ERROR_INVALID_CODE if invalid code encountered
 */
extern SocketDeflate_Result
SocketDeflate_HuffmanTable_decode (SocketDeflate_HuffmanTable_T table,
                                   SocketDeflate_BitReader_T reader,
                                   uint16_t *symbol);

/**
 * Reset table for reuse.
 *
 * Clears all entries without freeing memory. Use before rebuilding
 * for dynamic Huffman blocks.
 *
 * @param table The table to reset
 */
extern void SocketDeflate_HuffmanTable_reset (SocketDeflate_HuffmanTable_T table);

/*
 * Fixed Huffman Tables (RFC 1951 Section 3.2.6)
 *
 * Pre-built tables for BTYPE=01 (fixed Huffman codes).
 * Initialize once at startup, then reuse across all inflate operations.
 */

/**
 * Initialize global fixed Huffman tables.
 *
 * Must be called before using fixed tables. Thread-safe if called
 * once at startup before any concurrent inflate operations.
 *
 * @param arena Arena for allocation (must outlive all inflate operations)
 * @return DEFLATE_OK on success
 */
extern SocketDeflate_Result SocketDeflate_fixed_tables_init (Arena_T arena);

/**
 * Get the fixed literal/length Huffman table.
 *
 * @return Pre-built fixed litlen table, or NULL if not initialized
 */
extern SocketDeflate_HuffmanTable_T SocketDeflate_get_fixed_litlen_table (void);

/**
 * Get the fixed distance Huffman table.
 *
 * @return Pre-built fixed distance table, or NULL if not initialized
 */
extern SocketDeflate_HuffmanTable_T SocketDeflate_get_fixed_dist_table (void);

/** @} */ /* end of deflate group */

#endif /* SOCKETDEFLATE_INCLUDED */

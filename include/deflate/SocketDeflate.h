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
  DEFLATE_OUTPUT_FULL,
  DEFLATE_ERROR,
  DEFLATE_ERROR_INVALID_BTYPE,
  DEFLATE_ERROR_INVALID_CODE,
  DEFLATE_ERROR_INVALID_DISTANCE,
  DEFLATE_ERROR_DISTANCE_TOO_FAR,
  DEFLATE_ERROR_HUFFMAN_TREE,
  DEFLATE_ERROR_BOMB,
  DEFLATE_ERROR_GZIP_MAGIC,  /* Invalid gzip magic bytes */
  DEFLATE_ERROR_GZIP_METHOD, /* Unsupported compression method */
  DEFLATE_ERROR_GZIP_CRC,    /* CRC32 mismatch */
  DEFLATE_ERROR_GZIP_SIZE,   /* ISIZE mismatch */
  DEFLATE_ERROR_GZIP_HCRC,   /* Header CRC16 mismatch */
  DEFLATE_ERROR_GZIP_OS      /* Invalid/unknown OS code (warning only) */
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
 * Bit Stream Writer (RFC 1951 Section 3.1.1)
 *
 * DEFLATE uses LSB-first bit ordering for output:
 * - Within a byte: bits packed starting with LSB (bit 0)
 * - Non-Huffman data: packed starting with LSB of data element
 * - Huffman codes: packed starting with MSB of code (bit-reversed)
 *
 * The bit writer mirrors the reader's ordering for consistency.
 */

/** Opaque bit writer type. */
typedef struct SocketDeflate_BitWriter *SocketDeflate_BitWriter_T;

/**
 * Create a new bit writer.
 *
 * @param arena Arena for allocation (writer lifetime tied to arena)
 * @return New bit writer instance
 */
extern SocketDeflate_BitWriter_T SocketDeflate_BitWriter_new (Arena_T arena);

/**
 * Initialize bit writer with output buffer.
 *
 * @param writer   The bit writer
 * @param data     Output buffer
 * @param capacity Size of output buffer in bytes
 */
extern void SocketDeflate_BitWriter_init (SocketDeflate_BitWriter_T writer,
                                          uint8_t *data, size_t capacity);

/**
 * Write N bits to the stream (LSB-first for non-Huffman data).
 *
 * Writes bits in DEFLATE's LSB-first order. The value is masked
 * to n bits before writing.
 *
 * @param writer The bit writer
 * @param value  Value to write (only low n bits are used)
 * @param n      Number of bits to write (1-25)
 * @return DEFLATE_OK on success, DEFLATE_ERROR if buffer full or n invalid
 */
extern SocketDeflate_Result SocketDeflate_BitWriter_write (
    SocketDeflate_BitWriter_T writer, uint32_t value, unsigned int n);

/**
 * Write a Huffman code to the stream.
 *
 * Huffman codes are defined MSB-first in RFC 1951 but stored LSB-first
 * in the bit stream. This function reverses the code bits before writing.
 *
 * @param writer The bit writer
 * @param code   Huffman code value (MSB-first)
 * @param len    Code length in bits (1-15)
 * @return DEFLATE_OK on success, DEFLATE_ERROR if buffer full or len invalid
 */
extern SocketDeflate_Result SocketDeflate_BitWriter_write_huffman (
    SocketDeflate_BitWriter_T writer, uint32_t code, unsigned int len);

/**
 * Flush pending bits to output (pads with zeros).
 *
 * Writes any pending bits to the output buffer, padding with zeros
 * to complete the byte. After flush, the writer is byte-aligned.
 *
 * @param writer The bit writer
 * @return Total bytes written to output buffer
 */
extern size_t SocketDeflate_BitWriter_flush (SocketDeflate_BitWriter_T writer);

/**
 * Align to next byte boundary.
 *
 * Equivalent to flush() - pads remaining bits with zeros and writes
 * to output. After align, the writer is at a byte boundary.
 *
 * @param writer The bit writer
 */
extern void SocketDeflate_BitWriter_align (SocketDeflate_BitWriter_T writer);

/**
 * Write RFC 7692 sync flush marker.
 *
 * Per RFC 7692 Section 7.2.1, writes an empty stored block that
 * produces trailing bytes: 0x00 0x00 0xFF 0xFF.
 *
 * Format: BFINAL=0, BTYPE=00, align, LEN=0, NLEN=0xFFFF
 *
 * The 4-byte trailer is typically stripped before WebSocket transmission.
 *
 * @param writer The bit writer
 * @return Total bytes written to output buffer
 */
extern size_t
SocketDeflate_BitWriter_sync_flush (SocketDeflate_BitWriter_T writer);

/**
 * Get number of bytes written so far.
 *
 * @param writer The bit writer
 * @return Number of complete bytes in output buffer
 */
extern size_t SocketDeflate_BitWriter_size (SocketDeflate_BitWriter_T writer);

/**
 * Get remaining capacity in output buffer.
 *
 * @param writer The bit writer
 * @return Bytes remaining (capacity - bytes written)
 */
extern size_t
SocketDeflate_BitWriter_capacity_remaining (SocketDeflate_BitWriter_T writer);

/**
 * Get number of bits pending in accumulator.
 *
 * @param writer The bit writer
 * @return Number of bits not yet flushed (0-7)
 */
extern int
SocketDeflate_BitWriter_bits_pending (SocketDeflate_BitWriter_T writer);

/*
 * LZ77 String Matcher (RFC 1951 Section 4)
 *
 * Hash-table-based matcher for finding repeated byte sequences
 * in the sliding window. Uses chained hash tables for collision
 * resolution and supports lazy matching optimization.
 *
 * The matcher uses a 15-bit hash function on 3-byte sequences to
 * locate potential matches. Positions are stored as position+1 to
 * distinguish position 0 from "no match".
 */

/* LZ77 Matcher Constants */
#define DEFLATE_HASH_BITS 15
#define DEFLATE_HASH_SIZE (1U << DEFLATE_HASH_BITS) /* 32,768 entries */
#define DEFLATE_CHAIN_LIMIT 128  /* Default max chain traversal */
#define DEFLATE_GOOD_LENGTH 32   /* Skip lazy match if >= this length */
#define DEFLATE_NICE_LENGTH 258  /* Stop search if match >= this */

/** Opaque matcher type. */
typedef struct SocketDeflate_Matcher *SocketDeflate_Matcher_T;

/**
 * Match result structure.
 * Returned by SocketDeflate_Matcher_find() when a match is found.
 */
typedef struct
{
  uint16_t length;   /**< Match length (3-258) */
  uint16_t distance; /**< Back distance (1-32768) */
} SocketDeflate_Match;

/**
 * Create a new LZ77 matcher.
 *
 * @param arena Arena for allocation (matcher lifetime tied to arena)
 * @return New matcher instance
 */
extern SocketDeflate_Matcher_T SocketDeflate_Matcher_new (Arena_T arena);

/**
 * Initialize matcher with input data.
 *
 * @param matcher The matcher
 * @param data    Input data buffer
 * @param size    Size of input data in bytes
 */
extern void SocketDeflate_Matcher_init (SocketDeflate_Matcher_T matcher,
                                        const uint8_t *data, size_t size);

/**
 * Configure matcher limits.
 *
 * @param matcher     The matcher
 * @param chain_limit Maximum hash chain traversal (0 = default)
 * @param good_len    Skip lazy match if current >= this (0 = default)
 * @param nice_len    Stop search if match >= this (0 = default)
 */
extern void SocketDeflate_Matcher_set_limits (SocketDeflate_Matcher_T matcher,
                                              int chain_limit, int good_len,
                                              int nice_len);

/**
 * Insert a position into the hash table.
 *
 * Call this for each position as you advance through the input.
 * Positions must have at least 3 bytes remaining (pos + 3 <= size).
 *
 * @param matcher The matcher
 * @param pos     Position to insert (0-based)
 */
extern void SocketDeflate_Matcher_insert (SocketDeflate_Matcher_T matcher,
                                          size_t pos);

/**
 * Find the longest match at a position.
 *
 * Searches the hash chain for the best match at the given position.
 * Returns 1 if a match was found, 0 otherwise.
 *
 * @param matcher The matcher
 * @param pos     Position to find match for
 * @param match   Output: match result (length and distance)
 * @return 1 if match found, 0 otherwise
 */
extern int SocketDeflate_Matcher_find (SocketDeflate_Matcher_T matcher,
                                       size_t pos, SocketDeflate_Match *match);

/**
 * Check if current match should be deferred (lazy matching).
 *
 * Per RFC 1951 Section 4, lazy matching defers a match if the next
 * position has a longer match. This improves compression ratio.
 *
 * @param matcher The matcher
 * @param pos     Current position
 * @param cur_len Current match length
 * @return 1 if should defer (emit literal), 0 if should use current match
 */
extern int SocketDeflate_Matcher_should_defer (SocketDeflate_Matcher_T matcher,
                                               size_t pos, unsigned int cur_len);

/*
 * Huffman Code Generator (RFC 1951 Section 3.2.2)
 *
 * Builds optimal length-limited Huffman codes from symbol frequencies.
 * Uses package-merge algorithm to enforce the 15-bit maximum code length
 * required by DEFLATE.
 *
 * The code generation follows the canonical Huffman algorithm from
 * RFC 1951 Section 3.2.2, ensuring codes are compatible with the decoder.
 */

/**
 * Huffman code entry for encoding.
 * Generated by SocketDeflate_generate_codes().
 */
typedef struct
{
  uint16_t code; /**< Canonical code value (MSB-first) */
  uint8_t len;   /**< Code length in bits (0 = unused symbol) */
} SocketDeflate_HuffmanCode;

/**
 * Build optimal code lengths from symbol frequencies.
 *
 * Uses the package-merge algorithm to generate length-limited Huffman
 * code lengths. All generated lengths will be <= max_bits.
 *
 * Special cases:
 * - 0 symbols (all freqs=0): all lengths = 0
 * - 1 symbol: that symbol gets length = 1
 * - 2 symbols: both get length = 1
 *
 * @param freqs    Array of symbol frequencies (count elements)
 * @param lengths  Output: array of code lengths (count elements)
 * @param count    Number of symbols in alphabet
 * @param max_bits Maximum allowed code length (typically 15)
 * @param arena    Arena for temporary allocations
 * @return DEFLATE_OK on success
 */
extern SocketDeflate_Result
SocketDeflate_build_code_lengths (const uint32_t *freqs, uint8_t *lengths,
                                  unsigned int count, unsigned int max_bits,
                                  Arena_T arena);

/**
 * Generate canonical Huffman codes from code lengths.
 *
 * Implements the RFC 1951 Section 3.2.2 algorithm:
 * 1. Count codes per length
 * 2. Compute first code per length
 * 3. Assign consecutive codes
 *
 * @param lengths Array of code lengths (count elements)
 * @param codes   Output: array of code values (count elements)
 * @param count   Number of symbols in alphabet
 */
extern void SocketDeflate_generate_codes (const uint8_t *lengths,
                                          SocketDeflate_HuffmanCode *codes,
                                          unsigned int count);

/**
 * RLE-encode code lengths for dynamic block header.
 *
 * Encodes code lengths using symbols 16-18 per RFC 1951 Section 3.2.7:
 * - Symbol 16: Copy previous length 3-6 times (2 extra bits)
 * - Symbol 17: Repeat 0 for 3-10 times (3 extra bits)
 * - Symbol 18: Repeat 0 for 11-138 times (7 extra bits)
 *
 * @param lengths         Array of code lengths to encode
 * @param count           Number of code lengths
 * @param output          Output buffer for encoded symbols
 * @param output_capacity Size of output buffer
 * @return Number of symbols written to output
 */
extern size_t SocketDeflate_encode_code_lengths (const uint8_t *lengths,
                                                 unsigned int count,
                                                 uint8_t *output,
                                                 size_t output_capacity);

/*
 * Length/Distance Code Encoding (RFC 1951 Section 3.2.5)
 *
 * Converts match lengths (3-258) and distances (1-32768) to codes and
 * extra bits. These are the inverse of the decode functions.
 */

/**
 * Encode a match length to code and extra bits.
 *
 * Converts length (3-258) to a length code (257-285) and extra bits.
 *
 * @param length         Match length (3-258)
 * @param code_out       Output: length code (257-285)
 * @param extra_out      Output: extra bits value
 * @param extra_bits_out Output: number of extra bits (0-5)
 */
extern void SocketDeflate_encode_length (unsigned int length,
                                         unsigned int *code_out,
                                         unsigned int *extra_out,
                                         unsigned int *extra_bits_out);

/**
 * Encode a match distance to code and extra bits.
 *
 * Converts distance (1-32768) to a distance code (0-29) and extra bits.
 *
 * @param distance       Match distance (1-32768)
 * @param code_out       Output: distance code (0-29)
 * @param extra_out      Output: extra bits value
 * @param extra_bits_out Output: number of extra bits (0-13)
 */
extern void SocketDeflate_encode_distance (unsigned int distance,
                                           unsigned int *code_out,
                                           unsigned int *extra_out,
                                           unsigned int *extra_bits_out);

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

/*
 * Stored Block Decoder (RFC 1951 Section 3.2.4)
 *
 * Non-compressed blocks contain literal bytes with a length header.
 * The block format is: [align to byte][LEN:16][NLEN:16][DATA:LEN bytes]
 *
 * LEN is the number of data bytes (0-65535).
 * NLEN is the one's complement of LEN for validation.
 */

/**
 * Decode a stored block (BTYPE=00) from the bit stream.
 *
 * Per RFC 1951 Section 3.2.4:
 * 1. Aligns to next byte boundary (discards partial byte)
 * 2. Reads LEN (16-bit length)
 * 3. Reads NLEN (16-bit one's complement of LEN)
 * 4. Validates NLEN == ~LEN
 * 5. Copies LEN bytes to output
 *
 * @param reader      Bit reader positioned after BTYPE bits
 * @param output      Output buffer for decompressed data
 * @param output_len  Size of output buffer
 * @param written     Output: number of bytes written
 * @return DEFLATE_OK on success, DEFLATE_INCOMPLETE if need more input,
 *         DEFLATE_ERROR if NLEN validation fails or output too small
 */
extern SocketDeflate_Result
SocketDeflate_decode_stored_block (SocketDeflate_BitReader_T reader,
                                   uint8_t *output, size_t output_len,
                                   size_t *written);

/*
 * Fixed Huffman Block Decoder (RFC 1951 Section 3.2.6)
 *
 * Compressed blocks with fixed Huffman codes use predefined tables:
 * - Literal/length codes: 7-9 bits (0-143: 8 bits, 144-255: 9 bits,
 *   256-279: 7 bits, 280-287: 8 bits)
 * - Distance codes: 5 bits (all 32 codes)
 *
 * The decoder implements the LZ77 decompression loop:
 * - Literal (0-255): Write byte directly to output
 * - End-of-block (256): Terminate decoding
 * - Length code (257-285): Decode length, then distance, copy from history
 */

/**
 * Decode a fixed Huffman block (BTYPE=01) from the bit stream.
 *
 * Per RFC 1951 Section 3.2.6, decodes compressed data using the predefined
 * fixed Huffman tables. The fixed tables must be initialized via
 * SocketDeflate_fixed_tables_init() before calling this function.
 *
 * The decoder handles the LZ77 decompression with:
 * - Literal bytes output directly
 * - Back-references with length/distance pairs
 * - Overlap handling when distance < length (RFC 1951 §3.2.3)
 *
 * @param reader      Bit reader positioned after BTYPE bits
 * @param output      Output buffer for decompressed data
 * @param output_len  Size of output buffer
 * @param written     Output: number of bytes written
 * @return DEFLATE_OK on success (end-of-block reached),
 *         DEFLATE_INCOMPLETE if input exhausted before end-of-block,
 *         DEFLATE_ERROR_INVALID_CODE if invalid literal/length code,
 *         DEFLATE_ERROR_INVALID_DISTANCE if invalid distance code (30-31),
 *         DEFLATE_ERROR_DISTANCE_TOO_FAR if distance exceeds output position,
 *         DEFLATE_ERROR if fixed tables not initialized or output buffer full
 */
extern SocketDeflate_Result
SocketDeflate_decode_fixed_block (SocketDeflate_BitReader_T reader,
                                  uint8_t *output, size_t output_len,
                                  size_t *written);

/*
 * Dynamic Huffman Block Decoder (RFC 1951 Section 3.2.7)
 *
 * Compressed blocks with dynamic Huffman codes transmit the code tables
 * in the block header itself. The header contains:
 * - HLIT, HDIST, HCLEN counts
 * - Code length Huffman table (in permuted order)
 * - Literal/length code lengths (with run-length encoding)
 * - Distance code lengths (with run-length encoding)
 *
 * The dynamic block format is the most complex but most common in real
 * compressed data, as it allows optimal Huffman codes per block.
 */

/**
 * Decode a dynamic Huffman block (BTYPE=10) from the bit stream.
 *
 * Per RFC 1951 Section 3.2.7:
 * 1. Reads HLIT, HDIST, HCLEN from header
 * 2. Reads code length code lengths (in permuted order)
 * 3. Builds code length Huffman table (max 7 bits)
 * 4. Decodes literal/length and distance code lengths
 * 5. Handles run-length codes (16, 17, 18)
 * 6. Builds dynamic literal/length table (max 15 bits)
 * 7. Builds dynamic distance table (max 15 bits)
 * 8. Decodes compressed data using LZ77 loop
 *
 * @param reader      Bit reader positioned after BTYPE bits
 * @param arena       Arena for table allocations (temporary tables)
 * @param output      Output buffer for decompressed data
 * @param output_len  Size of output buffer
 * @param written     Output: number of bytes written
 * @return DEFLATE_OK on success, error code on failure
 */
extern SocketDeflate_Result
SocketDeflate_decode_dynamic_block (SocketDeflate_BitReader_T reader,
                                    Arena_T arena, uint8_t *output,
                                    size_t output_len, size_t *written);

/*
 * Internal: Shared LZ77 Decode Loop
 *
 * This function is used by both fixed and dynamic block decoders.
 * Not intended for direct use by applications.
 */

/**
 * Core LZ77 decode loop for Huffman blocks.
 *
 * @param reader       Bit reader with input data
 * @param litlen_table Literal/length Huffman table
 * @param dist_table   Distance Huffman table
 * @param output       Output buffer
 * @param output_len   Output buffer size
 * @param written      Output: bytes written
 * @return DEFLATE_OK on success (end-of-block reached)
 */
extern SocketDeflate_Result
inflate_lz77 (SocketDeflate_BitReader_T reader,
              SocketDeflate_HuffmanTable_T litlen_table,
              SocketDeflate_HuffmanTable_T dist_table, uint8_t *output,
              size_t output_len, size_t *written);

/*
 * Streaming Inflate API
 *
 * High-level API for decompressing DEFLATE streams. Handles multi-block
 * streams, maintains sliding window for back-references, and provides
 * security limits against decompression bombs.
 */

/** Opaque inflater type for streaming decompression. */
typedef struct SocketDeflate_Inflater *SocketDeflate_Inflater_T;

/**
 * Create a new inflater.
 *
 * @param arena      Arena for allocation (inflater lifetime tied to arena)
 * @param max_output Maximum output size (0 = unlimited). Used for bomb
 *                   protection - returns DEFLATE_ERROR_BOMB if exceeded.
 * @return New inflater instance, or NULL on allocation failure
 */
extern SocketDeflate_Inflater_T SocketDeflate_Inflater_new (Arena_T arena,
                                                            size_t max_output);

/**
 * Decompress data (streaming).
 *
 * Processes input data and produces decompressed output. Can be called
 * multiple times for streaming decompression. The function handles
 * multi-block DEFLATE streams automatically.
 *
 * @param inf        The inflater
 * @param input      Input buffer (compressed data)
 * @param input_len  Size of input buffer
 * @param consumed   Output: bytes consumed from input
 * @param output     Output buffer (decompressed data)
 * @param output_len Size of output buffer
 * @param written    Output: bytes written to output
 * @return DEFLATE_OK when final block complete,
 *         DEFLATE_INCOMPLETE if more input needed,
 *         DEFLATE_OUTPUT_FULL if output buffer full (call again with more
 * space), DEFLATE_ERROR_INVALID_BTYPE if BTYPE=11 encountered, other error
 * codes on failure
 */
extern SocketDeflate_Result
SocketDeflate_Inflater_inflate (SocketDeflate_Inflater_T inf,
                                const uint8_t *input, size_t input_len,
                                size_t *consumed, uint8_t *output,
                                size_t output_len, size_t *written);

/**
 * Check if decompression is complete.
 *
 * @param inf The inflater
 * @return 1 if final block processed and complete, 0 otherwise
 */
extern int SocketDeflate_Inflater_finished (SocketDeflate_Inflater_T inf);

/**
 * Reset inflater for reuse.
 *
 * Clears all state including sliding window. After reset, the inflater
 * can be used to decompress a new stream.
 *
 * @param inf The inflater
 */
extern void SocketDeflate_Inflater_reset (SocketDeflate_Inflater_T inf);

/**
 * Get total bytes output so far.
 *
 * @param inf The inflater
 * @return Total decompressed bytes produced
 */
extern size_t SocketDeflate_Inflater_total_out (SocketDeflate_Inflater_T inf);

/**
 * Get total bytes consumed so far.
 *
 * @param inf The inflater
 * @return Total compressed bytes consumed
 */
extern size_t SocketDeflate_Inflater_total_in (SocketDeflate_Inflater_T inf);

/**
 * Get string representation of result code.
 *
 * @param result Result code
 * @return Human-readable error string (static, never NULL)
 */
extern const char *SocketDeflate_result_string (SocketDeflate_Result result);

/*
 * CRC-32 (ISO 3309 / IEEE 802.3)
 *
 * Standard CRC-32 used by gzip, PNG, and many other formats.
 * Uses polynomial 0xEDB88320 (reflected form of 0x04C11DB7).
 */

/**
 * Compute CRC-32 checksum.
 *
 * The CRC-32 algorithm uses the ISO 3309 polynomial in reflected form.
 * For initial computation, pass crc=0. For incremental updates, pass
 * the previous CRC value.
 *
 * @param crc   Initial CRC (0 for first call, previous result for updates)
 * @param data  Data buffer to checksum
 * @param len   Length of data in bytes
 * @return Updated CRC-32 value
 *
 * @note IEEE test vector: crc32(0, "123456789", 9) == 0xCBF43926
 */
extern uint32_t SocketDeflate_crc32 (uint32_t crc, const uint8_t *data,
                                     size_t len);

/**
 * Combine two CRC-32 values.
 *
 * Given CRC(A) and CRC(B), computes CRC(A || B) without needing the
 * original data. Useful for parallel CRC computation where chunks are
 * processed independently then combined.
 *
 * @param crc1  CRC-32 of first data block
 * @param crc2  CRC-32 of second data block
 * @param len2  Length of second data block in bytes
 * @return CRC-32 of concatenated blocks
 *
 * @note Uses matrix exponentiation of the CRC polynomial's companion matrix.
 *       Algorithm derived from zlib's crc32_combine.
 */
extern uint32_t SocketDeflate_crc32_combine (uint32_t crc1, uint32_t crc2,
                                             size_t len2);

/*
 * gzip Format Support (RFC 1952)
 *
 * gzip wraps DEFLATE data with a header and trailer for:
 * - File metadata (name, timestamp, OS)
 * - Data integrity (CRC-32 + original size)
 */

/** gzip magic bytes */
#define GZIP_MAGIC_0 0x1F
#define GZIP_MAGIC_1 0x8B

/** gzip compression methods */
#define GZIP_METHOD_DEFLATE 8

/** gzip header flags (RFC 1952 Section 2.3) */
#define GZIP_FLAG_FTEXT 0x01    /* Hint: file is ASCII text */
#define GZIP_FLAG_FHCRC 0x02    /* CRC16 of header present */
#define GZIP_FLAG_FEXTRA 0x04   /* Extra field present */
#define GZIP_FLAG_FNAME 0x08    /* Original filename present */
#define GZIP_FLAG_FCOMMENT 0x10 /* Comment present */

/** gzip OS codes (RFC 1952 Section 2.3) */
#define GZIP_OS_FAT         0   /* FAT filesystem (MS-DOS, OS/2, NT/Win32) */
#define GZIP_OS_AMIGA       1   /* Amiga */
#define GZIP_OS_VMS         2   /* VMS (or OpenVMS) */
#define GZIP_OS_UNIX        3   /* Unix */
#define GZIP_OS_VM_CMS      4   /* VM/CMS */
#define GZIP_OS_ATARI_TOS   5   /* Atari TOS */
#define GZIP_OS_HPFS        6   /* HPFS filesystem (OS/2, NT) */
#define GZIP_OS_MACINTOSH   7   /* Macintosh */
#define GZIP_OS_Z_SYSTEM    8   /* Z-System */
#define GZIP_OS_CP_M        9   /* CP/M */
#define GZIP_OS_TOPS_20     10  /* TOPS-20 */
#define GZIP_OS_NTFS        11  /* NTFS filesystem (NT) */
#define GZIP_OS_QDOS        12  /* QDOS */
#define GZIP_OS_ACORN_RISCOS 13 /* Acorn RISCOS */
#define GZIP_OS_UNKNOWN     255 /* Unknown */

/** Minimum gzip header size (no optional fields) */
#define GZIP_HEADER_MIN_SIZE 10

/** gzip trailer size (CRC32 + ISIZE) */
#define GZIP_TRAILER_SIZE 8

/**
 * Parsed gzip header information.
 *
 * @note The filename and comment pointers point directly into the input
 *       buffer passed to SocketDeflate_gzip_parse_header(). The caller
 *       must ensure the input buffer remains valid while accessing these
 *       fields. If you need the strings to outlive the input buffer,
 *       copy them before freeing/reusing the buffer.
 */
typedef struct
{
  uint8_t method;          /**< Compression method (8 = deflate) */
  uint8_t flags;           /**< Header flags */
  uint32_t mtime;          /**< Modification time (Unix timestamp) */
  uint8_t xfl;             /**< Extra flags (compression level hint) */
  uint8_t os;              /**< Operating system code */
  const uint8_t *filename; /**< Original filename (NULL-terminated, or NULL) */
  const uint8_t *comment;  /**< Comment (NULL-terminated, or NULL) */
  size_t header_size;      /**< Total header size in bytes */
} SocketDeflate_GzipHeader;

/**
 * Parse gzip header (RFC 1952 Section 2.3).
 *
 * Parses the gzip header and extracts metadata. The header_size field
 * indicates where the DEFLATE data begins. If FHCRC flag is set, the
 * header CRC16 is validated.
 *
 * @param data   Input buffer containing gzip header
 * @param len    Length of input buffer
 * @param header Output: parsed header information
 * @return DEFLATE_OK on success,
 *         DEFLATE_INCOMPLETE if more data needed,
 *         DEFLATE_ERROR_GZIP_MAGIC if magic bytes invalid,
 *         DEFLATE_ERROR_GZIP_METHOD if method not 8 (deflate),
 *         DEFLATE_ERROR_GZIP_HCRC if header CRC16 mismatch
 */
extern SocketDeflate_Result
SocketDeflate_gzip_parse_header (const uint8_t *data, size_t len,
                                 SocketDeflate_GzipHeader *header);

/**
 * Verify gzip trailer (RFC 1952 Section 2.3.1).
 *
 * Checks CRC-32 and original size (ISIZE) against computed values.
 * The trailer is 8 bytes: 4-byte CRC32 + 4-byte ISIZE, both little-endian.
 *
 * @param trailer       8-byte gzip trailer
 * @param computed_crc  CRC-32 computed from decompressed data
 * @param computed_size Original size mod 2^32 from decompression
 * @return DEFLATE_OK if trailer matches,
 *         DEFLATE_ERROR_GZIP_CRC if CRC mismatch,
 *         DEFLATE_ERROR_GZIP_SIZE if size mismatch
 */
extern SocketDeflate_Result
SocketDeflate_gzip_verify_trailer (const uint8_t *trailer,
                                   uint32_t computed_crc,
                                   uint32_t computed_size);

/**
 * Check if OS code is a known value.
 *
 * @param os OS code from gzip header
 * @return 1 if known (0-13 or 255), 0 if unknown/reserved
 */
extern int SocketDeflate_gzip_is_valid_os (uint8_t os);

/**
 * Get string name for OS code.
 *
 * @param os OS code from gzip header
 * @return Human-readable OS name (static string, never NULL)
 */
extern const char *SocketDeflate_gzip_os_string (uint8_t os);

/** @} */ /* end of deflate group */

#endif /* SOCKETDEFLATE_INCLUDED */

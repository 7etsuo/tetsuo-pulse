/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_CORE_H
#define SOCKETUTIL_CORE_H

/**
 * @file SocketUtil/Core.h
 * @ingroup foundation
 * @brief Core utility macros for bit manipulation, array operations, and more.
 *
 * This header provides foundational macros used throughout the socket library:
 * - Array length calculation
 * - Bit manipulation (masks, append, extract)
 * - Ring buffer indexing
 * - ASCII case conversion
 * - DJB2 hash steps
 * - MIN/MAX utilities
 */

#include <stdint.h>

/* ============================================================================
 * ARRAY UTILITIES
 * ============================================================================
 */

/**
 * @brief ARRAY_LENGTH - Calculate number of elements in a static array
 * @param arr Array name (must be a static array, not a pointer)
 * @ingroup foundation
 *
 * Calculates the number of elements in a statically-allocated array at
 * compile time. This is the standard C idiom for array length calculation.
 *
 * WARNING: This macro only works for arrays with static storage duration
 * (declared with a known size at compile time). It will give incorrect
 * results if used on:
 * - Pointers (including function parameters declared as arrays)
 * - Dynamically allocated arrays
 * - Variable-length arrays (VLAs)
 *
 * Example:
 *   static const char *states[] = {"Ready", "Send", "DataSent"};
 *   for (size_t i = 0; i < ARRAY_LENGTH(states); i++) {
 *     printf("%s\n", states[i]);
 *   }
 */
#define ARRAY_LENGTH(arr) (sizeof (arr) / sizeof ((arr)[0]))

/* ============================================================================
 * BIT MANIPULATION MACROS
 * ============================================================================
 */

/**
 * @brief BITMASK32 - Create a 32-bit mask with N lowest bits set
 * @param n Number of bits to set (0-32)
 * @ingroup foundation
 *
 * Creates a bitmask with the lowest N bits set to 1.
 * For n=0 returns 0, for n=8 returns 0xFF, for n=32 returns 0xFFFFFFFF.
 *
 * @warning n must be in range 0-32; undefined behavior for n > 32
 * @see BITMASK64 for 64-bit version
 */
#define BITMASK32(n) ((1U << (n)) - 1U)

/**
 * @brief BITMASK64 - Create a 64-bit mask with N lowest bits set
 * @param n Number of bits to set (0-64)
 * @ingroup foundation
 *
 * Creates a 64-bit bitmask with the lowest N bits set to 1.
 * For n=0 returns 0, for n=30 returns 0x3FFFFFFF.
 *
 * @warning n must be in range 0-64; undefined behavior for n > 64
 * @see BITMASK32 for 32-bit version
 */
#define BITMASK64(n) ((1ULL << (n)) - 1ULL)

/**
 * @brief BITS_APPEND - Append N bits to a bit accumulator
 * @param acc Bit accumulator (modified in place)
 * @param value Value containing bits to append
 * @param n Number of bits to append
 * @ingroup foundation
 *
 * Shifts accumulator left by N bits and ORs in the new value.
 * Common pattern in Huffman encoding and bit-stream packing.
 */
#define BITS_APPEND(acc, value, n) ((acc) = ((acc) << (n)) | (value))

/**
 * @brief BITS_EXTRACT_TOP - Extract top N bits from accumulator
 * @param bits Bit accumulator
 * @param bits_avail Number of valid bits in accumulator
 * @param n Number of bits to extract
 * @return Top N bits, right-aligned
 * @ingroup foundation
 */
#define BITS_EXTRACT_TOP(bits, bits_avail, n) ((bits) >> ((bits_avail) - (n)))

/**
 * @brief BITS_TOP_BYTE - Extract top byte from bit accumulator
 * @param bits Bit accumulator
 * @param bits_avail Number of valid bits (must be >= 8)
 * @return Top 8 bits as unsigned char
 * @ingroup foundation
 */
#define BITS_TOP_BYTE(bits, bits_avail) \
  ((unsigned char)((bits) >> (bits_avail)))

/**
 * @brief BITS_PAD_EOS - Pad remaining bits with 1s (EOS pattern)
 * @param bits Bit accumulator with partial byte
 * @param pad_bits Number of padding bits needed (1-7)
 * @return Padded byte value
 * @ingroup foundation
 *
 * Per RFC 7541 §5.2, Huffman-encoded data must be padded with
 * most-significant bits of the EOS symbol (all 1s).
 */
#define BITS_PAD_EOS(bits, pad_bits) \
  (((bits) << (pad_bits)) | BITMASK32 (pad_bits))

/**
 * @brief HASH_KEY64 - Combine two 32-bit values into 64-bit hash key
 * @param hi High 32 bits
 * @param lo Low 32 bits
 * @return Combined 64-bit key
 * @ingroup foundation
 */
#define HASH_KEY64(hi, lo) (((uint64_t)(hi) << 32) | (uint64_t)(lo))

/**
 * @brief RINGBUF_WRAP - Wrap index for power-of-2 circular buffer
 * @param index Index value (may exceed capacity)
 * @param capacity Buffer capacity (MUST be power of 2)
 * @return Wrapped index in range [0, capacity-1]
 * @ingroup foundation
 *
 * @warning capacity MUST be a power of 2, otherwise results are undefined
 */
#define RINGBUF_WRAP(index, capacity) ((index) & ((capacity) - 1))

/* ============================================================================
 * ASCII CASE CONVERSION
 * ============================================================================
 */

/**
 * @brief ASCII_CASE_OFFSET - Offset between uppercase and lowercase ASCII
 * @ingroup foundation
 *
 * The difference between 'a' and 'A' in ASCII (32).
 */
#define ASCII_CASE_OFFSET 32

/**
 * @brief ASCII_TOLOWER - Convert ASCII uppercase letter to lowercase
 * @param c Character to convert (evaluated once)
 * @return Lowercase version of c if uppercase letter, otherwise unchanged
 * @ingroup foundation
 *
 * Branchless implementation for efficient case-insensitive operations.
 */
/** @cond INTERNAL */
/* Branchless: if c in A-Z, (c - 'A') is 0-25, unsigned < 26 is true (1),
 * shift left 5 gives 32 (ASCII_CASE_OFFSET), add to c converts to lowercase.
 * For non-letters, (c - 'A') wraps or >= 26, comparison is false (0),
 * 0 << 5 = 0, c unchanged. */
/** @endcond */
#define ASCII_TOLOWER(c) ((c) + (((unsigned)(c) - 'A' < 26U) << 5))

/* ============================================================================
 * DJB2 HASH STEP MACROS
 * ============================================================================
 */

/**
 * @brief DJB2_STEP - One step of DJB2 hash algorithm (addition variant)
 * @param hash Current hash value
 * @param c Character/byte to hash
 * @return Updated hash value
 * @ingroup foundation
 *
 * Implements: hash = hash * 33 + c
 * Optimized as (hash << 5) + hash + c which avoids multiplication.
 */
#define DJB2_STEP(hash, c) (((hash) << 5) + (hash) + (c))

/**
 * @brief DJB2_STEP_XOR - One step of DJB2 hash algorithm (XOR variant)
 * @param hash Current hash value
 * @param c Character/byte to hash
 * @return Updated hash value
 * @ingroup foundation
 *
 * Implements: hash = hash * 33 ^ c
 * Better avalanche for security-sensitive hashing.
 */
#define DJB2_STEP_XOR(hash, c) ((((hash) << 5) + (hash)) ^ (c))

/**
 * @brief HEX_NIBBLES_TO_BYTE - Combine two hex nibbles into a byte
 * @param hi High nibble (0-15)
 * @param lo Low nibble (0-15)
 * @return Combined byte value
 * @ingroup foundation
 */
#define HEX_NIBBLES_TO_BYTE(hi, lo) (((hi) << 4) | (lo))

/**
 * @brief HASH_PRIME_31 - Prime multiplier for byte sequence hashing
 * @ingroup foundation
 *
 * Prime 31 is optimized for random byte sequences (vs DJB2's 33 for ASCII).
 * Compiler optimizes 31*x as (x << 5) - x.
 */
#define HASH_PRIME_31 31

/* ============================================================================
 * MIN/MAX UTILITIES
 * ============================================================================
 */

/**
 * @brief MIN - Compute minimum of two values
 * @ingroup foundation
 * @param a First value
 * @param b Second value
 * @return Minimum value
 *
 * Type-generic min macro using GNU statement expression.
 * Evaluates arguments once (no side-effect issues).
 */
#ifndef MIN
#define MIN(a, b)            \
  ({                         \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b;       \
  })
#endif

/**
 * @brief MAX - Compute maximum of two values
 * @ingroup foundation
 * @param a First value
 * @param b Second value
 * @return Maximum value
 *
 * Type-generic max macro using GNU statement expression.
 * Evaluates arguments once (no side-effect issues).
 */
#ifndef MAX
#define MAX(a, b)            \
  ({                         \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b;       \
  })
#endif

#endif /* SOCKETUTIL_CORE_H */

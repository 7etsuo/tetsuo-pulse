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

/**
 * @brief BITMASK32 - Create a 32-bit mask with N lowest bits set
 * @param n Number of bits to set (0-32)
 * @ingroup foundation
 *
 * Creates a bitmask with the lowest N bits set to 1.
 * For n=0 returns 0, for n=8 returns 0xFF, for n=32 returns 0xFFFFFFFF.
 *
 * Uses right-shift of all-ones to avoid undefined behavior when n equals
 * the type width (left-shifting by 32 bits is UB for uint32_t).
 *
 * @warning n must be in range 0-32
 * @see BITMASK64 for 64-bit version
 */
#define BITMASK32(n) ((n) == 0 ? 0U : ~0U >> (32 - (n)))

/**
 * @brief BITMASK64 - Create a 64-bit mask with N lowest bits set
 * @param n Number of bits to set (0-64)
 * @ingroup foundation
 *
 * Creates a 64-bit bitmask with the lowest N bits set to 1.
 * For n=0 returns 0, for n=30 returns 0x3FFFFFFF, for n=64 returns all ones.
 *
 * Uses right-shift of all-ones to avoid undefined behavior when n equals
 * the type width (left-shifting by 64 bits is UB for uint64_t).
 *
 * @warning n must be in range 0-64
 * @see BITMASK32 for 32-bit version
 */
#define BITMASK64(n) ((n) == 0 ? 0ULL : ~0ULL >> (64 - (n)))

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

/**
 * @brief IS_POWER_OF_2 - Check if value is a power of 2
 * @param x Value to check (must be unsigned integer type)
 * @return Non-zero if x is a power of 2, zero otherwise
 * @ingroup foundation
 *
 * Uses the classic bithack: powers of 2 have exactly one bit set,
 * so (x & (x-1)) clears that bit, resulting in zero.
 * Special case: 0 is not a power of 2.
 */
#define IS_POWER_OF_2(x) ((x) != 0 && (((x) & ((x) - 1)) == 0))

/**
 * @brief ALIGN_UP - Round up to next alignment boundary
 * @param x Value to align
 * @param align Alignment (MUST be power of 2)
 * @return x rounded up to next multiple of align
 * @ingroup foundation
 *
 * @warning align MUST be a power of 2, otherwise results are undefined
 */
#define ALIGN_UP(x, align) (((x) + ((align) - 1)) & ~((align) - 1))

/**
 * @brief ALIGN_DOWN - Round down to alignment boundary
 * @param x Value to align
 * @param align Alignment (MUST be power of 2)
 * @return x rounded down to previous multiple of align
 * @ingroup foundation
 *
 * @warning align MUST be a power of 2, otherwise results are undefined
 */
#define ALIGN_DOWN(x, align) ((x) & ~((align) - 1))

#if defined(__GNUC__) || defined(__clang__)

/**
 * @brief CLZ32 - Count leading zeros in 32-bit value
 * @param x Value to count (MUST be non-zero)
 * @return Number of leading zero bits (0-31)
 * @ingroup foundation
 *
 * @warning x MUST be non-zero; result is undefined for x=0
 */
#define CLZ32(x) __builtin_clz (x)

/**
 * @brief CLZ64 - Count leading zeros in 64-bit value
 * @param x Value to count (MUST be non-zero)
 * @return Number of leading zero bits (0-63)
 * @ingroup foundation
 *
 * @warning x MUST be non-zero; result is undefined for x=0
 */
#define CLZ64(x) __builtin_clzll (x)

/**
 * @brief CTZ32 - Count trailing zeros in 32-bit value
 * @param x Value to count (MUST be non-zero)
 * @return Number of trailing zero bits (0-31)
 * @ingroup foundation
 *
 * @warning x MUST be non-zero; result is undefined for x=0
 */
#define CTZ32(x) __builtin_ctz (x)

/**
 * @brief CTZ64 - Count trailing zeros in 64-bit value
 * @param x Value to count (MUST be non-zero)
 * @return Number of trailing zero bits (0-63)
 * @ingroup foundation
 *
 * @warning x MUST be non-zero; result is undefined for x=0
 */
#define CTZ64(x) __builtin_ctzll (x)

/**
 * @brief POPCOUNT32 - Count set bits in 32-bit value
 * @param x Value to count
 * @return Number of bits set to 1 (0-32)
 * @ingroup foundation
 */
#define POPCOUNT32(x) __builtin_popcount (x)

/**
 * @brief POPCOUNT64 - Count set bits in 64-bit value
 * @param x Value to count
 * @return Number of bits set to 1 (0-64)
 * @ingroup foundation
 */
#define POPCOUNT64(x) __builtin_popcountll (x)

/**
 * @brief NEXT_POW2_32 - Round up to next power of 2 (32-bit)
 * @param x Value to round up (0 < x <= 2^31)
 * @return Smallest power of 2 >= x
 * @ingroup foundation
 *
 * Uses CLZ to find the position of the highest set bit.
 * For x=0, returns 1. For x already a power of 2, returns x.
 *
 * @warning For x > 2^31, result overflows
 */
#define NEXT_POW2_32(x) ((x) <= 1 ? 1U : 1U << (32 - CLZ32 ((x) - 1)))

/**
 * @brief NEXT_POW2_64 - Round up to next power of 2 (64-bit)
 * @param x Value to round up (0 < x <= 2^63)
 * @return Smallest power of 2 >= x
 * @ingroup foundation
 *
 * Uses CLZ to find the position of the highest set bit.
 * For x=0, returns 1. For x already a power of 2, returns x.
 *
 * @warning For x > 2^63, result overflows
 */
#define NEXT_POW2_64(x) ((x) <= 1 ? 1ULL : 1ULL << (64 - CLZ64 ((x) - 1)))

#endif /* __GNUC__ || __clang__ */

/**
 * @brief ROTL32 - Rotate 32-bit value left
 * @param x Value to rotate
 * @param n Number of bits to rotate (0-31)
 * @return Rotated value
 * @ingroup foundation
 *
 * Bits shifted out on the left wrap around to the right.
 * Modern compilers recognize this pattern and emit single ROL instruction.
 */
#define ROTL32(x, n) \
  ((uint32_t)(x) << ((n) & 31) | (uint32_t)(x) >> (32 - ((n) & 31)))

/**
 * @brief ROTR32 - Rotate 32-bit value right
 * @param x Value to rotate
 * @param n Number of bits to rotate (0-31)
 * @return Rotated value
 * @ingroup foundation
 *
 * Bits shifted out on the right wrap around to the left.
 * Modern compilers recognize this pattern and emit single ROR instruction.
 */
#define ROTR32(x, n) \
  ((uint32_t)(x) >> ((n) & 31) | (uint32_t)(x) << (32 - ((n) & 31)))

/**
 * @brief ROTL64 - Rotate 64-bit value left
 * @param x Value to rotate
 * @param n Number of bits to rotate (0-63)
 * @return Rotated value
 * @ingroup foundation
 */
#define ROTL64(x, n) \
  ((uint64_t)(x) << ((n) & 63) | (uint64_t)(x) >> (64 - ((n) & 63)))

/**
 * @brief ROTR64 - Rotate 64-bit value right
 * @param x Value to rotate
 * @param n Number of bits to rotate (0-63)
 * @return Rotated value
 * @ingroup foundation
 */
#define ROTR64(x, n) \
  ((uint64_t)(x) >> ((n) & 63) | (uint64_t)(x) << (64 - ((n) & 63)))

/**
 * @brief BYTE0 - Extract byte 0 (least significant) from value
 * @param x Value to extract from
 * @return Bits 0-7 as uint8_t
 * @ingroup foundation
 */
#define BYTE0(x) ((uint8_t)((x) & 0xFF))

/**
 * @brief BYTE1 - Extract byte 1 from value
 * @param x Value to extract from
 * @return Bits 8-15 as uint8_t
 * @ingroup foundation
 */
#define BYTE1(x) ((uint8_t)(((x) >> 8) & 0xFF))

/**
 * @brief BYTE2 - Extract byte 2 from value
 * @param x Value to extract from
 * @return Bits 16-23 as uint8_t
 * @ingroup foundation
 */
#define BYTE2(x) ((uint8_t)(((x) >> 16) & 0xFF))

/**
 * @brief BYTE3 - Extract byte 3 (most significant of 32-bit) from value
 * @param x Value to extract from
 * @return Bits 24-31 as uint8_t
 * @ingroup foundation
 */
#define BYTE3(x) ((uint8_t)(((x) >> 24) & 0xFF))

/**
 * @brief SIGN_EXTEND - Sign-extend a value from N bits to 32 bits
 * @param x Value to sign-extend (N-bit signed value in low bits)
 * @param bits Number of bits in original value (1-31)
 * @return Sign-extended 32-bit value
 * @ingroup foundation
 *
 * Uses arithmetic right shift to replicate the sign bit.
 * Example: SIGN_EXTEND(0x80, 8) -> 0xFFFFFF80 (-128)
 *          SIGN_EXTEND(0x7F, 8) -> 0x0000007F (+127)
 */
#define SIGN_EXTEND(x, bits) \
  (((int32_t)((uint32_t)(x) << (32 - (bits)))) >> (32 - (bits)))

/**
 * @brief SIGN_EXTEND64 - Sign-extend a value from N bits to 64 bits
 * @param x Value to sign-extend (N-bit signed value in low bits)
 * @param bits Number of bits in original value (1-63)
 * @return Sign-extended 64-bit value
 * @ingroup foundation
 */
#define SIGN_EXTEND64(x, bits) \
  (((int64_t)((uint64_t)(x) << (64 - (bits)))) >> (64 - (bits)))

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

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_HASH_H
#define SOCKETUTIL_HASH_H

/**
 * @file SocketUtil/Hash.h
 * @ingroup foundation
 * @brief Hash function utilities for tables, caches, and lookups.
 *
 * Provides:
 * - Golden ratio hash for integers/pointers
 * - DJB2 hash variants (standard, case-insensitive, seeded)
 * - Prime 31 hash for byte sequences
 * - Power-of-2 rounding
 * - DNS hostname normalization
 */

#include <stddef.h>
#include <stdint.h>

#include "core/SocketConfig.h"
#include "core/SocketUtil/Core.h"

/* ============================================================================
 * GOLDEN RATIO HASH FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Hash file descriptor using golden ratio multiplicative.
 * @ingroup foundation
 * @param fd File descriptor to hash (non-negative).
 * @param table_size Hash table size (should be prime for best distribution).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function, no shared state)
 */
static inline unsigned
socket_util_hash_fd (int fd, unsigned table_size)
{
  return ((unsigned)fd * HASH_GOLDEN_RATIO) % table_size;
}

/**
 * @brief Hash pointer using golden ratio multiplicative.
 * @ingroup foundation
 * @param ptr Pointer to hash (may be NULL).
 * @param table_size Hash table size (should be prime for best distribution).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function, no shared state)
 */
static inline unsigned
socket_util_hash_ptr (const void *ptr, unsigned table_size)
{
  return ((unsigned)(uintptr_t)ptr * HASH_GOLDEN_RATIO) % table_size;
}

/**
 * @brief Hash unsigned integer using golden ratio.
 * @ingroup foundation
 * @param value Unsigned integer to hash.
 * @param table_size Hash table size (should be prime for best distribution).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function, no shared state)
 */
static inline unsigned
socket_util_hash_uint (unsigned value, unsigned table_size)
{
  return (value * HASH_GOLDEN_RATIO) % table_size;
}

/**
 * @brief Seeded hash for collision resistance in security contexts.
 * @ingroup foundation
 * @param value Unsigned integer to hash.
 * @param table_size Hash table size (should be prime).
 * @param seed Per-instance random seed.
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function)
 */
static inline unsigned
socket_util_hash_uint_seeded (unsigned value,
                              unsigned table_size,
                              uint32_t seed)
{
  uint64_t h = (uint64_t)value * HASH_GOLDEN_RATIO + (uint64_t)seed;
  return (unsigned)(h % table_size);
}

/* ============================================================================
 * DJB2 HASH FUNCTIONS
 * ============================================================================
 */

/** DJB2 hash algorithm seed value (Daniel J. Bernstein) */
#define SOCKET_UTIL_DJB2_SEED 5381u

/**
 * @brief Hash string using DJB2 algorithm.
 * @ingroup foundation
 * @param str String to hash (must not be NULL).
 * @param table_size Hash table size (should be prime for best distribution).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function, no shared state)
 *
 * DJB2 hash: hash = hash * 33 + c
 * NOT cryptographic - do not use for security-sensitive purposes.
 */
static inline unsigned
socket_util_hash_djb2 (const char *str, unsigned table_size)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;
  int c;

  while ((c = *str++) != '\0')
    hash = DJB2_STEP (hash, (unsigned)c);

  return hash % table_size;
}

/**
 * @brief Hash string with explicit length using DJB2.
 * @ingroup foundation
 * @param str String to hash (may contain null bytes).
 * @param len Length of string.
 * @param table_size Hash table size (should be prime for best distribution).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function, no shared state)
 */
static inline unsigned
socket_util_hash_djb2_len (const char *str, size_t len, unsigned table_size)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;
  size_t i;

  for (i = 0; i < len; i++)
    hash = DJB2_STEP (hash, (unsigned char)str[i]);

  return hash % table_size;
}

/**
 * @brief Case-insensitive DJB2 hash.
 * @ingroup foundation
 * @param str String to hash (must not be NULL).
 * @param table_size Hash table size (should be prime for best distribution).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function, no shared state)
 */
static inline unsigned
socket_util_hash_djb2_ci (const char *str, unsigned table_size)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;
  int c;

  while ((c = *str++) != '\0')
    {
      c = ASCII_TOLOWER (c);
      hash = DJB2_STEP (hash, (unsigned)c);
    }

  return hash % table_size;
}

/**
 * @brief Case-insensitive length-aware DJB2 hash.
 * @ingroup foundation
 * @param str String to hash (may contain null bytes).
 * @param len Length of string.
 * @param table_size Hash table size (should be prime for best distribution).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function, no shared state)
 */
static inline unsigned
socket_util_hash_djb2_ci_len (const char *str, size_t len, unsigned table_size)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;
  size_t i;

  for (i = 0; i < len; i++)
    {
      unsigned char c = ASCII_TOLOWER ((unsigned char)str[i]);
      hash = DJB2_STEP (hash, c);
    }

  return hash % table_size;
}

/**
 * @brief Seeded DJB2 hash for DoS-resistant string hashing.
 * @ingroup foundation
 * @param str String to hash (must not be NULL).
 * @param table_size Hash table size (should be prime).
 * @param seed Per-instance random seed for collision resistance.
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function)
 */
static inline unsigned
socket_util_hash_djb2_seeded (const char *str,
                              unsigned table_size,
                              uint32_t seed)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;

  /* Mix in random seed for DoS protection */
  hash = DJB2_STEP_XOR (hash, seed);

  /* Hash the string */
  for (const char *p = str; *p; p++)
    hash = DJB2_STEP_XOR (hash, (unsigned char)*p);

  return hash % table_size;
}

/**
 * @brief Case-insensitive seeded DJB2 hash.
 * @ingroup foundation
 * @param str String to hash (must not be NULL).
 * @param table_size Hash table size (should be prime).
 * @param seed Per-instance random seed for collision resistance.
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function)
 */
static inline unsigned
socket_util_hash_djb2_seeded_ci (const char *str,
                                 unsigned table_size,
                                 uint32_t seed)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;

  /* Mix in random seed for DoS protection */
  hash = DJB2_STEP_XOR (hash, seed);

  /* Hash the string with case folding */
  for (const char *p = str; *p; p++)
    {
      unsigned char c = ASCII_TOLOWER ((unsigned char)*p);
      hash = DJB2_STEP_XOR (hash, c);
    }

  return hash % table_size;
}

/**
 * @brief Seeded case-insensitive length-aware DJB2 hash.
 * @ingroup foundation
 * @param str String to hash (may not be null-terminated).
 * @param len Length of string.
 * @param table_size Hash table size (should be prime for best distribution).
 * @param seed Per-instance random seed for DoS resistance.
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function)
 */
static inline unsigned
socket_util_hash_djb2_seeded_ci_len (const char *str,
                                     size_t len,
                                     unsigned table_size,
                                     uint32_t seed)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED ^ seed;

  /* Hash the string with case folding */
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = ASCII_TOLOWER ((unsigned char)str[i]);
      hash = DJB2_STEP_XOR (hash, c);
    }

  return hash % table_size;
}

/* ============================================================================
 * PRIME 31 HASH FOR BYTE SEQUENCES
 * ============================================================================
 */

/**
 * @brief Hash byte sequence with prime multiplier 31 for random data.
 * @ingroup foundation
 * @param data Byte sequence to hash (may contain any byte values).
 * @param len Length of byte sequence.
 * @param max_len Maximum bytes to hash from data (for performance).
 * @return Hash value (before modulo/masking).
 * @threadsafe Yes (pure function, no shared state)
 *
 * Uses prime 31 optimized for random byte sequences (vs DJB2's 33 for ASCII).
 * Returns raw hash for use with golden ratio mixing or power-of-2 masking.
 */
static inline unsigned
socket_util_hash_bytes_prime31 (const unsigned char *data,
                                size_t len,
                                size_t max_len)
{
  unsigned hash = 0;
  size_t limit = (len < max_len) ? len : max_len;
  size_t i = 0;

  /* 4-way unrolled for better instruction-level parallelism */
  for (; i + 4 <= limit; i += 4)
    {
      hash = hash * HASH_PRIME_31 + data[i];
      hash = hash * HASH_PRIME_31 + data[i + 1];
      hash = hash * HASH_PRIME_31 + data[i + 2];
      hash = hash * HASH_PRIME_31 + data[i + 3];
    }

  /* Handle remaining 0-3 bytes */
  for (; i < limit; i++)
    hash = hash * HASH_PRIME_31 + data[i];

  return hash;
}

/* ============================================================================
 * DNS HOSTNAME UTILITIES
 * ============================================================================
 */

/**
 * @brief Normalize hostname to lowercase for case-insensitive comparison.
 * @ingroup foundation
 * @param dest Destination buffer.
 * @param src Source hostname.
 * @param max_len Maximum length of destination buffer.
 * @threadsafe Yes (pure function)
 *
 * DNS names are case-insensitive per RFC 1035. This function normalizes
 * names for consistent hashing and comparison in caches.
 */
static inline void
socket_util_normalize_hostname (char *dest, const char *src, size_t max_len)
{
  size_t i;
  for (i = 0; src[i] && i < max_len - 1; i++)
    dest[i] = (char)ASCII_TOLOWER ((unsigned char)src[i]);
  dest[i] = '\0';
}

/* ============================================================================
 * POWER OF 2 UTILITIES
 * ============================================================================
 */

/**
 * @brief Round up to next power of 2.
 * @ingroup foundation
 * @param n Value to round up (must be > 0).
 * @return Smallest power of 2 >= n.
 * @threadsafe Yes (pure function)
 *
 * Useful for hash table sizing and circular buffer capacities
 * where power-of-2 sizes allow efficient modulo via bitwise AND.
 *
 * Uses NEXT_POW2_32/64 macros from Core.h when available (GCC/Clang),
 * falls back to bit-smearing for other compilers.
 */
static inline size_t
socket_util_round_up_pow2 (size_t n)
{
#if defined(__GNUC__) || defined(__clang__)
  /* Use optimized CLZ-based macros from Core.h */
#if SIZE_MAX > 0xFFFFFFFF
  return (size_t)NEXT_POW2_64 (n);
#else
  return (size_t)NEXT_POW2_32 (n);
#endif

#else
  /* Fallback: bit-smearing approach for non-GCC/Clang */
  if (n <= 1)
    return 1;
  n--;
  n |= n >> 1;
  n |= n >> 2;
  n |= n >> 4;
  n |= n >> 8;
  n |= n >> 16;
#if SIZE_MAX > 0xFFFFFFFF
  n |= n >> 32;
#endif
  return n + 1;
#endif
}

#endif /* SOCKETUTIL_HASH_H */

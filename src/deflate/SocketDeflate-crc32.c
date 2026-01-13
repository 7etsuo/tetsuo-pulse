/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDeflate-crc32.c
 * @brief CRC-32 implementation for gzip support.
 *
 * Implements CRC-32 using the ISO 3309/IEEE 802.3 polynomial (0xEDB88320
 * reflected form). This is the standard CRC used by gzip, PNG, and many
 * other formats.
 *
 * @see RFC 1952 Section 8 - CRC-32 algorithm
 */

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#include "deflate/SocketDeflate.h"

/*
 * CRC-32 lookup table.
 *
 * Generated using the reflected polynomial 0xEDB88320. Each entry
 * represents the CRC contribution of a single byte value (0-255).
 */
static uint32_t crc32_table[256];
static pthread_once_t crc32_init_once = PTHREAD_ONCE_INIT;

/**
 * Initialize the CRC-32 lookup table.
 *
 * Uses the ISO 3309 polynomial in reflected form:
 *   x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 +
 *   x^5 + x^4 + x^2 + x + 1
 *
 * The reflected polynomial 0xEDB88320 processes bits LSB-first, which
 * matches how bytes are processed in the streaming algorithm.
 */
static void
crc32_init_table (void)
{
  uint32_t poly = 0xEDB88320U;

  for (int i = 0; i < 256; i++)
    {
      uint32_t crc = (uint32_t)i;
      for (int j = 0; j < 8; j++)
        {
          if (crc & 1)
            crc = (crc >> 1) ^ poly;
          else
            crc >>= 1;
        }
      crc32_table[i] = crc;
    }
}

/**
 * Compute CRC-32 checksum.
 *
 * The algorithm processes data byte-by-byte using the precomputed table.
 * The CRC is initialized to 0xFFFFFFFF and the final result is XORed
 * with 0xFFFFFFFF (one's complement).
 *
 * For incremental updates, pass the previous result as the crc parameter.
 * The function handles the pre/post XOR internally, so incremental usage is:
 *
 *   uint32_t crc = 0;
 *   crc = SocketDeflate_crc32(crc, chunk1, len1);
 *   crc = SocketDeflate_crc32(crc, chunk2, len2);
 *   // crc now contains CRC of chunk1+chunk2
 *
 * @param crc   Initial CRC (0 for first call, previous result for updates)
 * @param data  Data buffer to checksum
 * @param len   Length of data in bytes
 * @return Updated CRC-32 value
 */
uint32_t
SocketDeflate_crc32 (uint32_t crc, const uint8_t *data, size_t len)
{
  /* Handle NULL data or zero length */
  if (data == NULL || len == 0)
    return crc;

  /* Thread-safe table initialization */
  pthread_once (&crc32_init_once, crc32_init_table);

  /* Pre-condition: complement the input CRC */
  crc = ~crc;

  /* Process each byte using table lookup */
  for (size_t i = 0; i < len; i++)
    {
      uint8_t index = (crc ^ data[i]) & 0xFF;
      crc = crc32_table[index] ^ (crc >> 8);
    }

  /* Post-condition: complement the result */
  return ~crc;
}

/*
 * GF(2) matrix operations for crc32_combine.
 *
 * CRC-32 is a linear function over GF(2), meaning:
 *   CRC(A ^ B) = CRC(A) ^ CRC(B)
 *   CRC(A || zeros) = matrix_mult(CRC(A), power_matrix)
 *
 * This allows combining CRCs without the original data.
 */

/**
 * Multiply a GF(2) vector by a GF(2) matrix.
 *
 * Each bit of vec selects whether to XOR the corresponding matrix row.
 *
 * @param mat  32x32 matrix (mat[i] = row i as 32-bit value)
 * @param vec  32-bit vector
 * @return Matrix-vector product
 */
static uint32_t
gf2_matrix_times (const uint32_t *mat, uint32_t vec)
{
  uint32_t sum = 0;

  while (vec)
    {
      if (vec & 1)
        sum ^= *mat;
      vec >>= 1;
      mat++;
    }

  return sum;
}

/**
 * Square a GF(2) matrix in place.
 *
 * @param square Output: mat * mat
 * @param mat    Input matrix
 */
static void
gf2_matrix_square (uint32_t *square, const uint32_t *mat)
{
  for (int n = 0; n < 32; n++)
    square[n] = gf2_matrix_times (mat, mat[n]);
}

/**
 * Initialize odd-power-of-two operator matrix.
 *
 * odd[0] = polynomial (effect of one zero bit)
 * odd[n] = effect of shifting by n bits
 *
 * @param odd Output: 32x32 GF(2) matrix
 */
static void
gf2_init_odd_matrix (uint32_t *odd)
{
  odd[0] = 0xEDB88320U; /* CRC polynomial */
  uint32_t row = 1;
  for (int n = 1; n < 32; n++)
    {
      odd[n] = row;
      row <<= 1;
    }
}

/**
 * Apply len zeros to CRC using repeated squaring.
 *
 * Uses binary exponentiation to efficiently compute CRC(data || zeros)
 * from CRC(data) without processing the actual zero bytes.
 *
 * @param crc   Input CRC value
 * @param odd   Odd-power operator matrix (modified during computation)
 * @param even  Even-power operator matrix (modified during computation)
 * @param len   Number of zero bytes to apply
 * @return CRC after appending len zero bytes
 */
static uint32_t
gf2_apply_zeros (uint32_t crc, uint32_t *odd, uint32_t *even, size_t len)
{
  while (len != 0)
    {
      gf2_matrix_square (even, odd);
      if (len & 1)
        crc = gf2_matrix_times (even, crc);
      len >>= 1;

      if (len == 0)
        break;

      gf2_matrix_square (odd, even);
      if (len & 1)
        crc = gf2_matrix_times (odd, crc);
      len >>= 1;
    }

  return crc;
}

/**
 * Combine two CRC-32 values.
 *
 * Given CRC(A) and CRC(B), computes CRC(A || B) without the original data.
 * Uses the identity: CRC(A || B) = CRC(A || zeros) ^ CRC(B)
 * where CRC(A || zeros) is computed via matrix exponentiation.
 *
 * Algorithm derived from zlib's crc32_combine by Mark Adler.
 */
uint32_t
SocketDeflate_crc32_combine (uint32_t crc1, uint32_t crc2, size_t len2)
{
  uint32_t even[32];
  uint32_t odd[32];

  if (len2 == 0)
    return crc1;

  pthread_once (&crc32_init_once, crc32_init_table);

  gf2_init_odd_matrix (odd);
  gf2_matrix_square (even, odd);
  gf2_matrix_square (odd, even);

  crc1 = gf2_apply_zeros (crc1, odd, even, len2);

  return crc1 ^ crc2;
}

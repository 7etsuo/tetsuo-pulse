/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_BYTEORDER_H
#define SOCKETUTIL_BYTEORDER_H

/**
 * @file SocketUtil/ByteOrder.h
 * @ingroup foundation
 * @brief Big-endian byte order conversion utilities.
 *
 * Provides portable pack/unpack functions for network byte order (big-endian)
 * conversions. Used for parsing network protocols (DNS, HTTP/2, QUIC).
 *
 * Optimized using compiler intrinsics where available:
 * - GCC/Clang: __builtin_bswap{16,32,64}
 * - MSVC: _byteswap_{ushort,ulong,uint64}
 *
 * Uses memcpy pattern for strict aliasing compliance and unaligned access.
 */

#include <stdint.h>
#include <string.h> /* memcpy */

/*
 * Compiler intrinsics for byte swapping.
 * These compile to single instructions on modern architectures:
 * - x86/x64: BSWAP (1 cycle)
 * - ARM: REV (1 cycle)
 */
#if defined(__GNUC__) || defined(__clang__)
#define SOCKET_BSWAP16(x) __builtin_bswap16 (x)
#define SOCKET_BSWAP32(x) __builtin_bswap32 (x)
#define SOCKET_BSWAP64(x) __builtin_bswap64 (x)
#define SOCKET_HAS_BSWAP_INTRINSICS 1
#elif defined(_MSC_VER)
#include <stdlib.h>
#define SOCKET_BSWAP16(x) _byteswap_ushort (x)
#define SOCKET_BSWAP32(x) _byteswap_ulong (x)
#define SOCKET_BSWAP64(x) _byteswap_uint64 (x)
#define SOCKET_HAS_BSWAP_INTRINSICS 1
#else
#define SOCKET_HAS_BSWAP_INTRINSICS 0
#endif

/*
 * Endianness detection.
 * On big-endian systems, no byte swapping is needed for network byte order.
 */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define SOCKET_IS_BIG_ENDIAN 1
#elif defined(__BIG_ENDIAN__) || defined(__ARMEB__) || defined(__THUMBEB__) \
    || defined(__AARCH64EB__) || defined(_MIPSEB) || defined(__MIPSEB)      \
    || defined(__MIPSEB__)
#define SOCKET_IS_BIG_ENDIAN 1
#else
#define SOCKET_IS_BIG_ENDIAN 0
#endif

/*
 * Conversion macros: host <-> big-endian.
 * No-op on big-endian systems, byte swap on little-endian.
 */
#if SOCKET_IS_BIG_ENDIAN
#define SOCKET_HTOBE16(x) (x)
#define SOCKET_HTOBE32(x) (x)
#define SOCKET_HTOBE64(x) (x)
#define SOCKET_BE16TOH(x) (x)
#define SOCKET_BE32TOH(x) (x)
#define SOCKET_BE64TOH(x) (x)
#elif SOCKET_HAS_BSWAP_INTRINSICS
#define SOCKET_HTOBE16(x) SOCKET_BSWAP16 (x)
#define SOCKET_HTOBE32(x) SOCKET_BSWAP32 (x)
#define SOCKET_HTOBE64(x) SOCKET_BSWAP64 (x)
#define SOCKET_BE16TOH(x) SOCKET_BSWAP16 (x)
#define SOCKET_BE32TOH(x) SOCKET_BSWAP32 (x)
#define SOCKET_BE64TOH(x) SOCKET_BSWAP64 (x)
#else
/* Fallback: manual byte swap */
#define SOCKET_HTOBE16(x) \
  ((uint16_t)(((uint16_t)(x) >> 8) | ((uint16_t)(x) << 8)))
#define SOCKET_HTOBE32(x)                                                  \
  ((uint32_t)(((uint32_t)(x) >> 24) | (((uint32_t)(x) >> 8) & 0x0000FF00U) \
              | (((uint32_t)(x) << 8) & 0x00FF0000U) | ((uint32_t)(x) << 24)))
#define SOCKET_HTOBE64(x)                                                 \
  ((uint64_t)(((uint64_t)(x) >> 56) | (((uint64_t)(x) >> 40) & 0xFF00ULL) \
              | (((uint64_t)(x) >> 24) & 0xFF0000ULL)                     \
              | (((uint64_t)(x) >> 8) & 0xFF000000ULL)                    \
              | (((uint64_t)(x) << 8) & 0xFF00000000ULL)                  \
              | (((uint64_t)(x) << 24) & 0xFF0000000000ULL)               \
              | (((uint64_t)(x) << 40) & 0xFF000000000000ULL)             \
              | ((uint64_t)(x) << 56)))
#define SOCKET_BE16TOH(x) SOCKET_HTOBE16 (x)
#define SOCKET_BE32TOH(x) SOCKET_HTOBE32 (x)
#define SOCKET_BE64TOH(x) SOCKET_HTOBE64 (x)
#endif

/**
 * @brief Unpack 16-bit big-endian value.
 * @ingroup foundation
 * @param p Pointer to 2-byte buffer (may be unaligned).
 * @return Decoded 16-bit value in host byte order.
 * @threadsafe Yes (pure function)
 */
static inline uint16_t
socket_util_unpack_be16 (const unsigned char *p)
{
  uint16_t v;
  memcpy (&v, p, sizeof (v));
  return SOCKET_BE16TOH (v);
}

/**
 * @brief Pack 16-bit value to big-endian.
 * @ingroup foundation
 * @param p Pointer to 2-byte buffer (may be unaligned).
 * @param v 16-bit value in host byte order.
 * @threadsafe Yes (pure function)
 */
static inline void
socket_util_pack_be16 (unsigned char *p, uint16_t v)
{
  v = SOCKET_HTOBE16 (v);
  memcpy (p, &v, sizeof (v));
}

/**
 * @brief Unpack 24-bit big-endian value.
 * @ingroup foundation
 * @param p Pointer to 3-byte buffer.
 * @return Decoded 24-bit value in host byte order (stored in uint32_t).
 * @threadsafe Yes (pure function)
 *
 * Used for HTTP/2 frame length fields (24-bit).
 * No intrinsic available for 24-bit, uses optimized manual implementation.
 */
static inline uint32_t
socket_util_unpack_be24 (const unsigned char *p)
{
  return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

/**
 * @brief Pack 24-bit value to big-endian.
 * @ingroup foundation
 * @param p Pointer to 3-byte buffer.
 * @param v 24-bit value in host byte order (lower 24 bits used).
 * @threadsafe Yes (pure function)
 */
static inline void
socket_util_pack_be24 (unsigned char *p, uint32_t v)
{
  p[0] = (unsigned char)((v >> 16) & 0xFF);
  p[1] = (unsigned char)((v >> 8) & 0xFF);
  p[2] = (unsigned char)(v & 0xFF);
}

/**
 * @brief Unpack 32-bit big-endian value.
 * @ingroup foundation
 * @param p Pointer to 4-byte buffer (may be unaligned).
 * @return Decoded 32-bit value in host byte order.
 * @threadsafe Yes (pure function)
 */
static inline uint32_t
socket_util_unpack_be32 (const unsigned char *p)
{
  uint32_t v;
  memcpy (&v, p, sizeof (v));
  return SOCKET_BE32TOH (v);
}

/**
 * @brief Pack 32-bit value to big-endian.
 * @ingroup foundation
 * @param p Pointer to 4-byte buffer (may be unaligned).
 * @param v 32-bit value in host byte order.
 * @threadsafe Yes (pure function)
 */
static inline void
socket_util_pack_be32 (unsigned char *p, uint32_t v)
{
  v = SOCKET_HTOBE32 (v);
  memcpy (p, &v, sizeof (v));
}

/**
 * @brief Unpack 64-bit big-endian value.
 * @ingroup foundation
 * @param p Pointer to 8-byte buffer (may be unaligned).
 * @return Decoded 64-bit value in host byte order.
 * @threadsafe Yes (pure function)
 */
static inline uint64_t
socket_util_unpack_be64 (const unsigned char *p)
{
  uint64_t v;
  memcpy (&v, p, sizeof (v));
  return SOCKET_BE64TOH (v);
}

/**
 * @brief Pack 64-bit value to big-endian.
 * @ingroup foundation
 * @param p Pointer to 8-byte buffer (may be unaligned).
 * @param v 64-bit value in host byte order.
 * @threadsafe Yes (pure function)
 */
static inline void
socket_util_pack_be64 (unsigned char *p, uint64_t v)
{
  v = SOCKET_HTOBE64 (v);
  memcpy (p, &v, sizeof (v));
}

#endif /* SOCKETUTIL_BYTEORDER_H */

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
 */

#include <stdint.h>

/**
 * @brief Unpack 16-bit big-endian value.
 * @ingroup foundation
 * @param p Pointer to 2-byte buffer.
 * @return Decoded 16-bit value in host byte order.
 * @threadsafe Yes (pure function)
 */
static inline uint16_t
socket_util_unpack_be16 (const unsigned char *p)
{
  return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

/**
 * @brief Pack 16-bit value to big-endian.
 * @ingroup foundation
 * @param p Pointer to 2-byte buffer.
 * @param v 16-bit value in host byte order.
 * @threadsafe Yes (pure function)
 */
static inline void
socket_util_pack_be16 (unsigned char *p, uint16_t v)
{
  p[0] = (unsigned char)((v >> 8) & 0xFF);
  p[1] = (unsigned char)(v & 0xFF);
}

/**
 * @brief Unpack 24-bit big-endian value.
 * @ingroup foundation
 * @param p Pointer to 3-byte buffer.
 * @return Decoded 24-bit value in host byte order (stored in uint32_t).
 * @threadsafe Yes (pure function)
 *
 * Used for HTTP/2 frame length fields (24-bit).
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
 * @param p Pointer to 4-byte buffer.
 * @return Decoded 32-bit value in host byte order.
 * @threadsafe Yes (pure function)
 */
static inline uint32_t
socket_util_unpack_be32 (const unsigned char *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8)
         | (uint32_t)p[3];
}

/**
 * @brief Pack 32-bit value to big-endian.
 * @ingroup foundation
 * @param p Pointer to 4-byte buffer.
 * @param v 32-bit value in host byte order.
 * @threadsafe Yes (pure function)
 */
static inline void
socket_util_pack_be32 (unsigned char *p, uint32_t v)
{
  p[0] = (unsigned char)((v >> 24) & 0xFF);
  p[1] = (unsigned char)((v >> 16) & 0xFF);
  p[2] = (unsigned char)((v >> 8) & 0xFF);
  p[3] = (unsigned char)(v & 0xFF);
}

/**
 * @brief Unpack 64-bit big-endian value.
 * @ingroup foundation
 * @param p Pointer to 8-byte buffer.
 * @return Decoded 64-bit value in host byte order.
 * @threadsafe Yes (pure function)
 */
static inline uint64_t
socket_util_unpack_be64 (const unsigned char *p)
{
  return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48)
         | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
         | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
         | ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

/**
 * @brief Pack 64-bit value to big-endian.
 * @ingroup foundation
 * @param p Pointer to 8-byte buffer.
 * @param v 64-bit value in host byte order.
 * @threadsafe Yes (pure function)
 */
static inline void
socket_util_pack_be64 (unsigned char *p, uint64_t v)
{
  p[0] = (unsigned char)((v >> 56) & 0xFF);
  p[1] = (unsigned char)((v >> 48) & 0xFF);
  p[2] = (unsigned char)((v >> 40) & 0xFF);
  p[3] = (unsigned char)((v >> 32) & 0xFF);
  p[4] = (unsigned char)((v >> 24) & 0xFF);
  p[5] = (unsigned char)((v >> 16) & 0xFF);
  p[6] = (unsigned char)((v >> 8) & 0xFF);
  p[7] = (unsigned char)(v & 0xFF);
}

#endif /* SOCKETUTIL_BYTEORDER_H */

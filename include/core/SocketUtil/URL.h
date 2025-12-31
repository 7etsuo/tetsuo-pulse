/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_URL_H
#define SOCKETUTIL_URL_H

/**
 * @file SocketUtil/URL.h
 * @ingroup foundation
 * @brief URL encoding/decoding utilities.
 *
 * Provides percent-decoding per RFC 3986 Section 2.1.
 */

#include <stddef.h>

#include "core/SocketUtil/Core.h"

/**
 * @brief Decode hexadecimal digit character.
 * @ingroup foundation
 * @param c Character to decode ('0'-'9', 'a'-'f', 'A'-'F').
 * @return Decoded value 0-15, or -1 if not a valid hex digit.
 * @threadsafe Yes (pure function, no shared state)
 */
static inline int
socket_util_hex_digit (char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F')
    return 10 + (c - 'A');
  return -1;
}

/**
 * @brief Decode a single URL-encoded character or percent sequence.
 * @ingroup foundation
 * @param src Pointer to current position in source string.
 * @param remaining Bytes remaining in source string.
 * @param out Output pointer for decoded character.
 * @return Number of source bytes consumed (1 for literal, 3 for %XX).
 * @threadsafe Yes (pure function, no shared state)
 */
static inline size_t
url_decode_char (const char *src, size_t remaining, char *out)
{
  if (remaining < 3 || src[0] != '%')
    {
      *out = src[0];
      return 1;
    }

  int hi = socket_util_hex_digit (src[1]);
  int lo = socket_util_hex_digit (src[2]);

  if (hi < 0 || lo < 0)
    {
      *out = src[0];
      return 1;
    }

  *out = (char)HEX_NIBBLES_TO_BYTE (hi, lo);
  return 3;
}

/**
 * @brief URL-decode percent-encoded string.
 * @ingroup foundation
 * @param src Source string with %XX encoding.
 * @param src_len Length of source string.
 * @param dst Destination buffer.
 * @param dst_size Size of destination buffer.
 * @param out_len Optional output pointer for decoded length (may be NULL).
 * @return 0 on success, -1 if output would be truncated.
 * @threadsafe Yes (pure function, no shared state)
 *
 * Decodes percent-encoded URL strings per RFC 3986. Invalid sequences
 * are copied literally. Always null-terminates output.
 */
static inline int
socket_util_url_decode (const char *src,
                        size_t src_len,
                        char *dst,
                        size_t dst_size,
                        size_t *out_len)
{
  size_t di = 0;
  size_t si = 0;
  int truncated = 0;

  if (dst_size == 0)
    return -1;

  while (si < src_len)
    {
      char decoded;
      size_t advance = url_decode_char (src + si, src_len - si, &decoded);

      if (di < dst_size - 1)
        dst[di++] = decoded;
      else
        truncated = 1;

      si += advance;
    }

  dst[di] = '\0';

  if (out_len != NULL)
    *out_len = di;

  return truncated ? -1 : 0;
}

#endif /* SOCKETUTIL_URL_H */

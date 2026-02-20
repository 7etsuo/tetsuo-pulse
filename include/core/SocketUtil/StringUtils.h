/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_STRINGUTILS_H
#define SOCKETUTIL_STRINGUTILS_H

/**
 * @file SocketUtil/StringUtils.h
 * @ingroup foundation
 * @brief String manipulation utilities.
 *
 * Provides:
 * - snprintf truncation checking
 * - Arena-based string duplication
 * - Safe string copy with null-termination
 */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "core/Arena.h"

/**
 * @brief Check snprintf return value for truncation
 * @ingroup foundation
 * @param ret Return value from snprintf
 * @param buflen Buffer size passed to snprintf
 * @return -1 if truncated or error, ret otherwise
 * @threadsafe Yes (macro expansion, no shared state)
 *
 * According to POSIX, snprintf returns:
 * - Negative value on encoding error
 * - Number of characters that would be written (excluding null terminator)
 * - Truncation occurs when return value >= buflen
 */
#define SOCKET_SNPRINTF_CHECK(ret, buflen) \
  ((ret) < 0 || (size_t)(ret) >= (buflen) ? -1 : (ret))

/**
 * @brief Duplicate string into arena.
 * @ingroup foundation
 * @param arena Arena for allocation.
 * @param str String to duplicate (may be NULL).
 * @return Duplicated string in arena, or NULL if str is NULL or alloc fails.
 * @threadsafe Yes (if arena is thread-safe)
 */
static inline char *
socket_util_arena_strdup (Arena_T arena, const char *str)
{
  size_t len;
  char *copy;

  if (str == NULL)
    return NULL;

  len = strlen (str);
  copy = Arena_alloc (arena, len + 1, __FILE__, __LINE__);
  if (copy != NULL)
    memcpy (copy, str, len + 1);

  return copy;
}

/**
 * @brief Duplicate string with max length into arena.
 * @ingroup foundation
 * @param arena Arena for allocation.
 * @param str String to duplicate (may be NULL).
 * @param maxlen Maximum characters to copy (excluding null terminator).
 * @return Duplicated string in arena, or NULL if str is NULL or alloc fails.
 * @threadsafe Yes (if arena is thread-safe)
 *
 * Uses strnlen() instead of strlen() to avoid scanning beyond maxlen,
 * which is important when str may be very long but only a prefix is needed.
 */
static inline char *
socket_util_arena_strndup (Arena_T arena, const char *str, size_t maxlen)
{
  size_t len;
  char *copy;

  if (str == NULL)
    return NULL;

  len = strnlen (str, maxlen);

  copy = Arena_alloc (arena, len + 1, __FILE__, __LINE__);
  if (copy != NULL)
    {
      memcpy (copy, str, len);
      copy[len] = '\0';
    }

  return copy;
}

/**
 * @brief Duplicate string with known length into arena.
 * @ingroup foundation
 * @param arena Arena for allocation.
 * @param str String to duplicate (may not be null-terminated).
 * @param len Exact length of string to copy.
 * @return Null-terminated copy in arena, or NULL if str is NULL or alloc fails.
 * @threadsafe Yes (if arena is thread-safe)
 */
static inline char *
socket_util_arena_strdup_len (Arena_T arena, const char *str, size_t len)
{
  char *copy;

  if (str == NULL)
    return NULL;

  copy = Arena_alloc (arena, len + 1, __FILE__, __LINE__);
  if (copy != NULL)
    {
      if (len > 0)
        memcpy (copy, str, len);
      copy[len] = '\0';
    }

  return copy;
}

/**
 * @brief Duplicate string with length into arena (convenience alias).
 * @ingroup foundation
 * @param arena Arena for allocation.
 * @param src String to duplicate (may not be null-terminated).
 * @param len Exact length of string to copy.
 * @return Null-terminated copy in arena, or NULL if src is NULL or alloc fails.
 * @threadsafe Yes (if arena is thread-safe)
 */
static inline char *
arena_strndup (Arena_T arena, const char *src, size_t len)
{
  return socket_util_arena_strdup_len (arena, src, len);
}

/**
 * @brief Safely copy IP address string with null termination
 * @ingroup utilities
 * @param dest Destination buffer (must be at least max_len bytes)
 * @param src Source IP string to copy
 * @param max_len Maximum size of destination buffer
 * @threadsafe Yes - no shared state
 */
static inline void
socket_util_safe_copy_ip (char *dest, const char *src, size_t max_len)
{
  if (max_len == 0)
    return;
  strncpy (dest, src, max_len - 1);
  dest[max_len - 1] = '\0';
}

/**
 * @brief Safe string copy with guaranteed null-termination
 * @param dest Destination buffer
 * @param src Source string to copy
 * @param max_len Maximum size of destination buffer (including null terminator)
 * @return true if entire string was copied, false if truncation occurred
 * @threadsafe Yes - no shared state
 */
static inline bool
socket_util_safe_strncpy (char *dest, const char *src, size_t max_len)
{
  size_t src_len;

  if (max_len == 0)
    return false;

  src_len = strlen (src);

/* Suppress GCC false positive: we explicitly null-terminate below */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#endif
  strncpy (dest, src, max_len - 1);
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
  dest[max_len - 1] = '\0';

  /* Return false if truncation occurred */
  return src_len < max_len;
}

#endif /* SOCKETUTIL_STRINGUTILS_H */

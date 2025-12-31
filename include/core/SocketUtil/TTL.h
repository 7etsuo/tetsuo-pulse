/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_TTL_H
#define SOCKETUTIL_TTL_H

/**
 * @file SocketUtil/TTL.h
 * @ingroup foundation
 * @brief TTL (Time-To-Live) expiry utilities for cache entries.
 *
 * Provides utilities for checking TTL expiry and calculating remaining TTL,
 * commonly used in DNS caching and protocol-level caching.
 */

#include <stdint.h>

/**
 * @brief Check if a TTL-based entry has expired.
 * @ingroup foundation
 * @param insert_time_ms Insertion time in milliseconds (from monotonic clock).
 * @param ttl_sec TTL in seconds.
 * @param now_ms Current time in milliseconds (from monotonic clock).
 * @return 1 if expired, 0 if still valid.
 * @threadsafe Yes (pure function)
 *
 * Handles time wraparound and backward time jumps safely.
 * Returns "not expired" if time appears to go backwards.
 */
static inline int
socket_util_ttl_expired (int64_t insert_time_ms,
                         uint32_t ttl_sec,
                         int64_t now_ms)
{
  /* Guard against time going backwards */
  if (now_ms < insert_time_ms)
    return 0;

  int64_t age_ms = now_ms - insert_time_ms;
  int64_t ttl_ms = (int64_t)ttl_sec * 1000;
  return age_ms >= ttl_ms;
}

/**
 * @brief Calculate remaining TTL in seconds.
 * @ingroup foundation
 * @param insert_time_ms Insertion time in milliseconds.
 * @param ttl_sec Original TTL in seconds.
 * @param now_ms Current time in milliseconds.
 * @return Remaining TTL in seconds (0 if expired).
 * @threadsafe Yes (pure function)
 *
 * Returns full TTL if time appears to go backwards.
 */
static inline uint32_t
socket_util_ttl_remaining (int64_t insert_time_ms,
                           uint32_t ttl_sec,
                           int64_t now_ms)
{
  /* Guard against time going backwards */
  if (now_ms < insert_time_ms)
    return ttl_sec;

  int64_t age_ms = now_ms - insert_time_ms;
  int64_t ttl_ms = (int64_t)ttl_sec * 1000;
  int64_t remaining_ms = ttl_ms - age_ms;

  if (remaining_ms <= 0)
    return 0;

  return (uint32_t)(remaining_ms / 1000);
}

#endif /* SOCKETUTIL_TTL_H */

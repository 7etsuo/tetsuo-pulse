/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_INCLUDED
#define SOCKETUTIL_INCLUDED

/**
 * @file SocketUtil.h
 * @ingroup foundation
 * @brief Consolidated utility header for logging, metrics, events, and error
 * handling.
 *
 * This header consolidates the observability, instrumentation, and error
 * handling utilities into a single include for cleaner dependencies.
 *
 * Provides:
 * - Logging subsystem (configurable callbacks, multiple log levels)
 * - Metrics collection (thread-safe counters, atomic snapshots)
 * - Event dispatching (connection events, DNS timeouts, poll wakeups)
 * - Error handling (thread-local buffers, errno mapping, exception macros)
 * - Hash functions (golden ratio, DJB2 variants for various use cases)
 * - Timeout utilities (monotonic clock timing, deadline calculations)
 *
 * @see SocketLogLevel for logging API.
 * @see SocketMetrics for metrics collection.
 * @see SocketError for error handling utilities.
 * @see @ref foundation for other core utilities.
 * @see @ref core_io for socket modules that use these utilities.
 */

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"

/* ============================================================================
 * CONSOLIDATED INCLUDES (Split Modules)
 * ============================================================================
 *
 * These subsystems have been split into focused modules for improved
 * maintainability and reduced compilation dependencies. SocketUtil.h
 * remains as an umbrella header for backward compatibility.
 */

#include "core/SocketError.h"  /* Error handling and categorization */
#include "core/SocketLog.h"    /* Logging subsystem */
#include "core/SocketEvent.h"  /* Event dispatching */

/* ============================================================================
 * ERROR HANDLING MACROS (Combine Error + Log)
 * ============================================================================
 */

/**
 * @brief SOCKET_ERROR_FMT - Format error message with errno information
 *
 * Includes truncation protection for long messages.
 */
#define SOCKET_ERROR_FMT(fmt, ...)                                            \
  do                                                                          \
    {                                                                         \
      socket_last_errno = errno;                                              \
      char tmp_buf[SOCKET_ERROR_BUFSIZE];                                     \
      int _socket_error_ret = snprintf (                                      \
          tmp_buf, sizeof (tmp_buf), fmt " (errno: %d - %s)", ##__VA_ARGS__,  \
          socket_last_errno, Socket_safe_strerror (socket_last_errno));       \
      memcpy (socket_error_buf, tmp_buf, SOCKET_ERROR_BUFSIZE);               \
      socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';                      \
      SOCKET_ERROR_APPLY_TRUNCATION (_socket_error_ret);                      \
      (void)_socket_error_ret;                                                \
      SocketLog_emit (SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT,                 \
                      socket_error_buf);                                      \
    }                                                                         \
  while (0)

/**
 * @brief SOCKET_ERROR_MSG - Format error message without errno
 *
 * Includes truncation protection for long messages.
 */
#define SOCKET_ERROR_MSG(fmt, ...)                                            \
  do                                                                          \
    {                                                                         \
      socket_last_errno = errno;                                              \
      char tmp_buf[SOCKET_ERROR_BUFSIZE];                                     \
      int _socket_error_ret                                                   \
          = snprintf (tmp_buf, sizeof (tmp_buf), fmt, ##__VA_ARGS__);         \
      memcpy (socket_error_buf, tmp_buf, SOCKET_ERROR_BUFSIZE);               \
      socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';                      \
      SOCKET_ERROR_APPLY_TRUNCATION (_socket_error_ret);                      \
      (void)_socket_error_ret;                                                \
      SocketLog_emit (SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT,                 \
                      socket_error_buf);                                      \
    }                                                                         \
  while (0)

/* ============================================================================
 * Centralized Exception Infrastructure
 * ============================================================================
 */

/**
 * @brief SOCKET_DECLARE_MODULE_EXCEPTION - Declare thread-local exception
 *
 * @module_name: Module name (e.g., Socket, SocketBuf, SocketPoll)
 */
#define SOCKET_DECLARE_MODULE_EXCEPTION(module_name)                          \
  static __thread Except_T module_name##_DetailedException

/**
 * @brief SOCKET_RAISE_MODULE_ERROR - Raise module-specific exception
 *
 * @module_name: Module name
 * @exception: Exception to raise
 * @brief Thread-safe: Creates thread-local copy with detailed reason
 *
 */
#define SOCKET_RAISE_MODULE_ERROR(module_name, exception)                     \
  do                                                                          \
    {                                                                         \
      module_name##_DetailedException = (exception);                          \
      module_name##_DetailedException.reason = socket_error_buf;              \
      RAISE (module_name##_DetailedException);                                \
    }                                                                         \
  while (0)

/* ============================================================================
 * Unified Error + Raise Macros (Eliminates Redundant Patterns)
 * ============================================================================
 */

/**
 * @brief SOCKET_RAISE_FMT - Format error with errno and raise exception in one
 step
 *
 * @module_name: Module name for exception
 * @exception: Exception to raise
 * @fmt: Printf-style format string
 * @...: Format arguments
 *
 * Combines SOCKET_ERROR_FMT + RAISE_MODULE_ERROR into single macro.
 * @brief Thread-safe: Yes (uses thread-local buffers)
 *
 */
#define SOCKET_RAISE_FMT(module_name, exception, fmt, ...)                    \
  do                                                                          \
    {                                                                         \
      SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__);                                  \
      SOCKET_RAISE_MODULE_ERROR (module_name, exception);                     \
    }                                                                         \
  while (0)

/**
 * @brief SOCKET_RAISE_MSG - Format error message and raise exception in one
 step
 *
 * @module_name: Module name for exception
 * @exception: Exception to raise
 * @fmt: Printf-style format string (without errno)
 * @...: Format arguments
 *
 * Combines SOCKET_ERROR_MSG + RAISE_MODULE_ERROR into single macro.
 * @brief Thread-safe: Yes (uses thread-local buffers)
 *
 */
#define SOCKET_RAISE_MSG(module_name, exception, fmt, ...)                    \
  do                                                                          \
    {                                                                         \
      SOCKET_ERROR_MSG (fmt, ##__VA_ARGS__);                                  \
      SOCKET_RAISE_MODULE_ERROR (module_name, exception);                     \
    }                                                                         \
  while (0)

/**
 * Helper macros for common module patterns - use RAISE_MODULE_ERROR macro
 * defined in each module that sets module_name appropriately.
 *
 * Example module setup:
 *   SOCKET_DECLARE_MODULE_EXCEPTION(MyModule);
 *   #define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(MyModule, e)
 *   #define RAISE_FMT(e, fmt, ...) SOCKET_RAISE_FMT(MyModule, e, fmt,
 * ##__VA_ARGS__) #define RAISE_MSG(e, fmt, ...) SOCKET_RAISE_MSG(MyModule, e,
 * fmt, ##__VA_ARGS__)
 */

/* ============================================================================
 * METRICS SUBSYSTEM (Legacy API)
 * ============================================================================
 */

/**
 * @brief Library-wide performance metrics.
 * @ingroup foundation
 *
 * @threadsafe Yes (atomic operations)
 */
typedef enum SocketMetric
{
  SOCKET_METRIC_SOCKET_CONNECT_SUCCESS = 0,
  SOCKET_METRIC_SOCKET_CONNECT_FAILURE,
  SOCKET_METRIC_SOCKET_SHUTDOWN_CALL,
  SOCKET_METRIC_DNS_REQUEST_SUBMITTED,
  SOCKET_METRIC_DNS_REQUEST_COMPLETED,
  SOCKET_METRIC_DNS_REQUEST_FAILED,
  SOCKET_METRIC_DNS_REQUEST_CANCELLED,
  SOCKET_METRIC_DNS_REQUEST_TIMEOUT,
  SOCKET_METRIC_DNS_CACHE_HIT,
  SOCKET_METRIC_DNS_CACHE_MISS,
  SOCKET_METRIC_POLL_WAKEUPS,
  SOCKET_METRIC_POLL_EVENTS_DISPATCHED,
  SOCKET_METRIC_POOL_CONNECTIONS_ADDED,
  SOCKET_METRIC_POOL_CONNECTIONS_REMOVED,
  SOCKET_METRIC_POOL_CONNECTIONS_REUSED,
  SOCKET_METRIC_POOL_DRAIN_INITIATED,
  SOCKET_METRIC_POOL_DRAIN_COMPLETED,
  SOCKET_METRIC_POOL_HEALTH_CHECKS,
  SOCKET_METRIC_POOL_HEALTH_FAILURES,
  SOCKET_METRIC_POOL_VALIDATION_FAILURES,
  SOCKET_METRIC_POOL_IDLE_CLEANUPS,
  SOCKET_METRIC_COUNT
} SocketMetric;

/**
 * @brief Thread-safe snapshot of all library metrics.
 * @ingroup foundation
 */
typedef struct SocketMetricsSnapshot
{
  unsigned long long values[SOCKET_METRIC_COUNT];
} SocketMetricsSnapshot;

/**
 * @brief SocketMetrics_increment - Legacy metric increment (forwards to new system)
 * @ingroup foundation
 * @deprecated Use SocketMetrics_counter_inc(SocketCounterMetric) from SocketMetrics.h
 * @param metric Legacy metric enum
 * @param value Amount to add (uint64_t in new API)
 * @threadsafe Yes - forwards to atomic new system
 * @note For backward compatibility; forwards to new counters where mapped.
 * @see SocketMetrics.h for full metrics suite (gauges, histograms, exports)
 */
void SocketMetrics_increment (SocketMetric metric, unsigned long value);

/**
 * @brief SocketMetrics_getsnapshot - Legacy snapshot (populated from new system)
 * @ingroup foundation
 * @deprecated Use SocketMetrics_get(SocketMetrics_Snapshot *) from SocketMetrics.h for full data
 * @param snapshot Legacy snapshot struct (counters only)
 * @threadsafe Yes - reads from new atomic/thread-safe system
 * @note Populates legacy values from mapped new counters; unmapped are 0.
 * @see SocketMetrics.h SocketMetrics_Snapshot for gauges/histograms too
 */
void SocketMetrics_getsnapshot (SocketMetricsSnapshot *snapshot);

/**
 * @brief SocketMetrics_legacy_reset - Reset (forwards to new system)
 * @ingroup foundation
 * @deprecated Use SocketMetrics_reset() from SocketMetrics.h
 * @threadsafe Yes - calls new reset_counters (resets all counters)
 * @note For compatibility; resets all new counters, not just legacy mapped.
 */
void SocketMetrics_legacy_reset (void);

/**
 * @brief SocketMetrics_name - Get name (forwards to new or legacy)
 * @ingroup foundation
 * @deprecated Use SocketMetrics_counter_name(SocketCounterMetric) etc. from SocketMetrics.h
 * @param metric Legacy metric enum
 * @return Mapped new name or legacy name for unmapped
 * @threadsafe Yes
 * @note For compatibility; prefer new API names for consistency.
 */
const char *SocketMetrics_name (SocketMetric metric);

/**
 * @brief SocketMetrics_count - Get total number of defined metrics
 * @ingroup foundation
 * @return Number of metrics
 * @threadsafe Yes
 */
size_t SocketMetrics_count (void);

/**
 * @brief Get a specific value from metrics snapshot.
 * @ingroup foundation
 * @param snapshot Snapshot to read from.
 * @param metric Metric to retrieve.
 * @return Metric value, or 0 for invalid inputs.
 * @threadsafe Yes (read-only operation)
 */
static inline unsigned long long
SocketMetrics_snapshot_value (const SocketMetricsSnapshot *snapshot,
                              SocketMetric metric)
{
  if (!snapshot)
    return 0ULL;
  if (metric >= SOCKET_METRIC_COUNT)
    return 0ULL;
  return snapshot->values[metric];
}

/* ============================================================================
 * TIME UTILITIES (Consolidated monotonic clock functions)
 * ============================================================================
 */

/**
 * @brief Socket_get_monotonic_ms - Get current monotonic time in milliseconds
 * @ingroup foundation
 * @return Current monotonic time in milliseconds since arbitrary epoch
 * @threadsafe Yes (no shared state)
 *
 * Uses CLOCK_MONOTONIC with CLOCK_REALTIME fallback. Immune to wall-clock
 * changes (NTP adjustments, manual time changes). Returns 0 on failure.
 *
 * Use for:
 * - Rate limiting timestamps
 * - Timer expiry calculations
 * - Elapsed time measurements
 */
int64_t Socket_get_monotonic_ms (void);

/* ============================================================================
 * HASH UTILITIES (Consolidated from multiple modules)
 * ============================================================================
 */

/**
 * @brief Hash file descriptor using golden ratio multiplicative.
 * @ingroup foundation
 * @param fd File descriptor to hash (non-negative).
 * @param table_size Hash table size (should be prime for best distribution).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function, no shared state)
 *
 * Uses the golden ratio constant (2^32 * (sqrt(5)-1)/2) for excellent
 * distribution properties. Suitable for file descriptors, socket IDs,
 * and other small integer keys.
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
 *
 * Converts pointer to integer and applies golden ratio hash.
 * Suitable for hashing opaque handles and memory addresses.
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
 *
 * General-purpose hash for unsigned integers including request IDs.
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
 * @param seed Per-instance random seed (e.g., from SocketCrypto_random_bytes).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function)
 *
 * Adds seed to prevent predictable collisions in tables like HTTP/2 streams.
 * Use for security-sensitive lookups where attacker may control keys.
 */
static inline unsigned
socket_util_hash_uint_seeded (unsigned value, unsigned table_size,
                              uint32_t seed)
{
  uint64_t h = (uint64_t)value * HASH_GOLDEN_RATIO + (uint64_t)seed;
  return (unsigned)(h % table_size);
}

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
 * The multiplication by 33 is optimized as (hash << 5) + hash.
 * Provides good distribution for string keys like IP addresses.
 *
 * Security note: DJB2 is a fast, simple hash for load distribution.
 * NOT cryptographic - do not use for security-sensitive purposes.
 */
static inline unsigned
socket_util_hash_djb2 (const char *str, unsigned table_size)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;
  int c;

  while ((c = *str++) != '\0')
    hash = ((hash << 5) + hash) + (unsigned)c;

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
 *
 * Length-aware variant for non-null-terminated strings.
 * Useful for parsing buffers where strings aren't null-terminated.
 */
static inline unsigned
socket_util_hash_djb2_len (const char *str, size_t len, unsigned table_size)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;
  size_t i;

  for (i = 0; i < len; i++)
    hash = ((hash << 5) + hash) + (unsigned char)str[i];

  return hash % table_size;
}

/**
 * @brief Case-insensitive DJB2 hash.
 * @ingroup foundation
 * @param str String to hash (must not be NULL).
 * @param table_size Hash table size (should be prime for best distribution).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function, no shared state)
 *
 * Case-insensitive variant for HTTP headers and similar keys.
 * Converts ASCII uppercase to lowercase before hashing.
 */
static inline unsigned
socket_util_hash_djb2_ci (const char *str, unsigned table_size)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;
  int c;

  while ((c = *str++) != '\0')
    {
      /* Convert ASCII uppercase to lowercase */
      if (c >= 'A' && c <= 'Z')
        c += 32;
      hash = ((hash << 5) + hash) + (unsigned)c;
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
 *
 * Combines length-aware and case-insensitive variants.
 * Ideal for HTTP header name hashing where names aren't null-terminated.
 */
static inline unsigned
socket_util_hash_djb2_ci_len (const char *str, size_t len, unsigned table_size)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;
  size_t i;

  for (i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)str[i];
      /* Convert ASCII uppercase to lowercase */
      if (c >= 'A' && c <= 'Z')
        c += 32;
      hash = ((hash << 5) + hash) + c;
    }

  return hash % table_size;
}

/**
 * @brief Round up to next power of 2.
 * @ingroup foundation
 * @param n Value to round up (must be > 0).
 * @return Smallest power of 2 >= n.
 * @threadsafe Yes (pure function)
 *
 * Useful for hash table sizing and circular buffer capacities
 * where power-of-2 sizes allow efficient modulo via bitwise AND.
 */
static inline size_t
socket_util_round_up_pow2 (size_t n)
{
  if (n == 0)
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
}

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
 * @threadsafe Yes (macro expansion, no shared state)
 *
 * Type-generic min macro. Works with any numeric types.
 * Evaluates arguments once (no side-effect issues).
 *
 * Note: Uses GNU statement expression extension for type safety.
 * Arguments are evaluated exactly once to avoid side effects.
 *
 * Example:
 *   int64_t timeout = MIN(user_timeout, max_timeout);
 *   size_t len = MIN(buf_size, data_len);
 */
#ifndef MIN
#define MIN(a, b)                                                             \
  ({                                                                          \
    __typeof__ (a) _a = (a);                                                  \
    __typeof__ (b) _b = (b);                                                  \
    _a < _b ? _a : _b;                                                        \
  })
#endif

/**
 * @brief MAX - Compute maximum of two values
 * @ingroup foundation
 * @param a First value
 * @param b Second value
 * @return Maximum value
 * @threadsafe Yes (macro expansion, no shared state)
 *
 * Type-generic max macro. Works with any numeric types.
 * Evaluates arguments once (no side-effect issues).
 *
 * Note: Uses GNU statement expression extension for type safety.
 * Arguments are evaluated exactly once to avoid side effects.
 *
 * Example:
 *   size_t capacity = MAX(min_capacity, requested_size);
 *   int64_t delay = MAX(0, computed_delay);
 */
#ifndef MAX
#define MAX(a, b)                                                             \
  ({                                                                          \
    __typeof__ (a) _a = (a);                                                  \
    __typeof__ (b) _b = (b);                                                  \
    _a > _b ? _a : _b;                                                        \
  })
#endif

/* ============================================================================
 * String Utilities
 * ============================================================================
 */

/**
 * @brief Duplicate string into arena.
 * @ingroup foundation
 * @param arena Arena for allocation.
 * @param str String to duplicate (may be NULL).
 * @return Duplicated string in arena, or NULL if str is NULL or alloc fails.
 * @threadsafe Yes (if arena is thread-safe)
 *
 * Convenience function to duplicate a string into an arena.
 * Avoids repeated strlen+alloc+memcpy pattern in calling code.
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
 * Duplicates at most maxlen characters from str. Always null-terminates.
 */
static inline char *
socket_util_arena_strndup (Arena_T arena, const char *str, size_t maxlen)
{
  size_t len;
  char *copy;

  if (str == NULL)
    return NULL;

  len = strlen (str);
  if (len > maxlen)
    len = maxlen;

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
 *
 * For non-null-terminated strings where the length is already known.
 * More efficient than strndup when length is pre-computed.
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
 *
 * Convenience wrapper for socket_util_arena_strdup_len with a shorter name.
 * Eliminates code duplication by delegating to the canonical implementation.
 */
static inline char *
arena_strndup (Arena_T arena, const char *src, size_t len)
{
  return socket_util_arena_strdup_len (arena, src, len);
}

/* ============================================================================
 * TIMEOUT CALCULATION HELPERS
 * ============================================================================
 *
 * These helpers provide consistent timeout calculation across all modules.
 * They use CLOCK_MONOTONIC for reliable timing that isn't affected by
 * system clock changes.
 */

/**
 * @brief Get current monotonic time in milliseconds.
 * @ingroup foundation
 * @return Current time in milliseconds from monotonic clock, or 0 on failure.
 * @threadsafe Yes
 * @note Delegates to Socket_get_monotonic_ms() for proper error handling.
 */
static inline int64_t
SocketTimeout_now_ms (void)
{
  return Socket_get_monotonic_ms ();
}

/**
 * @brief Create deadline from timeout.
 * @ingroup foundation
 * @param timeout_ms Timeout in milliseconds (0 or negative = no deadline).
 * @return Absolute deadline in milliseconds, or 0 if no timeout.
 * @threadsafe Yes
 */
static inline int64_t
SocketTimeout_deadline_ms (int timeout_ms)
{
  if (timeout_ms <= 0)
    return 0;
  return SocketTimeout_now_ms () + timeout_ms;
}

/**
 * @brief Calculate remaining time until deadline.
 * @ingroup foundation
 * @param deadline_ms Deadline from SocketTimeout_deadline_ms() (0 = no
 * deadline).
 * @return Remaining milliseconds (0 if expired, -1 if no deadline).
 * @threadsafe Yes
 */
static inline int64_t
SocketTimeout_remaining_ms (int64_t deadline_ms)
{
  int64_t remaining;

  if (deadline_ms == 0)
    return -1; /* No deadline = infinite */

  remaining = deadline_ms - SocketTimeout_now_ms ();
  return (remaining > 0) ? remaining : 0;
}

/**
 * @brief Check if deadline has passed.
 * @ingroup foundation
 * @param deadline_ms Deadline from SocketTimeout_deadline_ms() (0 = no
 * deadline).
 * @return 1 if expired, 0 if not expired or no deadline.
 * @threadsafe Yes
 */
static inline int
SocketTimeout_expired (int64_t deadline_ms)
{
  if (deadline_ms == 0)
    return 0; /* No deadline = never expires */

  return SocketTimeout_now_ms () >= deadline_ms;
}

/**
 * @brief Adjust poll timeout to not exceed deadline.
 * @ingroup foundation
 * @param current_timeout_ms Current poll timeout (-1 = infinite).
 * @param deadline_ms Deadline from SocketTimeout_deadline_ms() (0 = no
 * deadline).
 * @return Adjusted timeout for poll() (minimum of current and remaining).
 * @threadsafe Yes
 *
 * Usage: Use as the timeout argument to poll() when you need to respect
 * both a regular poll interval and an overall operation deadline.
 */
static inline int
SocketTimeout_poll_timeout (int current_timeout_ms, int64_t deadline_ms)
{
  int64_t remaining;

  if (deadline_ms == 0)
    return current_timeout_ms; /* No deadline */

  remaining = SocketTimeout_remaining_ms (deadline_ms);
  if (remaining == 0)
    return 0; /* Already expired */

  if (remaining == -1)
    return current_timeout_ms; /* No deadline (shouldn't happen here) */

  /* Cap remaining to INT_MAX for poll() */
  if (remaining > INT_MAX)
    remaining = INT_MAX;

  /* Return minimum of current timeout and remaining */
  if (current_timeout_ms < 0)
    return (int)remaining;

  return (current_timeout_ms < (int)remaining) ? current_timeout_ms
                                               : (int)remaining;
}

/**
 * @brief Calculate elapsed time since start.
 * @ingroup foundation
 * @param start_ms Start time from SocketTimeout_now_ms().
 * @return Elapsed milliseconds since start.
 * @threadsafe Yes
 */
static inline int64_t
SocketTimeout_elapsed_ms (int64_t start_ms)
{
  return SocketTimeout_now_ms () - start_ms;
}

/* ============================================================================
 * MUTEX + ARENA MANAGER PATTERN
 * ============================================================================
 *
 * Standard pattern for modules with mutex-protected arena allocation.
 * Embed SOCKET_MUTEX_ARENA_FIELDS in struct, use SOCKET_MUTEX_ARENA_*() macros.
 *
 * Example usage:
 *   struct MyModule_T {
 *     SOCKET_MUTEX_ARENA_FIELDS;
 *     // ... module-specific fields
 *   };
 *
 *   MyModule_T MyModule_new(Arena_T arena) {
 *     MyModule_T m = arena ? CALLOC(arena, 1, sizeof(*m)) : calloc(1, sizeof(*m));
 *     if (!m) SOCKET_RAISE_MSG(...);
 *     m->arena = arena;
 *     SOCKET_MUTEX_ARENA_INIT(m, MyModule, MyModule_Failed);
 *     return m;
 *   }
 *
 *   void MyModule_free(MyModule_T *m) {
 *     if (!m || !*m) return;
 *     SOCKET_MUTEX_ARENA_DESTROY(*m);
 *     if (!(*m)->arena) free(*m);
 *     *m = NULL;
 *   }
 */

/** Mutex initialization states */
#define SOCKET_MUTEX_UNINITIALIZED 0
#define SOCKET_MUTEX_INITIALIZED 1
#define SOCKET_MUTEX_SHUTDOWN (-1)

/**
 * @brief SOCKET_MUTEX_ARENA_FIELDS - Fields to embed in managed structs
 *
 * Provides the standard pattern for modules that need:
 * - pthread_mutex_t for thread-safe operations
 * - Arena_T for optional arena-based allocation
 * - Initialization state tracking for safe cleanup
 *
 * Usage:
 *   struct MyModule_T {
 *     SOCKET_MUTEX_ARENA_FIELDS;
 *     // ... other fields
 *   };
 */
#define SOCKET_MUTEX_ARENA_FIELDS                                             \
        pthread_mutex_t mutex;                                                \
        Arena_T arena;                                                        \
        int initialized

/**
 * @brief SOCKET_MUTEX_ARENA_INIT - Initialize mutex and set state
 * @param obj Pointer to struct containing SOCKET_MUTEX_ARENA_FIELDS
 * @param module_name Module name for exception (e.g., SocketRateLimit)
 * @param exc_var Exception variable to raise on failure
 *
 * Prerequisites: obj->arena must already be set by caller.
 * Initializes mutex and sets initialized = SOCKET_MUTEX_INITIALIZED.
 * Raises exception on mutex init failure.
 *
 * Usage:
 *   limiter->arena = arena;
 *   SOCKET_MUTEX_ARENA_INIT(limiter, SocketRateLimit, SocketRateLimit_Failed);
 */
#define SOCKET_MUTEX_ARENA_INIT(obj, module_name, exc_var)                    \
        do                                                                    \
          {                                                                   \
            (obj)->initialized = SOCKET_MUTEX_UNINITIALIZED;                  \
            if (pthread_mutex_init (&(obj)->mutex, NULL) != 0)                \
              {                                                               \
                SOCKET_RAISE_MSG (module_name, exc_var,                       \
                                  "Failed to initialize mutex");              \
              }                                                               \
            (obj)->initialized = SOCKET_MUTEX_INITIALIZED;                    \
          }                                                                   \
        while (0)

/**
 * @brief SOCKET_MUTEX_ARENA_DESTROY - Cleanup mutex if initialized
 * @param obj Pointer to struct containing SOCKET_MUTEX_ARENA_FIELDS
 *
 * Destroys mutex only if initialized == SOCKET_MUTEX_INITIALIZED.
 * Sets initialized = SOCKET_MUTEX_UNINITIALIZED after cleanup.
 * Safe to call multiple times (idempotent).
 */
#define SOCKET_MUTEX_ARENA_DESTROY(obj)                                       \
        do                                                                    \
          {                                                                   \
            if ((obj)->initialized == SOCKET_MUTEX_INITIALIZED)               \
              {                                                               \
                pthread_mutex_destroy (&(obj)->mutex);                        \
                (obj)->initialized = SOCKET_MUTEX_UNINITIALIZED;              \
              }                                                               \
          }                                                                   \
        while (0)

/**
 * @brief SOCKET_MUTEX_ARENA_ALLOC - Allocate from arena or malloc
 * @param obj Pointer to struct containing SOCKET_MUTEX_ARENA_FIELDS
 * @param size Bytes to allocate
 *
 * Returns: Allocated pointer (uninitialized) or NULL on failure
 */
#define SOCKET_MUTEX_ARENA_ALLOC(obj, size)                                   \
        ((obj)->arena ? Arena_alloc ((obj)->arena, (size), __FILE__, __LINE__)\
                      : malloc (size))

/**
 * @brief SOCKET_MUTEX_ARENA_CALLOC - Allocate zeroed memory
 * @param obj Pointer to struct containing SOCKET_MUTEX_ARENA_FIELDS
 * @param count Number of elements
 * @param size Size per element
 *
 * Returns: Allocated zeroed pointer or NULL on failure
 */
#define SOCKET_MUTEX_ARENA_CALLOC(obj, count, size)                           \
        ((obj)->arena ? Arena_calloc ((obj)->arena, (count), (size),          \
                                      __FILE__, __LINE__)                     \
                      : calloc ((count), (size)))

/**
 * @brief SOCKET_MUTEX_ARENA_FREE - Free if malloc mode (no-op for arena)
 * @param obj Pointer to struct containing SOCKET_MUTEX_ARENA_FIELDS
 * @param ptr Pointer to free
 *
 * Only frees if arena == NULL (malloc mode). Arena memory is freed
 * when the arena is disposed.
 */
#define SOCKET_MUTEX_ARENA_FREE(obj, ptr)                                     \
        do                                                                    \
          {                                                                   \
            if ((obj)->arena == NULL && (ptr) != NULL)                        \
              {                                                               \
                free (ptr);                                                   \
              }                                                               \
          }                                                                   \
        while (0)

/* ============================================================================
 * IP ADDRESS UTILITY FUNCTIONS
 * ============================================================================
 */

/* ============================================================================
 * DNS NAME UTILITIES
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
    dest[i] = (char)((src[i] >= 'A' && src[i] <= 'Z') ? src[i] + 32 : src[i]);
  dest[i] = '\0';
}

/**
 * @brief Seeded DJB2 hash for DoS-resistant string hashing.
 * @ingroup foundation
 * @param str String to hash (must not be NULL).
 * @param table_size Hash table size (should be prime).
 * @param seed Per-instance random seed for collision resistance.
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function)
 *
 * Adds a random seed to DJB2 to prevent predictable hash collisions.
 * Use for caches and hash tables where attacker may control keys.
 * Seed should come from SocketCrypto_random_uint32() or similar.
 */
static inline unsigned
socket_util_hash_djb2_seeded (const char *str, unsigned table_size,
                              uint32_t seed)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;

  /* Mix in random seed for DoS protection */
  hash = ((hash << 5) + hash) ^ seed;

  /* Hash the string */
  for (const char *p = str; *p; p++)
    hash = ((hash << 5) + hash) ^ (unsigned char)*p;

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
 *
 * Combines case-insensitive hashing with DoS resistance seed.
 * Ideal for DNS name hashing in caches.
 */
static inline unsigned
socket_util_hash_djb2_seeded_ci (const char *str, unsigned table_size,
                                 uint32_t seed)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;

  /* Mix in random seed for DoS protection */
  hash = ((hash << 5) + hash) ^ seed;

  /* Hash the string with case folding */
  for (const char *p = str; *p; p++)
    {
      unsigned char c = (unsigned char)*p;
      if (c >= 'A' && c <= 'Z')
        c += 32;
      hash = ((hash << 5) + hash) ^ c;
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
 *
 * Combines all three features needed for HTTP header hashing:
 * - Seeded: DoS protection via randomized hash seed
 * - Case-insensitive: HTTP header names are case-insensitive per RFC
 * - Length-aware: Header names in parsing buffers aren't null-terminated
 *
 * Uses XOR variant of DJB2 for character mixing (vs. addition in other variants).
 * Seed is mixed using XOR with the initial hash value for simplicity.
 *
 * Use for security-sensitive tables where keys may be attacker-controlled
 * and need case-insensitive comparison with known length.
 */
static inline unsigned
socket_util_hash_djb2_seeded_ci_len (const char *str, size_t len,
                                     unsigned table_size, uint32_t seed)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED ^ seed;

  /* Hash the string with case folding */
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)str[i];
      if (c >= 'A' && c <= 'Z')
        c += 32;
      hash = ((hash << 5) + hash) ^ c;
    }

  return hash % table_size;
}

/* ============================================================================
 * TTL EXPIRY UTILITIES
 * ============================================================================
 */

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
socket_util_ttl_expired (int64_t insert_time_ms, uint32_t ttl_sec,
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
socket_util_ttl_remaining (int64_t insert_time_ms, uint32_t ttl_sec,
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

/* ============================================================================
 * BIG-ENDIAN BYTE MANIPULATION UTILITIES
 * ============================================================================
 */

/**
 * @brief Unpack 16-bit big-endian value.
 * @ingroup foundation
 * @param p Pointer to 2-byte buffer.
 * @return Decoded 16-bit value in host byte order.
 * @threadsafe Yes (pure function)
 *
 * Converts 2 bytes from big-endian (network) byte order to host byte order.
 * Used for parsing network protocols (DNS, HTTP/2, QUIC).
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
 *
 * Converts 16-bit value from host byte order to big-endian (network) byte order.
 * Used for serializing network protocols (DNS, HTTP/2, QUIC).
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
 * Converts 3 bytes from big-endian byte order to host byte order.
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
 *
 * Converts 24-bit value from host byte order to big-endian byte order.
 * Used for HTTP/2 frame length fields (24-bit).
 * Only the lower 24 bits of v are encoded.
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
 *
 * Converts 4 bytes from big-endian (network) byte order to host byte order.
 * Used for parsing network protocols (DNS, HTTP/2, QUIC).
 */
static inline uint32_t
socket_util_unpack_be32 (const unsigned char *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/**
 * @brief Pack 32-bit value to big-endian.
 * @ingroup foundation
 * @param p Pointer to 4-byte buffer.
 * @param v 32-bit value in host byte order.
 * @threadsafe Yes (pure function)
 *
 * Converts 32-bit value from host byte order to big-endian (network) byte order.
 * Used for serializing network protocols (DNS, HTTP/2, QUIC).
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
 *
 * Converts 8 bytes from big-endian (network) byte order to host byte order.
 * Used for parsing network protocols (DNS, HTTP/2, QUIC).
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
 *
 * Converts 64-bit value from host byte order to big-endian (network) byte order.
 * Used for serializing network protocols (DNS, HTTP/2, QUIC).
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

/* ============================================================================
 * IP ADDRESS UTILITY FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Safely copy IP address string with null termination
 * @ingroup utilities
 *
 * Copies IP address from src to dest with guaranteed null-termination.
 * Prevents buffer overflows by limiting copy to max_len-1 bytes and
 * always null-terminating the result.
 *
 * @param[out] dest Destination buffer (must be at least max_len bytes)
 * @param[in] src Source IP string to copy
 * @param[in] max_len Maximum size of destination buffer
 *
 * @threadsafe Yes - no shared state
 *
 * @complexity O(min(strlen(src), max_len)) - linear in string length
 *
 * Usage:
 *   char ip_buf[SOCKET_IP_MAX_LEN];
 *   socket_util_safe_copy_ip(ip_buf, client_ip, sizeof(ip_buf));
 *
 * @note Truncates src if it exceeds max_len-1 characters
 * @warning dest must be at least max_len bytes to avoid buffer overflow
 *
 * @see SOCKET_IP_MAX_LEN for standard IP buffer size
 * @see strncpy(3) for underlying copy mechanism
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
 * socket_util_safe_strncpy - Safe string copy with guaranteed null-termination
 * @dest: Destination buffer
 * @src: Source string to copy
 * @max_len: Maximum size of destination buffer (including null terminator)
 *
 * Copies up to max_len-1 characters from src to dest and always null-terminates.
 * Prevents buffer overflow by design. Truncates if source exceeds max_len-1.
 *
 * @threadsafe Yes - no shared state
 *
 * @complexity O(min(strlen(src), max_len)) - linear in string length
 *
 * Usage:
 *   char buf[256];
 *   socket_util_safe_strncpy(buf, user_input, sizeof(buf));
 *
 * @note Truncates src if it exceeds max_len-1 characters
 * @warning dest must be at least max_len bytes to avoid buffer overflow
 *
 * @see strncpy(3) for underlying copy mechanism
 */
static inline void
socket_util_safe_strncpy (char *dest, const char *src, size_t max_len)
{
  if (max_len == 0)
    return;
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
}

/* ============================================================================
 * MUTEX LOCK/UNLOCK MACROS (Standardized Error Handling)
 * ============================================================================
 *
 * Provides consistent mutex locking patterns across the codebase:
 * - SOCKET_MUTEX_LOCK_OR_RAISE: Lock with error handling via exception
 * - SOCKET_MUTEX_UNLOCK: Unlock (ignores errors per POSIX recommendation)
 * - SOCKET_WITH_MUTEX: Exception-safe scoped locking with TRY/FINALLY
 *
 * Why unlock ignores errors:
 * Per POSIX, pthread_mutex_unlock() errors indicate programming bugs:
 * - EPERM: Calling thread does not own the mutex
 * - EINVAL: Mutex is invalid or uninitialized
 *
 * Raising exceptions in cleanup paths (FINALLY blocks, destructors) causes
 * cascading failures that mask the original error. Production code should
 * log unlock errors in debug builds but not abort.
 *
 * See issue #512 for background and migration plan.
 */

/**
 * @brief SOCKET_MUTEX_LOCK_OR_RAISE - Lock mutex with error handling
 * @param mutex_ptr Pointer to pthread_mutex_t
 * @param module Module name for exception (e.g., SocketTimer)
 * @param exc Exception to raise (e.g., SocketTimer_Failed)
 *
 * Locks the mutex and raises an exception if lock fails. Uses
 * Socket_safe_strerror() for human-readable error messages.
 *
 * Thread-safe: Yes (pthread_mutex_lock is thread-safe)
 *
 * Example:
 *   SOCKET_MUTEX_LOCK_OR_RAISE(&pool->mutex, SocketPool, SocketPool_Failed);
 *   // ... critical section ...
 *   SOCKET_MUTEX_UNLOCK(&pool->mutex);
 */
#define SOCKET_MUTEX_LOCK_OR_RAISE(mutex_ptr, module, exc)                    \
  do                                                                          \
    {                                                                         \
      int _lock_err = pthread_mutex_lock (mutex_ptr);                         \
      if (_lock_err != 0)                                                     \
        SOCKET_RAISE_MSG (module, exc, "pthread_mutex_lock failed: %s",       \
                          Socket_safe_strerror (_lock_err));                  \
    }                                                                         \
  while (0)

/**
 * @brief SOCKET_MUTEX_UNLOCK - Unlock mutex (ignores errors)
 * @param mutex_ptr Pointer to pthread_mutex_t
 *
 * Unlocks the mutex. Ignores return value per POSIX recommendation.
 * Unlock errors indicate programming bugs (double-unlock, unowned mutex).
 * Raising exceptions on unlock causes cascading failures in cleanup paths.
 *
 * Thread-safe: Yes (pthread_mutex_unlock is thread-safe)
 *
 * Example:
 *   SOCKET_MUTEX_LOCK_OR_RAISE(&pool->mutex, SocketPool, SocketPool_Failed);
 *   // ... critical section ...
 *   SOCKET_MUTEX_UNLOCK(&pool->mutex);
 */
#define SOCKET_MUTEX_UNLOCK(mutex_ptr) (void)pthread_mutex_unlock (mutex_ptr)

/**
 * @brief SOCKET_WITH_MUTEX - Execute code block with mutex protection
 * @param mutex_ptr Pointer to pthread_mutex_t
 * @param module Module name for exception
 * @param exc Exception to raise on lock failure
 * @param code Code block to execute under lock
 *
 * Exception-safe scoped locking. The mutex is unlocked via FINALLY
 * even if the code block raises an exception.
 *
 * Thread-safe: Yes
 *
 * Example:
 *   SOCKET_WITH_MUTEX(&cache->mutex, SocketDNS, SocketDNS_Failed, {
 *     cache->hit_count++;
 *     result = lookup_entry(cache, key);
 *   });
 *
 * Warning: Do not use 'return' inside the code block. Use exception
 * handling (RAISE) or restructure code to avoid early returns.
 */
#define SOCKET_WITH_MUTEX(mutex_ptr, module, exc, code)                       \
  do                                                                          \
    {                                                                         \
      SOCKET_MUTEX_LOCK_OR_RAISE (mutex_ptr, module, exc);                    \
      TRY{ code } FINALLY { SOCKET_MUTEX_UNLOCK (mutex_ptr); }                \
      END_TRY;                                                                \
    }                                                                         \
  while (0)

/* ============================================================================
 * TIME CONVERSION UTILITIES
 * ============================================================================
 */

/**
 * @brief Convert milliseconds to timespec structure.
 * @ingroup foundation
 * @param ms Milliseconds value to convert
 * @return Populated timespec structure
 * @threadsafe Yes (pure function, no shared state)
 *
 * Converts milliseconds to a timespec structure suitable for nanosleep(),
 * clock_nanosleep(), and other POSIX time functions. Uses the centralized
 * time constants SOCKET_MS_PER_SECOND and SOCKET_NS_PER_MS for consistency.
 *
 * This function provides a single source of truth for millisecond-to-timespec
 * conversion, eliminating duplicated conversion logic across multiple modules.
 *
 * Usage:
 *   struct timespec ts = socket_util_ms_to_timespec(500); // 500ms
 *   nanosleep(&ts, NULL);
 *
 * @see socket_util_timespec_to_ms() for inverse conversion
 * @see SOCKET_MS_PER_SECOND for milliseconds per second constant
 * @see SOCKET_NS_PER_MS for nanoseconds per millisecond constant
 */
static inline struct timespec
socket_util_ms_to_timespec (unsigned long ms)
{
  struct timespec ts;
  ts.tv_sec = ms / SOCKET_MS_PER_SECOND;
  ts.tv_nsec = (ms % SOCKET_MS_PER_SECOND) * SOCKET_NS_PER_MS;
  return ts;
}

/**
 * @brief Convert timespec structure to milliseconds.
 * @ingroup foundation
 * @param ts Timespec structure to convert
 * @return Milliseconds value
 * @threadsafe Yes (pure function, no shared state)
 *
 * Converts a timespec structure to milliseconds. Uses centralized time
 * constants for consistency. Result is clamped to prevent integer overflow
 * when seconds value is very large.
 *
 * This is the inverse of socket_util_ms_to_timespec(). Provides consistent
 * timespec-to-millisecond conversion across the codebase.
 *
 * Usage:
 *   struct timespec ts;
 *   clock_gettime(CLOCK_MONOTONIC, &ts);
 *   unsigned long ms = socket_util_timespec_to_ms(ts);
 *
 * @see socket_util_ms_to_timespec() for inverse conversion
 * @see SOCKET_MS_PER_SECOND for milliseconds per second constant
 * @see SOCKET_NS_PER_MS for nanoseconds per millisecond constant
 */
static inline unsigned long
socket_util_timespec_to_ms (struct timespec ts)
{
  return (unsigned long)ts.tv_sec * SOCKET_MS_PER_SECOND
         + ts.tv_nsec / SOCKET_NS_PER_MS;
}

/* ============================================================================
 * BUFFER SIZE CONSTANTS
 * ============================================================================
 */

/**
 * @brief Standard initial buffer capacity for protocol message assembly.
 * @ingroup foundation
 *
 * Default size for initial message buffers in WebSocket and other protocol
 * implementations. Sized to accommodate typical messages while allowing
 * growth for larger payloads.
 *
 * Used for:
 * - WebSocket message reassembly initial capacity
 * - Protocol message parsing buffers
 * - Initial allocation for dynamic buffers
 *
 * @see SocketBuf_T for dynamic buffer implementation
 */
#define SOCKET_INITIAL_MESSAGE_CAPACITY 4096

/**
 * @brief Standard buffer growth factor for dynamic buffers.
 * @ingroup foundation
 *
 * Multiplicative factor for buffer capacity growth when resizing.
 * Value of 2 provides good balance between memory usage and reallocation
 * frequency (amortized O(1) appends).
 *
 * Used for:
 * - SocketBuf dynamic resizing
 * - WebSocket message buffer growth
 * - General dynamic buffer expansion
 */
#define SOCKET_BUFFER_GROWTH_FACTOR 2

#endif /* SOCKETUTIL_INCLUDED */

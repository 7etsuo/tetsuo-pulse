/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETERROR_INCLUDED
#define SOCKETERROR_INCLUDED

/**
 * @file SocketError.h
 * @ingroup foundation
 * @brief Error handling subsystem for errno mapping and categorization.
 *
 * Provides:
 * - Thread-local error buffers with formatted messages
 * - errno to SocketErrorCode mapping
 * - Error categorization for retry logic
 * - Thread-safe strerror wrapper
 *
 * @see SocketErrorCode for normalized error codes
 * @see SocketErrorCategory for error classification
 * @see @ref foundation for other core utilities
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/SocketConfig.h"

/**
 * @brief Normalized error codes mapping POSIX errno values.
 * @ingroup foundation
 */
typedef enum SocketErrorCode
{
  SOCKET_ERROR_NONE = 0,
  SOCKET_ERROR_EINVAL,
  SOCKET_ERROR_EACCES,
  SOCKET_ERROR_EADDRINUSE,
  SOCKET_ERROR_EADDRNOTAVAIL,
  SOCKET_ERROR_EAFNOSUPPORT,
  SOCKET_ERROR_EAGAIN,
  SOCKET_ERROR_EALREADY,
  SOCKET_ERROR_EBADF,
  SOCKET_ERROR_ECONNREFUSED,
  SOCKET_ERROR_ECONNRESET,
  SOCKET_ERROR_EFAULT,
  SOCKET_ERROR_EHOSTUNREACH,
  SOCKET_ERROR_EINPROGRESS,
  SOCKET_ERROR_EINTR,
  SOCKET_ERROR_EISCONN,
  SOCKET_ERROR_EMFILE,
  SOCKET_ERROR_ENETUNREACH,
  SOCKET_ERROR_ENOBUFS,
  SOCKET_ERROR_ENOMEM,
  SOCKET_ERROR_ENOTCONN,
  SOCKET_ERROR_ENOTSOCK,
  SOCKET_ERROR_EOPNOTSUPP,
  SOCKET_ERROR_EPIPE,
  SOCKET_ERROR_EPROTONOSUPPORT,
  SOCKET_ERROR_ETIMEDOUT,
  SOCKET_ERROR_EWOULDBLOCK,
  SOCKET_ERROR_UNKNOWN
} SocketErrorCode;

/* Thread-local error buffer for detailed messages */
#ifdef _WIN32
extern __declspec (thread) char socket_error_buf[SOCKET_ERROR_BUFSIZE];
extern __declspec (thread) int socket_last_errno;
#else
extern __thread char socket_error_buf[SOCKET_ERROR_BUFSIZE];
extern __thread int socket_last_errno;
#endif

/**
 * @brief SOCKET_ERROR_APPLY_TRUNCATION - Apply truncation marker if message
 was cut
 *
 * @ret: Return value from snprintf
 *
 * Internal helper macro to eliminate duplication in error formatting.
 */
#define SOCKET_ERROR_APPLY_TRUNCATION(ret)                              \
  do                                                                    \
    {                                                                   \
      if ((ret) >= (int)SOCKET_ERROR_BUFSIZE)                           \
        {                                                               \
          socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';            \
          if (SOCKET_ERROR_BUFSIZE >= SOCKET_ERROR_TRUNCATION_SIZE + 1) \
            {                                                           \
              memcpy (socket_error_buf + SOCKET_ERROR_BUFSIZE           \
                          - SOCKET_ERROR_TRUNCATION_SIZE,               \
                      SOCKET_ERROR_TRUNCATION_MARKER,                   \
                      SOCKET_ERROR_TRUNCATION_SIZE - 1);                \
              socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';        \
            }                                                           \
        }                                                               \
    }                                                                   \
  while (0)

/**
 * @brief Get the last formatted error message.
 * @ingroup foundation
 *
 * @return Thread-local error string (never NULL).
 *
 * @threadsafe Yes
 */
extern const char *Socket_GetLastError (void);

/**
 * @brief Get the raw errno from the last error.
 * @ingroup foundation
 *
 * @return Last errno value.
 *
 * @threadsafe Yes
 */
extern int Socket_geterrno (void);

/**
 * @brief Convert last errno to normalized SocketErrorCode.
 * @ingroup foundation
 *
 * @return Mapped SocketErrorCode (SOCKET_ERROR_UNKNOWN if unmapped).
 *
 * @threadsafe Yes
 */
extern SocketErrorCode Socket_geterrorcode (void);

/**
 * @brief Thread-safe errno to string conversion.
 * @ingroup foundation
 *
 * @param errnum errno value to convert.
 * @return Descriptive error string.
 *
 * @threadsafe Yes
 */
const char *Socket_safe_strerror (int errnum);

/* Common error conditions with descriptive messages */
#define SOCKET_ENOMEM "Out of memory"
#define SOCKET_EINVAL "Invalid argument"
#define SOCKET_ECONNREFUSED "Connection refused"
#define SOCKET_ETIMEDOUT "Operation timed out"
#define SOCKET_EADDRINUSE "Address already in use"
#define SOCKET_ENETUNREACH "Network unreachable"
#define SOCKET_EHOSTUNREACH "Host unreachable"
#define SOCKET_EPIPE "Broken pipe"
#define SOCKET_ECONNRESET "Connection reset by peer"

/**
 * @brief High-level classification of error types.
 * @ingroup foundation
 */
typedef enum SocketErrorCategory
{
  SOCKET_ERROR_CATEGORY_NETWORK
  = 0, /**< Network-level: ECONNRESET, ECONNREFUSED, etc. */
  SOCKET_ERROR_CATEGORY_PROTOCOL,    /**< Protocol-level: Parse errors, invalid
                                        responses */
  SOCKET_ERROR_CATEGORY_APPLICATION, /**< App-level: Auth failures, 4xx
                                        responses */
  SOCKET_ERROR_CATEGORY_TIMEOUT,     /**< Timeout errors: ETIMEDOUT, deadline
                                        exceeded */
  SOCKET_ERROR_CATEGORY_RESOURCE,    /**< Resource exhaustion: OOM, fd limits */
  SOCKET_ERROR_CATEGORY_UNKNOWN,     /**< Unclassified errors */
  SOCKET_ERROR_CATEGORY_COUNT /**< Sentinel: total number of categories */
} SocketErrorCategory;

/**
 * @brief Classify errno into SocketErrorCategory.
 * @ingroup foundation
 *
 * @param err errno value to classify.
 * @return Appropriate SocketErrorCategory.
 *
 * @threadsafe Yes
 */
extern SocketErrorCategory SocketError_categorize_errno (int err);

/**
 * @brief Get string name for error category.
 * @param category Error category.
 * @return Static string with category name.
 * @threadsafe Yes (returns static data)
 */
extern const char *SocketError_category_name (SocketErrorCategory category);

/**
 * @brief SocketError_is_retryable_errno - Check if errno indicates retryable
 error
 *
 * @err: errno value to check
 *
 * Returns: 1 if error is typically retryable, 0 if fatal
 * @brief Thread-safe: Yes (pure function)
 *
 *
 * Retryable errors include:
 * - Network transient: ECONNREFUSED, ECONNRESET, ENETUNREACH, EHOSTUNREACH
 * - Timeout: ETIMEDOUT
 * - Temporary resource: EAGAIN, EWOULDBLOCK, EINTR
 *
 * @brief Non-retryable errors include:
 *
 * - Configuration: EACCES, EADDRINUSE, EADDRNOTAVAIL, EPERM
 * - Programming: EBADF, ENOTSOCK, EINVAL, EFAULT
 * - Permanent resource: ENOMEM, EMFILE, ENFILE
 */
extern int SocketError_is_retryable_errno (int err);

#endif /* SOCKETERROR_INCLUDED */

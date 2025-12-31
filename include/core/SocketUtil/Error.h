/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_ERROR_H
#define SOCKETUTIL_ERROR_H

/**
 * @file SocketUtil/Error.h
 * @ingroup foundation
 * @brief Error formatting macros combining error messages with logging.
 *
 * Provides convenience macros that format error messages into thread-local
 * buffers and emit them to the logging subsystem in a single operation.
 *
 * @see core/SocketError.h for underlying error buffer infrastructure
 * @see core/SocketLog.h for logging subsystem
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "core/SocketError.h"
#include "core/SocketLog.h"

/**
 * @brief SOCKET_ERROR_FMT - Format error message with errno information.
 *
 * Formats a printf-style message with errno details appended, stores it
 * in the thread-local error buffer, and emits it to the log subsystem.
 * Includes truncation protection for long messages.
 *
 * @param fmt Printf-style format string.
 * @param ... Format arguments.
 *
 * @threadsafe Yes (uses thread-local buffers)
 */
#define SOCKET_ERROR_FMT(fmt, ...)                                   \
  do                                                                 \
    {                                                                \
      socket_last_errno = errno;                                     \
      char tmp_buf[SOCKET_ERROR_BUFSIZE];                            \
      int _socket_error_ret                                          \
          = snprintf (tmp_buf,                                       \
                      sizeof (tmp_buf),                              \
                      fmt " (errno: %d - %s)",                       \
                      ##__VA_ARGS__,                                 \
                      socket_last_errno,                             \
                      Socket_safe_strerror (socket_last_errno));     \
      memcpy (socket_error_buf, tmp_buf, SOCKET_ERROR_BUFSIZE);      \
      socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';             \
      SOCKET_ERROR_APPLY_TRUNCATION (_socket_error_ret);             \
      (void)_socket_error_ret;                                       \
      SocketLog_emit (                                               \
          SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT, socket_error_buf); \
    }                                                                \
  while (0)

/**
 * @brief SOCKET_ERROR_MSG - Format error message without errno.
 *
 * Formats a printf-style message, stores it in the thread-local error buffer,
 * and emits it to the log subsystem. Use when errno is not relevant.
 * Includes truncation protection for long messages.
 *
 * @param fmt Printf-style format string.
 * @param ... Format arguments.
 *
 * @threadsafe Yes (uses thread-local buffers)
 */
#define SOCKET_ERROR_MSG(fmt, ...)                                    \
  do                                                                  \
    {                                                                 \
      socket_last_errno = errno;                                      \
      char tmp_buf[SOCKET_ERROR_BUFSIZE];                             \
      int _socket_error_ret                                           \
          = snprintf (tmp_buf, sizeof (tmp_buf), fmt, ##__VA_ARGS__); \
      memcpy (socket_error_buf, tmp_buf, SOCKET_ERROR_BUFSIZE);       \
      socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';              \
      SOCKET_ERROR_APPLY_TRUNCATION (_socket_error_ret);              \
      (void)_socket_error_ret;                                        \
      SocketLog_emit (                                                \
          SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT, socket_error_buf);  \
    }                                                                 \
  while (0)

#endif /* SOCKETUTIL_ERROR_H */

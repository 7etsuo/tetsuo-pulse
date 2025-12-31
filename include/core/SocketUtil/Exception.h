/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_EXCEPTION_H
#define SOCKETUTIL_EXCEPTION_H

/**
 * @file SocketUtil/Exception.h
 * @ingroup foundation
 * @brief Centralized exception infrastructure for socket modules.
 *
 * Provides macros for declaring module-specific exceptions and raising them
 * with detailed error messages. Combines error formatting with exception
 * raising in a single operation.
 *
 * @see core/Except.h for underlying exception handling framework
 * @see SocketUtil/Error.h for error formatting macros
 */

#include "core/Except.h"
#include "core/SocketError.h"
#include "core/SocketUtil/Error.h"

/**
 * @brief SOCKET_DECLARE_MODULE_EXCEPTION - Declare thread-local exception.
 *
 * Declares a thread-local exception variable for a module, allowing
 * thread-safe exception raising with detailed reason strings.
 *
 * @param module_name Module name (e.g., Socket, SocketBuf, SocketPoll).
 *
 * Usage:
 *   SOCKET_DECLARE_MODULE_EXCEPTION(MyModule);
 */
#define SOCKET_DECLARE_MODULE_EXCEPTION(module_name) \
  static __thread Except_T module_name##_DetailedException

/**
 * @brief SOCKET_RAISE_MODULE_ERROR - Raise module-specific exception.
 *
 * Creates a thread-local copy of the exception with the current error buffer
 * as the reason, then raises it.
 *
 * @param module_name Module name.
 * @param exception Exception to raise.
 *
 * @threadsafe Yes (uses thread-local storage)
 */
#define SOCKET_RAISE_MODULE_ERROR(module_name, exception)        \
  do                                                             \
    {                                                            \
      module_name##_DetailedException = (exception);             \
      module_name##_DetailedException.reason = socket_error_buf; \
      RAISE (module_name##_DetailedException);                   \
    }                                                            \
  while (0)

/**
 * @brief SOCKET_RAISE_FMT - Format error with errno and raise exception.
 *
 * Combines SOCKET_ERROR_FMT + SOCKET_RAISE_MODULE_ERROR into a single macro.
 * Formats the error message with errno details and raises the exception.
 *
 * @param module_name Module name for exception.
 * @param exception Exception to raise.
 * @param fmt Printf-style format string.
 * @param ... Format arguments.
 *
 * @threadsafe Yes (uses thread-local buffers)
 */
#define SOCKET_RAISE_FMT(module_name, exception, fmt, ...) \
  do                                                       \
    {                                                      \
      SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__);               \
      SOCKET_RAISE_MODULE_ERROR (module_name, exception);  \
    }                                                      \
  while (0)

/**
 * @brief SOCKET_RAISE_MSG - Format error message and raise exception.
 *
 * Combines SOCKET_ERROR_MSG + SOCKET_RAISE_MODULE_ERROR into a single macro.
 * Formats the error message (without errno) and raises the exception.
 *
 * @param module_name Module name for exception.
 * @param exception Exception to raise.
 * @param fmt Printf-style format string (without errno).
 * @param ... Format arguments.
 *
 * @threadsafe Yes (uses thread-local buffers)
 */
#define SOCKET_RAISE_MSG(module_name, exception, fmt, ...) \
  do                                                       \
    {                                                      \
      SOCKET_ERROR_MSG (fmt, ##__VA_ARGS__);               \
      SOCKET_RAISE_MODULE_ERROR (module_name, exception);  \
    }                                                      \
  while (0)

/*
 * Helper macros for common module patterns - use RAISE_MODULE_ERROR macro
 * defined in each module that sets module_name appropriately.
 *
 * Example module setup:
 *   SOCKET_DECLARE_MODULE_EXCEPTION(MyModule);
 *   #define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(MyModule, e)
 *   #define RAISE_FMT(e, fmt, ...) SOCKET_RAISE_FMT(MyModule, e, fmt,
 * ##__VA_ARGS__)
 *   #define RAISE_MSG(e, fmt, ...) SOCKET_RAISE_MSG(MyModule, e, fmt,
 * ##__VA_ARGS__)
 */

#endif /* SOCKETUTIL_EXCEPTION_H */

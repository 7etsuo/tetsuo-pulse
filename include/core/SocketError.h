#ifndef SOCKETERROR_INCLUDED
#define SOCKETERROR_INCLUDED

#include <errno.h>
#include <string.h>

#include "core/SocketConfig-limits.h"
#include "core/SocketLog.h"

/**
 * SocketErrorCode - Error code enumeration mapping common errno values
 * Provides structured error codes for programmatic error handling
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

/* Constants SOCKET_ERROR_BUFSIZE, SOCKET_ERROR_TRUNCATION_*, SOCKET_ERROR_MAX_*
 * are defined in SocketConfig-limits.h (single source of truth for limits) */

/* Thread-local error buffer for detailed messages */
#ifdef _WIN32
extern __declspec (thread) char socket_error_buf[SOCKET_ERROR_BUFSIZE];
extern __declspec (thread) int socket_last_errno;
#else
extern __thread char socket_error_buf[SOCKET_ERROR_BUFSIZE];
extern __thread int socket_last_errno;
#endif

/* Default log component (overridable before including this header) */
#ifndef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "Socket"
#endif

/* Macro to format error messages with errno information - with truncation
 * protection */
#define SOCKET_ERROR_FMT(fmt, ...)                                            \
  do                                                                          \
    {                                                                         \
      socket_last_errno = errno;                                              \
      int _socket_error_ret = snprintf (                                      \
          socket_error_buf, SOCKET_ERROR_BUFSIZE, fmt " (errno: %d - %s)",    \
          ##__VA_ARGS__, socket_last_errno,                                   \
          Socket_safe_strerror (socket_last_errno));                          \
      if (_socket_error_ret >= (int)SOCKET_ERROR_BUFSIZE)                     \
        {                                                                     \
          /* Message was truncated - add truncation marker */                 \
          socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';                  \
          if (SOCKET_ERROR_BUFSIZE >= SOCKET_ERROR_TRUNCATION_SIZE + 1)       \
            {                                                                 \
              memcpy (socket_error_buf + SOCKET_ERROR_BUFSIZE                 \
                          - SOCKET_ERROR_TRUNCATION_SIZE,                     \
                      SOCKET_ERROR_TRUNCATION_MARKER,                         \
                      SOCKET_ERROR_TRUNCATION_SIZE - 1);                      \
              socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';              \
            }                                                                 \
        }                                                                     \
      (void)_socket_error_ret; /* Suppress unused warning */                  \
      SocketLog_emit (SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT,                 \
                      socket_error_buf);                                      \
    }                                                                         \
  while (0)

/* Macro to format error messages without errno - with truncation protection */
#define SOCKET_ERROR_MSG(fmt, ...)                                            \
  do                                                                          \
    {                                                                         \
      socket_last_errno = errno;                                              \
      int _socket_error_ret = snprintf (                                      \
          socket_error_buf, SOCKET_ERROR_BUFSIZE, fmt, ##__VA_ARGS__);        \
      if (_socket_error_ret >= (int)SOCKET_ERROR_BUFSIZE)                     \
        {                                                                     \
          /* Message was truncated - add truncation marker */                 \
          socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';                  \
          if (SOCKET_ERROR_BUFSIZE >= SOCKET_ERROR_TRUNCATION_SIZE + 1)       \
            {                                                                 \
              memcpy (socket_error_buf + SOCKET_ERROR_BUFSIZE                 \
                          - SOCKET_ERROR_TRUNCATION_SIZE,                     \
                      SOCKET_ERROR_TRUNCATION_MARKER,                         \
                      SOCKET_ERROR_TRUNCATION_SIZE - 1);                      \
              socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';              \
            }                                                                 \
        }                                                                     \
      (void)_socket_error_ret; /* Suppress unused warning */                  \
      SocketLog_emit (SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT,                 \
                      socket_error_buf);                                      \
    }                                                                         \
  while (0)

/* Get the last error message - declared here, defined in SocketError.c */
extern const char *Socket_GetLastError (void);

/**
 * Socket_geterrno - Get the last captured errno value
 * Returns: Last errno value captured by error macros (0 if no error)
 * Thread-safe: Uses thread-local storage
 */
extern int Socket_geterrno (void);

/**
 * Socket_geterrorcode - Get the last error as a SocketErrorCode enum
 * Returns: SocketErrorCode enum value corresponding to last captured errno
 * Thread-safe: Uses thread-local storage
 */
extern SocketErrorCode Socket_geterrorcode (void);

/**
 * Socket_safe_strerror - Thread-safe strerror implementation
 * @errnum: Error number to convert
 * Returns: Static thread-local string describing the error
 * Thread-safe: Yes, uses thread-local buffer and strerror_r
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

/* ============================================================================
 * Centralized Exception Infrastructure
 * ============================================================================
 *
 * To eliminate massive duplication across 34+ socket source files, all modules
 * now use these centralized exception macros instead of copy-pasted boilerplate.
 *
 * Usage in source files:
 * 1. Include this header
 * 2. Use SOCKET_DECLARE_MODULE_EXCEPTION(MODULE_NAME) instead of:
 *    #ifdef _WIN32
 *    static __declspec(thread) Except_T Module_DetailedException;
 *    #else
 *    static __thread Except_T Module_DetailedException;
 *    #endif
 *
 * 3. Use SOCKET_RAISE_MODULE_ERROR(MODULE_NAME, exception) instead of:
 *    #define RAISE_MODULE_ERROR(exception) \
 *      do { \
 *        Module_DetailedException = (exception); \
 *        Module_DetailedException.reason = socket_error_buf; \
 *        RAISE(Module_DetailedException); \
 *      } while (0)
 */

/**
 * SOCKET_DECLARE_MODULE_EXCEPTION - Declare thread-local exception for a module
 * @module_name: Module name (e.g., Socket, SocketBuf, SocketPoll)
 *
 * Creates a thread-local Except_T variable named module_name_DetailedException
 */
#define SOCKET_DECLARE_MODULE_EXCEPTION(module_name)                           \
  static __thread Except_T module_name##_DetailedException

/**
 * SOCKET_RAISE_MODULE_ERROR - Raise a module-specific exception with detailed error
 * @module_name: Module name (e.g., Socket, SocketBuf, SocketPoll)
 * @exception: Exception to raise (e.g., Socket_Failed, SocketBuf_Failed)
 *
 * Thread-safe: Creates thread-local copy of exception with detailed reason string
 */
#define SOCKET_RAISE_MODULE_ERROR(module_name, exception)                      \
  do {                                                                         \
    module_name##_DetailedException = (exception);                             \
    module_name##_DetailedException.reason = socket_error_buf;                 \
    RAISE(module_name##_DetailedException);                                    \
  } while (0)

#endif /* SOCKETERROR_INCLUDED */

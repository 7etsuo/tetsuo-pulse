/**
 * SocketError.c - Thread-local error message handling
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Provides thread-safe error message storage and retrieval. Each thread
 * maintains its own error buffer and errno capture for detailed error
 * reporting.
 *
 * FEATURES:
 * - Thread-local error buffers
 * - errno to SocketErrorCode mapping
 * - Thread-safe strerror implementation
 * - Last error message retrieval
 *
 * THREAD SAFETY:
 * - All operations use thread-local storage
 * - No mutex required for error handling
 */

#include <string.h>

#include "core/SocketError.h"

/**
 * socket_errno_to_errorcode - Map errno value to SocketErrorCode
 * @errno_val: errno value to map
 *
 * Returns: Corresponding SocketErrorCode enum value
 * Thread-safe: Yes (pure function)
 *
 * Maps common POSIX errno values to structured SocketErrorCode values
 * for programmatic error handling.
 */
static SocketErrorCode
socket_errno_to_errorcode (int errno_val)
{
  switch (errno_val)
    {
    case 0:
      return SOCKET_ERROR_NONE;
    case EINVAL:
      return SOCKET_ERROR_EINVAL;
    case EACCES:
      return SOCKET_ERROR_EACCES;
    case EADDRINUSE:
      return SOCKET_ERROR_EADDRINUSE;
    case EADDRNOTAVAIL:
      return SOCKET_ERROR_EADDRNOTAVAIL;
    case EAFNOSUPPORT:
      return SOCKET_ERROR_EAFNOSUPPORT;
    case EAGAIN:
      return SOCKET_ERROR_EAGAIN;
#if EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
      return SOCKET_ERROR_EWOULDBLOCK;
#endif
    case EALREADY:
      return SOCKET_ERROR_EALREADY;
    case EBADF:
      return SOCKET_ERROR_EBADF;
    case ECONNREFUSED:
      return SOCKET_ERROR_ECONNREFUSED;
    case ECONNRESET:
      return SOCKET_ERROR_ECONNRESET;
    case EFAULT:
      return SOCKET_ERROR_EFAULT;
    case EHOSTUNREACH:
      return SOCKET_ERROR_EHOSTUNREACH;
    case EINPROGRESS:
      return SOCKET_ERROR_EINPROGRESS;
    case EINTR:
      return SOCKET_ERROR_EINTR;
    case EISCONN:
      return SOCKET_ERROR_EISCONN;
    case EMFILE:
      return SOCKET_ERROR_EMFILE;
    case ENETUNREACH:
      return SOCKET_ERROR_ENETUNREACH;
    case ENOBUFS:
      return SOCKET_ERROR_ENOBUFS;
    case ENOMEM:
      return SOCKET_ERROR_ENOMEM;
    case ENOTCONN:
      return SOCKET_ERROR_ENOTCONN;
    case ENOTSOCK:
      return SOCKET_ERROR_ENOTSOCK;
    case EOPNOTSUPP:
      return SOCKET_ERROR_EOPNOTSUPP;
    case EPIPE:
      return SOCKET_ERROR_EPIPE;
    case EPROTONOSUPPORT:
      return SOCKET_ERROR_EPROTONOSUPPORT;
    case ETIMEDOUT:
      return SOCKET_ERROR_ETIMEDOUT;
    default:
      return SOCKET_ERROR_UNKNOWN;
    }
}

/* Thread-local error buffer for detailed error messages */
#ifdef _WIN32
__declspec (thread) char socket_error_buf[SOCKET_ERROR_BUFSIZE] = { 0 };
__declspec (thread) int socket_last_errno = 0;
#else
__thread char socket_error_buf[SOCKET_ERROR_BUFSIZE] = { 0 };
__thread int socket_last_errno = 0;
#endif

/**
 * Socket_GetLastError - Get the last error message
 *
 * Returns: Pointer to thread-local error message buffer
 * Thread-safe: Yes (returns thread-local data)
 *
 * Returns the most recent error message set by SOCKET_ERROR_FMT or
 * SOCKET_ERROR_MSG macros.
 */
const char *
Socket_GetLastError (void)
{
  return socket_error_buf;
}

/**
 * Socket_geterrno - Get the last captured errno value
 *
 * Returns: Last errno value captured by error macros (0 if no error)
 * Thread-safe: Yes (uses thread-local storage)
 *
 * Returns the errno value that was captured when the last error message
 * was formatted.
 */
int
Socket_geterrno (void)
{
  return socket_last_errno;
}

/**
 * Socket_geterrorcode - Get the last error as a SocketErrorCode enum
 *
 * Returns: SocketErrorCode enum value corresponding to last captured errno
 * Thread-safe: Yes (uses thread-local storage)
 *
 * Converts the last captured errno to a structured SocketErrorCode
 * for programmatic error handling.
 */
SocketErrorCode
Socket_geterrorcode (void)
{
  return socket_errno_to_errorcode (socket_last_errno);
}

/**
 * Socket_safe_strerror - Thread-safe strerror implementation
 * @errnum: Error number to convert
 *
 * Returns: Pointer to thread-local string describing the error
 * Thread-safe: Yes (uses thread-local buffer and strerror_r)
 *
 * Provides a thread-safe alternative to strerror() which is not
 * guaranteed to be thread-safe on all platforms.
 */
const char *
Socket_safe_strerror (int errnum)
{
  static __thread char errbuf[128] = { 0 };

  if (errnum == 0)
    {
      strcpy (errbuf, "No error");
      return errbuf;
    }

#ifdef _GNU_SOURCE
  /* GNU extension: returns char* */
  return strerror_r (errnum, errbuf, sizeof (errbuf));
#else
  /* POSIX: returns int, 0 on success */
  if (strerror_r (errnum, errbuf, sizeof (errbuf)) != 0)
    strcpy (errbuf, "Unknown error");
  return errbuf;
#endif
}

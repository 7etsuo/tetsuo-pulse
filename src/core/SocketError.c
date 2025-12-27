/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* Error handling subsystem: errno mapping, categorization, thread-local buffers */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "core/SocketConfig.h"
#include "core/SocketError.h"

typedef struct SocketErrorMapping
{
  int err;
  SocketErrorCode code;
  SocketErrorCategory category;
  int retryable;
} SocketErrorMapping;

static const SocketErrorMapping error_mappings[] = {
  { 0, SOCKET_ERROR_NONE, SOCKET_ERROR_CATEGORY_UNKNOWN, 0 },
  { EINVAL, SOCKET_ERROR_EINVAL, SOCKET_ERROR_CATEGORY_PROTOCOL, 0 },
  { EACCES, SOCKET_ERROR_EACCES, SOCKET_ERROR_CATEGORY_APPLICATION, 0 },
  { EADDRINUSE, SOCKET_ERROR_EADDRINUSE, SOCKET_ERROR_CATEGORY_APPLICATION,
    0 },
  { EADDRNOTAVAIL, SOCKET_ERROR_EADDRNOTAVAIL,
    SOCKET_ERROR_CATEGORY_APPLICATION, 0 },
  { EAFNOSUPPORT, SOCKET_ERROR_EAFNOSUPPORT, SOCKET_ERROR_CATEGORY_PROTOCOL,
    0 },
  { EAGAIN, SOCKET_ERROR_EAGAIN, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
#ifdef EWOULDBLOCK
  { EWOULDBLOCK, SOCKET_ERROR_EWOULDBLOCK, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
#endif
  { EALREADY, SOCKET_ERROR_EALREADY, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
  { EBADF, SOCKET_ERROR_EBADF, SOCKET_ERROR_CATEGORY_PROTOCOL, 0 },
  { ECONNREFUSED, SOCKET_ERROR_ECONNREFUSED, SOCKET_ERROR_CATEGORY_NETWORK,
    1 },
  { ECONNRESET, SOCKET_ERROR_ECONNRESET, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
  { EFAULT, SOCKET_ERROR_EFAULT, SOCKET_ERROR_CATEGORY_PROTOCOL, 0 },
  { EHOSTUNREACH, SOCKET_ERROR_EHOSTUNREACH, SOCKET_ERROR_CATEGORY_NETWORK,
    1 },
  { EINPROGRESS, SOCKET_ERROR_EINPROGRESS, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
  { EINTR, SOCKET_ERROR_EINTR, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
  { EISCONN, SOCKET_ERROR_EISCONN, SOCKET_ERROR_CATEGORY_PROTOCOL, 0 },
  { EMFILE, SOCKET_ERROR_EMFILE, SOCKET_ERROR_CATEGORY_RESOURCE, 0 },
  { ENETUNREACH, SOCKET_ERROR_ENETUNREACH, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
  { ENOBUFS, SOCKET_ERROR_ENOBUFS, SOCKET_ERROR_CATEGORY_RESOURCE, 0 },
  { ENOMEM, SOCKET_ERROR_ENOMEM, SOCKET_ERROR_CATEGORY_RESOURCE, 0 },
  { ENOTCONN, SOCKET_ERROR_ENOTCONN, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
  { ENOTSOCK, SOCKET_ERROR_ENOTSOCK, SOCKET_ERROR_CATEGORY_PROTOCOL, 0 },
  { EOPNOTSUPP, SOCKET_ERROR_EOPNOTSUPP, SOCKET_ERROR_CATEGORY_PROTOCOL, 0 },
  { EPIPE, SOCKET_ERROR_EPIPE, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
  { EPROTONOSUPPORT, SOCKET_ERROR_EPROTONOSUPPORT,
    SOCKET_ERROR_CATEGORY_PROTOCOL, 0 },
  { ETIMEDOUT, SOCKET_ERROR_ETIMEDOUT, SOCKET_ERROR_CATEGORY_TIMEOUT, 1 },
  /* Additional errnos from categorize and retryable functions */
  { ECONNABORTED, SOCKET_ERROR_UNKNOWN, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
#ifdef ENETDOWN
  { ENETDOWN, SOCKET_ERROR_UNKNOWN, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
#endif
#ifdef ENETRESET
  { ENETRESET, SOCKET_ERROR_UNKNOWN, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
#endif
  { ENFILE, SOCKET_ERROR_UNKNOWN, SOCKET_ERROR_CATEGORY_RESOURCE, 0 },
#ifdef ENOSPC
  { ENOSPC, SOCKET_ERROR_UNKNOWN, SOCKET_ERROR_CATEGORY_RESOURCE, 0 },
#endif
#ifdef EPROTO
  { EPROTO, SOCKET_ERROR_UNKNOWN, SOCKET_ERROR_CATEGORY_PROTOCOL, 0 },
#endif
  { EPERM, SOCKET_ERROR_UNKNOWN, SOCKET_ERROR_CATEGORY_APPLICATION, 0 },
};

#define NUM_ERROR_MAPPINGS                                                    \
  (sizeof (error_mappings) / sizeof (error_mappings[0]))
#define NUM_ERROR_CATEGORIES 6

/* O(n) linear scan of ~30 entries - acceptable for small table */
static const SocketErrorMapping *
socket_find_error_mapping (const int err)
{
  for (size_t i = 0; i < NUM_ERROR_MAPPINGS; i++)
    {
      if (error_mappings[i].err == err)
        {
          return &error_mappings[i];
        }
    }
  return NULL;
}

static SocketErrorCode
socket_errno_to_errorcode (int errno_val)
{
  const SocketErrorMapping *m = socket_find_error_mapping (errno_val);
  return m ? m->code : SOCKET_ERROR_UNKNOWN;
}

#ifdef _WIN32
__declspec (thread) char socket_error_buf[SOCKET_ERROR_BUFSIZE] = { 0 };
__declspec (thread) int socket_last_errno = 0;
#else
__thread char socket_error_buf[SOCKET_ERROR_BUFSIZE] = { 0 };
__thread int socket_last_errno = 0;
#endif

const char *
Socket_GetLastError (void)
{
  return socket_error_buf;
}

int
Socket_geterrno (void)
{
  return socket_last_errno;
}

SocketErrorCode
Socket_geterrorcode (void)
{
  return socket_errno_to_errorcode (socket_last_errno);
}

const char *
Socket_safe_strerror (int errnum)
{
  static __thread char errbuf[SOCKET_STRERROR_BUFSIZE] = { 0 };

  if (errnum == 0)
    {
      snprintf (errbuf, sizeof (errbuf), "No error");
      return errbuf;
    }

#if defined(__GLIBC__) && defined(_GNU_SOURCE)
  /* GNU extension (glibc only): returns char* */
  return strerror_r (errnum, errbuf, sizeof (errbuf));
#else
  /* XSI-compliant (POSIX, macOS, BSD): returns int, 0 on success */
  if (strerror_r (errnum, errbuf, sizeof (errbuf)) != 0)
    snprintf (errbuf, sizeof (errbuf), "Unknown error %d", errnum);
  return errbuf;
#endif
}

static const char *const socket_error_category_names[] = {
  "NETWORK", "PROTOCOL", "APPLICATION", "TIMEOUT", "RESOURCE", "UNKNOWN"
};

SocketErrorCategory
SocketError_categorize_errno (int err)
{
  const SocketErrorMapping *m = socket_find_error_mapping (err);
  return m ? m->category : SOCKET_ERROR_CATEGORY_UNKNOWN;
}

const char *
SocketError_category_name (SocketErrorCategory category)
{
  if (category < 0 || (size_t)category >= NUM_ERROR_CATEGORIES)
    return "UNKNOWN";
  return socket_error_category_names[category];
}

int
SocketError_is_retryable_errno (int err)
{
  const SocketErrorMapping *m = socket_find_error_mapping (err);
  return m ? m->retryable : 0;
}

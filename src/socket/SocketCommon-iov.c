/**
 * SocketCommon-iov.c - I/O vector utilities
 *
 * Contains scatter/gather I/O vector operations
 * extracted from the main SocketCommon.c file.
 */

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#include "core/SocketConfig.h"
#define SOCKET_LOG_COMPONENT "SocketCommon"
#include "core/SocketError.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

/* Forward declarations for exception types */
extern const Except_T Socket_Failed;
extern const Except_T SocketDgram_Failed;
extern const Except_T SocketCommon_Failed;

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketCommon);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketCommon, e)

/**
 * SocketCommon_calculate_total_iov_len - Calculate total length of iovec
 * array with overflow protection Unifies duplicated loops from Socket.c,
 * SocketDgram.c, and SocketIO.c internals
 */
size_t
SocketCommon_calculate_total_iov_len (const struct iovec *iov, int iovcnt)
{
  size_t total = 0;
  int i;

  if (!iov || iovcnt <= 0 || iovcnt > IOV_MAX)
    {
      SOCKET_ERROR_FMT ("Invalid iov params: iov=%p iovcnt=%d", iov, iovcnt);
      RAISE_MODULE_ERROR (SocketCommon_Failed);
    }

  for (i = 0; i < iovcnt; i++)
    {
      if (iov[i].iov_len > SIZE_MAX - total)
        {
          SOCKET_ERROR_FMT ("iov[%d] overflow: total=%zu + len=%zu > SIZE_MAX",
                            i, total, iov[i].iov_len);
          RAISE_MODULE_ERROR (SocketCommon_Failed);
        }
      total += iov[i].iov_len;
    }

  return total;
}

/**
 * SocketCommon_advance_iov - Advance iovec past bytes (in place)
 * Unifies duplicated logic from Socket.c and SocketDgram.c for vall
 * functions Validates bytes <= total via calc (raises on mismatch/overflow)
 */
void
SocketCommon_advance_iov (struct iovec *iov, int iovcnt, size_t bytes)
{
  size_t remaining = bytes;
  int i;
  size_t total_len;

  if (!iov || iovcnt <= 0 || iovcnt > IOV_MAX)
    {
      SOCKET_ERROR_FMT ("Invalid advance params: iov=%p iovcnt=%d bytes=%zu",
                        iov, iovcnt, bytes);
      RAISE_MODULE_ERROR (SocketCommon_Failed);
    }

  total_len = SocketCommon_calculate_total_iov_len (
      iov, iovcnt); /* Raises on issues */

  if (bytes > total_len)
    {
      SOCKET_ERROR_FMT ("Advance too far: bytes=%zu > total=%zu", bytes,
                        total_len);
      RAISE_MODULE_ERROR (SocketCommon_Failed);
    }

  for (i = 0; i < iovcnt && remaining > 0; i++)
    {
      if (remaining >= iov[i].iov_len)
        {
          remaining -= iov[i].iov_len;
          iov[i].iov_base = NULL;
          iov[i].iov_len = 0;
        }
      else
        {
          iov[i].iov_base = (char *)iov[i].iov_base + remaining;
          iov[i].iov_len -= remaining;
          remaining = 0;
        }
    }
}

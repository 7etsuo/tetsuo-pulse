/**
 * Socket-all.c - All-data I/O operations
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements functions that ensure all requested data is sent or received,
 * handling partial I/O operations transparently.
 *
 * Features:
 * - Guaranteed complete data transfer
 * - Partial progress return on blocking
 * - Exception-safe operation
 * - Memory-efficient buffering
 */

#include <assert.h>
#include <stddef.h>
#include <sys/types.h>

#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/Socket.h"

#define T Socket_T

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (Socket);

/**
 * Socket_sendall - Send all data, handling partial writes
 * @socket: Socket to send on
 * @buf: Buffer containing data to send
 * @len: Total bytes to send
 *
 * Returns: Total bytes sent, or partial progress if would block
 * Raises: Socket_Closed, Socket_Failed
 * Thread-safe: Yes
 *
 * Continues sending until all data is transmitted or an error occurs.
 */
ssize_t
Socket_sendall (T socket, const void *buf, size_t len)
{
  const char *ptr = (const char *)buf;
  volatile size_t total = 0;
  ssize_t sent;

  assert (socket);
  assert (buf);
  assert (len > 0);

  TRY while (total < len)
    {
      sent = Socket_send (socket, ptr + total, len - total);
      if (sent == 0)
        return (ssize_t)total;
      total += (size_t)sent;
    }
  EXCEPT (Socket_Closed)
    RERAISE;
  EXCEPT (Socket_Failed)
    RERAISE;
  END_TRY;

  return (ssize_t)total;
}

/**
 * Socket_recvall - Receive all data, handling partial reads
 * @socket: Socket to receive from
 * @buf: Buffer to store received data
 * @len: Total bytes to receive
 *
 * Returns: Total bytes received, or partial progress if would block
 * Raises: Socket_Closed, Socket_Failed
 * Thread-safe: Yes
 *
 * Continues receiving until all data is read or an error occurs.
 */
ssize_t
Socket_recvall (T socket, void *buf, size_t len)
{
  char *ptr = (char *)buf;
  volatile size_t total = 0;
  ssize_t received;

  assert (socket);
  assert (buf);
  assert (len > 0);

  TRY while (total < len)
    {
      received = Socket_recv (socket, ptr + total, len - total);
      if (received == 0)
        return (ssize_t)total;
      total += (size_t)received;
    }
  EXCEPT (Socket_Closed)
    RERAISE;
  EXCEPT (Socket_Failed)
    RERAISE;
  END_TRY;

  return (ssize_t)total;
}

#undef T

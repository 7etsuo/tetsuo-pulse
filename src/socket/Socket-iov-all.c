/**
 * Socket-iov-all.c - Scatter/gather I/O with guaranteed completion
 *
 * Functions that ensure all data is transferred, handling partial operations
 * and blocking until completion.
 */

#include <assert.h>
#include <sys/uio.h>

#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/Socket.h"
#include "core/SocketError.h"

#define T Socket_T

/* Thread-local exception for detailed error messages */
/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketIO_All);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketIO_All, e)

ssize_t
Socket_sendvall (T socket, const struct iovec *volatile iov, volatile int iovcnt)
{
  volatile size_t total_sent = 0;
  ssize_t sent;
  int i;

  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

  /* Calculate total length */
  volatile size_t total_len = 0;
  for (i = 0; i < iovcnt; i++)
    {
      total_len += iov[i].iov_len;
    }

  TRY while (total_sent < total_len)
  {
    sent = Socket_sendv (socket, iov, iovcnt);
    if (sent == 0)
      {
        /* Would block (EAGAIN/EWOULDBLOCK) - return partial progress */
        return (ssize_t)total_sent;
      }
    total_sent += (size_t)sent;

    /* Adjust iovec array for partial send */
    for (i = 0; i < iovcnt && (size_t)sent > 0; i++)
      {
        if ((size_t)sent >= iov[i].iov_len)
          {
            sent -= (ssize_t)iov[i].iov_len;
          }
        else
          {
            /* Partial buffer sent - adjust iov */
            struct iovec adjusted_iov[IOV_MAX];
            volatile int adjusted_cnt = iovcnt - i;

            /* Copy remaining buffers */
            for (int j = 0; j < adjusted_cnt; j++)
              {
                adjusted_iov[j] = iov[i + j];
              }

            /* Adjust first buffer */
            adjusted_iov[0].iov_base = (char *)adjusted_iov[0].iov_base + sent;
            adjusted_iov[0].iov_len -= sent;

            iov = adjusted_iov;
            iovcnt = adjusted_cnt;
            break;
          }
      }
  }
  EXCEPT (Socket_Closed)
  RERAISE;
  EXCEPT (Socket_Failed)
  RERAISE;
  END_TRY;

  return (ssize_t)total_sent;
}

ssize_t
Socket_recvvall (T socket, struct iovec *volatile iov, volatile int iovcnt)
{
  volatile size_t total_received = 0;
  ssize_t received;
  int i;

  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

  /* Calculate total length */
  volatile size_t total_len = 0;
  for (i = 0; i < iovcnt; i++)
    {
      total_len += iov[i].iov_len;
    }

  TRY while (total_received < total_len)
  {
    received = Socket_recvv (socket, iov, iovcnt);
    if (received == 0)
      {
        /* Would block (EAGAIN/EWOULDBLOCK) - return partial progress */
        return (ssize_t)total_received;
      }
    total_received += (size_t)received;

    /* Adjust iovec array for partial receive */
    for (i = 0; i < iovcnt && (size_t)received > 0; i++)
      {
        if ((size_t)received >= iov[i].iov_len)
          {
            received -= (ssize_t)iov[i].iov_len;
          }
        else
          {
            /* Partial buffer received - adjust iov */
            struct iovec adjusted_iov[IOV_MAX];
            volatile int adjusted_cnt = iovcnt - i;

            /* Copy remaining buffers */
            for (int j = 0; j < adjusted_cnt; j++)
              {
                adjusted_iov[j] = iov[i + j];
              }

            /* Adjust first buffer */
            adjusted_iov[0].iov_base = (char *)adjusted_iov[0].iov_base + received;
            adjusted_iov[0].iov_len -= received;

            iov = adjusted_iov;
            iovcnt = adjusted_cnt;
            break;
          }
      }
  }
  EXCEPT (Socket_Closed)
  RERAISE;
  EXCEPT (Socket_Failed)
  RERAISE;
  END_TRY;

  return (ssize_t)total_received;
}

#undef T

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTPClient-io.c
 * @brief Socket I/O wrapper functions for HTTP client
 *
 * Provides exception-safe socket send/receive operations with:
 * - Async I/O support (io_uring) when available
 * - Fallback to synchronous Socket_send/Socket_recv
 * - Connection state tracking (closed flag)
 */

#include <errno.h>
#include <string.h>

#include "core/Except.h"
#include "http/SocketHTTPClient-private.h"
#include "socket/Socket.h"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTPClient);

ssize_t
httpclient_io_safe_send (SocketHTTPClient_T client,
                         HTTPPoolEntry *conn,
                         const void *data,
                         size_t len,
                         const char *op_desc)
{
  ssize_t sent;

  /* Use async I/O if available */
  if (client != NULL && client->async_available)
    {
      sent = httpclient_io_send (client, conn->proto.h1.socket, data, len);
      if (sent < 0)
        {
          conn->closed = 1;
          HTTPCLIENT_ERROR_FMT ("Failed to %s: %s",
                                op_desc ? op_desc : "send data",
                                Socket_safe_strerror (errno));
        }
      return sent;
    }

  /* Fallback to synchronous I/O */
  volatile ssize_t vsent = 0;

  TRY
  {
    vsent = Socket_send (conn->proto.h1.socket, data, len);
  }
  EXCEPT (Socket_Closed)
  {
    conn->closed = 1;
    HTTPCLIENT_ERROR_FMT ("Connection closed while %s",
                          op_desc ? op_desc : "sending data");
    return -1;
  }
  EXCEPT (Socket_Failed)
  {
    HTTPCLIENT_ERROR_FMT ("Failed to %s: %s",
                          op_desc ? op_desc : "send data",
                          Socket_safe_strerror (Socket_geterrno ()));
    return -1;
  }
  END_TRY;

  return vsent;
}

int
httpclient_io_safe_recv (SocketHTTPClient_T client,
                         HTTPPoolEntry *conn,
                         char *buf,
                         size_t size,
                         ssize_t *n)
{
  /* Use async I/O if available */
  if (client != NULL && client->async_available)
    {
      *n = httpclient_io_recv (client, conn->proto.h1.socket, buf, size);
      if (*n <= 0)
        {
          conn->closed = 1;
          return -1;
        }
      return 0;
    }

  /* Fallback to synchronous I/O */
  volatile int closed = 0;

  TRY
  {
    *n = Socket_recv (conn->proto.h1.socket, buf, size);
  }
  EXCEPT (Socket_Closed)
  {
    closed = 1;
    *n = 0;
  }
  END_TRY;

  if (closed || *n <= 0)
    {
      conn->closed = 1;
      return -1;
    }

  return 0;
}

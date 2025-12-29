/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketWS-transport.c - WebSocket Transport Abstraction Layer
 *
 * Implements pluggable transport backends for WebSocket I/O:
 * - TCP/TLS socket transport (RFC 6455)
 * - HTTP/2 stream transport (RFC 8441)
 *
 * This abstraction enables the same WebSocket framing logic to work
 * over different underlying transports without code duplication.
 *
 * Thread Safety:
 * - Transport instances are NOT thread-safe
 * - Each transport should be used from a single thread
 *
 * Logging Policy:
 * This module uses differentiated logging levels based on error severity
 * and operational context:
 *
 * - DEBUG level: Transport-layer errors (network timeouts, connection
 *   closed, socket I/O failures). These are expected in normal production
 *   operation and don't indicate bugs or security issues.
 *
 * - ERROR level: Protocol violations (flow control errors, framing errors)
 *   and resource allocation failures. These indicate bugs, attacks, or
 *   system resource exhaustion.
 *
 * This distinction prevents production logs from being flooded with
 * expected operational errors while ensuring protocol-level issues are
 * visible at the ERROR level for alerting and debugging.
 */

#include "socket/SocketWS-transport.h"

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTP2.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"

#include <assert.h>
#include <errno.h>
#include <string.h>

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketWS-transport"

#include "core/SocketUtil.h"

static ssize_t
socket_transport_send (void *ctx, const void *data, size_t len)
{
  Socket_T socket = (Socket_T)ctx;
  volatile ssize_t sent = 0;

  assert (socket != NULL);
  assert (data != NULL || len == 0);

  TRY
  {
    sent = Socket_send (socket, data, len);
  }
  EXCEPT (Socket_Failed)
  {
    /* Transport-layer error - expected in production (network issues) */
    SOCKET_LOG_DEBUG_MSG ("Socket send failed: %s", Socket_GetLastError ());
    errno = EIO;
    return -1;
  }
  EXCEPT (Socket_Closed)
  {
    /* Transport-layer error - expected in production (peer disconnect) */
    SOCKET_LOG_DEBUG_MSG ("Socket closed during send");
    errno = EPIPE;
    return -1;
  }
  END_TRY;

  return sent;
}

static ssize_t
socket_transport_recv (void *ctx, void *buf, size_t len)
{
  Socket_T socket = (Socket_T)ctx;
  volatile ssize_t received = 0;

  assert (socket != NULL);
  assert (buf != NULL || len == 0);

  TRY
  {
    received = Socket_recv (socket, buf, len);
  }
  EXCEPT (Socket_Failed)
  {
    /* Transport-layer error - expected in production (network issues) */
    SOCKET_LOG_DEBUG_MSG ("Socket recv failed: %s", Socket_GetLastError ());
    errno = EIO;
    return -1;
  }
  EXCEPT (Socket_Closed)
  {
    /* Transport-layer error - expected in production (peer disconnect) */
    SOCKET_LOG_DEBUG_MSG ("Socket closed during recv");
    return 0; /* EOF */
  }
  END_TRY;

  return received;
}

static int
socket_transport_close (void *ctx, int orderly)
{
  Socket_T socket = (Socket_T)ctx;

  assert (socket != NULL);

  if (orderly)
    {
      /* Graceful shutdown - send TCP FIN */
      TRY
      {
        Socket_shutdown (socket, SHUT_WR);
      }
      EXCEPT (Socket_Failed)
      {
        /* Transport-layer error - expected in production (already closed) */
        SOCKET_LOG_DEBUG_MSG ("Socket shutdown failed: %s",
                              Socket_GetLastError ());
        /* Continue to close anyway */
      }
      END_TRY;
    }

  /* Socket will be closed when transport is freed or by owner */
  return 0;
}

static int
socket_transport_get_fd (void *ctx)
{
  Socket_T socket = (Socket_T)ctx;

  assert (socket != NULL);

  return Socket_fd (socket);
}

static void
socket_transport_free (void *ctx)
{
  /* Socket lifecycle is managed externally (by SocketWS or caller).
   * We don't close it here to avoid double-free issues. */
  (void)ctx;
}

/** Socket transport operations vtable */
static const SocketWS_TransportOps socket_ops = {
  .send = socket_transport_send,
  .recv = socket_transport_recv,
  .close = socket_transport_close,
  .get_fd = socket_transport_get_fd,
  .free = socket_transport_free,
};

static ssize_t
h2stream_transport_send (void *ctx, const void *data, size_t len)
{
  SocketHTTP2_Stream_T stream = (SocketHTTP2_Stream_T)ctx;
  SocketHTTP2_Conn_T conn;
  SocketHTTP2_FrameHeader header;
  int32_t available;
  size_t send_len;

  assert (stream != NULL);
  assert (data != NULL || len == 0);

  if (len == 0)
    return 0;

  conn = stream->conn;
  assert (conn != NULL);

  /* Check stream state - must be open or half-closed remote */
  if (stream->state != HTTP2_STREAM_STATE_OPEN
      && stream->state != HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE)
    {
      SOCKET_LOG_DEBUG_MSG ("Cannot send on stream %u in state %d", stream->id,
                            stream->state);
      errno = EPIPE;
      return -1;
    }

  /* Check if we've already sent END_STREAM */
  if (stream->end_stream_sent)
    {
      SOCKET_LOG_DEBUG_MSG ("Cannot send after END_STREAM on stream %u",
                            stream->id);
      errno = EPIPE;
      return -1;
    }

  /* Check flow control window */
  available = http2_flow_available_send (conn, stream);
  if (available <= 0)
    {
      /* Flow control blocked - would need to wait for WINDOW_UPDATE */
      SOCKET_LOG_DEBUG_MSG (
          "Stream %u send blocked by flow control (available=%d)", stream->id,
          available);
      errno = EAGAIN;
      return -1;
    }

  /* Send up to available window and max frame size */
  send_len = len;
  if (send_len > (size_t)available)
    send_len = (size_t)available;
  if (send_len > conn->peer_settings[SETTINGS_IDX_MAX_FRAME_SIZE])
    send_len = conn->peer_settings[SETTINGS_IDX_MAX_FRAME_SIZE];

  /* Consume flow control window before sending */
  if (http2_flow_consume_send (conn, stream, send_len) != 0)
    {
      /* Protocol violation - indicates bug in flow control logic */
      SOCKET_LOG_ERROR_MSG ("Failed to consume flow control window");
      errno = ENOSPC;
      return -1;
    }

  /* Build and send DATA frame - no END_STREAM yet, caller handles close */
  memset (&header, 0, sizeof (header));
  header.length = (uint32_t)send_len;
  header.type = 0x0; /* DATA frame type */
  header.flags = 0;  /* No END_STREAM for now */
  header.stream_id = stream->id;

  if (http2_frame_send (conn, &header, data, send_len) != 0)
    {
      /* Protocol error - failed to queue frame in send buffer */
      SOCKET_LOG_ERROR_MSG ("Failed to queue DATA frame");
      errno = EIO;
      return -1;
    }

  SOCKET_LOG_DEBUG_MSG ("Queued %zu bytes as DATA on stream %u", send_len,
                        stream->id);

  return (ssize_t)send_len;
}

static ssize_t
h2stream_transport_recv (void *ctx, void *buf, size_t len)
{
  SocketHTTP2_Stream_T stream = (SocketHTTP2_Stream_T)ctx;
  size_t available;
  size_t read_len;

  assert (stream != NULL);
  assert (buf != NULL || len == 0);

  if (len == 0)
    return 0;

  /* Check if stream receive buffer has data */
  available = SocketBuf_available (stream->recv_buf);

  if (available == 0)
    {
      /* No data available */
      if (stream->end_stream_received)
        {
          /* EOF - peer sent END_STREAM */
          return 0;
        }
      /* Would block - no data yet, not EOF */
      errno = EAGAIN;
      return -1;
    }

  /* Read from recv buffer */
  read_len = (len < available) ? len : available;

  if ((size_t)SocketBuf_read (stream->recv_buf, buf, read_len) != read_len)
    {
      /* Protocol error - buffer read failed despite available data */
      SOCKET_LOG_ERROR_MSG ("Failed to read from stream recv buffer");
      errno = EIO;
      return -1;
    }

  SOCKET_LOG_DEBUG_MSG ("Read %zu bytes from stream %u recv buffer", read_len,
                        stream->id);

  /* Send WINDOW_UPDATE to replenish flow control window */
  if (http2_flow_update_recv (stream->conn, stream, (uint32_t)read_len) != 0)
    {
      SOCKET_LOG_DEBUG_MSG ("Failed to send WINDOW_UPDATE for stream %u",
                            stream->id);
      /* Non-fatal - continue */
    }

  return (ssize_t)read_len;
}

static int
h2stream_transport_close (void *ctx, int orderly)
{
  SocketHTTP2_Stream_T stream = (SocketHTTP2_Stream_T)ctx;
  SocketHTTP2_Conn_T conn;
  SocketHTTP2_FrameHeader header;

  assert (stream != NULL);

  conn = stream->conn;
  assert (conn != NULL);

  if (orderly)
    {
      /* Graceful close: send empty DATA frame with END_STREAM flag */
      if (!stream->end_stream_sent
          && (stream->state == HTTP2_STREAM_STATE_OPEN
              || stream->state == HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE))
        {
          memset (&header, 0, sizeof (header));
          header.length = 0;
          header.type = 0x0;            /* DATA frame type */
          header.flags = 0x1;           /* END_STREAM flag */
          header.stream_id = stream->id;

          if (http2_frame_send (conn, &header, NULL, 0) == 0)
            {
              stream->end_stream_sent = 1;
              SOCKET_LOG_DEBUG_MSG ("Sent END_STREAM on stream %u", stream->id);
            }
          else
            {
              SOCKET_LOG_WARN_MSG ("Failed to send END_STREAM on stream %u",
                                   stream->id);
            }
        }
    }
  else
    {
      /* Abnormal close: send RST_STREAM with CANCEL (0x8) */
      http2_send_stream_error (conn, stream->id, HTTP2_CANCEL);
      SOCKET_LOG_DEBUG_MSG ("Sent RST_STREAM CANCEL on stream %u", stream->id);
    }

  return 0;
}

static int
h2stream_transport_get_fd (void *ctx)
{
  (void)ctx;
  /* HTTP/2 streams don't have individual FDs.
   * Callers should poll the underlying connection socket. */
  return -1;
}

static void
h2stream_transport_free (void *ctx)
{
  /* Stream lifecycle is managed by the HTTP/2 connection.
   * We don't destroy it here to avoid issues with ongoing operations. */
  (void)ctx;
}

/** HTTP/2 stream transport operations vtable */
static const SocketWS_TransportOps h2stream_ops = {
  .send = h2stream_transport_send,
  .recv = h2stream_transport_recv,
  .close = h2stream_transport_close,
  .get_fd = h2stream_transport_get_fd,
  .free = h2stream_transport_free,
};

SocketWS_Transport_T
SocketWS_Transport_socket (Arena_T arena, Socket_T socket, int is_client)
{
  SocketWS_Transport_T transport;

  assert (arena != NULL);
  assert (socket != NULL);

  transport = Arena_alloc (arena, sizeof (*transport), __FILE__, __LINE__);
  if (transport == NULL)
    {
      /* Resource exhaustion - system out of memory */
      SOCKET_LOG_ERROR_MSG ("Failed to allocate socket transport");
      return NULL;
    }

  transport->type = SOCKETWS_TRANSPORT_SOCKET;
  transport->ops = &socket_ops;
  transport->ctx = socket;
  transport->arena = arena;
  transport->requires_masking = is_client ? 1 : 0;

  SOCKET_LOG_DEBUG_MSG (
      "Created socket transport (fd=%d, is_client=%d, masking=%d)",
      Socket_fd (socket), is_client, transport->requires_masking);

  return transport;
}

SocketWS_Transport_T
SocketWS_Transport_h2stream (Arena_T arena, SocketHTTP2_Stream_T stream)
{
  SocketWS_Transport_T transport;

  assert (arena != NULL);
  assert (stream != NULL);

  transport = Arena_alloc (arena, sizeof (*transport), __FILE__, __LINE__);
  if (transport == NULL)
    {
      /* Resource exhaustion - system out of memory */
      SOCKET_LOG_ERROR_MSG ("Failed to allocate H2 stream transport");
      return NULL;
    }

  transport->type = SOCKETWS_TRANSPORT_H2STREAM;
  transport->ops = &h2stream_ops;
  transport->ctx = stream;
  transport->arena = arena;
  transport->requires_masking = 0; /* RFC 8441: No masking for HTTP/2 */

  SOCKET_LOG_DEBUG_MSG (
      "Created H2 stream transport (stream_id=%u, masking=0)", stream->id);

  return transport;
}

SocketWS_TransportType
SocketWS_Transport_type (SocketWS_Transport_T transport)
{
  assert (transport != NULL);
  return transport->type;
}

int
SocketWS_Transport_requires_masking (SocketWS_Transport_T transport)
{
  assert (transport != NULL);
  return transport->requires_masking;
}

ssize_t
SocketWS_Transport_send (SocketWS_Transport_T transport, const void *data,
                         size_t len)
{
  assert (transport != NULL);
  assert (transport->ops != NULL);
  assert (transport->ops->send != NULL);

  return transport->ops->send (transport->ctx, data, len);
}

ssize_t
SocketWS_Transport_recv (SocketWS_Transport_T transport, void *buf, size_t len)
{
  assert (transport != NULL);
  assert (transport->ops != NULL);
  assert (transport->ops->recv != NULL);

  return transport->ops->recv (transport->ctx, buf, len);
}

int
SocketWS_Transport_close (SocketWS_Transport_T transport, int orderly)
{
  assert (transport != NULL);
  assert (transport->ops != NULL);
  assert (transport->ops->close != NULL);

  return transport->ops->close (transport->ctx, orderly);
}

int
SocketWS_Transport_get_fd (SocketWS_Transport_T transport)
{
  assert (transport != NULL);
  assert (transport->ops != NULL);
  assert (transport->ops->get_fd != NULL);

  return transport->ops->get_fd (transport->ctx);
}

void
SocketWS_Transport_free (SocketWS_Transport_T *transport)
{
  assert (transport != NULL);

  if (*transport == NULL)
    return;

  /* Call backend-specific free */
  if ((*transport)->ops && (*transport)->ops->free)
    (*transport)->ops->free ((*transport)->ctx);

  /* Transport struct itself is arena-allocated, don't free it */
  *transport = NULL;

  SOCKET_LOG_DEBUG_MSG ("Freed transport resources");
}

Socket_T
SocketWS_Transport_get_socket (SocketWS_Transport_T transport)
{
  assert (transport != NULL);

  if (transport->type != SOCKETWS_TRANSPORT_SOCKET)
    return NULL;

  return (Socket_T)transport->ctx;
}

SocketHTTP2_Stream_T
SocketWS_Transport_get_h2stream (SocketWS_Transport_T transport)
{
  assert (transport != NULL);

  if (transport->type != SOCKETWS_TRANSPORT_H2STREAM)
    return NULL;

  return (SocketHTTP2_Stream_T)transport->ctx;
}

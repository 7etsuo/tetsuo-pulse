/**
 * SocketHTTP2-flow.c - HTTP/2 Flow Control
 *
 * Part of the Socket Library
 *
 * Implements:
 * - Connection-level flow control (RFC 9113 Section 5.2)
 * - Stream-level flow control
 * - Window size management
 * - Overflow-safe arithmetic
 */

#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTP2.h"

#include "core/SocketUtil.h"

#include <assert.h>
#include <stdint.h>

/* ============================================================================
 * Module Exception Setup
 * ============================================================================ */

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTP2"

/* ============================================================================
 * Constants
 * ============================================================================ */

/* Maximum window size (2^31 - 1) per RFC 9113 */
#define HTTP2_MAX_WINDOW_SIZE 0x7FFFFFFF

/* ============================================================================
 * Flow Control - Receive Window
 * ============================================================================ */

int
http2_flow_consume_recv (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                         size_t bytes)
{
  assert (conn);

  /* Check connection-level window */
  if ((int32_t)bytes > conn->recv_window)
    {
      return -1; /* Flow control error */
    }

  conn->recv_window -= (int32_t)bytes;

  /* Check stream-level window */
  if (stream)
    {
      if ((int32_t)bytes > stream->recv_window)
        {
          return -1; /* Flow control error */
        }
      stream->recv_window -= (int32_t)bytes;
    }

  return 0;
}

int
http2_flow_update_recv (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                        uint32_t increment)
{
  assert (conn);

  if (stream)
    {
      /* Check for overflow */
      if ((int64_t)stream->recv_window + (int64_t)increment > HTTP2_MAX_WINDOW_SIZE)
        {
          return -1;
        }
      stream->recv_window += (int32_t)increment;
    }
  else
    {
      /* Connection-level update */
      if ((int64_t)conn->recv_window + (int64_t)increment > HTTP2_MAX_WINDOW_SIZE)
        {
          return -1;
        }
      conn->recv_window += (int32_t)increment;
    }

  return 0;
}

/* ============================================================================
 * Flow Control - Send Window
 * ============================================================================ */

int
http2_flow_consume_send (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                         size_t bytes)
{
  assert (conn);

  /* Consume connection-level window */
  conn->send_window -= (int32_t)bytes;

  /* Consume stream-level window */
  if (stream)
    {
      stream->send_window -= (int32_t)bytes;
    }

  return 0;
}

int
http2_flow_update_send (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                        uint32_t increment)
{
  assert (conn);

  if (stream)
    {
      /* Check for overflow */
      if ((int64_t)stream->send_window + (int64_t)increment > HTTP2_MAX_WINDOW_SIZE)
        {
          return -1;
        }
      stream->send_window += (int32_t)increment;
    }
  else
    {
      /* Connection-level update */
      if ((int64_t)conn->send_window + (int64_t)increment > HTTP2_MAX_WINDOW_SIZE)
        {
          return -1;
        }
      conn->send_window += (int32_t)increment;
    }

  return 0;
}

/* ============================================================================
 * Flow Control - Available Window
 * ============================================================================ */

int32_t
http2_flow_available_send (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream)
{
  int32_t available;

  assert (conn);

  available = conn->send_window;

  /* If stream specified, use minimum of connection and stream windows */
  if (stream)
    {
      if (stream->send_window < available)
        {
          available = stream->send_window;
        }
    }

  /* Return 0 if window is negative or zero */
  if (available <= 0)
    {
      return 0;
    }

  return available;
}


/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketHTTP2-flow.c - HTTP/2 Flow Control (RFC 9113 Section 5.2) */

#include <assert.h>
#include <stdint.h>

#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTP2.h"

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTP2-flow"

/* Per RFC 9113 Section 5.2.1, overflow is a flow control error */
static int
flow_update_window (int32_t *window, uint32_t increment)
{
  if (increment == 0)
    {
      SOCKET_LOG_WARN_MSG ("Invalid zero window increment");
      return -1;
    }

  if (*window < 0)
    {
      SOCKET_LOG_WARN_MSG ("Negative flow window: %d", *window);
      return -1;
    }

  size_t new_value;
  if (!SocketSecurity_check_add ((size_t)*window, (size_t)increment,
                                 &new_value)
      || new_value > (size_t)SOCKETHTTP2_MAX_WINDOW_SIZE)
    {
      SOCKET_LOG_WARN_MSG (
          "Flow window overflow: current %u + %u > max %u",
          (unsigned)*window, increment, SOCKETHTTP2_MAX_WINDOW_SIZE);
      return -1;
    }

  *window = (int32_t)new_value;
  return 0;
}

static inline int
http2_flow_validate (const SocketHTTP2_Conn_T conn,
                     const SocketHTTP2_Stream_T stream)
{
  assert (conn);

  if (stream && stream->conn != conn)
    {
      SOCKET_LOG_ERROR_MSG ("Invalid stream %u for conn - mismatch",
                            stream->id);
      return -1;
    }

  return 0;
}

static int
http2_flow_consume_level (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                          int is_recv, size_t bytes)
{
  if (http2_flow_validate (conn, stream) < 0)
    return -1;

  int32_t *cwindow = is_recv ? &conn->recv_window : &conn->send_window;
  int32_t *swindow = NULL;
  if (stream)
    swindow = is_recv ? &stream->recv_window : &stream->send_window;

  /* Check connection window */
  if (bytes > INT32_MAX)
    return -1;

  int32_t consume = (int32_t)bytes;
  if (consume > *cwindow)
    {
      SOCKET_LOG_WARN_MSG (
          "Flow control violation: consume %d > connection window %d",
          (int)consume, (int)*cwindow);
      return -1;
    }

  /* Check stream window if applicable */
  if (swindow && consume > *swindow)
    {
      SOCKET_LOG_WARN_MSG (
          "Flow control violation: consume %d > stream window %d",
          (int)consume, (int)*swindow);
      return -1;
    }

  /* Consume both windows atomically */
  *cwindow -= consume;
  if (swindow)
    *swindow -= consume;

  return 0;
}

static int
http2_flow_update_level (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                         int is_recv, uint32_t increment)
{
  if (http2_flow_validate (conn, stream) < 0)
    return -1;

  int32_t *window;
  if (stream)
    window = is_recv ? &stream->recv_window : &stream->send_window;
  else
    window = is_recv ? &conn->recv_window : &conn->send_window;

  return flow_update_window (window, increment);
}

int
http2_flow_consume_recv (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                         size_t bytes)
{
  return http2_flow_consume_level (conn, stream, 1, bytes);
}

int
http2_flow_update_recv (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                        uint32_t increment)
{
  return http2_flow_update_level (conn, stream, 1, increment);
}

int
http2_flow_consume_send (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                         size_t bytes)
{
  return http2_flow_consume_level (conn, stream, 0, bytes);
}

int
http2_flow_update_send (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                        uint32_t increment)
{
  return http2_flow_update_level (conn, stream, 0, increment);
}

int32_t
http2_flow_available_send (const SocketHTTP2_Conn_T conn,
                           const SocketHTTP2_Stream_T stream)
{
  if (http2_flow_validate (conn, stream) < 0)
    return 0;

  int32_t available = conn->send_window;

  if (stream && stream->send_window < available)
    available = stream->send_window;

  return (available > 0) ? available : 0;
}

/* Per RFC 9113 Section 6.5.2: SETTINGS_INITIAL_WINDOW_SIZE changes */
int
http2_flow_adjust_window (int32_t *window, int32_t delta)
{
  if (delta == 0)
    return 0;

  int64_t new_value = (int64_t)*window + (int64_t)delta;

  if (new_value < 0)
    {
      SOCKET_LOG_WARN_MSG (
          "Flow window adjustment would make negative: current %d + %d",
          (int)*window, (int)delta);
      return -1;
    }

  if (new_value > SOCKETHTTP2_MAX_WINDOW_SIZE)
    {
      SOCKET_LOG_WARN_MSG (
          "Flow window adjustment overflow: current %d + %d > max %u",
          (int)*window, (int)delta, (unsigned)SOCKETHTTP2_MAX_WINDOW_SIZE);
      return -1;
    }

  *window = (int32_t)new_value;
  return 0;
}

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketHTTP2-flow.c - HTTP/2 Flow Control
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements RFC 9113 Section 5.2 flow control:
 * - Connection-level flow control windows
 * - Stream-level flow control windows
 * - Window size management with overflow protection
 * - Overflow-safe 64-bit arithmetic for window updates
 *
 * Flow control in HTTP/2 operates at two levels:
 * 1. Connection level - shared across all streams
 * 2. Stream level - per-stream windows
 *
 * Both windows must have capacity for data transmission.
 * The effective window is the minimum of both levels.
 */

#include <assert.h>
#include <stdint.h>

#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTP2.h"

/* ============================================================================
 * Logging Component
 * ============================================================================
 */

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTP2-flow"

/* ============================================================================
 * Static Helper Functions
 * ============================================================================
 */

/**
 * flow_update_window - Add increment to a flow control window
 * @window: Pointer to window value (int32_t)
 * @increment: Amount to add (from WINDOW_UPDATE frame)
 *
 * Returns: 0 on success, -1 if would overflow SOCKETHTTP2_MAX_WINDOW_SIZE
 * Thread-safe: No - modifies window directly
 *
 * Uses 64-bit arithmetic to detect overflow before applying update.
 * Logs warning on overflow. Per RFC 9113 Section 5.2.1, overflow is a
 * flow control error.
 */
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

/* ============================================================================
 * Validation Helper
 * ============================================================================
 */

/**
 * http2_flow_validate - Validate stream belongs to connection
 * @conn: HTTP/2 connection (required, const compatible)
 * @stream: Stream to validate (may be NULL, const compatible)
 *
 * Returns: 0 if valid, -1 if mismatch
 * Thread-safe: Yes - read-only
 *
 * Common validation extracted from all flow functions to eliminate
 * duplication. Logs error on stream-connection mismatch.
 */
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

/* ============================================================================
 * Generic Flow Level Helpers
 * ============================================================================
 */

/**
 * http2_flow_consume_level - Consume windows at connection and stream level
 * @conn: HTTP/2 connection
 * @stream: Stream (NULL for connection-only)
 * @is_recv: 1 for recv_window, 0 for send_window
 * @bytes: Bytes to consume
 *
 * Returns: 0 on success, -1 if insufficient capacity
 * Thread-safe: No - modifies windows; caller must synchronize
 *
 * Internal helper consolidating recv/send consumption logic.
 * Validates params and consumes both levels if stream provided.
 */
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

/**
 * http2_flow_update_level - Update window at connection or stream level
 * @conn: HTTP/2 connection
 * @stream: Stream (NULL for connection-level)
 * @is_recv: 1 for recv_window, 0 for send_window
 * @increment: Window increment
 *
 * Returns: 0 on success, -1 on overflow
 * Thread-safe: No - modifies windows; caller must synchronize
 *
 * Internal helper consolidating recv/send update logic.
 * Updates either stream or connection window based on param.
 */
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

/* ============================================================================
 * Flow Control - Receive Window (Inbound DATA)
 * ============================================================================
 */

/**
 * http2_flow_consume_recv - Consume receive window for inbound DATA
 * @conn: HTTP/2 connection (required)
 * @stream: Stream receiving data (NULL for connection-only)
 * @bytes: Number of bytes received
 *
 * Returns: 0 on success, -1 on flow control violation
 * Thread-safe: No - modifies shared connection/stream windows; caller must
 * synchronize access
 *
 * Called when DATA frame is received. Both connection and stream
 * windows (if stream provided) must have capacity. On violation,
 * logs warning and caller should send GOAWAY with FLOW_CONTROL_ERROR.
 */
int
http2_flow_consume_recv (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                         size_t bytes)
{
  return http2_flow_consume_level (conn, stream, 1, bytes);
}

/**
 * http2_flow_update_recv - Update receive window when sending WINDOW_UPDATE
 * @conn: HTTP/2 connection (required)
 * @stream: Stream to update (NULL for connection-level)
 * @increment: Window increment to apply to our receive window
 *
 * Returns: 0 on success, -1 if update would cause overflow
 * Thread-safe: No - modifies shared connection/stream windows; caller must
 * synchronize access
 *
 * Called when sending WINDOW_UPDATE frame to peer (increasing our capacity to
 * receive). Overflow beyond SOCKETHTTP2_MAX_WINDOW_SIZE (2^31-1) is a flow
 * control error per RFC 9113 Section 5.2.1. Logs warning on error.
 */
int
http2_flow_update_recv (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                        uint32_t increment)
{
  return http2_flow_update_level (conn, stream, 1, increment);
}

/* ============================================================================
 * Flow Control - Send Window (Outbound DATA)
 * ============================================================================
 */

/**
 * http2_flow_consume_send - Consume send window for outbound DATA
 * @conn: HTTP/2 connection (required)
 * @stream: Stream sending data (NULL for connection-only)
 * @bytes: Number of bytes to send
 *
 * Returns: 0 on success, -1 if insufficient window
 * Thread-safe: No - modifies shared connection/stream windows; caller must
 * synchronize access
 *
 * Called before sending DATA frame. Both connection and stream
 * windows (if stream provided) must have capacity. On violation,
 * logs warning and caller should buffer data until WINDOW_UPDATE received.
 */
int
http2_flow_consume_send (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                         size_t bytes)
{
  return http2_flow_consume_level (conn, stream, 0, bytes);
}

/**
 * http2_flow_update_send - Update send window from received WINDOW_UPDATE
 * @conn: HTTP/2 connection (required)
 * @stream: Stream to update (NULL for connection-level)
 * @increment: Window increment from peer's WINDOW_UPDATE frame
 *
 * Returns: 0 on success, -1 if update would cause overflow
 * Thread-safe: No - modifies shared connection/stream windows; caller must
 * synchronize access
 *
 * Called when WINDOW_UPDATE frame received from peer (increasing our capacity
 * to send). Overflow beyond SOCKETHTTP2_MAX_WINDOW_SIZE (2^31-1) is a flow
 * control error per RFC 9113 Section 5.2.1. Logs warning on error.
 */
int
http2_flow_update_send (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                        uint32_t increment)
{
  return http2_flow_update_level (conn, stream, 0, increment);
}

/* ============================================================================
 * Flow Control - Window Query
 * ============================================================================
 */

/**
 * http2_flow_available_send - Get available send window
 * @conn: HTTP/2 connection (required)
 * @stream: Stream to check (NULL for connection-only)
 *
 * Returns: Available bytes (minimum of connection and stream windows,
 *          clamped to >=0), or 0 if windows exhausted/negative
 * Thread-safe: Yes - read-only access to windows
 *
 * The effective send window is the minimum of connection-level send window
 * and stream-level send window (if provided). Returns 0 if either is <=0.
 *
 * Use before sending DATA to determine safe payload size.
 */
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

/* ============================================================================
 * Flow Control - Window Adjustment (for SETTINGS changes)
 * ============================================================================
 */

/**
 * http2_flow_adjust_window - Adjust window by signed delta (SETTINGS initial
 * window change)
 * @window: Pointer to window value (int32_t)
 * @delta: Signed adjustment (+increase, -decrease)
 *
 * Returns: 0 on success, -1 if adjustment invalid (negative window or
 * overflow)
 * Thread-safe: No - modifies window directly
 *
 * Per RFC 9113 Section 6.5.2: Adjusts window for SETTINGS_INITIAL_WINDOW_SIZE
 * change.
 * - Negative window after adjustment -> FLOW_CONTROL_ERROR
 * - Window > SOCKETHTTP2_MAX_WINDOW_SIZE -> error (defense against invalid
 * settings)
 * - Logs warning on error.
 * - Handles delta == 0 as no-op.
 */
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

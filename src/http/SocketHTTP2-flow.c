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

#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTP2.h"

#include "core/SocketUtil.h"

#include <assert.h>
#include <stdint.h>

/* ============================================================================
 * Logging Component
 * ============================================================================ */

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTP2-flow"

/* ============================================================================
 * Constants (RFC 9113 Section 5.2)
 * ============================================================================ */

/* Maximum window size (2^31 - 1) per RFC 9113 Section 5.2.1 */
#define HTTP2_MAX_WINDOW_SIZE 0x7FFFFFFF

/* ============================================================================
 * Static Helper Functions
 * ============================================================================ */

/**
 * flow_consume_window - Consume bytes from a flow control window
 * @window: Pointer to window value (int32_t)
 * @bytes: Number of bytes to consume
 *
 * Returns: 0 on success, -1 if window would go negative or bytes > INT32_MAX
 * Thread-safe: No - modifies window directly
 *
 * Checks if window has capacity and deducts bytes atomically.
 * Logs warning on violation. Window may become negative if peer violates
 * flow control, but this function prevents it.
 */
static int
flow_consume_window (int32_t *window, size_t bytes)
{
  if (bytes > INT32_MAX)
    return -1;

  int32_t consume = (int32_t)bytes;

  if (consume > *window)
    {
      SOCKET_LOG_WARN_MSG("Flow control violation: consume %ld > window %ld", (long)consume, (long)*window);
      return -1;
    }

  *window -= consume;
  return 0;
}

/**
 * flow_update_window - Add increment to a flow control window
 * @window: Pointer to window value (int32_t)
 * @increment: Amount to add (from WINDOW_UPDATE frame)
 *
 * Returns: 0 on success, -1 if would overflow HTTP2_MAX_WINDOW_SIZE
 * Thread-safe: No - modifies window directly
 *
 * Uses 64-bit arithmetic to detect overflow before applying update.
 * Logs warning on overflow. Per RFC 9113 Section 5.2.1, overflow is a
 * flow control error.
 */
static int
flow_update_window (int32_t *window, uint32_t increment)
{
  int64_t new_value = (int64_t)*window + (int64_t)increment;

  if (new_value > HTTP2_MAX_WINDOW_SIZE)
    {
      SOCKET_LOG_WARN_MSG("Flow window update overflow: current %ld + %u > max %u", (long)*window, increment, HTTP2_MAX_WINDOW_SIZE);
      return -1;
    }

  *window += (int32_t)increment;
  return 0;
}

/* ============================================================================
 * Flow Control - Receive Window (Inbound DATA)
 * ============================================================================ */

/**
 * http2_flow_consume_recv - Consume receive window for inbound DATA
 * @conn: HTTP/2 connection (required)
 * @stream: Stream receiving data (NULL for connection-only)
 * @bytes: Number of bytes received
 *
 * Returns: 0 on success, -1 on flow control violation
 * Thread-safe: No - modifies shared connection/stream windows; caller must synchronize access
 *
 * Called when DATA frame is received. Both connection and stream
 * windows (if stream provided) must have capacity. On violation,
 * logs warning and caller should send GOAWAY with FLOW_CONTROL_ERROR.
 */
int
http2_flow_consume_recv (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                         size_t bytes)
{
  assert (conn);

  if (stream && stream->conn != conn)
    {
      SOCKET_LOG_ERROR_MSG("Invalid stream %u for conn - mismatch", stream->id);
      return -1;
    }

  if (flow_consume_window (&conn->recv_window, bytes) < 0)
    return -1;

  if (stream && flow_consume_window (&stream->recv_window, bytes) < 0)
    return -1;

  return 0;
}

/**
 * http2_flow_update_recv - Update receive window when sending WINDOW_UPDATE
 * @conn: HTTP/2 connection (required)
 * @stream: Stream to update (NULL for connection-level)
 * @increment: Window increment to apply to our receive window
 *
 * Returns: 0 on success, -1 if update would cause overflow
 * Thread-safe: No - modifies shared connection/stream windows; caller must synchronize access
 *
 * Called when sending WINDOW_UPDATE frame to peer (increasing our capacity to receive).
 * Overflow beyond HTTP2_MAX_WINDOW_SIZE is a flow control error per RFC 9113.
 * Logs warning on error.
 */
int
http2_flow_update_recv (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                        uint32_t increment)
{
  assert (conn);

  if (stream && stream->conn != conn)
    {
      SOCKET_LOG_ERROR_MSG("Invalid stream %u for conn - mismatch", stream->id);
      return -1;
    }

  if (stream)
    return flow_update_window (&stream->recv_window, increment);

  return flow_update_window (&conn->recv_window, increment);
}

/* ============================================================================
 * Flow Control - Send Window (Outbound DATA)
 * ============================================================================ */

/**
 * http2_flow_consume_send - Consume send window for outbound DATA
 * @conn: HTTP/2 connection (required)
 * @stream: Stream sending data (NULL for connection-only)
 * @bytes: Number of bytes to send
 *
 * Returns: 0 on success, -1 if insufficient window
 * Thread-safe: No - modifies shared connection/stream windows; caller must synchronize access
 *
 * Called before sending DATA frame. Both connection and stream
 * windows (if stream provided) must have capacity. On violation,
 * logs warning and caller should buffer data until WINDOW_UPDATE received.
 */
int
http2_flow_consume_send (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                         size_t bytes)
{
  assert (conn);

  if (stream && stream->conn != conn)
    {
      SOCKET_LOG_ERROR_MSG("Invalid stream %u for conn - mismatch", stream->id);
      return -1;
    }

  if (flow_consume_window (&conn->send_window, bytes) < 0)
    return -1;

  if (stream && flow_consume_window (&stream->send_window, bytes) < 0)
    return -1;

  return 0;
}

/**
 * http2_flow_update_send - Update send window from received WINDOW_UPDATE
 * @conn: HTTP/2 connection (required)
 * @stream: Stream to update (NULL for connection-level)
 * @increment: Window increment from peer's WINDOW_UPDATE frame
 *
 * Returns: 0 on success, -1 if update would cause overflow
 * Thread-safe: No - modifies shared connection/stream windows; caller must synchronize access
 *
 * Called when WINDOW_UPDATE frame received from peer (increasing our capacity to send).
 * Overflow beyond HTTP2_MAX_WINDOW_SIZE is a flow control error per RFC 9113.
 * Logs warning on error.
 */
int
http2_flow_update_send (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                        uint32_t increment)
{
  assert (conn);

  if (stream && stream->conn != conn)
    {
      SOCKET_LOG_ERROR_MSG("Invalid stream %u for conn - mismatch", stream->id);
      return -1;
    }

  if (stream)
    return flow_update_window (&stream->send_window, increment);

  return flow_update_window (&conn->send_window, increment);
}

/* ============================================================================
 * Flow Control - Window Query
 * ============================================================================ */

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
http2_flow_available_send (const SocketHTTP2_Conn_T conn, const SocketHTTP2_Stream_T stream)
{
  int32_t available;

  assert (conn);

  if (stream && stream->conn != conn)
    {
      SOCKET_LOG_ERROR_MSG("Invalid stream %u for conn - mismatch", stream->id);
      return 0;
    }

  available = conn->send_window;

  if (stream && stream->send_window < available)
    available = stream->send_window;

  return (available > 0) ? available : 0;
}


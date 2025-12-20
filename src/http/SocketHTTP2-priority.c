/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketHTTP2-priority.c - HTTP/2 Priority Frame Handling (Deprecated)
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * RFC 9113 Section 5.3.2 deprecates the priority signaling mechanism from
 * RFC 7540. This file provides minimal handling for backward compatibility
 * with older implementations that may still send PRIORITY frames.
 *
 * Per RFC 9113:
 *   "The PRIORITY frame is deprecated. Endpoints SHOULD NOT send PRIORITY
 *    frames. Endpoints MAY ignore PRIORITY frames."
 *
 * For modern priority signaling, see RFC 9218 (Extensible Priorities)
 * which uses HTTP header fields instead of the deprecated frame-based
 * priority scheme.
 *
 * Thread safety: Functions are thread-safe when called on different
 * connections; connections are NOT thread-safe.
 */

#include "http/SocketHTTP2-private.h"

#include "core/SocketUtil.h"

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTP2"

/* ============================================================================
 * PRIORITY Frame Processing (RFC 9113 Section 6.3 - Deprecated)
 *
 * PRIORITY frame format (5 octets):
 *   +---------------+
 *   |E|  Stream Dependency (31)                      |
 *   +---------------+
 *   | Weight (8)    |
 *   +---------------+
 *
 * Per RFC 9113, PRIORITY frames are deprecated and should be ignored.
 * This implementation follows that recommendation.
 * ============================================================================
 */

/**
 * http2_process_priority - Process deprecated PRIORITY frame (RFC 9113)
 * @conn: HTTP/2 connection context (unused, kept for dispatch API consistency)
 * @header: Frame header (stream ID used for debug logging only)
 * @payload: Frame payload (ignored per RFC 9113 deprecation)
 *
 * Returns: 0 (always succeeds since frame is ignored per specification)
 * Raises: None (validation errors raised earlier in http2_frame_validate)
 * Thread-safe: Yes (uses only thread-safe logging, no state modification)
 *
 * Per RFC 9113 Section 5.3.2, the PRIORITY frame mechanism from RFC 7540 is
 * deprecated. Endpoints SHOULD NOT send PRIORITY frames and MAY ignore them.
 * This implementation follows the recommendation to ignore with debug logging
 * for monitoring non-compliant peers that may still send these frames.
 *
 * Modern priority signaling uses RFC 9218 (Extensible Priorities) via HTTP
 * header fields (Priority header) instead of this deprecated frame-based
 * scheme.
 *
 * Prior validation in http2_frame_validate() ensures: stream_id > 0 and
 * length == 5 (fixed payload size per RFC 7540 Section 6.3).
 */
int
http2_process_priority (SocketHTTP2_Conn_T conn,
                        const SocketHTTP2_FrameHeader *header,
                        const unsigned char *payload)
{
  /* Suppress unused parameter warnings - parameters kept for API consistency */
  (void)conn;
  (void)payload;

  SOCKET_LOG_DEBUG_MSG ("Ignoring deprecated PRIORITY frame: stream=%u len=%u",
                        header->stream_id, (unsigned)header->length);

  return 0;
}

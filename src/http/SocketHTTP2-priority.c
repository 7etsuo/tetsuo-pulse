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
 * ============================================================================ */

/**
 * http2_process_priority - Process PRIORITY frame (deprecated)
 * @conn: HTTP/2 connection context (unused - kept for dispatch API consistency)
 * @header: Frame header (provides stream ID and confirms PRIORITY type)
 * @payload: Frame payload (ignored per RFC 9113)
 *
 * Returns: 0 on success (frame ignored)
 * Raises: None - any validation errors raised earlier in frame parser
 * Thread-safe: Yes - thread-safe logging; no changes to connection state
 *
 * Per RFC 9113 Section 5.3.2: PRIORITY frames deprecated - endpoints MAY ignore them.
 * Logs frame receipt for debugging non-compliant peers.
 * No parsing or state changes performed.
 *
 * Prior validation in frame parser ensures: stream ID > 0, payload len == 5.
 */
int
http2_process_priority (SocketHTTP2_Conn_T conn,
                        const SocketHTTP2_FrameHeader *header,
                        const unsigned char *payload)
{
        SOCKET_LOG_DEBUG_MSG("Ignoring deprecated HTTP/2 PRIORITY frame on stream %u (payload len=%u)",
                             header->stream_id, (unsigned)header->length);

        (void)conn; /* Unused parameter for API consistency */
        (void)payload;

        return 0;
}

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
#include "http/SocketHTTP2.h"
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
 * @payload: Frame payload (exactly 5 bytes: exclusive flag + 31-bit dependency stream ID + 8-bit weight)
 *
 * Returns: 0 on success (frame processed and ignored)
 * Raises: None - any validation errors raised earlier in frame parser
 * Thread-safe: Yes - read-only payload parsing and thread-safe logging; no changes to connection state
 *
 * Per RFC 9113 Section 5.3.2: PRIORITY frames deprecated - endpoints MUST ignore them.
 * Parses and logs payload details for observability and debugging (e.g., detect non-compliant peers).
 * No priority tree updates or state changes occur.
 *
 * Payload byte breakdown:
 * - Byte 0 bit 7: Exclusive (E) flag
 * - Byte 0 bits 0-6 + bytes 1-3: 31-bit dependency stream ID (0 = no dependency)
 * - Byte 4: Weight (1=weight 0 to 256=weight 255; 0 invalid but not checked here)
 *
 * Prior validation ensures: stream ID > 0, payload len == 5, valid frame header.
 */
int
http2_process_priority (SocketHTTP2_Conn_T conn,
                        const SocketHTTP2_FrameHeader *header,
                        const unsigned char *payload)
{
        /* Parse deprecated PRIORITY payload for logging (RFC 9113 ignores) */
        unsigned dep_stream = ((unsigned)(payload[0] & 0x7F) << 24) |
                              ((unsigned)payload[1] << 16) |
                              ((unsigned)payload[2] << 8) |
                              ((unsigned)payload[3]);
        unsigned weight = (unsigned)payload[4];
        int exclusive = !!(payload[0] & 0x80);

        SOCKET_LOG_DEBUG_MSG("Ignoring deprecated HTTP/2 PRIORITY frame: stream=%u dep=%u excl=%d weight=%u",
                             header->stream_id, dep_stream, exclusive, weight);

        (void)conn; /* Unused parameter for API consistency */

        return 0;
}

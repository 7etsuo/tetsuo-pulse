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
 * @conn: HTTP/2 connection
 * @header: Frame header
 * @payload: Frame payload (5 bytes: dependency + weight)
 *
 * Returns: 0 always (frame ignored per RFC 9113)
 *
 * Per RFC 9113 Section 5.3.2, PRIORITY frames are deprecated.
 * This function ignores the frame contents and returns success.
 *
 * The frame validation (stream ID non-zero, payload length = 5)
 * is performed in http2_frame_validate() before this function
 * is called, ensuring protocol compliance even though we ignore
 * the priority data.
 */
int
http2_process_priority (SocketHTTP2_Conn_T conn,
                        const SocketHTTP2_FrameHeader *header,
                        const unsigned char *payload)
{
        /* RFC 9113: PRIORITY frames are deprecated and should be ignored */
        (void)conn;
        (void)header;
        (void)payload;

        return 0;
}

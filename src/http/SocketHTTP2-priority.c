/**
 * SocketHTTP2-priority.c - HTTP/2 Priority Handling (Deprecated)
 *
 * Part of the Socket Library
 *
 * RFC 9113 deprecates the PRIORITY frame and priority signaling.
 * This file provides minimal handling for backward compatibility.
 *
 * Per RFC 9113 Section 5.3.2:
 * "The PRIORITY frame is deprecated. Endpoints SHOULD NOT send PRIORITY
 *  frames. Endpoints MAY ignore PRIORITY frames."
 */

#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTP2.h"

/* ============================================================================
 * Priority handling is intentionally minimal per RFC 9113
 * 
 * The priority scheme from RFC 7540 is deprecated. Modern HTTP/2
 * implementations should use Extensible Priorities (RFC 9218) if
 * priority signaling is needed.
 * ============================================================================ */

/* This file exists for completeness but contains no active code.
 * PRIORITY frame processing is handled in http2_process_priority()
 * in SocketHTTP2-connection.c, which simply ignores the frame. */


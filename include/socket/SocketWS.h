/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketWS.h
 * @ingroup websocket
 * @brief WebSocket Protocol (RFC 6455) implementation with compression
 * support.
 *
 * Complete WebSocket implementation with compression extension support.
 *
 * Features:
 * - Full RFC 6455 compliance
 * - Client and server modes
 * - Fragmented message support
 * - UTF-8 validation for text frames
 * - Automatic ping/pong keepalive
 * - permessage-deflate compression (RFC 7692)
 * - Subprotocol negotiation
 * - Non-blocking I/O support
 *
 * Module Reuse (zero code duplication):
 * - SocketCrypto: Key generation, Accept computation, masking
 * - SocketUTF8: Text frame validation (incremental)
 * - SocketHTTP1: HTTP upgrade handshake parsing
 * - SocketBuf: I/O buffering
 * - SocketTimer: Auto-ping integration
 * - Socket_get_monotonic_ms(): Timeout tracking
 *
 * Thread Safety:
 * - SocketWS_T instances are NOT thread-safe
 * - Multiple instances can be used from different threads
 * - Use external synchronization if sharing an instance
 *
 * Usage (Server):
 *   // After accepting connection and parsing HTTP request
 *   if (SocketWS_is_upgrade(request)) {
 *       SocketWS_T ws = SocketWS_server_accept(sock, request, &config);
 *       while (SocketWS_handshake(ws) > 0) { / * wait * / }
 *       // Now in OPEN state
 *   }
 *
 * Platform Requirements:
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - OpenSSL/LibreSSL for TLS WebSocket (wss://)
 * - zlib for permessage-deflate compression (optional)
 *
 * @see SocketWS_client_new() for client WebSocket creation.
 * @see SocketWS_server_accept() for server WebSocket creation.
 * @see SocketWS_send_text() for sending text messages.
 * @see SocketWS_recv_message() for receiving messages.
 * @see @ref SocketHTTP_Request for HTTP upgrade parsing.
 * @see @ref SocketPoll_T for event loop integration.
 * @see @ref SocketTimer_T for auto-ping timer integration.
 * @see @ref http for HTTP upgrade details.
 * @see docs/WEBSOCKET.md for detailed usage guide.
 */

/**
 * @defgroup websocket WebSocket Modules
 * @brief WebSocket protocol support for client and server, with framing,
 * compression, and integration.
 * @{
 *
 * The WebSocket module provides full support for the WebSocket protocol (RFC
 * 6455), including client and server roles, message framing, control frames
 * (ping/pong/close), fragmentation, UTF-8 validation, and optional
 * permessage-deflate compression (RFC 7692).
 *
 * Key Features:
 * - Non-blocking I/O compatible with SocketPoll.
 * - Automatic handling of control frames.
 * - Subprotocol negotiation during handshake.
 * - Integration with SocketTLS for secure WebSocket (wss://).
 * - Configurable limits for frame/message sizes.
 *
 * Dependencies:
 * - @ref http (SocketHTTP, SocketHTTP1 for upgrade handshake)
 * - @ref core_io (Socket, SocketBuf for I/O)
 * - @ref foundation (Arena, Except for memory/errors)
 * - @ref utilities (SocketUTF8 for text validation, SocketCrypto for masking)
 * - @ref event_system (SocketPoll, SocketTimer for events and keepalive)
 *
 * Usage:
 * - Server: Detect upgrade in HTTP request, accept with
 * SocketWS_server_accept(), handshake.
 * - Client: Connect socket, create with SocketWS_client_new(), handshake.
 * - Send/Recv: Use send_text/binary, recv_message in OPEN state.
 * - Event Loop: Poll with SocketWS_pollfd/events, process events.
 *
 * Error Handling:
 * - Uses SocketWS_* exceptions for failures.
 * - SocketWS_Error enum for detailed codes.
 *
 * @see SocketWS_Config for configuration options.
 * @see SocketWS_Message for received messages.
 * @see SocketWS_State for connection states.
 */

#ifndef SOCKETWS_INCLUDED
#define SOCKETWS_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "socket/Socket.h"

/* Forward declarations */
struct SocketPoll_T;
typedef struct SocketPoll_T *SocketPoll_T;

/* ============================================================================
 * Opaque Type
 * ============================================================================
 */

#define T SocketWS_T
typedef struct SocketWS *T;

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @brief Exception raised for general WebSocket operation failures.
 * @ingroup websocket
 *
 * Thrown on allocation failures, invalid states, or unrecoverable errors.
 *
 * @see SocketWS_Error for specific error codes.
 */
extern const Except_T SocketWS_Failed;

/**
 * @brief Exception for WebSocket protocol violations (RFC 6455
 * non-compliance).
 * @ingroup websocket
 *
 * Raised on invalid opcodes, malformed frames, missing masks (server), etc.
 *
 * @see WS_ERROR_PROTOCOL for related non-exception errors.
 */
extern const Except_T SocketWS_ProtocolError;

/**
 * @brief Exception indicating the WebSocket connection has been closed.
 * @ingroup websocket
 *
 * Raised when attempting operations on a CLOSED connection or after clean
 * close.
 *
 * @see SocketWS_state() == WS_STATE_CLOSED.
 * @see SocketWS_close() to initiate close.
 */
extern const Except_T SocketWS_Closed;

/* ============================================================================
 * WebSocket Opcodes (RFC 6455 Section 5.2)
 * ============================================================================
 */

/**
 * @brief WebSocket frame opcodes as defined in RFC 6455 section 5.2.
 * @ingroup websocket
 *
 * Opcodes determine frame type: data (text/binary), control (close/ping/pong),
 * or continuation for fragmented messages.
 *
 * @see SocketWS_Frame.opcode for frame parsing.
 * @see RFC 6455 for full opcode semantics and reserved values.
 */
typedef enum
{
  WS_OPCODE_CONTINUATION = 0x0, /**< Continuation frame for fragmented data. */
  WS_OPCODE_TEXT = 0x1,         /**< Text data frame (UTF-8 encoded). */
  WS_OPCODE_BINARY = 0x2,       /**< Binary data frame. */
  WS_OPCODE_CLOSE = 0x8,        /**< Connection close control frame. */
  WS_OPCODE_PING = 0x9,         /**< Ping control frame (keepalive). */
  WS_OPCODE_PONG = 0xA          /**< Pong control frame (response to ping). */
} SocketWS_Opcode;

/* ============================================================================
 * Close Status Codes (RFC 6455 Section 7.4.1)
 * ============================================================================
 */

/**
 * @brief Status codes for WebSocket CLOSE frames (RFC 6455 section 7.4).
 * @ingroup websocket
 *
 * Sent in CLOSE frame payload (2-byte code + optional UTF-8 reason).
 * Codes 0-999 reserved, 1000-1015+ defined, 1016-2999 for libraries,
 * 3000-3999 for apps, 4000+ for private.
 *
 * Internal codes (1002-1006,1015) not sent on wire.
 *
 * @see SocketWS_close() to send close with code.
 * @see SocketWS_close_code() to retrieve received code.
 * @see RFC 6455 section 7.4 for full list and semantics.
 */
typedef enum
{
  WS_CLOSE_NORMAL = 1000,           /**< Normal closure, no error. */
  WS_CLOSE_GOING_AWAY = 1001,       /**< Endpoint shutting down. */
  WS_CLOSE_PROTOCOL_ERROR = 1002,   /**< Generic protocol violation. */
  WS_CLOSE_UNSUPPORTED_DATA = 1003, /**< Received unsupported frame type. */
  WS_CLOSE_NO_STATUS = 1005,        /**< No status rcvd (internal use only). */
  WS_CLOSE_ABNORMAL = 1006,         /**< Closed without CLOSE frame. */
  WS_CLOSE_INVALID_PAYLOAD = 1007, /**< Invalid UTF-8 or other payload error. */
  WS_CLOSE_POLICY_VIOLATION = 1008, /**< Message violates policy. */
  WS_CLOSE_MESSAGE_TOO_BIG = 1009,  /**< Message exceeds size limits. */
  WS_CLOSE_MANDATORY_EXT = 1010,    /**< Required extension not offered. */
  WS_CLOSE_INTERNAL_ERROR = 1011,   /**< Server internal error. */
  WS_CLOSE_SERVICE_RESTART = 1012,  /**< Server restarting. */
  WS_CLOSE_TRY_AGAIN_LATER = 1013,  /**< Temporary server condition. */
  WS_CLOSE_BAD_GATEWAY = 1014,      /**< Bad gateway or tunnel error. */
  WS_CLOSE_TLS_HANDSHAKE = 1015     /**< Failed TLS handshake (internal). */
} SocketWS_CloseCode;

/* ============================================================================
 * Connection State
 * ============================================================================
 */

/**
 * @brief WebSocket connection lifecycle states.
 * @ingroup websocket
 *
 * Tracks progression from handshake to closure.
 *
 * @see SocketWS_state() to query current state.
 * @see SocketWS_handshake() transitions CONNECTING -> OPEN.
 * @see SocketWS_close() transitions OPEN -> CLOSING.
 */
typedef enum
{
  WS_STATE_CONNECTING, /**< Handshake (HTTP upgrade) in progress. */
  WS_STATE_OPEN,       /**< Connection established, ready for read/write. */
  WS_STATE_CLOSING,    /**< Close frame sent/received, awaiting ack. */
  WS_STATE_CLOSED      /**< Connection terminated, resources freed on free(). */
} SocketWS_State;

/**
 * @brief WebSocket endpoint roles per RFC 6455.
 * @ingroup websocket
 *
 * Clients mask outgoing frames; servers validate masks on incoming.
 * Set in SocketWS_Config.role.
 *
 * @see SocketWS_Config.role for configuration.
 * @see RFC 6455 section 5.3 for masking requirements.
 */
typedef enum
{
  WS_ROLE_CLIENT, /**< Client: must mask all outgoing data frames. */
  WS_ROLE_SERVER  /**< Server: rejects unmasked incoming data frames. */
} SocketWS_Role;

/* ============================================================================
 * Error Codes
 * ============================================================================
 */

/**
 * @brief WebSocket-specific error codes for SocketWS_last_error().
 * @ingroup websocket
 *
 * Returned by API functions; 0 indicates success.
 *
 * @see SocketWS_last_error() to retrieve after error.
 * @see SocketWS_error_string() for descriptions.
 */
typedef enum
{
  WS_OK = 0,                  /**< Operation succeeded. */
  WS_ERROR,                   /**< Generic WebSocket error. */
  WS_ERROR_HANDSHAKE,         /**< Handshake failure (invalid response/key). */
  WS_ERROR_PROTOCOL,          /**< Protocol violation (bad opcode, etc.). */
  WS_ERROR_FRAME_TOO_LARGE,   /**< Frame size exceeds config.max_frame_size. */
  WS_ERROR_MESSAGE_TOO_LARGE, /**< Reassembled message exceeds
                                 config.max_message_size. */
  WS_ERROR_INVALID_UTF8,      /**< Text frame contains invalid UTF-8. */
  WS_ERROR_COMPRESSION,       /**< permessage-deflate compression/decompression
                                 error. */
  WS_ERROR_CLOSED,            /**< Connection closed during operation. */
  WS_ERROR_WOULD_BLOCK,       /**< Non-blocking I/O would block. */
  WS_ERROR_TIMEOUT            /**< Operation timed out (ping or I/O). */
} SocketWS_Error;

/* ============================================================================
 * Configuration
 * ============================================================================
 */

/**
 * @brief Configuration parameters for WebSocket instances.
 * @ingroup websocket
 *
 * Passed to SocketWS_client_new() or SocketWS_server_accept().
 * Defaults set by SocketWS_config_defaults().
 *
 * @see SocketWS_config_defaults() to initialize.
 * @see RFC 6455 for protocol requirements on limits, etc.
 */
typedef struct
{
  SocketWS_Role role; /**< Role: client masks frames, server validates masks. */

  /* Limits */
  size_t max_frame_size;   /**< Maximum single frame payload size (default:
                              16MB). */
  size_t max_message_size; /**< Maximum reassembled message size (default:
                              64MB). */
  size_t max_fragments; /**< Maximum fragments per message (default: 1000). */

  /* Validation */
  int validate_utf8; /**< Enable UTF-8 validation for text frames (default: 1).
                      */

  /* Extensions */
  int enable_permessage_deflate;   /**< Offer permessage-deflate (RFC 7692,
                                      default: 0). */
  int deflate_no_context_takeover; /**< No context takeover for deflate
                                      (default: 0). */
  int deflate_max_window_bits; /**< Deflate window bits (8-15, default: 15). */

  /* Subprotocols */
  const char *
      *subprotocols; /**< NULL-terminated array of supported subprotocols. */

  /* Origin validation (server only) */
  const char *
      *allowed_origins; /**< NULL-terminated array of allowed Origin values.
                             If NULL or empty, all origins are allowed.
                             Example: {"https://example.com", "https://app.example.com", NULL} */
  int validate_origin;  /**< If non-zero, reject requests with missing or invalid Origin (default: 0). */

  /* Keepalive */
  int ping_interval_ms; /**< Auto-ping interval in ms (0=disabled, default: 0).
                         */
  int ping_timeout_ms;  /**< Timeout for pong response in ms (default: 5000). */
} SocketWS_Config;

/* ============================================================================
 * Received Frame Structure
 * ============================================================================
 */

/**
 * @brief Structure representing a parsed WebSocket frame.
 * @ingroup websocket
 *
 * Filled by internal parsing; not directly filled by user APIs.
 * Payload points to internal buffer; do not free.
 *
 * @see SocketWS-private.h for internal frame parsing details.
 */
typedef struct
{
  SocketWS_Opcode opcode; /**< Opcode of the frame (data or control). */
  int fin;                /**< 1 if final fragment of message, 0 otherwise. */
  int rsv1; /**< RSV1 bit: 1 if compressed (permessage-deflate). */
  const unsigned char
      *payload;       /**< Pointer to frame payload data (unmasked). */
  size_t payload_len; /**< Length of payload in bytes. */
} SocketWS_Frame;

/* ============================================================================
 * Received Message Structure (reassembled)
 * ============================================================================
 */

/**
 * @brief Complete reassembled WebSocket message from recv_message().
 * @ingroup websocket
 *
 * Aggregates potentially fragmented data frames into single buffer.
 * type is from first frame's opcode (TEXT or BINARY).
 * Caller owns data; free with free() or arena equivalent when done.
 *
 * @see SocketWS_recv_message() populates this structure.
 */
typedef struct
{
  SocketWS_Opcode
      type;            /**< Message type: WS_OPCODE_TEXT or WS_OPCODE_BINARY. */
  unsigned char *data; /**< Allocated message payload (caller frees). */
  size_t len;          /**< Total message length in bytes. */
} SocketWS_Message;

/* ============================================================================
 * Configuration Functions
 * ============================================================================
 */

/**
 * @brief Initialize WebSocket configuration with default values.
 * @ingroup websocket
 * @param config [out] Pointer to the configuration structure to initialize.
 *
 * Sets reasonable defaults such as 16MB max frame size, UTF-8 validation
 * enabled, compression disabled, and ping interval disabled.
 *
 * @return void
 * @threadsafe Yes - pure function with no side effects.
 * @see SocketWS_client_new() for creating client WebSockets.
 * @see SocketWS_server_accept() for accepting server WebSockets.
 * @see SocketWS_Config for individual field descriptions and customization.
 */
extern void SocketWS_config_defaults (SocketWS_Config *config);

/* ============================================================================
 * Client API
 * ============================================================================
 */

/**
 * @brief Create a new client WebSocket instance from a connected TCP socket.
 * @ingroup websocket
 * @param[in] socket Connected TCP socket (transferred to WebSocket; do not
 close externally).
 * @param[in] host Value for the Host header in upgrade request (required).
 * @param[in] path Resource path for the WebSocket endpoint (e.g., "/chat",
 defaults to "/").
 * @param[in] config Optional SocketWS_Config; NULL applies defaults via
 SocketWS_config_defaults().
 *
 * The returned instance starts in WS_STATE_CONNECTING. Call
 SocketWS_handshake()
 * to send the HTTP/1.1 Upgrade request and receive the server's response.
 *
 * Supports both blocking and non-blocking sockets, but non-blocking is
 recommended
 * for production to avoid head-of-line blocking during handshake.
 *
 * @return New SocketWS_T instance, or NULL on failure (except frame raised).
 * @throws SocketWS_Failed on invalid parameters, allocation failure, or socket
 issues.
 * @threadsafe Yes - creates independent instance.

 * ## Client Usage Example

 *
 * @code{.c}
 * SocketWS_Config config;
 * SocketWS_config_defaults(&config);
 * // Optional customizations
 * config.subprotocols = (const char*[]){"chat", NULL};
 * config.ping_interval_ms = 30000;  // Auto-ping every 30s
 * config.validate_utf8 = 1;          // Enable UTF-8 checks

 * TRY {
 *   Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 *   Socket_connect(sock, "example.com", 443);  // Port 80 or 443 for wss
 *
 *   // For secure WebSocket (wss://):
 *   // SocketTLSContext_T ctx = SocketTLSContext_new(...);
 *   // SocketTLS_enable(sock, ctx);
 *   // SocketTLS_set_hostname(sock, "example.com");
 *   // SocketTLS_handshake_auto(sock);
 *
 *   Socket_setnonblocking(sock);  // Recommended for production

 *   SocketWS_T ws = SocketWS_client_new(sock, "example.com", "/ws/chat",
 &config);
 *   if (ws == NULL) RAISE(SocketWS_Failed);

 *   // Non-blocking handshake loop
 *   int status;
 *   do {
 *     status = SocketWS_handshake(ws);
 *     if (status < 0) break;  // Error
 *     if (status == 0) break; // Success
 *     // Poll SocketWS_pollfd(ws) for SocketWS_poll_events(ws)
 *     // Then SocketWS_process(ws, events)
 *   } while (1);

 *   if (SocketWS_state(ws) == WS_STATE_OPEN) {
 *     // Send text message
 *     SocketWS_send_text(ws, "{\"msg\":\"Hello WebSocket\"}", 22);
 *     // Receive messages via SocketWS_recv_message() or event loop
 *   }

 *   SocketWS_free(&ws);
 * } EXCEPT (SocketWS_Failed | SocketWS_ProtocolError) {
 *   SOCKET_LOG_ERROR_MSG("Client WebSocket error: %s",
 SocketWS_error_string(SocketWS_last_error(ws)));
 * } END_TRY;
 * @endcode
 *
 * @note Socket ownership transfers to ws; close via SocketWS_free().
 * @note For wss://, complete TLS handshake before creating ws.
 * @note Use SocketWS_enable_auto_ping(ws, poll) after open for keepalive.
 *
 * @complexity O(1) - constant time allocation and initialization
 *
 * @see SocketWS_config_defaults() for configuration.
 * @see SocketWS_handshake() to complete upgrade.
 * @see SocketWS_process() for event-driven I/O.
 * @see SocketWS_server_accept() for server equivalent.
 * @see @ref SocketHTTP_Request for HTTP upgrade details.
 * @see docs/WEBSOCKET.md for full guide.
 */
extern T SocketWS_client_new (Socket_T socket,
                              const char *host,
                              const char *path,
                              const SocketWS_Config *config);

/* ============================================================================
 * Server API
 * ============================================================================
 */

/**
 * @brief Check if an HTTP request is a valid WebSocket upgrade request.
 * @ingroup websocket
 * @param[in] request Pointer to parsed SocketHTTP_Request from HTTP/1.1
 * parser.
 *
 * Validates presence of required headers: Upgrade: websocket, Connection:
 * Upgrade, Sec-WebSocket-Key, Sec-WebSocket-Version: 13. Optionally checks
 * Sec-WebSocket-Protocol against configured subprotocols.
 *
 * @return 1 if valid WebSocket upgrade, 0 if not (missing/invalid headers).
 * @threadsafe Yes - pure function, reads const request.
 * @see SocketWS_server_accept() to accept the upgrade.
 * @see SocketWS_server_reject() to reject with error response.
 * @see SocketHTTP_Request for HTTP request structure.
 */
extern int SocketWS_is_upgrade (const SocketHTTP_Request *request);

/**
 * @brief Accept a WebSocket upgrade from a parsed HTTP request on a server
 * socket.
 * @ingroup websocket
 * @param[in] socket Accepted TCP socket from Socket_accept() (transferred
 * ownership).
 * @param[in] request Parsed SocketHTTP_Request confirming WebSocket upgrade
 * via SocketWS_is_upgrade().
 * @param[in] config Optional SocketWS_Config; NULL uses defaults.
 *
 * Validates request, computes Sec-WebSocket-Accept key, prepares 101 Switching
 * Protocols response with negotiated subprotocol and extensions. Instance
 * starts in WS_STATE_CONNECTING. Call SocketWS_handshake() to send response
 * and transition to OPEN.
 *
 * @return New SocketWS_T instance, or NULL on failure.
 * @throws SocketWS_Failed on validation failure, allocation error, or invalid
 * request.
 * @throws SocketWS_ProtocolError if request headers invalid for WebSocket.
 * @threadsafe Yes - creates independent instance.
 * @see SocketWS_is_upgrade() to validate request first.
 * @see SocketWS_handshake() to send the acceptance response.
 * @see SocketWS_server_reject() for rejection cases.
 * @see SocketHTTP_Response for response structure used internally.
 */
extern T SocketWS_server_accept (Socket_T socket,
                                 const SocketHTTP_Request *request,
                                 const SocketWS_Config *config);

/**
 * @brief Reject a WebSocket upgrade request with an HTTP error response.
 * @ingroup websocket
 * @param[in] socket TCP socket from accepted connection.
 * @param[in] status_code HTTP status code (e.g., 400 Bad Request, 403
 * Forbidden).
 * @param[in] reason Optional human-readable reason phrase for the response
 * body.
 *
 * Sends HTTP response with given status and reason in body (if provided).
 * Closes the socket after sending. Use before SocketWS_server_accept() if
 * upgrade invalid.
 *
 * @return void
 * @throws Socket_Failed if send fails (e.g., socket closed).
 * @threadsafe Conditional - socket must not be in use by other threads.
 * @see SocketWS_is_upgrade() to check validity before accepting/rejecting.
 * @see SocketHTTPServer for full HTTP server handling including upgrades.
 */
extern void
SocketWS_server_reject (Socket_T socket, int status_code, const char *reason);

/* ============================================================================
 * Connection Lifecycle
 * ============================================================================
 */

/**
 * @brief Dispose of a WebSocket instance, closing connection if open.
 * @ingroup websocket
 * @param ws [in,out] Pointer to SocketWS_T; set to NULL after disposal.
 *
 * Performs graceful close if in OPEN or CLOSING state (sends CLOSE frame if
 * needed). Releases all resources including underlying socket, buffers,
 * compression context, and timers. Arena-allocated memory returned to owning
 * arena.
 *
 * Safe to call on already-freed or NULL pointers.
 *
 * @return void
 * @throws None - errors during close logged but not raised.
 * @threadsafe No - instance-specific resources.
 * @see SocketWS_close() for explicit close before free.
 * @see SocketWS_client_new(), SocketWS_server_accept() for creation.
 */
extern void SocketWS_free (T *ws);

/**
 * @brief Perform or continue the WebSocket handshake process.
 * @ingroup websocket
 * @param[in] ws SocketWS_T instance in CONNECTING state.
 *
 * Client mode: Sends HTTP Upgrade request with Sec-WebSocket-Key and
 * extensions, reads response, validates 101 status, Sec-WebSocket-Accept,
 * subprotocols, extensions.
 *
 * Server mode: Sends HTTP 101 response with computed Sec-WebSocket-Accept,
 * negotiated parameters. Validates client key if not pre-validated.
 *
 * Non-blocking compatible: returns 1 if more I/O needed (poll and call again).
 * Blocks if socket is blocking.
 *
 * On success, transitions to WS_STATE_OPEN.
 *
 * @return 0 on complete success (now OPEN), 1 if pending (call again after
 * poll), -1 on error (check SocketWS_last_error()).
 * @throws SocketWS_ProtocolError on invalid handshake response/request.
 * @throws SocketWS_Failed on I/O or allocation errors.
 * @threadsafe No - modifies instance state.
 * @see SocketWS_state() to check current state post-call.
 * @see SocketWS_process() for ongoing I/O after handshake.
 * @see Socket_geterrorcode() for underlying socket errors.
 */
extern int SocketWS_handshake (T ws);

/**
 * @brief Retrieve the current state of the WebSocket connection.
 * @ingroup websocket
 * @param[in] ws SocketWS_T instance.
 *
 * Possible states: WS_STATE_CONNECTING (handshake), WS_STATE_OPEN (ready),
 * WS_STATE_CLOSING (closing handshake), WS_STATE_CLOSED (terminated).
 *
 * @return SocketWS_State enum value.
 * @threadsafe Yes - atomic read of state variable.
 * @see SocketWS_State enum for state details.
 * @see SocketWS_handshake() which transitions from CONNECTING to OPEN.
 * @see SocketWS_close() which initiates CLOSING.
 */
extern SocketWS_State SocketWS_state (T ws);

/**
 * @brief Access the underlying TCP socket for the WebSocket.
 * @ingroup websocket
 * @param[in] ws SocketWS_T instance.
 *
 * Allows integration with external pollers or custom I/O handling.
 * Do NOT close or modify the socket directly; use WebSocket APIs for
 * lifecycle.
 *
 * @return Borrowed reference to Socket_T; valid until SocketWS_free().
 * @threadsafe No - concurrent access may race with internal I/O.
 * @see SocketWS_pollfd() for poll integration.
 * @see SocketWS_process() for processing events on this socket.
 * @see Socket_T for socket operations (use cautiously).
 */
extern Socket_T SocketWS_socket (T ws);

/**
 * @brief Get the negotiated WebSocket subprotocol.
 * @ingroup websocket
 * @param[in] ws SocketWS_T instance (must be post-handshake).
 *
 * Returns the subprotocol selected from client's Sec-WebSocket-Protocol header
 * matching one in server's config.subprotocols (server) or vice versa
 * (client). NULL if none negotiated.
 *
 * String is owned by WebSocket, valid until free or re-handshake.
 *
 * @return Const char* to subprotocol name, or NULL.
 * @threadsafe No - reads internal state.
 * @see SocketWS_Config.subprotocols for configuration.
 * @see RFC 6455 section 1.9 for subprotocol negotiation.
 */
extern const char *SocketWS_selected_subprotocol (T ws);

/**
 * @brief Check if compression is enabled.
 * @ingroup websocket
 * @param[in] ws WebSocket instance.
 * @return 1 if permessage-deflate enabled, 0 otherwise.
 * @threadsafe No - reads internal state.
 * @see SocketWS_Config for compression configuration.
 */
extern int SocketWS_compression_enabled (T ws);

/* ============================================================================
 * Sending
 * ============================================================================
 */

/**
 * @brief Send a text message over the WebSocket (opcode TEXT).
 * @ingroup websocket
 * @param[in] ws SocketWS_T in OPEN state.
 * @param[in] data Pointer to UTF-8 encoded text.
 * @param[in] len Length of data in bytes (may include embedded NUL).
 *
 * Validates UTF-8 if config.validate_utf8 enabled (raises on invalid).
 * Applies masking (client) or not (server).
 * Compresses if enabled and negotiated.
 * Fragments if exceeds max_frame_size, using continuation frames.
 * Queues for sending; call SocketWS_process() or poll to flush.
 *
 * @return 0 on success (queued), -1 on error (check last_error).
 * @throws SocketWS_Closed if not open.
 * @throws SocketWS_Invalid_UTF8 if validation fails.
 * @throws SocketWS_Failed on queue full or other issues.
 * @threadsafe No - modifies send buffer/state.
 * @see SocketWS_send_binary() for binary data.
 * @see SocketWS_Config.validate_utf8 for control.
 */
extern int SocketWS_send_text (T ws, const char *data, size_t len);

/**
 * @brief Send a binary message over the WebSocket (opcode BINARY).
 * @ingroup websocket
 * @param[in] ws SocketWS_T in OPEN state.
 * @param[in] data Pointer to arbitrary binary data.
 * @param[in] len Length of data in bytes.
 *
 * No UTF-8 validation (binary).
 * Applies masking/compression/fragmentation same as text.
 * Queues for sending.
 *
 * @return 0 on success (queued), -1 on error.
 * @throws SocketWS_Closed if not open.
 * @throws SocketWS_Failed on queue or state issues.
 * @threadsafe No.
 * @see SocketWS_send_text() for text (with UTF-8 validation).
 * @see SocketWS_Config.max_frame_size for fragmentation threshold.
 */
extern int SocketWS_send_binary (T ws, const void *data, size_t len);

/**
 * @brief Send a PING control frame for keepalive or to solicit immediate
 * response from peer.
 * @ingroup websocket
 * @param[in] ws SocketWS_T instance in OPEN or CONNECTING state.
 * @param[in] data Optional application-defined data payload (0-125 bytes, may
 * be NULL).
 * @param[in] len Length of data in bytes (must be <=125).
 *
 * Triggers peer to send PONG with same payload if provided.
 * Queues frame; call SocketWS_process() to send.
 * Used for keepalive or latency checks.
 *
 * @return 0 on success (queued for send), -1 on error.
 * @throws SocketWS_Closed if connection is closed.
 * @throws SocketWS_Failed on invalid parameters or internal error.
 * @throws SocketWS_ProtocolError if len > 125.
 * @threadsafe No - modifies send queue.
 *
 * @see SocketWS_pong() to send PONG.
 * @see SocketWS_enable_auto_ping() for automatic pings.
 * @see SocketWS_process() to flush queued frames.
 * @see RFC 6455 section 5.5.2 for PING frame details.
 */
extern int SocketWS_ping (T ws, const void *data, size_t len);

/**
 * @brief Send a PONG control frame, typically in response to PING.
 * @ingroup websocket
 * @param[in] ws SocketWS_T instance in OPEN or CONNECTING state.
 * @param[in] data Optional payload to echo back (0-125 bytes, may be NULL).
 * @param[in] len Length of data in bytes (must be <=125).
 *
 * Can be sent unsolicited, but usually auto-generated in response to PING.
 * Queues frame for sending.
 *
 * @return 0 on success (queued), -1 on error.
 * @throws SocketWS_Closed if closed.
 * @throws SocketWS_Failed on invalid params or queue error.
 * @throws SocketWS_ProtocolError if len > 125.
 * @threadsafe No - modifies send queue.
 *
 * @see SocketWS_ping() for sending PING.
 * @see RFC 6455 section 5.5.3 for PONG details.
 */
extern int SocketWS_pong (T ws, const void *data, size_t len);

/**
 * @brief Initiate graceful WebSocket close handshake.
 * @ingroup websocket
 * @param[in] ws SocketWS_T instance in OPEN or CLOSING state.
 * @param[in] code Close status code (WS_CLOSE_NORMAL=1000 for no error, see
 * SocketWS_CloseCode).
 * @param[in] reason Optional UTF-8 encoded reason string (max 123 bytes after
 * code, may be NULL).
 *
 * Sends CLOSE frame with code and reason to peer.
 * Transitions state to WS_STATE_CLOSING, awaits peer CLOSE response.
 * On completion or timeout, connection closes.
 * If already closing, updates code/reason if not sent yet.
 *
 * @return 0 on success (frame queued), -1 on error.
 * @throws SocketWS_Closed if already fully closed.
 * @throws SocketWS_Failed on allocation or queue error.
 * @throws SocketWS_ProtocolError on invalid code or reason length/UTF-8.
 * @threadsafe No - modifies state and send queue.
 *
 * @see SocketWS_state() to check transition to CLOSING.
 * @see SocketWS_close_code() and SocketWS_close_reason() for peer's close
 * info.
 * @see SocketWS_free() which calls this if open.
 * @see RFC 6455 section 7.1-7.4 for close handshake details.
 */
extern int SocketWS_close (T ws, int code, const char *reason);

/* ============================================================================
 * Receiving
 * ============================================================================
 */

/**
 * @brief Receive and reassemble a complete WebSocket message.
 * @ingroup websocket
 * @param[in] ws SocketWS_T in OPEN state.
 * @param msg [out] SocketWS_Message to populate with received data.
 *
 * Handles control frames automatically (pings ponged, closes processed).
 * Reassembles fragmented messages up to max_message_size.
 * Validates UTF-8 for text messages if enabled.
 * Decompresses if negotiated.
 * Blocks until complete message or close/error.
 * For non-blocking: use SocketWS_process() + SocketWS_recv_available().
 *
 * Caller must free(msg->data) after use.
 *
 * @return 1 on success (msg populated), 0 on clean close, -1 on error.
 * @throws SocketWS_Closed on peer close.
 * @throws SocketWS_ProtocolError on invalid frames.
 * @throws SocketWS_Invalid_UTF8 on text validation failure.
 * @threadsafe No - modifies recv state and msg.
 * @see SocketWS_Message for structure details.
 * @see SocketWS_recv_available() for non-blocking check.
 */
extern int SocketWS_recv_message (T ws, SocketWS_Message *msg);

/**
 * @brief Check for complete messages ready to receive without blocking.
 * @ingroup websocket
 * @param[in] ws SocketWS_T instance.
 *
 * Useful for non-blocking event loops: poll until >0, then recv_message().
 * Returns count of fully reassembled messages in internal queue.
 * Handles control frames internally but doesn't return them.
 *
 * @return >=0 number of messages available, -1 on error (check last_error).
 * @threadsafe Conditional - safe if no concurrent recv/process.
 * @see SocketWS_recv_message() to consume messages.
 * @see SocketWS_process() to advance parsing after poll events.
 * @see SocketWS_last_error() for error details.
 */
extern int SocketWS_recv_available (T ws);

/* ============================================================================
 * Event Loop Integration
 * ============================================================================
 */

/**
 * @brief Get the underlying socket file descriptor for use with
 * poll/epoll/kqueue.
 * @ingroup websocket
 * @param[in] ws SocketWS_T instance.
 *
 * Returns the FD of SocketWS_socket(ws) for registration in external event
 * loops. Use with SocketPoll_add() or native poll APIs. Do not close or modify
 * the FD directly.
 *
 * @return Valid file descriptor (>=0), or -1 if invalid/closed.
 * @threadsafe Yes - simple FD read, but concurrent close possible.
 *
 * @see SocketWS_socket() for full Socket_T access.
 * @see SocketWS_poll_events() for required events.
 * @see @ref event_system for event system integration.
 * @see SocketPoll_T::add for example usage.
 */
extern int SocketWS_pollfd (T ws);

/**
 * @brief Determine required poll events for the WebSocket socket.
 * @ingroup websocket
 * @param[in] ws SocketWS_T instance.
 *
 * Returns bitmask indicating needed events: always POLL_READ for incoming
 * data/handshake/close. POLL_WRITE if send queue has data to flush. Use with
 * SocketPoll_mod() to update registration dynamically.
 *
 * @return Event bitmask (POLL_READ | POLL_WRITE | 0).
 * @threadsafe Conditional - queue state may change.
 *
 * @see SocketWS_pollfd() for FD.
 * @see SocketWS_process() to handle triggered events.
 * @see SocketPoll_Events for bit definitions.
 */
extern unsigned SocketWS_poll_events (T ws);

/**
 * @brief Process socket events to advance WebSocket state machine.
 * @ingroup websocket
 * @param[in] ws SocketWS_T instance.
 * @param[in] events Bitmask of occurred events from poller (POLL_READ,
 * POLL_WRITE, POLL_ERROR, etc.).
 *
 * On POLL_READ: reads and parses incoming frames, handles controls,
 * reassembles messages. On POLL_WRITE: flushes queued send data/frames. On
 * POLL_ERROR/POLL_HANGUP: handles errors, may close connection. Advances
 * handshake if applicable. Integrates with auto-ping timers if enabled.
 *
 * Call repeatedly in event loop after poller signals readiness.
 *
 * @return 0 on success, -1 on error (updates last_error).
 * @throws SocketWS_ProtocolError on malformed frames.
 * @throws SocketWS_Failed on I/O failures.
 * @throws SocketWS_Closed on connection closure detected.
 * @threadsafe No - performs I/O and state changes.
 *
 * @see SocketWS_pollfd() and SocketWS_poll_events() for event setup.
 * @see SocketWS_recv_available() after process for new messages.
 * @see SocketPoll_T for full event loop example.
 */
extern int SocketWS_process (T ws, unsigned events);

/**
 * @brief Enable automatic periodic PING for connection keepalive.
 * @ingroup websocket
 * @param ws SocketWS_T instance in OPEN state.
 * @param[in] poll SocketPoll_T instance for timer callback integration.
 *
 * Installs repeating timer to send PING every
 * SocketWS_Config.ping_interval_ms. Monitors for timely PONG response within
 * ping_timeout_ms. Closes connection on missed pongs (after retries). Timer
 * events processed via SocketWS_process() on poll. Idempotent: already enabled
 * does nothing.
 *
 * Requires event loop with provided poll instance.
 *
 * @return 0 on success (timer installed), -1 on failure.
 * @throws SocketWS_Failed on timer or poll error.
 * @throws SocketWS_Closed if not open.
 * @threadsafe No - installs shared timer.
 *
 * @see SocketWS_Config::ping_interval_ms for configuration.
 * @see SocketWS_disable_auto_ping() to disable.
 * @see SocketWS_process() must be called regularly for pong checks.
 * @see @ref event_system "SocketTimer" for timer details.
 */
extern int SocketWS_enable_auto_ping (T ws, SocketPoll_T poll);

/**
 * @brief Disable and cancel automatic PING keepalive timer.
 * @ingroup websocket
 * @param[in] ws SocketWS_T instance.
 *
 * Removes any installed ping timer from associated poll.
 * Stops sending periodic PINGs and pong monitoring.
 * Does not affect manual ping/pong or current state.
 * Idempotent if not enabled.
 *
 * @return void
 * @threadsafe No - modifies timer state.
 *
 * @see SocketWS_enable_auto_ping() to enable.
 */
extern void SocketWS_disable_auto_ping (T ws);

/* ============================================================================
 * Close Status
 * ============================================================================
 */

/**
 * @brief Get close code from close frame.
 * @ingroup websocket
 * @param[in] ws WebSocket instance.
 * @return Close code, or -1 if not closed or no close frame received.
 * @threadsafe No - reads internal state.
 * @see SocketWS_close_reason() for close reason text.
 */
extern int SocketWS_close_code (T ws);

/**
 * @brief Get close reason text from close frame.
 * @ingroup websocket
 * @param[in] ws WebSocket instance.
 * @return Close reason text, or NULL if not available.
 * @note String is valid until WebSocket is freed.
 * @threadsafe No - reads internal state.
 * @see SocketWS_close_code() for close code.
 */
extern const char *SocketWS_close_reason (T ws);

/* ============================================================================
 * Error Handling
 * ============================================================================
 */

/**
 * @brief Retrieve the most recent error code for this WebSocket instance.
 * @ingroup websocket
 * @param[in] ws SocketWS_T instance.
 *
 * Provides detailed error from last failed API call on this instance.
 * Returns WS_OK (0) if no error pending.
 * Errors persist until next operation or explicit clear (if any).
 *
 * @return SocketWS_Error code from last operation.
 * @threadsafe Conditional - safe if errors not set concurrently.
 *
 * @see SocketWS_error_string() for textual description.
 * @see SocketWS_Error enum for possible values.
 * @see SocketWS_clear_error() if implemented for reset.
 */
extern SocketWS_Error SocketWS_last_error (T ws);

/**
 * @brief Get a human-readable string describing a WebSocket error code.
 * @ingroup websocket
 * @param[in] error SocketWS_Error value to describe.
 *
 * Returns pointer to static string (do not free or modify).
 * Covers all defined SocketWS_Error values.
 *
 * @return Const char* to error description, never NULL.
 * @threadsafe Yes - returns static immutable strings.
 *
 * @see SocketWS_last_error() to get code after failed operation.
 * @see SocketWS_Error enum for error codes.
 */
extern const char *SocketWS_error_string (SocketWS_Error error);

/* ============================================================================
 * Convenience Functions
 * ============================================================================
 */

/**
 * @brief One-liner WebSocket client connection
 * @ingroup websocket
 * @param[in] url WebSocket URL (ws:// or wss://)
 * @param[in] protocols Optional comma-separated subprotocols (may be NULL)
 *
 * Parses URL, creates socket, performs TLS handshake if wss://, creates
 * WebSocket, and completes the opening handshake. Returns fully connected
 * WebSocket in OPEN state.
 *
 * @return WebSocket in OPEN state, or NULL on error
 *
 * @throws SocketWS_Failed on connection or handshake failure
 * @threadsafe No
 *
 * ## URL Format
 *
 * ```
 * ws://host[:port][/path]     - Unencrypted WebSocket
 * wss://host[:port][/path]    - TLS-encrypted WebSocket
 * ```
 *
 * ## Example
 *
 * @code{.c}
 * // Simple connection
 * SocketWS_T ws = SocketWS_connect("wss://echo.websocket.org", NULL);
 * if (ws) {
 *     SocketWS_send_text(ws, "Hello!", 6);
 *     // ... receive ...
 *     SocketWS_close(ws, WS_CLOSE_NORMAL, NULL);
 *     SocketWS_free(&ws);
 * }
 *
 * // With subprotocol
 * SocketWS_T ws = SocketWS_connect("ws://api.example.com/ws", "graphql-ws");
 * @endcode
 *
 * @note For more control, use Socket_new + Socket_connect + SocketWS_client_new
 * @see SocketWS_client_new() for manual connection setup
 * @see SocketWS_free() for cleanup
 */
extern T SocketWS_connect (const char *url, const char *protocols);

/**
 * @brief Send JSON as text frame
 * @ingroup websocket
 * @param[in] ws WebSocket instance in OPEN state
 * @param[in] json JSON string to send (must be valid UTF-8)
 *
 * Convenience wrapper around SocketWS_send_text() that sends JSON data.
 * Validates UTF-8 if config.validate_utf8 is enabled.
 *
 * @return 0 on success, -1 on error
 *
 * @throws SocketWS_Closed if not open
 * @throws SocketWS_Invalid_UTF8 if validation fails
 * @threadsafe No
 *
 * ## Example
 *
 * @code{.c}
 * const char *msg = "{\"type\": \"ping\", \"id\": 123}";
 * SocketWS_send_json(ws, msg);
 * @endcode
 *
 * @see SocketWS_send_text() for raw text sending
 * @see SocketWS_recv_json() for receiving JSON
 */
extern int SocketWS_send_json (T ws, const char *json);

/**
 * @brief Receive and return JSON string
 * @ingroup websocket
 * @param[in] ws WebSocket instance in OPEN state
 * @param[out] json_out Output: received JSON string (caller must free)
 * @param[out] json_len Output: length of JSON string
 *
 * Receives a complete text message and returns it as a JSON string.
 * Only accepts TEXT frames; returns error for BINARY.
 *
 * @return WS_OK on success, error code on failure
 *
 * @throws SocketWS_Closed if connection closes
 * @throws SocketWS_Failed on receive error
 * @threadsafe No
 *
 * ## Example
 *
 * @code{.c}
 * char *json = NULL;
 * size_t len;
 * if (SocketWS_recv_json(ws, &json, &len) == WS_OK) {
 *     printf("Received: %s\n", json);
 *     // Parse with your JSON library
 *     free(json);
 * }
 * @endcode
 *
 * @note Caller must free(json_out) on success
 * @see SocketWS_recv_message() for full message control
 * @see SocketWS_send_json() for sending JSON
 */
extern SocketWS_Error
SocketWS_recv_json (T ws, char **json_out, size_t *json_len);

/**
 * @brief Get ping/pong round-trip time
 * @ingroup websocket
 * @param[in] ws WebSocket instance
 *
 * Returns the latency (RTT) of the most recent completed PING/PONG cycle.
 * If no ping has been sent or pong not yet received, returns -1.
 *
 * @return RTT in milliseconds (>= 0), or -1 if no data available
 *
 * @threadsafe No - reads internal timestamps
 *
 * ## Example
 *
 * @code{.c}
 * // Send ping and wait for pong
 * SocketWS_ping(ws, "test", 4);
 * // ... process events until pong received ...
 * int64_t rtt = SocketWS_get_ping_latency(ws);
 * if (rtt >= 0) {
 *     printf("Latency: %lld ms\n", (long long)rtt);
 * }
 * @endcode
 *
 * @see SocketWS_ping() to send PING
 * @see SocketWS_enable_auto_ping() for automatic keepalive
 */
extern int64_t SocketWS_get_ping_latency (T ws);

/**
 * @brief WebSocket compression options
 * @ingroup websocket
 */
typedef struct SocketWS_CompressionOptions
{
  int level; /**< zlib compression level (1-9, default 6) */
  int server_no_context_takeover; /**< Server resets context per message */
  int client_no_context_takeover; /**< Client resets context per message */
  int server_max_window_bits;     /**< Server LZ77 window (8-15, default 15) */
  int client_max_window_bits;     /**< Client LZ77 window (8-15, default 15) */
} SocketWS_CompressionOptions;

/**
 * @brief Initialize compression options with defaults
 * @ingroup websocket
 * @param[out] options Options structure to initialize
 */
extern void
SocketWS_compression_options_defaults (SocketWS_CompressionOptions *options);

/**
 * @brief Enable permessage-deflate compression
 * @ingroup websocket
 * @param[in] ws WebSocket instance (before handshake)
 * @param[in] options Compression options (NULL for defaults)
 *
 * Enables RFC 7692 permessage-deflate compression for this WebSocket.
 * Must be called before the handshake completes. The server may
 * negotiate different parameters.
 *
 * @return 0 on success, -1 if compression not supported or already connected
 *
 * @threadsafe No
 *
 * ## Example
 *
 * @code{.c}
 * SocketWS_T ws = SocketWS_client_new(sock, host, path, &config);
 *
 * // Enable compression before handshake
 * SocketWS_CompressionOptions opts;
 * SocketWS_compression_options_defaults(&opts);
 * opts.level = 9;  // Maximum compression
 * SocketWS_enable_compression(ws, &opts);
 *
 * // Now complete handshake
 * SocketWS_handshake(ws);
 * @endcode
 *
 * @note Requires zlib; returns -1 if compiled without SOCKETWS_HAS_DEFLATE
 * @see SocketWS_compression_enabled() to check if active
 * @see SocketWS_Config.enable_compression for config-based setup
 */
extern int
SocketWS_enable_compression (T ws, const SocketWS_CompressionOptions *options);

#undef T
/** @} */ /* websocket group */

#endif /* SOCKETWS_INCLUDED */

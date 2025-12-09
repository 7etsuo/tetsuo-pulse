/**
 * @file SocketWS.h
 * @ingroup core_io
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
 * @see SocketWS_server_new() for server WebSocket creation.
 * @see SocketWS_send_text() for sending text messages.
 * @see SocketWS_recv_message() for receiving messages.
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
 * @brief SocketWS_Failed - General WebSocket operation failure
 * @ingroup core_io
 */
extern const Except_T SocketWS_Failed;

/**
 * @brief SocketWS_ProtocolError - WebSocket protocol violation
 * @ingroup core_io
 */
extern const Except_T SocketWS_ProtocolError;

/**
 * @brief SocketWS_Closed - WebSocket connection closed
 * @ingroup core_io
 */
extern const Except_T SocketWS_Closed;

/* ============================================================================
 * WebSocket Opcodes (RFC 6455 Section 5.2)
 * ============================================================================
 */

typedef enum
{
  WS_OPCODE_CONTINUATION = 0x0, /**< Continuation frame */
  WS_OPCODE_TEXT = 0x1,         /**< Text frame (UTF-8) */
  WS_OPCODE_BINARY = 0x2,       /**< Binary frame */
  WS_OPCODE_CLOSE = 0x8,        /**< Close frame */
  WS_OPCODE_PING = 0x9,         /**< Ping frame */
  WS_OPCODE_PONG = 0xA          /**< Pong frame */
} SocketWS_Opcode;

/* ============================================================================
 * Close Status Codes (RFC 6455 Section 7.4.1)
 * ============================================================================
 */

typedef enum
{
  WS_CLOSE_NORMAL = 1000,           /**< Normal closure */
  WS_CLOSE_GOING_AWAY = 1001,       /**< Endpoint going away */
  WS_CLOSE_PROTOCOL_ERROR = 1002,   /**< Protocol error */
  WS_CLOSE_UNSUPPORTED_DATA = 1003, /**< Unsupported data type */
  WS_CLOSE_NO_STATUS = 1005,        /**< No status received (internal) */
  WS_CLOSE_ABNORMAL = 1006,         /**< Abnormal closure (internal) */
  WS_CLOSE_INVALID_PAYLOAD
  = 1007, /**< Invalid frame payload (e.g., bad UTF-8) */
  WS_CLOSE_POLICY_VIOLATION = 1008, /**< Policy violation */
  WS_CLOSE_MESSAGE_TOO_BIG = 1009,  /**< Message too big */
  WS_CLOSE_MANDATORY_EXT = 1010,    /**< Mandatory extension missing */
  WS_CLOSE_INTERNAL_ERROR = 1011,   /**< Internal server error */
  WS_CLOSE_SERVICE_RESTART = 1012,  /**< Service restart */
  WS_CLOSE_TRY_AGAIN_LATER = 1013,  /**< Try again later */
  WS_CLOSE_BAD_GATEWAY = 1014,      /**< Bad gateway */
  WS_CLOSE_TLS_HANDSHAKE = 1015     /**< TLS handshake failure (internal) */
} SocketWS_CloseCode;

/* ============================================================================
 * Connection State
 * ============================================================================
 */

typedef enum
{
  WS_STATE_CONNECTING, /**< Handshake in progress */
  WS_STATE_OPEN,       /**< Ready for messages */
  WS_STATE_CLOSING,    /**< Close handshake in progress */
  WS_STATE_CLOSED      /**< Connection terminated */
} SocketWS_State;

typedef enum
{
  WS_ROLE_CLIENT, /**< Client role (masks frames) */
  WS_ROLE_SERVER  /**< Server role (doesn't mask) */
} SocketWS_Role;

/* ============================================================================
 * Error Codes
 * ============================================================================
 */

typedef enum
{
  WS_OK = 0,                  /**< Success */
  WS_ERROR,                   /**< General error */
  WS_ERROR_HANDSHAKE,         /**< Handshake failed */
  WS_ERROR_PROTOCOL,          /**< Protocol violation */
  WS_ERROR_FRAME_TOO_LARGE,   /**< Frame exceeds limit */
  WS_ERROR_MESSAGE_TOO_LARGE, /**< Message exceeds limit */
  WS_ERROR_INVALID_UTF8,      /**< Invalid UTF-8 in text */
  WS_ERROR_COMPRESSION,       /**< Compression error */
  WS_ERROR_CLOSED,            /**< Connection closed */
  WS_ERROR_WOULD_BLOCK,       /**< Would block (non-blocking) */
  WS_ERROR_TIMEOUT            /**< Operation timed out */
} SocketWS_Error;

/* ============================================================================
 * Configuration
 * ============================================================================
 */

typedef struct
{
  SocketWS_Role role; /**< Client or server role */

  /* Limits */
  size_t max_frame_size;   /**< Max single frame (default: 16MB) */
  size_t max_message_size; /**< Max reassembled message (default: 64MB) */
  size_t max_fragments;    /**< Max fragments per message (default: 1000) */

  /* Validation */
  int validate_utf8; /**< Validate UTF-8 in text frames (default: yes) */

  /* Extensions */
  int enable_permessage_deflate;   /**< Enable compression (default: no) */
  int deflate_no_context_takeover; /**< Don't reuse compression context */
  int deflate_max_window_bits;     /**< LZ77 window size (8-15, default: 15) */

  /* Subprotocols */
  const char **subprotocols; /**< NULL-terminated list of subprotocols */

  /* Keepalive */
  int ping_interval_ms; /**< Auto-ping interval (0 = disabled) */
  int ping_timeout_ms;  /**< Pong timeout */
} SocketWS_Config;

/* ============================================================================
 * Received Frame Structure
 * ============================================================================
 */

typedef struct
{
  SocketWS_Opcode opcode;       /**< Frame opcode */
  int fin;                      /**< Final fragment flag */
  int rsv1;                     /**< Reserved bit 1 (compression) */
  const unsigned char *payload; /**< Payload data */
  size_t payload_len;           /**< Payload length */
} SocketWS_Frame;

/* ============================================================================
 * Received Message Structure (reassembled)
 * ============================================================================
 */

typedef struct
{
  SocketWS_Opcode type; /**< TEXT or BINARY */
  unsigned char *data;  /**< Message data (caller must free) */
  size_t len;           /**< Message length */
} SocketWS_Message;

/* ============================================================================
 * Configuration Functions
 * ============================================================================
 */

/**
 * @brief SocketWS_config_defaults - Initialize configuration with defaults
 * @ingroup core_io
 * @config: Configuration to initialize
 *
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern void SocketWS_config_defaults (SocketWS_Config *config);

/* ============================================================================
 * Client API
 * ============================================================================
 */

/**
 * @brief SocketWS_client_new - Create client WebSocket from connected socket
 * @ingroup core_io
 * @socket: Connected TCP socket
 * @host: Host header value (required)
 * @path: Request path (e.g., "/ws", default: "/")
 * @config: Configuration (NULL for defaults)
 *
 * Creates a WebSocket in CONNECTING state. Call SocketWS_handshake() to
 * complete the HTTP upgrade.
 *
 * Returns: WebSocket instance
 * Raises: SocketWS_Failed on error
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern T SocketWS_client_new (Socket_T socket, const char *host,
                              const char *path, const SocketWS_Config *config);

/* ============================================================================
 * Server API
 * ============================================================================
 */

/**
 * @brief SocketWS_is_upgrade - Check if HTTP request is WebSocket upgrade
 * @ingroup core_io
 * @request: Parsed HTTP request
 *
 * Returns: 1 if WebSocket upgrade request, 0 otherwise
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern int SocketWS_is_upgrade (const SocketHTTP_Request *request);

/**
 * @brief SocketWS_server_accept - Accept WebSocket upgrade
 * @ingroup core_io
 * @socket: TCP socket with pending upgrade request
 * @request: Parsed HTTP upgrade request
 * @config: Configuration (NULL for defaults)
 *
 * Creates a WebSocket in CONNECTING state. Call SocketWS_handshake() to
 * send the HTTP 101 response.
 *
 * Returns: WebSocket instance
 * Raises: SocketWS_Failed on error
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern T SocketWS_server_accept (Socket_T socket,
                                 const SocketHTTP_Request *request,
                                 const SocketWS_Config *config);

/**
 * @brief SocketWS_server_reject - Reject upgrade with HTTP response
 * @ingroup core_io
 * @socket: TCP socket
 * @status_code: HTTP status (e.g., 400, 403)
 * @reason: Rejection reason
 *
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern void SocketWS_server_reject (Socket_T socket, int status_code,
                                    const char *reason);

/* ============================================================================
 * Connection Lifecycle
 * ============================================================================
 */

/**
 * @brief SocketWS_free - Free WebSocket connection
 * @ingroup core_io
 * @ws: Pointer to WebSocket (set to NULL after free)
 *
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern void SocketWS_free (T *ws);

/**
 * @brief SocketWS_handshake - Perform/continue handshake
 * @ingroup core_io
 * @ws: WebSocket instance
 *
 * For clients: Sends HTTP upgrade request, receives and validates response.
 * For servers: Sends HTTP 101 response.
 *
 * Returns: 0 if complete, 1 if in progress (call again), -1 on error
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern int SocketWS_handshake (T ws);

/**
 * @brief SocketWS_state - Get current state
 * @ingroup core_io
 * @ws: WebSocket instance
 *
 * Returns: Current state (CONNECTING, OPEN, CLOSING, CLOSED)
 * @note Thread-safe: No (read-only, safe for status checks)
 * @ingroup core_io
 */
extern SocketWS_State SocketWS_state (T ws);

/**
 * @brief SocketWS_socket - Get underlying socket
 * @ingroup core_io
 * @ws: WebSocket instance
 *
 * Returns: TCP socket (do not close directly)
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern Socket_T SocketWS_socket (T ws);

/**
 * @brief SocketWS_selected_subprotocol - Get negotiated subprotocol
 * @ingroup core_io
 * @ws: WebSocket instance
 *
 * Returns: Selected subprotocol string, or NULL if none
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern const char *SocketWS_selected_subprotocol (T ws);

/**
 * @brief SocketWS_compression_enabled - Check if compression active
 * @ingroup core_io
 * @ws: WebSocket instance
 *
 * Returns: 1 if permessage-deflate enabled, 0 otherwise
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern int SocketWS_compression_enabled (T ws);

/* ============================================================================
 * Sending
 * ============================================================================
 */

/**
 * @brief SocketWS_send_text - Send text message
 * @ingroup core_io
 * @ws: WebSocket instance
 * @data: UTF-8 text data
 * @len: Length in bytes
 *
 * Data is validated for UTF-8 if validate_utf8 enabled.
 * Large messages are automatically fragmented.
 *
 * Returns: 0 on success, -1 on error
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern int SocketWS_send_text (T ws, const char *data, size_t len);

/**
 * @brief SocketWS_send_binary - Send binary message
 * @ingroup core_io
 * @ws: WebSocket instance
 * @data: Binary data
 * @len: Length in bytes
 *
 * Returns: 0 on success, -1 on error
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern int SocketWS_send_binary (T ws, const void *data, size_t len);

/**
 * @brief SocketWS_ping - Send PING control frame
 * @ingroup core_io
 * @ws: WebSocket instance
 * @data: Optional payload (max 125 bytes, may be NULL)
 * @len: Payload length
 *
 * Returns: 0 on success, -1 on error
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern int SocketWS_ping (T ws, const void *data, size_t len);

/**
 * @brief SocketWS_pong - Send unsolicited PONG
 * @ingroup core_io
 * @ws: WebSocket instance
 * @data: Payload (max 125 bytes, may be NULL)
 * @len: Payload length
 *
 * Returns: 0 on success, -1 on error
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern int SocketWS_pong (T ws, const void *data, size_t len);

/**
 * @brief SocketWS_close - Initiate close handshake
 * @ingroup core_io
 * @ws: WebSocket instance
 * @code: Close status code (use WS_CLOSE_NORMAL for normal close)
 * @reason: Optional UTF-8 reason (max 123 bytes, may be NULL)
 *
 * Transitions to CLOSING state and sends CLOSE frame.
 *
 * Returns: 0 on success, -1 on error
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern int SocketWS_close (T ws, int code, const char *reason);

/* ============================================================================
 * Receiving
 * ============================================================================
 */

/**
 * @brief SocketWS_recv_message - Receive complete message
 * @ingroup core_io
 * @ws: WebSocket instance
 * @msg: Output message structure
 *
 * Blocks until a complete message is received. Control frames
 * (PING/PONG/CLOSE) are handled automatically. Fragmented messages are
 * reassembled.
 *
 * Caller must free msg->data when done.
 *
 * Returns: 1 if message received, 0 if closed, -1 on error
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern int SocketWS_recv_message (T ws, SocketWS_Message *msg);

/**
 * @brief SocketWS_recv_available - Check if data available
 * @ingroup core_io
 * @ws: WebSocket instance
 *
 * Returns: 1 if data available, 0 otherwise
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern int SocketWS_recv_available (T ws);

/* ============================================================================
 * Event Loop Integration
 * ============================================================================
 */

/**
 * @brief SocketWS_pollfd - Get file descriptor for polling
 * @ingroup core_io
 * @ws: WebSocket instance
 *
 * Returns: Socket file descriptor
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern int SocketWS_pollfd (T ws);

/**
 * @brief SocketWS_poll_events - Get events to poll for
 * @ingroup core_io
 * @ws: WebSocket instance
 *
 * Returns: Bitmask of POLL_READ, POLL_WRITE
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern unsigned SocketWS_poll_events (T ws);

/**
 * @brief SocketWS_process - Process poll events
 * @ingroup core_io
 * @ws: WebSocket instance
 * @events: Events from poll
 *
 * Handles I/O based on poll results. Call this when poll indicates
 * the socket is ready.
 *
 * Returns: 0 on success, -1 on error
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern int SocketWS_process (T ws, unsigned events);

/**
 * @brief SocketWS_enable_auto_ping - Enable automatic ping/pong
 * @ingroup core_io
 * @ws: WebSocket instance
 * @poll: SocketPoll instance for timer
 *
 * Starts automatic ping timer based on config.ping_interval_ms.
 * Requires SocketPoll for timer integration.
 *
 * Returns: 0 on success, -1 on error
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern int SocketWS_enable_auto_ping (T ws, SocketPoll_T poll);

/**
 * @brief SocketWS_disable_auto_ping - Disable automatic ping/pong
 * @ingroup core_io
 * @ws: WebSocket instance
 *
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern void SocketWS_disable_auto_ping (T ws);

/* ============================================================================
 * Close Status
 * ============================================================================
 */

/**
 * @brief SocketWS_close_code - Get peer's close code
 * @ingroup core_io
 * @ws: WebSocket instance
 *
 * Returns: Close code, or 0 if not received
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern int SocketWS_close_code (T ws);

/**
 * @brief SocketWS_close_reason - Get peer's close reason
 * @ingroup core_io
 * @ws: WebSocket instance
 *
 * Returns: Close reason string, or NULL if none
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern const char *SocketWS_close_reason (T ws);

/* ============================================================================
 * Error Handling
 * ============================================================================
 */

/**
 * @brief SocketWS_last_error - Get last error code
 * @ingroup core_io
 * @ws: WebSocket instance
 *
 * Returns: Last error code
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern SocketWS_Error SocketWS_last_error (T ws);

/**
 * @brief SocketWS_error_string - Get human-readable error description
 * @ingroup core_io
 * @error: Error code
 *
 * Returns: Static string describing error
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern const char *SocketWS_error_string (SocketWS_Error error);

#undef T
#endif /* SOCKETWS_INCLUDED */

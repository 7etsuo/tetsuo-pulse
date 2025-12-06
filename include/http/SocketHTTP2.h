/**
 * SocketHTTP2.h - HTTP/2 Protocol Implementation (RFC 9113)
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Provides complete HTTP/2 implementation with:
 * - Binary framing layer (9-byte frame headers)
 * - Stream multiplexing with state machine
 * - Flow control (connection and stream level)
 * - HPACK header compression integration
 * - Server push support
 * - h2c cleartext upgrade support
 *
 * Dependencies:
 * - SocketHPACK for header compression
 * - SocketHTTP for HTTP semantics
 * - SocketBuf for I/O buffering
 * - Socket_T for underlying transport
 * - Arena for memory management
 *
 * Thread safety: Connection instances are NOT thread-safe.
 * Use one connection per thread or external synchronization.
 *
 * Security notes:
 * - Enforces MAX_CONCURRENT_STREAMS to prevent resource exhaustion
 * - HPACK bomb prevention via SocketHPACK limits
 * - Flow control window overflow prevention
 * - SETTINGS_TIMEOUT enforcement
 */

#ifndef SOCKETHTTP2_INCLUDED
#define SOCKETHTTP2_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHPACK.h"
#include "http/SocketHTTP.h"
#include "socket/Socket.h"

/* ============================================================================
 * Configuration Limits (RFC 9113 Section 6.5.2)
 * ============================================================================ */

/** Default SETTINGS_HEADER_TABLE_SIZE */
#ifndef SOCKETHTTP2_DEFAULT_HEADER_TABLE_SIZE
#define SOCKETHTTP2_DEFAULT_HEADER_TABLE_SIZE 4096
#endif

/** Default SETTINGS_ENABLE_PUSH (server only) */
#ifndef SOCKETHTTP2_DEFAULT_ENABLE_PUSH
#define SOCKETHTTP2_DEFAULT_ENABLE_PUSH 1
#endif

/**
 * Default SETTINGS_MAX_CONCURRENT_STREAMS
 *
 * ENFORCEMENT: Checked in http2_stream_create() before creating new streams.
 * Returns NULL if limit exceeded.
 */
#ifndef SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS
#define SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS 100
#endif

/** Default SETTINGS_INITIAL_WINDOW_SIZE */
#ifndef SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE
#define SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE 65535
#endif

/** Default SETTINGS_MAX_FRAME_SIZE */
#ifndef SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE
#define SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE 16384
#endif

/** Maximum allowed SETTINGS_MAX_FRAME_SIZE (2^24 - 1) */
#define SOCKETHTTP2_MAX_MAX_FRAME_SIZE 16777215

/**
 * Default SETTINGS_MAX_HEADER_LIST_SIZE
 *
 * ENFORCEMENT: Checked in http2_decode_headers() before processing.
 * Returns COMPRESSION_ERROR if exceeded.
 */
#ifndef SOCKETHTTP2_DEFAULT_MAX_HEADER_LIST_SIZE
#define SOCKETHTTP2_DEFAULT_MAX_HEADER_LIST_SIZE (16 * 1024)
#endif

/** Implementation limit: maximum streams per connection */
#ifndef SOCKETHTTP2_MAX_STREAMS
#define SOCKETHTTP2_MAX_STREAMS 1000
#endif

/** Default connection-level window size */
#ifndef SOCKETHTTP2_CONNECTION_WINDOW_SIZE
#define SOCKETHTTP2_CONNECTION_WINDOW_SIZE (1 << 20) /* 1MB */
#endif

/**
 * RST_STREAM rate limiting (CVE-2023-44487 Rapid Reset protection)
 *
 * These limits prevent attackers from exhausting server resources by rapidly
 * opening and resetting streams. When exceeded, ENHANCE_YOUR_CALM is sent.
 */
#ifndef SOCKETHTTP2_RST_RATE_LIMIT
#define SOCKETHTTP2_RST_RATE_LIMIT 100 /* Max RST_STREAM frames per window */
#endif

#ifndef SOCKETHTTP2_RST_RATE_WINDOW_MS
#define SOCKETHTTP2_RST_RATE_WINDOW_MS 1000 /* Rate window in milliseconds */
#endif

/** Frame header size in bytes */
#define HTTP2_FRAME_HEADER_SIZE 9

/** Connection preface magic string length */
#define HTTP2_PREFACE_SIZE 24

/** Stream hash table size (prime for better distribution) */
#define HTTP2_STREAM_HASH_SIZE 1021

/* ============================================================================
 * Exception Types
 * ============================================================================ */

/** Protocol-level error (connection must close) */
extern const Except_T SocketHTTP2_ProtocolError;

/** Stream-level error (stream reset, connection continues) */
extern const Except_T SocketHTTP2_StreamError;

/** Flow control violation */
extern const Except_T SocketHTTP2_FlowControlError;

/* ============================================================================
 * Frame Types (RFC 9113 Section 6)
 * ============================================================================ */

/**
 * HTTP/2 frame types
 */
typedef enum
{
  HTTP2_FRAME_DATA = 0x0,         /**< Section 6.1 - Payload data */
  HTTP2_FRAME_HEADERS = 0x1,      /**< Section 6.2 - Header block */
  HTTP2_FRAME_PRIORITY = 0x2,     /**< Section 6.3 - Deprecated */
  HTTP2_FRAME_RST_STREAM = 0x3,   /**< Section 6.4 - Stream termination */
  HTTP2_FRAME_SETTINGS = 0x4,     /**< Section 6.5 - Configuration */
  HTTP2_FRAME_PUSH_PROMISE = 0x5, /**< Section 6.6 - Server push */
  HTTP2_FRAME_PING = 0x6,         /**< Section 6.7 - Keep-alive/RTT */
  HTTP2_FRAME_GOAWAY = 0x7,       /**< Section 6.8 - Graceful shutdown */
  HTTP2_FRAME_WINDOW_UPDATE = 0x8, /**< Section 6.9 - Flow control */
  HTTP2_FRAME_CONTINUATION = 0x9  /**< Section 6.10 - Header continuation */
} SocketHTTP2_FrameType;

/* Frame flags */
#define HTTP2_FLAG_END_STREAM 0x01  /**< DATA, HEADERS */
#define HTTP2_FLAG_END_HEADERS 0x04 /**< HEADERS, PUSH_PROMISE, CONTINUATION */
#define HTTP2_FLAG_PADDED 0x08      /**< DATA, HEADERS, PUSH_PROMISE */
#define HTTP2_FLAG_PRIORITY 0x20    /**< HEADERS */
#define HTTP2_FLAG_ACK 0x01         /**< SETTINGS, PING */

/* ============================================================================
 * Error Codes (RFC 9113 Section 7)
 * ============================================================================ */

/**
 * HTTP/2 error codes for RST_STREAM and GOAWAY
 */
typedef enum
{
  HTTP2_NO_ERROR = 0x0,            /**< Graceful shutdown */
  HTTP2_PROTOCOL_ERROR = 0x1,      /**< Protocol error detected */
  HTTP2_INTERNAL_ERROR = 0x2,      /**< Implementation fault */
  HTTP2_FLOW_CONTROL_ERROR = 0x3,  /**< Flow control limits exceeded */
  HTTP2_SETTINGS_TIMEOUT = 0x4,    /**< Settings not acknowledged */
  HTTP2_STREAM_CLOSED = 0x5,       /**< Frame on closed stream */
  HTTP2_FRAME_SIZE_ERROR = 0x6,    /**< Frame size incorrect */
  HTTP2_REFUSED_STREAM = 0x7,      /**< Stream not processed */
  HTTP2_CANCEL = 0x8,              /**< Stream cancelled */
  HTTP2_COMPRESSION_ERROR = 0x9,   /**< HPACK decompression failure */
  HTTP2_CONNECT_ERROR = 0xa,       /**< TCP connection error for CONNECT */
  HTTP2_ENHANCE_YOUR_CALM = 0xb,   /**< Processing capacity exceeded */
  HTTP2_INADEQUATE_SECURITY = 0xc, /**< TLS requirements not met */
  HTTP2_HTTP_1_1_REQUIRED = 0xd    /**< Use HTTP/1.1 for request */
} SocketHTTP2_ErrorCode;

/* ============================================================================
 * Settings Identifiers (RFC 9113 Section 6.5.2)
 * ============================================================================ */

/**
 * HTTP/2 settings parameters
 */
typedef enum
{
  HTTP2_SETTINGS_HEADER_TABLE_SIZE = 0x1,
  HTTP2_SETTINGS_ENABLE_PUSH = 0x2,
  HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
  HTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 0x4,
  HTTP2_SETTINGS_MAX_FRAME_SIZE = 0x5,
  HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x6
} SocketHTTP2_SettingsId;

/** Number of defined settings */
#define HTTP2_SETTINGS_COUNT 6

/* ============================================================================
 * Stream States (RFC 9113 Section 5.1)
 * ============================================================================ */

/**
 * HTTP/2 stream states
 */
typedef enum
{
  HTTP2_STREAM_STATE_IDLE = 0,
  HTTP2_STREAM_STATE_RESERVED_LOCAL,
  HTTP2_STREAM_STATE_RESERVED_REMOTE,
  HTTP2_STREAM_STATE_OPEN,
  HTTP2_STREAM_STATE_HALF_CLOSED_LOCAL,
  HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE,
  HTTP2_STREAM_STATE_CLOSED
} SocketHTTP2_StreamState;

/* ============================================================================
 * Frame Header
 * ============================================================================ */

/**
 * HTTP/2 frame header (9 bytes on wire)
 */
typedef struct
{
  uint32_t length;    /**< 24-bit payload length */
  uint8_t type;       /**< Frame type */
  uint8_t flags;      /**< Frame flags */
  uint32_t stream_id; /**< 31-bit stream ID (R bit reserved) */
} SocketHTTP2_FrameHeader;

/* ============================================================================
 * Connection Role
 * ============================================================================ */

/**
 * HTTP/2 endpoint role
 */
typedef enum
{
  HTTP2_ROLE_CLIENT,
  HTTP2_ROLE_SERVER
} SocketHTTP2_Role;

/* ============================================================================
 * Connection Configuration
 * ============================================================================ */

/**
 * HTTP/2 connection configuration
 */
typedef struct
{
  SocketHTTP2_Role role;

  /* Local settings (we send to peer) */
  uint32_t header_table_size;
  uint32_t enable_push;
  uint32_t max_concurrent_streams;
  uint32_t initial_window_size;
  uint32_t max_frame_size;
  uint32_t max_header_list_size;

  /* Connection-level flow control */
  uint32_t connection_window_size;

  /* Timeouts (milliseconds) */
  int settings_timeout_ms;
  int ping_timeout_ms;
  int idle_timeout_ms;
} SocketHTTP2_Config;

/* ============================================================================
 * Opaque Types
 * ============================================================================ */

/** HTTP/2 connection (opaque) */
typedef struct SocketHTTP2_Conn *SocketHTTP2_Conn_T;

/** HTTP/2 stream (opaque) */
typedef struct SocketHTTP2_Stream *SocketHTTP2_Stream_T;

/* ============================================================================
 * Setting Entry (for SETTINGS frame)
 * ============================================================================ */

/**
 * Single setting entry
 */
typedef struct
{
  uint16_t id;
  uint32_t value;
} SocketHTTP2_Setting;

/* ============================================================================
 * Configuration Functions
 * ============================================================================ */

/**
 * SocketHTTP2_config_defaults - Initialize config with RFC defaults
 * @config: Configuration structure to initialize
 * @role: Client or server role
 *
 * Thread-safe: Yes
 */
extern void SocketHTTP2_config_defaults (SocketHTTP2_Config *config,
                                         SocketHTTP2_Role role);

/* ============================================================================
 * Connection Lifecycle
 * ============================================================================ */

/**
 * SocketHTTP2_Conn_new - Create HTTP/2 connection
 * @socket: Underlying TCP socket (after TLS handshake for h2)
 * @config: Configuration (NULL for defaults)
 * @arena: Memory arena
 *
 * Returns: New connection instance
 * Raises: SocketHTTP2_ProtocolError on allocation failure
 * Thread-safe: Yes (arena must be thread-safe or thread-local)
 */
extern SocketHTTP2_Conn_T SocketHTTP2_Conn_new (Socket_T socket,
                                                const SocketHTTP2_Config *config,
                                                Arena_T arena);

/**
 * SocketHTTP2_Conn_free - Free connection and all streams
 * @conn: Pointer to connection (will be set to NULL)
 *
 * Thread-safe: No
 */
extern void SocketHTTP2_Conn_free (SocketHTTP2_Conn_T *conn);

/**
 * SocketHTTP2_Conn_handshake - Perform HTTP/2 connection preface
 * @conn: Connection
 *
 * Client sends: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + SETTINGS
 * Server expects preface, sends SETTINGS
 *
 * Returns: 0 on complete, 1 if in progress, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTP2_Conn_handshake (SocketHTTP2_Conn_T conn);

/**
 * SocketHTTP2_Conn_process - Process incoming data
 * @conn: Connection
 * @events: Poll events (POLL_READ, POLL_WRITE, etc.)
 *
 * Call when socket is readable/writable. Processes frames and
 * invokes callbacks for stream events.
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTP2_Conn_process (SocketHTTP2_Conn_T conn, unsigned events);

/**
 * SocketHTTP2_Conn_flush - Flush pending output
 * @conn: Connection
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTP2_Conn_flush (SocketHTTP2_Conn_T conn);

/**
 * SocketHTTP2_Conn_socket - Get underlying socket
 * @conn: Connection
 *
 * Returns: Socket instance
 * Thread-safe: Yes
 */
extern Socket_T SocketHTTP2_Conn_socket (SocketHTTP2_Conn_T conn);

/**
 * SocketHTTP2_Conn_is_closed - Check if connection closed
 * @conn: Connection
 *
 * Returns: 1 if closed (GOAWAY sent/received), 0 otherwise
 * Thread-safe: Yes
 */
extern int SocketHTTP2_Conn_is_closed (SocketHTTP2_Conn_T conn);

/**
 * SocketHTTP2_Conn_arena - Get connection's arena
 * @conn: Connection
 *
 * Returns: Arena instance
 * Thread-safe: Yes
 */
extern Arena_T SocketHTTP2_Conn_arena (SocketHTTP2_Conn_T conn);

/* ============================================================================
 * Connection Control
 * ============================================================================ */

/**
 * SocketHTTP2_Conn_settings - Send SETTINGS frame
 * @conn: Connection
 * @settings: Array of settings
 * @count: Number of settings
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTP2_Conn_settings (SocketHTTP2_Conn_T conn,
                                      const SocketHTTP2_Setting *settings,
                                      size_t count);

/**
 * SocketHTTP2_Conn_get_setting - Get peer's setting value
 * @conn: Connection
 * @id: Setting identifier
 *
 * Returns: Setting value (peer's acknowledged value)
 * Thread-safe: Yes
 */
extern uint32_t SocketHTTP2_Conn_get_setting (SocketHTTP2_Conn_T conn,
                                              SocketHTTP2_SettingsId id);

/**
 * SocketHTTP2_Conn_get_local_setting - Get our setting value
 * @conn: Connection
 * @id: Setting identifier
 *
 * Returns: Our setting value
 * Thread-safe: Yes
 */
extern uint32_t SocketHTTP2_Conn_get_local_setting (SocketHTTP2_Conn_T conn,
                                                    SocketHTTP2_SettingsId id);

/**
 * SocketHTTP2_Conn_ping - Send PING frame
 * @conn: Connection
 * @opaque: 8 bytes opaque data (NULL for auto-generate)
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTP2_Conn_ping (SocketHTTP2_Conn_T conn,
                                  const unsigned char opaque[8]);

/**
 * SocketHTTP2_Conn_goaway - Send GOAWAY frame
 * @conn: Connection
 * @error_code: Error code
 * @debug_data: Optional debug data (NULL for none)
 * @debug_len: Debug data length
 *
 * Initiates graceful shutdown. No new streams will be accepted.
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTP2_Conn_goaway (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_ErrorCode error_code,
                                    const void *debug_data, size_t debug_len);

/**
 * SocketHTTP2_Conn_last_stream_id - Get last processed stream ID
 * @conn: Connection
 *
 * Returns: Last peer stream ID processed
 * Thread-safe: Yes
 */
extern uint32_t SocketHTTP2_Conn_last_stream_id (SocketHTTP2_Conn_T conn);

/* ============================================================================
 * Connection Flow Control
 * ============================================================================ */

/**
 * SocketHTTP2_Conn_window_update - Update connection-level window
 * @conn: Connection
 * @increment: Window size increment (1 to 2^31-1)
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTP2_Conn_window_update (SocketHTTP2_Conn_T conn,
                                           uint32_t increment);

/**
 * SocketHTTP2_Conn_send_window - Get available send window
 * @conn: Connection
 *
 * Returns: Available bytes in connection send window
 * Thread-safe: Yes
 */
extern int32_t SocketHTTP2_Conn_send_window (SocketHTTP2_Conn_T conn);

/**
 * SocketHTTP2_Conn_recv_window - Get receive window
 * @conn: Connection
 *
 * Returns: Current receive window size
 * Thread-safe: Yes
 */
extern int32_t SocketHTTP2_Conn_recv_window (SocketHTTP2_Conn_T conn);

/* ============================================================================
 * Stream Management
 * ============================================================================ */

/**
 * SocketHTTP2_Stream_new - Create new stream
 * @conn: Parent connection
 *
 * Client streams use odd IDs (1, 3, 5, ...)
 * Server streams (push) use even IDs (2, 4, 6, ...)
 *
 * Returns: New stream with auto-assigned ID, or NULL if limit reached
 * Thread-safe: No
 */
extern SocketHTTP2_Stream_T SocketHTTP2_Stream_new (SocketHTTP2_Conn_T conn);

/**
 * SocketHTTP2_Stream_id - Get stream ID
 * @stream: Stream
 *
 * Returns: Stream identifier
 * Thread-safe: Yes
 */
extern uint32_t SocketHTTP2_Stream_id (SocketHTTP2_Stream_T stream);

/**
 * SocketHTTP2_Stream_state - Get stream state
 * @stream: Stream
 *
 * Returns: Current stream state
 * Thread-safe: Yes
 */
extern SocketHTTP2_StreamState SocketHTTP2_Stream_state (SocketHTTP2_Stream_T stream);

/**
 * SocketHTTP2_Stream_close - Close stream
 * @stream: Stream to close
 * @error_code: Error code (HTTP2_NO_ERROR for normal close)
 *
 * Thread-safe: No
 */
extern void SocketHTTP2_Stream_close (SocketHTTP2_Stream_T stream,
                                      SocketHTTP2_ErrorCode error_code);

/**
 * SocketHTTP2_Stream_get_userdata - Get user data
 * @stream: Stream
 *
 * Returns: User data pointer
 * Thread-safe: Yes
 */
extern void *SocketHTTP2_Stream_get_userdata (SocketHTTP2_Stream_T stream);

/**
 * SocketHTTP2_Stream_set_userdata - Set user data
 * @stream: Stream
 * @userdata: User data pointer
 *
 * Thread-safe: No
 */
extern void SocketHTTP2_Stream_set_userdata (SocketHTTP2_Stream_T stream,
                                             void *userdata);

/* ============================================================================
 * Sending (Client/Server)
 * ============================================================================ */

/**
 * SocketHTTP2_Stream_send_headers - Send HEADERS frame
 * @stream: Stream
 * @headers: Header array (includes pseudo-headers)
 * @header_count: Number of headers
 * @end_stream: Set END_STREAM flag (no body follows)
 *
 * Pseudo-headers for requests: :method, :scheme, :authority, :path
 * Pseudo-headers for responses: :status
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTP2_Stream_send_headers (SocketHTTP2_Stream_T stream,
                                            const SocketHPACK_Header *headers,
                                            size_t header_count, int end_stream);

/**
 * SocketHTTP2_Stream_send_request - Send request (convenience)
 * @stream: Stream
 * @request: HTTP request
 * @end_stream: No body follows
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTP2_Stream_send_request (SocketHTTP2_Stream_T stream,
                                            const SocketHTTP_Request *request,
                                            int end_stream);

/**
 * SocketHTTP2_Stream_send_response - Send response (convenience)
 * @stream: Stream
 * @response: HTTP response
 * @end_stream: No body follows
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTP2_Stream_send_response (SocketHTTP2_Stream_T stream,
                                             const SocketHTTP_Response *response,
                                             int end_stream);

/**
 * SocketHTTP2_Stream_send_data - Send DATA frame
 * @stream: Stream
 * @data: Payload data
 * @len: Data length
 * @end_stream: Set END_STREAM flag
 *
 * Returns: Bytes accepted (may be less due to flow control), -1 on error
 * Thread-safe: No
 */
extern ssize_t SocketHTTP2_Stream_send_data (SocketHTTP2_Stream_T stream,
                                             const void *data, size_t len,
                                             int end_stream);

/**
 * SocketHTTP2_Stream_send_trailers - Send trailer headers
 * @stream: Stream
 * @trailers: Trailer header array
 * @count: Number of trailers
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTP2_Stream_send_trailers (SocketHTTP2_Stream_T stream,
                                             const SocketHPACK_Header *trailers,
                                             size_t count);

/* ============================================================================
 * Receiving
 * ============================================================================ */

/**
 * SocketHTTP2_Stream_recv_headers - Check for received headers
 * @stream: Stream
 * @headers: Output header array
 * @max_headers: Maximum headers to receive
 * @header_count: Output - number of headers
 * @end_stream: Output - END_STREAM was set
 *
 * Returns: 1 if headers available, 0 if not, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTP2_Stream_recv_headers (SocketHTTP2_Stream_T stream,
                                            SocketHPACK_Header *headers,
                                            size_t max_headers,
                                            size_t *header_count,
                                            int *end_stream);

/**
 * SocketHTTP2_Stream_recv_data - Receive DATA
 * @stream: Stream
 * @buf: Output buffer
 * @len: Buffer size
 * @end_stream: Output - END_STREAM was set
 *
 * Returns: Bytes received, 0 if would block, -1 on error
 * Thread-safe: No
 */
extern ssize_t SocketHTTP2_Stream_recv_data (SocketHTTP2_Stream_T stream,
                                             void *buf, size_t len,
                                             int *end_stream);

/**
 * SocketHTTP2_Stream_recv_trailers - Receive trailer headers
 * @stream: Stream
 * @trailers: Output trailer array
 * @max_trailers: Maximum trailers
 * @trailer_count: Output - number of trailers
 *
 * Returns: 1 if trailers available, 0 if not, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTP2_Stream_recv_trailers (SocketHTTP2_Stream_T stream,
                                             SocketHPACK_Header *trailers,
                                             size_t max_trailers,
                                             size_t *trailer_count);

/* ============================================================================
 * Stream Flow Control
 * ============================================================================ */

/**
 * SocketHTTP2_Stream_window_update - Update stream window
 * @stream: Stream
 * @increment: Window size increment
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTP2_Stream_window_update (SocketHTTP2_Stream_T stream,
                                             uint32_t increment);

/**
 * SocketHTTP2_Stream_send_window - Get stream send window
 * @stream: Stream
 *
 * Returns: Available bytes (minimum of stream and connection windows)
 * Thread-safe: Yes
 */
extern int32_t SocketHTTP2_Stream_send_window (SocketHTTP2_Stream_T stream);

/**
 * SocketHTTP2_Stream_recv_window - Get stream receive window
 * @stream: Stream
 *
 * Returns: Current receive window size
 * Thread-safe: Yes
 */
extern int32_t SocketHTTP2_Stream_recv_window (SocketHTTP2_Stream_T stream);

/* ============================================================================
 * Server Push (RFC 9113 Section 8.4)
 * ============================================================================ */

/**
 * SocketHTTP2_Stream_push_promise - Send PUSH_PROMISE (server only)
 * @stream: Parent stream
 * @request_headers: Pushed request headers
 * @header_count: Number of headers
 *
 * Returns: New reserved stream for pushing response, or NULL if disabled
 * Thread-safe: No
 */
extern SocketHTTP2_Stream_T SocketHTTP2_Stream_push_promise (
    SocketHTTP2_Stream_T stream, const SocketHPACK_Header *request_headers,
    size_t header_count);

/* ============================================================================
 * Callbacks
 * ============================================================================ */

/** Stream event types */
#define HTTP2_EVENT_STREAM_START 1      /**< New stream started */
#define HTTP2_EVENT_HEADERS_RECEIVED 2  /**< Headers ready */
#define HTTP2_EVENT_DATA_RECEIVED 3     /**< Data available */
#define HTTP2_EVENT_TRAILERS_RECEIVED 4 /**< Trailers ready */
#define HTTP2_EVENT_STREAM_END 5        /**< Stream ended normally */
#define HTTP2_EVENT_STREAM_RESET 6      /**< Stream reset by peer */
#define HTTP2_EVENT_PUSH_PROMISE 7      /**< Push promise received */
#define HTTP2_EVENT_WINDOW_UPDATE 8     /**< Window increased */

/**
 * Stream event callback
 */
typedef void (*SocketHTTP2_StreamCallback) (SocketHTTP2_Conn_T conn,
                                            SocketHTTP2_Stream_T stream,
                                            int event, void *userdata);

/**
 * SocketHTTP2_Conn_set_stream_callback - Set stream event callback
 * @conn: Connection
 * @callback: Callback function
 * @userdata: User data passed to callback
 *
 * Thread-safe: No
 */
extern void SocketHTTP2_Conn_set_stream_callback (
    SocketHTTP2_Conn_T conn, SocketHTTP2_StreamCallback callback,
    void *userdata);

/** Connection event types */
#define HTTP2_EVENT_SETTINGS_ACK 20     /**< SETTINGS acknowledged */
#define HTTP2_EVENT_PING_ACK 21         /**< PING response received */
#define HTTP2_EVENT_GOAWAY_RECEIVED 22  /**< GOAWAY received */
#define HTTP2_EVENT_CONNECTION_ERROR 23 /**< Connection error */

/**
 * Connection event callback
 */
typedef void (*SocketHTTP2_ConnCallback) (SocketHTTP2_Conn_T conn, int event,
                                          void *userdata);

/**
 * SocketHTTP2_Conn_set_conn_callback - Set connection callback
 * @conn: Connection
 * @callback: Callback function
 * @userdata: User data passed to callback
 *
 * Thread-safe: No
 */
extern void
SocketHTTP2_Conn_set_conn_callback (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_ConnCallback callback,
                                    void *userdata);

/* ============================================================================
 * h2c Upgrade (Cleartext HTTP/2)
 * ============================================================================ */

/**
 * SocketHTTP2_Conn_upgrade_client - Upgrade from HTTP/1.1 (client)
 * @socket: Socket after sending upgrade request
 * @settings_payload: Base64-decoded HTTP2-Settings header value
 * @settings_len: Length of settings payload
 * @arena: Memory arena
 *
 * Returns: HTTP/2 connection
 * Thread-safe: No
 */
extern SocketHTTP2_Conn_T
SocketHTTP2_Conn_upgrade_client (Socket_T socket,
                                 const unsigned char *settings_payload,
                                 size_t settings_len, Arena_T arena);

/**
 * SocketHTTP2_Conn_upgrade_server - Upgrade from HTTP/1.1 (server)
 * @socket: Socket after receiving upgrade request
 * @initial_request: The HTTP/1.1 request that triggered upgrade
 * @settings_payload: Decoded HTTP2-Settings from client
 * @settings_len: Length of settings
 * @arena: Memory arena
 *
 * Returns: HTTP/2 connection with stream 1 pre-created
 * Thread-safe: No
 */
extern SocketHTTP2_Conn_T
SocketHTTP2_Conn_upgrade_server (Socket_T socket,
                                 const SocketHTTP_Request *initial_request,
                                 const unsigned char *settings_payload,
                                 size_t settings_len, Arena_T arena);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * SocketHTTP2_error_string - Get error code description
 * @code: Error code
 *
 * Returns: Static string describing the error
 * Thread-safe: Yes
 */
extern const char *SocketHTTP2_error_string (SocketHTTP2_ErrorCode code);

/**
 * SocketHTTP2_frame_type_string - Get frame type name
 * @type: Frame type
 *
 * Returns: Static string with frame type name
 * Thread-safe: Yes
 */
extern const char *SocketHTTP2_frame_type_string (SocketHTTP2_FrameType type);

/**
 * SocketHTTP2_stream_state_string - Get stream state name
 * @state: Stream state
 *
 * Returns: Static string with state name
 * Thread-safe: Yes
 */
extern const char *
SocketHTTP2_stream_state_string (SocketHTTP2_StreamState state);

/* ============================================================================
 * Frame Parsing (Low-level API)
 * ============================================================================ */

/**
 * SocketHTTP2_frame_header_parse - Parse frame header from buffer
 * @data: Input buffer (at least HTTP2_FRAME_HEADER_SIZE bytes)
 * @header: Output header structure
 *
 * Returns: 0 on success
 * Thread-safe: Yes
 */
extern int SocketHTTP2_frame_header_parse (const unsigned char *data,
                                           SocketHTTP2_FrameHeader *header);

/**
 * SocketHTTP2_frame_header_serialize - Serialize frame header to buffer
 * @header: Header structure
 * @data: Output buffer (at least HTTP2_FRAME_HEADER_SIZE bytes)
 *
 * Thread-safe: Yes
 */
extern void SocketHTTP2_frame_header_serialize (
    const SocketHTTP2_FrameHeader *header, unsigned char *data);

#endif /* SOCKETHTTP2_INCLUDED */


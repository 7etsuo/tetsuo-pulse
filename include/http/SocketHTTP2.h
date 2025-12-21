/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @defgroup http2 HTTP/2 Protocol Implementation
 * @brief HTTP/2 (RFC 9113) support with framing, streams, flow control, and
 * HPACK integration.
 * @ingroup http
 * @{
 *
 * Complete HTTP/2 implementation including binary framing, stream
 * multiplexing, flow control, HPACK header compression, server push, and h2c
 * upgrade.
 *
 * Key features:
 * - Full RFC 9113 compliance
 * - Client and server support
 * - Automatic preface handling and SETTINGS exchange
 * - Stream lifecycle management
 * - Connection and stream flow control
 * - DoS protections (rate limits, frame size validation)
 * - Integration with SocketHTTP for semantics and SocketHPACK for compression
 *
 * @see SocketHTTP for protocol-agnostic HTTP types.
 * @see SocketHPACK for HPACK header compression.
 * @see SocketHTTP1 for HTTP/1.1 upgrade path.
 * @see SocketHTTPClient and SocketHTTPServer for high-level usage.
 */

/**
 * @file SocketHTTP2.h
 * @brief HTTP/2 protocol implementation (RFC 9113) with multiplexing and flow control.
 *
 * Thread safety: Connection instances are NOT thread-safe.
 * Use one connection per thread or external synchronization.
 *
 * Security notes (RFC 9113):
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

/* Configuration Limits (RFC 9113 Section 6.5.2) */

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

/** Default stream receive buffer size for DATA frames */
#define SOCKETHTTP2_DEFAULT_STREAM_RECV_BUF_SIZE (64 * 1024)

/** Default initial allocation for header blocks */
#define SOCKETHTTP2_DEFAULT_INITIAL_HEADER_BLOCK_SIZE (16 * 1024)

/** Maximum decoded headers per HPACK block */
#define SOCKETHTTP2_MAX_DECODED_HEADERS 128

/** Maximum CONTINUATION frames per header block (DoS protection) */
#define SOCKETHTTP2_MAX_CONTINUATION_FRAMES 32

/** Number of pseudo-headers in HTTP/2 requests (:method, :scheme, :authority,
 * :path) */
#define HTTP2_REQUEST_PSEUDO_HEADER_COUNT 4

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

/**
 * PING rate limiting (DoS protection)
 *
 * Prevents PING flood attacks.
 */
#ifndef SOCKETHTTP2_PING_RATE_LIMIT
#define SOCKETHTTP2_PING_RATE_LIMIT 50 /* Max PING frames per window */
#endif

#ifndef SOCKETHTTP2_PING_RATE_WINDOW_MS
#define SOCKETHTTP2_PING_RATE_WINDOW_MS                                       \
  1000 /* Rate window in milliseconds                                         \
        */
#endif

/**
 * SETTINGS rate limiting (DoS protection)
 *
 * Prevents SETTINGS flood for CPU/memory exhaustion.
 */
#ifndef SOCKETHTTP2_SETTINGS_RATE_LIMIT
#define SOCKETHTTP2_SETTINGS_RATE_LIMIT                                       \
  10 /* Max SETTINGS frames per window                                        \
      */
#endif

#ifndef SOCKETHTTP2_SETTINGS_RATE_WINDOW_MS
#define SOCKETHTTP2_SETTINGS_RATE_WINDOW_MS                                   \
  5000 /* Longer window for config changes */
#endif

#ifndef SOCKETHTTP2_DEFAULT_SETTINGS_TIMEOUT_MS
#define SOCKETHTTP2_DEFAULT_SETTINGS_TIMEOUT_MS 30000 /* 30 seconds */
#endif

#ifndef SOCKETHTTP2_DEFAULT_PING_TIMEOUT_MS
#define SOCKETHTTP2_DEFAULT_PING_TIMEOUT_MS 30000 /* 30 seconds */
#endif

#ifndef SOCKETHTTP2_MAX_WINDOW_SIZE
#define SOCKETHTTP2_MAX_WINDOW_SIZE 0x7FFFFFFF /* 2^31 - 1 */
#endif

#ifndef SOCKETHTTP2_IO_BUFFER_SIZE
#define SOCKETHTTP2_IO_BUFFER_SIZE SOCKETHTTP2_DEFAULT_STREAM_RECV_BUF_SIZE
#endif

/** Frame header size in bytes */
#define HTTP2_FRAME_HEADER_SIZE 9

/** WINDOW_UPDATE and RST_STREAM payload size */
#define HTTP2_WINDOW_UPDATE_PAYLOAD_SIZE 4

/** PUSH_PROMISE promised stream ID size */
#define HTTP2_PUSH_PROMISE_ID_SIZE 4

/** PRIORITY payload size (deprecated) */
#define HTTP2_PRIORITY_PAYLOAD_SIZE 5

/** Connection preface magic string length */
#define HTTP2_PREFACE_SIZE 24

/** Stream hash table size (prime for better distribution) */
#define HTTP2_STREAM_HASH_SIZE 1021

/* Exception Types */

/**
 * @brief Protocol-level error (connection must close)
 * @ingroup http2
 */
extern const Except_T SocketHTTP2_ProtocolError;

/**
 * @brief Stream-level error (stream reset, connection continues)
 * @ingroup http2
 */
extern const Except_T SocketHTTP2_StreamError;

/**
 * @brief Flow control violation
 * @ingroup http2
 */
extern const Except_T SocketHTTP2_FlowControlError;

/* Frame Types (RFC 9113 Section 6) */

/**
 * @brief HTTP/2 frame types (RFC 9113 Section 6)
 * @ingroup http2
 */
typedef enum
{
  HTTP2_FRAME_DATA = 0x0,          /**< Section 6.1 - Payload data */
  HTTP2_FRAME_HEADERS = 0x1,       /**< Section 6.2 - Header block */
  HTTP2_FRAME_PRIORITY = 0x2,      /**< Section 6.3 - Deprecated */
  HTTP2_FRAME_RST_STREAM = 0x3,    /**< Section 6.4 - Stream termination */
  HTTP2_FRAME_SETTINGS = 0x4,      /**< Section 6.5 - Configuration */
  HTTP2_FRAME_PUSH_PROMISE = 0x5,  /**< Section 6.6 - Server push */
  HTTP2_FRAME_PING = 0x6,          /**< Section 6.7 - Keep-alive/RTT */
  HTTP2_FRAME_GOAWAY = 0x7,        /**< Section 6.8 - Graceful shutdown */
  HTTP2_FRAME_WINDOW_UPDATE = 0x8, /**< Section 6.9 - Flow control */
  HTTP2_FRAME_CONTINUATION = 0x9   /**< Section 6.10 - Header continuation */
} SocketHTTP2_FrameType;

/**
 * @brief HTTP/2 frame flags (bitmasks, meanings depend on frame type)
 * @ingroup http2
 */
#define HTTP2_FLAG_END_STREAM 0x01 /**< DATA, HEADERS */
#define HTTP2_FLAG_END_HEADERS                                                \
  0x04                           /**< HEADERS, PUSH_PROMISE, CONTINUATION     \
                                  */
#define HTTP2_FLAG_PADDED 0x08   /**< DATA, HEADERS, PUSH_PROMISE */
#define HTTP2_FLAG_PRIORITY 0x20 /**< HEADERS */
#define HTTP2_FLAG_ACK 0x01      /**< SETTINGS, PING */

/* Error Codes (RFC 9113 Section 7) */

/**
 * @brief HTTP/2 error codes for RST_STREAM and GOAWAY (RFC 9113 Section 7)
 * @ingroup http2
 *
 * Standard error codes. HTTP2_NO_ERROR indicates graceful closure.
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

/* Settings Identifiers (RFC 9113 Section 6.5.2) */

/**
 * @brief HTTP/2 settings parameters (RFC 9113 Section 6.5.2)
 * @ingroup http2
 */
typedef enum
{
  HTTP2_SETTINGS_HEADER_TABLE_SIZE = 0x1,
  HTTP2_SETTINGS_ENABLE_PUSH = 0x2,
  HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
  HTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 0x4,
  HTTP2_SETTINGS_MAX_FRAME_SIZE = 0x5,
  HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x6,
  HTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x8
} SocketHTTP2_SettingsId;

/** Number of defined settings */
#define HTTP2_SETTINGS_COUNT 7

/* Stream States (RFC 9113 Section 5.1) */

/**
 * @brief HTTP/2 stream states (RFC 9113 Section 5.1)
 * @ingroup http2
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

/* Frame Header */

/**
 * @brief HTTP/2 frame header (9 bytes on wire)
 * @ingroup http2
 */
typedef struct
{
  uint32_t length;    /**< 24-bit payload length */
  uint8_t type;       /**< Frame type */
  uint8_t flags;      /**< Frame flags */
  uint32_t stream_id; /**< 31-bit stream ID (R bit reserved) */
} SocketHTTP2_FrameHeader;

/* Connection Role */

/**
 * @brief HTTP/2 endpoint role
 * @ingroup http2
 */
typedef enum
{
  HTTP2_ROLE_CLIENT,
  HTTP2_ROLE_SERVER
} SocketHTTP2_Role;

/* Connection Configuration */

/**
 * @brief HTTP/2 connection configuration
 * @ingroup http2
 */
typedef struct
{
  SocketHTTP2_Role role;

  /* Local settings (we send to peer) */
  uint32_t header_table_size;
  uint32_t enable_push;
  uint32_t max_concurrent_streams; /**< Max concurrent streams
                                      (SETTINGS_MAX_CONCURRENT_STREAMS) */
  uint32_t max_stream_open_rate;   /**< Max stream opens per second for rate
                                      limiting */
  uint32_t max_stream_open_burst;  /**< Burst allowance for stream opens */
  uint32_t max_stream_close_rate;  /**< Max stream closes/RST per second */
  uint32_t max_stream_close_burst; /**< Burst for closes/RST */
  uint32_t initial_window_size;
  uint32_t max_frame_size;
  uint32_t max_header_list_size;
  uint32_t enable_connect_protocol; /**< Enable extended CONNECT methods
                                       (SETTINGS_ENABLE_CONNECT_PROTOCOL) */

  /* Connection-level flow control */
  uint32_t connection_window_size;

  /* Timeouts (milliseconds) */
  int settings_timeout_ms;
  int ping_timeout_ms;
  int idle_timeout_ms;
} SocketHTTP2_Config;

/* Opaque Types */

/**
 * @brief HTTP/2 connection (opaque type)
 * @ingroup http2
 */
typedef struct SocketHTTP2_Conn *SocketHTTP2_Conn_T;

/**
 * @brief HTTP/2 stream (opaque type)
 * @ingroup http2
 */
typedef struct SocketHTTP2_Stream *SocketHTTP2_Stream_T;

/* Setting Entry (for SETTINGS frame) */

/**
 * @brief Single setting entry (for SETTINGS frame)
 * @ingroup http2
 */
typedef struct
{
  uint16_t id;
  uint32_t value;
} SocketHTTP2_Setting;

/* Configuration Functions */

/**
 * @brief Initialize HTTP/2 configuration with RFC 9113 compliant defaults.
 * @ingroup http2
 *
 * Sets recommended defaults: 100 max streams, 64KB window, 16KB frames,
 * DoS rate limits, and role-specific push settings.
 *
 * @param[out] config Configuration structure to populate
 * @param[in] role Client or server role
 *
 * @code{.c}
 * SocketHTTP2_Config config;
 * SocketHTTP2_config_defaults(&config, HTTP2_ROLE_CLIENT);
 * config.max_concurrent_streams = 50; // Customize as needed
 * SocketHTTP2_Conn_T conn = SocketHTTP2_Conn_new(sock, &config, arena);
 * @endcode
 */
extern void SocketHTTP2_config_defaults (SocketHTTP2_Config *config,
                                         SocketHTTP2_Role role);

/* Connection Lifecycle */

/**
 * @brief Create a new HTTP/2 connection instance.
 * @ingroup http2
 *
 * Initializes connection over provided socket with preface/settings handling
 * and flow control. Call SocketHTTP2_Conn_handshake() after creation.
 *
 * @param socket Underlying TCP socket (connected, after TLS if needed)
 * @param config Configuration (NULL uses client defaults)
 * @param arena Memory arena
 * @return New connection, or NULL on failure
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * Socket_T sock = Socket_connect("example.com", 443);
 * SocketHTTP2_Config config;
 * SocketHTTP2_config_defaults(&config, HTTP2_ROLE_CLIENT);
 * SocketHTTP2_Conn_T conn = SocketHTTP2_Conn_new(sock, &config, arena);
 * SocketHTTP2_Conn_handshake(conn);
 * @endcode
 */
extern SocketHTTP2_Conn_T
SocketHTTP2_Conn_new (Socket_T socket, const SocketHTTP2_Config *config,
                      Arena_T arena);

/**
 * @brief Dispose of HTTP/2 connection and release all resources.
 * @ingroup http2
 *
 * Cleans up connection, streams, HPACK state, and buffers. Does NOT close
 * underlying socket. Safe to call on NULL.
 *
 * @param conn Pointer to connection (set to NULL after cleanup)
 */
extern void SocketHTTP2_Conn_free (SocketHTTP2_Conn_T *conn);

/**
 * @brief Complete HTTP/2 connection preface and initial settings exchange (RFC 9113 Section 3.4-3.5).
 * @ingroup http2
 *
 * Call repeatedly until returns 0. Integrate with event loop for non-blocking I/O.
 *
 * @param conn Active connection
 * @return 0 = complete, 1 = in progress, -1 = error
 *
 * @code{.c}
 * while ((status = SocketHTTP2_Conn_handshake(conn)) == 1) {
 *     SocketHTTP2_Conn_process(conn, poll_events);
 *     SocketHTTP2_Conn_flush(conn);
 * }
 * @endcode
 */
extern int SocketHTTP2_Conn_handshake (SocketHTTP2_Conn_T conn);

/**
 * @brief Process socket events and HTTP/2 frames.
 * @ingroup http2
 *
 * Main event loop entry point. Reads from socket, parses frames, dispatches to
 * handlers, invokes callbacks. Pair with Conn_flush() to send pending responses.
 *
 * @param conn HTTP/2 connection
 * @param events Poll events (POLL_READ | POLL_WRITE | POLL_ERROR | POLL_HANGUP)
 * @return 0 = success, 1 = need more data, -1 = error
 *
 * @code{.c}
 * int r = SocketHTTP2_Conn_process(conn, events);
 * if (r < 0) {
 *     SocketHTTP2_Conn_goaway(conn, HTTP2_PROTOCOL_ERROR, NULL, 0);
 *     SocketHTTP2_Conn_free(&conn);
 * }
 * SocketHTTP2_Conn_flush(conn);
 * @endcode
 */
extern int SocketHTTP2_Conn_process (SocketHTTP2_Conn_T conn, unsigned events);

/**
 * @brief Flush pending HTTP/2 frames to socket.
 * @ingroup http2
 *
 * Sends buffered output frames. Call after Conn_process() or sending data/headers.
 *
 * @param conn Connection with buffered output
 * @return 0 = all sent, 1 = would block (poll for WRITE), -1 = error
 */
extern int SocketHTTP2_Conn_flush (SocketHTTP2_Conn_T conn);

/**
 * @brief Get underlying socket
 * @ingroup http2
 * @param conn  Connection
 *
 * @return Socket instance
 * @threadsafe Yes
 */
extern Socket_T SocketHTTP2_Conn_socket (SocketHTTP2_Conn_T conn);

/**
 * @brief Check if connection closed
 * @ingroup http2
 * @param conn  Connection
 *
 * @return 1 if closed (GOAWAY sent/received), 0 otherwise
 * @threadsafe Yes
 */
extern int SocketHTTP2_Conn_is_closed (SocketHTTP2_Conn_T conn);

/**
 * @brief Get connection's arena
 * @ingroup http2
 * @param conn  Connection
 *
 * @return Arena instance
 * @threadsafe Yes
 */
extern Arena_T SocketHTTP2_Conn_arena (SocketHTTP2_Conn_T conn);

/* Connection Control */

/**
 * @brief Send SETTINGS frame
 * @ingroup http2
 */
extern int SocketHTTP2_Conn_settings (SocketHTTP2_Conn_T conn,
                                      const SocketHTTP2_Setting *settings,
                                      size_t count);

/**
 * @brief Get peer's setting value
 * @ingroup http2
 */
extern uint32_t SocketHTTP2_Conn_get_setting (SocketHTTP2_Conn_T conn,
                                              SocketHTTP2_SettingsId id);

/**
 * @brief Get our setting value
 * @ingroup http2
 */
extern uint32_t SocketHTTP2_Conn_get_local_setting (SocketHTTP2_Conn_T conn,
                                                    SocketHTTP2_SettingsId id);

/**
 * @brief Send PING frame
 * @ingroup http2
 */
extern int SocketHTTP2_Conn_ping (SocketHTTP2_Conn_T conn,
                                  const unsigned char opaque[8]);

/**
 * @brief Send PING and wait for response with timeout
 * @ingroup http2
 *
 * Blocks until ACK received or timeout. Useful for RTT measurement.
 *
 * @param conn HTTP/2 connection
 * @param timeout_ms Maximum wait time in milliseconds
 * @return RTT in milliseconds on success, -1 on timeout or error
 */
extern int SocketHTTP2_Conn_ping_wait (SocketHTTP2_Conn_T conn, int timeout_ms);

/**
 * @brief Get current number of active streams
 * @ingroup http2
 */
extern uint32_t SocketHTTP2_Conn_get_concurrent_streams (SocketHTTP2_Conn_T conn);

/**
 * @brief Set maximum concurrent streams limit
 * @ingroup http2
 *
 * Sends SETTINGS frame to peer. Exceeding streams receive REFUSED_STREAM.
 */
extern int SocketHTTP2_Conn_set_max_concurrent (SocketHTTP2_Conn_T conn,
                                                uint32_t max);

/**
 * @brief Send GOAWAY frame
 * @ingroup http2
 *
 * Initiates graceful shutdown. No new streams will be accepted.
 */
extern int SocketHTTP2_Conn_goaway (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_ErrorCode error_code,
                                    const void *debug_data, size_t debug_len);

/**
 * @brief Get last processed stream ID
 * @ingroup http2
 */
extern uint32_t SocketHTTP2_Conn_last_stream_id (SocketHTTP2_Conn_T conn);

/* Connection Flow Control */

/**
 * @brief Update connection-level window
 * @ingroup http2
 */
extern int SocketHTTP2_Conn_window_update (SocketHTTP2_Conn_T conn,
                                           uint32_t increment);

/**
 * @brief Get available send window
 * @ingroup http2
 */
extern int32_t SocketHTTP2_Conn_send_window (SocketHTTP2_Conn_T conn);

/**
 * @brief Get receive window
 * @ingroup http2
 */
extern int32_t SocketHTTP2_Conn_recv_window (SocketHTTP2_Conn_T conn);

/* Stream Management */

/**
 * @brief Create new stream (odd IDs for client, even for server push)
 * @ingroup http2
 */
extern SocketHTTP2_Stream_T SocketHTTP2_Stream_new (SocketHTTP2_Conn_T conn);

/**
 * @brief Look up an existing stream by ID
 * @ingroup http2
 */
extern SocketHTTP2_Stream_T SocketHTTP2_Conn_get_stream (SocketHTTP2_Conn_T conn,
                                                         uint32_t stream_id);

/**
 * @brief Get stream ID
 * @ingroup http2
 */
extern uint32_t SocketHTTP2_Stream_id (SocketHTTP2_Stream_T stream);

/**
 * @brief Get stream state
 * @ingroup http2
 */
extern SocketHTTP2_StreamState
SocketHTTP2_Stream_state (SocketHTTP2_Stream_T stream);

/**
 * @brief Close HTTP/2 stream
 * @ingroup http2
 */
extern void SocketHTTP2_Stream_close (SocketHTTP2_Stream_T stream,
                                      SocketHTTP2_ErrorCode error_code);

/**
 * @brief Get user data
 * @ingroup http2
 */
extern void *SocketHTTP2_Stream_get_userdata (SocketHTTP2_Stream_T stream);

/**
 * @brief Set user data
 * @ingroup http2
 */
extern void SocketHTTP2_Stream_set_userdata (SocketHTTP2_Stream_T stream,
                                             void *userdata);

/* Sending (Client/Server) */

/**
 * @brief Send HEADERS frame
 * @ingroup http2
 *
 * Required pseudo-headers: requests (:method, :scheme, :authority, :path); responses (:status).
 */
extern int SocketHTTP2_Stream_send_headers (SocketHTTP2_Stream_T stream,
                                            const SocketHPACK_Header *headers,
                                            size_t header_count,
                                            int end_stream);

/**
 * @brief Send request (convenience)
 * @ingroup http2
 */
extern int SocketHTTP2_Stream_send_request (SocketHTTP2_Stream_T stream,
                                            const SocketHTTP_Request *request,
                                            int end_stream);

/**
 * @brief Send response (convenience)
 * @ingroup http2
 */
extern int
SocketHTTP2_Stream_send_response (SocketHTTP2_Stream_T stream,
                                  const SocketHTTP_Response *response,
                                  int end_stream);

/**
 * @brief Send DATA frame
 * @ingroup http2
 *
 * @return Bytes accepted (may be less due to flow control), -1 on error
 */
extern ssize_t SocketHTTP2_Stream_send_data (SocketHTTP2_Stream_T stream,
                                             const void *data, size_t len,
                                             int end_stream);

/**
 * @brief Send trailer headers
 * @ingroup http2
 */
extern int
SocketHTTP2_Stream_send_trailers (SocketHTTP2_Stream_T stream,
                                  const SocketHPACK_Header *trailers,
                                  size_t count);

/* Receiving */

/**
 * @brief Check for received headers
 * @ingroup http2
 * @return 1 if headers available, 0 if not, -1 on error
 */
extern int SocketHTTP2_Stream_recv_headers (SocketHTTP2_Stream_T stream,
                                            SocketHPACK_Header *headers,
                                            size_t max_headers,
                                            size_t *header_count,
                                            int *end_stream);

/**
 * @brief Receive DATA
 * @ingroup http2
 * @return Bytes received, 0 if would block, -1 on error
 */
extern ssize_t SocketHTTP2_Stream_recv_data (SocketHTTP2_Stream_T stream,
                                             void *buf, size_t len,
                                             int *end_stream);

/**
 * @brief Receive trailer headers
 * @ingroup http2
 * @return 1 if trailers available, 0 if not, -1 on error
 */
extern int SocketHTTP2_Stream_recv_trailers (SocketHTTP2_Stream_T stream,
                                             SocketHPACK_Header *trailers,
                                             size_t max_trailers,
                                             size_t *trailer_count);

/* Stream Flow Control */

/**
 * @brief Update stream window
 * @ingroup http2
 */
extern int SocketHTTP2_Stream_window_update (SocketHTTP2_Stream_T stream,
                                             uint32_t increment);

/**
 * @brief Get stream send window
 * @ingroup http2
 * @return Available bytes (minimum of stream and connection windows)
 */
extern int32_t SocketHTTP2_Stream_send_window (SocketHTTP2_Stream_T stream);

/**
 * @brief Get stream receive window
 * @ingroup http2
 */
extern int32_t SocketHTTP2_Stream_recv_window (SocketHTTP2_Stream_T stream);

/* Server Push (RFC 9113 Section 8.4) */

/**
 * @brief Send PUSH_PROMISE (server only)
 * @ingroup http2
 * @return New reserved stream for pushing response, or NULL if disabled
 */
extern SocketHTTP2_Stream_T
SocketHTTP2_Stream_push_promise (SocketHTTP2_Stream_T stream,
                                 const SocketHPACK_Header *request_headers,
                                 size_t header_count);

/* Callbacks */

/** Stream event types */
#define HTTP2_EVENT_STREAM_START 1      /**< New stream started */
#define HTTP2_EVENT_HEADERS_RECEIVED 2  /**< Headers ready */
#define HTTP2_EVENT_DATA_RECEIVED 3     /**< Data available */
#define HTTP2_EVENT_TRAILERS_RECEIVED 4 /**< Trailers ready */
#define HTTP2_EVENT_STREAM_END 5        /**< Stream ended normally */
#define HTTP2_EVENT_STREAM_RESET 6      /**< Stream reset by peer */
#define HTTP2_EVENT_PUSH_PROMISE 7      /**< Push promise received */
#define HTTP2_EVENT_WINDOW_UPDATE 8     /**< Window increased */

/** Stream event callback */
typedef void (*SocketHTTP2_StreamCallback) (SocketHTTP2_Conn_T conn,
                                            SocketHTTP2_Stream_T stream,
                                            int event, void *userdata);

/**
 * @brief Set stream event callback
 * @ingroup http2
 */
extern void
SocketHTTP2_Conn_set_stream_callback (SocketHTTP2_Conn_T conn,
                                      SocketHTTP2_StreamCallback callback,
                                      void *userdata);

/** Connection event types */
#define HTTP2_EVENT_SETTINGS_ACK 20     /**< SETTINGS acknowledged */
#define HTTP2_EVENT_PING_ACK 21         /**< PING response received */
#define HTTP2_EVENT_GOAWAY_RECEIVED 22  /**< GOAWAY received */
#define HTTP2_EVENT_CONNECTION_ERROR 23 /**< Connection error */

/** Connection event callback */
typedef void (*SocketHTTP2_ConnCallback) (SocketHTTP2_Conn_T conn, int event,
                                          void *userdata);

/**
 * @brief Set connection callback
 * @ingroup http2
 */
extern void
SocketHTTP2_Conn_set_conn_callback (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_ConnCallback callback,
                                    void *userdata);

/* h2c Upgrade (Cleartext HTTP/2) */

/**
 * @brief Upgrade from HTTP/1.1 (client)
 * @ingroup http2
 */
extern SocketHTTP2_Conn_T
SocketHTTP2_Conn_upgrade_client (Socket_T socket,
                                 const unsigned char *settings_payload,
                                 size_t settings_len, Arena_T arena);

/**
 * @brief Upgrade from HTTP/1.1 (server)
 * @ingroup http2
 * @return HTTP/2 connection with stream 1 pre-created
 */
extern SocketHTTP2_Conn_T SocketHTTP2_Conn_upgrade_server (
    Socket_T socket, const SocketHTTP_Request *initial_request,
    const unsigned char *settings_payload, size_t settings_len, Arena_T arena);

/* Utility Functions */

/**
 * @brief Get error code description
 * @ingroup http2
 */
extern const char *SocketHTTP2_error_string (SocketHTTP2_ErrorCode code);

/**
 * @brief Get frame type name
 * @ingroup http2
 */
extern const char *SocketHTTP2_frame_type_string (SocketHTTP2_FrameType type);

/**
 * @brief Get stream state name
 * @ingroup http2
 */
extern const char *
SocketHTTP2_stream_state_string (SocketHTTP2_StreamState state);

/* Stream Data API (duplicate declarations removed - see Sending/Receiving sections above) */

/**
 * @brief Get connection from stream
 * @ingroup http2
 */
extern SocketHTTP2_Conn_T
SocketHTTP2_Stream_get_connection (SocketHTTP2_Stream_T stream);

/* Frame Parsing (Low-level API) */

/**
 * @brief Parse frame header from buffer
 * @ingroup http2
 * @return 0 on success, -1 on invalid input
 */
extern int SocketHTTP2_frame_header_parse (const unsigned char *data,
                                           size_t input_len,
                                           SocketHTTP2_FrameHeader *header);

/**
 * @brief Serialize frame header to buffer
 * @ingroup http2
 */
extern void
SocketHTTP2_frame_header_serialize (const SocketHTTP2_FrameHeader *header,
                                    unsigned char *data);

/** @} */ /* http2 */

#endif /* SOCKETHTTP2_INCLUDED */

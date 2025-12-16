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
 * @ingroup http22
 * @brief HTTP/2 protocol implementation (RFC 9113) with multiplexing and flow
 * control.
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
 *
 * @see SocketHTTP2_Conn_new() for creating HTTP/2 connections.
 * @see SocketHTTP2_Stream_send_headers() for stream operations.
 * @see SocketHPACK.h for header compression integration.
 * @see SocketHTTP_Headers_T for core HTTP types and utilities.
 * @see SocketHTTPClient_T for HTTP client functionality.
 * @see SocketHTTPServer_T for HTTP server functionality.
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
 * ============================================================================
 */

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

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @brief Protocol-level error (connection must close)
 * @ingroup http2
 *
 * Thrown for fatal protocol errors requiring connection termination.
 * @see SocketHTTP2_Conn_free() for cleanup after error.
 */
extern const Except_T SocketHTTP2_ProtocolError;

/**
 * @brief Stream-level error (stream reset, connection continues)
 * @ingroup http2
 *
 * Thrown for stream-specific errors; other streams may continue.
 * @see SocketHTTP2_Stream_close() for explicit stream termination.
 */
extern const Except_T SocketHTTP2_StreamError;

/**
 * @brief Flow control violation
 * @ingroup http2
 *
 * Thrown when flow control limits (window size) are exceeded.
 * @see SocketHTTP2_Conn_window_update() to increase windows.
 * @see SocketHTTP2_Stream_window_update() for stream windows.
 */
extern const Except_T SocketHTTP2_FlowControlError;

/* ============================================================================
 * Frame Types (RFC 9113 Section 6)
 * ============================================================================
 */

/**
 * @brief HTTP/2 frame types (RFC 9113 Section 6)
 * @ingroup http2
 *
 * Enumerates all HTTP/2 frame types used in binary framing protocol.
 * @see SocketHTTP2_frame_type_string() for string representation.
 * @see SocketHTTP2_FrameHeader for frame header structure.
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
 * @brief HTTP/2 frame flags (bitmasks).
 * @ingroup http2
 *
 * Flags set in the 8-bit flags field of each frame header.
 * Specific meanings depend on frame type.
 * @see SocketHTTP2_FrameType
 * @see SocketHTTP2_FrameHeader
 */
/* Frame flags */
#define HTTP2_FLAG_END_STREAM 0x01 /**< DATA, HEADERS */
#define HTTP2_FLAG_END_HEADERS                                                \
  0x04                           /**< HEADERS, PUSH_PROMISE, CONTINUATION     \
                                  */
#define HTTP2_FLAG_PADDED 0x08   /**< DATA, HEADERS, PUSH_PROMISE */
#define HTTP2_FLAG_PRIORITY 0x20 /**< HEADERS */
#define HTTP2_FLAG_ACK 0x01      /**< SETTINGS, PING */

/* ============================================================================
 * Error Codes (RFC 9113 Section 7)
 * ============================================================================
 */

/**
 * @brief HTTP/2 error codes for RST_STREAM and GOAWAY (RFC 9113 Section 7)
 * @ingroup http2
 *
 * Standard error codes used in RST_STREAM and GOAWAY frames.
 * HTTP2_NO_ERROR indicates graceful closure without error.
 *
 * ## Error Code Usage in Header Validation
 *
 * | Error Code | Used For | Frame Type |
 * |------------|----------|------------|
 * | HTTP2_PROTOCOL_ERROR | Invalid pseudo-headers, forbidden headers, TE restrictions | RST_STREAM (requests), GOAWAY (responses) |
 * | HTTP2_COMPRESSION_ERROR | HPACK decompression failures | GOAWAY |
 * | HTTP2_ENHANCE_YOUR_CALM | Header list size exceeded, CONTINUATION flood | RST_STREAM |
 *
 * ## Header Validation Errors
 *
 * ### Stream-Level Errors (RST_STREAM)
 * - Pseudo-header order violations (pseudo after regular headers)
 * - Duplicate pseudo-headers
 * - Missing required pseudo-headers in requests
 * - Invalid :method values
 * - Forbidden connection-specific headers in requests
 * - TE header with invalid values in requests
 *
 * ### Connection-Level Errors (GOAWAY)
 * - Missing :status in responses
 * - Invalid :status values in responses
 * - Unknown pseudo-headers
 * - Protocol violations in header processing
 *
 * @see SocketHTTP2_error_string() for descriptive strings.
 * @see SocketHTTP2_Conn_goaway() to send GOAWAY with error code.
 * @see SocketHTTP2_Stream_close() to send RST_STREAM.
 * @see http2_validate_headers() for validation implementation.
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
 * ============================================================================
 */

/**
 * @brief HTTP/2 settings parameters (RFC 9113 Section 6.5.2)
 * @ingroup http2
 *
 * Identifiers for SETTINGS frame parameters exchanged during connection setup.
 * @see SocketHTTP2_Config for configuration structure.
 * @see SocketHTTP2_Conn_settings() to send SETTINGS frame.
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

/* ============================================================================
 * Stream States (RFC 9113 Section 5.1)
 * ============================================================================
 */

/**
 * @brief HTTP/2 stream states (RFC 9113 Section 5.1)
 * @ingroup http2
 *
 * Stream lifecycle states managed by HTTP/2 state machine.
 * Transitions driven by frame receipt and endpoint actions.
 * @see SocketHTTP2_Stream_state() to query current state.
 * @see SocketHTTP2_stream_state_string() for string names.
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
 * ============================================================================
 */

/**
 * @brief HTTP/2 frame header (9 bytes on wire)
 * @ingroup http2
 *
 * Every HTTP/2 frame begins with a fixed 9-byte header containing length,
 * type, flags, and stream ID. Stream ID 0 is reserved for connection-level
 * frames.
 * @see SocketHTTP2_frame_header_parse() to parse from wire format.
 * @see SocketHTTP2_frame_header_serialize() to encode to wire format.
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
 * ============================================================================
 */

/**
 * @brief HTTP/2 endpoint role
 * @ingroup http2
 *
 * Determines client or server behavior in connection setup and frame
 * processing. Clients initiate with preface; servers validate it.
 * @see SocketHTTP2_config_defaults() which requires role.
 * @see SocketHTTP2_Conn_new() for role-based connection creation.
 */
typedef enum
{
  HTTP2_ROLE_CLIENT,
  HTTP2_ROLE_SERVER
} SocketHTTP2_Role;

/* ============================================================================
 * Connection Configuration
 * ============================================================================
 */

/**
 * @brief HTTP/2 connection configuration
 * @ingroup http2
 *
 * Configuration parameters for HTTP/2 connections, including settings to send
 * to peer and local limits for resource management.
 *
 * Defaults provided by SocketHTTP2_config_defaults().
 * @see SocketHTTP2_config_defaults() to initialize with RFC-compliant values.
 * @see SocketHTTP2_SettingsId for setting identifiers.
 * @see SocketHTTP2_Conn_new() which uses this config.
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

/* ============================================================================
 * Opaque Types
 * ============================================================================
 */

/**
 * @brief HTTP/2 connection (opaque type)
 * @ingroup http22
 *
 * Manages connection state, streams, flow control windows, and frame
 * processing. Not thread-safe; use one per thread or synchronize externally.
 * @see SocketHTTP2_Conn_new() for creation.
 * @see SocketHTTP2_Conn_free() for destruction.
 * @see SocketHTTP2_Conn_process() for event-driven processing.
 */
typedef struct SocketHTTP2_Conn *SocketHTTP2_Conn_T;

/**
 * @brief HTTP/2 stream (opaque type)
 * @ingroup http22
 *
 * Represents a single bidirectional stream within an HTTP/2 connection.
 * Supports headers, data, trailers, and flow control.
 * @see SocketHTTP2_Stream_new() for creation.
 * @see SocketHTTP2_Stream_close() for termination.
 * @see SocketHTTP2_Stream_send_headers() and SocketHTTP2_Stream_send_data()
 * for sending.
 */
typedef struct SocketHTTP2_Stream *SocketHTTP2_Stream_T;

/* ============================================================================
 * Setting Entry (for SETTINGS frame)
 * ============================================================================
 */

/**
 * @brief Single setting entry (for SETTINGS frame)
 * @ingroup http2
 *
 * Represents one parameter in SETTINGS frame payload.
 * @see SocketHTTP2_SettingsId for valid IDs.
 * @see SocketHTTP2_Conn_settings() to send array of these.
 */
typedef struct
{
  uint16_t id;
  uint32_t value;
} SocketHTTP2_Setting;

/* ============================================================================
 * Configuration Functions
 * ============================================================================
 */

/**
 * @brief Initialize HTTP/2 configuration with safe RFC-compliant defaults.
 * @ingroup http2
 *
 * Populates the SocketHTTP2_Config structure with recommended default values
 * from RFC 9113 Section 6.5.2, plus library-specific security and performance
 * settings. This ensures secure and efficient operation out-of-the-box.
 *
 * Key defaults set:
 * - Header table size: 4096 bytes
 * - Enable push: 1 for servers, 0 for clients (clients can't push)
 * - Max concurrent streams: 100
 * - Initial window size: 65535 bytes
 * - Max frame size: 16384 bytes
 * - Max header list size: 16KB
 * - Enable connect protocol: 0 (RFC 8441 extended CONNECT disabled)
 * - Stream open rate: 100/sec with 10 burst (DoS protection)
 * - Stream close rate: 200/sec with 20 burst
 * - Connection window: 1MB
 * - Timeouts: 30s for settings/ping acknowledgments
 *
 * Role-specific:
 * - Servers: Push enabled by default
 * - Clients: Push disabled (per RFC, clients don't initiate push)
 *
 * The function zeros the entire struct first, then sets explicit values.
 * Call this before customizing settings for SocketHTTP2_Conn_new().
 *
 * @param[out] config Configuration structure to populate (must not be NULL)
 * @param[in] role Client or server role (affects enable_push)
 *
 * @return void (no return value)
 *
 * @throws None - pure initialization, no side effects or allocations
 *
 * @threadsafe Yes - operates only on provided struct, no shared state
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketHTTP2_Config config;
 * SocketHTTP2_config_defaults(&config, HTTP2_ROLE_CLIENT);
 * // Customize
 * config.max_concurrent_streams = 50;
 * config.initial_window_size = 32768;
 * // Use in connection
 * SocketHTTP2_Conn_T conn = SocketHTTP2_Conn_new(sock, &config, arena);
 * @endcode
 *
 * ## Server Configuration
 *
 * @code{.c}
 * SocketHTTP2_Config config;
 * SocketHTTP2_config_defaults(&config, HTTP2_ROLE_SERVER);
 * config.enable_push = 0; // Disable if not needed
 * config.max_concurrent_streams = 1000; // Higher for busy servers
 * @endcode
 *
 * ## Default Values Table
 *
 * | Setting | Client Default | Server Default | Description |
 * |---------|----------------|----------------|-------------|
 * | header_table_size | 4096 | 4096 | HPACK dynamic table size |
 * | enable_push | 0 | 1 | Server push support |
 * | max_concurrent_streams | 100 | 100 | Max simultaneous streams |
 * | initial_window_size | 65535 | 65535 | Stream flow control window |
 * | max_frame_size | 16384 | 16384 | Largest frame payload |
 * | max_header_list_size | 16KB | 16KB | Decompressed headers limit |
 * | max_stream_open_rate | 100/sec | 100/sec | DoS protection rate |
 *
 * @note All unset fields zeroed; explicitly set any custom values after call
 * @warning Defaults tuned for security; increasing limits may expose to DoS
 * @complexity O(1) - simple struct assignment
 *
 * @see SocketHTTP2_Config for full field documentation
 * @see SocketHTTP2_Conn_new() which uses this config
 * @see SocketHTTP2_SettingsId for settings identifiers
 */
extern void SocketHTTP2_config_defaults (SocketHTTP2_Config *config,
                                         SocketHTTP2_Role role);

/* ============================================================================
 * Connection Lifecycle
 * ============================================================================
 */

/**
 * @brief Create a new HTTP/2 connection instance.
 * @ingroup http2
 *
 * Initializes an HTTP/2 connection over the provided socket. The connection
 * supports both client and server roles, with automatic handling of preface,
 * settings exchange, and flow control. Memory is allocated from the provided
 * arena for lifecycle management.
 *
 * Detailed behavior:
 * - Validates inputs (socket and arena required)
 * - Applies default config if NULL provided (client role default)
 * - Initializes local and peer settings, flow control windows
 * - Generates random hash seed for stream table security
 * - Sets up rate limiting for stream opens/closes to prevent DoS
 * - Initializes internal buffers, HPACK decoder/encoder, stream hash table
 * - Sets initial next stream ID based on role (odd for client, even for
 * server)
 *
 * Edge cases:
 * - If config->role is invalid, behavior undefined (assert in debug)
 * - Socket must be connected TCP; UDP not supported
 * - For encrypted h2, call after TLS handshake completes
 * - Connection starts in INIT state; call SocketHTTP2_Conn_handshake() to
 * complete setup
 *
 * @param[in] socket Underlying TCP socket (connected, after TLS for h2)
 * @param[in] config Optional configuration; NULL uses client defaults
 * @param[in] arena Memory arena for allocations (must outlive connection)
 *
 * @return New HTTP/2 connection instance, or NULL on failure (check Except)
 *
 * @throws SocketHTTP2_Failed Allocation or initialization failure (arena full,
 * rate limit alloc fail, random bytes fail)
 * @throws Arena_Failed Underlying memory allocation failure
 *
 * @threadsafe Yes - but arena must be thread-local or synchronized; creates
 * independent instance
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Client connection
 * Arena_T arena = Arena_new();
 * Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 * Socket_connect(sock, "example.com", 443);
 * // Assume TLS handshake done...
 * SocketHTTP2_Config config;
 * SocketHTTP2_config_defaults(&config, HTTP2_ROLE_CLIENT);
 * config.enable_push = 0; // Disable server push
 * SocketHTTP2_Conn_T conn = SocketHTTP2_Conn_new(sock, &config, arena);
 * if (conn) {
 *     SocketHTTP2_Conn_handshake(conn);
 *     // Use connection...
 *     SocketHTTP2_Conn_free(&conn);
 * }
 * Arena_dispose(&arena);
 * @endcode
 *
 * ## Server Connection
 *
 * @code{.c}
 * // Server side (after accept)
 * SocketHTTP2_Config config;
 * SocketHTTP2_config_defaults(&config, HTTP2_ROLE_SERVER);
 * config.max_concurrent_streams = 100;
 * SocketHTTP2_Conn_T conn = SocketHTTP2_Conn_new(accepted_sock, &config,
 * arena);
 * @endcode
 *
 * @note Connection is not thread-safe; use one per event loop/thread
 * @warning Socket must remain valid until Conn_free(); do not close externally
 * @complexity O(1) - fixed allocations and initializations
 *
 * @see SocketHTTP2_config_defaults() for config setup
 * @see SocketHTTP2_Conn_handshake() to complete preface/settings exchange
 * @see SocketHTTP2_Conn_free() for cleanup
 * @see SocketHTTP2_Conn_process() for event processing
 */
extern SocketHTTP2_Conn_T
SocketHTTP2_Conn_new (Socket_T socket, const SocketHTTP2_Config *config,
                      Arena_T arena);

/**
 * @brief Dispose of HTTP/2 connection and release all resources.
 * @ingroup http2
 *
 * Cleans up the connection instance, including all associated streams,
 * internal buffers, HPACK state, rate limiters, and other resources.
 * The underlying socket is NOT closed; caller must close it separately if
 * needed. Sets the pointer to NULL after cleanup.
 *
 * Cleanup order:
 * - Free HPACK encoder and decoder
 * - Release stream open/close rate limiters
 * - Release receive and send buffers
 * - Connection struct memory returned to arena (not freed explicitly)
 * - All streams automatically cleaned via arena or explicit free
 *
 * Safe to call on NULL or already-freed pointer (no-op).
 * Call this in FINALLY block or after error to prevent leaks.
 *
 * @param[in,out] conn Pointer to connection (set to NULL on success)
 *
 * @return void
 *
 * @throws None - idempotent cleanup, no allocations or side effects
 *
 * @threadsafe No - assumes exclusive access to conn pointer
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketHTTP2_Conn_T conn = SocketHTTP2_Conn_new(sock, config, arena);
 * if (conn) {
 *     TRY {
 *         // Use connection: handshake, process events, etc.
 *         SocketHTTP2_Conn_process(conn, events);
 *     } EXCEPT (SocketHTTP2_Error) {
 *         SocketHTTP2_Conn_goaway(conn, HTTP2_PROTOCOL_ERROR, NULL, 0);
 *     } FINALLY {
 *         SocketHTTP2_Conn_free(&conn);  // Safe even if NULL
 *     } END_TRY;
 * }
 * // Close socket separately if needed
 * Socket_free(&sock);
 * @endcode
 *
 * @note Does NOT send GOAWAY or close socket; use Conn_goaway() for graceful
 * shutdown
 * @warning Failing to call free() leaks arena allocations; always pair with
 * new()
 * @complexity O(n) where n is number of active streams - frees all streams
 *
 * @see SocketHTTP2_Conn_new() for creation
 * @see SocketHTTP2_Conn_goaway() for graceful shutdown before free
 * @see Arena_clear() or Arena_dispose() for arena lifecycle
 */
extern void SocketHTTP2_Conn_free (SocketHTTP2_Conn_T *conn);

/**
 * @brief Complete HTTP/2 connection preface and initial settings exchange.
 * @ingroup http2
 *
 * Advances the connection through the initial HTTP/2 handshake state machine
 * (RFC 9113 Section 3.4-3.5). This includes sending/receiving the connection
 * preface, exchanging SETTINGS frames, and acknowledging them. Call repeatedly
 * until returns 0 (complete).
 *
 * State transitions:
 * - CLIENT from INIT: Send preface magic + initial SETTINGS, advance to
 * PREFACE_SENT
 * - SERVER from INIT: Wait for client preface (via Conn_process), then send
 * SETTINGS
 * - Both: Send settings if not sent, wait for peer ACK
 * - On mutual ACK: Transition to READY state, optional window update if needed
 *
 * Return values:
 * - 0: Handshake complete (READY state), ready for stream operations
 * - 1: In progress (waiting for peer response or I/O)
 * - -1: Error (invalid state, send failure); check errno or last error
 *
 * Integrate with event loop: Call when POLL_READ/WRITE on socket during
 * handshake. Errors may require Conn_goaway() and Conn_free().
 *
 * @param[in,out] conn Active connection (must not be NULL)
 *
 * @return 0 complete, 1 in progress, -1 error
 *
 * @throws SocketHTTP2_Failed Send failure during handshake (socket error, flow
 * control)
 * @throws SocketHTTP2_ProtocolError Invalid preface or settings ACK timeout
 *
 * @threadsafe No - modifies connection state
 *
 * ## Usage Example (Client)
 *
 * @code{.c}
 * SocketHTTP2_Conn_T conn = SocketHTTP2_Conn_new(sock, &config, arena);
 * int status;
 * while ((status = SocketHTTP2_Conn_handshake(conn)) == 1) {
 *     // Wait for socket events
 *     unsigned events = SocketPoll_wait(poll, timeout); // Pseudo
 *     SocketHTTP2_Conn_process(conn, events);
 *     SocketHTTP2_Conn_flush(conn);
 * }
 * if (status < 0) {
 *     // Handle error: log, goaway, free
 *     SocketHTTP2_Conn_free(&conn);
 *     return -1;
 * }
 * // Now in READY: create streams, send requests
 * @endcode
 *
 * ## Server Usage
 *
 * @code{.c}
 * // After Conn_new (INIT state)
 * // Handshake driven by Conn_process on incoming data
 * while (SocketHTTP2_Conn_handshake(conn) == 1) {
 *     SocketHTTP2_Conn_process(conn, POLL_READ);
 * }
 * // On 0: ready for client-initiated streams
 * @endcode
 *
 * ## Return Value Table
 *
 * | Value | State | Action |
 * |-------|-------|--------|
 * | 0 | READY | Proceed to streams |
 * | 1 | In progress | Continue polling/processing |
 * | -1 | Error | Check error, cleanup |
 *
 * @note May send initial WINDOW_UPDATE if connection window > default
 * @warning Call before any stream operations; undefined if skipped
 * @complexity O(1) per call - state machine steps
 *
 * @see SocketHTTP2_Conn_new() before handshake
 * @see SocketHTTP2_Conn_process() for I/O during handshake
 * @see SocketHTTP2_Conn_state() to query (private, for debug)
 */
extern int SocketHTTP2_Conn_handshake (SocketHTTP2_Conn_T conn);

/**
 * @brief Process socket events and HTTP/2 frames.
 * @ingroup http2
 *
 * Main event loop entry point for HTTP/2 connections. Handles reading from
 * socket, parsing frames, dispatching to frame handlers, and invoking stream
 * callbacks. Call this when the underlying socket has POLL_READ or POLL_WRITE
 * events.
 *
 * Behavior:
 * - Reads available data from socket into internal receive buffer
 * - Verifies client preface on server (if initial state)
 * - Processes complete frames from buffer (loop until buffer empty or partial)
 * - Dispatches frames to handlers (DATA, HEADERS, SETTINGS, etc.)
 * - Updates flow control windows, stream states
 * - Invokes user callbacks for stream events (headers, data, end, reset)
 * - Handles errors: may send GOAWAY, transition to error state
 *
 * During handshake: advances state via internal calls to Conn_handshake
 * After ready: processes multiplexed streams
 *
 * Return:
 * - 0: Success, processed all available data
 * - 1: Partial frame, need more data (continue polling)
 * - -1: Error (protocol violation, socket error); connection may be invalid
 *
 * Pair with Conn_flush() after process to send pending responses.
 * Integrate with SocketPoll or similar for non-blocking I/O.
 *
 * @param[in,out] conn HTTP/2 connection
 * @param[in] events Bitmask of poll events (POLL_READ | POLL_WRITE |
 * POLL_ERROR | POLL_HANGUP)
 *
 * @return 0 success, 1 need more data, -1 error
 *
 * @throws SocketHTTP2_ProtocolError Frame parsing or protocol violation
 * @throws SocketHTTP2_FlowControlError Window overflow or underflow
 * @throws SocketHTTP2_StreamError Stream-specific error
 * @throws Socket_Failed Underlying socket read error
 *
 * @threadsafe No - modifies connection and stream states
 *
 * ## Event Loop Integration
 *
 * @code{.c}
 * SocketPoll_T poll = SocketPoll_new(1024);
 * SocketPoll_add(poll, SocketHTTP2_Conn_socket(conn), POLL_READ | POLL_WRITE,
 * conn);
 *
 * while (running) {
 *     SocketEvent_T *events;
 *     int n = SocketPoll_wait(poll, &events, timeout_ms);
 *     for (int i = 0; i < n; i++) {
 *         SocketHTTP2_Conn_T c = events[i].data;
 *         int r = SocketHTTP2_Conn_process(c, events[i].events);
 *         if (r < 0) {
 *             // Error: log, goaway, free
 *             SocketHTTP2_Conn_goaway(c, HTTP2_PROTOCOL_ERROR, NULL, 0);
 *             SocketHTTP2_Conn_free(&c);
 *         }
 *         SocketHTTP2_Conn_flush(c); // Send pending frames
 *     }
 * }
 * @endcode
 *
 * ## Error Handling
 *
 * On -1 return:
 * - Check Socket_geterrorcode() or last except
 * - Send GOAWAY if protocol error
 * - Remove from poll, free connection
 * - Log peer IP/port for security monitoring
 *
 * @note Events param currently unused (always processes read); future opt for
 * write
 * @warning Must call after poll events on socket FD; blocking calls undefined
 * @complexity O(m) where m is number of frames processed - linear in input
 * size
 *
 * @see SocketHTTP2_Conn_flush() to send responses after process
 * @see SocketHTTP2_Conn_handshake() advanced internally during early calls
 * @see SocketPoll integration example above
 * @see SocketHTTP2_StreamCallback for event notifications
 */
extern int SocketHTTP2_Conn_process (SocketHTTP2_Conn_T conn, unsigned events);

/**
 * @brief Flush pending HTTP/2 frames to socket.
 * @ingroup http2
 *
 * Sends all buffered output frames from the send buffer to the underlying
 * socket. Handles partial sends and EAGAIN by returning 1 (would block). Call
 * this after Conn_process() or after sending data/headers to ensure timely
 * delivery.
 *
 * Behavior:
 * - Loops until send buffer empty or socket blocks
 * - Uses Socket_send() for transmission
 * - Updates send window on successful sends
 * - On EAGAIN/0: returns 1, caller should poll for WRITE
 * - On error: returns -1, errno set (e.g. ECONNRESET)
 *
 * Non-blocking friendly; integrates with event loops.
 *
 * @param[in,out] conn Connection with buffered output
 *
 * @return 0 all sent, 1 would block (partial send), -1 error
 *
 * @throws Socket_Failed Socket send error (connection closed, reset)
 * @throws SocketHTTP2_FlowControlError If send window exhausted (rare,
 * internal)
 *
 * @threadsafe No - modifies send buffer and windows
 *
 * ## Usage in Event Loop
 *
 * @code{.c}
 * // After processing input
 * int r = SocketHTTP2_Conn_process(conn, events);
 * if (r >= 0) {
 *     int f = SocketHTTP2_Conn_flush(conn);
 *     if (f == 1) {
 *         // Register for POLL_WRITE
 *         SocketPoll_mod(poll, SocketHTTP2_Conn_socket(conn), POLL_WRITE,
 * conn);
 *     }
 * }
 * @endcode
 *
 * ## Return Value Table
 *
 * | Value | Meaning | Next Action |
 * |-------|---------|-------------|
 * | 0 | All data sent | Normal |
 * | 1 | Partial send, need WRITE | Poll for write |
 * | -1 | Error | Check errno, cleanup |
 *
 * @note Buffers frames for efficient batched sending
 * @warning Must call regularly to avoid head-of-line blocking
 * @complexity O(k) where k bytes sent - linear in output size
 *
 * @see SocketHTTP2_Conn_process() before flush for full cycle
 * @see Socket_send_window() to check available capacity
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

/* ============================================================================
 * Connection Control
 * ============================================================================
 */

/**
 * @brief Send SETTINGS frame
 * @ingroup http2
 * @param conn  Connection
 * @param settings  Array of settings
 * @param count  Number of settings
 *
 * @return 0 on success, -1 on error
 * @threadsafe No
 */
extern int SocketHTTP2_Conn_settings (SocketHTTP2_Conn_T conn,
                                      const SocketHTTP2_Setting *settings,
                                      size_t count);

/**
 * @brief Get peer's setting value
 * @ingroup http2
 * @param conn  Connection
 * @param id  Setting identifier
 *
 * @return Setting value (peer's acknowledged value)
 * @threadsafe Yes
 */
extern uint32_t SocketHTTP2_Conn_get_setting (SocketHTTP2_Conn_T conn,
                                              SocketHTTP2_SettingsId id);

/**
 * @brief Get our setting value
 * @ingroup http2
 * @param conn  Connection
 * @param id  Setting identifier
 *
 * @return Our setting value
 * @threadsafe Yes
 */
extern uint32_t SocketHTTP2_Conn_get_local_setting (SocketHTTP2_Conn_T conn,
                                                    SocketHTTP2_SettingsId id);

/**
 * @brief Send PING frame
 * @ingroup http2
 * @param conn  Connection
 * @param opaque  8 bytes opaque data (NULL for auto-generate)
 *
 * @return 0 on success, -1 on error
 * @threadsafe No
 */
extern int SocketHTTP2_Conn_ping (SocketHTTP2_Conn_T conn,
                                  const unsigned char opaque[8]);

/**
 * @brief Send PING and wait for response with timeout
 * @ingroup http2
 * @param[in] conn HTTP/2 connection
 * @param[in] timeout_ms Maximum time to wait for PING ACK (milliseconds)
 *
 * Sends a PING frame and blocks until the ACK is received or timeout expires.
 * Useful for measuring RTT and verifying connection liveness.
 *
 * @return RTT in milliseconds on success, -1 on timeout or error
 *
 * @threadsafe No - modifies connection state
 *
 * ## Example
 *
 * @code{.c}
 * int rtt = SocketHTTP2_Conn_ping_wait(conn, 5000);
 * if (rtt >= 0) {
 *     printf("Connection alive, RTT: %d ms\n", rtt);
 * } else {
 *     printf("Connection dead or timeout\n");
 * }
 * @endcode
 *
 * @note For non-blocking ping, use SocketHTTP2_Conn_ping() and check
 *       HTTP2_EVENT_PING_ACK event
 *
 * @see SocketHTTP2_Conn_ping() for async version
 * @see SocketHTTP2_Conn_is_closed() to check connection state
 */
extern int SocketHTTP2_Conn_ping_wait (SocketHTTP2_Conn_T conn, int timeout_ms);

/**
 * @brief Get current number of active streams
 * @ingroup http2
 * @param conn HTTP/2 connection
 *
 * Returns the number of streams currently in non-closed states (open,
 * half-closed local, half-closed remote, reserved). Does not count
 * idle or closed streams.
 *
 * @return Number of concurrent active streams (>= 0)
 *
 * @threadsafe Yes - reads atomic counter
 *
 * @see SocketHTTP2_Conn_set_max_concurrent() to limit streams
 * @see SocketHTTP2_Conn_get_peer_setting() to check peer's limit
 */
extern uint32_t SocketHTTP2_Conn_get_concurrent_streams (SocketHTTP2_Conn_T conn);

/**
 * @brief Set maximum concurrent streams limit
 * @ingroup http2
 * @param[in] conn HTTP/2 connection
 * @param[in] max Maximum concurrent streams (1 to 2^31-1)
 *
 * Updates the SETTINGS_MAX_CONCURRENT_STREAMS value and sends a SETTINGS
 * frame to the peer. New streams exceeding this limit will receive
 * REFUSED_STREAM.
 *
 * @return 0 on success, -1 on error (invalid value or send failed)
 *
 * @threadsafe No - modifies settings
 *
 * ## Example
 *
 * @code{.c}
 * // Limit to 50 concurrent streams
 * SocketHTTP2_Conn_set_max_concurrent(conn, 50);
 *
 * // Check current active
 * uint32_t active = SocketHTTP2_Conn_get_concurrent_streams(conn);
 * printf("Active: %u / %u streams\n", active, 50);
 * @endcode
 *
 * @note Change takes effect after peer acknowledges SETTINGS
 * @see SocketHTTP2_Conn_get_concurrent_streams() to check usage
 * @see SocketHTTP2_Config.max_concurrent_streams for initial value
 */
extern int SocketHTTP2_Conn_set_max_concurrent (SocketHTTP2_Conn_T conn,
                                                uint32_t max);

/**
 * @brief Send GOAWAY frame
 * @ingroup http2
 * @param conn  Connection
 * @param error_code  Error code
 * @param debug_data  Optional debug data (NULL for none)
 * @param debug_len  Debug data length
 *
 * Initiates graceful shutdown. No new streams will be accepted.
 *
 * @return 0 on success, -1 on error
 * @threadsafe No
 */
extern int SocketHTTP2_Conn_goaway (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_ErrorCode error_code,
                                    const void *debug_data, size_t debug_len);

/**
 * @brief Get last processed stream ID
 * @ingroup http2
 * @param conn  Connection
 *
 * @return Last peer stream ID processed
 * @threadsafe Yes
 */
extern uint32_t SocketHTTP2_Conn_last_stream_id (SocketHTTP2_Conn_T conn);

/* ============================================================================
 * Connection Flow Control
 * ============================================================================
 */

/**
 * @brief Update connection-level window
 * @ingroup http2
 * @param conn  Connection
 * @param increment  Window size increment (1 to 2^31-1)
 *
 * @return 0 on success, -1 on error
 * @threadsafe No
 */
extern int SocketHTTP2_Conn_window_update (SocketHTTP2_Conn_T conn,
                                           uint32_t increment);

/**
 * @brief Get available send window
 * @ingroup http2
 * @param conn  Connection
 *
 * @return Available bytes in connection send window
 * @threadsafe Yes
 */
extern int32_t SocketHTTP2_Conn_send_window (SocketHTTP2_Conn_T conn);

/**
 * @brief Get receive window
 * @ingroup http2
 * @param conn  Connection
 *
 * @return Current receive window size
 * @threadsafe Yes
 */
extern int32_t SocketHTTP2_Conn_recv_window (SocketHTTP2_Conn_T conn);

/* ============================================================================
 * Stream Management
 * ============================================================================
 */

/**
 * @brief Create new stream
 * @ingroup http2
 * @param conn  Parent connection
 *
 * Client streams use odd IDs (1, 3, 5, ...)
 * Server streams (push) use even IDs (2, 4, 6, ...)
 *
 * @return New stream with auto-assigned ID, or NULL if limit reached
 * @threadsafe No
 */
extern SocketHTTP2_Stream_T SocketHTTP2_Stream_new (SocketHTTP2_Conn_T conn);

/**
 * @brief Look up an existing stream by ID.
 * @ingroup http2
 * @param conn  Parent connection
 * @param stream_id  Stream identifier (must be non-zero)
 *
 * Returns an existing stream object if present, or NULL if the stream is not
 * known/has been closed. This is primarily useful for h2c upgrade handling
 * where stream 1 is pre-created.
 *
 * @return Stream handle or NULL
 * @threadsafe No
 */
extern SocketHTTP2_Stream_T SocketHTTP2_Conn_get_stream (SocketHTTP2_Conn_T conn,
                                                         uint32_t stream_id);

/**
 * @brief Get stream ID
 * @ingroup http2
 * @param stream  Stream
 *
 * @return Stream identifier
 * @threadsafe Yes
 */
extern uint32_t SocketHTTP2_Stream_id (SocketHTTP2_Stream_T stream);

/**
 * @brief Get stream state
 * @ingroup http2
 * @param stream  Stream
 *
 * @return Current stream state
 * @threadsafe Yes
 */
extern SocketHTTP2_StreamState
SocketHTTP2_Stream_state (SocketHTTP2_Stream_T stream);

/**
 * @brief Close HTTP/2 stream
 * @ingroup http2
 * @param stream Stream to close
 * @param error_code Error code (HTTP2_NO_ERROR for normal close)
 * @threadsafe No
 */
extern void SocketHTTP2_Stream_close (SocketHTTP2_Stream_T stream,
                                      SocketHTTP2_ErrorCode error_code);

/**
 * @brief Get user data
 * @ingroup http2
 * @param stream Stream
 * @return User data pointer
 * @threadsafe Yes
 */
extern void *SocketHTTP2_Stream_get_userdata (SocketHTTP2_Stream_T stream);

/**
 * @brief Set user data
 * @ingroup http2
 * @param stream Stream
 * @param userdata User data pointer
 * @threadsafe No
 */
extern void SocketHTTP2_Stream_set_userdata (SocketHTTP2_Stream_T stream,
                                             void *userdata);

/* ============================================================================
 * Sending (Client/Server)
 * ============================================================================
 */

/**
 * @brief Send HEADERS frame
 * @ingroup http2
 * @param stream  Stream
 * @param headers  Header array (includes pseudo-headers)
 * @param header_count  Number of headers
 * @param end_stream  Set END_STREAM flag (no body follows)
 *
 * @note Required pseudo-headers: requests (:method, :scheme, :authority,
 * :path); responses (:status).
 *
 * @return 0 on success, -1 on error
 * @threadsafe No
 */
extern int SocketHTTP2_Stream_send_headers (SocketHTTP2_Stream_T stream,
                                            const SocketHPACK_Header *headers,
                                            size_t header_count,
                                            int end_stream);

/**
 * @brief Send request (convenience)
 * @ingroup http2
 * @param stream  Stream
 * @param request  HTTP request
 * @param end_stream  No body follows
 *
 * @return 0 on success, -1 on error
 * @threadsafe No
 */
extern int SocketHTTP2_Stream_send_request (SocketHTTP2_Stream_T stream,
                                            const SocketHTTP_Request *request,
                                            int end_stream);

/**
 * @brief Send response (convenience)
 * @ingroup http2
 * @param stream  Stream
 * @param response  HTTP response
 * @param end_stream  No body follows
 *
 * @return 0 on success, -1 on error
 * @threadsafe No
 */
extern int
SocketHTTP2_Stream_send_response (SocketHTTP2_Stream_T stream,
                                  const SocketHTTP_Response *response,
                                  int end_stream);

/**
 * @brief Send DATA frame
 * @ingroup http2
 * @param stream  Stream
 * @param data  Payload data
 * @param len  Data length
 * @param end_stream  Set END_STREAM flag
 *
 * @return Bytes accepted (may be less due to flow control), -1 on error
 * @threadsafe No
 */
extern ssize_t SocketHTTP2_Stream_send_data (SocketHTTP2_Stream_T stream,
                                             const void *data, size_t len,
                                             int end_stream);

/**
 * @brief Send trailer headers
 * @ingroup http2
 * @param stream  Stream
 * @param trailers  Trailer header array
 * @param count  Number of trailers
 *
 * @return 0 on success, -1 on error
 * @threadsafe No
 */
extern int
SocketHTTP2_Stream_send_trailers (SocketHTTP2_Stream_T stream,
                                  const SocketHPACK_Header *trailers,
                                  size_t count);

/* ============================================================================
 * Receiving
 * ============================================================================
 */

/**
 * @brief Check for received headers
 * @ingroup http2
 * @param stream  Stream
 * @param headers  Output header array
 * @param max_headers  Maximum headers to receive
 * @param header_count  Output - number of headers
 * @param end_stream  Output - END_STREAM was set
 *
 * @return 1 if headers available, 0 if not, -1 on error
 * @threadsafe No
 */
extern int SocketHTTP2_Stream_recv_headers (SocketHTTP2_Stream_T stream,
                                            SocketHPACK_Header *headers,
                                            size_t max_headers,
                                            size_t *header_count,
                                            int *end_stream);

/**
 * @brief Receive DATA
 * @ingroup http2
 * @param stream  Stream
 * @param buf  Output buffer
 * @param len  Buffer size
 * @param end_stream  Output - END_STREAM was set
 *
 * @return Bytes received, 0 if would block, -1 on error
 * @threadsafe No
 */
extern ssize_t SocketHTTP2_Stream_recv_data (SocketHTTP2_Stream_T stream,
                                             void *buf, size_t len,
                                             int *end_stream);

/**
 * @brief Receive trailer headers
 * @ingroup http2
 * @param stream  Stream
 * @param trailers  Output trailer array
 * @param max_trailers  Maximum trailers
 * @param trailer_count  Output - number of trailers
 *
 * @return 1 if trailers available, 0 if not, -1 on error
 * @threadsafe No
 */
extern int SocketHTTP2_Stream_recv_trailers (SocketHTTP2_Stream_T stream,
                                             SocketHPACK_Header *trailers,
                                             size_t max_trailers,
                                             size_t *trailer_count);

/* ============================================================================
 * Stream Flow Control
 * ============================================================================
 */

/**
 * @brief Update stream window
 * @ingroup http2
 * @param stream  Stream
 * @param increment  Window size increment
 *
 * @return 0 on success, -1 on error
 * @threadsafe No
 */
extern int SocketHTTP2_Stream_window_update (SocketHTTP2_Stream_T stream,
                                             uint32_t increment);

/**
 * @brief Get stream send window
 * @ingroup http2
 * @param stream  Stream
 *
 * @return Available bytes (minimum of stream and connection windows)
 * @threadsafe Yes
 */
extern int32_t SocketHTTP2_Stream_send_window (SocketHTTP2_Stream_T stream);

/**
 * @brief Get stream receive window
 * @ingroup http2
 * @param stream  Stream
 *
 * @return Current receive window size
 * @threadsafe Yes
 */
extern int32_t SocketHTTP2_Stream_recv_window (SocketHTTP2_Stream_T stream);

/* ============================================================================
 * Server Push (RFC 9113 Section 8.4)
 * ============================================================================
 */

/**
 * @brief Send PUSH_PROMISE (server only)
 * @ingroup http2
 * @param stream  Parent stream
 * @param request_headers  Pushed request headers
 * @param header_count  Number of headers
 *
 * @return New reserved stream for pushing response, or NULL if disabled
 * @threadsafe No
 */
extern SocketHTTP2_Stream_T
SocketHTTP2_Stream_push_promise (SocketHTTP2_Stream_T stream,
                                 const SocketHPACK_Header *request_headers,
                                 size_t header_count);

/* ============================================================================
 * Callbacks
 * ============================================================================
 */

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
 * @brief Set stream event callback
 * @ingroup http2
 * @param conn  Connection
 * @param callback  Callback function
 * @param userdata  User data passed to callback
 *
 * @threadsafe No
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

/**
 * Connection event callback
 */
typedef void (*SocketHTTP2_ConnCallback) (SocketHTTP2_Conn_T conn, int event,
                                          void *userdata);

/**
 * @brief Set connection callback
 * @ingroup http2
 * @param conn  Connection
 * @param callback  Callback function
 * @param userdata  User data passed to callback
 *
 * @threadsafe No
 */
extern void
SocketHTTP2_Conn_set_conn_callback (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_ConnCallback callback,
                                    void *userdata);

/* ============================================================================
 * h2c Upgrade (Cleartext HTTP/2)
 * ============================================================================
 */

/**
 * @brief Upgrade from HTTP/1.1 (client)
 * @ingroup http2
 * @param socket  Socket after sending upgrade request
 * @param settings_payload  Base64-decoded HTTP2-Settings header value
 * @param settings_len  Length of settings payload
 * @param arena  Memory arena
 *
 * @return HTTP/2 connection
 * @threadsafe No
 */
extern SocketHTTP2_Conn_T
SocketHTTP2_Conn_upgrade_client (Socket_T socket,
                                 const unsigned char *settings_payload,
                                 size_t settings_len, Arena_T arena);

/**
 * @brief Upgrade from HTTP/1.1 (server)
 * @ingroup http2
 * @param socket  Socket after receiving upgrade request
 * @param initial_request  The HTTP/1.1 request that triggered upgrade
 * @param settings_payload  Decoded HTTP2-Settings from client
 * @param settings_len  Length of settings
 * @param arena  Memory arena
 *
 * @return HTTP/2 connection with stream 1 pre-created
 * @threadsafe No
 */
extern SocketHTTP2_Conn_T SocketHTTP2_Conn_upgrade_server (
    Socket_T socket, const SocketHTTP_Request *initial_request,
    const unsigned char *settings_payload, size_t settings_len, Arena_T arena);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Get error code description
 * @ingroup http2
 * @param code Error code
 * @return Static string describing the error
 * @threadsafe Yes
 */
extern const char *SocketHTTP2_error_string (SocketHTTP2_ErrorCode code);

/**
 * @brief Get frame type name
 * @ingroup http2
 * @type  Frame type
 *
 * @return Static string with frame type name
 * @threadsafe Yes
 */
extern const char *SocketHTTP2_frame_type_string (SocketHTTP2_FrameType type);

/**
 * @brief Get stream state name
 * @ingroup http2
 * @state  Stream state
 *
 * @return Static string with state name
 * @threadsafe Yes
 */
extern const char *
SocketHTTP2_stream_state_string (SocketHTTP2_StreamState state);

/* ============================================================================
 * Frame Parsing (Low-level API)
 * ============================================================================
 */

/**
 * @brief Parse frame header from buffer
 * @ingroup http2
 * @param data  Input buffer containing frame header
 * @input_len  Length of available data (must be >= HTTP2_FRAME_HEADER_SIZE=9;
 * runtime validated)
 * @header  Output header structure (populated on success)
 *
 * @return 0 on success, -1 on invalid input (null pointers, input_len < 9)
 * @threadsafe Yes
 *
 * Note: Performs basic length validation for safety; caller should ensure data
 * is from trusted source. No deep payload validation—use http2_frame_validate
 * for protocol checks.
 */
extern int SocketHTTP2_frame_header_parse (const unsigned char *data,
                                           size_t input_len,
                                           SocketHTTP2_FrameHeader *header);

/**
 * @brief Serialize frame header to buffer
 * @ingroup http2
 * @header  Header structure
 * @param data  Output buffer (at least HTTP2_FRAME_HEADER_SIZE bytes)
 *
 * @threadsafe Yes
 */
extern void
SocketHTTP2_frame_header_serialize (const SocketHTTP2_FrameHeader *header,
                                    unsigned char *data);

/** @} */ /* http2 */

/* ============================================================================
 * End of HTTP/2 module documentation
 * ============================================================================
 */

#endif /* SOCKETHTTP2_INCLUDED */

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP2-private.h
 * @brief Internal HTTP/2 connection and stream structures.
 * @ingroup http
 * @defgroup http2_private HTTP/2 Private Implementation Details
 * @ingroup http
 * @internal
 *
 * This header exposes private structures and functions for HTTP/2 protocol
 * handling. For public API, include and use SocketHTTP2.h exclusively.
 *
 * Key internals:
 * - Connection and stream state machines
 * - Frame validation, processing, and serialization
 * - HPACK header (de)compression integration
 * - Flow control window management
 * - DoS protections: rate limiting for RST_STREAM (CVE-2023-44487), PING,
 * SETTINGS floods
 * - Settings negotiation and GOAWAY handling
 * - Stream hashing and lifecycle with push support
 *
 * ## Header Validation and Error Handling
 *
 * HTTP/2 header validation strictly follows RFC 9113 requirements:
 *
 * ### Pseudo-Header Validation
 * - **Order**: Pseudo-headers (:*) must appear before regular headers
 * - **Duplication**: Pseudo-headers must not be duplicated
 * - **Required (Requests)**: :method, :scheme/:authority, :path
 * - **Required (Responses)**: :status
 * - **:protocol**: Requires SETTINGS_ENABLE_CONNECT_PROTOCOL=1
 *
 * ### Forbidden Headers
 * Connection-specific headers are forbidden per RFC 9113 Section 8.2.2:
 * - connection, keep-alive, proxy-authenticate, proxy-authorization
 * - te (except "trailers"), trailers, transfer-encoding, upgrade
 *
 * ### TE Header Restrictions
 * - TE header may only contain "trailers" value in HTTP/2
 * - Empty TE header is equivalent to "trailers"
 *
 * ### Error Code Mapping
 * - **Stream Errors (RST_STREAM)**: Request header validation failures
 * - **Connection Errors (GOAWAY)**: Response header validation failures,
 *   protocol violations
 *
 * @see SocketHTTP2.h Public HTTP/2 connection and stream API.
 * @see SocketHPACK.h Header compression (HPACK) module.
 * @see SocketHTTP-private.h Shared HTTP internals.
 * @see @ref group__http "HTTP Module" for high-level overview.
 *
 * @{
 */

#ifndef SOCKETHTTP2_PRIVATE_INCLUDED
#define SOCKETHTTP2_PRIVATE_INCLUDED

#include "core/Except.h"
#include "core/SocketRateLimit.h"
#include "http/SocketHPACK.h"
#include "http/SocketHTTP2.h"
#include "socket/SocketBuf.h"
#include "core/TimeWindow.h"

extern const Except_T SocketHTTP2_Failed;
extern const Except_T SocketHTTP2_ProtocolError;
extern const Except_T SocketHTTP2_StreamError;
extern const Except_T SocketHTTP2_FlowControlError;
extern const Except_T SocketHTTP2; /* Base for EXCEPT(SocketHTTP2) */

/* ============================================================================
 * Connection Preface
 * ============================================================================
 */

/**
 * @brief Client connection preface magic string per RFC 9113.
 * @ingroup http
 * @internal
 *
 * The fixed 24-byte sequence
 * "\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a"
 * (ASCII: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") sent by clients to initiate
 * HTTP/2.
 *
 * @see RFC 9113 Section 3.5 HTTP/2 Connection Preface
 * @see http2_process_frame() for preface validation during handshake.
 */
static const unsigned char HTTP2_CLIENT_PREFACE[HTTP2_PREFACE_SIZE]
    = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/* ============================================================================
 * Internal Settings Array Indices
 * ============================================================================
 *
 * @brief Array indices for HTTP/2 settings parameters.
 * @ingroup http
 * @internal
 *
 * These #define provide compile-time constants for indexing into the
 * local_settings[] and peer_settings[] uint32_t arrays in SocketHTTP2_Conn.
 * Maps to HTTP/2 SETTINGS identifiers (e.g., HEADER_TABLE_SIZE = 1).
 *
 * @see RFC 9113 Section 6.5.2 for settings parameter definitions and
 * semantics.
 * @see SocketHTTP2_Conn::local_settings
 * @see SocketHTTP2_Conn::peer_settings
 * @see http2_process_settings() for applying settings changes.
 */

#define SETTINGS_IDX_HEADER_TABLE_SIZE 0
#define SETTINGS_IDX_ENABLE_PUSH 1
#define SETTINGS_IDX_MAX_CONCURRENT_STREAMS 2
#define SETTINGS_IDX_INITIAL_WINDOW_SIZE 3
#define SETTINGS_IDX_MAX_FRAME_SIZE 4
#define SETTINGS_IDX_MAX_HEADER_LIST_SIZE 5
#define SETTINGS_IDX_ENABLE_CONNECT_PROTOCOL 6

/**
 * @brief Fixed size of a SETTINGS frame parameter entry.
 * @ingroup http
 * @internal
 * @details 6 bytes: 2-byte identifier + 4-byte value (RFC 9113).
 */
#define HTTP2_SETTING_ENTRY_SIZE 6

/**
 * @brief Fixed size of PING frame payload (opaque data).
 * @ingroup http
 * @internal
 * @details 8 bytes of arbitrary data for round-trip measurement or app use.
 * @see RFC 9113 Section 6.7 PING.
 */
#define HTTP2_PING_PAYLOAD_SIZE 8

/**
 * @brief Fixed size of GOAWAY frame header fields (excluding debug data).
 * @ingroup http
 * @internal
 * @details 8 bytes: last stream ID (4) + error code (4).
 * @see RFC 9113 Section 6.8 GOAWAY.
 */
#define HTTP2_GOAWAY_HEADER_SIZE 8

/**
 * @brief Fixed size of WINDOW_UPDATE frame payload (window increment).
 * @ingroup http
 * @internal
 * @details 4 bytes unsigned integer for flow control window adjustment.
 * @see RFC 9113 Section 6.9 WINDOW_UPDATE.
 */
#define HTTP2_WINDOW_UPDATE_SIZE 4

/**
 * @brief Fixed size of RST_STREAM frame payload (error code).
 * @ingroup http
 * @internal
 * @details 4 bytes unsigned integer error code.
 * @see RFC 9113 Section 6.4 RST_STREAM.
 */
#define HTTP2_RST_STREAM_PAYLOAD_SIZE 4

/* ============================================================================
 * Connection State
 * ============================================================================
 */

/**
 * @brief HTTP/2 connection lifecycle states.
 * @ingroup http
 * @internal
 *
 * Defines the finite state machine states for HTTP/2 connection establishment,
 * settings exchange, operational phase, GOAWAY handling, and closure.
 *
 * @see SocketHTTP2_Conn::state for storage in connection struct.
 * @see RFC 9113 Section 5.1 for connection preface and state transitions.
 */
typedef enum
{
  HTTP2_CONN_STATE_INIT = 0,      /**< Initial state */
  HTTP2_CONN_STATE_PREFACE_SENT,  /**< Client preface sent */
  HTTP2_CONN_STATE_PREFACE_RECV,  /**< Server preface received */
  HTTP2_CONN_STATE_SETTINGS_SENT, /**< SETTINGS sent */
  HTTP2_CONN_STATE_SETTINGS_RECV, /**< SETTINGS received */
  HTTP2_CONN_STATE_READY,         /**< Connection ready */
  HTTP2_CONN_STATE_GOAWAY_SENT,   /**< GOAWAY sent */
  HTTP2_CONN_STATE_GOAWAY_RECV,   /**< GOAWAY received */
  HTTP2_CONN_STATE_CLOSED         /**< Connection closed */
} SocketHTTP2_ConnState;

/* ============================================================================
 * Stream Structure
 * ============================================================================
 */

/**
 * @brief Internal structure for managing an HTTP/2 stream.
 * @ingroup http
 * @internal
 *
 * Tracks stream ID, state, flow control windows, received DATA buffering,
 * header/trailer decoding state, and user data. Supports split headers via
 * CONTINUATION frames and distinguishes push vs. regular streams.
 *
 * @note Fields are subject to change; use public API functions for access.
 *
 * @threadsafe No - internal fields modified by protocol processing; direct
 * access unsafe in multi-threaded contexts without external synchronization
 *
 * @see SocketHTTP2_Stream_T for opaque public handle.
 * @see http2_stream_create() for instantiation.
 * @see http2_stream_lookup() for retrieval by ID.
 * @see RFC 9113 Section 5.1 for stream lifecycle.
 */
struct SocketHTTP2_Stream
{
  uint32_t id;                   /**< Stream identifier */
  SocketHTTP2_StreamState state; /**< Current state */
  SocketHTTP2_Conn_T conn;       /**< Parent connection */

  /* Flow control */
  int32_t send_window; /**< Send window size */
  int32_t recv_window; /**< Receive window size */

  /* Received data buffer */
  SocketBuf_T recv_buf; /**< Received DATA frames */

  /* Content-Length validation */
  int64_t expected_content_length; /**< Expected Content-Length from headers (-1 if not set) */
  size_t total_data_received;      /**< Total DATA payload bytes received */

  /* Header state */
  int headers_received;    /**< Headers have been received */
  int end_stream_received; /**< END_STREAM flag received */
  int end_stream_sent;     /**< END_STREAM flag sent */
  int pending_end_stream;  /**< Pending END_STREAM flag from initial frame in
                              split headers */
  int is_push_stream;    /**< 1 if this is a server push stream, 0 otherwise */
  int trailers_received; /**< Trailers received */
  int rst_received;      /**< RST_STREAM received (prevents sending RST_STREAM in response) */

  /* RFC 8441 Extended CONNECT support */
  int is_extended_connect; /**< 1 if RFC 8441 Extended CONNECT request */
  char protocol[32];       /**< :protocol value (e.g., "websocket") for Extended CONNECT */

  /* Decoded headers storage */
  SocketHPACK_Header
      headers[SOCKETHTTP2_MAX_DECODED_HEADERS]; /**< Decoded initial headers */
  size_t header_count;  /**< Number of initial headers */
  int headers_consumed; /**< Headers already consumed by user */

  SocketHPACK_Header
      trailers[SOCKETHTTP2_MAX_DECODED_HEADERS]; /**< Decoded trailers */
  size_t trailer_count;                          /**< Number of trailers */
  int trailers_consumed; /**< Trailers already consumed by user */

  /* Pending headers (accumulated from CONTINUATION) */
  unsigned char *header_block;  /**< Accumulated header block */
  size_t header_block_len;      /**< Current length */
  size_t header_block_capacity; /**< Allocated capacity */

  /* User data */
  void *userdata;
  bool is_local_initiated; /**< True if locally initiated (for limit
                              enforcement) */

  /* Hash table chaining */
  struct SocketHTTP2_Stream *hash_next;
};

/* ============================================================================
 * Connection Structure
 * ============================================================================
 */

/**
 * @brief Internal structure for HTTP/2 connection management.
 * @ingroup http
 * @internal
 *
 * Central state holder for an HTTP/2 connection: underlying socket, memory
 * arena, role (client/server), HPACK encoder/decoder, I/O buffers, settings
 * (local/peer), flow control, stream hash table with counts and rate limits,
 * frame state (e.g., CONTINUATION, GOAWAY, PING), callbacks, timeouts, and DoS
 * protections (RST/PING/ SETTINGS rate limiting per CVE-2023-44487 and
 * similar).
 *
 * Handles protocol compliance, security hardening, and event emission.
 *
 * @note Internal fields; access via public SocketHTTP2_Conn_T functions.
 *
 * @threadsafe No - shared connection state modified without internal mutex;
 * applications must serialize calls to connection functions (e.g., via
 * external locking or single-threaded event loop)
 *
 * @see SocketHTTP2_Conn_T opaque public type.
 * @see SocketHTTP2_Conn_new() for public creation.
 * @see RFC 9113 for full HTTP/2 specification.
 * @see SocketHPACK_Encoder_T and SocketHPACK_Decoder_T for header compression.
 */
struct SocketHTTP2_Conn
{
  Socket_T socket;             /**< Underlying transport */
  Arena_T arena;               /**< Memory arena */
  SocketHTTP2_Role role;       /**< Client or server */
  SocketHTTP2_ConnState state; /**< Connection state */

  /* HPACK compressor/decompressor */
  SocketHPACK_Encoder_T encoder; /**< Header encoder */
  SocketHPACK_Decoder_T decoder; /**< Header decoder */

  /* I/O buffers */
  SocketBuf_T recv_buf; /**< Receive buffer */
  SocketBuf_T send_buf; /**< Send buffer */

  /* Settings */
  uint32_t local_settings[HTTP2_SETTINGS_COUNT]; /**< Our settings */
  uint32_t peer_settings[HTTP2_SETTINGS_COUNT];  /**< Peer's settings */
  int settings_ack_pending; /**< Waiting for SETTINGS ACK */

  /* Flow control */
  int32_t send_window;         /**< Connection send window */
  int32_t recv_window;         /**< Connection receive window */
  int32_t initial_send_window; /**< Initial stream send window */
  int32_t initial_recv_window; /**< Initial stream recv window */

  /* Stream management */
  struct SocketHTTP2_Stream **streams; /**< Hash table */
  size_t
      stream_count; /**< Active stream count (total for legacy, deprecate) */
  uint32_t client_initiated_count; /**< Count of client-initiated streams */
  uint32_t server_initiated_count; /**< Count of server-initiated streams (incl
                                      push) */
  SocketRateLimit_T
      stream_open_rate_limit; /**< Rate limit for stream creations */
  SocketRateLimit_T
      stream_close_rate_limit; /**< Rate limit for stream closes/RST */
  uint32_t hash_seed; /**< Random seed for stream hash randomization */

  uint32_t next_stream_id;      /**< Next stream ID to use */
  uint32_t last_peer_stream_id; /**< Last peer stream ID processed */
  uint32_t max_peer_stream_id;  /**< Max stream ID from GOAWAY */

  /* CONTINUATION frame state */
  uint32_t continuation_stream_id;   /**< Stream expecting CONTINUATION */
  int expecting_continuation;        /**< Expecting CONTINUATION frame */
  uint32_t continuation_frame_count; /**< Current CONTINUATION count for header
                                        block */

  /* GOAWAY state */
  int goaway_sent;                         /**< GOAWAY frame sent */
  int goaway_received;                     /**< GOAWAY frame received */
  SocketHTTP2_ErrorCode goaway_error_code; /**< GOAWAY error code */

  /* PING state */
  unsigned char ping_opaque[8]; /**< Last PING opaque data */
  int ping_pending;             /**< Waiting for PING ACK */

  /* Callbacks */
  SocketHTTP2_StreamCallback stream_callback;
  SocketHTTP2_ConnCallback conn_callback;
  void *stream_callback_data;
  void *conn_callback_data;

  /* Timeouts (milliseconds) */
  int settings_timeout_ms;
  int ping_timeout_ms;
  int idle_timeout_ms;  /**< Idle connection timeout in ms (0 = disabled) */

  /** Monotonic time (ms) when last SETTINGS frame sent, expecting ACK */
  int64_t settings_sent_time;

  /** Monotonic time (ms) when PING frame sent, expecting ACK */
  int64_t ping_sent_time;

  /** Monotonic time (ms) of last frame recv or send activity */
  int64_t last_activity_time;

  /* Frame rate limiting using TimeWindow module (sliding window counters) */
  TimeWindow_T rst_window;       /**< RST_STREAM rate limiter (CVE-2023-44487 protection) */
  TimeWindow_T ping_window;      /**< PING frame rate limiter (DoS protection) */
  TimeWindow_T settings_window;  /**< SETTINGS frame rate limiter (DoS protection) */
};

/* ============================================================================
 * Internal Functions - Frame Layer
 * ============================================================================
 */

/**
 * @brief Validate an HTTP/2 frame header against protocol rules.
 * @ingroup http
 * @internal
 *
 * Performs comprehensive checks including frame length bounds, type-specific
 * flags, stream ID validity (odd/even for client/server), dependency rules,
 * and connection state constraints (e.g., no frames before preface
 * verification).
 *
 * @param conn The HTTP/2 connection context (non-NULL).
 * @param header Pointer to frame header structure.
 * @return 0 if valid, otherwise specific HTTP/2 error code (e.g.,
 * PROTOCOL_ERROR, REFUSED_STREAM).
 * @note Early validation prevents malformed frames from proceeding to payload
 * processing.
 * @throws SocketHTTP2_ProtocolError if validation triggers connection-level
 * error.
 *
 * @threadsafe No - reads connection state without internal synchronization;
 * caller must ensure exclusive access to the connection object
 *
 * @complexity O(1) - performs a fixed set of validation checks independent of
 * input size
 *
 *  Internal Usage
 *
 * @code{.c}
 * // Example: Validate frame header in frame reader loop
 * SocketHTTP2_ErrorCode err = http2_frame_validate(conn, &header);
 * if (err != HTTP2_NO_ERROR) {
 *     SOCKET_LOG_WARN_MSG("Frame validation failed: %d", err);
 *     http2_send_connection_error(conn, err);
 *     return -1;
 * }
 * // Safe to process payload
 * int processed = http2_process_frame(conn, &header, payload);
 * @endcode
 *
 * @see http2_process_frame() for subsequent frame dispatching after
 * validation.
 * @see RFC 9113 Sections 4.1 Frame Parsing and 4.2 Frame Layout for detailed
 * validation rules.
 */
extern SocketHTTP2_ErrorCode
http2_frame_validate (SocketHTTP2_Conn_T conn,
                      const SocketHTTP2_FrameHeader *header);

/**
 * @brief Adjust flow control window by signed delta, typically from SETTINGS
 * update.
 * @ingroup http
 * @internal
 *
 * Safely modifies a 32-bit signed window size, preventing underflow (negative)
 * or overflow beyond INT32_MAX. Used when peer's INITIAL_WINDOW_SIZE setting
 * change requires updating connection and all active stream windows.
 *
 * @param window Pointer to int32_t window value to modify (non-NULL).
 * @param delta Signed integer delta (positive increase, negative decrease).
 * @return 0 on successful adjustment, -1 if delta would cause invalid state.
 * @note Logs debug info on clamping; may trigger flow control errors if
 * extreme.
 * @see http2_process_settings() for applying INITIAL_WINDOW_SIZE changes.
 * @threadsafe Yes - modifies only the caller-provided window value via
 * pointer; no shared state or connection access, safe for concurrent calls on
 * distinct windows
 *
 * @complexity O(1) - simple arithmetic adjustment and bounds check
 *
 *  Internal Usage
 *
 * @code{.c}
 * // Adjust stream window after SETTINGS change
 * int32_t stream_window = get_initial_window();
 * int32_t delta = new_setting - old_setting;
 * if (http2_flow_adjust_window(&stream_window, delta) == 0) {
 *     // Apply to all active streams
 *     for each stream {
 *         stream->send_window += delta;  // Already validated per-stream
 *     }
 *     conn->initial_send_window = new_setting;
 * } else {
 *     // Log clamping or error
 *     SOCKET_LOG_WARN_MSG("Window adjustment failed");
 * }
 * @endcode
 *
 * @see RFC 9113 Section 6.5.2 SETTINGS and Section 6.9.2 Flow Control Windows
 * for adjustment triggers.
 */
extern int http2_flow_adjust_window (int32_t *window, int32_t delta);

/**
 * @brief Serialize HTTP/2 frame and queue it in send buffer.
 * @ingroup http
 * @internal
 *
 * Builds the 9-byte frame header (length, type, flags, stream ID, reserved
 * bits), appends payload (if any), and writes to connection's send buffer.
 * Applies frame-specific serialization (e.g., big-endian integers) and
 * preliminary flow control checks for DATA frames.
 *
 * @param conn The HTTP/2 connection (non-NULL).
 * @param header Frame header with type, flags, length, stream ID populated.
 * @param payload Optional frame payload bytes (NULL if length=0).
 * @param payload_len Must match header->length; validated.
 * @return 0 if successfully queued, -1 on buffer overflow or param mismatch.
 * @throws SocketHTTP2_FlowControlError for DATA frames exceeding send window.
 *
 * @threadsafe No - modifies connection send buffer and flow control state;
 * caller must ensure exclusive access to conn
 *
 * @complexity O(frame length) - serializes and copies frame data to buffer
 *
 *  Internal Usage
 *
 * @code{.c}
 * // Send a SETTINGS ACK frame
 * SocketHTTP2_FrameHeader hdr = {0};
 * hdr.type = HTTP2_SETTINGS_FRAME;
 * hdr.flags = HTTP2_SETTINGS_ACK_FLAG;
 * hdr.length = 0;
 * hdr.stream_id = 0;
 *
 * if (http2_frame_send(conn, &hdr, NULL, 0) != 0) {
 *     SOCKET_LOG_ERROR_MSG("Failed to queue SETTINGS ACK");
 *     // Handle error, possibly close connection
 * }
 * // Buffer queued; flush later via SocketHTTP2_Conn_process() or manual send
 * @endcode
 *
 * @note Does not flush; call SocketHTTP2_Conn_flush() or process events to
 * transmit.
 *
 * @see SocketHTTP2_Conn::send_buf for buffering details.
 * @see RFC 9113 Section 4 Frame Format for header and payload serialization
 * rules.
 */
extern int http2_frame_send (SocketHTTP2_Conn_T conn,
                             const SocketHTTP2_FrameHeader *header,
                             const void *payload, size_t payload_len);

/* ============================================================================
 * Internal Functions - Stream Management
 * ============================================================================
 */

/**
 * @brief Retrieve HTTP/2 stream from connection by stream identifier.
 * @ingroup http
 * @internal
 *
 * Performs hashed lookup using stream_id modulo table size with randomized
 * seed for security, then linear search in chain for exact match. Returns NULL
 * for invalid IDs (e.g., closed streams, wrong parity for role).
 *
 * @param conn The HTTP/2 connection (non-NULL).
 * @param stream_id 31-bit unsigned stream ID (0 invalid for streams).
 * @return Matching SocketHTTP2_Stream_T or NULL if not active.
 * @note Average O(1) time; worst-case linear in chain length.
 * @throws None - safe read-only operation.
 * @see http2_stream_create() to insert into hash table.
 * @see SocketHTTP2_Conn::streams for hash table details.
 * @see RFC 9113 Section 5.1.1 Stream Identifiers and State.
 */
extern SocketHTTP2_Stream_T http2_stream_lookup (const SocketHTTP2_Conn_T conn,
                                                 uint32_t stream_id);

/**
 * @brief Create and initialize a new HTTP/2 stream structure.
 * @ingroup http
 * @internal
 *
 * Allocates stream from connection's arena, sets initial state, flow windows
 * from connection defaults, header buffers, and inserts into hash table.
 * Enforces concurrency limits, ID parity rules, and stream open rate limiting.
 * Increments appropriate stream count (client/server initiated).
 *
 * @param conn The HTTP/2 connection (non-NULL, ready state).
 * @param stream_id The 31-bit stream identifier to assign (validated).
 * @param is_local_initiated True if stream initiated locally (affects limits).
 * @return Allocated and initialized SocketHTTP2_Stream_T or NULL on error.
 * @throws SocketHTTP2_ProtocolError for invalid stream ID (e.g., wrong
 * parity).
 * @throws SocketHTTP2_StreamError if max concurrent streams or rate limit
 * exceeded.
 * @note Automatically emits stream event if callbacks registered.
 * @see http2_stream_destroy() for symmetric cleanup.
 * @see SocketHTTP2_Conn::client_initiated_count etc. for counting.
 * @see RFC 9113 Section 5.1.1 Stream Identifiers and Section 5.2 Stream
 * Concurrency.
 */
extern SocketHTTP2_Stream_T http2_stream_create (SocketHTTP2_Conn_T conn,
                                                 uint32_t stream_id,
                                                 int is_local_initiated);

/**
 * @brief Deallocate HTTP/2 stream resources and remove from connection.
 * @ingroup http
 * @internal
 *
 * Extracts stream from hash table, decrements client/server initiated counts,
 * clears recv_buf and header/trailer arrays, frees header_block if allocated,
 * resets flow windows contribution, and emits stream close event via callback.
 * Marks slot available for reuse.
 *
 * @param stream Pointer to stream to destroy (non-NULL, belonging to valid
 * conn).
 * @note Must not be called from stream callback to avoid reentrancy issues.
 * @note Automatically handles rate limiting enforcement before destruction.
 * @throws SocketHTTP2_Failed on arena free issues (rare).
 * @see http2_stream_create() for creation counterpart.
 * @see http2_emit_stream_event() for event emission.
 * @see RFC 9113 Section 5.1.1 Stream Termination.
 */
extern void http2_stream_destroy (SocketHTTP2_Stream_T stream);

/**
 * @brief Validate and apply stream state transition for frame receipt or send.
 * @ingroup http
 * @internal
 *
 * Enforces HTTP/2 state machine rules: checks current state vs. frame
 * type/flags, updates state (e.g., OPEN -> HALF_CLOSED on END_STREAM DATA),
 * handles special cases like push promise in odd states. Invalid transitions
 * trigger RST or GOAWAY.
 *
 * @param stream The HTTP/2 stream (non-NULL).
 * @param frame_type The frame type constant (e.g., HTTP2_HEADERS_FRAME).
 * @param flags The frame flags bitfield.
 * @param is_send True for sender state machine (outgoing frames), false for
 * receiver.
 * @return 0 if transition valid and applied, else HTTP/2 error code (e.g.,
 * PROTOCOL_ERROR).
 * @note Separate state machines for send/receive per RFC.
 * @throws SocketHTTP2_StreamError on stream-level invalid state change.
 * @see SocketHTTP2_StreamState enum for states.
 * @see RFC 9113 Section 5.1 Stream State Machine with transition tables.
 */
extern SocketHTTP2_ErrorCode
http2_stream_transition (SocketHTTP2_Stream_T stream, uint8_t frame_type,
                         uint8_t flags, int is_send);

/* ============================================================================
 * Internal Functions - Flow Control
 * ============================================================================
 */

/**
 * @brief Deduct bytes from receive flow control windows (connection and
 * stream).
 * @ingroup http
 * @internal
 *
 * Reduces recv_window on stream (if provided) and connection level by bytes.
 * Validates against current available; atomic update to prevent race.
 * Called after processing received DATA payload to account for buffered bytes.
 *
 * @param conn The HTTP/2 connection (non-NULL).
 * @param stream The stream (NULL for connection-level only).
 * @param bytes Positive count of bytes to consume from windows.
 * @return 0 if windows sufficient and deducted, -1 otherwise (no change made).
 * @note Triggers PROTOCOL_ERROR GOAWAY if persistent violation detected.
 * @throws SocketHTTP2_FlowControlError on window underflow attempt.
 * @see http2_flow_update_recv() to increase receive window via WINDOW_UPDATE
 * ack.
 * @see RFC 9113 Section 6.9.1 Flow Control Principles.
 */
extern int http2_flow_consume_recv (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_Stream_T stream, size_t bytes);

/**
 * @brief Deduct bytes from send flow control windows prior to frame
 * transmission.
 * @ingroup http
 * @internal
 *
 * Subtracts from stream and connection send_windows before adding DATA to send
 * buffer. Validates available via http2_flow_available_send(); atomic to avoid
 * races in multi-thread. Used in http2_frame_send for DATA frames to enforce
 * flow control.
 *
 * @param conn The HTTP/2 connection (non-NULL).
 * @param stream The stream (NULL for connection headers/priority etc.).
 * @param bytes Number of bytes to consume for sending (>0).
 * @return 0 if windows allow and deducted, -1 if insufficient (no deduction).
 * @note Send blocked until window replenished by peer WINDOW_UPDATE.
 * @throws SocketHTTP2_FlowControlError if violation would occur.
 * @see http2_flow_available_send() for pre-check.
 * @see http2_flow_update_send() for peer window increase.
 * @see RFC 9113 Section 6.9.2 Flow Control for sending.
 */
extern int http2_flow_consume_send (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_Stream_T stream, size_t bytes);

/**
 * @brief Increase receive flow control window after data consumption.
 * @ingroup http
 * @internal
 *
 * Adds increment to connection recv_window and stream recv_window (if stream).
 * Clamps to INT32_MAX; sends WINDOW_UPDATE frame if increment >0 and
 * thresholds met. Called when app reads/consumes buffered received data,
 * advertising capacity for more.
 *
 * @param conn The HTTP/2 connection (non-NULL).
 * @param stream The stream (NULL for connection-level window update).
 * @param increment uint32 amount to add (0-2^31-1 typically).
 * @return 0 if updated successfully, -1 if overflow or invalid increment
 * (<=0).
 * @note Batch updates possible; frame sent only if significant change.
 * @throws SocketHTTP2_FlowControlError on arithmetic overflow.
 * @see http2_flow_consume_recv() counterpart for consumption.
 * @see http2_process_window_update() for handling peer increments.
 * @see RFC 9113 Section 6.9.2 Receiving WINDOW_UPDATE Frames.
 */
extern int http2_flow_update_recv (SocketHTTP2_Conn_T conn,
                                   SocketHTTP2_Stream_T stream,
                                   uint32_t increment);

/**
 * @brief Update send flow control windows based on peer WINDOW_UPDATE frame.
 * @ingroup http
 * @internal
 *
 * Applies validated increment to connection send_window and stream
 * send_window. Ensures increment >0 and no overflow; may unblock pending sends
 * if window was starved. Logs suspicious large increments as potential DoS.
 *
 * @param conn The HTTP/2 connection (non-NULL).
 * @param stream The stream (NULL for connection window).
 * @param increment The uint32 increment from received WINDOW_UPDATE payload.
 * @return 0 if successfully added (clamped if needed), -1 if invalid (<=0 or
 * overflow).
 * @note Affects http2_flow_available_send() immediately.
 * @throws SocketHTTP2_FlowControlError on invalid update parameters.
 * @see http2_process_window_update() for frame parsing and call to this.
 * @see http2_flow_consume_send() for symmetric consumption on send.
 * @see RFC 9113 Section 6.9.2 Flow Control Windows: Receiving Updates.
 */
extern int http2_flow_update_send (SocketHTTP2_Conn_T conn,
                                   SocketHTTP2_Stream_T stream,
                                   uint32_t increment);

/**
 * @brief Get available send window for HTTP/2 connection or stream.
 * @ingroup http
 * @internal
 *
 * Computes the minimum available send window between the connection-level
 * and stream-level windows, clamped to >= 0. Performs validation to ensure
 * the provided stream (if any) belongs to the connection.
 *
 * @param conn The HTTP/2 connection (const, non-NULL).
 * @param stream The stream (const, may be NULL for connection window only).
 * @return Number of bytes available in send window (>=0), or negative error
 * code.
 * @note Thread-safe: Yes - read-only access to internal state.
 * @throws SocketHTTP2_FlowControlError If stream does not belong to
 * connection.
 * @see http2_flow_consume_send() to reduce the send window.
 * @see http2_flow_update_send() to increase the send window via WINDOW_UPDATE.
 */
extern int32_t http2_flow_available_send (const SocketHTTP2_Conn_T conn,
                                          const SocketHTTP2_Stream_T stream);

/* ============================================================================
 * Internal Functions - Frame Processing
 * ============================================================================
 */

/**
 * @brief Main entry for processing a received HTTP/2 frame.
 * @ingroup http
 * @internal
 *
 * After header parsing and validation, dispatches to frame-type specific
 * processor based on header->type. Handles common logic like stream lookup,
 * state transitions, flow consumption, and error propagation (RST_STREAM or
 * GOAWAY). Updates connection/stream states and may trigger callbacks.
 *
 * @param conn The HTTP/2 connection context.
 * @param header The parsed frame header structure.
 * @param payload Pointer to frame payload bytes (validated length).
 * @return 0 on successful processing, -1 on any error (may close connection).
 * @pre Frame header validated by caller or http2_frame_validate().
 * @throws SocketHTTP2_ProtocolError or sub-errors leading to GOAWAY.
 * @see http2_frame_validate() for header checks.
 * @see http2_process_data(), http2_process_headers() etc. for type handlers.
 * @see RFC 9113 Chapter 4 Frame Parsing and Chapter 6 Frame Types.
 */
extern int http2_process_frame (SocketHTTP2_Conn_T conn,
                                const SocketHTTP2_FrameHeader *header,
                                const unsigned char *payload);

/**
 * @brief Handle incoming HTTP/2 DATA frame for stream data transfer.
 * @ingroup http
 * @internal
 *
 * Extracts padding length if PADDED flag, validates total length, deducts from
 * receive flow control windows using http2_flow_consume_recv(). Appends
 * unpadded payload to stream's recv_buf, processes END_STREAM flag for state
 * transition and trailers if present. May emit stream data event to user
 * callback.
 *
 * @param conn The HTTP/2 connection.
 * @param header The DATA frame header (includes stream ID, padding flag/len).
 * @param payload Raw frame payload including optional padding.
 * @return 0 on successful processing and buffering, -1 on error (e.g., padding
 * mismatch, flow exceeded).
 * @pre Frame validated and stream exists/open.
 * @throws SocketHTTP2_FlowControlError if DATA exceeds recv window.
 * @throws SocketHTTP2_StreamError if stream closed or invalid state.
 * @see http2_flow_consume_recv() window consumption.
 * @see SocketHTTP2_Stream::recv_buf for data buffering.
 * @see RFC 9113 Section 6.1 DATA for format and flow control rules.
 */
extern int http2_process_data (SocketHTTP2_Conn_T conn,
                               const SocketHTTP2_FrameHeader *header,
                               const unsigned char *payload);

/**
 * @internal
 * @brief Process incoming HTTP/2 HEADERS frame (pseudo-headers and HPACK
 * decoding).
 * @ingroup http
 *
 * Decodes HPACK-compressed headers from payload, validates pseudo-headers
 * (e.g., :method, :path), handles END_HEADERS and PRIORITY flags, updates
 * stream state (may transition to OPEN or CLOSED). Applies header table size
 * updates if SETTINGS_ENABLE_PUSH, emits headers event to callback. Handles
 * CONTINUATION chaining for oversized headers.
 *
 * @param conn HTTP/2 connection context.
 * @param header Parsed frame header (includes stream ID, flags, length).
 * @param payload Raw frame payload bytes for HPACK decoding.
 * @return 0 on success (headers decoded and applied), -1 on error (e.g., HPACK
 * decode fail, invalid pseudo-header).
 * @pre Frame header validated, stream exists or valid for new stream.
 * @throws SocketHTTP2_ProtocolError for malformed headers or forbidden
 * pseudo-headers.
 * @throws SocketHTTP2_StreamError if stream state invalid for HEADERS.
 * @see SocketHPACK_decode() for header decompression.
 * @see http2_frame_validate() pre-validation.
 * @see RFC 9113 §6.3 HEADERS format and semantics.
 * @see RFC 7541 §4.3 Pseudo-Header Fields for server/client rules.
 */
extern int http2_process_headers (SocketHTTP2_Conn_T conn,
                                  const SocketHTTP2_FrameHeader *header,
                                  const unsigned char *payload);



/**
 * @internal
 * @brief Process incoming HTTP/2 RST_STREAM frame to abort a stream.
 * @ingroup http
 *
 * Parses 4-byte error code from payload, looks up stream by ID, transitions to
 * CLOSED state, releases recv/send windows, notifies user callback of RST with
 * error details. Counts protocol errors for potential GOAWAY if threshold
 * exceeded.
 *
 * @param conn HTTP/2 connection context.
 * @param header RST_STREAM frame header (stream ID identifies aborted stream).
 * @param payload Fixed 4-byte error code (SocketHTTP2_ErrorCode enum value).
 * @return 0 on success (stream aborted cleanly), -1 if invalid (e.g., ID=0,
 * unknown stream).
 * @pre Frame length == 4, header validated (flags must be 0).
 * @throws SocketHTTP2_ProtocolError if malformed or invalid stream ID.
 * @see SocketHTTP2_ErrorCode for standard error values (e.g., PROTOCOL_ERROR,
 * CANCEL).
 * @see RFC 9113 §6.4 RST_STREAM for abort semantics and codes.
 * @see Connection GOAWAY for repeated error handling.
 */
extern int http2_process_rst_stream (SocketHTTP2_Conn_T conn,
                                     const SocketHTTP2_FrameHeader *header,
                                     const unsigned char *payload);

/**
 * @internal
 * @brief Process incoming HTTP/2 SETTINGS frame for parameter negotiation.
 * @ingroup http
 *
 * Parses variable-length settings pairs (ID + value), applies valid ones to
 * connection config (e.g., MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE),
 * acknowledges with ACK frame if ACK flag not set. Logs deprecated settings,
 * rejects invalid IDs/values, may trigger flow control window adjustments or
 * stream limits update.
 *
 * @param conn HTTP/2 connection (updates conn->settings).
 * @param header SETTINGS frame header (flags: ACK or none).
 * @param payload Sequence of 6-byte settings (2-byte ID + 4-byte value,
 * multiple possible).
 * @return 0 on success (settings applied/acked), -1 on error (invalid
 * settings).
 * @pre Frame length even, multiple of 6 if not ACK.
 * @throws SocketHTTP2_ProtocolError for unknown settings ID or invalid values.
 * @see SocketHTTP2_Setting enum for standard IDs and defaults.
 * @see RFC 9113 §6.5 SETTINGS for negotiation rules and ACK requirement.
 * @see http2_send_settings_ack() for response generation.
 */
extern int http2_process_settings (SocketHTTP2_Conn_T conn,
                                   const SocketHTTP2_FrameHeader *header,
                                   const unsigned char *payload);

/**
 * @brief Process incoming HTTP/2 PUSH_PROMISE frame for server push promise.
 * @ingroup http
 * @internal
 *
 * Handles server-sent PUSH_PROMISE frames on client side: validates receipt
 * conditions (client role, push enabled in settings, associated stream open),
 * extracts promised stream ID (must be even, unused), creates promised stream
 * in RESERVED_REMOTE state marked as push, handles padding if flagged,
 * initiates HPACK header block decoding into promised stream's headers, sets
 * up CONTINUATION state if END_HEADERS not flagged, checks against
 * MAX_HEADER_LIST_SIZE setting.
 *
 * On failure (invalid promised ID, size exceed, etc.), sends RST_STREAM
 * (REFUSED_STREAM) or triggers GOAWAY (PROTOCOL_ERROR). Successfully starts
 * header decoding process.
 *
 * @param conn The HTTP/2 connection context (must be client role).
 * @param header PUSH_PROMISE frame header (stream_id identifies associated
 * open request stream).
 * @param payload Raw payload: optional pad length (1 byte if PADDED),
 * promised_stream_id (4 bytes), header block fragment, optional padding bytes.
 * @return 0 on successful processing (stream created, decoding queued), -1 on
 * error (connection/stream error sent, may lead to GOAWAY).
 * @pre Frame header validated by http2_frame_validate(); connection ready.
 * @throws SocketHTTP2_ProtocolError via http2_send_connection_error() on
 * validation failure.
 * @throws SocketHTTP2_StreamError via RST if stream creation fails or limits
 * exceeded.
 * @note Server push only; servers ignore incoming PUSH_PROMISE.
 * @see validate_push_promise() internal validation.
 * @see extract_push_promise_payload() payload parsing.
 * @see http2_stream_create() for promised stream allocation.
 * @see http2_decode_headers() for header block decompression.
 * @see SocketHTTP2_Conn::expecting_continuation for chaining support.
 * @see RFC 9113 Section 6.6 PUSH_PROMISE for format and semantics.
 * @see RFC 9113 Section 8.2 Server Push for usage and client control via
 * settings.
 */
extern int http2_process_push_promise (SocketHTTP2_Conn_T conn,
                                       const SocketHTTP2_FrameHeader *header,
                                       const unsigned char *payload);

/**
 * @brief Process incoming HTTP/2 PING frame for connection liveness checks and
 * timing.
 * @ingroup http
 * @internal
 *
 * Applies DoS protection by rate limiting PING frames within a sliding time
 * window; exceeds limit triggers connection closure with ENHANCE_YOUR_CALM
 * error. For frames with ACK flag, verifies the 8-byte opaque payload matches
 * any outstanding ping request opaque data, clears pending state if matched,
 * and emits HTTP2_EVENT_PING_ACK event via connection callback. For non-ACK
 * PING frames (probes from peer), immediately responds by queuing a PING ACK
 * frame echoing the same opaque payload for round-trip time measurement. PING
 * frames are connection-level (stream_id must be 0) and do not affect flow
 * control or streams.
 *
 * @param conn The HTTP/2 connection context.
 * @param header PING frame header (type=PING, length=8, stream_id=0, flags=ACK
 * or 0).
 * @param payload Fixed 8-byte opaque arbitrary data for correlation between
 * request/ACK.
 * @return 0 on successful processing (ACK queued or verified), -1 on rate
 * limit exceeded or validation failure (sends GOAWAY via connection error).
 * @pre Frame header validated (fixed length 8, stream_id 0).
 * @throws SocketHTTP2_ProtocolError indirectly if validation or state
 * mismatch.
 * @note Rate limiting uses monotonic timestamps; window reset on timeout.
 * @note Thread-safe: No - modifies connection state (use mutex if
 * multi-threaded).
 * @see SocketHTTP2_Conn::ping_count_in_window and ::ping_window_start_ms for
 * limits.
 * @see http2_frame_send() for queuing ACK response.
 * @see http2_emit_conn_event() for PING_ACK notification.
 * @see RFC 9113 Section 6.7 PING Frames for protocol details and usage.
 * @see SocketHTTP2_Conn::ping_pending and ::ping_opaque for request/ACK
 * matching.
 */
extern int http2_process_ping (SocketHTTP2_Conn_T conn,
                               const SocketHTTP2_FrameHeader *header,
                               const unsigned char *payload);

/**
 * @brief Process incoming HTTP/2 GOAWAY frame for connection shutdown
 * notification.
 * @ingroup http
 * @internal
 *
 * Parses the GOAWAY payload to extract the highest stream ID the sender has
 * processed successfully (last_stream_id, 31-bit unsigned) and the error code
 * indicating the reason for initiating shutdown (e.g., NO_ERROR for graceful
 * close, PROTOCOL_ERROR for issues). Updates connection state: sets
 * goaway_received flag, records max_peer_stream_id to prevent new streams
 * beyond this ID, and stores error code. Emits HTTP2_EVENT_GOAWAY_RECEIVED
 * event via connection callback, allowing application to handle (e.g., close
 * higher streams, retry elsewhere). Ignores frame header (pre-validated) and
 * any optional debug data following the 8-byte fixed header fields in payload.
 * Does not respond or alter other state.
 *
 * @param conn The HTTP/2 connection context.
 * @param header GOAWAY frame header (type=GOAWAY, stream_id=0, length >=8).
 * @param payload Payload: last_stream_id (4 bytes big-endian u31), error_code
 * (4 bytes u32), optional variable-length debug data (ignored).
 * @return 0 on successful parsing and state update (always succeeds
 * post-validation).
 * @pre Frame header validated by http2_frame_validate().
 * @note NO_ERROR (0) indicates graceful shutdown; non-zero codes signal errors
 * affecting new streams.
 * @note Application must poll connection state or events to detect and react.
 * @see SocketHTTP2_Conn::goaway_received, ::max_peer_stream_id,
 * ::goaway_error_code for updated fields.
 * @see http2_emit_conn_event() for event notification.
 * @see http2_send_connection_error() for sending local GOAWAY.
 * @see RFC 9113 Section 6.8 GOAWAY for format, semantics, and error code
 * details.
 * @see RFC 9113 Section 9.3 for HTTP/2 error handling and connection closure.
 */
extern int http2_process_goaway (SocketHTTP2_Conn_T conn,
                                 const SocketHTTP2_FrameHeader *header,
                                 const unsigned char *payload);

/**
 * @brief Process incoming HTTP/2 WINDOW_UPDATE frame to replenish flow control
 * windows.
 * @ingroup http
 * @internal
 *
 * Deserializes the 31-bit unsigned window increment from the fixed 4-byte
 * payload. Rejects increment == 0 as PROTOCOL_ERROR, sending GOAWAY
 * (connection-level) or RST_STREAM (stream-level) accordingly. For
 * connection-level updates (stream_id=0), applies increment to connection send
 * window using http2_flow_update_send (NULL stream); arithmetic overflow or
 * invalid state triggers GOAWAY with FLOW_CONTROL_ERROR. For stream-level
 * (stream_id >0), retrieves stream via lookup; if found, updates both stream
 * and connection send windows, emits HTTP2_EVENT_WINDOW_UPDATE via stream
 * callback on success; failure sends RST_STREAM with FLOW_CONTROL_ERROR to
 * that stream. Unknown or closed streams are silently ignored per RFC. This
 * frame allows receiver to advertise additional data capacity after consuming
 * buffered DATA, unblocking peer sends.
 *
 * @param conn The HTTP/2 connection context.
 * @param header WINDOW_UPDATE frame header (type=WINDOW_UPDATE, length=4,
 * stream_id=0 or stream ID).
 * @param payload Fixed 4-byte big-endian unsigned 31-bit increment (>0
 * required).
 * @return 0 on successful update (or ignore for unknown stream), -1 on
 * validation or update error (sends GOAWAY or RST_STREAM as appropriate).
 * @pre Frame header validated by http2_frame_validate().
 * @throws SocketHTTP2_FlowControlError via error frames on window update
 * failure (e.g., overflow).
 * @throws SocketHTTP2_ProtocolError for zero increment.
 * @note Updates affect http2_flow_available_send() immediately, potentially
 * unblocking sends.
 * @see http2_flow_update_send() for window arithmetic and validation.
 * @see process_connection_window_update() and process_stream_window_update()
 * for dispatch logic.
 * @see http2_stream_lookup() for stream retrieval.
 * @see http2_emit_stream_event() for event emission on stream updates.
 * @see RFC 9113 Section 6.9 WINDOW_UPDATE Frames for details and rules.
 * @see RFC 9113 Section 6.9.2 Flow-Control Windows: receiving updates.
 * @see RFC 9113 Section 5.1 Stream States: window updates only on
 * open/half-closed streams.
 */
extern int http2_process_window_update (SocketHTTP2_Conn_T conn,
                                        const SocketHTTP2_FrameHeader *header,
                                        const unsigned char *payload);

/**
 * @brief Process incoming HTTP/2 CONTINUATION frame to continue oversized
 * header blocks.
 * @ingroup http
 * @internal
 *
 * Validates the frame occurs immediately after a HEADERS, PUSH_PROMISE, or
 * previous CONTINUATION without END_HEADERS (checks expecting_continuation and
 * stream_id match). Retrieves the target stream; failure or no pending
 * header_block triggers PROTOCOL_ERROR GOAWAY. Enforces limit on CONTINUATION
 * frames per header block to mitigate DoS floods (exceed -> GOAWAY
 * ENHANCE_YOUR_CALM). Appends payload fragment to stream's accumulated
 * header_block, validating total size <= MAX_HEADER_LIST_SIZE setting (exceed
 * -> RST_STREAM ENHANCE_YOUR_CALM). Dynamically grows the temporary buffer if
 * needed via arena allocation. If END_HEADERS flag set, finalizes the block:
 * resets continuation state, decodes complete HPACK header block into stream's
 * headers[] or trailers[] array (depending on context), emits headers event
 * via stream callback, applies any pending END_STREAM from initial frame, and
 * frees the temporary header_block. Supports split headers for large or
 * compressed blocks.
 *
 * @param conn The HTTP/2 connection context (must be expecting CONTINUATION).
 * @param header CONTINUATION frame header (type=CONTINUATION,
 * stream_id=pending stream, flags=END_HEADERS or 0, length=fragment size; no
 * padding/priority).
 * @param payload Raw header block fragment bytes to append (HPACK compressed).
 * @return 0 on successful append or complete processing/decode, -1 on
 * validation, size exceed, or DoS detection (sends GOAWAY or RST_STREAM).
 * @pre Frame header validated by http2_frame_validate(); prior frame set
 * continuation state.
 * @throws SocketHTTP2_ProtocolError on unexpected CONTINUATION or state
 * mismatch.
 * @throws SocketHTTP2_StreamError via RST on size limits or stream issues.
 * @note CONTINUATION must strictly follow without interleaving other frames
 * for same stream.
 * @note Temporary buffer grown via arena; cleared after decode to free memory.
 * @see SocketHTTP2_Conn::expecting_continuation, ::continuation_stream_id,
 * ::continuation_frame_count.
 * @see SocketHTTP2_Stream::header_block, ::header_block_len for accumulation.
 * @see http2_decode_headers() invoked on END_HEADERS for HPACK decompression.
 * @see grow_header_block() for buffer expansion.
 * @see RFC 9113 Section 6.10 CONTINUATION Frames for sequencing and format.
 * @see RFC 9113 Section 4.3 Header Block Fragment for split handling rules.
 * @see RFC 9114 Section 4 for HPACK block processing after reassembly.
 */
extern int http2_process_continuation (SocketHTTP2_Conn_T conn,
                                       const SocketHTTP2_FrameHeader *header,
                                       const unsigned char *payload);

/* ============================================================================
 * Internal Functions - Header Processing
 * ============================================================================
 */

/**
 * @brief Decode HPACK-compressed header block into stream headers/trailers.
 * @ingroup http
 * @internal
 *
 * Uses connection's SocketHPACK_Decoder_T to decompress block, validating
 * against max header list size setting. Stores decoded SocketHPACK_Header in
 * stream's headers[] or trailers[] array, handling pseudo-headers order and
 * duplicates. Supports CONTINUATION by appending to pending block if in
 * progress.
 *
 * @param conn The HTTP/2 connection with decoder context.
 * @param stream The target stream for storing decoded headers (non-NULL).
 * @param block Compressed HPACK header block bytes.
 * @param len Length of block.
 * @return 0 on successful decoding and storage, -1 on HPACK error or limits
 * exceeded.
 * @pre Decoder initialized; stream expecting headers (HEADERS/PUSH_PROMISE
 * frame).
 * @throws SocketHTTP2_ProtocolError on decompression failure or invalid
 * headers.
 * @see SocketHPACK_Decoder_T::decode for low-level HPACK.
 * @see SocketHTTP2_Stream::headers and ::trailers for storage.
 * @see RFC 9114 HPACK Section 4 Header Block Decoding.
 */
extern int http2_decode_headers (SocketHTTP2_Conn_T conn,
                                 SocketHTTP2_Stream_T stream,
                                 const unsigned char *block, size_t len);

/**
 * @brief Encode array of headers into HPACK-compressed block for transmission.
 * @ingroup http
 * @internal
 *
 * Utilizes connection's SocketHPACK_Encoder_T to compress headers, applying
 * dynamic table updates, huffman coding where beneficial, and size limits.
 * Ensures pseudo- headers first, validates against peer MAX_HEADER_LIST_SIZE.
 * Produces block for HEADERS, PUSH_PROMISE, or CONTINUATION frames.
 *
 * @param conn The HTTP/2 connection with encoder context.
 * @param headers Array of SocketHPACK_Header to encode (non-NULL).
 * @param count Number of headers in array (>0).
 * @param output Buffer to write compressed block (non-NULL).
 * @param output_size Available space in output (>= header block size).
 * @return Number of bytes written to output, or -1 on compression failure or
 * overflow.
 * @pre Encoder initialized via settings.
 * @throws SocketHTTP2_ProtocolError if headers violate encoding rules (e.g.,
 * size).
 * @see SocketHPACK_Encoder_T::encode for core logic.
 * @see http2_frame_send() to frame and queue the block.
 * @see RFC 9114 HPACK Section 3 Header Block Encoding and Section 6. Huffman
 * Coding.
 */
extern ssize_t http2_encode_headers (SocketHTTP2_Conn_T conn,
                                     const SocketHPACK_Header *headers,
                                     size_t count, unsigned char *output,
                                     size_t output_size);

/* ============================================================================
 * Internal Functions - Utility
 * ============================================================================
 */

/**
 * @brief Emit GOAWAY frame with error code and shutdown connection gracefully.
 * @ingroup http
 * @internal
 *
 * Builds GOAWAY frame identifying last processed stream ID and error code,
 * optionally appends debug data. Sends via frame_send, sets internal flags,
 * transitions state to GOAWAY_SENT, closes higher streams, notifies via
 * callback, and finally closes underlying socket after drain.
 *
 * @param conn The HTTP/2 connection in error state.
 * @param error_code The SocketHTTP2_ErrorCode to include in GOAWAY (e.g.,
 * NO_ERROR for clean close).
 * @note Does not block; asynchronous close after send.
 * @throws SocketHTTP2_Failed if frame send fails (socket error).
 * @see http2_send_stream_error() for per-stream RST_STREAM.
 * @see SocketHTTP2_Conn::goaway_sent and ::goaway_error_code.
 * @see RFC 9113 Section 6.8 GOAWAY for error notification and shutdown
 * sequence.
 */
extern void http2_send_connection_error (SocketHTTP2_Conn_T conn,
                                         SocketHTTP2_ErrorCode error_code);

/**
 * @brief Send RST_STREAM frame to terminate a specific stream abruptly.
 * @ingroup http
 * @internal
 *
 * Serializes 4-byte error code into RST_STREAM payload, targets stream_id,
 * sends via http2_frame_send without flow check (control frame). Applies
 * close rate limiting; immediately closes local stream state/resources.
 * Notifies peer of error for cleanup.
 *
 * @param conn The HTTP/2 connection.
 * @param stream_id The 31-bit ID of stream to reset.
 * @param error_code SocketHTTP2_ErrorCode reason (e.g., PROTOCOL_ERROR,
 * CANCEL).
 * @note Does not affect other streams or connection.
 * @throws SocketHTTP2_StreamError if stream ID invalid or rate limited.
 * @see http2_process_rst_stream() for receiving RST.
 * @see SocketHTTP2_Conn::stream_close_rate_limit for flood protection.
 * @see RFC 9113 Section 6.4 RST_STREAM for usage and codes.
 */
extern void http2_send_stream_error (SocketHTTP2_Conn_T conn,
                                     uint32_t stream_id,
                                     SocketHTTP2_ErrorCode error_code);

/**
 * @brief Invoke registered stream event callback for notifications.
 * @ingroup http
 * @internal
 *
 * Calls the connection's stream_callback function if registered (non-null),
 * passing the connection context, the affected stream, the specific event type
 * (e.g., HTTP2_EVENT_HEADERS_RECEIVED, HTTP2_EVENT_DATA_RECEIVED,
 * HTTP2_EVENT_STREAM_RESET, HTTP2_EVENT_WINDOW_UPDATE), and the associated
 * userdata. Includes null checks on conn and stream parameters to safely skip
 * invocation if invalid. Emitted internally after key stream lifecycle events
 * like header decoding complete, data buffering, flow control updates, or
 * error conditions, enabling user code to react (e.g., parse headers, forward
 * data, retry logic). Synchronous direct call; does not queue events.
 *
 * @param conn The HTTP/2 connection containing the callback registration
 * (null-safe).
 * @param stream The stream associated with the event (null-safe).
 * @param event Event identifier from HTTP2_EVENT_* constants.
 * @note Callback execution is immediate; user must avoid modifying conn/stream
 * destructively.
 * @note No return value from callback; fire-and-forget notification.
 * @note Thread-unsafe: Direct state access; serialize if multi-threaded.
 * @see SocketHTTP2_Conn::stream_callback and ::stream_callback_data for
 * registration.
 * @see SocketHTTP2_StreamCallback typedef in SocketHTTP2.h for function
 * signature.
 * @see http2_emit_conn_event() counterpart for connection events.
 * @see Usage in frame processors like http2_process_headers(),
 * http2_process_data().
 */
extern void http2_emit_stream_event (SocketHTTP2_Conn_T conn,
                                     SocketHTTP2_Stream_T stream, int event);

/**
 * @brief Invoke registered connection event callback for notifications.
 * @ingroup http
 * @internal
 *
 * Calls the connection's conn_callback function if registered (non-null),
 * passing the connection context, the event type (e.g.,
 * HTTP2_EVENT_SETTINGS_ACK, HTTP2_EVENT_PING_ACK, HTTP2_EVENT_GOAWAY_RECEIVED,
 * HTTP2_EVENT_CONN_CLOSED), and the associated userdata. Includes null check
 * on conn to safely skip if invalid. Emitted internally after significant
 * connection-level events like settings negotiation complete, ping
 * acknowledgments, GOAWAY receipt, or connection closure/ready states,
 * allowing user code to monitor health, adjust configuration, or initiate
 * failover. Synchronous direct call; no queuing.
 *
 * @param conn The HTTP/2 connection containing the callback registration
 * (null-safe).
 * @param event Event identifier from HTTP2_EVENT_* constants
 * (connection-specific).
 * @note Immediate execution; user callback should not destroy the connection.
 * @note Fire-and-forget; callback return ignored.
 * @note Thread-unsafe: Direct access; protect with locks in concurrent use.
 * @see SocketHTTP2_Conn::conn_callback and ::conn_callback_data for
 * registration.
 * @see SocketHTTP2_ConnCallback typedef in SocketHTTP2.h for function
 * signature.
 * @see http2_emit_stream_event() for stream-specific events.
 * @see Examples: emitted in http2_process_settings(), http2_process_ping(),
 * http2_process_goaway().
 */
extern void http2_emit_conn_event (SocketHTTP2_Conn_T conn, int event);

/**
 * @} -- http2_private
 */

#endif /* SOCKETHTTP2_PRIVATE_INCLUDED */

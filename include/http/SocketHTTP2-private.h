/**
 * SocketHTTP2-private.h - HTTP/2 Internal Structures
 *
 * Part of the Socket Library
 * Internal header - do not include directly.
 */

#ifndef SOCKETHTTP2_PRIVATE_INCLUDED
#define SOCKETHTTP2_PRIVATE_INCLUDED

#include "http/SocketHTTP2.h"
#include "http/SocketHPACK.h"
#include "socket/SocketBuf.h"

/* ============================================================================
 * Connection Preface
 * ============================================================================ */

/** Client connection preface magic string */
static const unsigned char HTTP2_CLIENT_PREFACE[HTTP2_PREFACE_SIZE]
    = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/* ============================================================================
 * Internal Settings Array Indices
 * ============================================================================ */

#define SETTINGS_IDX_HEADER_TABLE_SIZE 0
#define SETTINGS_IDX_ENABLE_PUSH 1
#define SETTINGS_IDX_MAX_CONCURRENT_STREAMS 2
#define SETTINGS_IDX_INITIAL_WINDOW_SIZE 3
#define SETTINGS_IDX_MAX_FRAME_SIZE 4
#define SETTINGS_IDX_MAX_HEADER_LIST_SIZE 5

/* ============================================================================
 * Connection State
 * ============================================================================ */

/**
 * HTTP/2 connection handshake state
 */
typedef enum
{
  HTTP2_CONN_STATE_INIT = 0,       /**< Initial state */
  HTTP2_CONN_STATE_PREFACE_SENT,   /**< Client preface sent */
  HTTP2_CONN_STATE_PREFACE_RECV,   /**< Server preface received */
  HTTP2_CONN_STATE_SETTINGS_SENT,  /**< SETTINGS sent */
  HTTP2_CONN_STATE_SETTINGS_RECV,  /**< SETTINGS received */
  HTTP2_CONN_STATE_READY,          /**< Connection ready */
  HTTP2_CONN_STATE_GOAWAY_SENT,    /**< GOAWAY sent */
  HTTP2_CONN_STATE_GOAWAY_RECV,    /**< GOAWAY received */
  HTTP2_CONN_STATE_CLOSED          /**< Connection closed */
} SocketHTTP2_ConnState;

/* ============================================================================
 * Stream Structure
 * ============================================================================ */

/**
 * HTTP/2 stream
 */
struct SocketHTTP2_Stream
{
  uint32_t id;                    /**< Stream identifier */
  SocketHTTP2_StreamState state;  /**< Current state */
  SocketHTTP2_Conn_T conn;        /**< Parent connection */

  /* Flow control */
  int32_t send_window;            /**< Send window size */
  int32_t recv_window;            /**< Receive window size */

  /* Received data buffer */
  SocketBuf_T recv_buf;           /**< Received DATA frames */

  /* Header state */
  int headers_received;           /**< Headers have been received */
  int end_stream_received;        /**< END_STREAM flag received */
  int end_stream_sent;            /**< END_STREAM flag sent */
  int trailers_received;          /**< Trailers received */

  /* Pending headers (accumulated from CONTINUATION) */
  unsigned char *header_block;    /**< Accumulated header block */
  size_t header_block_len;        /**< Current length */
  size_t header_block_capacity;   /**< Allocated capacity */

  /* User data */
  void *userdata;

  /* Hash table chaining */
  struct SocketHTTP2_Stream *hash_next;
};

/* ============================================================================
 * Connection Structure
 * ============================================================================ */

/**
 * HTTP/2 connection
 */
struct SocketHTTP2_Conn
{
  Socket_T socket;                /**< Underlying transport */
  Arena_T arena;                  /**< Memory arena */
  SocketHTTP2_Role role;          /**< Client or server */
  SocketHTTP2_ConnState state;    /**< Connection state */

  /* HPACK compressor/decompressor */
  SocketHPACK_Encoder_T encoder;  /**< Header encoder */
  SocketHPACK_Decoder_T decoder;  /**< Header decoder */

  /* I/O buffers */
  SocketBuf_T recv_buf;           /**< Receive buffer */
  SocketBuf_T send_buf;           /**< Send buffer */

  /* Settings */
  uint32_t local_settings[HTTP2_SETTINGS_COUNT];  /**< Our settings */
  uint32_t peer_settings[HTTP2_SETTINGS_COUNT];   /**< Peer's settings */
  int settings_ack_pending;       /**< Waiting for SETTINGS ACK */

  /* Flow control */
  int32_t send_window;            /**< Connection send window */
  int32_t recv_window;            /**< Connection receive window */
  int32_t initial_send_window;    /**< Initial stream send window */
  int32_t initial_recv_window;    /**< Initial stream recv window */

  /* Stream management */
  struct SocketHTTP2_Stream **streams;  /**< Hash table */
  size_t stream_count;            /**< Active stream count */
  uint32_t next_stream_id;        /**< Next stream ID to use */
  uint32_t last_peer_stream_id;   /**< Last peer stream ID processed */
  uint32_t max_peer_stream_id;    /**< Max stream ID from GOAWAY */

  /* CONTINUATION frame state */
  uint32_t continuation_stream_id; /**< Stream expecting CONTINUATION */
  int expecting_continuation;      /**< Expecting CONTINUATION frame */

  /* GOAWAY state */
  int goaway_sent;                /**< GOAWAY frame sent */
  int goaway_received;            /**< GOAWAY frame received */
  SocketHTTP2_ErrorCode goaway_error_code;  /**< GOAWAY error code */

  /* PING state */
  unsigned char ping_opaque[8];   /**< Last PING opaque data */
  int ping_pending;               /**< Waiting for PING ACK */

  /* Callbacks */
  SocketHTTP2_StreamCallback stream_callback;
  SocketHTTP2_ConnCallback conn_callback;
  void *stream_callback_data;
  void *conn_callback_data;

  /* Timeouts (milliseconds) */
  int settings_timeout_ms;
  int ping_timeout_ms;
  int idle_timeout_ms;

  /* RST_STREAM rate limiting (CVE-2023-44487 protection) */
  uint32_t rst_count_in_window; /**< RST_STREAM count in current window */
  int64_t rst_window_start_ms;  /**< Window start timestamp (monotonic) */
};

/* ============================================================================
 * Internal Functions - Frame Layer
 * ============================================================================ */

/**
 * http2_frame_validate - Validate frame against protocol rules
 * @conn: Connection
 * @header: Frame header
 *
 * Returns: 0 if valid, HTTP2 error code if invalid
 */
extern SocketHTTP2_ErrorCode http2_frame_validate (SocketHTTP2_Conn_T conn,
                                                   const SocketHTTP2_FrameHeader *header);

/**
 * http2_frame_send - Queue frame for sending
 * @conn: Connection
 * @header: Frame header
 * @payload: Payload data (may be NULL)
 * @payload_len: Payload length
 *
 * Returns: 0 on success, -1 on error
 */
extern int http2_frame_send (SocketHTTP2_Conn_T conn,
                             const SocketHTTP2_FrameHeader *header,
                             const void *payload, size_t payload_len);

/* ============================================================================
 * Internal Functions - Stream Management
 * ============================================================================ */

/**
 * http2_stream_lookup - Find stream by ID
 * @conn: Connection
 * @stream_id: Stream identifier
 *
 * Returns: Stream or NULL if not found
 */
extern SocketHTTP2_Stream_T http2_stream_lookup (const SocketHTTP2_Conn_T conn,
                                                 uint32_t stream_id);

/**
 * http2_stream_create - Create stream with specific ID
 * @conn: Connection
 * @stream_id: Stream identifier
 *
 * Returns: New stream or NULL on error
 */
extern SocketHTTP2_Stream_T http2_stream_create (SocketHTTP2_Conn_T conn,
                                                 uint32_t stream_id);

/**
 * http2_stream_destroy - Remove and free stream
 * @stream: Stream to destroy
 */
extern void http2_stream_destroy (SocketHTTP2_Stream_T stream);

/**
 * http2_stream_transition - Attempt state transition
 * @stream: Stream
 * @frame_type: Incoming frame type
 * @flags: Frame flags
 * @is_send: 1 if sending, 0 if receiving
 *
 * Returns: 0 on valid transition, HTTP2 error code on invalid
 */
extern SocketHTTP2_ErrorCode http2_stream_transition (SocketHTTP2_Stream_T stream,
                                                      uint8_t frame_type,
                                                      uint8_t flags,
                                                      int is_send);

/* ============================================================================
 * Internal Functions - Flow Control
 * ============================================================================ */

/**
 * http2_flow_consume_recv - Consume receive window
 * @conn: Connection
 * @stream: Stream (may be NULL for connection-only)
 * @bytes: Bytes consumed
 *
 * Returns: 0 on success, -1 if window exceeded
 */
extern int http2_flow_consume_recv (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_Stream_T stream,
                                    size_t bytes);

/**
 * http2_flow_consume_send - Consume send window
 * @conn: Connection
 * @stream: Stream (may be NULL for connection-only)
 * @bytes: Bytes consumed
 *
 * Returns: 0 on success, -1 if window exceeded
 */
extern int http2_flow_consume_send (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_Stream_T stream,
                                    size_t bytes);

/**
 * http2_flow_update_recv - Update receive window
 * @conn: Connection
 * @stream: Stream (may be NULL for connection-only)
 * @increment: Window increment
 *
 * Returns: 0 on success, -1 on overflow
 */
extern int http2_flow_update_recv (SocketHTTP2_Conn_T conn,
                                   SocketHTTP2_Stream_T stream,
                                   uint32_t increment);

/**
 * http2_flow_update_send - Update send window (from WINDOW_UPDATE)
 * @conn: Connection
 * @stream: Stream (may be NULL for connection-only)
 * @increment: Window increment
 *
 * Returns: 0 on success, -1 on overflow
 */
extern int http2_flow_update_send (SocketHTTP2_Conn_T conn,
                                   SocketHTTP2_Stream_T stream,
                                   uint32_t increment);

/**
 * http2_flow_available_send - Get available send window
 * @conn: Connection
 * @stream: Stream (may be NULL for connection-only)
 *
 * Returns: Minimum of connection and stream windows
 */
extern int32_t http2_flow_available_send (SocketHTTP2_Conn_T conn,
                                          SocketHTTP2_Stream_T stream);

/* ============================================================================
 * Internal Functions - Frame Processing
 * ============================================================================ */

/**
 * http2_process_frame - Process a single frame
 * @conn: Connection
 * @header: Frame header
 * @payload: Frame payload
 *
 * Returns: 0 on success, -1 on error
 */
extern int http2_process_frame (SocketHTTP2_Conn_T conn,
                                const SocketHTTP2_FrameHeader *header,
                                const unsigned char *payload);

/**
 * http2_process_data - Process DATA frame
 */
extern int http2_process_data (SocketHTTP2_Conn_T conn,
                               const SocketHTTP2_FrameHeader *header,
                               const unsigned char *payload);

/**
 * http2_process_headers - Process HEADERS frame
 */
extern int http2_process_headers (SocketHTTP2_Conn_T conn,
                                  const SocketHTTP2_FrameHeader *header,
                                  const unsigned char *payload);

/**
 * http2_process_priority - Process PRIORITY frame
 */
extern int http2_process_priority (SocketHTTP2_Conn_T conn,
                                   const SocketHTTP2_FrameHeader *header,
                                   const unsigned char *payload);

/**
 * http2_process_rst_stream - Process RST_STREAM frame
 */
extern int http2_process_rst_stream (SocketHTTP2_Conn_T conn,
                                     const SocketHTTP2_FrameHeader *header,
                                     const unsigned char *payload);

/**
 * http2_process_settings - Process SETTINGS frame
 */
extern int http2_process_settings (SocketHTTP2_Conn_T conn,
                                   const SocketHTTP2_FrameHeader *header,
                                   const unsigned char *payload);

/**
 * http2_process_push_promise - Process PUSH_PROMISE frame
 */
extern int http2_process_push_promise (SocketHTTP2_Conn_T conn,
                                       const SocketHTTP2_FrameHeader *header,
                                       const unsigned char *payload);

/**
 * http2_process_ping - Process PING frame
 */
extern int http2_process_ping (SocketHTTP2_Conn_T conn,
                               const SocketHTTP2_FrameHeader *header,
                               const unsigned char *payload);

/**
 * http2_process_goaway - Process GOAWAY frame
 */
extern int http2_process_goaway (SocketHTTP2_Conn_T conn,
                                 const SocketHTTP2_FrameHeader *header,
                                 const unsigned char *payload);

/**
 * http2_process_window_update - Process WINDOW_UPDATE frame
 */
extern int http2_process_window_update (SocketHTTP2_Conn_T conn,
                                        const SocketHTTP2_FrameHeader *header,
                                        const unsigned char *payload);

/**
 * http2_process_continuation - Process CONTINUATION frame
 */
extern int http2_process_continuation (SocketHTTP2_Conn_T conn,
                                       const SocketHTTP2_FrameHeader *header,
                                       const unsigned char *payload);

/* ============================================================================
 * Internal Functions - Header Processing
 * ============================================================================ */

/**
 * http2_decode_headers - Decode HPACK header block
 * @conn: Connection
 * @stream: Target stream
 * @block: Header block data
 * @len: Block length
 *
 * Returns: 0 on success, -1 on error
 */
extern int http2_decode_headers (SocketHTTP2_Conn_T conn,
                                 SocketHTTP2_Stream_T stream,
                                 const unsigned char *block,
                                 size_t len);

/**
 * http2_encode_headers - Encode headers using HPACK
 * @conn: Connection
 * @headers: Headers to encode
 * @count: Number of headers
 * @output: Output buffer
 * @output_size: Buffer size
 *
 * Returns: Encoded length, or -1 on error
 */
extern ssize_t http2_encode_headers (SocketHTTP2_Conn_T conn,
                                     const SocketHPACK_Header *headers,
                                     size_t count,
                                     unsigned char *output,
                                     size_t output_size);

/* ============================================================================
 * Internal Functions - Utility
 * ============================================================================ */

/**
 * http2_send_connection_error - Send GOAWAY and close
 * @conn: Connection
 * @error_code: Error code
 */
extern void http2_send_connection_error (SocketHTTP2_Conn_T conn,
                                         SocketHTTP2_ErrorCode error_code);

/**
 * http2_send_stream_error - Send RST_STREAM
 * @conn: Connection
 * @stream_id: Stream ID
 * @error_code: Error code
 */
extern void http2_send_stream_error (SocketHTTP2_Conn_T conn,
                                     uint32_t stream_id,
                                     SocketHTTP2_ErrorCode error_code);

/**
 * http2_emit_stream_event - Emit stream event callback
 */
extern void http2_emit_stream_event (SocketHTTP2_Conn_T conn,
                                     SocketHTTP2_Stream_T stream,
                                     int event);

/**
 * http2_emit_conn_event - Emit connection event callback
 */
extern void http2_emit_conn_event (SocketHTTP2_Conn_T conn, int event);

#endif /* SOCKETHTTP2_PRIVATE_INCLUDED */


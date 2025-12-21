/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP2-private.h
 * @brief Internal HTTP/2 connection and stream structures.
 * @internal
 *
 * Header validation follows RFC 9113 requirements:
 * - Pseudo-headers (:*) before regular headers, no duplication
 * - Required request: :method, :scheme/:authority, :path
 * - Required response: :status
 * - Forbidden: connection-specific headers (connection, keep-alive, etc.)
 * - TE header: only "trailers" allowed
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
extern const Except_T SocketHTTP2;

static const unsigned char HTTP2_CLIENT_PREFACE[HTTP2_PREFACE_SIZE]
    = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#define SETTINGS_IDX_HEADER_TABLE_SIZE 0
#define SETTINGS_IDX_ENABLE_PUSH 1
#define SETTINGS_IDX_MAX_CONCURRENT_STREAMS 2
#define SETTINGS_IDX_INITIAL_WINDOW_SIZE 3
#define SETTINGS_IDX_MAX_FRAME_SIZE 4
#define SETTINGS_IDX_MAX_HEADER_LIST_SIZE 5
#define SETTINGS_IDX_ENABLE_CONNECT_PROTOCOL 6

#define HTTP2_SETTING_ENTRY_SIZE 6
#define HTTP2_PING_PAYLOAD_SIZE 8
#define HTTP2_GOAWAY_HEADER_SIZE 8
#define HTTP2_WINDOW_UPDATE_SIZE 4
#define HTTP2_RST_STREAM_PAYLOAD_SIZE 4
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
  HTTP2_CONN_STATE_CLOSED
} SocketHTTP2_ConnState;
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
  TimeWindow_T rst_window;       /**< RST_STREAM rate limiter (CVE-2023-44487) */
  TimeWindow_T ping_window;      /**< PING frame rate limiter */
  TimeWindow_T settings_window;  /**< SETTINGS frame rate limiter */
};
/* Validate frame header against protocol rules */
extern SocketHTTP2_ErrorCode
http2_frame_validate (SocketHTTP2_Conn_T conn,
                      const SocketHTTP2_FrameHeader *header);

/* Adjust flow control window by signed delta */
extern int http2_flow_adjust_window (int32_t *window, int32_t delta);

/* Serialize frame and queue in send buffer */
extern int http2_frame_send (SocketHTTP2_Conn_T conn,
                             const SocketHTTP2_FrameHeader *header,
                             const void *payload, size_t payload_len);

/* Retrieve stream from connection by ID */
extern SocketHTTP2_Stream_T http2_stream_lookup (const SocketHTTP2_Conn_T conn,
                                                 uint32_t stream_id);

/* Create and initialize new stream */
extern SocketHTTP2_Stream_T http2_stream_create (SocketHTTP2_Conn_T conn,
                                                 uint32_t stream_id,
                                                 int is_local_initiated);

/* Deallocate stream resources and remove from connection */
extern void http2_stream_destroy (SocketHTTP2_Stream_T stream);

/* Validate and apply stream state transition */
extern SocketHTTP2_ErrorCode
http2_stream_transition (SocketHTTP2_Stream_T stream, uint8_t frame_type,
                         uint8_t flags, int is_send);

/* Deduct bytes from receive flow control windows */
extern int http2_flow_consume_recv (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_Stream_T stream, size_t bytes);

/* Deduct bytes from send flow control windows */
extern int http2_flow_consume_send (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_Stream_T stream, size_t bytes);

/* Increase receive flow control window */
extern int http2_flow_update_recv (SocketHTTP2_Conn_T conn,
                                   SocketHTTP2_Stream_T stream,
                                   uint32_t increment);

/* Update send flow control windows from peer WINDOW_UPDATE */
extern int http2_flow_update_send (SocketHTTP2_Conn_T conn,
                                   SocketHTTP2_Stream_T stream,
                                   uint32_t increment);

/* Get available send window */
extern int32_t http2_flow_available_send (const SocketHTTP2_Conn_T conn,
                                          const SocketHTTP2_Stream_T stream);

/* Process received HTTP/2 frame */
extern int http2_process_frame (SocketHTTP2_Conn_T conn,
                                const SocketHTTP2_FrameHeader *header,
                                const unsigned char *payload);

/* Handle incoming DATA frame */
extern int http2_process_data (SocketHTTP2_Conn_T conn,
                               const SocketHTTP2_FrameHeader *header,
                               const unsigned char *payload);

/* Process HEADERS frame with HPACK decoding */
extern int http2_process_headers (SocketHTTP2_Conn_T conn,
                                  const SocketHTTP2_FrameHeader *header,
                                  const unsigned char *payload);

/* Process RST_STREAM frame to abort stream */
extern int http2_process_rst_stream (SocketHTTP2_Conn_T conn,
                                     const SocketHTTP2_FrameHeader *header,
                                     const unsigned char *payload);

/* Process SETTINGS frame for parameter negotiation */
extern int http2_process_settings (SocketHTTP2_Conn_T conn,
                                   const SocketHTTP2_FrameHeader *header,
                                   const unsigned char *payload);

/* Process PUSH_PROMISE frame for server push */
extern int http2_process_push_promise (SocketHTTP2_Conn_T conn,
                                       const SocketHTTP2_FrameHeader *header,
                                       const unsigned char *payload);

/* Process PING frame for liveness checks */
extern int http2_process_ping (SocketHTTP2_Conn_T conn,
                               const SocketHTTP2_FrameHeader *header,
                               const unsigned char *payload);

/* Process GOAWAY frame for connection shutdown */
extern int http2_process_goaway (SocketHTTP2_Conn_T conn,
                                 const SocketHTTP2_FrameHeader *header,
                                 const unsigned char *payload);

/* Process WINDOW_UPDATE frame to replenish flow control */
extern int http2_process_window_update (SocketHTTP2_Conn_T conn,
                                        const SocketHTTP2_FrameHeader *header,
                                        const unsigned char *payload);

/* Process CONTINUATION frame for oversized header blocks */
extern int http2_process_continuation (SocketHTTP2_Conn_T conn,
                                       const SocketHTTP2_FrameHeader *header,
                                       const unsigned char *payload);

/* Decode HPACK-compressed header block */
extern int http2_decode_headers (SocketHTTP2_Conn_T conn,
                                 SocketHTTP2_Stream_T stream,
                                 const unsigned char *block, size_t len);

/* Encode headers into HPACK-compressed block */
extern ssize_t http2_encode_headers (SocketHTTP2_Conn_T conn,
                                     const SocketHPACK_Header *headers,
                                     size_t count, unsigned char *output,
                                     size_t output_size);

/* Send GOAWAY frame and shutdown connection */
extern void http2_send_connection_error (SocketHTTP2_Conn_T conn,
                                         SocketHTTP2_ErrorCode error_code);

/* Send RST_STREAM frame to terminate stream */
extern void http2_send_stream_error (SocketHTTP2_Conn_T conn,
                                     uint32_t stream_id,
                                     SocketHTTP2_ErrorCode error_code);

/* Invoke stream event callback */
extern void http2_emit_stream_event (SocketHTTP2_Conn_T conn,
                                     SocketHTTP2_Stream_T stream, int event);

/* Invoke connection event callback */
extern void http2_emit_conn_event (SocketHTTP2_Conn_T conn, int event);
static inline void
write_u16_be (unsigned char *buf, uint16_t value)
{
  buf[0] = (unsigned char)((value >> 8) & 0xFF);
  buf[1] = (unsigned char)(value & 0xFF);
}

static inline void
write_u32_be (unsigned char *buf, uint32_t value)
{
  buf[0] = (unsigned char)((value >> 24) & 0xFF);
  buf[1] = (unsigned char)((value >> 16) & 0xFF);
  buf[2] = (unsigned char)((value >> 8) & 0xFF);
  buf[3] = (unsigned char)(value & 0xFF);
}

static inline void
write_u31_be (unsigned char *buf, uint32_t value)
{
  buf[0] = (unsigned char)((value >> 24) & 0x7F);
  buf[1] = (unsigned char)((value >> 16) & 0xFF);
  buf[2] = (unsigned char)((value >> 8) & 0xFF);
  buf[3] = (unsigned char)(value & 0xFF);
}

static inline uint16_t
read_u16_be (const unsigned char *buf)
{
  return ((uint16_t)buf[0] << 8) | buf[1];
}

static inline uint32_t
read_u32_be (const unsigned char *buf)
{
  return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16)
         | ((uint32_t)buf[2] << 8) | buf[3];
}

static inline uint32_t
read_u31_be (const unsigned char *buf)
{
  return ((uint32_t)(buf[0] & 0x7F) << 24) | ((uint32_t)buf[1] << 16)
         | ((uint32_t)buf[2] << 8) | buf[3];
}

/* Header validation (RFC 9113 Section 8) */
extern int http2_is_connection_header_forbidden (const SocketHPACK_Header *header);
extern int http2_field_has_uppercase (const char *name, size_t len);
extern int http2_field_has_prohibited_chars (const char *data, size_t len);
extern int http2_field_has_boundary_whitespace (const char *value, size_t len);
extern int http2_validate_te_header (const char *value, size_t len);
extern int http2_validate_regular_header (const SocketHPACK_Header *header);

#endif /* SOCKETHTTP2_PRIVATE_INCLUDED */

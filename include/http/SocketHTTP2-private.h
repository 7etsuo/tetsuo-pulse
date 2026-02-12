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

/* SECURITY: Limit to prevent DoS via hash collision attacks */
#define HTTP2_STREAM_MAX_HASH_CHAIN_LEN 32
typedef enum
{
  HTTP2_CONN_STATE_INIT = 0,
  HTTP2_CONN_STATE_PREFACE_SENT,
  HTTP2_CONN_STATE_PREFACE_RECV,
  HTTP2_CONN_STATE_SETTINGS_SENT,
  HTTP2_CONN_STATE_SETTINGS_RECV,
  HTTP2_CONN_STATE_READY,
  HTTP2_CONN_STATE_GOAWAY_SENT,
  HTTP2_CONN_STATE_GOAWAY_RECV,
  HTTP2_CONN_STATE_CLOSED
} SocketHTTP2_ConnState;
struct SocketHTTP2_Stream
{
  uint32_t id;
  SocketHTTP2_StreamState state;
  SocketHTTP2_Conn_T conn;
  int32_t send_window;
  int32_t recv_window;
  SocketBuf_T recv_buf;
  int64_t expected_content_length;
  size_t total_data_received;
  int headers_received;
  int headers_end_stream;
  int end_stream_received;
  int end_stream_sent;
  int pending_end_stream;
  int is_push_stream;
  int trailers_received;
  int rst_received;
  int is_extended_connect;
  char protocol[32];
  SocketHTTP2_Priority priority; /* RFC 9218 extensible priority */
  SocketHPACK_Header headers[SOCKETHTTP2_MAX_DECODED_HEADERS];
  size_t header_count;
  int headers_consumed;
  SocketHPACK_Header trailers[SOCKETHTTP2_MAX_DECODED_HEADERS];
  size_t trailer_count;
  int trailers_consumed;
  unsigned char *header_block;
  size_t header_block_len;
  size_t header_block_capacity;
  void *userdata;
  bool is_local_initiated;
  struct SocketHTTP2_Stream *hash_next;
};
struct SocketHTTP2_Conn
{
  Socket_T socket;
  Arena_T arena;
  SocketHTTP2_Role role;
  SocketHTTP2_ConnState state;
  SocketHPACK_Encoder_T encoder;
  SocketHPACK_Decoder_T decoder;
  SocketBuf_T recv_buf;
  SocketBuf_T send_buf;
  uint32_t local_settings[HTTP2_SETTINGS_COUNT];
  uint32_t peer_settings[HTTP2_SETTINGS_COUNT];
  int settings_ack_pending;
  int32_t send_window;
  int32_t recv_window;
  int32_t initial_send_window;
  int32_t initial_recv_window;
  struct SocketHTTP2_Stream **streams;
  size_t stream_count;
  uint32_t client_initiated_count;
  uint32_t server_initiated_count;
  SocketRateLimit_T stream_open_rate_limit;
  SocketRateLimit_T stream_close_rate_limit;
  uint32_t hash_seed;
  uint32_t next_stream_id;
  uint32_t last_peer_stream_id;
  uint32_t max_peer_stream_id;
  uint32_t continuation_stream_id;
  int expecting_continuation;
  uint32_t continuation_frame_count;
  int goaway_sent;
  int goaway_received;
  SocketHTTP2_ErrorCode goaway_error_code;
  unsigned char ping_opaque[8];
  int ping_pending;
  SocketHTTP2_StreamCallback stream_callback;
  SocketHTTP2_ConnCallback conn_callback;
  void *stream_callback_data;
  void *conn_callback_data;
  int settings_timeout_ms;
  int ping_timeout_ms;
  int idle_timeout_ms;
  int64_t settings_sent_time;
  int64_t ping_sent_time;
  int64_t last_activity_time;
  TimeWindow_T rst_window;
  TimeWindow_T ping_window;
  TimeWindow_T settings_window;

  /* Sliding window stream creation rate limiting (CVE-2023-44487 protection) */
  TimeWindow_T stream_create_window; /* Tracks creations over window period */
  TimeWindow_T stream_burst_window;  /* Short-term burst detection */
  TimeWindow_T stream_churn_window;  /* Rapid create+close cycle detection */
  uint32_t stream_max_per_window;    /* Max creations per window */
  uint32_t stream_burst_threshold;   /* Max per burst interval */
  uint32_t stream_churn_threshold;   /* Max rapid cycles per window */
};

/**
 * @brief State tracking for pseudo-header validation
 *
 * Tracks which pseudo-headers have been seen and their validation state
 * during HTTP/2 header block parsing per RFC 9113 Section 8.3.
 */
typedef struct
{
  int has_method;        /**< :method pseudo-header present */
  int has_scheme;        /**< :scheme pseudo-header present */
  int has_authority;     /**< :authority pseudo-header present */
  int has_path;          /**< :path pseudo-header present */
  int has_status;        /**< :status pseudo-header present */
  int has_protocol;      /**< :protocol pseudo-header present (RFC 8441) */
  int is_connect_method; /**< CONNECT method detected */
} HTTP2_PseudoHeaderState;

extern SocketHTTP2_ErrorCode
http2_frame_validate (SocketHTTP2_Conn_T conn,
                      const SocketHTTP2_FrameHeader *header);

extern int http2_flow_adjust_window (int32_t *window, int32_t delta);

extern int http2_frame_send (SocketHTTP2_Conn_T conn,
                             const SocketHTTP2_FrameHeader *header,
                             const void *payload,
                             size_t payload_len);

extern SocketHTTP2_Stream_T
http2_stream_lookup (const SocketHTTP2_Conn_T conn, uint32_t stream_id);

extern SocketHTTP2_Stream_T http2_stream_create (SocketHTTP2_Conn_T conn,
                                                 uint32_t stream_id,
                                                 int is_local_initiated);

extern void http2_stream_destroy (SocketHTTP2_Stream_T stream);

extern SocketHTTP2_ErrorCode
http2_stream_transition (SocketHTTP2_Stream_T stream,
                         uint8_t frame_type,
                         uint8_t flags,
                         int is_send);

extern int http2_flow_consume_recv (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_Stream_T stream,
                                    size_t bytes);

extern int http2_flow_consume_send (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_Stream_T stream,
                                    size_t bytes);

extern int http2_flow_update_recv (SocketHTTP2_Conn_T conn,
                                   SocketHTTP2_Stream_T stream,
                                   uint32_t increment);

extern int http2_flow_update_send (SocketHTTP2_Conn_T conn,
                                   SocketHTTP2_Stream_T stream,
                                   uint32_t increment);

extern int32_t http2_flow_available_send (const SocketHTTP2_Conn_T conn,
                                          const SocketHTTP2_Stream_T stream);

extern int http2_process_frame (SocketHTTP2_Conn_T conn,
                                const SocketHTTP2_FrameHeader *header,
                                const unsigned char *payload);

extern int http2_process_data (SocketHTTP2_Conn_T conn,
                               const SocketHTTP2_FrameHeader *header,
                               const unsigned char *payload);

extern int http2_process_headers (SocketHTTP2_Conn_T conn,
                                  const SocketHTTP2_FrameHeader *header,
                                  const unsigned char *payload);

extern int http2_process_rst_stream (SocketHTTP2_Conn_T conn,
                                     const SocketHTTP2_FrameHeader *header,
                                     const unsigned char *payload);

extern int http2_process_settings (SocketHTTP2_Conn_T conn,
                                   const SocketHTTP2_FrameHeader *header,
                                   const unsigned char *payload);

extern int http2_process_push_promise (SocketHTTP2_Conn_T conn,
                                       const SocketHTTP2_FrameHeader *header,
                                       const unsigned char *payload);

extern int http2_process_ping (SocketHTTP2_Conn_T conn,
                               const SocketHTTP2_FrameHeader *header,
                               const unsigned char *payload);

extern int http2_process_goaway (SocketHTTP2_Conn_T conn,
                                 const SocketHTTP2_FrameHeader *header,
                                 const unsigned char *payload);

extern int http2_process_window_update (SocketHTTP2_Conn_T conn,
                                        const SocketHTTP2_FrameHeader *header,
                                        const unsigned char *payload);

extern int http2_process_continuation (SocketHTTP2_Conn_T conn,
                                       const SocketHTTP2_FrameHeader *header,
                                       const unsigned char *payload);

extern int http2_process_priority_update (SocketHTTP2_Conn_T conn,
                                          const SocketHTTP2_FrameHeader *header,
                                          const unsigned char *payload);

extern int http2_decode_headers (SocketHTTP2_Conn_T conn,
                                 SocketHTTP2_Stream_T stream,
                                 const unsigned char *block,
                                 size_t len);

extern ssize_t http2_encode_headers (SocketHTTP2_Conn_T conn,
                                     const SocketHPACK_Header *headers,
                                     size_t count,
                                     unsigned char *output,
                                     size_t output_size);

extern void http2_send_connection_error (SocketHTTP2_Conn_T conn,
                                         SocketHTTP2_ErrorCode error_code);

extern void http2_send_stream_error (SocketHTTP2_Conn_T conn,
                                     uint32_t stream_id,
                                     SocketHTTP2_ErrorCode error_code);

extern void http2_emit_stream_event (SocketHTTP2_Conn_T conn,
                                     SocketHTTP2_Stream_T stream,
                                     int event);

extern void http2_emit_conn_event (SocketHTTP2_Conn_T conn, int event);

/* --- Error handling convenience macros --- */

/**
 * @brief Send connection error and return failure
 *
 * Combines http2_send_connection_error() with return -1 for cleaner
 * error handling in frame processing functions.
 */
#define HTTP2_SEND_CONN_ERROR_AND_FAIL(conn, code)  \
  do                                                \
    {                                               \
      http2_send_connection_error ((conn), (code)); \
      return -1;                                    \
    }                                               \
  while (0)

/**
 * @brief Send stream error and return success (continue processing)
 *
 * Combines http2_send_stream_error() with return 0 for stream-level
 * errors that don't terminate the connection.
 */
#define HTTP2_SEND_STREAM_ERROR_AND_CONTINUE(conn, id, code) \
  do                                                         \
    {                                                        \
      http2_send_stream_error ((conn), (id), (code));        \
      return 0;                                              \
    }                                                        \
  while (0)

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

extern int
http2_is_connection_header_forbidden (const SocketHPACK_Header *header);
extern int http2_field_has_uppercase (const char *name, size_t len);
extern int http2_field_has_prohibited_chars (const char *data, size_t len);
extern int http2_field_name_has_prohibited_chars (const char *name, size_t len);
extern int http2_field_has_boundary_whitespace (const char *value, size_t len);
extern int http2_validate_te_header (const char *value, size_t len);
extern int http2_validate_regular_header (const SocketHPACK_Header *header);

/* --- Pseudo-header validation helpers (RFC 9113 Section 8.3) --- */

/**
 * @brief Parse HTTP status code from :status pseudo-header value
 * @param value Status code string (e.g., "200", "404")
 * @param len Length of value
 * @param status Output: parsed status code (100-599)
 * @return 0 on success, -1 on invalid status
 */
extern int http2_parse_status_code (const char *value, size_t len, int *status);

/**
 * @brief Parse Content-Length header value with overflow protection
 * @param value Content-Length value string
 * @param len Length of value
 * @param cl Output: parsed content length
 * @return 0 on success, -1 on empty/invalid/overflow
 */
extern int
http2_parse_content_length (const char *value, size_t len, int64_t *cl);

/**
 * @brief Validate :method pseudo-header
 * @return 0 on success, -1 on error
 */
extern int http2_validate_method_header (const SocketHPACK_Header *h,
                                         int is_request,
                                         HTTP2_PseudoHeaderState *state);

/**
 * @brief Validate :scheme pseudo-header
 * @return 0 on success, -1 on error
 */
extern int http2_validate_scheme_header (const SocketHPACK_Header *h,
                                         HTTP2_PseudoHeaderState *state);

/**
 * @brief Validate :authority pseudo-header
 * @return 0 on success, -1 on error
 */
extern int http2_validate_authority_header (const SocketHPACK_Header *h,
                                            HTTP2_PseudoHeaderState *state);

/**
 * @brief Validate :path pseudo-header
 * @return 0 on success, -1 on error
 */
extern int http2_validate_path_header (const SocketHPACK_Header *h,
                                       HTTP2_PseudoHeaderState *state);

/**
 * @brief Validate :status pseudo-header
 * @return 0 on success, -1 on error
 */
extern int http2_validate_status_header (const SocketHPACK_Header *h,
                                         int is_request,
                                         HTTP2_PseudoHeaderState *state);

/**
 * @brief Validate :protocol pseudo-header (RFC 8441 Extended CONNECT)
 * @return 0 on success, -1 on error
 */
extern int http2_validate_protocol_header (SocketHTTP2_Conn_T conn,
                                           SocketHTTP2_Stream_T stream,
                                           const SocketHPACK_Header *h,
                                           HTTP2_PseudoHeaderState *state);

/**
 * @brief Validate standard CONNECT request pseudo-headers (RFC 9113
 * Section 8.5)
 * @return 0 on success, -1 on error
 */
extern int
http2_validate_standard_connect (const HTTP2_PseudoHeaderState *state);

/**
 * @brief Validate Extended CONNECT request pseudo-headers (RFC 8441)
 * @return 0 on success, -1 on error
 */
extern int
http2_validate_extended_connect (const HTTP2_PseudoHeaderState *state);

#endif /* SOCKETHTTP2_PRIVATE_INCLUDED */

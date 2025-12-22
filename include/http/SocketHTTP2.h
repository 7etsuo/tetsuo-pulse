/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @defgroup http2 HTTP/2 Protocol Implementation
 * @ingroup http
 * @{
 *
 * HTTP/2 (RFC 9113) with framing, stream multiplexing, flow control,
 * and HPACK compression. Client and server support.
 *
 * Thread safety: Connection instances are NOT thread-safe.
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

#ifndef SOCKETHTTP2_DEFAULT_HEADER_TABLE_SIZE
#define SOCKETHTTP2_DEFAULT_HEADER_TABLE_SIZE 4096
#endif

#ifndef SOCKETHTTP2_DEFAULT_ENABLE_PUSH
#define SOCKETHTTP2_DEFAULT_ENABLE_PUSH 1
#endif

#ifndef SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS
#define SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS 100
#endif

#ifndef SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE
#define SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE 65535
#endif

#ifndef SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE
#define SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE 16384
#endif

#define SOCKETHTTP2_MAX_MAX_FRAME_SIZE 16777215

#ifndef SOCKETHTTP2_DEFAULT_MAX_HEADER_LIST_SIZE
#define SOCKETHTTP2_DEFAULT_MAX_HEADER_LIST_SIZE (16 * 1024)

#define SOCKETHTTP2_DEFAULT_STREAM_RECV_BUF_SIZE (64 * 1024)
#define SOCKETHTTP2_DEFAULT_INITIAL_HEADER_BLOCK_SIZE (16 * 1024)
#define SOCKETHTTP2_MAX_DECODED_HEADERS 128
#define SOCKETHTTP2_MAX_CONTINUATION_FRAMES 32
#define HTTP2_REQUEST_PSEUDO_HEADER_COUNT 4

#endif

#ifndef SOCKETHTTP2_MAX_STREAMS
#define SOCKETHTTP2_MAX_STREAMS 1000
#endif

#ifndef SOCKETHTTP2_CONNECTION_WINDOW_SIZE
#define SOCKETHTTP2_CONNECTION_WINDOW_SIZE (1 << 20)
#endif

/* Rate Limiting (DoS protection, CVE-2023-44487) */

/* Sliding window stream creation rate limiting */
#ifndef SOCKETHTTP2_STREAM_WINDOW_SIZE_MS
#define SOCKETHTTP2_STREAM_WINDOW_SIZE_MS 60000  /* 1 minute sliding window */
#endif

#ifndef SOCKETHTTP2_STREAM_MAX_PER_WINDOW
#define SOCKETHTTP2_STREAM_MAX_PER_WINDOW 1000   /* Max streams per window */
#endif

#ifndef SOCKETHTTP2_STREAM_BURST_THRESHOLD
#define SOCKETHTTP2_STREAM_BURST_THRESHOLD 50    /* Max streams per burst interval */
#endif

#ifndef SOCKETHTTP2_STREAM_BURST_INTERVAL_MS
#define SOCKETHTTP2_STREAM_BURST_INTERVAL_MS 1000  /* Burst detection interval */
#endif

#ifndef SOCKETHTTP2_STREAM_CHURN_THRESHOLD
#define SOCKETHTTP2_STREAM_CHURN_THRESHOLD 100   /* Max rapid create+close cycles per window */
#endif

#ifndef SOCKETHTTP2_RST_RATE_LIMIT
#define SOCKETHTTP2_RST_RATE_LIMIT 100
#endif

#ifndef SOCKETHTTP2_RST_RATE_WINDOW_MS
#define SOCKETHTTP2_RST_RATE_WINDOW_MS 1000
#endif

#ifndef SOCKETHTTP2_PING_RATE_LIMIT
#define SOCKETHTTP2_PING_RATE_LIMIT 50
#endif

#ifndef SOCKETHTTP2_PING_RATE_WINDOW_MS
#define SOCKETHTTP2_PING_RATE_WINDOW_MS 1000
#endif

#ifndef SOCKETHTTP2_SETTINGS_RATE_LIMIT
#define SOCKETHTTP2_SETTINGS_RATE_LIMIT 10
#endif

#ifndef SOCKETHTTP2_SETTINGS_RATE_WINDOW_MS
#define SOCKETHTTP2_SETTINGS_RATE_WINDOW_MS 5000
#endif

#ifndef SOCKETHTTP2_DEFAULT_SETTINGS_TIMEOUT_MS
#define SOCKETHTTP2_DEFAULT_SETTINGS_TIMEOUT_MS 30000
#endif

#ifndef SOCKETHTTP2_DEFAULT_PING_TIMEOUT_MS
#define SOCKETHTTP2_DEFAULT_PING_TIMEOUT_MS 30000
#endif

#ifndef SOCKETHTTP2_MAX_WINDOW_SIZE
#define SOCKETHTTP2_MAX_WINDOW_SIZE 0x7FFFFFFF
#endif

#ifndef SOCKETHTTP2_IO_BUFFER_SIZE
#define SOCKETHTTP2_IO_BUFFER_SIZE SOCKETHTTP2_DEFAULT_STREAM_RECV_BUF_SIZE
#endif

/* Frame/Protocol Constants */

#define HTTP2_FRAME_HEADER_SIZE 9
#define HTTP2_WINDOW_UPDATE_PAYLOAD_SIZE 4
#define HTTP2_PUSH_PROMISE_ID_SIZE 4
#define HTTP2_PRIORITY_PAYLOAD_SIZE 5
#define HTTP2_PREFACE_SIZE 24
#define HTTP2_STREAM_HASH_SIZE 1021

/* Exception Types */

extern const Except_T SocketHTTP2_ProtocolError;
extern const Except_T SocketHTTP2_StreamError;
extern const Except_T SocketHTTP2_FlowControlError;

/* Frame Types (RFC 9113 Section 6) */

/** HTTP/2 frame types (RFC 9113 Section 6) */
typedef enum
{
  HTTP2_FRAME_DATA = 0x0,
  HTTP2_FRAME_HEADERS = 0x1,
  HTTP2_FRAME_PRIORITY = 0x2,
  HTTP2_FRAME_RST_STREAM = 0x3,
  HTTP2_FRAME_SETTINGS = 0x4,
  HTTP2_FRAME_PUSH_PROMISE = 0x5,
  HTTP2_FRAME_PING = 0x6,
  HTTP2_FRAME_GOAWAY = 0x7,
  HTTP2_FRAME_WINDOW_UPDATE = 0x8,
  HTTP2_FRAME_CONTINUATION = 0x9
} SocketHTTP2_FrameType;

/* Frame flags (bitmasks) */
#define HTTP2_FLAG_END_STREAM 0x01
#define HTTP2_FLAG_END_HEADERS 0x04
#define HTTP2_FLAG_PADDED 0x08
#define HTTP2_FLAG_PRIORITY 0x20
#define HTTP2_FLAG_ACK 0x01

/* Error Codes (RFC 9113 Section 7) */

/** HTTP/2 error codes for RST_STREAM and GOAWAY */
typedef enum
{
  HTTP2_NO_ERROR = 0x0,
  HTTP2_PROTOCOL_ERROR = 0x1,
  HTTP2_INTERNAL_ERROR = 0x2,
  HTTP2_FLOW_CONTROL_ERROR = 0x3,
  HTTP2_SETTINGS_TIMEOUT = 0x4,
  HTTP2_STREAM_CLOSED = 0x5,
  HTTP2_FRAME_SIZE_ERROR = 0x6,
  HTTP2_REFUSED_STREAM = 0x7,
  HTTP2_CANCEL = 0x8,
  HTTP2_COMPRESSION_ERROR = 0x9,
  HTTP2_CONNECT_ERROR = 0xa,
  HTTP2_ENHANCE_YOUR_CALM = 0xb,
  HTTP2_INADEQUATE_SECURITY = 0xc,
  HTTP2_HTTP_1_1_REQUIRED = 0xd
} SocketHTTP2_ErrorCode;

/* Settings Identifiers (RFC 9113 Section 6.5.2) */

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

#define HTTP2_SETTINGS_COUNT 7

/* Stream States (RFC 9113 Section 5.1) */

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

/* Frame Header (9 bytes on wire) */

typedef struct
{
  uint32_t length;
  uint8_t type;
  uint8_t flags;
  uint32_t stream_id;
} SocketHTTP2_FrameHeader;

/* Connection Role */

typedef enum
{
  HTTP2_ROLE_CLIENT,
  HTTP2_ROLE_SERVER
} SocketHTTP2_Role;

/* Connection Configuration */

typedef struct
{
  SocketHTTP2_Role role;

  /* Local settings (sent to peer) */
  uint32_t header_table_size;
  uint32_t enable_push;
  uint32_t max_concurrent_streams;
  uint32_t max_stream_open_rate;
  uint32_t max_stream_open_burst;
  uint32_t max_stream_close_rate;
  uint32_t max_stream_close_burst;
  uint32_t initial_window_size;
  uint32_t max_frame_size;
  uint32_t max_header_list_size;
  uint32_t enable_connect_protocol;

  /* Connection-level flow control */
  uint32_t connection_window_size;

  /* Sliding window stream rate limiting (CVE-2023-44487 protection) */
  uint32_t stream_window_size_ms;     /* Sliding window duration (default: 60000) */
  uint32_t stream_max_per_window;     /* Max creations per window (default: 1000) */
  uint32_t stream_burst_threshold;    /* Max per burst interval (default: 50) */
  uint32_t stream_burst_interval_ms;  /* Burst detection interval (default: 1000) */
  uint32_t stream_churn_threshold;    /* Max rapid create+close cycles (default: 100) */

  /* Timeouts (milliseconds) */
  int settings_timeout_ms;
  int ping_timeout_ms;
  int idle_timeout_ms;
} SocketHTTP2_Config;

/* Opaque Types */

typedef struct SocketHTTP2_Conn *SocketHTTP2_Conn_T;
typedef struct SocketHTTP2_Stream *SocketHTTP2_Stream_T;

/* Setting Entry */

typedef struct
{
  uint16_t id;
  uint32_t value;
} SocketHTTP2_Setting;

/* Configuration Functions */

/** Initialize configuration with RFC 9113 compliant defaults. */
extern void SocketHTTP2_config_defaults (SocketHTTP2_Config *config,
                                         SocketHTTP2_Role role);

/* Connection Lifecycle */

/**
 * Create a new HTTP/2 connection. Call Conn_handshake() after creation.
 * Does NOT close underlying socket on free. Config NULL uses client defaults.
 */
extern SocketHTTP2_Conn_T
SocketHTTP2_Conn_new (Socket_T socket, const SocketHTTP2_Config *config,
                      Arena_T arena);

/** Free connection and all resources. Safe to call on NULL. */
extern void SocketHTTP2_Conn_free (SocketHTTP2_Conn_T *conn);

/**
 * Complete connection preface and settings exchange.
 * @return 0 = complete, 1 = in progress, -1 = error
 */
extern int SocketHTTP2_Conn_handshake (SocketHTTP2_Conn_T conn);

/**
 * Process socket events and HTTP/2 frames.
 * @return 0 = success, 1 = need more data, -1 = error
 */
extern int SocketHTTP2_Conn_process (SocketHTTP2_Conn_T conn, unsigned events);

/**
 * Flush pending frames to socket.
 * @return 0 = all sent, 1 = would block, -1 = error
 */
extern int SocketHTTP2_Conn_flush (SocketHTTP2_Conn_T conn);

/** Get underlying socket. */
extern Socket_T SocketHTTP2_Conn_socket (SocketHTTP2_Conn_T conn);

/** Check if connection closed (GOAWAY sent/received). */
extern int SocketHTTP2_Conn_is_closed (SocketHTTP2_Conn_T conn);

/** Get connection's memory arena. */
extern Arena_T SocketHTTP2_Conn_arena (SocketHTTP2_Conn_T conn);

/* Connection Control */

extern int SocketHTTP2_Conn_settings (SocketHTTP2_Conn_T conn,
                                      const SocketHTTP2_Setting *settings,
                                      size_t count);
extern uint32_t SocketHTTP2_Conn_get_setting (SocketHTTP2_Conn_T conn,
                                              SocketHTTP2_SettingsId id);
extern uint32_t SocketHTTP2_Conn_get_local_setting (SocketHTTP2_Conn_T conn,
                                                    SocketHTTP2_SettingsId id);
extern int SocketHTTP2_Conn_ping (SocketHTTP2_Conn_T conn,
                                  const unsigned char opaque[8]);

/** Send PING and block until ACK. Returns RTT in ms, -1 on timeout/error. */
extern int SocketHTTP2_Conn_ping_wait (SocketHTTP2_Conn_T conn, int timeout_ms);

extern uint32_t SocketHTTP2_Conn_get_concurrent_streams (SocketHTTP2_Conn_T conn);
extern int SocketHTTP2_Conn_set_max_concurrent (SocketHTTP2_Conn_T conn,
                                                uint32_t max);

/** Send GOAWAY frame to initiate graceful shutdown. */
extern int SocketHTTP2_Conn_goaway (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_ErrorCode error_code,
                                    const void *debug_data, size_t debug_len);

extern uint32_t SocketHTTP2_Conn_last_stream_id (SocketHTTP2_Conn_T conn);

/* Connection Flow Control */

extern int SocketHTTP2_Conn_window_update (SocketHTTP2_Conn_T conn,
                                           uint32_t increment);
extern int32_t SocketHTTP2_Conn_send_window (SocketHTTP2_Conn_T conn);
extern int32_t SocketHTTP2_Conn_recv_window (SocketHTTP2_Conn_T conn);

/* Stream Management */

/** Create new stream (odd IDs for client, even for server push). */
extern SocketHTTP2_Stream_T SocketHTTP2_Stream_new (SocketHTTP2_Conn_T conn);

extern SocketHTTP2_Stream_T SocketHTTP2_Conn_get_stream (SocketHTTP2_Conn_T conn,
                                                         uint32_t stream_id);
extern uint32_t SocketHTTP2_Stream_id (SocketHTTP2_Stream_T stream);
extern SocketHTTP2_StreamState
SocketHTTP2_Stream_state (SocketHTTP2_Stream_T stream);
extern void SocketHTTP2_Stream_close (SocketHTTP2_Stream_T stream,
                                      SocketHTTP2_ErrorCode error_code);
extern void *SocketHTTP2_Stream_get_userdata (SocketHTTP2_Stream_T stream);
extern void SocketHTTP2_Stream_set_userdata (SocketHTTP2_Stream_T stream,
                                             void *userdata);

/* Sending */

extern int SocketHTTP2_Stream_send_headers (SocketHTTP2_Stream_T stream,
                                            const SocketHPACK_Header *headers,
                                            size_t header_count,
                                            int end_stream);

/**
 * Send HEADERS frame with padding (RFC 9113 Section 6.2).
 *
 * Padding can be used to obscure the exact size of frame content for
 * traffic analysis mitigation. The padding bytes are filled with zeros.
 *
 * @param stream The stream to send headers on
 * @param headers Array of HPACK headers to send
 * @param header_count Number of headers in the array
 * @param pad_length Number of padding bytes (0-255)
 * @param end_stream Set to 1 to close the stream after sending
 * @return 0 on success, -1 on error
 */
extern int
SocketHTTP2_Stream_send_headers_padded (SocketHTTP2_Stream_T stream,
                                        const SocketHPACK_Header *headers,
                                        size_t header_count, uint8_t pad_length,
                                        int end_stream);

extern int SocketHTTP2_Stream_send_request (SocketHTTP2_Stream_T stream,
                                            const SocketHTTP_Request *request,
                                            int end_stream);
extern int
SocketHTTP2_Stream_send_response (SocketHTTP2_Stream_T stream,
                                  const SocketHTTP_Response *response,
                                  int end_stream);

/** Returns bytes accepted (may be less due to flow control), -1 on error. */
extern ssize_t SocketHTTP2_Stream_send_data (SocketHTTP2_Stream_T stream,
                                             const void *data, size_t len,
                                             int end_stream);

/**
 * Send DATA frame with padding (RFC 9113 Section 6.1).
 *
 * Padding can be used to obscure the exact size of frame content for
 * traffic analysis mitigation. The padding bytes are filled with zeros.
 *
 * @param stream The stream to send data on
 * @param data The data payload to send
 * @param len Length of the data payload
 * @param pad_length Number of padding bytes (0-255)
 * @param end_stream Set to 1 to close the stream after sending
 * @return Bytes accepted (may be less due to flow control), -1 on error
 */
extern ssize_t
SocketHTTP2_Stream_send_data_padded (SocketHTTP2_Stream_T stream,
                                     const void *data, size_t len,
                                     uint8_t pad_length, int end_stream);

extern int
SocketHTTP2_Stream_send_trailers (SocketHTTP2_Stream_T stream,
                                  const SocketHPACK_Header *trailers,
                                  size_t count);

/* Receiving */

/** @return 1 = headers available, 0 = not ready, -1 = error */
extern int SocketHTTP2_Stream_recv_headers (SocketHTTP2_Stream_T stream,
                                            SocketHPACK_Header *headers,
                                            size_t max_headers,
                                            size_t *header_count,
                                            int *end_stream);

/** @return bytes received, 0 = would block, -1 = error */
extern ssize_t SocketHTTP2_Stream_recv_data (SocketHTTP2_Stream_T stream,
                                             void *buf, size_t len,
                                             int *end_stream);

/** @return 1 = trailers available, 0 = not ready, -1 = error */
extern int SocketHTTP2_Stream_recv_trailers (SocketHTTP2_Stream_T stream,
                                             SocketHPACK_Header *trailers,
                                             size_t max_trailers,
                                             size_t *trailer_count);

/* Stream Flow Control */

extern int SocketHTTP2_Stream_window_update (SocketHTTP2_Stream_T stream,
                                             uint32_t increment);
extern int32_t SocketHTTP2_Stream_send_window (SocketHTTP2_Stream_T stream);
extern int32_t SocketHTTP2_Stream_recv_window (SocketHTTP2_Stream_T stream);

/* Server Push (RFC 9113 Section 8.4) */

/** Send PUSH_PROMISE. Returns new reserved stream, or NULL if disabled. */
extern SocketHTTP2_Stream_T
SocketHTTP2_Stream_push_promise (SocketHTTP2_Stream_T stream,
                                 const SocketHPACK_Header *request_headers,
                                 size_t header_count);

/* Callbacks */

/* Stream events */
#define HTTP2_EVENT_STREAM_START 1
#define HTTP2_EVENT_HEADERS_RECEIVED 2
#define HTTP2_EVENT_DATA_RECEIVED 3
#define HTTP2_EVENT_TRAILERS_RECEIVED 4
#define HTTP2_EVENT_STREAM_END 5
#define HTTP2_EVENT_STREAM_RESET 6
#define HTTP2_EVENT_PUSH_PROMISE 7
#define HTTP2_EVENT_WINDOW_UPDATE 8

typedef void (*SocketHTTP2_StreamCallback) (SocketHTTP2_Conn_T conn,
                                            SocketHTTP2_Stream_T stream,
                                            int event, void *userdata);

extern void
SocketHTTP2_Conn_set_stream_callback (SocketHTTP2_Conn_T conn,
                                      SocketHTTP2_StreamCallback callback,
                                      void *userdata);

/* Connection events */
#define HTTP2_EVENT_SETTINGS_ACK 20
#define HTTP2_EVENT_PING_ACK 21
#define HTTP2_EVENT_GOAWAY_RECEIVED 22
#define HTTP2_EVENT_CONNECTION_ERROR 23

typedef void (*SocketHTTP2_ConnCallback) (SocketHTTP2_Conn_T conn, int event,
                                          void *userdata);

extern void
SocketHTTP2_Conn_set_conn_callback (SocketHTTP2_Conn_T conn,
                                    SocketHTTP2_ConnCallback callback,
                                    void *userdata);

/* h2c Upgrade (Cleartext HTTP/2) */

extern SocketHTTP2_Conn_T
SocketHTTP2_Conn_upgrade_client (Socket_T socket,
                                 const unsigned char *settings_payload,
                                 size_t settings_len, Arena_T arena);

/** Returns HTTP/2 connection with stream 1 pre-created. */
extern SocketHTTP2_Conn_T SocketHTTP2_Conn_upgrade_server (
    Socket_T socket, const SocketHTTP_Request *initial_request,
    const unsigned char *settings_payload, size_t settings_len, Arena_T arena);

/* Utility Functions */

extern const char *SocketHTTP2_error_string (SocketHTTP2_ErrorCode code);
extern const char *SocketHTTP2_frame_type_string (SocketHTTP2_FrameType type);
extern const char *
SocketHTTP2_stream_state_string (SocketHTTP2_StreamState state);

extern SocketHTTP2_Conn_T
SocketHTTP2_Stream_get_connection (SocketHTTP2_Stream_T stream);

/* Frame Parsing (Low-level) */

/** @return 0 on success, -1 on invalid input */
extern int SocketHTTP2_frame_header_parse (const unsigned char *data,
                                           size_t input_len,
                                           SocketHTTP2_FrameHeader *header);

extern void
SocketHTTP2_frame_header_serialize (const SocketHTTP2_FrameHeader *header,
                                    unsigned char *data);

/* TLS Validation (RFC 9113 Section 9.2) */

/**
 * @brief TLS validation result codes for HTTP/2 connections.
 *
 * RFC 9113 Section 9.2 specifies TLS requirements for HTTP/2:
 * - TLS version 1.2 or higher
 * - ALPN protocol "h2" must be negotiated
 * - Certain cipher suites are forbidden (Appendix A)
 */
typedef enum
{
  HTTP2_TLS_OK = 0,               /**< TLS requirements satisfied */
  HTTP2_TLS_NOT_ENABLED = -1,     /**< Socket has no TLS enabled */
  HTTP2_TLS_VERSION_TOO_LOW = -2, /**< TLS version < 1.2 */
  HTTP2_TLS_CIPHER_FORBIDDEN = -3, /**< Cipher suite is on forbidden list */
  HTTP2_TLS_ALPN_MISMATCH = -4    /**< ALPN is not "h2" */
} SocketHTTP2_TLSResult;

/**
 * @brief Validate TLS connection meets HTTP/2 requirements (RFC 9113 §9.2).
 *
 * Checks that the TLS connection satisfies RFC 9113 security requirements:
 * 1. TLS version is 1.2 or higher
 * 2. ALPN protocol "h2" was negotiated (for TLS connections)
 * 3. Cipher suite is not on the forbidden list (Appendix A)
 *
 * This function should be called after the TLS handshake completes but
 * before creating HTTP/2 streams.
 *
 * @param socket The socket to validate (may or may not have TLS)
 * @return HTTP2_TLS_OK if requirements met, negative error code otherwise
 *
 * @note For cleartext HTTP/2 (h2c), TLS is not required and this returns
 *       HTTP2_TLS_NOT_ENABLED which callers can treat as acceptable.
 */
extern SocketHTTP2_TLSResult SocketHTTP2_validate_tls (Socket_T socket);

/**
 * @brief Get human-readable string for TLS validation result.
 *
 * @param result The TLS validation result code
 * @return Static string describing the result
 */
extern const char *SocketHTTP2_tls_result_string (SocketHTTP2_TLSResult result);

/** @} */

#endif /* SOCKETHTTP2_INCLUDED */

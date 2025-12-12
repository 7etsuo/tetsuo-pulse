/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketHTTP2-frame.c - HTTP/2 Frame Parsing and Serialization
 *
 * Part of the Socket Library
 *
 * Implements:
 * - Frame header parsing (9 bytes)
 * - Frame header serialization
 * - Frame validation per RFC 9113
 * - Utility functions for error codes and frame types
 */

#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTP2.h"

#include "core/SocketUtil.h"

#include <assert.h>

/* ============================================================================
 * Module Setup
 * ============================================================================
 */

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTP2"

/* ============================================================================
 * Frame Validation Helper Macros
 * ============================================================================
 */

/**
 * REQUIRE_STREAM - Validate frame requires a stream association
 * @header: Frame header to validate
 *
 * Returns HTTP2_PROTOCOL_ERROR if stream_id is 0.
 * Used for DATA, HEADERS, PRIORITY, RST_STREAM, PUSH_PROMISE, CONTINUATION.
 */
#define REQUIRE_STREAM(header)                                                \
  do                                                                          \
    {                                                                         \
      if ((header)->stream_id == 0)                                           \
        return HTTP2_PROTOCOL_ERROR;                                          \
    }                                                                         \
  while (0)

/**
 * REQUIRE_CONNECTION_ONLY - Validate frame must NOT have stream association
 * @header: Frame header to validate
 *
 * Returns HTTP2_PROTOCOL_ERROR if stream_id is non-zero.
 * Used for SETTINGS, PING, GOAWAY.
 */
#define REQUIRE_CONNECTION_ONLY(header)                                       \
  do                                                                          \
    {                                                                         \
      if ((header)->stream_id != 0)                                           \
        return HTTP2_PROTOCOL_ERROR;                                          \
    }                                                                         \
  while (0)

/**
 * REQUIRE_EXACT_LENGTH - Validate exact payload length
 * @header: Frame header to validate
 * @expected: Expected payload length
 *
 * Returns HTTP2_FRAME_SIZE_ERROR if length doesn't match.
 */
#define REQUIRE_EXACT_LENGTH(header, expected)                                \
  do                                                                          \
    {                                                                         \
      if ((header)->length != (expected))                                     \
        return HTTP2_FRAME_SIZE_ERROR;                                        \
    }                                                                         \
  while (0)

/**
 * STRING_LOOKUP - Lookup string from static array with bounds check
 * @array: Static string array
 * @count: Number of elements in array
 * @index: Index to lookup
 * @unknown: String to return if out of bounds
 */
#define STRING_LOOKUP(array, count, index, unknown)                           \
  (((size_t)(index) < (count)) ? (array)[(index)] : (unknown))

/* ============================================================================
 * Frame Validator Dispatch Table
 * ============================================================================
 */

typedef SocketHTTP2_ErrorCode (*FrameValidator) (
    const SocketHTTP2_FrameHeader *header, SocketHTTP2_Conn_T conn);

/* Forward declarations for frame validators */
static SocketHTTP2_ErrorCode
validate_data_frame (const SocketHTTP2_FrameHeader *header,
                     SocketHTTP2_Conn_T conn);
static SocketHTTP2_ErrorCode
validate_headers_frame (const SocketHTTP2_FrameHeader *header,
                        SocketHTTP2_Conn_T conn);
static SocketHTTP2_ErrorCode
validate_priority_frame (const SocketHTTP2_FrameHeader *header,
                         SocketHTTP2_Conn_T conn);
static SocketHTTP2_ErrorCode
validate_rst_stream_frame (const SocketHTTP2_FrameHeader *header,
                           SocketHTTP2_Conn_T conn);
static SocketHTTP2_ErrorCode
validate_settings_frame (const SocketHTTP2_FrameHeader *header,
                         SocketHTTP2_Conn_T conn);
static SocketHTTP2_ErrorCode
validate_push_promise_frame (const SocketHTTP2_FrameHeader *header,
                             SocketHTTP2_Conn_T conn);
static SocketHTTP2_ErrorCode
validate_ping_frame (const SocketHTTP2_FrameHeader *header,
                     SocketHTTP2_Conn_T conn);
static SocketHTTP2_ErrorCode
validate_goaway_frame (const SocketHTTP2_FrameHeader *header,
                       SocketHTTP2_Conn_T conn);
static SocketHTTP2_ErrorCode
validate_window_update_frame (const SocketHTTP2_FrameHeader *header,
                              SocketHTTP2_Conn_T conn);
static SocketHTTP2_ErrorCode
validate_continuation_frame (const SocketHTTP2_FrameHeader *header,
                             SocketHTTP2_Conn_T conn);

static FrameValidator frame_validators[]
    = { validate_data_frame,          validate_headers_frame,
        validate_priority_frame,      validate_rst_stream_frame,
        validate_settings_frame,      validate_push_promise_frame,
        validate_ping_frame,          validate_goaway_frame,
        validate_window_update_frame, validate_continuation_frame };

/* ============================================================================
 * String Lookup Tables
 * ============================================================================
 */

static const char *frame_type_names[] = {
  "DATA",          /* 0x0 */
  "HEADERS",       /* 0x1 */
  "PRIORITY",      /* 0x2 */
  "RST_STREAM",    /* 0x3 */
  "SETTINGS",      /* 0x4 */
  "PUSH_PROMISE",  /* 0x5 */
  "PING",          /* 0x6 */
  "GOAWAY",        /* 0x7 */
  "WINDOW_UPDATE", /* 0x8 */
  "CONTINUATION"   /* 0x9 */
};

#define FRAME_TYPE_COUNT                                                      \
  (sizeof (frame_type_names) / sizeof (frame_type_names[0]))

static const char *error_code_names[] = {
  "NO_ERROR",            /* 0x0 */
  "PROTOCOL_ERROR",      /* 0x1 */
  "INTERNAL_ERROR",      /* 0x2 */
  "FLOW_CONTROL_ERROR",  /* 0x3 */
  "SETTINGS_TIMEOUT",    /* 0x4 */
  "STREAM_CLOSED",       /* 0x5 */
  "FRAME_SIZE_ERROR",    /* 0x6 */
  "REFUSED_STREAM",      /* 0x7 */
  "CANCEL",              /* 0x8 */
  "COMPRESSION_ERROR",   /* 0x9 */
  "CONNECT_ERROR",       /* 0xa */
  "ENHANCE_YOUR_CALM",   /* 0xb */
  "INADEQUATE_SECURITY", /* 0xc */
  "HTTP_1_1_REQUIRED"    /* 0xd */
};

#define ERROR_CODE_COUNT                                                      \
  (sizeof (error_code_names) / sizeof (error_code_names[0]))

static const char *stream_state_names[]
    = { "idle",  "reserved (local)",    "reserved (remote)",
        "open",  "half-closed (local)", "half-closed (remote)",
        "closed" };

#define STREAM_STATE_COUNT                                                    \
  (sizeof (stream_state_names) / sizeof (stream_state_names[0]))

/* ============================================================================
 * Big-Endian Packing Helpers
 * ============================================================================
 */

static inline uint32_t
http2_unpack_be24 (const unsigned char *data)
{
  return ((uint32_t)data[0] << 16) | ((uint32_t)data[1] << 8)
         | (uint32_t)data[2];
}

static inline void
http2_pack_be24 (unsigned char *data, uint32_t value)
{
  data[0] = (unsigned char)((value >> 16) & 0xFF);
  data[1] = (unsigned char)((value >> 8) & 0xFF);
  data[2] = (unsigned char)(value & 0xFF);
}

static inline uint32_t
http2_unpack_stream_id (const unsigned char *data)
{
  return ((uint32_t)(data[0] & 0x7F) << 24) | ((uint32_t)data[1] << 16)
         | ((uint32_t)data[2] << 8) | (uint32_t)data[3];
}

static inline void
http2_pack_stream_id (unsigned char *data, uint32_t stream_id)
{
  data[0] = (unsigned char)((stream_id >> 24) & 0x7F);
  data[1] = (unsigned char)((stream_id >> 16) & 0xFF);
  data[2] = (unsigned char)((stream_id >> 8) & 0xFF);
  data[3] = (unsigned char)(stream_id & 0xFF);
}

static inline void
http2_pack_uint32_be (unsigned char *data, uint32_t value)
{
  data[0] = (unsigned char)((value >> 24) & 0xFF);
  data[1] = (unsigned char)((value >> 16) & 0xFF);
  data[2] = (unsigned char)((value >> 8) & 0xFF);
  data[3] = (unsigned char)(value & 0xFF);
}

/* ============================================================================
 * Frame Header Parsing/Serialization
 * ============================================================================
 */

/**
 * SocketHTTP2_frame_header_parse - Parse 9-byte frame header
 * @data: Input buffer containing frame header
 * @input_len: Available bytes in data (must >= HTTP2_FRAME_HEADER_SIZE=9)
 * @header: Output structure (populated on success)
 *
 * Returns: 0 on success, -1 on invalid input (null pointers, insufficient
 * length)
 *
 * Thread-safe: Yes
 */
int
SocketHTTP2_frame_header_parse (const unsigned char *data, size_t input_len,
                                SocketHTTP2_FrameHeader *header)
{
  if (!data || input_len < HTTP2_FRAME_HEADER_SIZE || !header)
    return -1;

  /* Length: 24-bit big-endian */
  header->length = http2_unpack_be24 (data + 0);

  header->type = data[3];
  header->flags = data[4];

  /* Stream ID: 31-bit big-endian (R bit is reserved, must be masked) */
  header->stream_id = http2_unpack_stream_id (data + 5);

  return 0;
}

/**
 * SocketHTTP2_frame_header_serialize - Serialize frame header to 9 bytes
 * @header: Header structure
 * @data: Output buffer (at least HTTP2_FRAME_HEADER_SIZE bytes)
 *
 * Thread-safe: Yes
 */
void
SocketHTTP2_frame_header_serialize (const SocketHTTP2_FrameHeader *header,
                                    unsigned char *data)
{
  if (!header || !data)
    return;

  /* Length: 24-bit big-endian */
  http2_pack_be24 (data + 0, header->length);

  data[3] = header->type;
  data[4] = header->flags;

  /* Stream ID: 31-bit big-endian (R bit always 0) */
  http2_pack_stream_id (data + 5, header->stream_id);
}

/* ============================================================================
 * Per-Frame-Type Validators (RFC 9113 Section 6)
 * ============================================================================
 */

/**
 * validate_data_frame - Validate DATA frame (Section 6.1)
 *
 * DATA frames MUST be associated with a stream (stream_id != 0).
 */
static SocketHTTP2_ErrorCode
validate_data_frame (const SocketHTTP2_FrameHeader *header,
                     SocketHTTP2_Conn_T conn)
{
  (void)conn;
  REQUIRE_STREAM (header);
  return HTTP2_NO_ERROR;
}

/**
 * validate_headers_frame - Validate HEADERS frame (Section 6.2)
 *
 * HEADERS frames MUST be associated with a stream (stream_id != 0).
 */
static SocketHTTP2_ErrorCode
validate_headers_frame (const SocketHTTP2_FrameHeader *header,
                        SocketHTTP2_Conn_T conn)
{
  (void)conn;
  REQUIRE_STREAM (header);
  return HTTP2_NO_ERROR;
}

/**
 * validate_priority_frame - Validate PRIORITY frame (Section 6.3)
 *
 * PRIORITY has fixed 5-byte payload and requires stream association.
 */
static SocketHTTP2_ErrorCode
validate_priority_frame (const SocketHTTP2_FrameHeader *header,
                         SocketHTTP2_Conn_T conn)
{
  (void)conn;
  REQUIRE_STREAM (header);
  REQUIRE_EXACT_LENGTH (header, HTTP2_PRIORITY_PAYLOAD_SIZE);
  return HTTP2_NO_ERROR;
}

/**
 * validate_rst_stream_frame - Validate RST_STREAM frame (Section 6.4)
 *
 * RST_STREAM has fixed 4-byte payload and requires stream association.
 */
static SocketHTTP2_ErrorCode
validate_rst_stream_frame (const SocketHTTP2_FrameHeader *header,
                           SocketHTTP2_Conn_T conn)
{
  (void)conn;
  REQUIRE_STREAM (header);
  REQUIRE_EXACT_LENGTH (header, HTTP2_WINDOW_UPDATE_PAYLOAD_SIZE);
  return HTTP2_NO_ERROR;
}

/**
 * validate_settings_frame - Validate SETTINGS frame (Section 6.5)
 *
 * SETTINGS applies to connection, not stream. ACK must have empty payload.
 * Non-ACK payload must be divisible by 6 (each setting is 6 bytes).
 */
static SocketHTTP2_ErrorCode
validate_settings_frame (const SocketHTTP2_FrameHeader *header,
                         SocketHTTP2_Conn_T conn)
{
  (void)conn;
  REQUIRE_CONNECTION_ONLY (header);

  if ((header->flags & HTTP2_FLAG_ACK)
          ? (header->length != 0)
          : (header->length % HTTP2_SETTING_ENTRY_SIZE != 0))
    return HTTP2_FRAME_SIZE_ERROR;

  return HTTP2_NO_ERROR;
}

/**
 * validate_push_promise_frame - Validate PUSH_PROMISE frame (Section 6.6)
 *
 * PUSH_PROMISE requires stream association. Clients must have push enabled.
 * Servers must not receive PUSH_PROMISE.
 */
static SocketHTTP2_ErrorCode
validate_push_promise_frame (const SocketHTTP2_FrameHeader *header,
                             SocketHTTP2_Conn_T conn)
{
  REQUIRE_STREAM (header);

  /* Servers never receive PUSH_PROMISE; clients error if push disabled */
  if (conn->role == HTTP2_ROLE_SERVER
      || (conn->role == HTTP2_ROLE_CLIENT
          && conn->local_settings[SETTINGS_IDX_ENABLE_PUSH] == 0))
    return HTTP2_PROTOCOL_ERROR;

  return HTTP2_NO_ERROR;
}

/**
 * validate_ping_frame - Validate PING frame (Section 6.7)
 *
 * PING has fixed 8-byte payload and must be connection-level (stream_id=0).
 */
static SocketHTTP2_ErrorCode
validate_ping_frame (const SocketHTTP2_FrameHeader *header,
                     SocketHTTP2_Conn_T conn)
{
  (void)conn;
  REQUIRE_CONNECTION_ONLY (header);
  REQUIRE_EXACT_LENGTH (header, HTTP2_PING_PAYLOAD_SIZE);
  return HTTP2_NO_ERROR;
}

/**
 * validate_goaway_frame - Validate GOAWAY frame (Section 6.8)
 *
 * GOAWAY must be connection-level with minimum 8-byte payload.
 */
static SocketHTTP2_ErrorCode
validate_goaway_frame (const SocketHTTP2_FrameHeader *header,
                       SocketHTTP2_Conn_T conn)
{
  (void)conn;
  REQUIRE_CONNECTION_ONLY (header);
  if (header->length < HTTP2_GOAWAY_HEADER_SIZE)
    return HTTP2_FRAME_SIZE_ERROR;
  return HTTP2_NO_ERROR;
}

/**
 * validate_window_update_frame - Validate WINDOW_UPDATE frame (Section 6.9)
 *
 * WINDOW_UPDATE has fixed 4-byte payload. Can be connection or stream level.
 */
static SocketHTTP2_ErrorCode
validate_window_update_frame (const SocketHTTP2_FrameHeader *header,
                              SocketHTTP2_Conn_T conn)
{
  (void)conn;
  REQUIRE_EXACT_LENGTH (header, HTTP2_WINDOW_UPDATE_PAYLOAD_SIZE);
  return HTTP2_NO_ERROR;
}

/**
 * validate_continuation_frame - Validate CONTINUATION frame (Section 6.10)
 *
 * CONTINUATION must follow HEADERS/PUSH_PROMISE/CONTINUATION and must be
 * for the same stream that started the header block.
 */
static SocketHTTP2_ErrorCode
validate_continuation_frame (const SocketHTTP2_FrameHeader *header,
                             SocketHTTP2_Conn_T conn)
{
  REQUIRE_STREAM (header);

  if (!conn->expecting_continuation
      || conn->continuation_stream_id != header->stream_id)
    return HTTP2_PROTOCOL_ERROR;

  return HTTP2_NO_ERROR;
}

/* ============================================================================
 * Frame Validation Entry Point
 * ============================================================================
 */

/**
 * http2_frame_validate - Validate frame against RFC 9113 rules
 * @conn: Connection context
 * @header: Frame header to validate
 *
 * Returns: HTTP2_NO_ERROR if valid, error code otherwise
 */
SocketHTTP2_ErrorCode
http2_frame_validate (SocketHTTP2_Conn_T conn,
                      const SocketHTTP2_FrameHeader *header)
{
  assert (conn);
  assert (header);

  uint32_t max_frame_size = conn->peer_settings[SETTINGS_IDX_MAX_FRAME_SIZE];

  /* RFC 9113 Section 4.2: Frame size constraints */
  if (header->length > max_frame_size)
    return HTTP2_FRAME_SIZE_ERROR;

  /* If expecting CONTINUATION, only CONTINUATION is allowed */
  if (conn->expecting_continuation && header->type != HTTP2_FRAME_CONTINUATION)
    return HTTP2_PROTOCOL_ERROR;

  /* Ignore unknown frame types (RFC 9113 Section 4.1) */
  if (header->type > HTTP2_FRAME_CONTINUATION)
    return HTTP2_NO_ERROR;

  return frame_validators[header->type](header, conn);
}

/* ============================================================================
 * Frame Sending
 * ============================================================================
 */

/**
 * http2_frame_send - Queue frame for sending
 * @conn: Connection
 * @header: Frame header
 * @payload: Payload data (may be NULL)
 * @payload_len: Payload length
 *
 * Returns: 0 on success, -1 on error (buffer full or invalid input)
 * Thread-safe: No
 */
int
http2_frame_send (SocketHTTP2_Conn_T conn,
                  const SocketHTTP2_FrameHeader *header, const void *payload,
                  size_t payload_len)
{
  unsigned char frame_header[HTTP2_FRAME_HEADER_SIZE];

  if (!conn || !header || header->length != payload_len
      || (payload_len > 0 && !payload))
    return -1;

  SocketHTTP2_frame_header_serialize (header, frame_header);

  if (SocketBuf_write (conn->send_buf, frame_header, HTTP2_FRAME_HEADER_SIZE)
      != HTTP2_FRAME_HEADER_SIZE)
    {
      SOCKET_LOG_ERROR_MSG ("Failed to write HTTP/2 frame header to send "
                            "buffer: type=%s stream=%u",
                            SocketHTTP2_frame_type_string (header->type),
                            header->stream_id);
      return -1;
    }

  if (payload_len > 0)
    {
      if (SocketBuf_write (conn->send_buf, payload, payload_len)
          != payload_len)
        {
          SOCKET_LOG_ERROR_MSG ("Failed to write HTTP/2 frame payload to send "
                                "buffer: type=%s stream=%u len=%zu",
                                SocketHTTP2_frame_type_string (header->type),
                                header->stream_id, payload_len);
          return -1;
        }
    }

  return 0;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * SocketHTTP2_error_string - Get error code description
 * @code: Error code
 *
 * Returns: Static string describing the error
 * Thread-safe: Yes
 */
const char *
SocketHTTP2_error_string (SocketHTTP2_ErrorCode code)
{
  return STRING_LOOKUP (error_code_names, ERROR_CODE_COUNT, code,
                        "UNKNOWN_ERROR");
}

/**
 * SocketHTTP2_frame_type_string - Get frame type name
 * @type: Frame type
 *
 * Returns: Static string with frame type name
 * Thread-safe: Yes
 */
const char *
SocketHTTP2_frame_type_string (SocketHTTP2_FrameType type)
{
  return STRING_LOOKUP (frame_type_names, FRAME_TYPE_COUNT, type,
                        "UNKNOWN_FRAME");
}

/**
 * SocketHTTP2_stream_state_string - Get stream state name
 * @state: Stream state
 *
 * Returns: Static string with state name
 * Thread-safe: Yes
 */
const char *
SocketHTTP2_stream_state_string (SocketHTTP2_StreamState state)
{
  return STRING_LOOKUP (stream_state_names, STREAM_STATE_COUNT, state,
                        "UNKNOWN_STATE");
}

/* ============================================================================
 * Error Emission Helpers
 * ============================================================================
 */

/**
 * http2_send_connection_error - Send GOAWAY and prepare for close
 * @conn: Connection
 * @error_code: HTTP/2 error code
 *
 * Only sends GOAWAY once per connection.
 * Thread-safe: No
 */
void
http2_send_connection_error (SocketHTTP2_Conn_T conn,
                             SocketHTTP2_ErrorCode error_code)
{
  if (!conn)
    return;

  if (!conn->goaway_sent)
    SocketHTTP2_Conn_goaway (conn, error_code, NULL, 0);
}

/**
 * http2_send_stream_error - Send RST_STREAM frame
 * @conn: Connection
 * @stream_id: Target stream ID
 * @error_code: HTTP/2 error code
 *
 * Thread-safe: No
 */
void
http2_send_stream_error (SocketHTTP2_Conn_T conn, uint32_t stream_id,
                         SocketHTTP2_ErrorCode error_code)
{
  SocketHTTP2_FrameHeader header;
  unsigned char payload[HTTP2_WINDOW_UPDATE_PAYLOAD_SIZE];

  if (!conn)
    return;

  header.length = HTTP2_WINDOW_UPDATE_PAYLOAD_SIZE;
  header.type = HTTP2_FRAME_RST_STREAM;
  header.flags = 0;
  header.stream_id = stream_id;

  /* Error code: 32-bit big-endian */
  http2_pack_uint32_be (payload, error_code);

  if (http2_frame_send (conn, &header, payload, sizeof (payload)) != 0)
    {
      SOCKET_LOG_WARN_MSG ("Failed to send RST_STREAM for stream %u: %s",
                           stream_id, SocketHTTP2_error_string (error_code));
    }
}

/* ============================================================================
 * Event Emission Helpers
 * ============================================================================
 */

/**
 * http2_emit_stream_event - Invoke stream event callback
 * @conn: Connection
 * @stream: Target stream
 * @event: Event type (HTTP2_EVENT_*)
 *
 * Thread-safe: No
 */
void
http2_emit_stream_event (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                         int event)
{
  if (!conn || !stream)
    return;

  if (conn->stream_callback)
    conn->stream_callback (conn, stream, event, conn->stream_callback_data);
}

/**
 * http2_emit_conn_event - Invoke connection event callback
 * @conn: Connection
 * @event: Event type (HTTP2_EVENT_*)
 *
 * Thread-safe: No
 */
void
http2_emit_conn_event (SocketHTTP2_Conn_T conn, int event)
{
  if (!conn)
    return;

  if (conn->conn_callback)
    conn->conn_callback (conn, event, conn->conn_callback_data);
}

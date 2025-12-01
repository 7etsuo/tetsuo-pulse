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
#include <string.h>

/* ============================================================================
 * Module Exception Setup
 * ============================================================================ */

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTP2"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTP2);

#define RAISE_HTTP2_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketHTTP2, e)

/* ============================================================================
 * Exception Definitions
 * ============================================================================ */

const Except_T SocketHTTP2_ProtocolError
    = { &SocketHTTP2_ProtocolError, "HTTP/2 protocol error" };
const Except_T SocketHTTP2_StreamError
    = { &SocketHTTP2_StreamError, "HTTP/2 stream error" };
const Except_T SocketHTTP2_FlowControlError
    = { &SocketHTTP2_FlowControlError, "HTTP/2 flow control error" };

/* ============================================================================
 * Frame Type Names
 * ============================================================================ */

static const char *frame_type_names[] = {
  "DATA",         /* 0x0 */
  "HEADERS",      /* 0x1 */
  "PRIORITY",     /* 0x2 */
  "RST_STREAM",   /* 0x3 */
  "SETTINGS",     /* 0x4 */
  "PUSH_PROMISE", /* 0x5 */
  "PING",         /* 0x6 */
  "GOAWAY",       /* 0x7 */
  "WINDOW_UPDATE", /* 0x8 */
  "CONTINUATION"  /* 0x9 */
};

#define FRAME_TYPE_COUNT (sizeof (frame_type_names) / sizeof (frame_type_names[0]))

/* ============================================================================
 * Error Code Names
 * ============================================================================ */

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

#define ERROR_CODE_COUNT (sizeof (error_code_names) / sizeof (error_code_names[0]))

/* ============================================================================
 * Stream State Names
 * ============================================================================ */

static const char *stream_state_names[] = {
  "idle",
  "reserved (local)",
  "reserved (remote)",
  "open",
  "half-closed (local)",
  "half-closed (remote)",
  "closed"
};

#define STREAM_STATE_COUNT (sizeof (stream_state_names) / sizeof (stream_state_names[0]))

/* ============================================================================
 * Frame Header Parsing/Serialization
 * ============================================================================ */

int
SocketHTTP2_frame_header_parse (const unsigned char *data,
                                SocketHTTP2_FrameHeader *header)
{
  assert (data);
  assert (header);

  /* Length: 24-bit big-endian */
  header->length = ((uint32_t)data[0] << 16) | ((uint32_t)data[1] << 8)
                   | (uint32_t)data[2];

  /* Type: 8-bit */
  header->type = data[3];

  /* Flags: 8-bit */
  header->flags = data[4];

  /* Stream ID: 31-bit big-endian (R bit is reserved) */
  header->stream_id = ((uint32_t)(data[5] & 0x7F) << 24)
                      | ((uint32_t)data[6] << 16) | ((uint32_t)data[7] << 8)
                      | (uint32_t)data[8];

  return 0;
}

void
SocketHTTP2_frame_header_serialize (const SocketHTTP2_FrameHeader *header,
                                    unsigned char *data)
{
  assert (header);
  assert (data);

  /* Length: 24-bit big-endian */
  data[0] = (unsigned char)((header->length >> 16) & 0xFF);
  data[1] = (unsigned char)((header->length >> 8) & 0xFF);
  data[2] = (unsigned char)(header->length & 0xFF);

  /* Type: 8-bit */
  data[3] = header->type;

  /* Flags: 8-bit */
  data[4] = header->flags;

  /* Stream ID: 31-bit big-endian (R bit always 0) */
  data[5] = (unsigned char)((header->stream_id >> 24) & 0x7F);
  data[6] = (unsigned char)((header->stream_id >> 16) & 0xFF);
  data[7] = (unsigned char)((header->stream_id >> 8) & 0xFF);
  data[8] = (unsigned char)(header->stream_id & 0xFF);
}

/* ============================================================================
 * Frame Validation (RFC 9113 Section 4 and 6)
 * ============================================================================ */

SocketHTTP2_ErrorCode
http2_frame_validate (SocketHTTP2_Conn_T conn,
                      const SocketHTTP2_FrameHeader *header)
{
  assert (conn);
  assert (header);

  uint32_t max_frame_size = conn->peer_settings[SETTINGS_IDX_MAX_FRAME_SIZE];

  /* RFC 9113 Section 4.2: Frame size constraints */
  if (header->length > max_frame_size)
    {
      return HTTP2_FRAME_SIZE_ERROR;
    }

  /* Validate frame-specific constraints */
  switch (header->type)
    {
    case HTTP2_FRAME_DATA:
      /* DATA frames MUST be associated with a stream */
      if (header->stream_id == 0)
        {
          return HTTP2_PROTOCOL_ERROR;
        }
      break;

    case HTTP2_FRAME_HEADERS:
      /* HEADERS frames MUST be associated with a stream */
      if (header->stream_id == 0)
        {
          return HTTP2_PROTOCOL_ERROR;
        }
      break;

    case HTTP2_FRAME_PRIORITY:
      /* PRIORITY frames MUST be associated with a stream */
      if (header->stream_id == 0)
        {
          return HTTP2_PROTOCOL_ERROR;
        }
      /* PRIORITY frames have a fixed payload size of 5 octets */
      if (header->length != 5)
        {
          return HTTP2_FRAME_SIZE_ERROR;
        }
      break;

    case HTTP2_FRAME_RST_STREAM:
      /* RST_STREAM frames MUST be associated with a stream */
      if (header->stream_id == 0)
        {
          return HTTP2_PROTOCOL_ERROR;
        }
      /* RST_STREAM frames have a fixed payload size of 4 octets */
      if (header->length != 4)
        {
          return HTTP2_FRAME_SIZE_ERROR;
        }
      break;

    case HTTP2_FRAME_SETTINGS:
      /* SETTINGS frames always apply to a connection, not a stream */
      if (header->stream_id != 0)
        {
          return HTTP2_PROTOCOL_ERROR;
        }
      /* SETTINGS ACK frames MUST have length 0 */
      if ((header->flags & HTTP2_FLAG_ACK) && header->length != 0)
        {
          return HTTP2_FRAME_SIZE_ERROR;
        }
      /* SETTINGS frames must have length divisible by 6 */
      if (!(header->flags & HTTP2_FLAG_ACK) && (header->length % 6 != 0))
        {
          return HTTP2_FRAME_SIZE_ERROR;
        }
      break;

    case HTTP2_FRAME_PUSH_PROMISE:
      /* PUSH_PROMISE frames MUST be associated with a stream */
      if (header->stream_id == 0)
        {
          return HTTP2_PROTOCOL_ERROR;
        }
      /* Client role should not receive PUSH_PROMISE if push disabled */
      if (conn->role == HTTP2_ROLE_CLIENT
          && conn->local_settings[SETTINGS_IDX_ENABLE_PUSH] == 0)
        {
          return HTTP2_PROTOCOL_ERROR;
        }
      /* Server should not receive PUSH_PROMISE */
      if (conn->role == HTTP2_ROLE_SERVER)
        {
          return HTTP2_PROTOCOL_ERROR;
        }
      break;

    case HTTP2_FRAME_PING:
      /* PING frames are not associated with any individual stream */
      if (header->stream_id != 0)
        {
          return HTTP2_PROTOCOL_ERROR;
        }
      /* PING frames have a fixed payload size of 8 octets */
      if (header->length != 8)
        {
          return HTTP2_FRAME_SIZE_ERROR;
        }
      break;

    case HTTP2_FRAME_GOAWAY:
      /* GOAWAY frames always apply to connection, not stream */
      if (header->stream_id != 0)
        {
          return HTTP2_PROTOCOL_ERROR;
        }
      /* Minimum payload: 4 (last_stream_id) + 4 (error_code) = 8 */
      if (header->length < 8)
        {
          return HTTP2_FRAME_SIZE_ERROR;
        }
      break;

    case HTTP2_FRAME_WINDOW_UPDATE:
      /* WINDOW_UPDATE payload is exactly 4 octets */
      if (header->length != 4)
        {
          return HTTP2_FRAME_SIZE_ERROR;
        }
      break;

    case HTTP2_FRAME_CONTINUATION:
      /* CONTINUATION frames MUST be associated with a stream */
      if (header->stream_id == 0)
        {
          return HTTP2_PROTOCOL_ERROR;
        }
      /* CONTINUATION must follow HEADERS/PUSH_PROMISE/CONTINUATION */
      if (!conn->expecting_continuation
          || conn->continuation_stream_id != header->stream_id)
        {
          return HTTP2_PROTOCOL_ERROR;
        }
      break;

    default:
      /* Unknown frame types MUST be ignored (RFC 9113 Section 4.1) */
      break;
    }

  /* If expecting CONTINUATION, only CONTINUATION is allowed */
  if (conn->expecting_continuation && header->type != HTTP2_FRAME_CONTINUATION)
    {
      return HTTP2_PROTOCOL_ERROR;
    }

  return HTTP2_NO_ERROR;
}

/* ============================================================================
 * Frame Sending
 * ============================================================================ */

int
http2_frame_send (SocketHTTP2_Conn_T conn,
                  const SocketHTTP2_FrameHeader *header, const void *payload,
                  size_t payload_len)
{
  unsigned char frame_header[HTTP2_FRAME_HEADER_SIZE];

  assert (conn);
  assert (header);
  assert (header->length == payload_len);

  /* Serialize frame header */
  SocketHTTP2_frame_header_serialize (header, frame_header);

  /* Write header to send buffer */
  if (SocketBuf_write (conn->send_buf, frame_header, HTTP2_FRAME_HEADER_SIZE)
      != HTTP2_FRAME_HEADER_SIZE)
    {
      return -1;
    }

  /* Write payload to send buffer */
  if (payload_len > 0 && payload != NULL)
    {
      if (SocketBuf_write (conn->send_buf, payload, payload_len) != payload_len)
        {
          return -1;
        }
    }

  return 0;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

const char *
SocketHTTP2_error_string (SocketHTTP2_ErrorCode code)
{
  if (code < ERROR_CODE_COUNT)
    {
      return error_code_names[code];
    }
  return "UNKNOWN_ERROR";
}

const char *
SocketHTTP2_frame_type_string (SocketHTTP2_FrameType type)
{
  if (type < FRAME_TYPE_COUNT)
    {
      return frame_type_names[type];
    }
  return "UNKNOWN_FRAME";
}

const char *
SocketHTTP2_stream_state_string (SocketHTTP2_StreamState state)
{
  if (state < STREAM_STATE_COUNT)
    {
      return stream_state_names[state];
    }
  return "UNKNOWN_STATE";
}

/* ============================================================================
 * Error Emission Helpers
 * ============================================================================ */

void
http2_send_connection_error (SocketHTTP2_Conn_T conn,
                             SocketHTTP2_ErrorCode error_code)
{
  /* Only send GOAWAY once */
  if (!conn->goaway_sent)
    {
      SocketHTTP2_Conn_goaway (conn, error_code, NULL, 0);
    }
}

void
http2_send_stream_error (SocketHTTP2_Conn_T conn, uint32_t stream_id,
                         SocketHTTP2_ErrorCode error_code)
{
  SocketHTTP2_FrameHeader header;
  unsigned char payload[4];

  header.length = 4;
  header.type = HTTP2_FRAME_RST_STREAM;
  header.flags = 0;
  header.stream_id = stream_id;

  /* Error code: 32-bit big-endian */
  payload[0] = (unsigned char)((error_code >> 24) & 0xFF);
  payload[1] = (unsigned char)((error_code >> 16) & 0xFF);
  payload[2] = (unsigned char)((error_code >> 8) & 0xFF);
  payload[3] = (unsigned char)(error_code & 0xFF);

  http2_frame_send (conn, &header, payload, sizeof (payload));
}

/* ============================================================================
 * Event Emission Helpers
 * ============================================================================ */

void
http2_emit_stream_event (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                         int event)
{
  if (conn->stream_callback)
    {
      conn->stream_callback (conn, stream, event, conn->stream_callback_data);
    }
}

void
http2_emit_conn_event (SocketHTTP2_Conn_T conn, int event)
{
  if (conn->conn_callback)
    {
      conn->conn_callback (conn, event, conn->conn_callback_data);
    }
}


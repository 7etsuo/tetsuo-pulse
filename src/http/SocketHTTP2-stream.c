/**
 * SocketHTTP2-stream.c - HTTP/2 Stream State Machine
 *
 * Part of the Socket Library
 *
 * Implements:
 * - Stream creation and lookup (O(1) hash table)
 * - Stream state machine (RFC 9113 Section 5.1)
 * - DATA/HEADERS frame processing
 * - Header encoding/decoding integration
 * - Stream sending/receiving
 */

#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTP2.h"

#include "core/SocketUtil.h"
#include "socket/SocketBuf.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Module Exception Setup
 * ============================================================================ */

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTP2"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTP2);

#define RAISE_HTTP2_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketHTTP2, e)

/* ============================================================================
 * Stream Lookup (O(1) using hash table)
 * ============================================================================ */

SocketHTTP2_Stream_T
http2_stream_lookup (SocketHTTP2_Conn_T conn, uint32_t stream_id)
{
  unsigned idx;
  SocketHTTP2_Stream_T stream;

  assert (conn);

  idx = socket_util_hash_uint (stream_id, HTTP2_STREAM_HASH_SIZE);
  stream = conn->streams[idx];

  while (stream)
    {
      if (stream->id == stream_id)
        return stream;
      stream = stream->hash_next;
    }

  return NULL;
}

/* ============================================================================
 * Stream Creation
 * ============================================================================ */

SocketHTTP2_Stream_T
http2_stream_create (SocketHTTP2_Conn_T conn, uint32_t stream_id)
{
  SocketHTTP2_Stream_T stream;
  unsigned idx;

  assert (conn);
  assert (stream_id > 0);

  /* Check concurrent stream limit */
  if (conn->stream_count >= conn->local_settings[SETTINGS_IDX_MAX_CONCURRENT_STREAMS])
    {
      return NULL;
    }

  /* Allocate stream */
  stream = Arena_alloc (conn->arena, sizeof (*stream), __FILE__, __LINE__);
  if (!stream)
    {
      return NULL;
    }
  memset (stream, 0, sizeof (*stream));

  stream->id = stream_id;
  stream->state = HTTP2_STREAM_STATE_IDLE;
  stream->conn = conn;

  /* Initialize flow control windows */
  stream->send_window = conn->initial_send_window;
  stream->recv_window = conn->initial_recv_window;

  /* Create receive buffer for DATA frames */
  stream->recv_buf = SocketBuf_new (conn->arena, 64 * 1024); /* 64KB */
  if (!stream->recv_buf)
    {
      return NULL;
    }

  /* Add to hash table */
  idx = socket_util_hash_uint (stream_id, HTTP2_STREAM_HASH_SIZE);
  stream->hash_next = conn->streams[idx];
  conn->streams[idx] = stream;
  conn->stream_count++;

  return stream;
}

void
http2_stream_destroy (SocketHTTP2_Stream_T stream)
{
  SocketHTTP2_Conn_T conn;
  unsigned idx;
  SocketHTTP2_Stream_T *prev;

  if (!stream)
    return;

  conn = stream->conn;

  /* Remove from hash table */
  idx = socket_util_hash_uint (stream->id, HTTP2_STREAM_HASH_SIZE);
  prev = &conn->streams[idx];

  while (*prev)
    {
      if (*prev == stream)
        {
          *prev = stream->hash_next;
          conn->stream_count--;
          break;
        }
      prev = &(*prev)->hash_next;
    }

  /* Free buffer */
  if (stream->recv_buf)
    SocketBuf_release (&stream->recv_buf);

  /* Stream memory managed by arena */
}

/* ============================================================================
 * Stream State Machine (RFC 9113 Section 5.1)
 * ============================================================================
 *
 *                          +--------+
 *                  send PP |        | recv PP
 *                 ,--------|  idle  |--------.
 *                /         |        |         \
 *               v          +--------+          v
 *        +----------+          |           +----------+
 *        |          |          | send H /  |          |
 * ,------| reserved |          | recv H    | reserved |------.
 * |      | (local)  |          |           | (remote) |      |
 * |      +----------+          v           +----------+      |
 * |          |             +--------+             |          |
 * |          |     recv ES |        | send ES     |          |
 * |   send H |     ,-------|  open  |-------.     | recv H   |
 * |          |    /        |        |        \    |          |
 * |          v   v         +--------+         v   v          |
 * |      +----------+          |           +----------+      |
 * |      |   half   |          |           |   half   |      |
 * |      |  closed  |          | send R /  |  closed  |      |
 * |      | (remote) |          | recv R    | (local)  |      |
 * |      +----------+          |           +----------+      |
 * |           |                |                 |           |
 * |           | send ES /      |       recv ES / |           |
 * |           | send R /       v        send R / |           |
 * |           | recv R     +--------+   recv R   |           |
 * | send R /  `----------->|        |<-----------'  send R / |
 * | recv R                 | closed |               recv R   |
 * `----------------------->|        |<-----------------------'
 *                          +--------+
 */

SocketHTTP2_ErrorCode
http2_stream_transition (SocketHTTP2_Stream_T stream, uint8_t frame_type,
                         uint8_t flags, int is_send)
{
  SocketHTTP2_StreamState new_state = stream->state;
  int end_stream = (flags & HTTP2_FLAG_END_STREAM) != 0;
  int end_headers = (flags & HTTP2_FLAG_END_HEADERS) != 0;

  (void)end_headers; /* Used implicitly in HEADERS handling */

  switch (stream->state)
    {
    case HTTP2_STREAM_STATE_IDLE:
      if (frame_type == HTTP2_FRAME_HEADERS)
        {
          if (is_send)
            {
              new_state = end_stream ? HTTP2_STREAM_STATE_HALF_CLOSED_LOCAL
                                     : HTTP2_STREAM_STATE_OPEN;
            }
          else
            {
              new_state = end_stream ? HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE
                                     : HTTP2_STREAM_STATE_OPEN;
            }
        }
      else if (frame_type == HTTP2_FRAME_PUSH_PROMISE)
        {
          if (is_send)
            {
              new_state = HTTP2_STREAM_STATE_RESERVED_LOCAL;
            }
          else
            {
              new_state = HTTP2_STREAM_STATE_RESERVED_REMOTE;
            }
        }
      else if (frame_type == HTTP2_FRAME_PRIORITY)
        {
          /* PRIORITY can be sent/received on idle streams */
          new_state = HTTP2_STREAM_STATE_IDLE;
        }
      else
        {
          return HTTP2_PROTOCOL_ERROR;
        }
      break;

    case HTTP2_STREAM_STATE_RESERVED_LOCAL:
      if (is_send && frame_type == HTTP2_FRAME_HEADERS)
        {
          new_state = HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE;
        }
      else if (!is_send && frame_type == HTTP2_FRAME_RST_STREAM)
        {
          new_state = HTTP2_STREAM_STATE_CLOSED;
        }
      else if (is_send && frame_type == HTTP2_FRAME_RST_STREAM)
        {
          new_state = HTTP2_STREAM_STATE_CLOSED;
        }
      else if (frame_type == HTTP2_FRAME_PRIORITY)
        {
          /* PRIORITY allowed */
        }
      else if (frame_type == HTTP2_FRAME_WINDOW_UPDATE && is_send)
        {
          /* Can send WINDOW_UPDATE */
        }
      else
        {
          return HTTP2_PROTOCOL_ERROR;
        }
      break;

    case HTTP2_STREAM_STATE_RESERVED_REMOTE:
      if (!is_send && frame_type == HTTP2_FRAME_HEADERS)
        {
          new_state = HTTP2_STREAM_STATE_HALF_CLOSED_LOCAL;
        }
      else if (is_send && frame_type == HTTP2_FRAME_RST_STREAM)
        {
          new_state = HTTP2_STREAM_STATE_CLOSED;
        }
      else if (!is_send && frame_type == HTTP2_FRAME_RST_STREAM)
        {
          new_state = HTTP2_STREAM_STATE_CLOSED;
        }
      else if (frame_type == HTTP2_FRAME_PRIORITY)
        {
          /* PRIORITY allowed */
        }
      else if (frame_type == HTTP2_FRAME_WINDOW_UPDATE && !is_send)
        {
          /* Can receive WINDOW_UPDATE */
        }
      else
        {
          return HTTP2_PROTOCOL_ERROR;
        }
      break;

    case HTTP2_STREAM_STATE_OPEN:
      if (frame_type == HTTP2_FRAME_RST_STREAM)
        {
          new_state = HTTP2_STREAM_STATE_CLOSED;
        }
      else if (end_stream)
        {
          if (is_send)
            {
              new_state = HTTP2_STREAM_STATE_HALF_CLOSED_LOCAL;
            }
          else
            {
              new_state = HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE;
            }
        }
      /* DATA, HEADERS (trailers), WINDOW_UPDATE, CONTINUATION allowed */
      break;

    case HTTP2_STREAM_STATE_HALF_CLOSED_LOCAL:
      if (!is_send)
        {
          if (frame_type == HTTP2_FRAME_RST_STREAM)
            {
              new_state = HTTP2_STREAM_STATE_CLOSED;
            }
          else if (end_stream)
            {
              new_state = HTTP2_STREAM_STATE_CLOSED;
            }
          /* Can receive DATA, HEADERS (trailers), WINDOW_UPDATE */
        }
      else
        {
          if (frame_type == HTTP2_FRAME_RST_STREAM)
            {
              new_state = HTTP2_STREAM_STATE_CLOSED;
            }
          else if (frame_type == HTTP2_FRAME_WINDOW_UPDATE)
            {
              /* Can send WINDOW_UPDATE */
            }
          else if (frame_type == HTTP2_FRAME_PRIORITY)
            {
              /* Can send PRIORITY */
            }
          else
            {
              return HTTP2_STREAM_CLOSED;
            }
        }
      break;

    case HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE:
      if (is_send)
        {
          if (frame_type == HTTP2_FRAME_RST_STREAM)
            {
              new_state = HTTP2_STREAM_STATE_CLOSED;
            }
          else if (end_stream)
            {
              new_state = HTTP2_STREAM_STATE_CLOSED;
            }
          /* Can send DATA, HEADERS (trailers) */
        }
      else
        {
          if (frame_type == HTTP2_FRAME_RST_STREAM)
            {
              new_state = HTTP2_STREAM_STATE_CLOSED;
            }
          else if (frame_type == HTTP2_FRAME_WINDOW_UPDATE)
            {
              /* Can receive WINDOW_UPDATE */
            }
          else if (frame_type == HTTP2_FRAME_PRIORITY)
            {
              /* Can receive PRIORITY */
            }
          else
            {
              return HTTP2_STREAM_CLOSED;
            }
        }
      break;

    case HTTP2_STREAM_STATE_CLOSED:
      /* Can still receive PRIORITY and WINDOW_UPDATE briefly */
      if (frame_type == HTTP2_FRAME_PRIORITY)
        {
          /* Allowed */
        }
      else if (!is_send && frame_type == HTTP2_FRAME_WINDOW_UPDATE)
        {
          /* May receive briefly after close */
        }
      else if (!is_send && frame_type == HTTP2_FRAME_RST_STREAM)
        {
          /* May receive briefly after close */
        }
      else
        {
          return HTTP2_STREAM_CLOSED;
        }
      break;
    }

  stream->state = new_state;
  return HTTP2_NO_ERROR;
}

/* ============================================================================
 * Stream Public API
 * ============================================================================ */

SocketHTTP2_Stream_T
SocketHTTP2_Stream_new (SocketHTTP2_Conn_T conn)
{
  SocketHTTP2_Stream_T stream;
  uint32_t stream_id;

  assert (conn);

  /* Check if GOAWAY received */
  if (conn->goaway_received)
    {
      return NULL;
    }

  /* Get next stream ID */
  stream_id = conn->next_stream_id;

  /* Check stream ID exhaustion */
  if (stream_id > 0x7FFFFFFF)
    {
      return NULL;
    }

  stream = http2_stream_create (conn, stream_id);
  if (!stream)
    {
      return NULL;
    }

  /* Advance to next stream ID */
  conn->next_stream_id += 2;

  return stream;
}

uint32_t
SocketHTTP2_Stream_id (SocketHTTP2_Stream_T stream)
{
  assert (stream);
  return stream->id;
}

SocketHTTP2_StreamState
SocketHTTP2_Stream_state (SocketHTTP2_Stream_T stream)
{
  assert (stream);
  return stream->state;
}

void
SocketHTTP2_Stream_close (SocketHTTP2_Stream_T stream,
                          SocketHTTP2_ErrorCode error_code)
{
  assert (stream);

  if (stream->state != HTTP2_STREAM_STATE_CLOSED)
    {
      http2_send_stream_error (stream->conn, stream->id, error_code);
      stream->state = HTTP2_STREAM_STATE_CLOSED;
    }
}

void *
SocketHTTP2_Stream_get_userdata (SocketHTTP2_Stream_T stream)
{
  assert (stream);
  return stream->userdata;
}

void
SocketHTTP2_Stream_set_userdata (SocketHTTP2_Stream_T stream, void *userdata)
{
  assert (stream);
  stream->userdata = userdata;
}

/* ============================================================================
 * Stream Flow Control
 * ============================================================================ */

int
SocketHTTP2_Stream_window_update (SocketHTTP2_Stream_T stream,
                                  uint32_t increment)
{
  SocketHTTP2_FrameHeader header;
  unsigned char payload[4];

  assert (stream);
  assert (increment > 0 && increment <= 0x7FFFFFFF);

  payload[0] = (unsigned char)((increment >> 24) & 0x7F);
  payload[1] = (unsigned char)((increment >> 16) & 0xFF);
  payload[2] = (unsigned char)((increment >> 8) & 0xFF);
  payload[3] = (unsigned char)(increment & 0xFF);

  header.length = 4;
  header.type = HTTP2_FRAME_WINDOW_UPDATE;
  header.flags = 0;
  header.stream_id = stream->id;

  return http2_frame_send (stream->conn, &header, payload, 4);
}

int32_t
SocketHTTP2_Stream_send_window (SocketHTTP2_Stream_T stream)
{
  assert (stream);
  return http2_flow_available_send (stream->conn, stream);
}

int32_t
SocketHTTP2_Stream_recv_window (SocketHTTP2_Stream_T stream)
{
  assert (stream);
  return stream->recv_window;
}

/* ============================================================================
 * Header Encoding/Decoding
 * ============================================================================ */

ssize_t
http2_encode_headers (SocketHTTP2_Conn_T conn, const SocketHPACK_Header *headers,
                      size_t count, unsigned char *output, size_t output_size)
{
  return SocketHPACK_Encoder_encode (conn->encoder, headers, count, output,
                                     output_size);
}

int
http2_decode_headers (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                      const unsigned char *block, size_t len)
{
  SocketHPACK_Header decoded_headers[128];
  size_t header_count = 0;
  SocketHPACK_Result result;

  (void)stream; /* Headers stored in stream later if needed */

  result = SocketHPACK_Decoder_decode (conn->decoder, block, len, decoded_headers,
                                       128, &header_count, conn->arena);

  if (result != HPACK_OK)
    {
      http2_send_connection_error (conn, HTTP2_COMPRESSION_ERROR);
      return -1;
    }

  return 0;
}

/* ============================================================================
 * Sending Headers
 * ============================================================================ */

int
SocketHTTP2_Stream_send_headers (SocketHTTP2_Stream_T stream,
                                 const SocketHPACK_Header *headers,
                                 size_t header_count, int end_stream)
{
  SocketHTTP2_Conn_T conn;
  SocketHTTP2_FrameHeader frame_header;
  unsigned char *header_block;
  ssize_t block_len;
  size_t max_block_size;
  uint32_t max_frame_size;
  SocketHTTP2_ErrorCode error;

  assert (stream);
  assert (headers || header_count == 0);

  conn = stream->conn;

  /* Check state transition */
  error = http2_stream_transition (stream, HTTP2_FRAME_HEADERS,
                                   end_stream ? HTTP2_FLAG_END_STREAM : 0, 1);
  if (error != HTTP2_NO_ERROR)
    {
      return -1;
    }

  /* Allocate buffer for header block */
  max_block_size = 16 * 1024; /* Start with 16KB */
  header_block = Arena_alloc (conn->arena, max_block_size, __FILE__, __LINE__);
  if (!header_block)
    {
      return -1;
    }

  /* Encode headers */
  block_len = http2_encode_headers (conn, headers, header_count, header_block,
                                    max_block_size);
  if (block_len < 0)
    {
      return -1;
    }

  max_frame_size = conn->peer_settings[SETTINGS_IDX_MAX_FRAME_SIZE];

  if ((size_t)block_len <= max_frame_size)
    {
      /* Single HEADERS frame */
      frame_header.length = (uint32_t)block_len;
      frame_header.type = HTTP2_FRAME_HEADERS;
      frame_header.flags
          = HTTP2_FLAG_END_HEADERS | (end_stream ? HTTP2_FLAG_END_STREAM : 0);
      frame_header.stream_id = stream->id;

      if (http2_frame_send (conn, &frame_header, header_block, (size_t)block_len) < 0)
        {
          return -1;
        }
    }
  else
    {
      /* Need CONTINUATION frames */
      size_t offset = 0;
      int first = 1;

      while (offset < (size_t)block_len)
        {
          size_t chunk = (size_t)block_len - offset;
          if (chunk > max_frame_size)
            chunk = max_frame_size;

          frame_header.length = (uint32_t)chunk;
          frame_header.type = first ? HTTP2_FRAME_HEADERS : HTTP2_FRAME_CONTINUATION;
          frame_header.flags = 0;

          /* END_STREAM only on first frame */
          if (first && end_stream)
            {
              frame_header.flags |= HTTP2_FLAG_END_STREAM;
            }

          /* END_HEADERS on last frame */
          if (offset + chunk >= (size_t)block_len)
            {
              frame_header.flags |= HTTP2_FLAG_END_HEADERS;
            }

          frame_header.stream_id = stream->id;

          if (http2_frame_send (conn, &frame_header, header_block + offset, chunk) < 0)
            {
              return -1;
            }

          offset += chunk;
          first = 0;
        }
    }

  if (end_stream)
    {
      stream->end_stream_sent = 1;
    }

  return 0;
}

int
SocketHTTP2_Stream_send_request (SocketHTTP2_Stream_T stream,
                                 const SocketHTTP_Request *request,
                                 int end_stream)
{
  SocketHPACK_Header pseudo_headers[4];
  SocketHPACK_Header *all_headers;
  size_t total_count;
  size_t header_count;
  char status_buf[16];

  assert (stream);
  assert (request);

  /* Build pseudo-headers */
  pseudo_headers[0].name = ":method";
  pseudo_headers[0].name_len = 7;
  pseudo_headers[0].value = SocketHTTP_method_name (request->method);
  pseudo_headers[0].value_len = strlen (pseudo_headers[0].value);
  pseudo_headers[0].never_index = 0;

  pseudo_headers[1].name = ":scheme";
  pseudo_headers[1].name_len = 7;
  pseudo_headers[1].value = request->scheme ? request->scheme : "https";
  pseudo_headers[1].value_len = strlen (pseudo_headers[1].value);
  pseudo_headers[1].never_index = 0;

  pseudo_headers[2].name = ":authority";
  pseudo_headers[2].name_len = 10;
  pseudo_headers[2].value = request->authority ? request->authority : "";
  pseudo_headers[2].value_len = strlen (pseudo_headers[2].value);
  pseudo_headers[2].never_index = 0;

  pseudo_headers[3].name = ":path";
  pseudo_headers[3].name_len = 5;
  pseudo_headers[3].value = request->path ? request->path : "/";
  pseudo_headers[3].value_len = strlen (pseudo_headers[3].value);
  pseudo_headers[3].never_index = 0;

  (void)status_buf;

  /* Count regular headers */
  header_count = request->headers ? SocketHTTP_Headers_count (request->headers) : 0;
  total_count = 4 + header_count;

  /* Allocate combined array */
  all_headers = Arena_alloc (stream->conn->arena,
                             total_count * sizeof (SocketHPACK_Header),
                             __FILE__, __LINE__);
  if (!all_headers)
    {
      return -1;
    }

  /* Copy pseudo-headers */
  memcpy (all_headers, pseudo_headers, 4 * sizeof (SocketHPACK_Header));

  /* Copy regular headers */
  if (request->headers)
    {
      for (size_t i = 0; i < header_count; i++)
        {
          const SocketHTTP_Header *h = SocketHTTP_Headers_at (request->headers, i);
          all_headers[4 + i].name = h->name;
          all_headers[4 + i].name_len = h->name_len;
          all_headers[4 + i].value = h->value;
          all_headers[4 + i].value_len = h->value_len;
          all_headers[4 + i].never_index = 0;
        }
    }

  return SocketHTTP2_Stream_send_headers (stream, all_headers, total_count,
                                          end_stream);
}

int
SocketHTTP2_Stream_send_response (SocketHTTP2_Stream_T stream,
                                  const SocketHTTP_Response *response,
                                  int end_stream)
{
  SocketHPACK_Header pseudo_header;
  SocketHPACK_Header *all_headers;
  size_t total_count;
  size_t header_count;
  char status_buf[16];
  int status_len;

  assert (stream);
  assert (response);

  /* Build :status pseudo-header */
  status_len = snprintf (status_buf, sizeof (status_buf), "%d", response->status_code);
  pseudo_header.name = ":status";
  pseudo_header.name_len = 7;
  pseudo_header.value = status_buf;
  pseudo_header.value_len = (size_t)status_len;
  pseudo_header.never_index = 0;

  /* Count regular headers */
  header_count = response->headers ? SocketHTTP_Headers_count (response->headers) : 0;
  total_count = 1 + header_count;

  /* Allocate combined array */
  all_headers = Arena_alloc (stream->conn->arena,
                             total_count * sizeof (SocketHPACK_Header),
                             __FILE__, __LINE__);
  if (!all_headers)
    {
      return -1;
    }

  /* Copy pseudo-header */
  all_headers[0] = pseudo_header;

  /* Copy regular headers */
  if (response->headers)
    {
      for (size_t i = 0; i < header_count; i++)
        {
          const SocketHTTP_Header *h = SocketHTTP_Headers_at (response->headers, i);
          all_headers[1 + i].name = h->name;
          all_headers[1 + i].name_len = h->name_len;
          all_headers[1 + i].value = h->value;
          all_headers[1 + i].value_len = h->value_len;
          all_headers[1 + i].never_index = 0;
        }
    }

  return SocketHTTP2_Stream_send_headers (stream, all_headers, total_count,
                                          end_stream);
}

int
SocketHTTP2_Stream_send_trailers (SocketHTTP2_Stream_T stream,
                                  const SocketHPACK_Header *trailers,
                                  size_t count)
{
  /* Trailers are HEADERS with END_STREAM */
  return SocketHTTP2_Stream_send_headers (stream, trailers, count, 1);
}

/* ============================================================================
 * Sending Data
 * ============================================================================ */

ssize_t
SocketHTTP2_Stream_send_data (SocketHTTP2_Stream_T stream, const void *data,
                              size_t len, int end_stream)
{
  SocketHTTP2_Conn_T conn;
  SocketHTTP2_FrameHeader header;
  SocketHTTP2_ErrorCode error;
  int32_t available;
  size_t send_len;
  uint32_t max_frame_size;

  assert (stream);
  assert (data || len == 0);

  conn = stream->conn;

  /* Check state transition */
  error = http2_stream_transition (stream, HTTP2_FRAME_DATA,
                                   end_stream ? HTTP2_FLAG_END_STREAM : 0, 1);
  if (error != HTTP2_NO_ERROR)
    {
      return -1;
    }

  /* Check flow control */
  available = http2_flow_available_send (conn, stream);
  if (available <= 0)
    {
      return 0; /* Would block - need WINDOW_UPDATE */
    }

  send_len = len;
  if (send_len > (size_t)available)
    {
      send_len = (size_t)available;
      end_stream = 0; /* Can't end stream without sending all data */
    }

  max_frame_size = conn->peer_settings[SETTINGS_IDX_MAX_FRAME_SIZE];
  if (send_len > max_frame_size)
    {
      send_len = max_frame_size;
      end_stream = 0;
    }

  /* Consume flow control windows */
  http2_flow_consume_send (conn, stream, send_len);

  /* Send DATA frame */
  header.length = (uint32_t)send_len;
  header.type = HTTP2_FRAME_DATA;
  header.flags = end_stream ? HTTP2_FLAG_END_STREAM : 0;
  header.stream_id = stream->id;

  if (http2_frame_send (conn, &header, data, send_len) < 0)
    {
      return -1;
    }

  if (end_stream)
    {
      stream->end_stream_sent = 1;
    }

  return (ssize_t)send_len;
}

/* ============================================================================
 * Receiving
 * ============================================================================ */

int
SocketHTTP2_Stream_recv_headers (SocketHTTP2_Stream_T stream,
                                 SocketHPACK_Header *headers,
                                 size_t max_headers, size_t *header_count,
                                 int *end_stream)
{
  assert (stream);
  assert (headers || max_headers == 0);
  assert (header_count);
  assert (end_stream);

  /* Suppress unused parameter warnings - these will be used
   * when full header storage is implemented */
  (void)headers;
  (void)max_headers;

  if (!stream->headers_received)
    {
      *header_count = 0;
      *end_stream = 0;
      return 0; /* No headers yet */
    }

  /* Headers were decoded during frame processing */
  /* For now, return indication that headers are available */
  *header_count = 0; /* Actual headers stored elsewhere */
  *end_stream = stream->end_stream_received;

  return 1;
}

ssize_t
SocketHTTP2_Stream_recv_data (SocketHTTP2_Stream_T stream, void *buf,
                              size_t len, int *end_stream)
{
  size_t available;
  size_t read_len;

  assert (stream);
  assert (buf || len == 0);
  assert (end_stream);

  available = SocketBuf_available (stream->recv_buf);
  if (available == 0)
    {
      *end_stream = stream->end_stream_received;
      return 0;
    }

  read_len = available;
  if (read_len > len)
    read_len = len;

  SocketBuf_read (stream->recv_buf, buf, read_len);

  *end_stream = (stream->end_stream_received
                 && SocketBuf_available (stream->recv_buf) == 0);

  return (ssize_t)read_len;
}

int
SocketHTTP2_Stream_recv_trailers (SocketHTTP2_Stream_T stream,
                                  SocketHPACK_Header *trailers,
                                  size_t max_trailers, size_t *trailer_count)
{
  assert (stream);
  assert (trailers || max_trailers == 0);
  assert (trailer_count);

  /* Suppress unused parameter warnings - these will be used
   * when full trailer storage is implemented */
  (void)trailers;
  (void)max_trailers;

  if (!stream->trailers_received)
    {
      *trailer_count = 0;
      return 0;
    }

  *trailer_count = 0;
  return 1;
}

/* ============================================================================
 * Server Push
 * ============================================================================ */

SocketHTTP2_Stream_T
SocketHTTP2_Stream_push_promise (SocketHTTP2_Stream_T stream,
                                 const SocketHPACK_Header *request_headers,
                                 size_t header_count)
{
  SocketHTTP2_Conn_T conn;
  SocketHTTP2_Stream_T pushed;
  SocketHTTP2_FrameHeader frame_header;
  unsigned char *payload;
  ssize_t header_block_len;
  size_t payload_len;
  uint32_t promised_id;

  assert (stream);

  conn = stream->conn;

  /* Only server can push */
  if (conn->role != HTTP2_ROLE_SERVER)
    {
      return NULL;
    }

  /* Check if push is enabled */
  if (conn->peer_settings[SETTINGS_IDX_ENABLE_PUSH] == 0)
    {
      return NULL;
    }

  /* Allocate promised stream ID (server uses even IDs) */
  promised_id = conn->next_stream_id;
  conn->next_stream_id += 2;

  /* Create the promised stream */
  pushed = http2_stream_create (conn, promised_id);
  if (!pushed)
    {
      return NULL;
    }
  pushed->state = HTTP2_STREAM_STATE_RESERVED_LOCAL;

  /* Encode headers */
  payload = Arena_alloc (conn->arena, 16 * 1024, __FILE__, __LINE__);
  if (!payload)
    {
      http2_stream_destroy (pushed);
      return NULL;
    }

  /* 4 bytes for promised stream ID */
  payload[0] = (unsigned char)((promised_id >> 24) & 0x7F);
  payload[1] = (unsigned char)((promised_id >> 16) & 0xFF);
  payload[2] = (unsigned char)((promised_id >> 8) & 0xFF);
  payload[3] = (unsigned char)(promised_id & 0xFF);

  header_block_len = http2_encode_headers (conn, request_headers, header_count,
                                           payload + 4, 16 * 1024 - 4);
  if (header_block_len < 0)
    {
      http2_stream_destroy (pushed);
      return NULL;
    }

  payload_len = 4 + (size_t)header_block_len;

  frame_header.length = (uint32_t)payload_len;
  frame_header.type = HTTP2_FRAME_PUSH_PROMISE;
  frame_header.flags = HTTP2_FLAG_END_HEADERS;
  frame_header.stream_id = stream->id;

  if (http2_frame_send (conn, &frame_header, payload, payload_len) < 0)
    {
      http2_stream_destroy (pushed);
      return NULL;
    }

  return pushed;
}

/* ============================================================================
 * Frame Processing - DATA
 * ============================================================================ */

int
http2_process_data (SocketHTTP2_Conn_T conn,
                    const SocketHTTP2_FrameHeader *header,
                    const unsigned char *payload)
{
  SocketHTTP2_Stream_T stream;
  const unsigned char *data;
  size_t data_len;
  uint8_t pad_len = 0;

  stream = http2_stream_lookup (conn, header->stream_id);
  if (!stream)
    {
      /* Stream closed or never existed */
      http2_send_stream_error (conn, header->stream_id, HTTP2_STREAM_CLOSED);
      return 0;
    }

  /* Handle padding */
  data = payload;
  data_len = header->length;

  if (header->flags & HTTP2_FLAG_PADDED)
    {
      if (header->length == 0)
        {
          http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
          return -1;
        }
      pad_len = payload[0];
      if (pad_len >= header->length)
        {
          http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
          return -1;
        }
      data = payload + 1;
      data_len = header->length - 1 - pad_len;
    }

  /* Check state transition */
  SocketHTTP2_ErrorCode error = http2_stream_transition (
      stream, HTTP2_FRAME_DATA, header->flags, 0);
  if (error != HTTP2_NO_ERROR)
    {
      http2_send_stream_error (conn, header->stream_id, error);
      return 0;
    }

  /* Consume flow control */
  if (http2_flow_consume_recv (conn, stream, header->length) < 0)
    {
      http2_send_connection_error (conn, HTTP2_FLOW_CONTROL_ERROR);
      return -1;
    }

  /* Write to stream buffer */
  SocketBuf_write (stream->recv_buf, data, data_len);

  if (header->flags & HTTP2_FLAG_END_STREAM)
    {
      stream->end_stream_received = 1;
    }

  http2_emit_stream_event (conn, stream, HTTP2_EVENT_DATA_RECEIVED);

  /* Auto window update if buffer is being consumed */
  /* This could be made configurable */

  return 0;
}

/* ============================================================================
 * Frame Processing - HEADERS
 * ============================================================================ */

int
http2_process_headers (SocketHTTP2_Conn_T conn,
                       const SocketHTTP2_FrameHeader *header,
                       const unsigned char *payload)
{
  SocketHTTP2_Stream_T stream;
  const unsigned char *header_block;
  size_t header_block_len;
  uint8_t pad_len = 0;
  size_t offset = 0;

  /* Find or create stream */
  stream = http2_stream_lookup (conn, header->stream_id);
  if (!stream)
    {
      /* New stream from peer */
      if (conn->role == HTTP2_ROLE_SERVER)
        {
          /* Client initiated stream (odd ID) */
          if ((header->stream_id & 1) == 0)
            {
              http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
              return -1;
            }
        }
      else
        {
          /* Server initiated stream (even ID) - only via PUSH_PROMISE */
          http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
          return -1;
        }

      stream = http2_stream_create (conn, header->stream_id);
      if (!stream)
        {
          http2_send_stream_error (conn, header->stream_id, HTTP2_REFUSED_STREAM);
          return 0;
        }

      /* Update last peer stream ID */
      if (header->stream_id > conn->last_peer_stream_id)
        {
          conn->last_peer_stream_id = header->stream_id;
        }
    }

  /* Check state transition */
  SocketHTTP2_ErrorCode error = http2_stream_transition (
      stream, HTTP2_FRAME_HEADERS, header->flags, 0);
  if (error != HTTP2_NO_ERROR)
    {
      http2_send_stream_error (conn, header->stream_id, error);
      return 0;
    }

  /* Handle padding and priority */
  if (header->flags & HTTP2_FLAG_PADDED)
    {
      if (header->length == 0)
        {
          http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
          return -1;
        }
      pad_len = payload[0];
      offset = 1;
    }

  if (header->flags & HTTP2_FLAG_PRIORITY)
    {
      /* Skip 5-byte priority data (deprecated) */
      offset += 5;
    }

  if (offset + pad_len > header->length)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  header_block = payload + offset;
  header_block_len = header->length - offset - pad_len;

  if (header->flags & HTTP2_FLAG_END_HEADERS)
    {
      /* Complete header block */
      if (http2_decode_headers (conn, stream, header_block, header_block_len) < 0)
        {
          return -1;
        }

      stream->headers_received = 1;

      if (header->flags & HTTP2_FLAG_END_STREAM)
        {
          stream->end_stream_received = 1;
        }

      http2_emit_stream_event (conn, stream, HTTP2_EVENT_HEADERS_RECEIVED);
    }
  else
    {
      /* Need CONTINUATION frames */
      stream->header_block = Arena_alloc (conn->arena, header_block_len + 16 * 1024,
                                          __FILE__, __LINE__);
      if (!stream->header_block)
        {
          http2_send_connection_error (conn, HTTP2_INTERNAL_ERROR);
          return -1;
        }
      memcpy (stream->header_block, header_block, header_block_len);
      stream->header_block_len = header_block_len;
      stream->header_block_capacity = header_block_len + 16 * 1024;

      conn->expecting_continuation = 1;
      conn->continuation_stream_id = header->stream_id;
    }

  return 0;
}

/* ============================================================================
 * Frame Processing - CONTINUATION
 * ============================================================================ */

int
http2_process_continuation (SocketHTTP2_Conn_T conn,
                            const SocketHTTP2_FrameHeader *header,
                            const unsigned char *payload)
{
  SocketHTTP2_Stream_T stream;

  stream = http2_stream_lookup (conn, header->stream_id);
  if (!stream || !stream->header_block)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  /* Append to header block */
  if (stream->header_block_len + header->length > stream->header_block_capacity)
    {
      /* Need to reallocate - use arena */
      unsigned char *new_block = Arena_alloc (
          conn->arena, stream->header_block_capacity + header->length + 16 * 1024,
          __FILE__, __LINE__);
      if (!new_block)
        {
          http2_send_connection_error (conn, HTTP2_INTERNAL_ERROR);
          return -1;
        }
      memcpy (new_block, stream->header_block, stream->header_block_len);
      stream->header_block = new_block;
      stream->header_block_capacity += header->length + 16 * 1024;
    }

  memcpy (stream->header_block + stream->header_block_len, payload, header->length);
  stream->header_block_len += header->length;

  if (header->flags & HTTP2_FLAG_END_HEADERS)
    {
      /* Complete header block */
      conn->expecting_continuation = 0;
      conn->continuation_stream_id = 0;

      if (http2_decode_headers (conn, stream, stream->header_block,
                                stream->header_block_len)
          < 0)
        {
          return -1;
        }

      stream->header_block = NULL;
      stream->header_block_len = 0;
      stream->header_block_capacity = 0;
      stream->headers_received = 1;

      http2_emit_stream_event (conn, stream, HTTP2_EVENT_HEADERS_RECEIVED);
    }

  return 0;
}

/* ============================================================================
 * Frame Processing - PUSH_PROMISE
 * ============================================================================ */

int
http2_process_push_promise (SocketHTTP2_Conn_T conn,
                            const SocketHTTP2_FrameHeader *header,
                            const unsigned char *payload)
{
  SocketHTTP2_Stream_T stream;
  SocketHTTP2_Stream_T promised;
  uint32_t promised_id;
  const unsigned char *header_block;
  size_t header_block_len;
  uint8_t pad_len = 0;
  size_t offset = 0;

  /* Only clients receive PUSH_PROMISE */
  if (conn->role != HTTP2_ROLE_CLIENT)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  /* Check if push is enabled */
  if (conn->local_settings[SETTINGS_IDX_ENABLE_PUSH] == 0)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  stream = http2_stream_lookup (conn, header->stream_id);
  if (!stream)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  /* Handle padding */
  if (header->flags & HTTP2_FLAG_PADDED)
    {
      if (header->length < 5)
        {
          http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
          return -1;
        }
      pad_len = payload[0];
      offset = 1;
    }

  /* Parse promised stream ID */
  if (header->length < offset + 4 + pad_len)
    {
      http2_send_connection_error (conn, HTTP2_FRAME_SIZE_ERROR);
      return -1;
    }

  promised_id = ((uint32_t)(payload[offset] & 0x7F) << 24)
                | ((uint32_t)payload[offset + 1] << 16)
                | ((uint32_t)payload[offset + 2] << 8)
                | payload[offset + 3];
  offset += 4;

  /* Promised stream ID must be even (server-initiated) */
  if ((promised_id & 1) != 0)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  /* Create promised stream */
  promised = http2_stream_create (conn, promised_id);
  if (!promised)
    {
      /* Refuse the push */
      http2_send_stream_error (conn, promised_id, HTTP2_REFUSED_STREAM);
      return 0;
    }
  promised->state = HTTP2_STREAM_STATE_RESERVED_REMOTE;

  header_block = payload + offset;
  header_block_len = header->length - offset - pad_len;

  if (header->flags & HTTP2_FLAG_END_HEADERS)
    {
      if (http2_decode_headers (conn, promised, header_block, header_block_len) < 0)
        {
          return -1;
        }
      http2_emit_stream_event (conn, promised, HTTP2_EVENT_PUSH_PROMISE);
    }
  else
    {
      /* Need CONTINUATION */
      promised->header_block = Arena_alloc (conn->arena, header_block_len + 16 * 1024,
                                            __FILE__, __LINE__);
      if (!promised->header_block)
        {
          http2_send_connection_error (conn, HTTP2_INTERNAL_ERROR);
          return -1;
        }
      memcpy (promised->header_block, header_block, header_block_len);
      promised->header_block_len = header_block_len;
      promised->header_block_capacity = header_block_len + 16 * 1024;

      conn->expecting_continuation = 1;
      conn->continuation_stream_id = promised_id;
    }

  return 0;
}


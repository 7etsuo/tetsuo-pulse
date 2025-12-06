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
#include "core/SocketConfig.h"


/* ============================================================================
 * Module Log Component
 * ============================================================================ */

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTP2"

/* ============================================================================
 * Module Exception
 * ============================================================================ */

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTP2);

/* ============================================================================
 * Module Constants
 * ============================================================================ */

/** Default stream receive buffer size */
#define HTTP2_STREAM_RECV_BUF_SIZE SOCKETHTTP2_DEFAULT_STREAM_RECV_BUF_SIZE

/** Initial header block allocation size */
#define HTTP2_INITIAL_HEADER_BLOCK_SIZE SOCKETHTTP2_DEFAULT_INITIAL_HEADER_BLOCK_SIZE

/** Maximum decoded headers per block */
#define HTTP2_MAX_DECODED_HEADERS SOCKETHTTP2_MAX_DECODED_HEADERS

/** Maximum stream ID (2^31 - 1) */
#define HTTP2_MAX_STREAM_ID 0x7FFFFFFF



/* ============================================================================
 * 31-bit serialization helpers (stream ID and window sizes)
 * ============================================================================ */

/**
 * http2_serialize_31bit_uint - Serialize 31-bit unsigned integer
 * @value: Value to serialize (high bit must be 0 for stream IDs)
 * @payload: Output buffer (4 bytes)
 *
 * Thread-safe: Yes
 */
static void
http2_serialize_31bit_uint (uint32_t value, unsigned char *payload)
{
  payload[0] = (unsigned char)((value >> 24) & 0x7F);
  payload[1] = (unsigned char)((value >> 16) & 0xFF);
  payload[2] = (unsigned char)((value >> 8) & 0xFF);
  payload[3] = (unsigned char)(value & 0xFF);
}

/**
 * http2_deserialize_31bit_uint - Deserialize 31-bit unsigned integer
 * @payload: Input buffer
 * @offset: Byte offset in payload
 *
 * Returns: Deserialized value
 * Thread-safe: Yes
 */
static uint32_t
http2_deserialize_31bit_uint (const unsigned char *payload, size_t offset)
{
  return ((uint32_t)(payload[offset] & 0x7F) << 24)
         | ((uint32_t)payload[offset + 1] << 16)
         | ((uint32_t)payload[offset + 2] << 8) | payload[offset + 3];
}

static inline int
http2_is_end_stream (uint8_t flags)
{
  return (flags & HTTP2_FLAG_END_STREAM) != 0;
}

/**
 * http2_extract_padded - Extract padding information from frame
 * @header: Frame header
 * @payload: Frame payload
 * @extra_offset: Output - bytes consumed by padding field and optional fields
 * @pad_len: Output - padding length
 *
 * Common logic for PADDED frames (DATA, HEADERS, PUSH_PROMISE).
 * Handles validation of padding length and frame size.
 *
 * Returns: 0 on success, -1 on protocol error
 */
static int
http2_extract_padded (const SocketHTTP2_FrameHeader *header,
                      const unsigned char *payload,
                      size_t *extra_offset, uint8_t *pad_len)
{
  *pad_len = 0;
  *extra_offset = 0;

  if (header->flags & HTTP2_FLAG_PADDED)
    {
      if (header->length == 0)
        return -1;

      *pad_len = payload[0];
      if (*pad_len >= header->length)
        return -1;

      *extra_offset = 1;
    }

  return 0;
}


/* ============================================================================
 * Stream Lookup (O(1) using hash table)
 * ============================================================================ */

SocketHTTP2_Stream_T
http2_stream_lookup (const SocketHTTP2_Conn_T conn, uint32_t stream_id)
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
 * Stream Creation Helpers
 * ============================================================================ */

/**
 * init_stream_fields - Initialize stream structure fields
 * @stream: Stream to initialize
 * @conn: Parent connection
 * @stream_id: Stream identifier
 */
static void
init_stream_fields (SocketHTTP2_Stream_T stream, const SocketHTTP2_Conn_T conn,
                    uint32_t stream_id)
{
  stream->id = stream_id;
  stream->state = HTTP2_STREAM_STATE_IDLE;
  stream->conn = conn;
  stream->send_window = conn->initial_send_window;
  stream->recv_window = conn->initial_recv_window;
}

/**
 * add_stream_to_hash - Add stream to connection's hash table
 * @conn: Connection
 * @stream: Stream to add
 */
static void
add_stream_to_hash (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream)
{
  unsigned idx = socket_util_hash_uint (stream->id, HTTP2_STREAM_HASH_SIZE);
  stream->hash_next = conn->streams[idx];
  conn->streams[idx] = stream;
  conn->stream_count++;
}

/**
 * remove_stream_from_hash - Remove stream from hash table
 * @conn: Connection
 * @stream: Stream to remove
 */
static void
remove_stream_from_hash (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream)
{
  unsigned idx = socket_util_hash_uint (stream->id, HTTP2_STREAM_HASH_SIZE);
  SocketHTTP2_Stream_T *prev = &conn->streams[idx];

  while (*prev)
    {
      if (*prev == stream)
        {
          *prev = stream->hash_next;
          conn->stream_count--;
          return;
        }
      prev = &(*prev)->hash_next;
    }
}

/* ============================================================================
 * Stream Lifecycle
 * ============================================================================ */

SocketHTTP2_Stream_T
http2_stream_create (SocketHTTP2_Conn_T conn, uint32_t stream_id)
{
  SocketHTTP2_Stream_T stream;

  assert (conn);
  assert (stream_id > 0);

  if (conn->stream_count
      >= conn->local_settings[SETTINGS_IDX_MAX_CONCURRENT_STREAMS])
    return NULL;

  stream = Arena_calloc (conn->arena, 1, sizeof (struct SocketHTTP2_Stream), __FILE__, __LINE__);
  if (!stream)
    {
      SOCKET_LOG_ERROR_MSG ("failed to allocate HTTP/2 stream");
      return NULL;
    }
  init_stream_fields (stream, conn, stream_id);

  stream->recv_buf = SocketBuf_new (conn->arena, HTTP2_STREAM_RECV_BUF_SIZE);
  if (!stream->recv_buf)
    {
      SOCKET_LOG_ERROR_MSG ("failed to allocate recv buffer for HTTP/2 stream");
      http2_stream_destroy (stream);  /* partial, clean */
      return NULL;
    }

  add_stream_to_hash (conn, stream);
  return stream;
}

void
http2_stream_destroy (SocketHTTP2_Stream_T stream)
{
  if (!stream)
    return;

  remove_stream_from_hash (stream->conn, stream);

  if (stream->recv_buf)
    SocketBuf_release (&stream->recv_buf);
}

/* ============================================================================
 * Stream State Machine - Transition Helpers
 * ============================================================================ */

/**
 * transition_from_idle - Handle state transition from IDLE
 * @stream: Stream
 * @frame_type: Frame type
 * @flags: Frame flags
 * @is_send: 1 if sending, 0 if receiving
 * @new_state: Output - new state
 *
 * Returns: HTTP2_NO_ERROR on success, error code otherwise
 */
static SocketHTTP2_ErrorCode
transition_from_idle (uint8_t frame_type,
                      uint8_t flags, int is_send,
                      SocketHTTP2_StreamState *new_state)
{
  int end_stream = http2_is_end_stream (flags);

  if (frame_type == HTTP2_FRAME_HEADERS)
    {
      if (is_send)
        *new_state = end_stream ? HTTP2_STREAM_STATE_HALF_CLOSED_LOCAL
                                : HTTP2_STREAM_STATE_OPEN;
      else
        *new_state = end_stream ? HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE
                                : HTTP2_STREAM_STATE_OPEN;
      return HTTP2_NO_ERROR;
    }

  if (frame_type == HTTP2_FRAME_PUSH_PROMISE)
    {
      *new_state = is_send ? HTTP2_STREAM_STATE_RESERVED_LOCAL
                           : HTTP2_STREAM_STATE_RESERVED_REMOTE;
      return HTTP2_NO_ERROR;
    }

  if (frame_type == HTTP2_FRAME_PRIORITY)
    {
      *new_state = HTTP2_STREAM_STATE_IDLE;
      return HTTP2_NO_ERROR;
    }

  return HTTP2_PROTOCOL_ERROR;
}

/**
 * transition_from_reserved_local - Handle transition from RESERVED_LOCAL
 */
static SocketHTTP2_ErrorCode
transition_from_reserved_local (uint8_t frame_type, int is_send,
                                SocketHTTP2_StreamState *new_state)
{
  if (is_send && frame_type == HTTP2_FRAME_HEADERS)
    {
      *new_state = HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE;
      return HTTP2_NO_ERROR;
    }

  if (frame_type == HTTP2_FRAME_RST_STREAM)
    {
      *new_state = HTTP2_STREAM_STATE_CLOSED;
      return HTTP2_NO_ERROR;
    }

  if (frame_type == HTTP2_FRAME_PRIORITY)
    return HTTP2_NO_ERROR;

  if (frame_type == HTTP2_FRAME_WINDOW_UPDATE && is_send)
    return HTTP2_NO_ERROR;

  return HTTP2_PROTOCOL_ERROR;
}

/**
 * transition_from_reserved_remote - Handle transition from RESERVED_REMOTE
 */
static SocketHTTP2_ErrorCode
transition_from_reserved_remote (uint8_t frame_type, int is_send,
                                 SocketHTTP2_StreamState *new_state)
{
  if (!is_send && frame_type == HTTP2_FRAME_HEADERS)
    {
      *new_state = HTTP2_STREAM_STATE_HALF_CLOSED_LOCAL;
      return HTTP2_NO_ERROR;
    }

  if (frame_type == HTTP2_FRAME_RST_STREAM)
    {
      *new_state = HTTP2_STREAM_STATE_CLOSED;
      return HTTP2_NO_ERROR;
    }

  if (frame_type == HTTP2_FRAME_PRIORITY)
    return HTTP2_NO_ERROR;

  if (frame_type == HTTP2_FRAME_WINDOW_UPDATE && !is_send)
    return HTTP2_NO_ERROR;

  return HTTP2_PROTOCOL_ERROR;
}

/**
 * transition_from_open - Handle transition from OPEN
 */
static SocketHTTP2_ErrorCode
transition_from_open (uint8_t frame_type, uint8_t flags, int is_send,
                      SocketHTTP2_StreamState *new_state)
{
  int end_stream = http2_is_end_stream (flags);

  if (frame_type == HTTP2_FRAME_RST_STREAM)
    {
      *new_state = HTTP2_STREAM_STATE_CLOSED;
      return HTTP2_NO_ERROR;
    }

  if (end_stream)
    {
      *new_state = is_send ? HTTP2_STREAM_STATE_HALF_CLOSED_LOCAL
                           : HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE;
    }

  return HTTP2_NO_ERROR;
}

/**
 * transition_from_half_closed_local - Handle transition from HALF_CLOSED_LOCAL
 */
static SocketHTTP2_ErrorCode
transition_from_half_closed_local (uint8_t frame_type, uint8_t flags,
                                   int is_send,
                                   SocketHTTP2_StreamState *new_state)
{
  int end_stream = http2_is_end_stream (flags);

  if (!is_send)
    {
      if (frame_type == HTTP2_FRAME_RST_STREAM || end_stream)
        {
          *new_state = HTTP2_STREAM_STATE_CLOSED;
          return HTTP2_NO_ERROR;
        }
      return HTTP2_NO_ERROR;
    }

  if (frame_type == HTTP2_FRAME_RST_STREAM)
    {
      *new_state = HTTP2_STREAM_STATE_CLOSED;
      return HTTP2_NO_ERROR;
    }

  if (frame_type == HTTP2_FRAME_WINDOW_UPDATE
      || frame_type == HTTP2_FRAME_PRIORITY)
    return HTTP2_NO_ERROR;

  return HTTP2_STREAM_CLOSED;
}

/**
 * transition_from_half_closed_remote - Handle transition from
 * HALF_CLOSED_REMOTE
 */
static SocketHTTP2_ErrorCode
transition_from_half_closed_remote (uint8_t frame_type, uint8_t flags,
                                    int is_send,
                                    SocketHTTP2_StreamState *new_state)
{
  int end_stream = http2_is_end_stream (flags);

  if (is_send)
    {
      if (frame_type == HTTP2_FRAME_RST_STREAM || end_stream)
        {
          *new_state = HTTP2_STREAM_STATE_CLOSED;
          return HTTP2_NO_ERROR;
        }
      return HTTP2_NO_ERROR;
    }

  if (frame_type == HTTP2_FRAME_RST_STREAM)
    {
      *new_state = HTTP2_STREAM_STATE_CLOSED;
      return HTTP2_NO_ERROR;
    }

  if (frame_type == HTTP2_FRAME_WINDOW_UPDATE
      || frame_type == HTTP2_FRAME_PRIORITY)
    return HTTP2_NO_ERROR;

  return HTTP2_STREAM_CLOSED;
}

/**
 * transition_from_closed - Handle transition from CLOSED
 */
static SocketHTTP2_ErrorCode
transition_from_closed (uint8_t frame_type, int is_send)
{
  if (frame_type == HTTP2_FRAME_PRIORITY)
    return HTTP2_NO_ERROR;

  if (!is_send
      && (frame_type == HTTP2_FRAME_WINDOW_UPDATE
          || frame_type == HTTP2_FRAME_RST_STREAM))
    return HTTP2_NO_ERROR;

  return HTTP2_STREAM_CLOSED;
}

/* ============================================================================
 * Stream State Machine (RFC 9113 Section 5.1)
 * ============================================================================ */

SocketHTTP2_ErrorCode
http2_stream_transition (SocketHTTP2_Stream_T stream, uint8_t frame_type,
                         uint8_t flags, int is_send)
{
  SocketHTTP2_StreamState new_state = stream->state;
  SocketHTTP2_ErrorCode error = HTTP2_NO_ERROR;

  switch (stream->state)
    {
    case HTTP2_STREAM_STATE_IDLE:
      error = transition_from_idle (frame_type, flags, is_send,
                                    &new_state);
      break;

    case HTTP2_STREAM_STATE_RESERVED_LOCAL:
      error = transition_from_reserved_local (frame_type, is_send, &new_state);
      break;

    case HTTP2_STREAM_STATE_RESERVED_REMOTE:
      error
          = transition_from_reserved_remote (frame_type, is_send, &new_state);
      break;

    case HTTP2_STREAM_STATE_OPEN:
      error = transition_from_open (frame_type, flags, is_send, &new_state);
      break;

    case HTTP2_STREAM_STATE_HALF_CLOSED_LOCAL:
      error = transition_from_half_closed_local (frame_type, flags, is_send,
                                                 &new_state);
      break;

    case HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE:
      error = transition_from_half_closed_remote (frame_type, flags, is_send,
                                                  &new_state);
      break;

    case HTTP2_STREAM_STATE_CLOSED:
      error = transition_from_closed (frame_type, is_send);
      break;
    }

  if (error == HTTP2_NO_ERROR)
    stream->state = new_state;

  return error;
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

  if (conn->goaway_received)
    return NULL;

  stream_id = conn->next_stream_id;
  if (stream_id > HTTP2_MAX_STREAM_ID)
    return NULL;

  stream = http2_stream_create (conn, stream_id);
  if (!stream)
    return NULL;

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

/**
 * serialize_window_update_payload - Serialize WINDOW_UPDATE payload
 * @increment: Window increment
 * @payload: Output buffer (4 bytes)
 */
static void
serialize_window_update_payload (uint32_t increment, unsigned char *payload)
{
  http2_serialize_31bit_uint (increment, payload);
}

int
SocketHTTP2_Stream_window_update (SocketHTTP2_Stream_T stream,
                                  uint32_t increment)
{
  SocketHTTP2_FrameHeader header;
  unsigned char payload[HTTP2_WINDOW_UPDATE_PAYLOAD_SIZE];

  assert (stream);
  assert (increment > 0 && increment <= HTTP2_MAX_STREAM_ID);

  serialize_window_update_payload (increment, payload);

  header.length = HTTP2_WINDOW_UPDATE_PAYLOAD_SIZE;
  header.type = HTTP2_FRAME_WINDOW_UPDATE;
  header.flags = 0;
  header.stream_id = stream->id;

  return http2_frame_send (stream->conn, &header, payload, HTTP2_WINDOW_UPDATE_PAYLOAD_SIZE);
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
http2_encode_headers (SocketHTTP2_Conn_T conn,
                      const SocketHPACK_Header *headers, size_t count,
                      unsigned char *output, size_t output_size)
{
  return SocketHPACK_Encoder_encode (conn->encoder, headers, count, output,
                                     output_size);
}

/**
 * http2_encode_and_alloc_block - Encode headers and allocate block
 * @conn: Connection
 * @headers: Headers to encode
 * @count: Number of headers
 * @block_out: Output - allocated block
 *
 * Allocates block using arena, encodes, returns length or -1 on error
 * Caller must not free block (arena managed)
 *
 * Returns: Encoded length or -1 on error
 * Thread-safe: No
 */
static unsigned char *
alloc_header_block (SocketHTTP2_Conn_T conn, size_t initial_size);

static ssize_t
http2_encode_and_alloc_block (SocketHTTP2_Conn_T conn,
                              const SocketHPACK_Header *headers, size_t count,
                              unsigned char **block_out)
{
  size_t initial_size = HTTP2_INITIAL_HEADER_BLOCK_SIZE;
  *block_out = alloc_header_block (conn, initial_size);
  if (!*block_out)
    return -1;

  ssize_t len = http2_encode_headers (conn, headers, count, *block_out, initial_size);
  if (len < 0)
    return -1;

  return len;
}

int
http2_decode_headers (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                      const unsigned char *block, size_t len)
{
  SocketHPACK_Header decoded_headers[HTTP2_MAX_DECODED_HEADERS];
  size_t header_count = 0;
  SocketHPACK_Result result;

  result = SocketHPACK_Decoder_decode (conn->decoder, block, len,
                                       decoded_headers, HTTP2_MAX_DECODED_HEADERS,
                                       &header_count, conn->arena);

  if (result != HPACK_OK)
    {
      http2_send_connection_error (conn, HTTP2_COMPRESSION_ERROR);
      return -1;
    }

  /* Store decoded headers based on whether this is initial headers or trailers */
  if (!stream->headers_received)
    {
      if (header_count > HTTP2_MAX_DECODED_HEADERS)
        {
          http2_send_connection_error (conn, HTTP2_COMPRESSION_ERROR);
          return -1;
        }
      memcpy (stream->headers, decoded_headers, header_count * sizeof (SocketHPACK_Header));
      stream->header_count = header_count;
      stream->headers_consumed = 0;
    }
  else
    {
      if (header_count > HTTP2_MAX_DECODED_HEADERS)
        {
          http2_send_connection_error (conn, HTTP2_COMPRESSION_ERROR);
          return -1;
        }
      memcpy (stream->trailers, decoded_headers, header_count * sizeof (SocketHPACK_Header));
      stream->trailer_count = header_count;
      stream->trailers_consumed = 0;
      stream->trailers_received = 1;
    }

  return 0;
}

/* ============================================================================
 * Header Block Buffer Management
 * ============================================================================ */

/**
 * alloc_header_block - Allocate header block buffer
 * @conn: Connection
 * @initial_size: Initial size
 *
 * Returns: Allocated buffer or NULL
 */
static unsigned char *
alloc_header_block (SocketHTTP2_Conn_T conn, size_t initial_size)
{
  return Arena_alloc (conn->arena, initial_size, __FILE__, __LINE__);
}

/**
 * grow_header_block - Grow header block buffer
 * @conn: Connection
 * @stream: Stream with header block
 * @needed: Additional bytes needed
 *
 * Returns: 0 on success, -1 on error
 */
static int
grow_header_block (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                   size_t needed)
{
  size_t new_capacity
      = stream->header_block_capacity + needed + HTTP2_INITIAL_HEADER_BLOCK_SIZE;
  unsigned char *new_block = Arena_alloc (conn->arena, new_capacity, __FILE__,
                                          __LINE__);
  if (!new_block)
    return -1;

  memcpy (new_block, stream->header_block, stream->header_block_len);
  stream->header_block = new_block;
  stream->header_block_capacity = new_capacity;
  return 0;
}

/**
 * init_pending_header_block - Initialize pending header block for CONTINUATION
 * @conn: Connection
 * @stream: Stream
 * @data: Initial header data
 * @len: Data length
 *
 * Returns: 0 on success, -1 on error
 */
static int
init_pending_header_block (SocketHTTP2_Conn_T conn,
                           SocketHTTP2_Stream_T stream,
                           const unsigned char *data, size_t len)
{
  size_t capacity = len + HTTP2_INITIAL_HEADER_BLOCK_SIZE;
  stream->header_block = alloc_header_block (conn, capacity);
  if (!stream->header_block)
    return -1;

  memcpy (stream->header_block, data, len);
  stream->header_block_len = len;
  stream->header_block_capacity = capacity;
  return 0;
}

/**
 * clear_pending_header_block - Clear pending header block state
 * @stream: Stream
 */
static void
clear_pending_header_block (SocketHTTP2_Stream_T stream)
{
  stream->header_block = NULL;
  stream->header_block_len = 0;
  stream->header_block_capacity = 0;
}

/* ============================================================================
 * Sending Headers - Helpers
 * ============================================================================ */

/**
 * send_single_headers_frame - Send complete headers in single frame
 * @conn: Connection
 * @stream: Stream
 * @header_block: Encoded header block
 * @block_len: Block length
 * @end_stream: END_STREAM flag
 *
 * Returns: 0 on success, -1 on error
 */
static int
send_single_headers_frame (SocketHTTP2_Conn_T conn,
                           SocketHTTP2_Stream_T stream,
                           const unsigned char *header_block, size_t block_len,
                           int end_stream)
{
  SocketHTTP2_FrameHeader frame_header;

  frame_header.length = (uint32_t)block_len;
  frame_header.type = HTTP2_FRAME_HEADERS;
  frame_header.flags
      = HTTP2_FLAG_END_HEADERS | (end_stream ? HTTP2_FLAG_END_STREAM : 0);
  frame_header.stream_id = stream->id;

  return http2_frame_send (conn, &frame_header, header_block, block_len);
}

/**
 * send_headers_chunk - Send single chunk of headers/CONTINUATION frame
 * @conn: Connection
 * @stream: Stream
 * @data: Data to send
 * @chunk_len: Chunk length
 * @first: 1 if first chunk (HEADERS frame)
 * @last: 1 if last chunk (END_HEADERS flag)
 * @end_stream: Set END_STREAM if first chunk
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
static int
send_headers_chunk (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                    const unsigned char *data, size_t chunk_len,
                    int first, int last, int end_stream)
{
  SocketHTTP2_FrameHeader frame_header;

  frame_header.length = (uint32_t)chunk_len;
  frame_header.type = first ? HTTP2_FRAME_HEADERS : HTTP2_FRAME_CONTINUATION;
  frame_header.flags = 0;
  if (first && end_stream)
    frame_header.flags |= HTTP2_FLAG_END_STREAM;
  if (last)
    frame_header.flags |= HTTP2_FLAG_END_HEADERS;
  frame_header.stream_id = stream->id;

  return http2_frame_send (conn, &frame_header, data, chunk_len);
}

/**
 * send_fragmented_headers - Send headers with CONTINUATION frames
 * @conn: Connection
 * @stream: Stream
 * @header_block: Encoded header block
 * @block_len: Block length
 * @max_frame_size: Maximum frame payload size
 * @end_stream: END_STREAM flag
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
static int
send_fragmented_headers (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                         const unsigned char *header_block, size_t block_len,
                         uint32_t max_frame_size, int end_stream)
{
  size_t offset = 0;
  int first = 1;

  while (offset < block_len)
    {
      size_t chunk_len = block_len - offset;
      if (chunk_len > max_frame_size)
        chunk_len = max_frame_size;
      int is_last = (offset + chunk_len >= block_len);

      if (send_headers_chunk (conn, stream, header_block + offset, chunk_len,
                              first, is_last, end_stream) < 0)
        return -1;

      offset += chunk_len;
      first = 0;
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
  SocketHTTP2_ErrorCode error;

  assert (stream);
  assert (headers || header_count == 0);

  conn = stream->conn;

  error = http2_stream_transition (stream, HTTP2_FRAME_HEADERS,
                                   end_stream ? HTTP2_FLAG_END_STREAM : 0, 1);
  if (error != HTTP2_NO_ERROR)
    return -1;

  unsigned char *header_block;
  ssize_t block_len_ssize = http2_encode_and_alloc_block (conn, headers, header_count, &header_block);
  if (block_len_ssize < 0)
    return -1;
  size_t block_len = (size_t)block_len_ssize;

  uint32_t max_frame_size = conn->peer_settings[SETTINGS_IDX_MAX_FRAME_SIZE];

  if ((size_t)block_len <= max_frame_size)
    {
      if (send_single_headers_frame (conn, stream, header_block,
                                     (size_t)block_len, end_stream)
          < 0)
        return -1;
    }
  else
    {
      if (send_fragmented_headers (conn, stream, header_block,
                                   (size_t)block_len, max_frame_size,
                                   end_stream)
          < 0)
        return -1;
    }

  if (end_stream)
    stream->end_stream_sent = 1;

  return 0;
}

/* ============================================================================
 * Request/Response Header Building
 * ============================================================================ */

/**
 * build_request_pseudo_headers - Build pseudo-headers for HTTP/2 request
 * @request: HTTP request
 * @pseudo: Output array (4 elements)
 */
static void
build_request_pseudo_headers (const SocketHTTP_Request *request,
                              SocketHPACK_Header *pseudo)
{
  pseudo[0].name = ":method";
  pseudo[0].name_len = 7;
  pseudo[0].value = SocketHTTP_method_name (request->method);
  pseudo[0].value_len = strlen (pseudo[0].value);
  pseudo[0].never_index = 0;

  pseudo[1].name = ":scheme";
  pseudo[1].name_len = 7;
  pseudo[1].value = request->scheme ? request->scheme : "https";
  pseudo[1].value_len = strlen (pseudo[1].value);
  pseudo[1].never_index = 0;

  pseudo[2].name = ":authority";
  pseudo[2].name_len = 10;
  pseudo[2].value = request->authority ? request->authority : "";
  pseudo[2].value_len = strlen (pseudo[2].value);
  pseudo[2].never_index = 0;

  pseudo[3].name = ":path";
  pseudo[3].name_len = 5;
  pseudo[3].value = request->path ? request->path : "/";
  pseudo[3].value_len = strlen (pseudo[3].value);
  pseudo[3].never_index = 0;
}

/**
 * copy_regular_headers - Copy regular headers to HPACK array
 * @src: Source headers collection
 * @dest: Destination HPACK array
 * @offset: Starting offset in dest
 * @count: Number of headers to copy
 */
static void
copy_regular_headers (SocketHTTP_Headers_T src, SocketHPACK_Header *dest,
                      size_t offset, size_t count)
{
  for (size_t i = 0; i < count; i++)
    {
      const SocketHTTP_Header *h = SocketHTTP_Headers_at (src, i);
      dest[offset + i].name = h->name;
      dest[offset + i].name_len = h->name_len;
      dest[offset + i].value = h->value;
      dest[offset + i].value_len = h->value_len;
      dest[offset + i].never_index = 0;
    }
}

int
SocketHTTP2_Stream_send_request (SocketHTTP2_Stream_T stream,
                                 const SocketHTTP_Request *request,
                                 int end_stream)
{
  SocketHPACK_Header pseudo_headers[HTTP2_REQUEST_PSEUDO_HEADER_COUNT];
  SocketHPACK_Header *all_headers;
  size_t header_count, total_count;

  assert (stream);
  assert (request);

  build_request_pseudo_headers (request, pseudo_headers);

  header_count
      = request->headers ? SocketHTTP_Headers_count (request->headers) : 0;
  total_count = HTTP2_REQUEST_PSEUDO_HEADER_COUNT + header_count;

  all_headers = Arena_alloc (stream->conn->arena,
                             total_count * sizeof (SocketHPACK_Header),
                             __FILE__, __LINE__);
  if (!all_headers)
    return -1;

  memcpy (all_headers, pseudo_headers,
          HTTP2_REQUEST_PSEUDO_HEADER_COUNT * sizeof (SocketHPACK_Header));

  if (request->headers)
    copy_regular_headers (request->headers, all_headers,
                          HTTP2_REQUEST_PSEUDO_HEADER_COUNT, header_count);

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
  size_t header_count, total_count;
  char status_buf[16];
  int status_len;

  assert (stream);
  assert (response);

  status_len
      = snprintf (status_buf, sizeof (status_buf), "%d", response->status_code);
  pseudo_header.name = ":status";
  pseudo_header.name_len = 7;
  pseudo_header.value = status_buf;
  pseudo_header.value_len = (size_t)status_len;
  pseudo_header.never_index = 0;

  header_count
      = response->headers ? SocketHTTP_Headers_count (response->headers) : 0;
  total_count = 1 + header_count;

  all_headers = Arena_alloc (stream->conn->arena,
                             total_count * sizeof (SocketHPACK_Header),
                             __FILE__, __LINE__);
  if (!all_headers)
    return -1;

  all_headers[0] = pseudo_header;

  if (response->headers)
    copy_regular_headers (response->headers, all_headers, 1, header_count);

  return SocketHTTP2_Stream_send_headers (stream, all_headers, total_count,
                                          end_stream);
}

int
SocketHTTP2_Stream_send_trailers (SocketHTTP2_Stream_T stream,
                                  const SocketHPACK_Header *trailers,
                                  size_t count)
{
  return SocketHTTP2_Stream_send_headers (stream, trailers, count, 1);
}

/* ============================================================================
 * Sending Data
 * ============================================================================ */

/**
 * calculate_send_length - Calculate actual send length based on flow control
 * @conn: Connection
 * @stream: Stream
 * @requested_len: Requested length
 * @end_stream: Pointer to end_stream flag (may be cleared)
 *
 * Returns: Actual bytes to send (0 if blocked)
 */
static size_t
calculate_send_length (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                       size_t requested_len, int *end_stream)
{
  int32_t available = http2_flow_available_send (conn, stream);
  uint32_t max_frame_size = conn->peer_settings[SETTINGS_IDX_MAX_FRAME_SIZE];
  size_t send_len = requested_len;

  if (available <= 0)
    return 0;

  if (send_len > (size_t)available)
    {
      send_len = (size_t)available;
      *end_stream = 0;
    }

  if (send_len > max_frame_size)
    {
      send_len = max_frame_size;
      *end_stream = 0;
    }

  return send_len;
}

ssize_t
SocketHTTP2_Stream_send_data (SocketHTTP2_Stream_T stream, const void *data,
                              size_t len, int end_stream)
{
  SocketHTTP2_Conn_T conn;
  SocketHTTP2_FrameHeader header;
  SocketHTTP2_ErrorCode error;
  size_t send_len;

  assert (stream);
  assert (data || len == 0);

  conn = stream->conn;

  error = http2_stream_transition (stream, HTTP2_FRAME_DATA,
                                   end_stream ? HTTP2_FLAG_END_STREAM : 0, 1);
  if (error != HTTP2_NO_ERROR)
    return -1;

  send_len = calculate_send_length (conn, stream, len, &end_stream);
  if (send_len == 0)
    return 0;

  http2_flow_consume_send (conn, stream, send_len);

  header.length = (uint32_t)send_len;
  header.type = HTTP2_FRAME_DATA;
  header.flags = end_stream ? HTTP2_FLAG_END_STREAM : 0;
  header.stream_id = stream->id;

  if (http2_frame_send (conn, &header, data, send_len) < 0)
    return -1;

  if (end_stream)
    stream->end_stream_sent = 1;

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

  if (!stream->headers_received || stream->headers_consumed)
    {
      *header_count = 0;
      *end_stream = 0;
      return 0;
    }

  size_t copy_count = (stream->header_count > max_headers) ? max_headers : stream->header_count;
  if (copy_count > 0 && headers != NULL)
    {
      memcpy (headers, stream->headers, copy_count * sizeof (SocketHPACK_Header));
    }
  *header_count = copy_count;
  *end_stream = stream->end_stream_received;
  stream->headers_consumed = 1;
  return 1;
}

ssize_t
SocketHTTP2_Stream_recv_data (SocketHTTP2_Stream_T stream, void *buf,
                              size_t len, int *end_stream)
{
  size_t available, read_len;

  assert (stream);
  assert (buf || len == 0);
  assert (end_stream);

  available = SocketBuf_available (stream->recv_buf);
  if (available == 0)
    {
      *end_stream = stream->end_stream_received;
      return 0;
    }

  read_len = (available > len) ? len : available;
  SocketBuf_read (stream->recv_buf, buf, read_len);

  *end_stream = (stream->end_stream_received
                 && SocketBuf_available (stream->recv_buf) == 0
                 && (!stream->trailers_received || stream->trailers_consumed));

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

  if (!stream->trailers_received || stream->trailers_consumed)
    {
      *trailer_count = 0;
      return 0;
    }

  size_t copy_count = (stream->trailer_count > max_trailers) ? max_trailers : stream->trailer_count;
  if (copy_count > 0 && trailers != NULL)
    {
      memcpy (trailers, stream->trailers, copy_count * sizeof (SocketHPACK_Header));
    }
  *trailer_count = copy_count;
  stream->trailers_consumed = 1;
  return 1;
}

/* ============================================================================
 * Server Push
 * ============================================================================ */

/**
 * serialize_promised_stream_id - Serialize promised stream ID
 * @promised_id: Stream ID
 * @payload: Output buffer (4 bytes)
 */
static void
serialize_promised_stream_id (uint32_t promised_id, unsigned char *payload)
{
  http2_serialize_31bit_uint (promised_id, payload);
}

/**
 * parse_promised_stream_id - Parse promised stream ID from payload
 * @payload: Input buffer
 * @offset: Offset into payload
 *
 * Returns: Stream ID
 */
static uint32_t
parse_promised_stream_id (const unsigned char *payload, size_t offset)
{
  return http2_deserialize_31bit_uint (payload, offset);
}

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

  if (conn->role != HTTP2_ROLE_SERVER)
    return NULL;

  if (conn->peer_settings[SETTINGS_IDX_ENABLE_PUSH] == 0)
    return NULL;

  promised_id = conn->next_stream_id;
  conn->next_stream_id += 2;

  pushed = http2_stream_create (conn, promised_id);
  if (!pushed)
    return NULL;

  pushed->state = HTTP2_STREAM_STATE_RESERVED_LOCAL;

  payload = alloc_header_block (conn, HTTP2_PUSH_PROMISE_ID_SIZE + HTTP2_INITIAL_HEADER_BLOCK_SIZE);
  if (!payload)
    {
      http2_stream_destroy (pushed);
      return NULL;
    }

  serialize_promised_stream_id (promised_id, payload);

  header_block_len = http2_encode_headers (conn, request_headers, header_count,
                                           payload + HTTP2_PUSH_PROMISE_ID_SIZE,
                                           HTTP2_INITIAL_HEADER_BLOCK_SIZE);
  if (header_block_len < 0)
    {
      http2_stream_destroy (pushed);
      return NULL;
    }

  payload_len = HTTP2_PUSH_PROMISE_ID_SIZE + (size_t)header_block_len;

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
 * Frame Processing - Padding Helpers
 * ============================================================================ */

/**
 * PaddedData - Extracted payload data after removing padding
 */
typedef struct
{
  const unsigned char *data;
  size_t len;
} PaddedData;

/**
 * extract_padded_data - Extract payload with padding removed
 * @header: Frame header
 * @payload: Frame payload
 * @result: Output - data pointer and length
 *
 * Returns: 0 on success, -1 on protocol error
 */
static int
extract_padded_data (const SocketHTTP2_FrameHeader *header,
                     const unsigned char *payload, PaddedData *result)
{
  size_t extra = 0;
  uint8_t pad_len = 0;

  if (http2_extract_padded (header, payload, &extra, &pad_len) < 0)
    return -1;

  result->data = payload + extra;
  result->len = header->length - extra - pad_len;

  return 0;
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
  PaddedData padded;
  SocketHTTP2_ErrorCode error;

  stream = http2_stream_lookup (conn, header->stream_id);
  if (!stream)
    {
      http2_send_stream_error (conn, header->stream_id, HTTP2_STREAM_CLOSED);
      return 0;
    }

  if (extract_padded_data (header, payload, &padded) < 0)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  error = http2_stream_transition (stream, HTTP2_FRAME_DATA, header->flags, 0);
  if (error != HTTP2_NO_ERROR)
    {
      http2_send_stream_error (conn, header->stream_id, error);
      return 0;
    }

  if (http2_flow_consume_recv (conn, stream, header->length) < 0)
    {
      http2_send_connection_error (conn, HTTP2_FLOW_CONTROL_ERROR);
      return -1;
    }

  SocketBuf_write (stream->recv_buf, padded.data, padded.len);

  if (header->flags & HTTP2_FLAG_END_STREAM)
    stream->end_stream_received = 1;

  http2_emit_stream_event (conn, stream, HTTP2_EVENT_DATA_RECEIVED);
  return 0;
}

/* ============================================================================
 * Stream Creation for Incoming Frames
 * ============================================================================ */

/**
 * http2_get_or_create_stream_for_headers - Get or create stream for HEADERS frame
 * @conn: Connection
 * @stream_id: Stream ID from frame
 *
 * Looks up existing stream or creates new one if valid new stream ID.
 * Sends appropriate error frames on failure.
 *
 * Returns: Stream pointer or NULL on error (error frame already sent)
 * Note: Caller must check return and handle connection/stream error accordingly.
 */
static int validate_new_stream_id (SocketHTTP2_Conn_T conn, uint32_t stream_id);

static SocketHTTP2_Stream_T
http2_get_or_create_stream_for_headers (SocketHTTP2_Conn_T conn, uint32_t stream_id)
{
  SocketHTTP2_Stream_T stream;

  stream = http2_stream_lookup (conn, stream_id);
  if (!stream)
    {
      if (validate_new_stream_id (conn, stream_id) < 0)
        {
          http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
          return NULL;
        }

      stream = http2_stream_create (conn, stream_id);
      if (!stream)
        {
          http2_send_stream_error (conn, stream_id, HTTP2_REFUSED_STREAM);
          return NULL;
        }

      if (stream_id > conn->last_peer_stream_id)
        conn->last_peer_stream_id = stream_id;
    }

  return stream;
}

/* ============================================================================
 * Frame Processing - HEADERS
 * ============================================================================ */

/**
 * validate_new_stream_id - Validate stream ID for new peer-initiated stream
 * @conn: Connection
 * @stream_id: Stream ID
 *
 * Returns: 0 if valid, -1 on protocol error
 */
static int
validate_new_stream_id (SocketHTTP2_Conn_T conn, uint32_t stream_id)
{
  int expected_parity = (conn->role == HTTP2_ROLE_SERVER) ? 1 : 0;

  if ((stream_id & 1U) != (unsigned int)expected_parity)
    return -1;

  if (stream_id == 0 || stream_id > HTTP2_MAX_STREAM_ID)
    return -1;

  if (stream_id <= conn->last_peer_stream_id)
    return -1;

  return 0;
}

/**
 * extract_headers_payload - Extract header block with padding/priority removed
 * @header: Frame header
 * @payload: Frame payload
 * @block: Output - header block pointer
 * @block_len: Output - header block length
 *
 * Returns: 0 on success, -1 on protocol error
 */
static int
extract_headers_payload (const SocketHTTP2_FrameHeader *header,
                         const unsigned char *payload,
                         const unsigned char **block, size_t *block_len)
{
  size_t extra = 0;
  uint8_t pad_len = 0;

  if (http2_extract_padded (header, payload, &extra, &pad_len) < 0)
    return -1;

  if (header->flags & HTTP2_FLAG_PRIORITY)
    extra += HTTP2_PRIORITY_PAYLOAD_SIZE;

  if (extra + pad_len > header->length)
    return -1;

  *block = payload + extra;
  *block_len = header->length - extra - pad_len;
  return 0;
}

/**
 * process_complete_header_block - Process complete header block
 * @conn: Connection
 * @stream: Stream
 * @block: Header block
 * @len: Block length
 * @end_stream: END_STREAM flag set
 *
 * Returns: 0 on success, -1 on error
 */
static int
process_complete_header_block (SocketHTTP2_Conn_T conn,
                               SocketHTTP2_Stream_T stream,
                               const unsigned char *block, size_t len,
                               int end_stream)
{
  if (http2_decode_headers (conn, stream, block, len) < 0)
    return -1;

  if (!stream->headers_received)
    {
      stream->headers_received = 1;
      http2_emit_stream_event (conn, stream, HTTP2_EVENT_HEADERS_RECEIVED);
    }
  else
    {
      http2_emit_stream_event (conn, stream, HTTP2_EVENT_TRAILERS_RECEIVED);
    }

  if (end_stream)
    stream->end_stream_received = 1;

  return 0;
}

/**
 * setup_continuation_state - Setup state for CONTINUATION frames
 * @conn: Connection
 * @stream: Stream
 * @block: Initial header block
 * @len: Block length
 *
 * Returns: 0 on success, -1 on error
 */
static int
setup_continuation_state (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream,
                          const unsigned char *block, size_t len)
{
  if (init_pending_header_block (conn, stream, block, len) < 0)
    {
      http2_send_connection_error (conn, HTTP2_INTERNAL_ERROR);
      return -1;
    }

  conn->expecting_continuation = 1;
  conn->continuation_stream_id = stream->id;
  return 0;
}

int
http2_process_headers (SocketHTTP2_Conn_T conn,
                       const SocketHTTP2_FrameHeader *header,
                       const unsigned char *payload)
{
  SocketHTTP2_Stream_T stream;
  const unsigned char *header_block;
  size_t header_block_len, max_header_list;
  SocketHTTP2_ErrorCode error;

  stream = http2_get_or_create_stream_for_headers (conn, header->stream_id);
  if (!stream)
    {
      /* Error frame sent by helper */
      return -1;
    }

  error
      = http2_stream_transition (stream, HTTP2_FRAME_HEADERS, header->flags, 0);
  if (error != HTTP2_NO_ERROR)
    {
      http2_send_stream_error (conn, header->stream_id, error);
      return 0;
    }

  if (extract_headers_payload (header, payload, &header_block, &header_block_len)
      < 0)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  max_header_list = conn->local_settings[SETTINGS_IDX_MAX_HEADER_LIST_SIZE];
  if (header_block_len > max_header_list)
    {
      http2_send_stream_error (conn, header->stream_id, HTTP2_ENHANCE_YOUR_CALM);
      return -1;
    }

  if (header->flags & HTTP2_FLAG_END_HEADERS)
    {
      return process_complete_header_block (
          conn, stream, header_block, header_block_len,
          (header->flags & HTTP2_FLAG_END_STREAM) != 0);
    }

  return setup_continuation_state (conn, stream, header_block, header_block_len);
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
  size_t max_header_list;

  stream = http2_stream_lookup (conn, header->stream_id);
  if (!stream || !stream->header_block)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  max_header_list = conn->local_settings[SETTINGS_IDX_MAX_HEADER_LIST_SIZE];
  if (stream->header_block_len + header->length > max_header_list)
    {
      http2_send_stream_error (conn, header->stream_id, HTTP2_ENHANCE_YOUR_CALM);
      return -1;
    }

  if (stream->header_block_len + header->length > stream->header_block_capacity)
    {
      if (grow_header_block (conn, stream, header->length) < 0)
        {
          http2_send_connection_error (conn, HTTP2_INTERNAL_ERROR);
          return -1;
        }
    }

  memcpy (stream->header_block + stream->header_block_len, payload,
          header->length);
  stream->header_block_len += header->length;

  if (header->flags & HTTP2_FLAG_END_HEADERS)
    {
      conn->expecting_continuation = 0;
      conn->continuation_stream_id = 0;

      if (http2_decode_headers (conn, stream, stream->header_block,
                                stream->header_block_len)
          < 0)
        return -1;

      clear_pending_header_block (stream);

      if (!stream->headers_received)
        {
          stream->headers_received = 1;
          http2_emit_stream_event (conn, stream, HTTP2_EVENT_HEADERS_RECEIVED);
        }
      else
        {
          http2_emit_stream_event (conn, stream, HTTP2_EVENT_TRAILERS_RECEIVED);
        }
    }

  return 0;
}

/* ============================================================================
 * Frame Processing - PUSH_PROMISE
 * ============================================================================ */

/**
 * validate_push_promise - Validate PUSH_PROMISE can be received
 * @conn: Connection
 * @header: Frame header
 *
 * Returns: 0 if valid, -1 on protocol error
 */
static int
validate_push_promise (SocketHTTP2_Conn_T conn,
                       const SocketHTTP2_FrameHeader *header)
{
  if (conn->role != HTTP2_ROLE_CLIENT)
    return -1;

  if (conn->local_settings[SETTINGS_IDX_ENABLE_PUSH] == 0)
    return -1;

  if (!http2_stream_lookup (conn, header->stream_id))
    return -1;

  return 0;
}

/**
 * extract_push_promise_payload - Extract PUSH_PROMISE payload
 * @header: Frame header
 * @payload: Frame payload
 * @promised_id: Output - promised stream ID
 * @block: Output - header block pointer
 * @block_len: Output - header block length
 *
 * Returns: 0 on success, -1 on protocol error
 */
static int
extract_push_promise_payload (const SocketHTTP2_FrameHeader *header,
                              const unsigned char *payload,
                              uint32_t *promised_id,
                              const unsigned char **block, size_t *block_len)
{
  uint8_t pad_len = 0;
  size_t offset = 0;

  if (header->flags & HTTP2_FLAG_PADDED)
    {
      if (header->length < (1 + HTTP2_PUSH_PROMISE_ID_SIZE))
        return -1;
      pad_len = payload[0];
      offset = 1;
    }

  if (header->length < offset + HTTP2_PUSH_PROMISE_ID_SIZE + pad_len)
    return -1;

  *promised_id = parse_promised_stream_id (payload, offset);
  offset += HTTP2_PUSH_PROMISE_ID_SIZE;

  if ((*promised_id & 1) != 0)
    return -1;

  *block = payload + offset;
  *block_len = header->length - offset - pad_len;
  return 0;
}

int
http2_process_push_promise (SocketHTTP2_Conn_T conn,
                            const SocketHTTP2_FrameHeader *header,
                            const unsigned char *payload)
{
  SocketHTTP2_Stream_T promised;
  uint32_t promised_id;
  const unsigned char *header_block;
  size_t header_block_len, max_header_list;

  if (validate_push_promise (conn, header) < 0)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  if (extract_push_promise_payload (header, payload, &promised_id,
                                    &header_block, &header_block_len)
      < 0)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  promised = http2_stream_create (conn, promised_id);
  if (!promised)
    {
      http2_send_stream_error (conn, promised_id, HTTP2_REFUSED_STREAM);
      return 0;
    }

  promised->state = HTTP2_STREAM_STATE_RESERVED_REMOTE;

  max_header_list = conn->local_settings[SETTINGS_IDX_MAX_HEADER_LIST_SIZE];
  if (header_block_len > max_header_list)
    {
      http2_send_stream_error (conn, promised_id, HTTP2_ENHANCE_YOUR_CALM);
      return -1;
    }

  if (header->flags & HTTP2_FLAG_END_HEADERS)
    {
      if (http2_decode_headers (conn, promised, header_block, header_block_len)
          < 0)
        return -1;

      promised->headers_received = 1;

      http2_emit_stream_event (conn, promised, HTTP2_EVENT_PUSH_PROMISE);
    }
  else
    {
      if (init_pending_header_block (conn, promised, header_block,
                                     header_block_len)
          < 0)
        {
          http2_send_connection_error (conn, HTTP2_INTERNAL_ERROR);
          return -1;
        }

      conn->expecting_continuation = 1;
      conn->continuation_stream_id = promised_id;
    }

  return 0;
}

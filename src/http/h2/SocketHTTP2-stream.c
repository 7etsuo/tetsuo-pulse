/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/*
 * SocketHTTP2-stream.c - HTTP/2 Stream State Machine (RFC 9113)
 */

#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTP2.h"

#include "core/SocketUtil.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"

#include <assert.h>
#include <inttypes.h>
#include <string.h>

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTP2"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTP2);

#define HTTP2_STREAM_RECV_BUF_SIZE SOCKETHTTP2_DEFAULT_STREAM_RECV_BUF_SIZE
#define HTTP2_INITIAL_HEADER_BLOCK_SIZE \
  SOCKETHTTP2_DEFAULT_INITIAL_HEADER_BLOCK_SIZE
#define HTTP2_MAX_DECODED_HEADERS SOCKETHTTP2_MAX_DECODED_HEADERS
#define HTTP2_MAX_STREAM_ID 0x7FFFFFFF

/* Compile-time string length for literals */
#define STRLEN_LIT(s) (sizeof (s) - 1)

/* Forward declaration for RFC 9113 §8.4 push method validation */
static int validate_push_request_method (SocketHTTP2_Stream_T stream);

static inline int
http2_is_end_stream (uint8_t flags)
{
  return (flags & HTTP2_FLAG_END_STREAM) != 0;
}

static int
http2_extract_padded (const SocketHTTP2_FrameHeader *header,
                      const unsigned char *payload,
                      size_t *extra_offset,
                      uint8_t *pad_len)
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

SocketHTTP2_Stream_T
http2_stream_lookup (const SocketHTTP2_Conn_T conn, uint32_t stream_id)
{
  unsigned idx;
  SocketHTTP2_Stream_T stream;

  assert (conn);

  idx = socket_util_hash_uint_seeded (
      stream_id, HTTP2_STREAM_HASH_SIZE, conn->hash_seed);
  stream = conn->streams[idx];

  int chain_len = 0;
  while (stream)
    {
      chain_len++;
      if (chain_len > HTTP2_STREAM_MAX_HASH_CHAIN_LEN)
        { /* Prevent DoS from hash collision chains */
          SOCKET_LOG_WARN_MSG (
              "Long hash chain in stream lookup: %d (potential DoS)",
              chain_len);
          http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
          return NULL;
        }
      if (stream->id == stream_id)
        return stream;
      stream = stream->hash_next;
    }

  return NULL;
}

static void
init_stream_fields (SocketHTTP2_Stream_T stream,
                    const SocketHTTP2_Conn_T conn,
                    uint32_t stream_id,
                    bool is_local_initiated)
{
  stream->id = stream_id;
  stream->state = HTTP2_STREAM_STATE_IDLE;
  stream->conn = conn;
  stream->is_local_initiated = is_local_initiated;
  stream->send_window = conn->initial_send_window;
  stream->recv_window = conn->initial_recv_window;
  stream->pending_end_stream = 0;
  stream->is_push_stream = 0;
  stream->rst_received = 0;

  /* Initialize Content-Length validation fields */
  stream->expected_content_length = -1; /* No Content-Length specified */
  stream->total_data_received = 0;

  /* Initialize RFC 9218 priority to defaults */
  stream->priority.urgency = SOCKETHTTP2_PRIORITY_DEFAULT_URGENCY;
  stream->priority.incremental = 0;
}

static void
add_stream_to_hash (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream)
{
  unsigned idx = socket_util_hash_uint_seeded (
      stream->id, HTTP2_STREAM_HASH_SIZE, conn->hash_seed);
  stream->hash_next = conn->streams[idx];
  conn->streams[idx] = stream;
  conn->stream_count++;
}

static void
remove_stream_from_hash (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream)
{
  unsigned idx = socket_util_hash_uint_seeded (
      stream->id, HTTP2_STREAM_HASH_SIZE, conn->hash_seed);
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

static inline uint32_t *
get_initiated_count (SocketHTTP2_Conn_T conn, int is_local)
{
  return is_local ? &conn->server_initiated_count
                  : &conn->client_initiated_count;
}

/**
 * Helper function to check a TimeWindow limit and log security warnings.
 *
 * @param window Pointer to the TimeWindow to check
 * @param threshold Maximum allowed count within the window
 * @param now_ms Current time in milliseconds
 * @param limit_name Description of the limit being checked (for logging)
 * @param extra_msg Additional message to append to the warning (can be NULL)
 * @return 0 if within limit, -1 if limit exceeded
 */
static int
check_time_window_limit (TimeWindow_T *window,
                         uint32_t threshold,
                         int64_t now_ms,
                         const char *limit_name,
                         const char *extra_msg)
{
  uint32_t effective_count = TimeWindow_effective_count (window, now_ms);

  if (effective_count >= threshold)
    {
      SOCKET_LOG_WARN_MSG ("SECURITY: HTTP/2 %s limit exceeded: "
                           "%" PRIu32 " >= %" PRIu32 " in %" PRId64 " ms%s",
                           limit_name,
                           effective_count,
                           threshold,
                           window->duration_ms,
                           extra_msg ? extra_msg : "");
      return -1;
    }

  return 0;
}

/**
 * Check sliding window stream creation rate limits.
 *
 * Implements CVE-2023-44487 (HTTP/2 Rapid Reset Attack) protection using
 * sliding window counters for:
 * 1. Total stream creations over window period
 * 2. Short-term burst detection
 * 3. Rapid create+close cycle detection (churn)
 *
 * @return 0 if allowed, -1 if rate limited
 */
static int
http2_stream_rate_check (SocketHTTP2_Conn_T conn)
{
  int64_t now_ms = Socket_get_monotonic_ms ();

  /* Check sliding window: total creations over window period */
  if (check_time_window_limit (&conn->stream_create_window,
                               conn->stream_max_per_window,
                               now_ms,
                               "stream creation window",
                               " - potential DoS attack")
      < 0)
    return -1;

  /* Check burst: short-term rate spike detection */
  if (check_time_window_limit (&conn->stream_burst_window,
                               conn->stream_burst_threshold,
                               now_ms,
                               "stream creation burst",
                               " - potential DoS attack")
      < 0)
    return -1;

  /* Check churn: rapid create+close cycles (CVE-2023-44487 specific) */
  if (check_time_window_limit (&conn->stream_churn_window,
                               conn->stream_churn_threshold,
                               now_ms,
                               "stream churn",
                               " - CVE-2023-44487 Rapid Reset Attack detected")
      < 0)
    return -1;

  return 0;
}


/**
 * Record stream close for churn detection.
 *
 * When a stream is closed shortly after creation, this contributes
 * to the churn counter for CVE-2023-44487 protection.
 */
static void
http2_stream_close_record (SocketHTTP2_Conn_T conn)
{
  int64_t now_ms = Socket_get_monotonic_ms ();
  TimeWindow_record (&conn->stream_churn_window, now_ms);
}

SocketHTTP2_Stream_T
http2_stream_create (SocketHTTP2_Conn_T conn,
                     uint32_t stream_id,
                     int is_local_initiated)
{
  SocketHTTP2_Stream_T stream;

  assert (conn);
  assert (stream_id > 0);

  /* Sliding window rate limiting (CVE-2023-44487 protection) */
  if (http2_stream_rate_check (conn) < 0)
    {
      SOCKET_LOG_DEBUG_MSG (
          "Stream creation rate limited (sliding window) for conn %p",
          (void *)conn);
      return NULL;
    }

  /* Token bucket rate limit (legacy, provides complementary protection) */
  if (!SocketRateLimit_try_acquire (conn->stream_open_rate_limit, 1))
    {
      SOCKET_LOG_DEBUG_MSG (
          "Stream creation rate limited (token bucket) for conn %p",
          (void *)conn);
      return NULL;
    }

  /* Enforce correct concurrent limits based on initiator */
  uint32_t *open_count = get_initiated_count (conn, is_local_initiated);
  uint32_t limit
      = is_local_initiated
            ? conn->peer_settings[SETTINGS_IDX_MAX_CONCURRENT_STREAMS]
            : conn->local_settings[SETTINGS_IDX_MAX_CONCURRENT_STREAMS];
  if (*open_count >= limit)
    {
      SOCKET_LOG_DEBUG_MSG (
          "Max concurrent streams exceeded: local=%d, count=%u >= limit=%u",
          is_local_initiated,
          *open_count,
          limit);
      return NULL;
    }

  stream = Arena_calloc (
      conn->arena, 1, sizeof (struct SocketHTTP2_Stream), __FILE__, __LINE__);
  if (!stream)
    {
      SOCKET_LOG_ERROR_MSG ("failed to allocate HTTP/2 stream");
      return NULL;
    }
  init_stream_fields (stream, conn, stream_id, is_local_initiated);

  stream->recv_buf = SocketBuf_new (conn->arena, HTTP2_STREAM_RECV_BUF_SIZE);
  if (!stream->recv_buf)
    {
      SOCKET_LOG_ERROR_MSG ("failed to allocate recv buffer for HTTP/2 stream");
      http2_stream_destroy (stream); /* partial, clean */
      return NULL;
    }

  add_stream_to_hash (conn, stream);
  (*get_initiated_count (conn, stream->is_local_initiated))++;

  /* Record stream creation in sliding windows for rate limiting */
  int64_t now_ms = Socket_get_monotonic_ms ();
  TimeWindow_record (&conn->stream_create_window, now_ms);
  TimeWindow_record (&conn->stream_burst_window, now_ms);

  return stream;
}

void
http2_stream_destroy (SocketHTTP2_Stream_T stream)
{
  if (!stream)
    return;

  SocketHTTP2_Conn_T conn = stream->conn;
  uint32_t *count = get_initiated_count (conn, stream->is_local_initiated);

  if (*count > 0)
    (*count)--; /* Defensive >0 */

  /* Record stream close for churn detection (CVE-2023-44487) */
  http2_stream_close_record (conn);

  remove_stream_from_hash (conn, stream);

  if (stream->recv_buf)
    SocketBuf_release (&stream->recv_buf);
}

static SocketHTTP2_ErrorCode
transition_from_idle (uint8_t frame_type,
                      uint8_t flags,
                      int is_send,
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

static SocketHTTP2_ErrorCode
transition_from_reserved_local (uint8_t frame_type,
                                int is_send,
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

static SocketHTTP2_ErrorCode
transition_from_reserved_remote (uint8_t frame_type,
                                 int is_send,
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

static SocketHTTP2_ErrorCode
transition_from_open (uint8_t frame_type,
                      uint8_t flags,
                      int is_send,
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

static SocketHTTP2_ErrorCode
transition_from_half_closed_local (uint8_t frame_type,
                                   uint8_t flags,
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

static SocketHTTP2_ErrorCode
transition_from_half_closed_remote (uint8_t frame_type,
                                    uint8_t flags,
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

SocketHTTP2_ErrorCode
http2_stream_transition (SocketHTTP2_Stream_T stream,
                         uint8_t frame_type,
                         uint8_t flags,
                         int is_send)
{
  SocketHTTP2_StreamState new_state = stream->state;
  SocketHTTP2_ErrorCode error = HTTP2_NO_ERROR;

  switch (stream->state)
    {
    case HTTP2_STREAM_STATE_IDLE:
      error = transition_from_idle (frame_type, flags, is_send, &new_state);
      break;

    case HTTP2_STREAM_STATE_RESERVED_LOCAL:
      error = transition_from_reserved_local (frame_type, is_send, &new_state);
      break;

    case HTTP2_STREAM_STATE_RESERVED_REMOTE:
      error = transition_from_reserved_remote (frame_type, is_send, &new_state);
      break;

    case HTTP2_STREAM_STATE_OPEN:
      error = transition_from_open (frame_type, flags, is_send, &new_state);
      break;

    case HTTP2_STREAM_STATE_HALF_CLOSED_LOCAL:
      error = transition_from_half_closed_local (
          frame_type, flags, is_send, &new_state);
      break;

    case HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE:
      error = transition_from_half_closed_remote (
          frame_type, flags, is_send, &new_state);
      break;

    case HTTP2_STREAM_STATE_CLOSED:
      error = transition_from_closed (frame_type, is_send);
      break;
    }

  if (error == HTTP2_NO_ERROR)
    stream->state = new_state;

  return error;
}

static void
emit_header_event (SocketHTTP2_Conn_T conn, SocketHTTP2_Stream_T stream)
{
  assert (conn && stream);

  if (!stream->headers_received)
    {
      stream->headers_received = 1;
      if (stream->is_push_stream)
        {
          http2_emit_stream_event (conn, stream, HTTP2_EVENT_PUSH_PROMISE);
        }
      else
        {
          http2_emit_stream_event (conn, stream, HTTP2_EVENT_HEADERS_RECEIVED);
        }
    }
  else
    {
      http2_emit_stream_event (conn, stream, HTTP2_EVENT_TRAILERS_RECEIVED);
    }
}

static size_t
copy_and_consume (SocketHPACK_Header *dest,
                  size_t max_count,
                  const SocketHPACK_Header *src,
                  size_t src_count,
                  int *consumed)
{
  size_t copy_count = (src_count > max_count) ? max_count : src_count;

  if (copy_count > 0 && dest != NULL)
    {
      memcpy (dest, src, copy_count * sizeof (SocketHPACK_Header));
    }

  if (consumed != NULL)
    {
      *consumed = 1;
    }

  return copy_count;
}

SocketHTTP2_Stream_T
SocketHTTP2_Stream_new (SocketHTTP2_Conn_T conn)
{
  SocketHTTP2_Stream_T stream;
  uint32_t stream_id;

  assert (conn);

  /* After GOAWAY (sent or received), no new streams allowed */
  if (conn->goaway_received || conn->goaway_sent)
    return NULL;

  stream_id = conn->next_stream_id;
  if (stream_id > HTTP2_MAX_STREAM_ID)
    return NULL;

  stream = http2_stream_create (conn, stream_id, 1 /* local initiated */);
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

  /* Rate limit closes to prevent RST flood */
  if (!SocketRateLimit_try_acquire (stream->conn->stream_close_rate_limit, 1))
    {
      SOCKET_LOG_DEBUG_MSG ("Stream close rate limited for stream %u",
                            stream->id);
      stream->state = HTTP2_STREAM_STATE_CLOSED; /* Close locally anyway */
      /* Still record for churn detection even if rate limited */
      http2_stream_close_record (stream->conn);
      return;
    }

  if (stream->state != HTTP2_STREAM_STATE_CLOSED)
    {
      http2_send_stream_error (stream->conn, stream->id, error_code);
      stream->state = HTTP2_STREAM_STATE_CLOSED;
      /* Record stream close for churn detection (CVE-2023-44487) */
      http2_stream_close_record (stream->conn);
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

SocketHTTP2_Conn_T
SocketHTTP2_Stream_get_connection (SocketHTTP2_Stream_T stream)
{
  assert (stream);
  return stream->conn;
}

int
SocketHTTP2_Stream_window_update (SocketHTTP2_Stream_T stream,
                                  uint32_t increment)
{
  SocketHTTP2_FrameHeader header;
  unsigned char payload[HTTP2_WINDOW_UPDATE_PAYLOAD_SIZE];

  assert (stream);
  assert (increment > 0 && increment <= HTTP2_MAX_STREAM_ID);

  write_u31_be (payload, increment);

  header.length = HTTP2_WINDOW_UPDATE_PAYLOAD_SIZE;
  header.type = HTTP2_FRAME_WINDOW_UPDATE;
  header.flags = 0;
  header.stream_id = stream->id;

  return http2_frame_send (
      stream->conn, &header, payload, HTTP2_WINDOW_UPDATE_PAYLOAD_SIZE);
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

ssize_t
http2_encode_headers (SocketHTTP2_Conn_T conn,
                      const SocketHPACK_Header *headers,
                      size_t count,
                      unsigned char *output,
                      size_t output_size)
{
  return SocketHPACK_Encoder_encode (
      conn->encoder, headers, count, output, output_size);
}

static unsigned char *
alloc_header_block (SocketHTTP2_Conn_T conn, size_t initial_size);

static ssize_t
http2_encode_and_alloc_block (SocketHTTP2_Conn_T conn,
                              const SocketHPACK_Header *headers,
                              size_t count,
                              unsigned char **block_out)
{
  size_t initial_size = HTTP2_INITIAL_HEADER_BLOCK_SIZE;
  *block_out = alloc_header_block (conn, initial_size);
  if (!*block_out)
    return -1;

  ssize_t len
      = http2_encode_headers (conn, headers, count, *block_out, initial_size);
  if (len < 0)
    return -1;

  return len;
}

/* Pseudo-header bit positions for duplicate detection */
#define PSEUDO_BIT_METHOD (1 << 0)
#define PSEUDO_BIT_SCHEME (1 << 1)
#define PSEUDO_BIT_AUTHORITY (1 << 2)
#define PSEUDO_BIT_PATH (1 << 3)
#define PSEUDO_BIT_STATUS (1 << 4)
#define PSEUDO_BIT_PROTOCOL (1 << 5)

static int
validate_pseudo_header (SocketHTTP2_Conn_T conn,
                        SocketHTTP2_Stream_T stream,
                        const SocketHPACK_Header *h,
                        int is_request,
                        int *pseudo_headers_seen,
                        HTTP2_PseudoHeaderState *state)
{
  /* Dispatch by pseudo-header name with duplicate detection */
  if (h->name_len == STRLEN_LIT (":method")
      && memcmp (h->name, ":method", STRLEN_LIT (":method")) == 0)
    {
      if (*pseudo_headers_seen & PSEUDO_BIT_METHOD)
        {
          SOCKET_LOG_ERROR_MSG ("Duplicate :method pseudo-header");
          return -1;
        }
      *pseudo_headers_seen |= PSEUDO_BIT_METHOD;

      if (http2_validate_method_header (h, is_request, state) < 0)
        {
          SOCKET_LOG_ERROR_MSG ("Invalid HTTP method in :method pseudo-header");
          return -1;
        }
      return 0;
    }

  if (h->name_len == STRLEN_LIT (":scheme")
      && memcmp (h->name, ":scheme", STRLEN_LIT (":scheme")) == 0)
    {
      if (*pseudo_headers_seen & PSEUDO_BIT_SCHEME)
        {
          SOCKET_LOG_ERROR_MSG ("Duplicate :scheme pseudo-header");
          return -1;
        }
      *pseudo_headers_seen |= PSEUDO_BIT_SCHEME;
      return http2_validate_scheme_header (h, state);
    }

  if (h->name_len == STRLEN_LIT (":authority")
      && memcmp (h->name, ":authority", STRLEN_LIT (":authority")) == 0)
    {
      if (*pseudo_headers_seen & PSEUDO_BIT_AUTHORITY)
        {
          SOCKET_LOG_ERROR_MSG ("Duplicate :authority pseudo-header");
          return -1;
        }
      *pseudo_headers_seen |= PSEUDO_BIT_AUTHORITY;
      return http2_validate_authority_header (h, state);
    }

  if (h->name_len == STRLEN_LIT (":path")
      && memcmp (h->name, ":path", STRLEN_LIT (":path")) == 0)
    {
      if (*pseudo_headers_seen & PSEUDO_BIT_PATH)
        {
          SOCKET_LOG_ERROR_MSG ("Duplicate :path pseudo-header");
          return -1;
        }
      *pseudo_headers_seen |= PSEUDO_BIT_PATH;
      return http2_validate_path_header (h, state);
    }

  if (h->name_len == STRLEN_LIT (":status")
      && memcmp (h->name, ":status", STRLEN_LIT (":status")) == 0)
    {
      if (*pseudo_headers_seen & PSEUDO_BIT_STATUS)
        {
          SOCKET_LOG_ERROR_MSG ("Duplicate :status pseudo-header");
          return -1;
        }
      *pseudo_headers_seen |= PSEUDO_BIT_STATUS;

      if (http2_validate_status_header (h, is_request, state) < 0)
        {
          SOCKET_LOG_ERROR_MSG (
              "Invalid HTTP status code: %.*s", (int)h->value_len, h->value);
          return -1;
        }
      return 0;
    }

  if (h->name_len == STRLEN_LIT (":protocol")
      && memcmp (h->name, ":protocol", STRLEN_LIT (":protocol")) == 0)
    {
      if (*pseudo_headers_seen & PSEUDO_BIT_PROTOCOL)
        {
          SOCKET_LOG_ERROR_MSG ("Duplicate :protocol pseudo-header");
          return -1;
        }
      *pseudo_headers_seen |= PSEUDO_BIT_PROTOCOL;

      if (http2_validate_protocol_header (conn, stream, h, state) < 0)
        {
          if (conn->role != HTTP2_ROLE_SERVER)
            SOCKET_LOG_ERROR_MSG (
                ":protocol pseudo-header not allowed in responses");
          else if (conn->local_settings[SETTINGS_IDX_ENABLE_CONNECT_PROTOCOL]
                   == 0)
            SOCKET_LOG_ERROR_MSG (
                ":protocol requires SETTINGS_ENABLE_CONNECT_PROTOCOL=1");
          else
            SOCKET_LOG_ERROR_MSG (":protocol value too long: %zu bytes",
                                  h->value_len);
          return -1;
        }
      return 0;
    }

  /* Unknown pseudo-header */
  SOCKET_LOG_ERROR_MSG (
      "Unknown pseudo-header: %.*s", (int)h->name_len, h->name);
  return -1;
}

static int
validate_regular_header_entry (const SocketHPACK_Header *h,
                               int *has_te,
                               SocketHTTP2_Stream_T stream,
                               bool *parsed_content_length)
{
  /* Malformed message validation per RFC 9113 Section 8.2.1 */

  /* Field names MUST be lowercase */
  if (http2_field_has_uppercase (h->name, h->name_len))
    {
      SOCKET_LOG_ERROR_MSG (
          "Uppercase character in field name: %.*s", (int)h->name_len, h->name);
      return -1;
    }

  /* Reject prohibited characters in field names (NUL/CR/LF) */
  if (http2_field_has_prohibited_chars (h->name, h->name_len))
    {
      SOCKET_LOG_ERROR_MSG ("Prohibited character in field name: %.*s",
                            (int)h->name_len,
                            h->name);
      return -1;
    }

  /* Reject prohibited characters in field values (NUL/CR/LF) */
  if (http2_field_has_prohibited_chars (h->value, h->value_len))
    {
      SOCKET_LOG_ERROR_MSG ("Prohibited character in field value: %.*s",
                            (int)h->name_len,
                            h->name);
      return -1;
    }

  /* Reject leading/trailing whitespace in field values */
  if (http2_field_has_boundary_whitespace (h->value, h->value_len))
    {
      SOCKET_LOG_ERROR_MSG ("Leading/trailing whitespace in field value: %.*s",
                            (int)h->name_len,
                            h->name);
      return -1;
    }

  /* Check for forbidden connection-specific headers */
  if (http2_is_connection_header_forbidden (h))
    {
      SOCKET_LOG_ERROR_MSG ("Forbidden connection-specific header: %.*s",
                            (int)h->name_len,
                            h->name);
      return -1;
    }

  /* Check TE header restrictions */
  if (h->name_len == STRLEN_LIT ("te")
      && memcmp (h->name, "te", STRLEN_LIT ("te")) == 0)
    {
      if (*has_te)
        {
          SOCKET_LOG_ERROR_MSG ("Duplicate TE header");
          return -1;
        }
      *has_te = 1;

      /* TE must be "trailers" or empty */
      if (h->value_len > 0 && h->value_len != STRLEN_LIT ("trailers"))
        {
          SOCKET_LOG_ERROR_MSG ("TE header value must be 'trailers', got: %.*s",
                                (int)h->value_len,
                                h->value);
          return -1;
        }
      if (h->value_len == STRLEN_LIT ("trailers")
          && memcmp (h->value, "trailers", STRLEN_LIT ("trailers")) != 0)
        {
          SOCKET_LOG_ERROR_MSG ("TE header value must be 'trailers', got: %.*s",
                                (int)h->value_len,
                                h->value);
          return -1;
        }
    }

  /* Parse first Content-Length header for validation */
  if (!*parsed_content_length && h->name_len == STRLEN_LIT ("content-length")
      && memcmp (h->name, "content-length", STRLEN_LIT ("content-length")) == 0)
    {
      int64_t cl;
      if (http2_parse_content_length (h->value, h->value_len, &cl) < 0)
        {
          SOCKET_LOG_ERROR_MSG ("Invalid Content-Length value: %.*s",
                                (int)h->value_len,
                                h->value);
          return -1;
        }

      stream->expected_content_length = cl;
      *parsed_content_length = true;
    }

  return 0;
}

static int
validate_required_pseudo_headers (const HTTP2_PseudoHeaderState *state,
                                  int is_request)
{
  /* Response validation: simple single check */
  if (!is_request)
    {
      if (!state->has_status)
        {
          SOCKET_LOG_ERROR_MSG (
              "Response missing required :status pseudo-header");
          return -1;
        }
      return 0;
    }

  /* All requests need :method */
  if (!state->has_method)
    {
      SOCKET_LOG_ERROR_MSG ("Request missing required :method pseudo-header");
      return -1;
    }

  /* Extended CONNECT (CONNECT with :protocol) - RFC 8441 */
  if (state->is_connect_method && state->has_protocol)
    {
      if (http2_validate_extended_connect (state) < 0)
        {
          SOCKET_LOG_ERROR_MSG (
              "Extended CONNECT requires :scheme, :path, and :authority");
          return -1;
        }
      return 0;
    }

  /* Standard CONNECT (CONNECT without :protocol) - RFC 9113 Section 8.5 */
  if (state->is_connect_method)
    {
      if (http2_validate_standard_connect (state) < 0)
        {
          if (!state->has_authority)
            SOCKET_LOG_ERROR_MSG ("CONNECT requires :authority pseudo-header");
          else
            SOCKET_LOG_ERROR_MSG ("Standard CONNECT must not have :scheme or "
                                  ":path pseudo-headers");
          return -1;
        }
      return 0;
    }

  /* Non-CONNECT: need :scheme or :authority, and :path */
  if (!state->has_scheme && !state->has_authority)
    {
      SOCKET_LOG_ERROR_MSG (
          "Request missing required :scheme or :authority pseudo-header");
      return -1;
    }

  if (!state->has_path)
    {
      SOCKET_LOG_ERROR_MSG ("Request missing required :path pseudo-header");
      return -1;
    }

  if (state->has_protocol)
    {
      SOCKET_LOG_ERROR_MSG (
          ":protocol pseudo-header only valid with CONNECT method");
      return -1;
    }

  return 0;
}

static int
http2_validate_headers (SocketHTTP2_Conn_T conn,
                        SocketHTTP2_Stream_T stream,
                        const SocketHPACK_Header *headers,
                        size_t count,
                        int is_trailer)
{
  int is_request = (conn->role == HTTP2_ROLE_CLIENT ? 1 : 0);
  int pseudo_headers_seen = 0;
  HTTP2_PseudoHeaderState state = { 0 };
  int has_te = 0;
  bool parsed_content_length = false;
  int pseudo_section_ended = 0;

  for (size_t i = 0; i < count; i++)
    {
      const SocketHPACK_Header *h = &headers[i];

      /* Check for pseudo-header */
      if (h->name_len > 0 && h->name[0] == ':')
        {
          /* RFC 9113 §8.1.3: Pseudo-headers not allowed in trailers */
          if (is_trailer)
            {
              SOCKET_LOG_ERROR_MSG (
                  "Pseudo-header '%.*s' not allowed in trailers",
                  (int)h->name_len,
                  h->name);
              goto protocol_error;
            }

          /* Pseudo-headers must appear before regular headers */
          if (pseudo_section_ended)
            {
              SOCKET_LOG_ERROR_MSG (
                  "Pseudo-header '%.*s' appears after regular headers",
                  (int)h->name_len,
                  h->name);
              goto protocol_error;
            }

          if (validate_pseudo_header (
                  conn, stream, h, is_request, &pseudo_headers_seen, &state)
              < 0)
            goto protocol_error;
        }
      else
        {
          /* Regular header - pseudo-header section has ended */
          pseudo_section_ended = 1;

          if (validate_regular_header_entry (
                  h, &has_te, stream, &parsed_content_length)
              < 0)
            goto protocol_error;
        }
    }

  /* Validate required pseudo-headers */
  if (validate_required_pseudo_headers (&state, is_request) < 0)
    goto protocol_error;

  return 0;

protocol_error:
  if (is_request)
    {
      /* Request validation errors are stream errors */
      http2_send_stream_error (conn, stream->id, HTTP2_PROTOCOL_ERROR);
    }
  else
    {
      /* Response validation errors are connection errors */
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
    }
  return -1;
}

static int
http2_recombine_cookie_headers (Arena_T arena,
                                SocketHPACK_Header *headers,
                                size_t *count)
{
  size_t cookie_count = 0;
  size_t first_cookie_idx = (size_t)-1;
  size_t total_value_len = 0;
  size_t *cookie_indices = NULL;
  size_t num_cookies = 0;

  if (*count == 0)
    return 0;

  cookie_indices
      = Arena_alloc (arena, *count * sizeof (size_t), __FILE__, __LINE__);
  if (cookie_indices == NULL)
    return -1;

  /* Single pass: collect cookie indices, calculate lengths, find first */
  for (size_t i = 0; i < *count; i++)
    {
      const SocketHPACK_Header *h = &headers[i];
      if (h->name_len == STRLEN_LIT ("cookie")
          && memcmp (h->name, "cookie", STRLEN_LIT ("cookie")) == 0)
        {
          cookie_indices[num_cookies] = i;
          if (first_cookie_idx == (size_t)-1)
            first_cookie_idx = i;
          total_value_len += h->value_len;
          num_cookies++;
        }
    }

  cookie_count = num_cookies;

  if (cookie_count <= 1)
    return 0;

  total_value_len += 2 * (cookie_count - 1); /* delimiters "; " */

  char *combined_value
      = Arena_alloc (arena, total_value_len + 1, __FILE__, __LINE__);
  if (combined_value == NULL)
    return -1;

  /* Build combined value using indices */
  size_t offset = 0;
  for (size_t k = 0; k < cookie_count; k++)
    {
      size_t i = cookie_indices[k];
      memcpy (combined_value + offset, headers[i].value, headers[i].value_len);
      offset += headers[i].value_len;
      if (k < cookie_count - 1)
        {
          memcpy (combined_value + offset, "; ", 2);
          offset += 2;
        }
    }

  headers[first_cookie_idx].value = combined_value;
  headers[first_cookie_idx].value_len = total_value_len;

  /* Build skip bitmap for cookie headers (except first) */
  char *skip = Arena_calloc (arena, *count, 1, __FILE__, __LINE__);
  if (skip == NULL)
    return -1;

  for (size_t k = 1; k < cookie_count; k++)
    skip[cookie_indices[k]] = 1;

  /* Compact array, skipping marked indices */
  size_t new_count = 0;
  for (size_t i = 0; i < *count; i++)
    {
      if (skip[i])
        continue;
      if (new_count != i)
        headers[new_count] = headers[i];
      new_count++;
    }

  *count = new_count;
  return 0;
}

int
http2_decode_headers (SocketHTTP2_Conn_T conn,
                      SocketHTTP2_Stream_T stream,
                      const unsigned char *block,
                      size_t len)
{
  SocketHPACK_Header decoded_headers[HTTP2_MAX_DECODED_HEADERS];
  size_t header_count = 0;
  SocketHPACK_Result result;

  result = SocketHPACK_Decoder_decode (conn->decoder,
                                       block,
                                       len,
                                       decoded_headers,
                                       HTTP2_MAX_DECODED_HEADERS,
                                       &header_count,
                                       conn->arena);

  if (result != HPACK_OK)
    {
      http2_send_connection_error (conn, HTTP2_COMPRESSION_ERROR);
      return -1;
    }

  /* header_count <= HTTP2_MAX_DECODED_HEADERS guaranteed by decoder limit */
  assert (header_count <= HTTP2_MAX_DECODED_HEADERS);

  /* Validate headers according to RFC 9113 */
  int is_trailer = stream->end_stream_received;
  if (http2_validate_headers (
          conn, stream, decoded_headers, header_count, is_trailer)
      < 0)
    return -1;

  /* Recombine multiple cookie headers per RFC 9113 §8.2.3 */
  if (http2_recombine_cookie_headers (
          conn->arena, decoded_headers, &header_count)
      < 0)
    {
      SOCKET_LOG_ERROR_MSG ("failed to recombine cookie headers");
      return -1;
    }

  /* Store decoded headers based on whether this is initial headers or trailers
   */
  if (!stream->headers_received)
    {
      memcpy (stream->headers,
              decoded_headers,
              header_count * sizeof (SocketHPACK_Header));
      stream->header_count = header_count;
      stream->headers_consumed = 0;
    }
  else
    {
      memcpy (stream->trailers,
              decoded_headers,
              header_count * sizeof (SocketHPACK_Header));
      stream->trailer_count = header_count;
      stream->trailers_consumed = 0;
      stream->trailers_received = 1;
    }

  return 0;
}

static unsigned char *
alloc_header_block (SocketHTTP2_Conn_T conn, size_t initial_size)
{
  return Arena_alloc (conn->arena, initial_size, __FILE__, __LINE__);
}

static int
grow_header_block (SocketHTTP2_Conn_T conn,
                   SocketHTTP2_Stream_T stream,
                   size_t needed)
{
  size_t new_capacity = stream->header_block_capacity + needed
                        + HTTP2_INITIAL_HEADER_BLOCK_SIZE;
  unsigned char *new_block
      = Arena_alloc (conn->arena, new_capacity, __FILE__, __LINE__);
  if (!new_block)
    return -1;

  memcpy (new_block, stream->header_block, stream->header_block_len);
  stream->header_block = new_block;
  stream->header_block_capacity = new_capacity;
  return 0;
}

static int
init_pending_header_block (SocketHTTP2_Conn_T conn,
                           SocketHTTP2_Stream_T stream,
                           const unsigned char *data,
                           size_t len)
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


static int
send_single_headers_frame (SocketHTTP2_Conn_T conn,
                           SocketHTTP2_Stream_T stream,
                           const unsigned char *header_block,
                           size_t block_len,
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

static int
send_headers_chunk (SocketHTTP2_Conn_T conn,
                    SocketHTTP2_Stream_T stream,
                    const unsigned char *data,
                    size_t chunk_len,
                    int first,
                    int last,
                    int end_stream)
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

static int
send_fragmented_headers (SocketHTTP2_Conn_T conn,
                         SocketHTTP2_Stream_T stream,
                         const unsigned char *header_block,
                         size_t block_len,
                         uint32_t max_frame_size,
                         int end_stream)
{
  size_t offset = 0;
  int first = 1;

  while (offset < block_len)
    {
      size_t chunk_len = block_len - offset;
      if (chunk_len > max_frame_size)
        chunk_len = max_frame_size;
      int is_last = (offset + chunk_len >= block_len);

      if (send_headers_chunk (conn,
                              stream,
                              header_block + offset,
                              chunk_len,
                              first,
                              is_last,
                              end_stream)
          < 0)
        return -1;

      offset += chunk_len;
      first = 0;
    }

  return 0;
}

int
SocketHTTP2_Stream_send_headers (SocketHTTP2_Stream_T stream,
                                 const SocketHPACK_Header *headers,
                                 size_t header_count,
                                 int end_stream)
{
  SocketHTTP2_Conn_T conn;
  SocketHTTP2_ErrorCode error;

  assert (stream);
  assert (headers || header_count == 0);

  conn = stream->conn;

  error = http2_stream_transition (
      stream, HTTP2_FRAME_HEADERS, end_stream ? HTTP2_FLAG_END_STREAM : 0, 1);
  if (error != HTTP2_NO_ERROR)
    return -1;

  unsigned char *header_block;
  ssize_t block_len_ssize = http2_encode_and_alloc_block (
      conn, headers, header_count, &header_block);
  if (block_len_ssize < 0)
    return -1;
  size_t block_len = (size_t)block_len_ssize;

  uint32_t max_frame_size = conn->peer_settings[SETTINGS_IDX_MAX_FRAME_SIZE];

  if ((size_t)block_len <= max_frame_size)
    {
      if (send_single_headers_frame (
              conn, stream, header_block, (size_t)block_len, end_stream)
          < 0)
        return -1;
    }
  else
    {
      if (send_fragmented_headers (conn,
                                   stream,
                                   header_block,
                                   (size_t)block_len,
                                   max_frame_size,
                                   end_stream)
          < 0)
        return -1;
    }

  if (end_stream)
    stream->end_stream_sent = 1;

  return 0;
}

static int
send_single_headers_frame_padded (SocketHTTP2_Conn_T conn,
                                  SocketHTTP2_Stream_T stream,
                                  const unsigned char *header_block,
                                  size_t block_len,
                                  uint8_t pad_length,
                                  int end_stream)
{
  SocketHTTP2_FrameHeader frame_header;
  unsigned char *padded_payload;
  size_t total_len;

  /* Total payload: 1 (pad_length) + header_block + padding */
  total_len = 1 + block_len + pad_length;

  padded_payload = Arena_alloc (conn->arena, total_len, __FILE__, __LINE__);
  if (!padded_payload)
    return -1;

  padded_payload[0] = pad_length;
  memcpy (padded_payload + 1, header_block, block_len);
  /* RFC 9113 §6.2: Padding octets MUST be set to zero */
  memset (padded_payload + 1 + block_len, 0, pad_length);

  frame_header.length = (uint32_t)total_len;
  frame_header.type = HTTP2_FRAME_HEADERS;
  frame_header.flags = HTTP2_FLAG_PADDED | HTTP2_FLAG_END_HEADERS
                       | (end_stream ? HTTP2_FLAG_END_STREAM : 0);
  frame_header.stream_id = stream->id;

  return http2_frame_send (conn, &frame_header, padded_payload, total_len);
}

static int
send_fragmented_headers_padded (SocketHTTP2_Conn_T conn,
                                SocketHTTP2_Stream_T stream,
                                const unsigned char *header_block,
                                size_t block_len,
                                uint32_t max_frame_size,
                                uint8_t pad_length,
                                int end_stream)
{
  SocketHTTP2_FrameHeader frame_header;
  unsigned char *first_payload;
  size_t first_data_len, first_total_len;
  size_t offset;

  /* First frame includes padding overhead: 1 (pad_length) + data + padding */
  /* Calculate how much header data fits in first frame with padding */
  if (max_frame_size < (size_t)(1 + pad_length + 1))
    return -1; /* Frame too small for any data with padding */

  first_data_len = max_frame_size - 1 - pad_length;
  if (first_data_len > block_len)
    first_data_len = block_len;
  first_total_len = 1 + first_data_len + pad_length;

  first_payload
      = Arena_alloc (conn->arena, first_total_len, __FILE__, __LINE__);
  if (!first_payload)
    return -1;

  first_payload[0] = pad_length;
  memcpy (first_payload + 1, header_block, first_data_len);
  memset (first_payload + 1 + first_data_len, 0, pad_length);

  frame_header.length = (uint32_t)first_total_len;
  frame_header.type = HTTP2_FRAME_HEADERS;
  frame_header.flags = HTTP2_FLAG_PADDED;
  if (end_stream)
    frame_header.flags |= HTTP2_FLAG_END_STREAM;
  if (first_data_len >= block_len)
    frame_header.flags |= HTTP2_FLAG_END_HEADERS;
  frame_header.stream_id = stream->id;

  if (http2_frame_send (conn, &frame_header, first_payload, first_total_len)
      < 0)
    return -1;

  /* Send remaining header data as CONTINUATION frames (no padding) */
  offset = first_data_len;
  while (offset < block_len)
    {
      size_t chunk_len = block_len - offset;
      if (chunk_len > max_frame_size)
        chunk_len = max_frame_size;
      int is_last = (offset + chunk_len >= block_len);

      frame_header.length = (uint32_t)chunk_len;
      frame_header.type = HTTP2_FRAME_CONTINUATION;
      frame_header.flags = is_last ? HTTP2_FLAG_END_HEADERS : 0;
      frame_header.stream_id = stream->id;

      if (http2_frame_send (
              conn, &frame_header, header_block + offset, chunk_len)
          < 0)
        return -1;

      offset += chunk_len;
    }

  return 0;
}

int
SocketHTTP2_Stream_send_headers_padded (SocketHTTP2_Stream_T stream,
                                        const SocketHPACK_Header *headers,
                                        size_t header_count,
                                        uint8_t pad_length,
                                        int end_stream)
{
  SocketHTTP2_Conn_T conn;
  SocketHTTP2_ErrorCode error;

  assert (stream);
  assert (headers || header_count == 0);

  conn = stream->conn;

  /* If no padding requested, use the unpadded version */
  if (pad_length == 0)
    return SocketHTTP2_Stream_send_headers (
        stream, headers, header_count, end_stream);

  error = http2_stream_transition (
      stream, HTTP2_FRAME_HEADERS, end_stream ? HTTP2_FLAG_END_STREAM : 0, 1);
  if (error != HTTP2_NO_ERROR)
    return -1;

  unsigned char *header_block;
  ssize_t block_len_ssize = http2_encode_and_alloc_block (
      conn, headers, header_count, &header_block);
  if (block_len_ssize < 0)
    return -1;
  size_t block_len = (size_t)block_len_ssize;

  uint32_t max_frame_size = conn->peer_settings[SETTINGS_IDX_MAX_FRAME_SIZE];

  /* Total padded frame size: 1 (pad_length) + header_block + padding */
  size_t total_padded_len = 1 + block_len + pad_length;

  if (total_padded_len <= max_frame_size)
    {
      if (send_single_headers_frame_padded (
              conn, stream, header_block, block_len, pad_length, end_stream)
          < 0)
        return -1;
    }
  else
    {
      if (send_fragmented_headers_padded (conn,
                                          stream,
                                          header_block,
                                          block_len,
                                          max_frame_size,
                                          pad_length,
                                          end_stream)
          < 0)
        return -1;
    }

  if (end_stream)
    stream->end_stream_sent = 1;

  return 0;
}

static void
build_request_pseudo_headers (const SocketHTTP_Request *request,
                              SocketHPACK_Header *pseudo,
                              size_t scheme_len,
                              size_t authority_len,
                              size_t path_len)
{
  pseudo[0].name = ":method";
  pseudo[0].name_len = STRLEN_LIT (":method");
  pseudo[0].value = SocketHTTP_method_name (request->method);
  pseudo[0].value_len = strlen (pseudo[0].value);
  pseudo[0].never_index = 0;

  pseudo[1].name = ":scheme";
  pseudo[1].name_len = STRLEN_LIT (":scheme");
  pseudo[1].value = request->scheme ? request->scheme : "https";
  pseudo[1].value_len = scheme_len;
  pseudo[1].never_index = 0;

  pseudo[2].name = ":authority";
  pseudo[2].name_len = STRLEN_LIT (":authority");
  pseudo[2].value = request->authority ? request->authority : "";
  pseudo[2].value_len = authority_len;
  pseudo[2].never_index = 0;

  pseudo[3].name = ":path";
  pseudo[3].name_len = STRLEN_LIT (":path");
  pseudo[3].value = request->path ? request->path : "/";
  pseudo[3].value_len = path_len;
  pseudo[3].never_index = 0;
}

static void
copy_regular_headers (SocketHTTP_Headers_T src,
                      SocketHPACK_Header *dest,
                      size_t offset,
                      size_t count)
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
  volatile size_t path_len = 0, scheme_len = 0, auth_len = 0;

  assert (stream);
  assert (request);

  /* Validate pseudo-header inputs for security and calculate lengths once */
  TRY
  {
    const char *path = request->path ? request->path : "/";
    path_len = request->path ? strlen (request->path) : STRLEN_LIT ("/");
    if (path_len == 0 || path[0] != '/' || path_len > SOCKETHTTP_MAX_URI_LEN)
      {
        RAISE (SocketHTTP2_ProtocolError);
      }

    const char *scheme = request->scheme ? request->scheme : "https";
    scheme_len
        = request->scheme ? strlen (request->scheme) : STRLEN_LIT ("https");
    if (strcmp (scheme, "http") != 0 && strcmp (scheme, "https") != 0)
      {
        SOCKET_RAISE_MSG (SocketHTTP2,
                          SocketHTTP2_ProtocolError,
                          "Invalid :scheme '%s'",
                          scheme);
      }
    if (scheme_len > SOCKETHTTP_MAX_HEADER_VALUE)
      { /* Reasonable limit */
        RAISE (SocketHTTP2_ProtocolError);
      }

    const char *authority = request->authority ? request->authority : "";
    auth_len
        = request->authority ? strlen (request->authority) : STRLEN_LIT ("");
    if (auth_len > SOCKETHTTP_MAX_URI_LEN || strchr (authority, '\r')
        || strchr (authority, '\n'))
      {
        SOCKET_RAISE_MSG (SocketHTTP2,
                          SocketHTTP2_ProtocolError,
                          "Invalid :authority '%s'",
                          authority);
      }

    if (request->method == HTTP_METHOD_UNKNOWN)
      {
        SOCKET_RAISE_MSG (SocketHTTP2,
                          SocketHTTP2_ProtocolError,
                          "Invalid method %d",
                          request->method);
      }
  }
  EXCEPT (SocketHTTP2)
  {
    RERAISE;
  }
  END_TRY;

  build_request_pseudo_headers (
      request, pseudo_headers, scheme_len, auth_len, path_len);

  header_count
      = request->headers ? SocketHTTP_Headers_count (request->headers) : 0;
  total_count = HTTP2_REQUEST_PSEUDO_HEADER_COUNT + header_count;

  all_headers = Arena_alloc (stream->conn->arena,
                             total_count * sizeof (SocketHPACK_Header),
                             __FILE__,
                             __LINE__);
  if (!all_headers)
    return -1;

  memcpy (all_headers,
          pseudo_headers,
          HTTP2_REQUEST_PSEUDO_HEADER_COUNT * sizeof (SocketHPACK_Header));

  if (request->headers)
    copy_regular_headers (request->headers,
                          all_headers,
                          HTTP2_REQUEST_PSEUDO_HEADER_COUNT,
                          header_count);

  return SocketHTTP2_Stream_send_headers (
      stream, all_headers, total_count, end_stream);
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

  /* Validate response for security */
  TRY
  {
    if (!SocketHTTP_status_valid (response->status_code))
      {
        SOCKET_RAISE_MSG (SocketHTTP2,
                          SocketHTTP2_ProtocolError,
                          "Invalid status code %d",
                          response->status_code);
      }
    if (response->headers)
      {
        size_t hcount = SocketHTTP_Headers_count (response->headers);
        if (hcount > SOCKETHTTP2_MAX_DECODED_HEADERS)
          {
            RAISE (SocketHTTP2_ProtocolError);
          }
      }
  }
  EXCEPT (SocketHTTP2)
  {
    RERAISE;
  }
  END_TRY;

  status_len
      = snprintf (status_buf, sizeof (status_buf), "%d", response->status_code);
  pseudo_header.name = ":status";
  pseudo_header.name_len = STRLEN_LIT (":status");
  pseudo_header.value = status_buf;
  pseudo_header.value_len = (size_t)status_len;
  pseudo_header.never_index = 0;

  header_count
      = response->headers ? SocketHTTP_Headers_count (response->headers) : 0;
  total_count = 1 + header_count;

  all_headers = Arena_alloc (stream->conn->arena,
                             total_count * sizeof (SocketHPACK_Header),
                             __FILE__,
                             __LINE__);
  if (!all_headers)
    return -1;

  all_headers[0] = pseudo_header;

  if (response->headers)
    copy_regular_headers (response->headers, all_headers, 1, header_count);

  return SocketHTTP2_Stream_send_headers (
      stream, all_headers, total_count, end_stream);
}

int
SocketHTTP2_Stream_send_trailers (SocketHTTP2_Stream_T stream,
                                  const SocketHPACK_Header *trailers,
                                  size_t count)
{
  return SocketHTTP2_Stream_send_headers (stream, trailers, count, 1);
}

static size_t
calculate_send_length (SocketHTTP2_Conn_T conn,
                       SocketHTTP2_Stream_T stream,
                       size_t requested_len,
                       int *end_stream)
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
SocketHTTP2_Stream_send_data (SocketHTTP2_Stream_T stream,
                              const void *data,
                              size_t len,
                              int end_stream)
{
  SocketHTTP2_Conn_T conn;
  SocketHTTP2_FrameHeader header;
  SocketHTTP2_ErrorCode error;
  size_t send_len;

  assert (stream);
  assert (data || len == 0);

  conn = stream->conn;

  error = http2_stream_transition (
      stream, HTTP2_FRAME_DATA, end_stream ? HTTP2_FLAG_END_STREAM : 0, 1);
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

ssize_t
SocketHTTP2_Stream_send_data_padded (SocketHTTP2_Stream_T stream,
                                     const void *data,
                                     size_t len,
                                     uint8_t pad_length,
                                     int end_stream)
{
  SocketHTTP2_Conn_T conn;
  SocketHTTP2_FrameHeader header;
  SocketHTTP2_ErrorCode error;
  size_t send_len, total_frame_len;
  unsigned char *padded_payload;

  assert (stream);
  assert (data || len == 0);

  conn = stream->conn;

  /* If no padding requested, use the unpadded version */
  if (pad_length == 0)
    return SocketHTTP2_Stream_send_data (stream, data, len, end_stream);

  error = http2_stream_transition (
      stream, HTTP2_FRAME_DATA, end_stream ? HTTP2_FLAG_END_STREAM : 0, 1);
  if (error != HTTP2_NO_ERROR)
    return -1;

  /* Calculate total frame size: 1 (pad_length field) + data + padding */
  total_frame_len = 1 + len + pad_length;

  /* RFC 9113 §6.1: Pad Length MUST NOT exceed payload minus required fields */
  if (pad_length >= total_frame_len)
    return -1;

  /* Check against max frame size */
  uint32_t max_frame_size = conn->peer_settings[SETTINGS_IDX_MAX_FRAME_SIZE];
  if (total_frame_len > max_frame_size)
    {
      /* Adjust data length to fit within frame size constraints */
      size_t max_data = max_frame_size - 1 - pad_length;
      if (max_data == 0)
        return 0; /* Cannot send any data with this padding */
      len = (len > max_data) ? max_data : len;
      total_frame_len = 1 + len + pad_length;
      end_stream = 0; /* Can't end stream if we can't send all data */
    }

  send_len = calculate_send_length (conn, stream, total_frame_len, &end_stream);
  if (send_len == 0)
    return 0;

  /* If flow control reduced send_len, recalculate data portion */
  if (send_len < total_frame_len)
    {
      if (send_len <= (size_t)(1 + pad_length))
        return 0; /* Not enough room for any data */
      len = send_len - 1 - pad_length;
      total_frame_len = send_len;
      end_stream = 0;
    }

  http2_flow_consume_send (conn, stream, total_frame_len);

  /* Build padded payload: [Pad Length (1)] [Data (*)] [Padding (*)] */
  padded_payload
      = Arena_alloc (conn->arena, total_frame_len, __FILE__, __LINE__);
  if (!padded_payload)
    return -1;

  padded_payload[0] = pad_length;
  if (len > 0)
    memcpy (padded_payload + 1, data, len);
  /* RFC 9113 §6.1: Padding octets MUST be set to zero */
  memset (padded_payload + 1 + len, 0, pad_length);

  header.length = (uint32_t)total_frame_len;
  header.type = HTTP2_FRAME_DATA;
  header.flags = HTTP2_FLAG_PADDED | (end_stream ? HTTP2_FLAG_END_STREAM : 0);
  header.stream_id = stream->id;

  if (http2_frame_send (conn, &header, padded_payload, total_frame_len) < 0)
    return -1;

  if (end_stream)
    stream->end_stream_sent = 1;

  return (ssize_t)len;
}

int
SocketHTTP2_Stream_recv_headers (SocketHTTP2_Stream_T stream,
                                 SocketHPACK_Header *headers,
                                 size_t max_headers,
                                 size_t *header_count,
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

  *header_count = copy_and_consume (headers,
                                    max_headers,
                                    stream->headers,
                                    stream->header_count,
                                    &stream->headers_consumed);
  *end_stream = stream->end_stream_received;
  return 1;
}

ssize_t
SocketHTTP2_Stream_recv_data (SocketHTTP2_Stream_T stream,
                              void *buf,
                              size_t len,
                              int *end_stream)
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
                                  size_t max_trailers,
                                  size_t *trailer_count)
{
  assert (stream);
  assert (trailers || max_trailers == 0);
  assert (trailer_count);

  if (!stream->trailers_received || stream->trailers_consumed)
    {
      *trailer_count = 0;
      return 0;
    }

  *trailer_count = copy_and_consume (trailers,
                                     max_trailers,
                                     stream->trailers,
                                     stream->trailer_count,
                                     &stream->trailers_consumed);
  return 1;
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

  pushed = http2_stream_create (conn, promised_id, 1 /* local push */);
  if (!pushed)
    return NULL;
  pushed->is_push_stream = 1;

  pushed->state = HTTP2_STREAM_STATE_RESERVED_LOCAL;

  payload = alloc_header_block (
      conn, HTTP2_PUSH_PROMISE_ID_SIZE + HTTP2_INITIAL_HEADER_BLOCK_SIZE);
  if (!payload)
    {
      http2_stream_destroy (pushed);
      return NULL;
    }

  write_u31_be (payload, promised_id);

  header_block_len = http2_encode_headers (conn,
                                           request_headers,
                                           header_count,
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


int
http2_process_data (SocketHTTP2_Conn_T conn,
                    const SocketHTTP2_FrameHeader *header,
                    const unsigned char *payload)
{
  SocketHTTP2_Stream_T stream;
  SocketHTTP2_ErrorCode error;

  stream = http2_stream_lookup (conn, header->stream_id);
  if (!stream)
    {
      http2_send_stream_error (conn, header->stream_id, HTTP2_STREAM_CLOSED);
      return 0;
    }

  /* Extract padded DATA payload */
  size_t extra = 0;
  uint8_t pad_len = 0;
  if (http2_extract_padded (header, payload, &extra, &pad_len) < 0)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }
  const unsigned char *data = payload + extra;
  size_t data_len = header->length - extra - pad_len;

  error = http2_stream_transition (stream, HTTP2_FRAME_DATA, header->flags, 0);
  if (error != HTTP2_NO_ERROR)
    {
      http2_send_stream_error (conn, header->stream_id, error);
      return 0;
    }

  /* Check buffer space before writing full frame - defensive against app not
   * draining */
  if (SocketBuf_space (stream->recv_buf) < data_len)
    {
      SOCKET_LOG_WARN_MSG ("Insufficient recv_buf space for DATA frame on "
                           "stream %u: need %zu, space %zu",
                           stream->id,
                           data_len,
                           SocketBuf_space (stream->recv_buf));
      http2_send_stream_error (conn, stream->id, HTTP2_FLOW_CONTROL_ERROR);
      return -1;
    }

  if (http2_flow_consume_recv (conn, stream, header->length) < 0)
    {
      http2_send_connection_error (conn, HTTP2_FLOW_CONTROL_ERROR);
      return -1;
    }

  size_t written = SocketBuf_write (stream->recv_buf, data, data_len);
  assert (written == data_len); /* Should be full after space check */

  /* Track total DATA bytes received for Content-Length validation */
  stream->total_data_received += data_len;

  if (header->flags & HTTP2_FLAG_END_STREAM)
    {
      stream->end_stream_received = 1;

      /* Validate Content-Length when END_STREAM is received */
      if (stream->expected_content_length >= 0
          && (size_t)stream->expected_content_length
                 != stream->total_data_received)
        {
          SOCKET_LOG_ERROR_MSG ("Content-Length mismatch: expected %" PRId64
                                " bytes, "
                                "received %zu bytes",
                                stream->expected_content_length,
                                stream->total_data_received);
          http2_send_stream_error (conn, stream->id, HTTP2_PROTOCOL_ERROR);
          return -1;
        }
    }

  http2_emit_stream_event (conn, stream, HTTP2_EVENT_DATA_RECEIVED);
  return 0;
}

static int validate_new_stream_id (SocketHTTP2_Conn_T conn, uint32_t stream_id);

static SocketHTTP2_Stream_T
http2_get_or_create_stream_for_headers (SocketHTTP2_Conn_T conn,
                                        uint32_t stream_id)
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

      stream = http2_stream_create (conn, stream_id, 0 /* peer initiated */);
      if (!stream)
        {
          http2_send_stream_error (conn, stream_id, HTTP2_REFUSED_STREAM);
          return NULL;
        }
      stream->is_push_stream = 0;

      if (stream_id > conn->last_peer_stream_id)
        conn->last_peer_stream_id = stream_id;
    }

  return stream;
}

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

  /* After receiving GOAWAY, reject streams beyond the peer's last stream ID */
  if (conn->goaway_received && stream_id > conn->max_peer_stream_id)
    return -1;

  /* After sending GOAWAY, reject streams beyond our advertised last stream ID
   * (RFC 9113 §6.8: sender can discard frames for streams > last_stream_id) */
  if (conn->goaway_sent && stream_id > conn->last_peer_stream_id)
    return -1;

  return 0;
}

static int
extract_headers_payload (const SocketHTTP2_FrameHeader *header,
                         const unsigned char *payload,
                         const unsigned char **block,
                         size_t *block_len)
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

static int
process_complete_header_block (SocketHTTP2_Conn_T conn,
                               SocketHTTP2_Stream_T stream,
                               const unsigned char *block,
                               size_t len)
{
  if (http2_decode_headers (conn, stream, block, len) < 0)
    return -1;

  /* RFC 9113 §8.4: For push streams, validate method is safe (GET/HEAD) */
  if (stream->is_push_stream && validate_push_request_method (stream) < 0)
    {
      http2_send_stream_error (conn, stream->id, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  emit_header_event (conn, stream);

  if (stream->pending_end_stream)
    {
      stream->end_stream_received = 1;
      stream->pending_end_stream = 0;
    }

  return 0;
}

static int
setup_continuation_state (SocketHTTP2_Conn_T conn,
                          SocketHTTP2_Stream_T stream,
                          const unsigned char *block,
                          size_t len)
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

  /* Reset continuation counter for new header block */
  conn->continuation_frame_count = 0;
  conn->expecting_continuation = !(header->flags & HTTP2_FLAG_END_HEADERS);
  conn->continuation_stream_id = header->stream_id;

  error
      = http2_stream_transition (stream, HTTP2_FRAME_HEADERS, header->flags, 0);
  /* RFC 9113: PROTOCOL_ERROR in reserved states is a connection error */
  if (error == HTTP2_PROTOCOL_ERROR
      && (stream->state == HTTP2_STREAM_STATE_RESERVED_LOCAL
          || stream->state == HTTP2_STREAM_STATE_RESERVED_REMOTE))
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  if (error != HTTP2_NO_ERROR)
    {
      http2_send_stream_error (conn, header->stream_id, error);
      return 0;
    }

  if (extract_headers_payload (
          header, payload, &header_block, &header_block_len)
      < 0)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  max_header_list = conn->local_settings[SETTINGS_IDX_MAX_HEADER_LIST_SIZE];
  if (header_block_len > max_header_list)
    {
      http2_send_stream_error (
          conn, header->stream_id, HTTP2_ENHANCE_YOUR_CALM);
      return -1;
    }

  if (header->flags & HTTP2_FLAG_END_HEADERS)
    {
      return process_complete_header_block (
          conn, stream, header_block, header_block_len);
    }

  return setup_continuation_state (
      conn, stream, header_block, header_block_len);
}

int
http2_process_continuation (SocketHTTP2_Conn_T conn,
                            const SocketHTTP2_FrameHeader *header,
                            const unsigned char *payload)
{
  SocketHTTP2_Stream_T stream;
  size_t max_header_list;

  if (!conn->expecting_continuation
      || header->stream_id != conn->continuation_stream_id)
    {
      SOCKET_LOG_ERROR_MSG (
          "unexpected CONTINUATION frame for stream %u (expecting %u)",
          header->stream_id,
          conn->continuation_stream_id);
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  /* SECURITY: Enforce CONTINUATION frame limit BEFORE processing to prevent
   * memory exhaustion attacks. This protects against malicious clients sending
   * unlimited CONTINUATION frames. RFC 9113 does not specify a limit, but this
   * is a critical DoS protection measure. */
  conn->continuation_frame_count++;
  if (conn->continuation_frame_count > SOCKETHTTP2_MAX_CONTINUATION_FRAMES)
    {
      SOCKET_LOG_WARN_MSG (
          "SECURITY: HTTP/2 CONTINUATION frame limit exceeded: "
          "%" PRIu32 " > %u for stream %u - potential DoS attack detected",
          conn->continuation_frame_count,
          SOCKETHTTP2_MAX_CONTINUATION_FRAMES,
          header->stream_id);
      http2_send_connection_error (conn, HTTP2_ENHANCE_YOUR_CALM);
      return -1;
    }

  stream = http2_stream_lookup (conn, header->stream_id);
  if (!stream || !stream->header_block)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  max_header_list = conn->local_settings[SETTINGS_IDX_MAX_HEADER_LIST_SIZE];
  if (stream->header_block_len + header->length > max_header_list)
    {
      http2_send_stream_error (
          conn, header->stream_id, HTTP2_ENHANCE_YOUR_CALM);
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

  memcpy (
      stream->header_block + stream->header_block_len, payload, header->length);
  stream->header_block_len += header->length;

  if (header->flags & HTTP2_FLAG_END_HEADERS)
    {
      conn->expecting_continuation = 0;
      conn->continuation_stream_id = 0;
      conn->continuation_frame_count = 0; /* Reset for next header block */

      int result = process_complete_header_block (
          conn, stream, stream->header_block, stream->header_block_len);
      /* Clear pending header block */
      stream->header_block = NULL;
      stream->header_block_len = 0;
      stream->header_block_capacity = 0;
      return result;
    }

  return 0;
}

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
 * Validate PUSH_PROMISE request method per RFC 9113 Section 8.4.
 *
 * Promised requests MUST be safe (GET, HEAD) per RFC 9110 Section 9.2.1.
 * This prevents servers from pushing responses for unsafe methods like
 * POST, PUT, DELETE which could have side effects.
 *
 * @param stream The push stream with decoded headers.
 * @return 0 if method is safe (GET/HEAD), -1 otherwise.
 */
static int
validate_push_request_method (SocketHTTP2_Stream_T stream)
{
  for (size_t i = 0; i < stream->header_count; i++)
    {
      const SocketHPACK_Header *h = &stream->headers[i];

      /* Check for :method pseudo-header */
      if (h->name_len == STRLEN_LIT (":method")
          && memcmp (h->name, ":method", STRLEN_LIT (":method")) == 0)
        {
          /* RFC 9113 §8.4: Only GET and HEAD are valid for pushed requests */
          if ((h->value_len == STRLEN_LIT ("GET")
               && memcmp (h->value, "GET", STRLEN_LIT ("GET")) == 0)
              || (h->value_len == STRLEN_LIT ("HEAD")
                  && memcmp (h->value, "HEAD", STRLEN_LIT ("HEAD")) == 0))
            {
              return 0; /* Valid safe method */
            }

          SOCKET_LOG_WARN_MSG (
              "PUSH_PROMISE rejected: unsafe method '%.*s' (RFC 9113 §8.4)",
              (int)h->value_len,
              h->value);
          return -1; /* Invalid/unsafe method */
        }
    }

  /* :method pseudo-header not found - this is also a protocol error */
  SOCKET_LOG_WARN_MSG (
      "PUSH_PROMISE rejected: missing :method pseudo-header (RFC 9113 §8.4)");
  return -1;
}

/**
 * Validate promised stream ID per RFC 9113 Section 6.6/8.4.
 *
 * The promised stream identifier MUST be a valid choice for the next
 * stream sent by the sender (monotonically increasing, not in use).
 *
 * @return 0 on success, -1 on error (caller sends PROTOCOL_ERROR).
 */
static int
validate_promised_stream_id (SocketHTTP2_Conn_T conn, uint32_t promised_id)
{
  /* RFC 9113 §5.1.1: Stream ID 0 reserved, must be <= max */
  if (promised_id == 0 || promised_id > HTTP2_MAX_STREAM_ID)
    return -1;

  /* RFC 9113 §5.1.1: Server streams must be even (defensive check) */
  if ((promised_id & 1) != 0)
    return -1;

  /* RFC 9113 §5.1.1: Must be greater than any previously opened/reserved */
  if (promised_id <= conn->last_peer_stream_id)
    return -1;

  /* Stream must not already exist */
  if (http2_stream_lookup (conn, promised_id) != NULL)
    return -1;

  /* After GOAWAY, reject streams beyond the peer's limit */
  if (conn->goaway_received && promised_id > conn->max_peer_stream_id)
    return -1;

  return 0;
}

static int
extract_push_promise_payload (const SocketHTTP2_FrameHeader *header,
                              const unsigned char *payload,
                              uint32_t *promised_id,
                              const unsigned char **block,
                              size_t *block_len)
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

  *promised_id = read_u31_be (payload + offset);
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

  if (extract_push_promise_payload (
          header, payload, &promised_id, &header_block, &header_block_len)
      < 0)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  /* RFC 9113 §8.4: Validate promised stream ID */
  if (validate_promised_stream_id (conn, promised_id) < 0)
    {
      http2_send_connection_error (conn, HTTP2_PROTOCOL_ERROR);
      return -1;
    }

  promised = http2_stream_create (
      conn, promised_id, 1 /* local server-initiated push */);
  if (!promised)
    {
      http2_send_stream_error (conn, promised_id, HTTP2_REFUSED_STREAM);
      return 0;
    }
  promised->is_push_stream = 1;

  /* Track highest server-initiated stream ID for future validation */
  if (promised_id > conn->last_peer_stream_id)
    conn->last_peer_stream_id = promised_id;

  /* Reset continuation counter for new push header block */
  conn->continuation_frame_count = 0;
  conn->expecting_continuation = !(header->flags & HTTP2_FLAG_END_HEADERS);
  conn->continuation_stream_id
      = header->stream_id; /* Parent stream for CONTINUATION */

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

      /* RFC 9113 §8.4: Validate pushed request uses safe method (GET/HEAD) */
      if (validate_push_request_method (promised) < 0)
        {
          http2_send_stream_error (conn, promised_id, HTTP2_PROTOCOL_ERROR);
          return -1;
        }

      emit_header_event (conn, promised);

      if (promised->pending_end_stream)
        {
          promised->end_stream_received = 1;
          promised->pending_end_stream = 0;
        }
    }
  else
    {
      if (init_pending_header_block (
              conn, promised, header_block, header_block_len)
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

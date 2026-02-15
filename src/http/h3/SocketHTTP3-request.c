/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP3-request.c
 * @brief HTTP/3 request/response state machine (RFC 9114 Section 4).
 *
 * Implements QPACK encoding/decoding of headers using the static table
 * only (no dynamic table insertions), DATA frame encapsulation, and the
 * request send/receive state machines.
 */

#include "http/SocketHTTP3-private.h"
#include "http/SocketHTTP3-constants.h"
#include "http/SocketHTTP3-frame.h"
#include "http/SocketHTTP3-request.h"
#include "http/qpack/SocketQPACK.h"
#include "quic/SocketQUICVarInt.h"

#include <stdint.h>
#include <string.h>
#include <strings.h>

/* Compile-time string literal length (avoids strlen at runtime) */
#define STRLEN_LIT(s) (sizeof (s) - 1)

/* ============================================================================
 * Request Receive Buffer
 * ============================================================================
 */

#define H3_REQ_RECV_BUF_INIT_CAP 1024
#define H3_REQ_DATA_BUF_INIT_CAP 4096
#define H3_QPACK_ENCODE_BUF 8192
#define H3_MAX_HEADER_NAME 256
#define H3_MAX_HEADER_VALUE 4096
#define H3_MAX_COOKIE_HEADERS 32
#define H3_FIELD_SECTION_ENTRY_OVERHEAD 32

/* ============================================================================
 * QPACK Encoding Helpers (Static Table Only)
 *
 * Key static table indices for pseudo-headers (RFC 9204 Appendix A):
 *   0: :authority ""        15: :method CONNECT
 *   1: :path /              17: :method GET
 *  22: :scheme http         20: :method POST
 *  23: :scheme https        24: :status 103
 *  25: :status 200          26: :status 304
 *  27: :status 404          28: :status 503
 *  29: :status 100          30: :status 204
 *  31: :status 206          32: :status 302
 *  33: :status 400          34: :status 403
 *  35: :status 421          36: :status 425
 *  37: :status 500
 * ============================================================================
 */

/* Static table lookup uses h3_find_static_exact/name from private.h */
#define find_static_exact h3_find_static_exact
#define find_static_name h3_find_static_name

/**
 * @brief QPACK-encode a set of headers into a HEADERS frame payload.
 *
 * Uses static-table-only encoding: RIC=0, Base=0, no dynamic table refs.
 *
 * @param arena    Memory arena for allocations.
 * @param headers  HTTP headers to encode.
 * @param[out] out      Output buffer (arena-allocated).
 * @param[out] out_len  Output length.
 * @return 0 on success, negative error code on failure.
 */
int
h3_qpack_encode_headers (Arena_T arena,
                         const SocketHTTP_Headers_T headers,
                         uint8_t **out,
                         size_t *out_len)
{
  size_t buf_cap = H3_QPACK_ENCODE_BUF;
  unsigned char *buf = ALLOC (arena, buf_cap);
  size_t pos = 0;

  /* Write QPACK prefix: RIC=0, Base=0 (static-only, no dynamic refs) */
  size_t prefix_len;
  SocketQPACK_Result qres
      = SocketQPACK_encode_prefix (0, 0, 1, buf, buf_cap, &prefix_len);
  if (qres != QPACK_OK)
    return -(int)H3_INTERNAL_ERROR;
  pos += prefix_len;

  /* Encode each header */
  size_t count = SocketHTTP_Headers_count (headers);
  for (size_t i = 0; i < count; i++)
    {
      const SocketHTTP_Header *h = SocketHTTP_Headers_at (headers, i);
      if (h == NULL)
        return -(int)H3_INTERNAL_ERROR;

      size_t written = 0;

      /* Try exact match in static table */
      int exact_idx
          = find_static_exact (h->name, h->name_len, h->value, h->value_len);
      if (exact_idx >= 0)
        {
          qres = SocketQPACK_encode_indexed_field (
              buf + pos, buf_cap - pos, (uint64_t)exact_idx, true, &written);
          if (qres != QPACK_OK)
            return -(int)H3_INTERNAL_ERROR;
          pos += written;
          continue;
        }

      /* Try name match in static table */
      int name_idx = find_static_name (h->name, h->name_len);
      if (name_idx >= 0)
        {
          qres = SocketQPACK_encode_literal_name_ref (
              buf + pos,
              buf_cap - pos,
              true,
              (uint64_t)name_idx,
              false,
              (const unsigned char *)h->value,
              h->value_len,
              false,
              &written);
          if (qres != QPACK_OK)
            return -(int)H3_INTERNAL_ERROR;
          pos += written;
          continue;
        }

      /* Literal name + literal value */
      qres = SocketQPACK_encode_literal_field_literal_name (
          buf + pos,
          buf_cap - pos,
          (const unsigned char *)h->name,
          h->name_len,
          false,
          (const unsigned char *)h->value,
          h->value_len,
          false,
          false,
          &written);
      if (qres != QPACK_OK)
        return -(int)H3_INTERNAL_ERROR;
      pos += written;
    }

  *out = buf;
  *out_len = pos;
  return 0;
}

/* ============================================================================
 * QPACK Decoding Helpers
 * ============================================================================
 */

/**
 * @brief Add a decoded header, dispatching pseudo vs regular.
 */
static int
h3_headers_add (SocketHTTP_Headers_T hdrs,
                const char *name,
                size_t name_len,
                const char *value,
                size_t value_len)
{
  if (name_len > 0 && name[0] == ':')
    return SocketHTTP_Headers_add_pseudo_n (
        hdrs, name, name_len, value, value_len);
  return SocketHTTP_Headers_add_n (hdrs, name, name_len, value, value_len);
}

/**
 * @brief Decode an Indexed Field Line (§4.5.2).
 */
static int
decode_indexed_field (SocketHTTP_Headers_T hdrs,
                      const uint8_t *data,
                      size_t len,
                      size_t *consumed)
{
  uint64_t index;
  int is_static;
  SocketQPACK_Result qres = SocketQPACK_decode_indexed_field (
      data, len, &index, &is_static, consumed);
  if (qres != QPACK_OK)
    return -1;

  if (!is_static)
    return -1; /* no dynamic table */

  const char *name, *value;
  size_t name_len, value_len;
  qres = SocketQPACK_static_table_get (
      index, &name, &name_len, &value, &value_len);
  if (qres != QPACK_OK)
    return -1;

  return h3_headers_add (hdrs, name, name_len, value, value_len);
}

/**
 * @brief Decode a Literal with Name Reference (§4.5.4).
 */
static int
decode_literal_nameref (SocketHTTP_Headers_T hdrs,
                        Arena_T arena,
                        const uint8_t *data,
                        size_t len,
                        size_t *consumed)
{
  SocketQPACK_LiteralNameRef ref;
  SocketQPACK_Result qres = SocketQPACK_decode_literal_name_ref_arena (
      data, len, arena, &ref, consumed);
  if (qres != QPACK_OK)
    return -1;

  if (!ref.is_static)
    return -1; /* no dynamic table */

  const char *name;
  size_t name_len;
  qres = SocketQPACK_static_table_get (
      ref.name_index, &name, &name_len, NULL, NULL);
  if (qres != QPACK_OK)
    return -1;

  return h3_headers_add (hdrs, name, name_len, ref.value, ref.value_len);
}

/**
 * @brief Decode a Literal with Literal Name (§4.5.6).
 */
static int
decode_literal_field (SocketHTTP_Headers_T hdrs,
                      const uint8_t *data,
                      size_t len,
                      size_t *consumed)
{
  unsigned char name_buf[H3_MAX_HEADER_NAME];
  unsigned char value_buf[H3_MAX_HEADER_VALUE];
  size_t name_len, value_len;
  bool never_indexed;
  SocketQPACK_Result qres
      = SocketQPACK_decode_literal_field_literal_name (data,
                                                       len,
                                                       name_buf,
                                                       sizeof (name_buf),
                                                       &name_len,
                                                       value_buf,
                                                       sizeof (value_buf),
                                                       &value_len,
                                                       &never_indexed,
                                                       consumed);
  if (qres != QPACK_OK)
    return -1;

  return h3_headers_add (hdrs,
                         (const char *)name_buf,
                         name_len,
                         (const char *)value_buf,
                         value_len);
}

/**
 * @brief QPACK-decode a field section into an HTTP headers collection.
 *
 * Handles all five field line representation types. Since we use static-
 * table-only encoding (RIC=0), post-base references will return errors
 * for now (they require dynamic table).
 *
 * @param arena    Memory arena.
 * @param data     QPACK-encoded field section (after HEADERS frame header).
 * @param len      Length of encoded data.
 * @param[out] headers  Output header collection.
 * @return 0 on success, negative error code on failure.
 */
int
h3_qpack_decode_headers (Arena_T arena,
                         const uint8_t *data,
                         size_t len,
                         SocketHTTP_Headers_T *headers_out)
{
  *headers_out = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_T hdrs = *headers_out;

  size_t pos = 0;

  /* Decode QPACK prefix (RIC, Base) */
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed;
  SocketQPACK_Result qres = SocketQPACK_decode_prefix (
      data,
      len,
      1, /* max_entries — 1 to avoid div-by-zero; RIC must be 0 */
      0, /* total_insert_count — no dynamic table */
      &prefix,
      &consumed);
  if (qres != QPACK_OK)
    return -(int)QPACK_DECOMPRESSION_FAILED;

  /* Static-table-only: Required Insert Count must be 0 */
  if (prefix.required_insert_count != 0)
    return -(int)QPACK_DECOMPRESSION_FAILED;

  pos += consumed;

  /* Decode field lines */
  while (pos < len)
    {
      uint8_t first_byte = data[pos];
      int rc;

      if (first_byte & 0x80)
        {
          rc = decode_indexed_field (hdrs, data + pos, len - pos, &consumed);
        }
      else if ((first_byte & 0xC0) == 0x40)
        {
          rc = decode_literal_nameref (
              hdrs, arena, data + pos, len - pos, &consumed);
        }
      else if ((first_byte & 0xE0) == 0x20)
        {
          rc = decode_literal_field (hdrs, data + pos, len - pos, &consumed);
        }
      else
        {
          /* Post-base references (§4.5.3, §4.5.5) — needs dynamic table */
          return -(int)QPACK_DECOMPRESSION_FAILED;
        }

      if (rc < 0)
        return -(int)QPACK_DECOMPRESSION_FAILED;

      pos += consumed;
    }

  return 0;
}

/* ============================================================================
 * Cookie Concatenation (RFC 9114 §4.2.1)
 * ============================================================================
 */

static void
h3_coalesce_cookies (Arena_T arena, SocketHTTP_Headers_T headers)
{
  const char *values[H3_MAX_COOKIE_HEADERS];
  size_t n = SocketHTTP_Headers_get_all_n (
      headers, "cookie", 6, values, H3_MAX_COOKIE_HEADERS);
  if (n <= 1)
    return;

  /* Calculate total length and cache string lengths to avoid redundant strlen() */
  size_t lengths[H3_MAX_COOKIE_HEADERS];
  size_t total = 0;
  for (size_t i = 0; i < n; i++)
    {
      lengths[i] = strlen (values[i]);
      total += lengths[i];
      if (i > 0)
        total += 2; /* "; " */
    }

  char *combined = ALLOC (arena, total + 1);
  size_t pos = 0;
  for (size_t i = 0; i < n; i++)
    {
      if (i > 0)
        {
          memcpy (combined + pos, "; ", 2);
          pos += 2;
        }
      memcpy (combined + pos, values[i], lengths[i]);
      pos += lengths[i];
    }
  combined[pos] = '\0';

  SocketHTTP_Headers_remove_all (headers, "cookie");
  SocketHTTP_Headers_add_n (headers, "cookie", 6, combined, pos);
}

/* ============================================================================
 * Request Struct
 * ============================================================================
 */

struct SocketHTTP3_Request
{
  SocketHTTP3_Conn_T conn;
  Arena_T arena;
  uint64_t stream_id;

  /* Send state */
  SocketHTTP3_ReqSendState send_state;
  int send_end_stream;

  /* Recv state */
  SocketHTTP3_ReqRecvState recv_state;
  int recv_end_stream;
  int cancelled;

  /* Frame parsing */
  int first_frame_seen;
  int trailers_received;

  /* Receive buffer for HEADERS payload */
  uint8_t *recv_buf;
  size_t recv_buf_len;
  size_t recv_buf_cap;

  /* Receive buffer for DATA payload */
  uint8_t *data_buf;
  size_t data_buf_len;
  size_t data_buf_cap;

  /* Decoded response headers */
  SocketHTTP_Headers_T recv_headers;
  SocketHTTP_Headers_T recv_trailers;
  int status_code;
  int64_t expected_content_length;
  size_t total_data_received;

  /* Per-stream send buffer */
  H3_StreamBuf send_buf;

#ifdef SOCKET_HAS_H3_PUSH
  int is_push_stream;
  uint64_t push_id;
#endif
};

/* ============================================================================
 * Request Lifecycle
 * ============================================================================
 */

SocketHTTP3_Request_T
SocketHTTP3_Request_new (SocketHTTP3_Conn_T conn)
{
  if (conn == NULL)
    return NULL;
  if (conn->state != H3_CONN_STATE_OPEN)
    return NULL;

  uint64_t stream_id = conn->next_bidi_stream_id;
  size_t index = (size_t)(stream_id / 4);
  if (index >= H3_MAX_CONCURRENT_REQUESTS)
    return NULL;

  struct SocketHTTP3_Request *req
      = CALLOC (conn->arena, 1, sizeof (struct SocketHTTP3_Request));

  req->conn = conn;
  req->arena = conn->arena;
  req->stream_id = stream_id;
  req->send_state = H3_REQ_SEND_IDLE;
  req->recv_state = H3_REQ_RECV_IDLE;
  req->cancelled = 0;
  req->first_frame_seen = 0;
  req->trailers_received = 0;
  req->recv_headers = NULL;
  req->recv_trailers = NULL;
  req->status_code = 0;
  req->expected_content_length = -1;
  req->total_data_received = 0;
  req->send_end_stream = 0;
  req->recv_end_stream = 0;

  /* Initialize receive buffer */
  req->recv_buf = ALLOC (conn->arena, H3_REQ_RECV_BUF_INIT_CAP);
  req->recv_buf_len = 0;
  req->recv_buf_cap = H3_REQ_RECV_BUF_INIT_CAP;

  /* Initialize data buffer */
  req->data_buf = ALLOC (conn->arena, H3_REQ_DATA_BUF_INIT_CAP);
  req->data_buf_len = 0;
  req->data_buf_cap = H3_REQ_DATA_BUF_INIT_CAP;

  /* Initialize send buffer */
  stream_buf_init (&req->send_buf, conn->arena, stream_id);

  /* Register in connection */
  conn->requests[index] = req;
  conn->request_count++;
  conn->next_bidi_stream_id += 4;

  return req;
}

SocketHTTP3_Request_T
SocketHTTP3_Request_new_incoming (SocketHTTP3_Conn_T conn, uint64_t stream_id)
{
  if (conn == NULL)
    return NULL;
  if (conn->state != H3_CONN_STATE_OPEN)
    return NULL;

  /* Must be client-initiated bidi (stream_id % 4 == 0) */
  if (stream_id % 4 != 0)
    return NULL;

  size_t index = (size_t)(stream_id / 4);
  if (index >= H3_MAX_CONCURRENT_REQUESTS)
    return NULL;

  /* Already exists? */
  if (conn->requests[index] != NULL)
    return NULL;

  struct SocketHTTP3_Request *req
      = CALLOC (conn->arena, 1, sizeof (struct SocketHTTP3_Request));

  req->conn = conn;
  req->arena = conn->arena;
  req->stream_id = stream_id;
  req->send_state = H3_REQ_SEND_IDLE;
  req->recv_state = H3_REQ_RECV_IDLE;
  req->cancelled = 0;
  req->first_frame_seen = 0;
  req->trailers_received = 0;
  req->recv_headers = NULL;
  req->recv_trailers = NULL;
  req->status_code = 0;
  req->expected_content_length = -1;
  req->total_data_received = 0;
  req->send_end_stream = 0;
  req->recv_end_stream = 0;

  /* Initialize receive buffer */
  req->recv_buf = ALLOC (conn->arena, H3_REQ_RECV_BUF_INIT_CAP);
  req->recv_buf_len = 0;
  req->recv_buf_cap = H3_REQ_RECV_BUF_INIT_CAP;

  /* Initialize data buffer */
  req->data_buf = ALLOC (conn->arena, H3_REQ_DATA_BUF_INIT_CAP);
  req->data_buf_len = 0;
  req->data_buf_cap = H3_REQ_DATA_BUF_INIT_CAP;

  /* Initialize send buffer */
  stream_buf_init (&req->send_buf, conn->arena, stream_id);

  /* Register in connection (don't advance next_bidi_stream_id) */
  conn->requests[index] = req;
  conn->request_count++;

  return req;
}

/* ============================================================================
 * Push Request Constructor (RFC 9114 §4.6)
 * ============================================================================
 */

#ifdef SOCKET_HAS_H3_PUSH
SocketHTTP3_Request_T
SocketHTTP3_Request_new_push (SocketHTTP3_Conn_T conn,
                              uint64_t stream_id,
                              uint64_t push_id)
{
  if (conn == NULL)
    return NULL;
  if (conn->state != H3_CONN_STATE_OPEN)
    return NULL;

  struct SocketHTTP3_Request *req
      = CALLOC (conn->arena, 1, sizeof (struct SocketHTTP3_Request));

  req->conn = conn;
  req->arena = conn->arena;
  req->stream_id = stream_id;
  req->send_state = H3_REQ_SEND_IDLE;
  req->recv_state = H3_REQ_RECV_IDLE;
  req->cancelled = 0;
  req->first_frame_seen = 0;
  req->trailers_received = 0;
  req->recv_headers = NULL;
  req->recv_trailers = NULL;
  req->status_code = 0;
  req->expected_content_length = -1;
  req->total_data_received = 0;
  req->send_end_stream = 0;
  req->recv_end_stream = 0;

  req->recv_buf = ALLOC (conn->arena, H3_REQ_RECV_BUF_INIT_CAP);
  req->recv_buf_len = 0;
  req->recv_buf_cap = H3_REQ_RECV_BUF_INIT_CAP;

  req->data_buf = ALLOC (conn->arena, H3_REQ_DATA_BUF_INIT_CAP);
  req->data_buf_len = 0;
  req->data_buf_cap = H3_REQ_DATA_BUF_INIT_CAP;

  stream_buf_init (&req->send_buf, conn->arena, stream_id);

  req->is_push_stream = 1;
  req->push_id = push_id;

  return req;
}
#endif /* SOCKET_HAS_H3_PUSH */

/* ============================================================================
 * Send Side
 * ============================================================================
 */

int
SocketHTTP3_Request_send_headers (SocketHTTP3_Request_T req,
                                  const SocketHTTP_Headers_T headers,
                                  int end_stream)
{
  if (req == NULL || headers == NULL)
    return -1;
  if (req->cancelled)
    return -(int)H3_REQUEST_CANCELLED;
  if (req->send_state != H3_REQ_SEND_IDLE)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;

    /* Validate headers — push streams send responses, not requests */
#ifdef SOCKET_HAS_H3_PUSH
  int rc = req->is_push_stream ? SocketHTTP3_validate_response_headers (headers)
                               : SocketHTTP3_validate_request_headers (headers);
#else
  int rc = SocketHTTP3_validate_request_headers (headers);
#endif
  if (rc != 0)
    return rc;

  /* QPACK-encode headers */
  uint8_t *qpack_data;
  size_t qpack_len;
  rc = h3_qpack_encode_headers (req->arena, headers, &qpack_data, &qpack_len);
  if (rc != 0)
    return rc;

  /* Build HEADERS frame: header + QPACK payload */
  uint8_t frame_hdr[16];
  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_HEADERS, qpack_len, frame_hdr, sizeof (frame_hdr));
  if (hdr_len < 0)
    return -(int)H3_INTERNAL_ERROR;

  stream_buf_reset (&req->send_buf);
  stream_buf_append (&req->send_buf, req->arena, frame_hdr, (size_t)hdr_len);
  stream_buf_append (&req->send_buf, req->arena, qpack_data, qpack_len);

  h3_output_queue_push (&req->conn->output,
                        req->stream_id,
                        req->send_buf.data,
                        req->send_buf.len);

  req->send_state = H3_REQ_SEND_HEADERS_SENT;
  if (end_stream)
    {
      req->send_end_stream = 1;
      req->send_state = H3_REQ_SEND_DONE;
    }

  return 0;
}

int
SocketHTTP3_Request_send_data (SocketHTTP3_Request_T req,
                               const void *data,
                               size_t len,
                               int end_stream)
{
  if (req == NULL)
    return -1;
  if (req->cancelled)
    return -(int)H3_REQUEST_CANCELLED;
  if (req->send_state != H3_REQ_SEND_HEADERS_SENT
      && req->send_state != H3_REQ_SEND_BODY_SENT)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;
  if (req->send_end_stream)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;

  /* Build DATA frame */
  uint8_t frame_hdr[16];
  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_DATA, len, frame_hdr, sizeof (frame_hdr));
  if (hdr_len < 0)
    return -(int)H3_INTERNAL_ERROR;

  stream_buf_reset (&req->send_buf);
  stream_buf_append (&req->send_buf, req->arena, frame_hdr, (size_t)hdr_len);
  if (len > 0)
    stream_buf_append (&req->send_buf, req->arena, data, len);

  h3_output_queue_push (&req->conn->output,
                        req->stream_id,
                        req->send_buf.data,
                        req->send_buf.len);

  req->send_state = H3_REQ_SEND_BODY_SENT;
  if (end_stream)
    {
      req->send_end_stream = 1;
      req->send_state = H3_REQ_SEND_DONE;
    }

  return 0;
}

int
SocketHTTP3_Request_send_trailers (SocketHTTP3_Request_T req,
                                   const SocketHTTP_Headers_T trailers)
{
  if (req == NULL || trailers == NULL)
    return -1;
  if (req->cancelled)
    return -(int)H3_REQUEST_CANCELLED;
  if (req->send_state != H3_REQ_SEND_HEADERS_SENT
      && req->send_state != H3_REQ_SEND_BODY_SENT)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;
  if (req->send_end_stream)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;

  /* QPACK-encode trailers (no pseudo-headers allowed in trailers) */
  uint8_t *qpack_data;
  size_t qpack_len;
  int rc
      = h3_qpack_encode_headers (req->arena, trailers, &qpack_data, &qpack_len);
  if (rc != 0)
    return rc;

  /* Build HEADERS frame for trailers */
  uint8_t frame_hdr[16];
  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_HEADERS, qpack_len, frame_hdr, sizeof (frame_hdr));
  if (hdr_len < 0)
    return -(int)H3_INTERNAL_ERROR;

  stream_buf_reset (&req->send_buf);
  stream_buf_append (&req->send_buf, req->arena, frame_hdr, (size_t)hdr_len);
  stream_buf_append (&req->send_buf, req->arena, qpack_data, qpack_len);

  h3_output_queue_push (&req->conn->output,
                        req->stream_id,
                        req->send_buf.data,
                        req->send_buf.len);

  req->send_state = H3_REQ_SEND_TRAILERS_SENT;
  req->send_end_stream = 1;

  return 0;
}

/* ============================================================================
 * Receive Side — Feed
 * ============================================================================
 */

/* Buffer append wrappers using generic h3_growbuf_append() */
#define recv_buf_append(req, data, len)    \
  h3_growbuf_append ((req)->arena,         \
                     &(req)->recv_buf,     \
                     &(req)->recv_buf_len, \
                     &(req)->recv_buf_cap, \
                     (data),               \
                     (len))

#define data_buf_append(req, data, len)    \
  h3_growbuf_append ((req)->arena,         \
                     &(req)->data_buf,     \
                     &(req)->data_buf_len, \
                     &(req)->data_buf_cap, \
                     (data),               \
                     (len))

/**
 * @brief Parse status code from :status header value.
 * @return Status code (100-599), or -1 on invalid format.
 */
static int
parse_status_code (const char *value, size_t value_len)
{
  if (value_len != 3)
    return -1;
  int code = 0;
  for (size_t i = 0; i < 3; i++)
    {
      if (value[i] < '0' || value[i] > '9')
        return -1;
      code = code * 10 + (value[i] - '0');
    }
  if (code < 100 || code > 599)
    return -1;
  return code;
}

static int
h3_parse_content_length_value (const char *value,
                               size_t value_len,
                               int64_t *out)
{
  if (value == NULL || out == NULL)
    return -1;

  int64_t v = 0;
  if (value_len == 0)
    return -1;

  for (size_t i = 0; i < value_len; i++)
    {
      unsigned char c = (unsigned char)value[i];
      if (c < '0' || c > '9')
        return -1;
      int digit = (int)(c - '0');
      if (v > (INT64_MAX - digit) / 10)
        return -1;
      v = v * 10 + digit;
    }

  /* Keep comparisons safe on 32-bit. */
  if ((uint64_t)v > (uint64_t)SIZE_MAX)
    return -1;

  *out = v;
  return 0;
}

typedef struct
{
  int found;
  int error;
  int64_t value;
} H3_ContentLengthScan;

static int
h3_content_length_scan_cb (const char *name,
                           size_t name_len,
                           const char *value,
                           size_t value_len,
                           void *userdata)
{
  H3_ContentLengthScan *scan = (H3_ContentLengthScan *)userdata;

  if (scan == NULL)
    return 1;

  if (name_len != STRLEN_LIT ("content-length")
      || strncasecmp (name, "content-length", STRLEN_LIT ("content-length"))
             != 0)
    return 0;

  int64_t parsed;
  if (h3_parse_content_length_value (value, value_len, &parsed) < 0)
    {
      scan->error = 1;
      return 1;
    }

  if (!scan->found)
    {
      scan->found = 1;
      scan->value = parsed;
      return 0;
    }

  if (parsed != scan->value)
    {
      scan->error = 1;
      return 1;
    }

  return 0;
}

/**
 * @brief Enforce SETTINGS_MAX_FIELD_SECTION_SIZE for decoded headers.
 *
 * RFC 9114 reuses HTTP field section sizing rules: sum(name_len + value_len +
 * 32) across all header fields.
 */
static int
validate_field_section_size (const struct SocketHTTP3_Request *req,
                             const SocketHTTP_Headers_T headers)
{
  uint64_t max_size;
  uint64_t total = 0;
  size_t count;

  if (req == NULL || req->conn == NULL || headers == NULL)
    return -(int)H3_INTERNAL_ERROR;

  max_size = req->conn->local_settings.max_field_section_size;
  if (max_size == UINT64_MAX)
    return 0; /* No explicit limit configured */

  count = SocketHTTP_Headers_count (headers);
  for (size_t i = 0; i < count; i++)
    {
      const SocketHTTP_Header *h = SocketHTTP_Headers_at (headers, i);
      uint64_t entry_size;

      if (h == NULL)
        return -(int)H3_MESSAGE_ERROR;

      entry_size = (uint64_t)h->name_len + (uint64_t)h->value_len
                   + (uint64_t)H3_FIELD_SECTION_ENTRY_OVERHEAD;

      if (entry_size > max_size || total > max_size - entry_size)
        return -(int)H3_MESSAGE_ERROR;

      total += entry_size;
    }

  return 0;
}

/**
 * @brief Handle a received HEADERS frame on a request stream.
 *
 * Decodes QPACK, validates, extracts status code and content-length.
 * Handles both initial response headers and trailers.
 */
static int
handle_headers_frame (struct SocketHTTP3_Request *req,
                      const uint8_t *payload,
                      size_t payload_len)
{
  SocketHTTP_Headers_T hdrs;
  int rc;

  if (req->conn != NULL
      && req->conn->local_settings.max_field_section_size != UINT64_MAX
      && payload_len > req->conn->local_settings.max_field_section_size)
    return -(int)H3_MESSAGE_ERROR;

  if (req->recv_state == H3_REQ_RECV_BODY_RECEIVING
      || (req->recv_state == H3_REQ_RECV_HEADERS_RECEIVED
          && req->status_code >= 200))
    {
      /* Trailers: decode and retain for callers. */
      rc = h3_qpack_decode_headers (req->arena, payload, payload_len, &hdrs);
      if (rc != 0)
        return rc;

      for (size_t i = 0; i < SocketHTTP_Headers_count (hdrs); i++)
        {
          const SocketHTTP_Header *h = SocketHTTP_Headers_at (hdrs, i);
          if (h != NULL && h->name_len > 0 && h->name[0] == ':')
            return -(int)H3_MESSAGE_ERROR;
        }

      req->recv_trailers = hdrs;
      req->trailers_received = 1;
      return 0;
    }

  /* Decode QPACK headers */
  rc = h3_qpack_decode_headers (req->arena, payload, payload_len, &hdrs);
  if (rc != 0)
    return rc;

  h3_coalesce_cookies (req->arena, hdrs);

  rc = validate_field_section_size (req, hdrs);
  if (rc != 0)
    return rc;

  if (req->conn != NULL && req->conn->role == H3_ROLE_SERVER)
    {
      rc = SocketHTTP3_validate_request_headers (hdrs);
      if (rc != 0)
        return rc;
      req->status_code = 0;
    }
  else
    {
      const char *status_val;
      int code;

      rc = SocketHTTP3_validate_response_headers (hdrs);
      if (rc != 0)
        return rc;

      status_val = SocketHTTP_Headers_get_n (hdrs, ":status", 7);
      if (status_val == NULL)
        return -(int)H3_MESSAGE_ERROR;

      code = parse_status_code (status_val, strlen (status_val));
      if (code < 0)
        return -(int)H3_MESSAGE_ERROR;
      req->status_code = code;
    }

  req->recv_headers = hdrs;

  /* Content-Length: validate all values match (RFC 9114 / RFC 9110 rules). */
  req->expected_content_length = -1;
  H3_ContentLengthScan scan = { 0 };
  (void)SocketHTTP_Headers_iterate (hdrs, h3_content_length_scan_cb, &scan);
  if (scan.error)
    return -(int)H3_MESSAGE_ERROR;
  if (scan.found)
    req->expected_content_length = scan.value;

  req->recv_state = H3_REQ_RECV_HEADERS_RECEIVED;
  return 0;
}

/**
 * @brief Handle a received DATA frame on a request stream.
 */
static int
handle_data_frame (struct SocketHTTP3_Request *req,
                   const uint8_t *payload,
                   size_t payload_len)
{
  if (req->recv_state == H3_REQ_RECV_IDLE)
    return -(int)H3_FRAME_UNEXPECTED;
  if (req->trailers_received)
    return -(int)H3_FRAME_UNEXPECTED;

  if (data_buf_append (req, payload, payload_len) < 0)
    return -(int)H3_INTERNAL_ERROR;

  size_t new_total;
  if (!SocketSecurity_check_add (
          req->total_data_received, payload_len, &new_total))
    return -(int)H3_MESSAGE_ERROR;
  req->total_data_received = new_total;

  if (req->recv_state == H3_REQ_RECV_HEADERS_RECEIVED)
    req->recv_state = H3_REQ_RECV_BODY_RECEIVING;
  return 0;
}

int
SocketHTTP3_Request_feed (SocketHTTP3_Request_T req,
                          const uint8_t *data,
                          size_t len,
                          int fin)
{
  if (req == NULL)
    return -1;
  if (req->cancelled)
    return 0;
  if (req->recv_state == H3_REQ_RECV_COMPLETE)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;

  /* Append to receive buffer */
  if (len > 0)
    {
      if (recv_buf_append (req, data, len) < 0)
        return -(int)H3_INTERNAL_ERROR;
    }

  /* Process frames from receive buffer */
  while (req->recv_buf_len > 0)
    {
      SocketHTTP3_FrameHeader fhdr;
      size_t consumed;
      SocketHTTP3_ParseResult pres = SocketHTTP3_Frame_parse_header (
          req->recv_buf, req->recv_buf_len, &fhdr, &consumed);

      if (pres == HTTP3_PARSE_INCOMPLETE)
        break;
      if (pres == HTTP3_PARSE_ERROR)
        return -(int)H3_FRAME_ERROR;

      /* Check if we have the full payload */
      if (consumed + fhdr.length > req->recv_buf_len)
        break;

      const uint8_t *payload = req->recv_buf + consumed;
      size_t payload_len = (size_t)fhdr.length;
      size_t total_consumed = consumed + payload_len;

      /* Validate frame on request stream */
      uint64_t err = SocketHTTP3_Frame_validate (
          fhdr.type, HTTP3_STREAM_REQUEST, !req->first_frame_seen);
      if (err != 0)
        return -(int)err;

      req->first_frame_seen = 1;

      int rc = 0;
      switch (fhdr.type)
        {
        case HTTP3_FRAME_HEADERS:
          rc = handle_headers_frame (req, payload, payload_len);
          break;
        case HTTP3_FRAME_DATA:
          rc = handle_data_frame (req, payload, payload_len);
          break;
#ifdef SOCKET_HAS_H3_PUSH
        case HTTP3_FRAME_PUSH_PROMISE:
          if (req->conn->role != H3_ROLE_CLIENT)
            return -(int)H3_FRAME_UNEXPECTED;
          rc = h3_conn_recv_push_promise (
              req->conn, req->stream_id, payload, payload_len);
          break;
#endif
        default:
          break;
        }
      if (rc != 0)
        return rc;

      /* Consume parsed bytes */
      H3_BUF_CONSUME (req->recv_buf, req->recv_buf_len, total_consumed);
    }

  /* Handle FIN */
  if (fin)
    {
      req->recv_end_stream = 1;

      if (req->recv_state == H3_REQ_RECV_IDLE)
        return -(int)H3_REQUEST_INCOMPLETE;

      /* Content-Length mismatch check */
      if (req->expected_content_length >= 0
          && (size_t)req->expected_content_length != req->total_data_received)
        return -(int)H3_MESSAGE_ERROR;

      req->recv_state = H3_REQ_RECV_COMPLETE;
    }

  return 0;
}

/* ============================================================================
 * Receive Side — Read
 * ============================================================================
 */

int
SocketHTTP3_Request_recv_headers (SocketHTTP3_Request_T req,
                                  SocketHTTP_Headers_T *headers,
                                  int *status_code)
{
  if (req == NULL)
    return -1;
  if (req->recv_state < H3_REQ_RECV_HEADERS_RECEIVED)
    return -1;

  if (headers != NULL)
    *headers = req->recv_headers;
  if (status_code != NULL)
    *status_code = req->status_code;
  return 0;
}

int
SocketHTTP3_Request_recv_trailers (SocketHTTP3_Request_T req,
                                   SocketHTTP_Headers_T *trailers)
{
  if (req == NULL || !req->trailers_received || req->recv_trailers == NULL)
    return -1;
  if (trailers != NULL)
    *trailers = req->recv_trailers;
  return 0;
}

ssize_t
SocketHTTP3_Request_recv_data (SocketHTTP3_Request_T req,
                               void *buf,
                               size_t buflen,
                               int *end_stream)
{
  if (req == NULL || buf == NULL)
    return -1;

  size_t to_copy = req->data_buf_len;
  if (to_copy > buflen)
    to_copy = buflen;

  if (to_copy > 0)
    {
      memcpy (buf, req->data_buf, to_copy);
      H3_BUF_CONSUME (req->data_buf, req->data_buf_len, to_copy);
    }

  if (end_stream != NULL)
    *end_stream = (req->recv_end_stream && req->data_buf_len == 0) ? 1 : 0;

  return (ssize_t)to_copy;
}

/* ============================================================================
 * Control
 * ============================================================================
 */

int
SocketHTTP3_Request_cancel (SocketHTTP3_Request_T req)
{
  if (req == NULL)
    return -1;
  if (req->cancelled)
    return -1;
  req->cancelled = 1;
  return 0;
}

uint64_t
SocketHTTP3_Request_stream_id (SocketHTTP3_Request_T req)
{
  if (req == NULL)
    return UINT64_MAX;
  return req->stream_id;
}

SocketHTTP3_ReqSendState
SocketHTTP3_Request_send_state (SocketHTTP3_Request_T req)
{
  if (req == NULL)
    return H3_REQ_SEND_DONE;
  return req->send_state;
}

SocketHTTP3_ReqRecvState
SocketHTTP3_Request_recv_state (SocketHTTP3_Request_T req)
{
  if (req == NULL)
    return H3_REQ_RECV_COMPLETE;
  return req->recv_state;
}

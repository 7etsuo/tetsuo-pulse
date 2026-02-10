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

#include <string.h>

/* ============================================================================
 * Request Receive Buffer
 * ============================================================================
 */

#define H3_REQ_RECV_BUF_INIT_CAP 1024
#define H3_REQ_DATA_BUF_INIT_CAP 4096

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

/**
 * @brief Try to find an exact match in the static table.
 *
 * @return Static table index (0-98), or -1 if no exact match found.
 */
static int
find_static_exact (const char *name,
                   size_t name_len,
                   const char *value,
                   size_t value_len)
{
  for (uint64_t i = 0; i < SOCKETQPACK_STATIC_TABLE_SIZE; i++)
    {
      const char *sn;
      size_t snl;
      const char *sv;
      size_t svl;
      if (SocketQPACK_static_table_get (i, &sn, &snl, &sv, &svl) != QPACK_OK)
        continue;
      if (snl == name_len && svl == value_len
          && memcmp (sn, name, name_len) == 0
          && memcmp (sv, value, value_len) == 0)
        return (int)i;
    }
  return -1;
}

/**
 * @brief Try to find a name-only match in the static table.
 *
 * @return Static table index (0-98), or -1 if no name match found.
 */
static int
find_static_name (const char *name, size_t name_len)
{
  for (uint64_t i = 0; i < SOCKETQPACK_STATIC_TABLE_SIZE; i++)
    {
      const char *sn;
      size_t snl;
      if (SocketQPACK_static_table_get (i, &sn, &snl, NULL, NULL) != QPACK_OK)
        continue;
      if (snl == name_len && memcmp (sn, name, name_len) == 0)
        return (int)i;
    }
  return -1;
}

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
static int
h3_qpack_encode_headers (Arena_T arena,
                         const SocketHTTP_Headers_T headers,
                         uint8_t **out,
                         size_t *out_len)
{
  /* Allocate a work buffer — 8KB should handle most header sets */
  size_t buf_cap = 8192;
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
              buf + pos, buf_cap - pos, (uint64_t)exact_idx, 1, &written);
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
static int
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
  pos += consumed;

  /* Decode field lines */
  while (pos < len)
    {
      uint8_t first_byte = data[pos];

      if (first_byte & 0x80)
        {
          /* 1xxxxxxx: Indexed Field Line (§4.5.2) */
          uint64_t index;
          int is_static;
          qres = SocketQPACK_decode_indexed_field (
              data + pos, len - pos, &index, &is_static, &consumed);
          if (qres != QPACK_OK)
            return -(int)QPACK_DECOMPRESSION_FAILED;
          pos += consumed;

          if (!is_static)
            return -(int)QPACK_DECOMPRESSION_FAILED; /* no dynamic table */

          const char *name, *value;
          size_t name_len, value_len;
          qres = SocketQPACK_static_table_get (
              index, &name, &name_len, &value, &value_len);
          if (qres != QPACK_OK)
            return -(int)QPACK_DECOMPRESSION_FAILED;

          if (h3_headers_add (hdrs, name, name_len, value, value_len) < 0)
            return -(int)QPACK_DECOMPRESSION_FAILED;
        }
      else if ((first_byte & 0xC0) == 0x40)
        {
          /* 01xxxxxx: Literal with Name Reference (§4.5.4) */
          SocketQPACK_LiteralNameRef ref;
          qres = SocketQPACK_decode_literal_name_ref_arena (
              data + pos, len - pos, arena, &ref, &consumed);
          if (qres != QPACK_OK)
            return -(int)QPACK_DECOMPRESSION_FAILED;
          pos += consumed;

          if (!ref.is_static)
            return -(int)QPACK_DECOMPRESSION_FAILED; /* no dynamic table */

          const char *name;
          size_t name_len;
          qres = SocketQPACK_static_table_get (
              ref.name_index, &name, &name_len, NULL, NULL);
          if (qres != QPACK_OK)
            return -(int)QPACK_DECOMPRESSION_FAILED;

          if (h3_headers_add (hdrs, name, name_len, ref.value, ref.value_len)
              < 0)
            return -(int)QPACK_DECOMPRESSION_FAILED;
        }
      else if ((first_byte & 0xE0) == 0x20)
        {
          /* 001xxxxx: Literal with Literal Name (§4.5.6) */
          unsigned char name_buf[256];
          unsigned char value_buf[4096];
          size_t name_len, value_len;
          bool never_indexed;
          qres = SocketQPACK_decode_literal_field_literal_name (
              data + pos,
              len - pos,
              name_buf,
              sizeof (name_buf),
              &name_len,
              value_buf,
              sizeof (value_buf),
              &value_len,
              &never_indexed,
              &consumed);
          if (qres != QPACK_OK)
            return -(int)QPACK_DECOMPRESSION_FAILED;
          pos += consumed;

          if (h3_headers_add (hdrs,
                              (const char *)name_buf,
                              name_len,
                              (const char *)value_buf,
                              value_len)
              < 0)
            return -(int)QPACK_DECOMPRESSION_FAILED;
        }
      else if ((first_byte & 0xF0) == 0x10)
        {
          /* 0001xxxx: Indexed with Post-Base (§4.5.3) — needs dynamic table */
          return -(int)QPACK_DECOMPRESSION_FAILED;
        }
      else
        {
          /* 0000xxxx: Literal with Post-Base Name (§4.5.5) — needs dynamic
           * table */
          return -(int)QPACK_DECOMPRESSION_FAILED;
        }
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
  const char *values[32];
  size_t n = SocketHTTP_Headers_get_all_n (headers, "cookie", 6, values, 32);
  if (n <= 1)
    return;

  /* Calculate total length: sum of values + "; " separators */
  size_t total = 0;
  for (size_t i = 0; i < n; i++)
    {
      total += strlen (values[i]);
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
      size_t vlen = strlen (values[i]);
      memcpy (combined + pos, values[i], vlen);
      pos += vlen;
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
  int status_code;
  int64_t expected_content_length;
  size_t total_data_received;

  /* Per-stream send buffer */
  H3_StreamBuf send_buf;
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

  /* Validate headers */
  int rc = SocketHTTP3_validate_request_headers (headers);
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

/**
 * @brief Append data to the request's receive buffer, growing if needed.
 */
static int
recv_buf_append (struct SocketHTTP3_Request *req,
                 const uint8_t *data,
                 size_t len)
{
  if (req->recv_buf_len + len > req->recv_buf_cap)
    {
      size_t new_cap = req->recv_buf_cap;
      while (new_cap < req->recv_buf_len + len)
        new_cap *= 2;
      uint8_t *new_buf = ALLOC (req->arena, new_cap);
      memcpy (new_buf, req->recv_buf, req->recv_buf_len);
      req->recv_buf = new_buf;
      req->recv_buf_cap = new_cap;
    }
  memcpy (req->recv_buf + req->recv_buf_len, data, len);
  req->recv_buf_len += len;
  return 0;
}

/**
 * @brief Append data to the request's data buffer, growing if needed.
 */
static int
data_buf_append (struct SocketHTTP3_Request *req,
                 const uint8_t *data,
                 size_t len)
{
  if (req->data_buf_len + len > req->data_buf_cap)
    {
      size_t new_cap = req->data_buf_cap;
      while (new_cap < req->data_buf_len + len)
        new_cap *= 2;
      uint8_t *new_buf = ALLOC (req->arena, new_cap);
      memcpy (new_buf, req->data_buf, req->data_buf_len);
      req->data_buf = new_buf;
      req->data_buf_cap = new_cap;
    }
  memcpy (req->data_buf + req->data_buf_len, data, len);
  req->data_buf_len += len;
  return 0;
}

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
    recv_buf_append (req, data, len);

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

      switch (fhdr.type)
        {
        case HTTP3_FRAME_HEADERS:
          {
            if (req->recv_state == H3_REQ_RECV_BODY_RECEIVING
                || (req->recv_state == H3_REQ_RECV_HEADERS_RECEIVED
                    && req->status_code >= 200))
              {
                /* Trailers */
                req->trailers_received = 1;
                /* For now, just skip trailers — don't decode */
                break;
              }

            /* Decode QPACK headers */
            SocketHTTP_Headers_T hdrs;
            int rc = h3_qpack_decode_headers (
                req->arena, payload, payload_len, &hdrs);
            if (rc != 0)
              return rc;

            /* Coalesce cookie headers */
            h3_coalesce_cookies (req->arena, hdrs);

            /* Validate response headers */
            rc = SocketHTTP3_validate_response_headers (hdrs);
            if (rc != 0)
              return rc;

            /* Extract status code */
            const char *status_val
                = SocketHTTP_Headers_get_n (hdrs, ":status", 7);
            if (status_val == NULL)
              return -(int)H3_MESSAGE_ERROR;

            int code = parse_status_code (status_val, strlen (status_val));
            if (code < 0)
              return -(int)H3_MESSAGE_ERROR;

            req->status_code = code;
            req->recv_headers = hdrs;

            /* Extract content-length if present */
            const char *cl_val
                = SocketHTTP_Headers_get_n (hdrs, "content-length", 14);
            if (cl_val != NULL)
              {
                int64_t cl = 0;
                const char *p = cl_val;
                while (*p >= '0' && *p <= '9')
                  {
                    cl = cl * 10 + (*p - '0');
                    p++;
                  }
                if (*p == '\0')
                  req->expected_content_length = cl;
              }

            req->recv_state = H3_REQ_RECV_HEADERS_RECEIVED;
            break;
          }

        case HTTP3_FRAME_DATA:
          {
            if (req->recv_state == H3_REQ_RECV_IDLE)
              return -(int)H3_FRAME_UNEXPECTED;
            if (req->trailers_received)
              return -(int)H3_FRAME_UNEXPECTED;

            data_buf_append (req, payload, payload_len);
            req->total_data_received += payload_len;

            if (req->recv_state == H3_REQ_RECV_HEADERS_RECEIVED)
              req->recv_state = H3_REQ_RECV_BODY_RECEIVING;
            break;
          }

        default:
          /* Skip unknown frames on request stream */
          break;
        }

      /* Consume parsed bytes */
      size_t remaining = req->recv_buf_len - total_consumed;
      if (remaining > 0)
        memmove (req->recv_buf, req->recv_buf + total_consumed, remaining);
      req->recv_buf_len = remaining;
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
      size_t remaining = req->data_buf_len - to_copy;
      if (remaining > 0)
        memmove (req->data_buf, req->data_buf + to_copy, remaining);
      req->data_buf_len = remaining;
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

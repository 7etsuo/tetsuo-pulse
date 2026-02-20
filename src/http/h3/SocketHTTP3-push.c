/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP3-push.c
 * @brief HTTP/3 server push implementation (RFC 9114 Section 4.6).
 */

#ifdef SOCKET_HAS_H3_PUSH

#include "http/SocketHTTP3-push.h"
#include "http/SocketHTTP3-constants.h"
#include "http/SocketHTTP3-frame.h"
#include "http/SocketHTTP3-private.h"
#include "http/SocketHTTP3-request.h"
#include "http/SocketHTTP3-stream.h"
#include "quic/SocketQUICVarInt.h"

#include <string.h>

static H3_PushEntry *
find_push_entry (SocketHTTP3_Conn_T conn, uint64_t push_id)
{
  for (size_t i = 0; i < conn->push_count; i++)
    {
      if (conn->pushes[i].push_id == push_id)
        return &conn->pushes[i];
    }
  return NULL;
}

/**
 * @brief Append a frame to the control stream output buffer and queue it.
 */
static int
send_control_frame (SocketHTTP3_Conn_T conn,
                    uint64_t frame_type,
                    const uint8_t *payload,
                    size_t payload_len)
{
  uint8_t frame_hdr[16];
  int hdr_len = SocketHTTP3_Frame_write_header (
      frame_type, payload_len, frame_hdr, sizeof (frame_hdr));
  if (hdr_len < 0)
    return -(int)H3_INTERNAL_ERROR;

  stream_buf_reset (&conn->control_out);
  stream_buf_append (
      &conn->control_out, conn->arena, frame_hdr, (size_t)hdr_len);
  if (payload_len > 0)
    stream_buf_append (&conn->control_out, conn->arena, payload, payload_len);

  return h3_output_queue_push (&conn->output,
                               conn->local_control_id,
                               conn->control_out.data,
                               conn->control_out.len);
}

int
SocketHTTP3_Conn_allocate_push_id (SocketHTTP3_Conn_T conn,
                                   uint64_t *out_push_id)
{
  if (conn == NULL || out_push_id == NULL)
    return -1;
  if (conn->role != H3_ROLE_SERVER)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;
  if (conn->state != H3_CONN_STATE_OPEN)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;
  if (!conn->max_push_id_received)
    return -(int)H3_ID_ERROR;
  if (conn->next_push_id > conn->max_push_id)
    return -(int)H3_ID_ERROR;
  if (conn->push_count >= H3_MAX_PUSH_STREAMS)
    return -(int)H3_ID_ERROR;

  *out_push_id = conn->next_push_id;
  conn->next_push_id++;
  return 0;
}

int
SocketHTTP3_Conn_send_push_promise (SocketHTTP3_Conn_T conn,
                                    uint64_t request_stream_id,
                                    uint64_t push_id,
                                    const SocketHTTP_Headers_T headers)
{
  if (conn == NULL || headers == NULL)
    return -1;
  if (conn->role != H3_ROLE_SERVER)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;
  if (conn->state != H3_CONN_STATE_OPEN)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;

  /* Validate push_id isn't already tracked */
  if (find_push_entry (conn, push_id) != NULL)
    return -(int)H3_ID_ERROR;

  /* push_id must be within max_push_id */
  if (!conn->max_push_id_received || push_id > conn->max_push_id)
    return -(int)H3_ID_ERROR;

  if (conn->push_count >= H3_MAX_PUSH_STREAMS)
    return -(int)H3_ID_ERROR;

  /* QPACK-encode the promised headers */
  uint8_t *qpack_data;
  size_t qpack_len;
  int rc
      = h3_qpack_encode_headers (conn->arena, headers, &qpack_data, &qpack_len);
  if (rc != 0)
    return rc;

  /* Build PUSH_PROMISE payload: push_id(varint) + qpack_data */
  uint8_t push_id_buf[SOCKETQUICVARINT_MAX_SIZE];
  size_t push_id_len
      = SocketQUICVarInt_encode (push_id, push_id_buf, sizeof (push_id_buf));
  if (push_id_len == 0)
    return -(int)H3_INTERNAL_ERROR;

  size_t payload_len = push_id_len + qpack_len;

  /* Build frame header */
  uint8_t frame_hdr[16];
  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_PUSH_PROMISE, payload_len, frame_hdr, sizeof (frame_hdr));
  if (hdr_len < 0)
    return -(int)H3_INTERNAL_ERROR;

  /* Build promise frame in a temporary buffer */
  H3_StreamBuf promise_buf;
  stream_buf_init (&promise_buf, conn->arena, request_stream_id);
  stream_buf_append (&promise_buf, conn->arena, frame_hdr, (size_t)hdr_len);
  stream_buf_append (&promise_buf, conn->arena, push_id_buf, push_id_len);
  stream_buf_append (&promise_buf, conn->arena, qpack_data, qpack_len);

  h3_output_queue_push (
      &conn->output, request_stream_id, promise_buf.data, promise_buf.len);

  /* Create push entry */
  H3_PushEntry *entry = &conn->pushes[conn->push_count++];
  entry->push_id = push_id;
  entry->request_stream_id = request_stream_id;
  entry->push_stream_id = 0;
  entry->state = H3_PUSH_PROMISED;
  entry->promised_headers = NULL;
  entry->request = NULL;

  return 0;
}

SocketHTTP3_Request_T
SocketHTTP3_Conn_open_push_stream (SocketHTTP3_Conn_T conn, uint64_t push_id)
{
  if (conn == NULL)
    return NULL;
  if (conn->role != H3_ROLE_SERVER)
    return NULL;
  if (conn->state != H3_CONN_STATE_OPEN)
    return NULL;

  H3_PushEntry *entry = find_push_entry (conn, push_id);
  if (entry == NULL)
    return NULL;
  if (entry->state != H3_PUSH_PROMISED)
    return NULL;

  /* Allocate server-initiated unidi stream ID */
  uint64_t stream_id = conn->next_server_unidi_id;
  conn->next_server_unidi_id += 4;

  /* Create push request */
  SocketHTTP3_Request_T req
      = SocketHTTP3_Request_new_push (conn, stream_id, push_id);
  if (req == NULL)
    return NULL;

  /* Build push stream header: type(0x01) + push_id(varint) */
  uint8_t type_byte = (uint8_t)H3_STREAM_TYPE_PUSH;
  uint8_t push_id_buf[SOCKETQUICVARINT_MAX_SIZE];
  size_t push_id_len
      = SocketQUICVarInt_encode (push_id, push_id_buf, sizeof (push_id_buf));
  if (push_id_len == 0)
    return NULL;

  /* Build stream header in a temporary buffer */
  H3_StreamBuf stream_hdr;
  stream_buf_init (&stream_hdr, conn->arena, stream_id);
  stream_buf_append (&stream_hdr, conn->arena, &type_byte, 1);
  stream_buf_append (&stream_hdr, conn->arena, push_id_buf, push_id_len);

  h3_output_queue_push (
      &conn->output, stream_id, stream_hdr.data, stream_hdr.len);

  /* Register in stream map */
  SocketHTTP3_StreamMap_register (
      conn->stream_map, stream_id, H3_STREAM_TYPE_PUSH);

  /* Update entry */
  entry->push_stream_id = stream_id;
  entry->state = H3_PUSH_STREAM_OPENED;
  entry->request = req;

  return req;
}

void
SocketHTTP3_Conn_on_push (SocketHTTP3_Conn_T conn,
                          SocketHTTP3_PushCallback cb,
                          void *userdata)
{
  if (conn == NULL)
    return;
  conn->push_cb = cb;
  conn->push_cb_userdata = userdata;
}

int
SocketHTTP3_Conn_send_max_push_id (SocketHTTP3_Conn_T conn,
                                   uint64_t max_push_id)
{
  if (conn == NULL)
    return -1;
  if (conn->role != H3_ROLE_CLIENT)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;
  if (conn->state != H3_CONN_STATE_OPEN)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;

  /* Must not decrease */
  if (conn->local_max_push_id_sent && max_push_id < conn->local_max_push_id)
    return -(int)H3_ID_ERROR;

  uint8_t payload[SOCKETQUICVARINT_MAX_SIZE];
  int payload_len
      = SocketHTTP3_MaxPushId_write (max_push_id, payload, sizeof (payload));
  if (payload_len < 0)
    return -(int)H3_INTERNAL_ERROR;

  int rc = send_control_frame (
      conn, HTTP3_FRAME_MAX_PUSH_ID, payload, (size_t)payload_len);
  if (rc < 0)
    return rc;

  conn->local_max_push_id = max_push_id;
  conn->local_max_push_id_sent = 1;
  return 0;
}

int
SocketHTTP3_Conn_cancel_push (SocketHTTP3_Conn_T conn, uint64_t push_id)
{
  if (conn == NULL)
    return -1;
  if (conn->state != H3_CONN_STATE_OPEN)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;

  /* Send CANCEL_PUSH frame on control stream */
  uint8_t payload[SOCKETQUICVARINT_MAX_SIZE];
  int payload_len
      = SocketHTTP3_CancelPush_write (push_id, payload, sizeof (payload));
  if (payload_len < 0)
    return -(int)H3_INTERNAL_ERROR;

  int rc = send_control_frame (
      conn, HTTP3_FRAME_CANCEL_PUSH, payload, (size_t)payload_len);
  if (rc < 0)
    return rc;

  /* Update local push entry if it exists */
  H3_PushEntry *entry = find_push_entry (conn, push_id);
  if (entry != NULL)
    {
      entry->state = H3_PUSH_CANCELLED;
      if (entry->request != NULL)
        SocketHTTP3_Request_cancel (entry->request);
    }

  return 0;
}

void
h3_handle_cancel_push (SocketHTTP3_Conn_T conn, uint64_t push_id)
{
  H3_PushEntry *entry = find_push_entry (conn, push_id);
  if (entry == NULL)
    return; /* Unknown push_id: silently ignore per RFC 9114 §7.2.3 */

  entry->state = H3_PUSH_CANCELLED;
  if (entry->request != NULL)
    SocketHTTP3_Request_cancel (entry->request);
}

int
h3_conn_recv_push_promise (SocketHTTP3_Conn_T conn,
                           uint64_t request_stream_id,
                           const uint8_t *payload,
                           size_t payload_len)
{
  if (conn == NULL)
    return -1;
  if (conn->role != H3_ROLE_CLIENT)
    return -(int)H3_FRAME_UNEXPECTED;

  /* Parse push_id from payload start */
  uint64_t push_id;
  size_t push_id_offset;
  int rc = SocketHTTP3_PushPromise_parse_id (
      payload, payload_len, &push_id, &push_id_offset);
  if (rc != 0)
    return -(int)H3_FRAME_ERROR;

  /* Duplicate check */
  if (find_push_entry (conn, push_id) != NULL)
    return -(int)H3_ID_ERROR;

  if (conn->push_count >= H3_MAX_PUSH_STREAMS)
    return -(int)H3_ID_ERROR;

  /* Decode promised headers from remaining payload */
  const uint8_t *qpack_data = payload + push_id_offset;
  size_t qpack_len = payload_len - push_id_offset;

  SocketHTTP_Headers_T promised_headers = NULL;
  if (qpack_len > 0)
    {
      rc = h3_qpack_decode_headers (
          conn->arena, qpack_data, qpack_len, &promised_headers);
      if (rc != 0)
        return rc;
    }

  /* Create push entry */
  H3_PushEntry *entry = &conn->pushes[conn->push_count++];
  entry->push_id = push_id;
  entry->request_stream_id = request_stream_id;
  entry->push_stream_id = 0;
  entry->state = H3_PUSH_PROMISED;
  entry->promised_headers = promised_headers;
  entry->request = NULL;

  /* Invoke callback if registered */
  if (conn->push_cb != NULL)
    conn->push_cb (conn, push_id, promised_headers, conn->push_cb_userdata);

  return 0;
}

int
h3_feed_push_stream (SocketHTTP3_Conn_T conn,
                     uint64_t stream_id,
                     const uint8_t *data,
                     size_t len,
                     int fin)
{
  if (conn == NULL)
    return -1;

  /* Find push entry by stream_id */
  H3_PushEntry *entry = NULL;
  for (size_t i = 0; i < conn->push_count; i++)
    {
      if (conn->pushes[i].push_stream_id == stream_id
          && conn->pushes[i].state == H3_PUSH_STREAM_OPENED)
        {
          entry = &conn->pushes[i];
          break;
        }
    }

  if (entry == NULL)
    {
      /* First data on push stream: decode push_id varint */
      if (len == 0)
        return 0;

      uint64_t push_id;
      size_t consumed;
      SocketQUICVarInt_Result vres
          = SocketQUICVarInt_decode (data, len, &push_id, &consumed);
      if (vres == QUIC_VARINT_INCOMPLETE)
        return 0;
      if (vres != QUIC_VARINT_OK)
        return -(int)H3_GENERAL_PROTOCOL_ERROR;

      entry = find_push_entry (conn, push_id);
      if (entry == NULL)
        return -(int)H3_ID_ERROR;
      if (entry->state == H3_PUSH_CANCELLED)
        return 0;

      /* Create request for receiving push response */
      SocketHTTP3_Request_T req
          = SocketHTTP3_Request_new_push (conn, stream_id, push_id);
      if (req == NULL)
        return -(int)H3_INTERNAL_ERROR;

      entry->push_stream_id = stream_id;
      entry->state = H3_PUSH_STREAM_OPENED;
      entry->request = req;

      /* Feed remaining data after push_id */
      if (consumed < len)
        return SocketHTTP3_Request_feed (
            req, data + consumed, len - consumed, fin);

      if (fin)
        return SocketHTTP3_Request_feed (req, NULL, 0, fin);

      return 0;
    }

  /* Subsequent calls: feed to existing request */
  if (entry->request == NULL)
    return -(int)H3_INTERNAL_ERROR;

  return SocketHTTP3_Request_feed (entry->request, data, len, fin);
}

#endif /* SOCKET_HAS_H3_PUSH */

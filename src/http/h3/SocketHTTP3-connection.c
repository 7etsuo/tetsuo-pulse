/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP3-connection.c
 * @brief HTTP/3 connection lifecycle implementation (RFC 9114).
 */

#include "http/SocketHTTP3-private.h"
#include "http/SocketHTTP3-constants.h"
#include "http/SocketHTTP3-frame.h"
#include "http/SocketHTTP3-request.h"
#include "http/SocketHTTP3-stream.h"
#include "quic/SocketQUICVarInt.h"

#include <string.h>

/* ============================================================================
 * Config Defaults
 * ============================================================================
 */

void
SocketHTTP3_ConnConfig_defaults (SocketHTTP3_ConnConfig *config,
                                 SocketHTTP3_Role role)
{
  if (config == NULL)
    return;

  config->role = role;
  SocketHTTP3_Settings_init (&config->local_settings);
}

/* ============================================================================
 * Connection Creation
 * ============================================================================
 */

SocketHTTP3_Conn_T
SocketHTTP3_Conn_new (Arena_T arena,
                      void *quic,
                      const SocketHTTP3_ConnConfig *config)
{
  if (arena == NULL || config == NULL)
    return NULL;

  SocketHTTP3_Conn_T conn = CALLOC (arena, 1, sizeof (struct SocketHTTP3_Conn));

  conn->arena = arena;
  conn->role = config->role;
  conn->state = H3_CONN_STATE_IDLE;
  conn->quic = quic;

  conn->stream_map = SocketHTTP3_StreamMap_new (arena);
  if (conn->stream_map == NULL)
    return NULL;

  conn->local_control_id = 0;
  conn->local_encoder_id = 0;
  conn->local_decoder_id = 0;

  conn->local_settings = config->local_settings;
  SocketHTTP3_Settings_init (&conn->peer_settings);
  conn->peer_settings_received = 0;

  conn->ctrl_recv_len = 0;
  conn->control_first_frame_seen = 0;

  conn->goaway_sent = 0;
  conn->goaway_received = 0;
  conn->local_goaway_id = 0;
  conn->peer_goaway_id = 0;

  conn->max_push_id = 0;
  conn->max_push_id_received = 0;

  conn->pending_unidi.count = 0;
  conn->output.count = 0;

  /* Request tracking */
  memset (conn->requests, 0, sizeof (conn->requests));
  conn->request_count = 0;
  conn->next_bidi_stream_id = (config->role == H3_ROLE_CLIENT) ? 0 : 1;

  return conn;
}

/* ============================================================================
 * Connection Initialization
 * ============================================================================
 */

int
SocketHTTP3_Conn_init (SocketHTTP3_Conn_T conn)
{
  if (conn == NULL)
    return -1;

  if (conn->state != H3_CONN_STATE_IDLE)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;

  /*
   * Assign local stream IDs per QUIC conventions (RFC 9000 §2.1):
   *   Client-initiated unidi: 2, 6, 10
   *   Server-initiated unidi: 3, 7, 11
   */
  uint64_t base = (conn->role == H3_ROLE_CLIENT) ? 2 : 3;
  conn->local_control_id = base;     /* +0 */
  conn->local_encoder_id = base + 4; /* +4 */
  conn->local_decoder_id = base + 8; /* +8 */

  /* Register in stream map */
  SocketHTTP3_StreamMap_set_local_control (conn->stream_map,
                                           conn->local_control_id);
  SocketHTTP3_StreamMap_set_local_qpack_encoder (conn->stream_map,
                                                 conn->local_encoder_id);
  SocketHTTP3_StreamMap_set_local_qpack_decoder (conn->stream_map,
                                                 conn->local_decoder_id);

  /* Initialize per-stream output buffers */
  stream_buf_init (&conn->control_out, conn->arena, conn->local_control_id);
  stream_buf_init (&conn->encoder_out, conn->arena, conn->local_encoder_id);
  stream_buf_init (&conn->decoder_out, conn->arena, conn->local_decoder_id);

  /*
   * Build control stream output: type byte (0x00) + SETTINGS frame.
   */
  uint8_t type_byte = (uint8_t)H3_STREAM_TYPE_CONTROL;
  stream_buf_append (&conn->control_out, conn->arena, &type_byte, 1);

  /* Serialize SETTINGS payload */
  uint8_t settings_payload[HTTP3_SETTINGS_MAX_WRITE_SIZE];
  int settings_len = SocketHTTP3_Settings_write (
      &conn->local_settings, settings_payload, sizeof (settings_payload));
  if (settings_len < 0)
    return -1;

  /* Write frame header for SETTINGS */
  uint8_t frame_hdr[16];
  int hdr_len = SocketHTTP3_Frame_write_header (HTTP3_FRAME_SETTINGS,
                                                (uint64_t)settings_len,
                                                frame_hdr,
                                                sizeof (frame_hdr));
  if (hdr_len < 0)
    return -1;

  stream_buf_append (
      &conn->control_out, conn->arena, frame_hdr, (size_t)hdr_len);
  if (settings_len > 0)
    stream_buf_append (&conn->control_out,
                       conn->arena,
                       settings_payload,
                       (size_t)settings_len);

  /* Build QPACK encoder stream output: type byte 0x02 */
  type_byte = (uint8_t)H3_STREAM_TYPE_QPACK_ENCODER;
  stream_buf_append (&conn->encoder_out, conn->arena, &type_byte, 1);

  /* Build QPACK decoder stream output: type byte 0x03 */
  type_byte = (uint8_t)H3_STREAM_TYPE_QPACK_DECODER;
  stream_buf_append (&conn->decoder_out, conn->arena, &type_byte, 1);

  /* Queue output entries */
  h3_output_queue_push (&conn->output,
                        conn->local_control_id,
                        conn->control_out.data,
                        conn->control_out.len);
  h3_output_queue_push (&conn->output,
                        conn->local_encoder_id,
                        conn->encoder_out.data,
                        conn->encoder_out.len);
  h3_output_queue_push (&conn->output,
                        conn->local_decoder_id,
                        conn->decoder_out.data,
                        conn->decoder_out.len);

  conn->state = H3_CONN_STATE_OPEN;
  return 0;
}

/* ============================================================================
 * Control Stream Processing
 * ============================================================================
 */

static int
process_control_stream (SocketHTTP3_Conn_T conn,
                        const uint8_t *data,
                        size_t len)
{
  /* Append incoming data to control receive buffer */
  if (conn->ctrl_recv_len + len > H3_CTRL_RECV_BUF_SIZE)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;

  memcpy (conn->ctrl_recv_buf + conn->ctrl_recv_len, data, len);
  conn->ctrl_recv_len += len;

  /* Process frames while we have data */
  while (conn->ctrl_recv_len > 0)
    {
      SocketHTTP3_FrameHeader header;
      size_t consumed;
      SocketHTTP3_ParseResult pres = SocketHTTP3_Frame_parse_header (
          conn->ctrl_recv_buf, conn->ctrl_recv_len, &header, &consumed);

      if (pres == HTTP3_PARSE_INCOMPLETE)
        return 0;
      if (pres == HTTP3_PARSE_ERROR)
        return -(int)H3_FRAME_ERROR;

      /* Check if we have the full payload */
      if (consumed + header.length > conn->ctrl_recv_len)
        return 0;

      /* Validate frame on control stream */
      int is_first = !conn->control_first_frame_seen;
      uint64_t err = SocketHTTP3_Frame_validate (
          header.type, HTTP3_STREAM_CONTROL, is_first);
      if (err != 0)
        return -(int)err;

      const uint8_t *payload = conn->ctrl_recv_buf + consumed;
      size_t payload_len = (size_t)header.length;
      size_t total_consumed = consumed + payload_len;

      conn->control_first_frame_seen = 1;

      /* Dispatch by frame type */
      switch (header.type)
        {
        case HTTP3_FRAME_SETTINGS:
          {
            if (conn->peer_settings_received)
              return -(int)H3_FRAME_UNEXPECTED;

            int rc = SocketHTTP3_Settings_parse (
                payload, payload_len, &conn->peer_settings);
            if (rc != 0)
              return rc;

            conn->peer_settings_received = 1;
            break;
          }

        case HTTP3_FRAME_GOAWAY:
          {
            uint64_t id;
            int rc = SocketHTTP3_Goaway_parse (payload, payload_len, &id);
            if (rc != 0)
              return -(int)H3_FRAME_ERROR;

            /* Role validation per RFC 9114 §5.2:
             * Server sends GOAWAY with client-initiated bidi stream ID
             * (must be divisible by 4).
             * Client sends GOAWAY with push ID. */
            if (conn->role == H3_ROLE_CLIENT)
              {
                /* Peer is server: GOAWAY ID must be client-initiated bidi */
                if (id % 4 != 0)
                  return -(int)H3_ID_ERROR;
              }

            /* GOAWAY ID must not increase */
            if (conn->goaway_received && id > conn->peer_goaway_id)
              return -(int)H3_ID_ERROR;

            conn->peer_goaway_id = id;
            conn->goaway_received = 1;

            /* Update connection state */
            if (conn->goaway_sent)
              conn->state = H3_CONN_STATE_CLOSING;
            else
              conn->state = H3_CONN_STATE_GOAWAY_RECV;

            break;
          }

        case HTTP3_FRAME_MAX_PUSH_ID:
          {
            /* Only clients send MAX_PUSH_ID */
            if (conn->role == H3_ROLE_CLIENT)
              return -(int)H3_FRAME_UNEXPECTED;

            uint64_t push_id;
            int rc
                = SocketHTTP3_MaxPushId_parse (payload, payload_len, &push_id);
            if (rc != 0)
              return -(int)H3_FRAME_ERROR;

            /* Must not decrease */
            if (conn->max_push_id_received && push_id < conn->max_push_id)
              return -(int)H3_ID_ERROR;

            conn->max_push_id = push_id;
            conn->max_push_id_received = 1;
            break;
          }

        case HTTP3_FRAME_CANCEL_PUSH:
          {
            uint64_t push_id;
            int rc
                = SocketHTTP3_CancelPush_parse (payload, payload_len, &push_id);
            if (rc != 0)
              return -(int)H3_FRAME_ERROR;

            /* Stub: store/ignore for push support */
            (void)push_id;
            break;
          }

        default:
          /* Unknown/GREASE frames on control stream: skip payload */
          break;
        }

      /* Consume parsed bytes, shift remainder */
      size_t remaining = conn->ctrl_recv_len - total_consumed;
      if (remaining > 0)
        memmove (conn->ctrl_recv_buf,
                 conn->ctrl_recv_buf + total_consumed,
                 remaining);
      conn->ctrl_recv_len = remaining;
    }

  return 0;
}

/* ============================================================================
 * Feed Stream
 * ============================================================================
 */

int
SocketHTTP3_Conn_feed_stream (SocketHTTP3_Conn_T conn,
                              uint64_t stream_id,
                              const uint8_t *data,
                              size_t len,
                              int fin)
{
  if (conn == NULL)
    return -1;

  SocketHTTP3_StreamRole role
      = SocketHTTP3_StreamMap_role (conn->stream_map, stream_id);

  switch (role)
    {
    case H3_STREAM_ROLE_CONTROL:
      (void)fin;
      return process_control_stream (conn, data, len);

    case H3_STREAM_ROLE_QPACK_ENCODER:
    case H3_STREAM_ROLE_QPACK_DECODER:
      /* Stub: forward to QPACK layer */
      (void)fin;
      return 0;

    case H3_STREAM_ROLE_REQUEST:
      {
        size_t index = (size_t)(stream_id / 4);
        if (index >= H3_MAX_CONCURRENT_REQUESTS)
          return -(int)H3_GENERAL_PROTOCOL_ERROR;

        struct SocketHTTP3_Request *req = conn->requests[index];
        if (req == NULL)
          {
            /* Auto-create for peer-initiated bidi streams (server receiving) */
            /* For now, peer-initiated requests need explicit creation */
            return 0;
          }

        return SocketHTTP3_Request_feed (req, data, len, fin);
      }

    case H3_STREAM_ROLE_PUSH:
      /* Stub for push support */
      return 0;

    case H3_STREAM_ROLE_UNKNOWN:
      break;
    }

  /*
   * Unknown unidirectional stream: try to read the type byte.
   * Track in pending_unidi until we can classify it.
   */

  /* Check if already in pending list */
  int found = 0;
  for (size_t i = 0; i < conn->pending_unidi.count; i++)
    {
      if (conn->pending_unidi.stream_ids[i] == stream_id)
        {
          found = 1;
          break;
        }
    }

  if (!found)
    {
      if (conn->pending_unidi.count >= H3_MAX_PENDING_UNIDI)
        return -(int)H3_GENERAL_PROTOCOL_ERROR;

      conn->pending_unidi.stream_ids[conn->pending_unidi.count++] = stream_id;
    }

  /* Try to decode the stream type varint */
  if (len == 0)
    return 0;

  uint64_t stream_type;
  size_t consumed;
  SocketQUICVarInt_Result vres
      = SocketQUICVarInt_decode (data, len, &stream_type, &consumed);

  if (vres == QUIC_VARINT_INCOMPLETE)
    return 0;
  if (vres != QUIC_VARINT_OK)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;

  /* Remove from pending list */
  for (size_t i = 0; i < conn->pending_unidi.count; i++)
    {
      if (conn->pending_unidi.stream_ids[i] == stream_id)
        {
          conn->pending_unidi.stream_ids[i]
              = conn->pending_unidi.stream_ids[conn->pending_unidi.count - 1];
          conn->pending_unidi.count--;
          break;
        }
    }

  /* Register the stream type */
  uint64_t reg_err = SocketHTTP3_StreamMap_register (
      conn->stream_map, stream_id, stream_type);
  if (reg_err != 0)
    return -(int)reg_err;

  /* If there's remaining data after the type byte, process it */
  if (consumed < len)
    {
      return SocketHTTP3_Conn_feed_stream (
          conn, stream_id, data + consumed, len - consumed, fin);
    }

  return 0;
}

/* ============================================================================
 * Shutdown (GOAWAY)
 * ============================================================================
 */

int
SocketHTTP3_Conn_shutdown (SocketHTTP3_Conn_T conn, uint64_t last_id)
{
  if (conn == NULL)
    return -1;

  if (conn->state == H3_CONN_STATE_CLOSED)
    return -(int)H3_GENERAL_PROTOCOL_ERROR;

  /* GOAWAY ID must not increase on subsequent calls */
  if (conn->goaway_sent && last_id > conn->local_goaway_id)
    return -(int)H3_ID_ERROR;

  /* Build GOAWAY frame: header + payload */
  uint8_t goaway_payload[SOCKETQUICVARINT_MAX_SIZE];
  int payload_len = SocketHTTP3_Goaway_write (
      last_id, goaway_payload, sizeof (goaway_payload));
  if (payload_len < 0)
    return -1;

  uint8_t frame_hdr[16];
  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_GOAWAY, (uint64_t)payload_len, frame_hdr, sizeof (frame_hdr));
  if (hdr_len < 0)
    return -1;

  /* Reset control output buffer for the GOAWAY frame */
  conn->control_out.len = 0;
  stream_buf_append (
      &conn->control_out, conn->arena, frame_hdr, (size_t)hdr_len);
  stream_buf_append (
      &conn->control_out, conn->arena, goaway_payload, (size_t)payload_len);

  h3_output_queue_push (&conn->output,
                        conn->local_control_id,
                        conn->control_out.data,
                        conn->control_out.len);

  conn->goaway_sent = 1;
  conn->local_goaway_id = last_id;

  /* Update connection state */
  if (conn->goaway_received)
    conn->state = H3_CONN_STATE_CLOSING;
  else
    conn->state = H3_CONN_STATE_GOAWAY_SENT;

  return 0;
}

/* ============================================================================
 * Close
 * ============================================================================
 */

int
SocketHTTP3_Conn_close (SocketHTTP3_Conn_T conn, uint64_t error_code)
{
  if (conn == NULL)
    return -1;

  conn->state = H3_CONN_STATE_CLOSED;
  return (int)error_code;
}

/* ============================================================================
 * Accessors
 * ============================================================================
 */

SocketHTTP3_ConnState
SocketHTTP3_Conn_state (SocketHTTP3_Conn_T conn)
{
  if (conn == NULL)
    return H3_CONN_STATE_CLOSED;
  return conn->state;
}

const SocketHTTP3_Settings *
SocketHTTP3_Conn_peer_settings (SocketHTTP3_Conn_T conn)
{
  if (conn == NULL)
    return NULL;
  return &conn->peer_settings;
}

const SocketHTTP3_Output *
SocketHTTP3_Conn_get_output (SocketHTTP3_Conn_T conn, size_t index)
{
  if (conn == NULL || index >= conn->output.count)
    return NULL;
  return &conn->output.entries[index];
}

size_t
SocketHTTP3_Conn_output_count (SocketHTTP3_Conn_T conn)
{
  if (conn == NULL)
    return 0;
  return conn->output.count;
}

void
SocketHTTP3_Conn_drain_output (SocketHTTP3_Conn_T conn)
{
  if (conn != NULL)
    conn->output.count = 0;
}

const char *
SocketHTTP3_Conn_state_name (SocketHTTP3_ConnState state)
{
  switch (state)
    {
    case H3_CONN_STATE_IDLE:
      return "IDLE";
    case H3_CONN_STATE_OPEN:
      return "OPEN";
    case H3_CONN_STATE_GOAWAY_SENT:
      return "GOAWAY_SENT";
    case H3_CONN_STATE_GOAWAY_RECV:
      return "GOAWAY_RECV";
    case H3_CONN_STATE_CLOSING:
      return "CLOSING";
    case H3_CONN_STATE_CLOSED:
      return "CLOSED";
    default:
      return "UNKNOWN";
    }
}

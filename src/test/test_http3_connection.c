/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_http3_connection.c
 * @brief Unit tests for HTTP/3 connection lifecycle (RFC 9114).
 */

#include "core/Arena.h"
#include "http/SocketHTTP3.h"
#include "http/SocketHTTP3-constants.h"
#include "http/SocketHTTP3-frame.h"
#include "http/SocketHTTP3-private.h"
#include "quic/SocketQUICVarInt.h"
#include "test/Test.h"

#include <string.h>

/* ============================================================================
 * Test Helpers
 * ============================================================================
 */

/**
 * @brief Build a SETTINGS frame with default (empty) settings payload.
 *
 * Wire format: stream_type(0x00) + frame_type(0x04) + length(0x00)
 * The stream type byte is included because this simulates the first data
 * on a peer control stream.
 *
 * @return Number of bytes written to buf.
 */
static size_t
build_control_stream_settings (uint8_t *buf,
                               size_t buflen,
                               const SocketHTTP3_Settings *settings)
{
  size_t pos = 0;

  /* Stream type byte for control stream */
  buf[pos++] = 0x00;

  /* Serialize settings payload */
  uint8_t payload[HTTP3_SETTINGS_MAX_WRITE_SIZE];
  int payload_len
      = SocketHTTP3_Settings_write (settings, payload, sizeof (payload));
  if (payload_len < 0)
    payload_len = 0;

  /* Frame header: type=SETTINGS(0x04) + length */
  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_SETTINGS, (uint64_t)payload_len, buf + pos, buflen - pos);
  if (hdr_len < 0)
    return 0;
  pos += (size_t)hdr_len;

  /* Payload */
  if (payload_len > 0)
    {
      memcpy (buf + pos, payload, (size_t)payload_len);
      pos += (size_t)payload_len;
    }

  return pos;
}

/**
 * @brief Build SETTINGS frame bytes only (no stream type byte).
 *
 * For feeding to an already-registered control stream.
 */
static size_t
build_settings_frame (uint8_t *buf,
                      size_t buflen,
                      const SocketHTTP3_Settings *settings)
{
  size_t pos = 0;

  uint8_t payload[HTTP3_SETTINGS_MAX_WRITE_SIZE];
  int payload_len
      = SocketHTTP3_Settings_write (settings, payload, sizeof (payload));
  if (payload_len < 0)
    payload_len = 0;

  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_SETTINGS, (uint64_t)payload_len, buf + pos, buflen - pos);
  if (hdr_len < 0)
    return 0;
  pos += (size_t)hdr_len;

  if (payload_len > 0)
    {
      memcpy (buf + pos, payload, (size_t)payload_len);
      pos += (size_t)payload_len;
    }

  return pos;
}

/**
 * @brief Build a GOAWAY frame (no stream type byte).
 */
static size_t
build_goaway_frame (uint8_t *buf, size_t buflen, uint64_t id)
{
  size_t pos = 0;

  uint8_t payload[SOCKETQUICVARINT_MAX_SIZE];
  int payload_len = SocketHTTP3_Goaway_write (id, payload, sizeof (payload));
  if (payload_len < 0)
    return 0;

  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_GOAWAY, (uint64_t)payload_len, buf + pos, buflen - pos);
  if (hdr_len < 0)
    return 0;
  pos += (size_t)hdr_len;

  memcpy (buf + pos, payload, (size_t)payload_len);
  pos += (size_t)payload_len;
  return pos;
}

/**
 * @brief Build a MAX_PUSH_ID frame (no stream type byte).
 */
static size_t
build_max_push_id_frame (uint8_t *buf, size_t buflen, uint64_t push_id)
{
  size_t pos = 0;

  uint8_t payload[SOCKETQUICVARINT_MAX_SIZE];
  int payload_len
      = SocketHTTP3_MaxPushId_write (push_id, payload, sizeof (payload));
  if (payload_len < 0)
    return 0;

  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_MAX_PUSH_ID, (uint64_t)payload_len, buf + pos, buflen - pos);
  if (hdr_len < 0)
    return 0;
  pos += (size_t)hdr_len;

  memcpy (buf + pos, payload, (size_t)payload_len);
  pos += (size_t)payload_len;
  return pos;
}

/**
 * @brief Create and initialize a client connection with a peer control
 *        stream already registered (stream 3, server-initiated unidi).
 *
 * The peer control stream is pre-registered so tests can feed frames
 * directly without first sending the type byte.
 */
static SocketHTTP3_Conn_T
make_client_conn_with_peer_control (Arena_T arena)
{
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);
  SocketHTTP3_Conn_drain_output (conn);

  /* Register peer control stream (server-initiated unidi stream 3) */
  SocketHTTP3_StreamMap_register (conn->stream_map, 3, H3_STREAM_TYPE_CONTROL);
  return conn;
}

/**
 * @brief Create and initialize a server connection with a peer control
 *        stream already registered (stream 2, client-initiated unidi).
 */
static SocketHTTP3_Conn_T
make_server_conn_with_peer_control (Arena_T arena)
{
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_SERVER);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);
  SocketHTTP3_Conn_drain_output (conn);

  /* Register peer control stream (client-initiated unidi stream 2) */
  SocketHTTP3_StreamMap_register (conn->stream_map, 2, H3_STREAM_TYPE_CONTROL);
  return conn;
}

/* ============================================================================
 * Creation & Config Tests
 * ============================================================================
 */

TEST (h3_conn_config_defaults)
{
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  ASSERT_EQ (H3_ROLE_CLIENT, config.role);
  ASSERT_EQ (UINT64_MAX, config.local_settings.max_field_section_size);
  ASSERT_EQ (0ULL, config.local_settings.qpack_max_table_capacity);
  ASSERT_EQ (0ULL, config.local_settings.qpack_blocked_streams);
}

TEST (h3_conn_new_client)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  ASSERT_NOT_NULL (conn);
  ASSERT_EQ (H3_CONN_STATE_IDLE, SocketHTTP3_Conn_state (conn));

  Arena_dispose (&arena);
}

TEST (h3_conn_new_server)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_SERVER);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  ASSERT_NOT_NULL (conn);
  ASSERT_EQ (H3_CONN_STATE_IDLE, SocketHTTP3_Conn_state (conn));

  Arena_dispose (&arena);
}

TEST (h3_conn_new_null_arena)
{
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (NULL, NULL, &config);
  ASSERT_NULL (conn);
}

/* ============================================================================
 * Initialization Tests
 * ============================================================================
 */

TEST (h3_conn_init_transitions_to_open)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  ASSERT_EQ (0, SocketHTTP3_Conn_init (conn));
  ASSERT_EQ (H3_CONN_STATE_OPEN, SocketHTTP3_Conn_state (conn));

  Arena_dispose (&arena);
}

TEST (h3_conn_init_output_has_three_streams)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);

  ASSERT_EQ ((size_t)3, SocketHTTP3_Conn_output_count (conn));

  /* Client unidi stream IDs: 2, 6, 10 */
  const SocketHTTP3_Output *o0 = SocketHTTP3_Conn_get_output (conn, 0);
  const SocketHTTP3_Output *o1 = SocketHTTP3_Conn_get_output (conn, 1);
  const SocketHTTP3_Output *o2 = SocketHTTP3_Conn_get_output (conn, 2);
  ASSERT_NOT_NULL (o0);
  ASSERT_NOT_NULL (o1);
  ASSERT_NOT_NULL (o2);

  ASSERT_EQ (2ULL, o0->stream_id);  /* control */
  ASSERT_EQ (6ULL, o1->stream_id);  /* encoder */
  ASSERT_EQ (10ULL, o2->stream_id); /* decoder */

  Arena_dispose (&arena);
}

TEST (h3_conn_init_server_stream_ids)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_SERVER);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);

  ASSERT_EQ ((size_t)3, SocketHTTP3_Conn_output_count (conn));

  /* Server unidi stream IDs: 3, 7, 11 */
  const SocketHTTP3_Output *o0 = SocketHTTP3_Conn_get_output (conn, 0);
  const SocketHTTP3_Output *o1 = SocketHTTP3_Conn_get_output (conn, 1);
  const SocketHTTP3_Output *o2 = SocketHTTP3_Conn_get_output (conn, 2);

  ASSERT_EQ (3ULL, o0->stream_id);  /* control */
  ASSERT_EQ (7ULL, o1->stream_id);  /* encoder */
  ASSERT_EQ (11ULL, o2->stream_id); /* decoder */

  Arena_dispose (&arena);
}

TEST (h3_conn_init_control_stream_has_settings)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);

  const SocketHTTP3_Output *ctrl = SocketHTTP3_Conn_get_output (conn, 0);
  ASSERT_NOT_NULL (ctrl);
  ASSERT (ctrl->len >= 3); /* type byte + frame header (at least 2 bytes) */

  /* First byte is control stream type 0x00 */
  ASSERT_EQ (0x00, ctrl->data[0]);

  /* Next should be SETTINGS frame header: type=0x04 */
  ASSERT_EQ (0x04, ctrl->data[1]);

  Arena_dispose (&arena);
}

TEST (h3_conn_init_encoder_stream_type_byte)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);

  const SocketHTTP3_Output *enc = SocketHTTP3_Conn_get_output (conn, 1);
  ASSERT_NOT_NULL (enc);
  ASSERT_EQ ((size_t)1, enc->len);
  ASSERT_EQ (0x02, enc->data[0]); /* QPACK encoder type byte */

  Arena_dispose (&arena);
}

TEST (h3_conn_init_decoder_stream_type_byte)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);

  const SocketHTTP3_Output *dec = SocketHTTP3_Conn_get_output (conn, 2);
  ASSERT_NOT_NULL (dec);
  ASSERT_EQ ((size_t)1, dec->len);
  ASSERT_EQ (0x03, dec->data[0]); /* QPACK decoder type byte */

  Arena_dispose (&arena);
}

/* ============================================================================
 * Settings Exchange Tests
 * ============================================================================
 */

TEST (h3_conn_settings_parse_ok)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer_control (arena);

  /* Build and feed a SETTINGS frame with custom values */
  SocketHTTP3_Settings peer_settings;
  SocketHTTP3_Settings_init (&peer_settings);
  peer_settings.max_field_section_size = 8192;
  peer_settings.qpack_max_table_capacity = 4096;

  uint8_t buf[64];
  size_t len = build_settings_frame (buf, sizeof (buf), &peer_settings);
  ASSERT (len > 0);

  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, len, 0);
  ASSERT_EQ (0, rc);

  const SocketHTTP3_Settings *ps = SocketHTTP3_Conn_peer_settings (conn);
  ASSERT_EQ (8192ULL, ps->max_field_section_size);
  ASSERT_EQ (4096ULL, ps->qpack_max_table_capacity);

  Arena_dispose (&arena);
}

TEST (h3_conn_settings_default_before_peer)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);

  const SocketHTTP3_Settings *ps = SocketHTTP3_Conn_peer_settings (conn);
  ASSERT_EQ (UINT64_MAX, ps->max_field_section_size);
  ASSERT_EQ (0ULL, ps->qpack_max_table_capacity);
  ASSERT_EQ (0ULL, ps->qpack_blocked_streams);

  Arena_dispose (&arena);
}

TEST (h3_conn_settings_missing)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer_control (arena);

  /* Send a GOAWAY as the first frame instead of SETTINGS */
  uint8_t buf[16];
  size_t len = build_goaway_frame (buf, sizeof (buf), 0);
  ASSERT (len > 0);

  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, len, 0);
  ASSERT_EQ (-(int)H3_MISSING_SETTINGS, rc);

  Arena_dispose (&arena);
}

TEST (h3_conn_settings_duplicate)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer_control (arena);

  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);

  uint8_t buf[64];
  size_t len = build_settings_frame (buf, sizeof (buf), &settings);

  /* First SETTINGS: OK */
  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, len, 0);
  ASSERT_EQ (0, rc);

  /* Second SETTINGS: must fail */
  rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, len, 0);
  ASSERT_EQ (-(int)H3_FRAME_UNEXPECTED, rc);

  Arena_dispose (&arena);
}

TEST (h3_conn_settings_reserved_h2_id)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer_control (arena);

  /* Manually build a SETTINGS frame with reserved H2 setting ID 0x02 */
  uint8_t payload[16];
  size_t ppos = 0;
  ppos += SocketQUICVarInt_encode (
      0x02, payload + ppos, sizeof (payload) - ppos);
  ppos += SocketQUICVarInt_encode (0, payload + ppos, sizeof (payload) - ppos);

  uint8_t buf[32];
  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_SETTINGS, ppos, buf, sizeof (buf));
  ASSERT (hdr_len > 0);
  memcpy (buf + hdr_len, payload, ppos);
  size_t total = (size_t)hdr_len + ppos;

  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, total, 0);
  ASSERT_EQ (-(int)H3_SETTINGS_ERROR, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * GOAWAY Tests
 * ============================================================================
 */

TEST (h3_conn_goaway_send)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_SERVER);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);
  SocketHTTP3_Conn_drain_output (conn);

  int rc = SocketHTTP3_Conn_shutdown (conn, 4);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (H3_CONN_STATE_GOAWAY_SENT, SocketHTTP3_Conn_state (conn));
  ASSERT (SocketHTTP3_Conn_output_count (conn) > 0);

  Arena_dispose (&arena);
}

TEST (h3_conn_goaway_recv)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer_control (arena);

  /* Feed SETTINGS first (required) */
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  uint8_t sbuf[32];
  size_t slen = build_settings_frame (sbuf, sizeof (sbuf), &settings);
  SocketHTTP3_Conn_feed_stream (conn, 3, sbuf, slen, 0);

  /* Feed GOAWAY with stream ID 0 */
  uint8_t buf[16];
  size_t len = build_goaway_frame (buf, sizeof (buf), 0);
  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, len, 0);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (H3_CONN_STATE_GOAWAY_RECV, SocketHTTP3_Conn_state (conn));

  Arena_dispose (&arena);
}

TEST (h3_conn_goaway_decreasing_ok)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer_control (arena);

  /* Feed SETTINGS */
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  uint8_t sbuf[32];
  size_t slen = build_settings_frame (sbuf, sizeof (sbuf), &settings);
  SocketHTTP3_Conn_feed_stream (conn, 3, sbuf, slen, 0);

  /* First GOAWAY with ID 8 */
  uint8_t buf[16];
  size_t len = build_goaway_frame (buf, sizeof (buf), 8);
  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, len, 0);
  ASSERT_EQ (0, rc);

  /* Second GOAWAY with smaller ID 4 */
  len = build_goaway_frame (buf, sizeof (buf), 4);
  rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, len, 0);
  ASSERT_EQ (0, rc);

  Arena_dispose (&arena);
}

TEST (h3_conn_goaway_increasing_error)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer_control (arena);

  /* Feed SETTINGS */
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  uint8_t sbuf[32];
  size_t slen = build_settings_frame (sbuf, sizeof (sbuf), &settings);
  SocketHTTP3_Conn_feed_stream (conn, 3, sbuf, slen, 0);

  /* First GOAWAY with ID 4 */
  uint8_t buf[16];
  size_t len = build_goaway_frame (buf, sizeof (buf), 4);
  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, len, 0);
  ASSERT_EQ (0, rc);

  /* Second GOAWAY with larger ID 8 → error */
  len = build_goaway_frame (buf, sizeof (buf), 8);
  rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, len, 0);
  ASSERT_EQ (-(int)H3_ID_ERROR, rc);

  Arena_dispose (&arena);
}

TEST (h3_conn_goaway_server_validates_bidi_id)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer_control (arena);

  /* Feed SETTINGS */
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  uint8_t sbuf[32];
  size_t slen = build_settings_frame (sbuf, sizeof (sbuf), &settings);
  SocketHTTP3_Conn_feed_stream (conn, 3, sbuf, slen, 0);

  /* Server GOAWAY with non-bidi stream ID (1 is server-initiated bidi,
   * but 1 % 4 == 1, not 0) → H3_ID_ERROR */
  uint8_t buf[16];
  size_t len = build_goaway_frame (buf, sizeof (buf), 1);
  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, len, 0);
  ASSERT_EQ (-(int)H3_ID_ERROR, rc);

  Arena_dispose (&arena);
}

TEST (h3_conn_graceful_shutdown)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_SERVER);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);
  SocketHTTP3_Conn_drain_output (conn);

  /* First GOAWAY with max varint value (graceful, RFC 9114 §5.2) */
  int rc = SocketHTTP3_Conn_shutdown (conn, SOCKETQUICVARINT_MAX);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (H3_CONN_STATE_GOAWAY_SENT, SocketHTTP3_Conn_state (conn));
  SocketHTTP3_Conn_drain_output (conn);

  /* Then final GOAWAY with actual last ID */
  rc = SocketHTTP3_Conn_shutdown (conn, 4);
  ASSERT_EQ (0, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * MAX_PUSH_ID Tests
 * ============================================================================
 */

TEST (h3_conn_max_push_id_from_client_ok)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_server_conn_with_peer_control (arena);

  /* Feed SETTINGS first */
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  uint8_t sbuf[32];
  size_t slen = build_settings_frame (sbuf, sizeof (sbuf), &settings);
  SocketHTTP3_Conn_feed_stream (conn, 2, sbuf, slen, 0);

  /* Client sends MAX_PUSH_ID to server */
  uint8_t buf[16];
  size_t len = build_max_push_id_frame (buf, sizeof (buf), 7);
  int rc = SocketHTTP3_Conn_feed_stream (conn, 2, buf, len, 0);
  ASSERT_EQ (0, rc);

  Arena_dispose (&arena);
}

TEST (h3_conn_max_push_id_from_server_rejected)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer_control (arena);

  /* Feed SETTINGS first */
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  uint8_t sbuf[32];
  size_t slen = build_settings_frame (sbuf, sizeof (sbuf), &settings);
  SocketHTTP3_Conn_feed_stream (conn, 3, sbuf, slen, 0);

  /* Server sends MAX_PUSH_ID to client → error */
  uint8_t buf[16];
  size_t len = build_max_push_id_frame (buf, sizeof (buf), 3);
  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, len, 0);
  ASSERT_EQ (-(int)H3_FRAME_UNEXPECTED, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Control Stream Validation Tests
 * ============================================================================
 */

TEST (h3_conn_reserved_h2_frame_rejected)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer_control (arena);

  /* Feed SETTINGS first */
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  uint8_t sbuf[32];
  size_t slen = build_settings_frame (sbuf, sizeof (sbuf), &settings);
  SocketHTTP3_Conn_feed_stream (conn, 3, sbuf, slen, 0);

  /* Send reserved H2 PRIORITY frame (0x02) */
  uint8_t buf[16];
  int hdr_len = SocketHTTP3_Frame_write_header (0x02, 0, buf, sizeof (buf));
  ASSERT (hdr_len > 0);

  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, (size_t)hdr_len, 0);
  ASSERT_EQ (-(int)H3_FRAME_UNEXPECTED, rc);

  Arena_dispose (&arena);
}

TEST (h3_conn_data_on_control_rejected)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer_control (arena);

  /* Feed SETTINGS first */
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  uint8_t sbuf[32];
  size_t slen = build_settings_frame (sbuf, sizeof (sbuf), &settings);
  SocketHTTP3_Conn_feed_stream (conn, 3, sbuf, slen, 0);

  /* Send DATA frame (0x00) on control stream → rejected */
  uint8_t buf[16];
  int hdr_len
      = SocketHTTP3_Frame_write_header (HTTP3_FRAME_DATA, 0, buf, sizeof (buf));
  ASSERT (hdr_len > 0);

  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, (size_t)hdr_len, 0);
  ASSERT_EQ (-(int)H3_FRAME_UNEXPECTED, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Unidirectional Stream Type Detection Tests
 * ============================================================================
 */

TEST (h3_conn_unidi_stream_type_detection)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);
  SocketHTTP3_Conn_drain_output (conn);

  /* Feed a server-initiated unidi stream (3) with control type byte + SETTINGS
   */
  uint8_t buf[64];
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  size_t len = build_control_stream_settings (buf, sizeof (buf), &settings);

  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, len, 0);
  ASSERT_EQ (0, rc);

  /* Verify the stream is now recognized as control */
  ASSERT_EQ (H3_STREAM_ROLE_CONTROL,
             SocketHTTP3_StreamMap_role (conn->stream_map, 3));

  Arena_dispose (&arena);
}

/* ============================================================================
 * State Tests
 * ============================================================================
 */

TEST (h3_conn_state_names)
{
  ASSERT (SocketHTTP3_Conn_state_name (H3_CONN_STATE_IDLE) != NULL);
  ASSERT (SocketHTTP3_Conn_state_name (H3_CONN_STATE_OPEN) != NULL);
  ASSERT (SocketHTTP3_Conn_state_name (H3_CONN_STATE_GOAWAY_SENT) != NULL);
  ASSERT (SocketHTTP3_Conn_state_name (H3_CONN_STATE_GOAWAY_RECV) != NULL);
  ASSERT (SocketHTTP3_Conn_state_name (H3_CONN_STATE_CLOSING) != NULL);
  ASSERT (SocketHTTP3_Conn_state_name (H3_CONN_STATE_CLOSED) != NULL);
}

TEST (h3_conn_close_transitions_to_closed)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);

  int rc = SocketHTTP3_Conn_close (conn, H3_NO_ERROR);
  ASSERT_EQ ((int)H3_NO_ERROR, rc);
  ASSERT_EQ (H3_CONN_STATE_CLOSED, SocketHTTP3_Conn_state (conn));

  Arena_dispose (&arena);
}

TEST (h3_conn_drain_output)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);

  ASSERT_EQ ((size_t)3, SocketHTTP3_Conn_output_count (conn));
  SocketHTTP3_Conn_drain_output (conn);
  ASSERT_EQ ((size_t)0, SocketHTTP3_Conn_output_count (conn));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

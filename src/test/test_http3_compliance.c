/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_http3_compliance.c
 * @brief RFC 9114 compliance tests for HTTP/3.
 *
 * Wire-level compliance tests that verify correct handling of edge cases
 * from RFC 9114. Creates SocketHTTP3_Conn_T instances directly and feeds
 * wire-format data via feed_stream(). No real sockets or TLS needed.
 *
 * Tests that are NOT duplicated here (already covered):
 * - Pseudo-header order         → test_http3_request.c
 * - Uppercase header            → test_http3_request.c
 * - Connection header           → test_http3_request.c
 * - te: trailers                → test_http3_request.c
 * - Status 101                  → test_http3_request.c
 * - CONNECT validation          → test_http3_request.c
 * - Reserved H2 frame           → test_http3_connection.c
 * - DATA before HEADERS         → test_http3_request.c
 * - Content-Length mismatch     → test_http3_request.c
 * - GOAWAY increasing           → test_http3_connection.c
 * - Duplicate control stream    → test_http3_stream.c
 * - Cookie splitting            → test_http3_request.c
 * - DATA on control stream      → test_http3_connection.c
 */

#include "core/Arena.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP3.h"
#include "http/SocketHTTP3-constants.h"
#include "http/SocketHTTP3-frame.h"
#include "http/SocketHTTP3-private.h"
#include "http/SocketHTTP3-request.h"
#include "quic/SocketQUICVarInt.h"
#include "test/Test.h"

#include <string.h>

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
 * @brief Create a client connection with peer control stream registered
 *        and SETTINGS already fed.
 */
static SocketHTTP3_Conn_T
make_client_conn_with_peer (Arena_T arena)
{
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);
  SocketHTTP3_Conn_drain_output (conn);

  /* Register peer control stream (server-initiated unidi stream 3) */
  SocketHTTP3_StreamMap_register (conn->stream_map, 3, H3_STREAM_TYPE_CONTROL);

  /* Feed default SETTINGS on stream 3 */
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  uint8_t sbuf[64];
  size_t slen = build_settings_frame (sbuf, sizeof (sbuf), &settings);
  SocketHTTP3_Conn_feed_stream (conn, 3, sbuf, slen, 0);

  return conn;
}

/**
 * @brief Create a server connection with peer control stream registered
 *        and SETTINGS already fed.
 */
static SocketHTTP3_Conn_T
make_server_conn_with_peer (Arena_T arena)
{
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_SERVER);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);
  SocketHTTP3_Conn_drain_output (conn);

  /* Register peer control stream (client-initiated unidi stream 2) */
  SocketHTTP3_StreamMap_register (conn->stream_map, 2, H3_STREAM_TYPE_CONTROL);

  /* Feed default SETTINGS on stream 2 */
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  uint8_t sbuf[64];
  size_t slen = build_settings_frame (sbuf, sizeof (sbuf), &settings);
  SocketHTTP3_Conn_feed_stream (conn, 2, sbuf, slen, 0);

  return conn;
}

TEST (h3_comply_transfer_encoding)
{
  Arena_T arena = Arena_new ();

  SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_add_pseudo_n (h, ":method", 7, "GET", 3);
  SocketHTTP_Headers_add_pseudo_n (h, ":scheme", 7, "https", 5);
  SocketHTTP_Headers_add_pseudo_n (h, ":path", 5, "/", 1);
  SocketHTTP_Headers_add_pseudo_n (h, ":authority", 10, "example.com", 11);
  SocketHTTP_Headers_add (h, "transfer-encoding", "chunked");

  int rc = SocketHTTP3_validate_request_headers (h);
  ASSERT (rc < 0);

  Arena_dispose (&arena);
}

TEST (h3_comply_unknown_frame_type)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer (arena);

  /* Build an unknown frame type (0xFF) with empty payload */
  uint8_t buf[16];
  int hdr_len = SocketHTTP3_Frame_write_header (0xFF, 0, buf, sizeof (buf));
  ASSERT (hdr_len > 0);

  /* Should be silently ignored, not an error */
  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, (size_t)hdr_len, 0);
  ASSERT_EQ (0, rc);

  Arena_dispose (&arena);
}

TEST (h3_comply_grease_frames)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer (arena);

  /* GREASE type: 0x1f * N + 0x21, use N=0 → 0x21 */
  uint64_t grease_type = 0x21;
  ASSERT (H3_IS_GREASE (grease_type));

  uint8_t buf[16];
  int hdr_len
      = SocketHTTP3_Frame_write_header (grease_type, 0, buf, sizeof (buf));
  ASSERT (hdr_len > 0);

  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, (size_t)hdr_len, 0);
  ASSERT_EQ (0, rc);

  Arena_dispose (&arena);
}

TEST (h3_comply_grease_settings)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);
  SocketHTTP3_Conn_drain_output (conn);

  /* Register peer control stream without feeding SETTINGS yet */
  SocketHTTP3_StreamMap_register (conn->stream_map, 3, H3_STREAM_TYPE_CONTROL);

  /* Build SETTINGS with a GREASE ID (0x21 = 0x1f*0 + 0x21) */
  uint8_t payload[32];
  size_t ppos = 0;
  /* GREASE setting: id=0x21, value=0 */
  ppos += SocketQUICVarInt_encode (
      0x21, payload + ppos, sizeof (payload) - ppos);
  ppos += SocketQUICVarInt_encode (0, payload + ppos, sizeof (payload) - ppos);

  uint8_t buf[64];
  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_SETTINGS, ppos, buf, sizeof (buf));
  ASSERT (hdr_len > 0);
  memcpy (buf + hdr_len, payload, ppos);
  size_t total = (size_t)hdr_len + ppos;

  /* GREASE settings should be silently ignored */
  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, total, 0);
  ASSERT_EQ (0, rc);

  Arena_dispose (&arena);
}

TEST (h3_comply_duplicate_settings)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);
  SocketHTTP3_Conn_drain_output (conn);

  SocketHTTP3_StreamMap_register (conn->stream_map, 3, H3_STREAM_TYPE_CONTROL);

  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);

  uint8_t buf[64];
  size_t len = build_settings_frame (buf, sizeof (buf), &settings);

  /* First SETTINGS: OK */
  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, len, 0);
  ASSERT_EQ (0, rc);

  /* Second SETTINGS: MUST be H3_FRAME_UNEXPECTED */
  rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, len, 0);
  ASSERT_EQ (-(int)H3_FRAME_UNEXPECTED, rc);

  Arena_dispose (&arena);
}

TEST (h3_comply_headers_on_control_rejected)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer (arena);

  /* Build a HEADERS frame on control stream → H3_FRAME_UNEXPECTED */
  uint8_t buf[16];
  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_HEADERS, 0, buf, sizeof (buf));
  ASSERT (hdr_len > 0);

  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, (size_t)hdr_len, 0);
  ASSERT_EQ (-(int)H3_FRAME_UNEXPECTED, rc);

  Arena_dispose (&arena);
}

TEST (h3_comply_max_push_id_decreasing)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_server_conn_with_peer (arena);

  /* First MAX_PUSH_ID with value 10 — OK */
  uint8_t buf[16];
  size_t len = build_max_push_id_frame (buf, sizeof (buf), 10);
  ASSERT (len > 0);

  int rc = SocketHTTP3_Conn_feed_stream (conn, 2, buf, len, 0);
  ASSERT_EQ (0, rc);

  /* Second MAX_PUSH_ID with smaller value 5 — MUST fail with H3_ID_ERROR */
  len = build_max_push_id_frame (buf, sizeof (buf), 5);
  ASSERT (len > 0);

  rc = SocketHTTP3_Conn_feed_stream (conn, 2, buf, len, 0);
  ASSERT_EQ (-(int)H3_ID_ERROR, rc);

  Arena_dispose (&arena);
}

TEST (h3_comply_request_large_headers)
{
  Arena_T arena = Arena_new ();

  /* Create a client connection */
  SocketHTTP3_Conn_T conn;
  {
    SocketHTTP3_ConnConfig config;
    SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);
    conn = SocketHTTP3_Conn_new (arena, NULL, &config);
    SocketHTTP3_Conn_init (conn);
    SocketHTTP3_Conn_drain_output (conn);
  }

  /* Create a client-initiated request */
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new (conn);
  ASSERT_NOT_NULL (req);

  /* Build request headers with a large custom header (~1KB value) */
  SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_add_pseudo_n (h, ":method", 7, "GET", 3);
  SocketHTTP_Headers_add_pseudo_n (h, ":scheme", 7, "https", 5);
  SocketHTTP_Headers_add_pseudo_n (h, ":path", 5, "/", 1);
  SocketHTTP_Headers_add_pseudo_n (h, ":authority", 10, "example.com", 11);

  char large_val[1024];
  memset (large_val, 'x', sizeof (large_val) - 1);
  large_val[sizeof (large_val) - 1] = '\0';
  SocketHTTP_Headers_add (h, "x-large", large_val);

  /* Sending request headers should succeed */
  int rc = SocketHTTP3_Request_send_headers (req, h, 1);
  ASSERT_EQ (0, rc);

  Arena_dispose (&arena);
}

TEST (h3_comply_settings_max_field_section_stored)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);
  SocketHTTP3_Conn_drain_output (conn);

  SocketHTTP3_StreamMap_register (conn->stream_map, 3, H3_STREAM_TYPE_CONTROL);

  /* Feed SETTINGS with specific max_field_section_size */
  SocketHTTP3_Settings peer_settings;
  SocketHTTP3_Settings_init (&peer_settings);
  peer_settings.max_field_section_size = 4096;

  uint8_t buf[64];
  size_t len = build_settings_frame (buf, sizeof (buf), &peer_settings);
  ASSERT (len > 0);

  int rc = SocketHTTP3_Conn_feed_stream (conn, 3, buf, len, 0);
  ASSERT_EQ (0, rc);

  /* Verify peer settings are stored correctly */
  const SocketHTTP3_Settings *ps = SocketHTTP3_Conn_peer_settings (conn);
  ASSERT_NOT_NULL (ps);
  ASSERT_EQ (4096ULL, ps->max_field_section_size);

  Arena_dispose (&arena);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

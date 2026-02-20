/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_http3_push.c
 * @brief Unit tests for HTTP/3 server push (RFC 9114 Section 4.6).
 */

#ifdef SOCKET_HAS_H3_PUSH

#include "core/Arena.h"
#include "http/SocketHTTP3.h"
#include "http/SocketHTTP3-constants.h"
#include "http/SocketHTTP3-frame.h"
#include "http/SocketHTTP3-private.h"
#include "http/SocketHTTP3-push.h"
#include "http/SocketHTTP3-request.h"
#include "http/SocketHTTP3-stream.h"
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

static size_t
build_cancel_push_frame (uint8_t *buf, size_t buflen, uint64_t push_id)
{
  size_t pos = 0;
  uint8_t payload[SOCKETQUICVARINT_MAX_SIZE];
  int payload_len
      = SocketHTTP3_CancelPush_write (push_id, payload, sizeof (payload));
  if (payload_len < 0)
    return 0;

  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_CANCEL_PUSH, (uint64_t)payload_len, buf + pos, buflen - pos);
  if (hdr_len < 0)
    return 0;
  pos += (size_t)hdr_len;

  memcpy (buf + pos, payload, (size_t)payload_len);
  pos += (size_t)payload_len;
  return pos;
}

/**
 * @brief Create and init a server conn with peer control registered +
 *        SETTINGS received + MAX_PUSH_ID received.
 */
static SocketHTTP3_Conn_T
make_server_conn_push_ready (Arena_T arena, uint64_t max_push_id)
{
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_SERVER);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);
  SocketHTTP3_Conn_drain_output (conn);

  /* Register peer control stream (client-initiated unidi stream 2) */
  SocketHTTP3_StreamMap_register (conn->stream_map, 2, H3_STREAM_TYPE_CONTROL);

  /* Feed SETTINGS */
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  uint8_t sbuf[64];
  size_t slen = build_settings_frame (sbuf, sizeof (sbuf), &settings);
  SocketHTTP3_Conn_feed_stream (conn, 2, sbuf, slen, 0);

  /* Feed MAX_PUSH_ID */
  uint8_t mbuf[16];
  size_t mlen = build_max_push_id_frame (mbuf, sizeof (mbuf), max_push_id);
  SocketHTTP3_Conn_feed_stream (conn, 2, mbuf, mlen, 0);

  SocketHTTP3_Conn_drain_output (conn);
  return conn;
}

/**
 * @brief Create a server conn with a client request registered at stream 0.
 */
static SocketHTTP3_Conn_T
make_server_conn_with_request (Arena_T arena, uint64_t max_push_id)
{
  SocketHTTP3_Conn_T conn = make_server_conn_push_ready (arena, max_push_id);

  /* Simulate an incoming client request on bidi stream 0 */
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new_incoming (conn, 0);
  (void)req;

  return conn;
}

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

static SocketHTTP_Headers_T
make_push_promise_headers (Arena_T arena)
{
  SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_add_pseudo_n (h, ":method", 7, "GET", 3);
  SocketHTTP_Headers_add_pseudo_n (h, ":scheme", 7, "https", 5);
  SocketHTTP_Headers_add_pseudo_n (h, ":path", 5, "/style.css", 10);
  SocketHTTP_Headers_add_pseudo_n (h, ":authority", 10, "example.com", 11);
  return h;
}

static SocketHTTP_Headers_T
make_response_headers (Arena_T arena)
{
  SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_add_pseudo_n (h, ":status", 7, "200", 3);
  SocketHTTP_Headers_add_n (h, "content-type", 12, "text/css", 8);
  return h;
}

TEST (h3_push_allocate_id)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_server_conn_push_ready (arena, 5);

  uint64_t id0, id1, id2;
  ASSERT_EQ (0, SocketHTTP3_Conn_allocate_push_id (conn, &id0));
  ASSERT_EQ (0ULL, id0);
  ASSERT_EQ (0, SocketHTTP3_Conn_allocate_push_id (conn, &id1));
  ASSERT_EQ (1ULL, id1);
  ASSERT_EQ (0, SocketHTTP3_Conn_allocate_push_id (conn, &id2));
  ASSERT_EQ (2ULL, id2);

  Arena_dispose (&arena);
}

TEST (h3_push_allocate_without_max)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_SERVER);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);
  SocketHTTP3_Conn_drain_output (conn);

  /* No MAX_PUSH_ID received — allocate must fail */
  uint64_t id;
  ASSERT_EQ (-(int)H3_ID_ERROR, SocketHTTP3_Conn_allocate_push_id (conn, &id));

  Arena_dispose (&arena);
}

TEST (h3_push_promise_basic)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_server_conn_with_request (arena, 5);

  uint64_t push_id;
  ASSERT_EQ (0, SocketHTTP3_Conn_allocate_push_id (conn, &push_id));
  ASSERT_EQ (0ULL, push_id);

  SocketHTTP_Headers_T headers = make_push_promise_headers (arena);
  ASSERT_EQ (0, SocketHTTP3_Conn_send_push_promise (conn, 0, push_id, headers));

  /* Output queue should have the PUSH_PROMISE frame */
  ASSERT (SocketHTTP3_Conn_output_count (conn) > 0);
  const SocketHTTP3_Output *out = SocketHTTP3_Conn_get_output (conn, 0);
  ASSERT_NOT_NULL (out);
  ASSERT_EQ (0ULL, out->stream_id); /* On request stream 0 */

  /* Verify frame starts with PUSH_PROMISE type (0x05) */
  ASSERT (out->len >= 2);
  ASSERT_EQ (0x05, out->data[0]);

  /* Verify push entry state */
  ASSERT_EQ ((size_t)1, conn->push_count);
  ASSERT_EQ (H3_PUSH_PROMISED, conn->pushes[0].state);

  Arena_dispose (&arena);
}

TEST (h3_push_promise_exceeds_max)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_server_conn_with_request (arena, 0);

  SocketHTTP_Headers_T headers = make_push_promise_headers (arena);

  /* Allocate push_id 0 (within max_push_id=0) */
  uint64_t push_id;
  ASSERT_EQ (0, SocketHTTP3_Conn_allocate_push_id (conn, &push_id));
  ASSERT_EQ (0ULL, push_id);
  ASSERT_EQ (0, SocketHTTP3_Conn_send_push_promise (conn, 0, push_id, headers));
  SocketHTTP3_Conn_drain_output (conn);

  /* Try push_id 1 — exceeds max_push_id=0 */
  ASSERT_EQ (-(int)H3_ID_ERROR,
             SocketHTTP3_Conn_allocate_push_id (conn, &push_id));

  Arena_dispose (&arena);
}

TEST (h3_push_promise_duplicate)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_server_conn_with_request (arena, 5);
  SocketHTTP_Headers_T headers = make_push_promise_headers (arena);

  uint64_t push_id;
  ASSERT_EQ (0, SocketHTTP3_Conn_allocate_push_id (conn, &push_id));
  ASSERT_EQ (0, SocketHTTP3_Conn_send_push_promise (conn, 0, push_id, headers));
  SocketHTTP3_Conn_drain_output (conn);

  /* Same push_id again → error */
  ASSERT_EQ (-(int)H3_ID_ERROR,
             SocketHTTP3_Conn_send_push_promise (conn, 0, push_id, headers));

  Arena_dispose (&arena);
}

TEST (h3_push_promise_client_send)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer_control (arena);
  SocketHTTP_Headers_T headers = make_push_promise_headers (arena);

  /* Client cannot send PUSH_PROMISE */
  ASSERT_EQ (-(int)H3_GENERAL_PROTOCOL_ERROR,
             SocketHTTP3_Conn_send_push_promise (conn, 0, 0, headers));

  Arena_dispose (&arena);
}

TEST (h3_push_open_stream)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_server_conn_with_request (arena, 5);

  uint64_t push_id;
  SocketHTTP3_Conn_allocate_push_id (conn, &push_id);
  SocketHTTP_Headers_T headers = make_push_promise_headers (arena);
  SocketHTTP3_Conn_send_push_promise (conn, 0, push_id, headers);
  SocketHTTP3_Conn_drain_output (conn);

  SocketHTTP3_Request_T req = SocketHTTP3_Conn_open_push_stream (conn, push_id);
  ASSERT_NOT_NULL (req);

  /* Output queue should have push stream header */
  ASSERT (SocketHTTP3_Conn_output_count (conn) > 0);
  const SocketHTTP3_Output *out = SocketHTTP3_Conn_get_output (conn, 0);
  ASSERT_NOT_NULL (out);

  /* First byte should be stream type 0x01 (push) */
  ASSERT (out->len >= 2);
  ASSERT_EQ (0x01, out->data[0]);

  /* Push entry should be STREAM_OPENED */
  ASSERT_EQ (H3_PUSH_STREAM_OPENED, conn->pushes[0].state);

  /* Stream ID should be server unidi starting at 15 */
  ASSERT_EQ (15ULL, out->stream_id);

  Arena_dispose (&arena);
}

TEST (h3_push_open_unpromised)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_server_conn_push_ready (arena, 5);

  /* Try to open stream for push_id 0 that was never promised */
  SocketHTTP3_Request_T req = SocketHTTP3_Conn_open_push_stream (conn, 0);
  ASSERT_NULL (req);

  Arena_dispose (&arena);
}

TEST (h3_push_open_cancelled)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_server_conn_with_request (arena, 5);

  uint64_t push_id;
  SocketHTTP3_Conn_allocate_push_id (conn, &push_id);
  SocketHTTP_Headers_T headers = make_push_promise_headers (arena);
  SocketHTTP3_Conn_send_push_promise (conn, 0, push_id, headers);
  SocketHTTP3_Conn_drain_output (conn);

  /* Cancel the push */
  SocketHTTP3_Conn_cancel_push (conn, push_id);
  SocketHTTP3_Conn_drain_output (conn);

  /* Try to open — should fail */
  SocketHTTP3_Request_T req = SocketHTTP3_Conn_open_push_stream (conn, push_id);
  ASSERT_NULL (req);

  Arena_dispose (&arena);
}

TEST (h3_push_response)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_server_conn_with_request (arena, 5);

  uint64_t push_id;
  SocketHTTP3_Conn_allocate_push_id (conn, &push_id);
  SocketHTTP_Headers_T promise = make_push_promise_headers (arena);
  SocketHTTP3_Conn_send_push_promise (conn, 0, push_id, promise);
  SocketHTTP3_Conn_drain_output (conn);

  SocketHTTP3_Request_T req = SocketHTTP3_Conn_open_push_stream (conn, push_id);
  ASSERT_NOT_NULL (req);
  SocketHTTP3_Conn_drain_output (conn);

  /* Send response headers */
  SocketHTTP_Headers_T resp = make_response_headers (arena);
  int rc = SocketHTTP3_Request_send_headers (req, resp, 0);
  ASSERT_EQ (0, rc);
  ASSERT (SocketHTTP3_Conn_output_count (conn) > 0);
  SocketHTTP3_Conn_drain_output (conn);

  /* Send response data */
  const char *body = "body { color: red; }";
  rc = SocketHTTP3_Request_send_data (req, body, strlen (body), 1);
  ASSERT_EQ (0, rc);
  ASSERT (SocketHTTP3_Conn_output_count (conn) > 0);

  Arena_dispose (&arena);
}

TEST (h3_push_cancel_before_open)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_server_conn_with_request (arena, 5);

  uint64_t push_id;
  SocketHTTP3_Conn_allocate_push_id (conn, &push_id);
  SocketHTTP_Headers_T headers = make_push_promise_headers (arena);
  SocketHTTP3_Conn_send_push_promise (conn, 0, push_id, headers);
  SocketHTTP3_Conn_drain_output (conn);

  int rc = SocketHTTP3_Conn_cancel_push (conn, push_id);
  ASSERT_EQ (0, rc);

  /* Output should have CANCEL_PUSH frame on control stream */
  ASSERT (SocketHTTP3_Conn_output_count (conn) > 0);
  const SocketHTTP3_Output *out = SocketHTTP3_Conn_get_output (conn, 0);
  ASSERT_NOT_NULL (out);
  ASSERT_EQ (conn->local_control_id, out->stream_id);

  /* Push entry should be CANCELLED */
  ASSERT_EQ (H3_PUSH_CANCELLED, conn->pushes[0].state);

  Arena_dispose (&arena);
}

TEST (h3_push_cancel_after_open)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_server_conn_with_request (arena, 5);

  uint64_t push_id;
  SocketHTTP3_Conn_allocate_push_id (conn, &push_id);
  SocketHTTP_Headers_T headers = make_push_promise_headers (arena);
  SocketHTTP3_Conn_send_push_promise (conn, 0, push_id, headers);
  SocketHTTP3_Conn_drain_output (conn);

  SocketHTTP3_Conn_open_push_stream (conn, push_id);
  SocketHTTP3_Conn_drain_output (conn);

  int rc = SocketHTTP3_Conn_cancel_push (conn, push_id);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (H3_PUSH_CANCELLED, conn->pushes[0].state);

  Arena_dispose (&arena);
}

TEST (h3_push_cancel_server_recv)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_server_conn_with_request (arena, 5);

  uint64_t push_id;
  SocketHTTP3_Conn_allocate_push_id (conn, &push_id);
  SocketHTTP_Headers_T headers = make_push_promise_headers (arena);
  SocketHTTP3_Conn_send_push_promise (conn, 0, push_id, headers);
  SocketHTTP3_Conn_drain_output (conn);

  /* Simulate client sending CANCEL_PUSH via control stream */
  uint8_t buf[16];
  size_t len = build_cancel_push_frame (buf, sizeof (buf), push_id);
  ASSERT (len > 0);

  int rc = SocketHTTP3_Conn_feed_stream (conn, 2, buf, len, 0);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (H3_PUSH_CANCELLED, conn->pushes[0].state);

  Arena_dispose (&arena);
}

TEST (h3_push_max_push_id_send)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer_control (arena);
  SocketHTTP3_Conn_drain_output (conn);

  int rc = SocketHTTP3_Conn_send_max_push_id (conn, 10);
  ASSERT_EQ (0, rc);

  /* Output should have MAX_PUSH_ID on control stream */
  ASSERT (SocketHTTP3_Conn_output_count (conn) > 0);
  const SocketHTTP3_Output *out = SocketHTTP3_Conn_get_output (conn, 0);
  ASSERT_NOT_NULL (out);
  ASSERT_EQ (conn->local_control_id, out->stream_id);

  /* Verify tracked locally */
  ASSERT_EQ (10ULL, conn->local_max_push_id);
  ASSERT_EQ (1, conn->local_max_push_id_sent);

  Arena_dispose (&arena);
}

TEST (h3_push_max_push_id_decrease)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer_control (arena);

  SocketHTTP3_Conn_send_max_push_id (conn, 10);
  SocketHTTP3_Conn_drain_output (conn);

  /* Decrease should fail */
  ASSERT_EQ (-(int)H3_ID_ERROR, SocketHTTP3_Conn_send_max_push_id (conn, 5));

  Arena_dispose (&arena);
}

/**
 * @brief Build a PUSH_PROMISE frame payload: push_id(varint) + QPACK data.
 *
 * Uses static-table-only encoding for the promised headers.
 */
static size_t
build_push_promise_payload (Arena_T arena,
                            uint64_t push_id,
                            const SocketHTTP_Headers_T headers,
                            uint8_t *buf,
                            size_t buflen)
{
  size_t pos = 0;

  /* Push ID varint */
  size_t vid_len = SocketQUICVarInt_encode (push_id, buf + pos, buflen - pos);
  if (vid_len == 0)
    return 0;
  pos += vid_len;

  /* QPACK encode headers */
  uint8_t *qpack_data;
  size_t qpack_len;
  int rc = h3_qpack_encode_headers (arena, headers, &qpack_data, &qpack_len);
  if (rc != 0)
    return 0;

  if (pos + qpack_len > buflen)
    return 0;
  memcpy (buf + pos, qpack_data, qpack_len);
  pos += qpack_len;

  return pos;
}

/**
 * @brief Build a complete PUSH_PROMISE frame (frame header + payload).
 */
static size_t
build_push_promise_frame (Arena_T arena,
                          uint64_t push_id,
                          const SocketHTTP_Headers_T headers,
                          uint8_t *buf,
                          size_t buflen)
{
  /* Build payload first in temp buffer */
  uint8_t payload[4096];
  size_t payload_len = build_push_promise_payload (
      arena, push_id, headers, payload, sizeof (payload));
  if (payload_len == 0)
    return 0;

  /* Frame header */
  size_t pos = 0;
  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_PUSH_PROMISE, payload_len, buf + pos, buflen - pos);
  if (hdr_len < 0)
    return 0;
  pos += (size_t)hdr_len;

  memcpy (buf + pos, payload, payload_len);
  pos += payload_len;
  return pos;
}

/* Callback state for push promise tests */
static int push_cb_called;
static uint64_t push_cb_push_id;

static void
push_callback (SocketHTTP3_Conn_T conn,
               uint64_t push_id,
               SocketHTTP_Headers_T promised_headers,
               void *userdata)
{
  (void)conn;
  (void)promised_headers;
  (void)userdata;
  push_cb_called = 1;
  push_cb_push_id = push_id;
}

TEST (h3_push_client_recv_promise)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer_control (arena);

  /* Feed SETTINGS from server on peer control stream 3 */
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  uint8_t sbuf[64];
  size_t slen = build_settings_frame (sbuf, sizeof (sbuf), &settings);
  SocketHTTP3_Conn_feed_stream (conn, 3, sbuf, slen, 0);

  /* Register push callback */
  push_cb_called = 0;
  push_cb_push_id = UINT64_MAX;
  SocketHTTP3_Conn_on_push (conn, push_callback, NULL);

  /* Create a client request on stream 0 */
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new (conn);
  ASSERT_NOT_NULL (req);

  /* Build a response with PUSH_PROMISE before the actual response headers */
  SocketHTTP_Headers_T promise = make_push_promise_headers (arena);
  uint8_t pp_frame[4096];
  size_t pp_len = build_push_promise_frame (
      arena, 0, promise, pp_frame, sizeof (pp_frame));
  ASSERT (pp_len > 0);

  /* Feed PUSH_PROMISE on request stream 0 */
  int rc = SocketHTTP3_Conn_feed_stream (conn, 0, pp_frame, pp_len, 0);
  ASSERT_EQ (0, rc);

  /* Callback should have been invoked */
  ASSERT_EQ (1, push_cb_called);
  ASSERT_EQ (0ULL, push_cb_push_id);

  /* Push entry should exist */
  ASSERT_EQ ((size_t)1, conn->push_count);
  ASSERT_EQ (H3_PUSH_PROMISED, conn->pushes[0].state);

  Arena_dispose (&arena);
}

TEST (h3_push_client_recv_stream)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn_with_peer_control (arena);

  /* Feed SETTINGS */
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  uint8_t sbuf[64];
  size_t slen = build_settings_frame (sbuf, sizeof (sbuf), &settings);
  SocketHTTP3_Conn_feed_stream (conn, 3, sbuf, slen, 0);

  /* Create request + send PUSH_PROMISE for push_id=0 */
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new (conn);
  ASSERT_NOT_NULL (req);

  SocketHTTP_Headers_T promise = make_push_promise_headers (arena);
  uint8_t pp_frame[4096];
  size_t pp_len = build_push_promise_frame (
      arena, 0, promise, pp_frame, sizeof (pp_frame));
  SocketHTTP3_Conn_feed_stream (conn, 0, pp_frame, pp_len, 0);

  /* Simulate server push stream (server unidi stream 15): type(0x01) */
  uint8_t stream_type = 0x01;
  int rc = SocketHTTP3_Conn_feed_stream (conn, 15, &stream_type, 1, 0);
  ASSERT_EQ (0, rc);

  /* Feed push_id varint (0) + a HEADERS frame */
  uint8_t push_data[4096];
  size_t pos = 0;
  pos += SocketQUICVarInt_encode (0, push_data + pos, sizeof (push_data) - pos);

  /* Build response HEADERS frame */
  SocketHTTP_Headers_T resp = make_response_headers (arena);
  uint8_t *qpack_data;
  size_t qpack_len;
  h3_qpack_encode_headers (arena, resp, &qpack_data, &qpack_len);

  uint8_t frame_hdr[16];
  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_HEADERS, qpack_len, frame_hdr, sizeof (frame_hdr));
  ASSERT (hdr_len > 0);
  memcpy (push_data + pos, frame_hdr, (size_t)hdr_len);
  pos += (size_t)hdr_len;
  memcpy (push_data + pos, qpack_data, qpack_len);
  pos += qpack_len;

  rc = SocketHTTP3_Conn_feed_stream (conn, 15, push_data, pos, 1);
  ASSERT_EQ (0, rc);

  /* Push entry should be STREAM_OPENED with a request */
  ASSERT_EQ (H3_PUSH_STREAM_OPENED, conn->pushes[0].state);
  ASSERT_NOT_NULL (conn->pushes[0].request);

  Arena_dispose (&arena);
}

TEST (h3_push_full_lifecycle)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_server_conn_with_request (arena, 5);

  /* Allocate push ID */
  uint64_t push_id;
  ASSERT_EQ (0, SocketHTTP3_Conn_allocate_push_id (conn, &push_id));
  ASSERT_EQ (0ULL, push_id);

  /* Send PUSH_PROMISE */
  SocketHTTP_Headers_T promise = make_push_promise_headers (arena);
  ASSERT_EQ (0, SocketHTTP3_Conn_send_push_promise (conn, 0, push_id, promise));
  SocketHTTP3_Conn_drain_output (conn);

  /* Open push stream */
  SocketHTTP3_Request_T req = SocketHTTP3_Conn_open_push_stream (conn, push_id);
  ASSERT_NOT_NULL (req);
  SocketHTTP3_Conn_drain_output (conn);

  /* Send response headers */
  SocketHTTP_Headers_T resp = make_response_headers (arena);
  ASSERT_EQ (0, SocketHTTP3_Request_send_headers (req, resp, 0));
  SocketHTTP3_Conn_drain_output (conn);

  /* Send response body */
  const char *body = "body{}";
  ASSERT_EQ (0, SocketHTTP3_Request_send_data (req, body, strlen (body), 1));
  ASSERT (SocketHTTP3_Conn_output_count (conn) > 0);

  /* Verify send state is complete */
  ASSERT_EQ (H3_REQ_SEND_DONE, SocketHTTP3_Request_send_state (req));

  Arena_dispose (&arena);
}

TEST (h3_push_null_params)
{
  ASSERT_EQ (-1, SocketHTTP3_Conn_allocate_push_id (NULL, NULL));
  ASSERT_EQ (-1, SocketHTTP3_Conn_send_push_promise (NULL, 0, 0, NULL));
  ASSERT_NULL (SocketHTTP3_Conn_open_push_stream (NULL, 0));
  ASSERT_EQ (-1, SocketHTTP3_Conn_cancel_push (NULL, 0));
  ASSERT_EQ (-1, SocketHTTP3_Conn_send_max_push_id (NULL, 0));
}

TEST (h3_push_after_goaway)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_server_conn_with_request (arena, 5);

  /* Shutdown the connection */
  SocketHTTP3_Conn_shutdown (conn, 0);
  SocketHTTP3_Conn_drain_output (conn);

  /* Push operations should fail after GOAWAY */
  uint64_t push_id;
  ASSERT_NE (0, SocketHTTP3_Conn_allocate_push_id (conn, &push_id));

  Arena_dispose (&arena);
}

TEST (h3_push_count_exhaustion)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn
      = make_server_conn_with_request (arena, H3_MAX_PUSH_STREAMS + 10);

  SocketHTTP_Headers_T headers = make_push_promise_headers (arena);

  /* Allocate and promise all push IDs up to max */
  for (size_t i = 0; i < H3_MAX_PUSH_STREAMS; i++)
    {
      uint64_t push_id;
      ASSERT_EQ (0, SocketHTTP3_Conn_allocate_push_id (conn, &push_id));
      ASSERT_EQ (
          0, SocketHTTP3_Conn_send_push_promise (conn, 0, push_id, headers));
      SocketHTTP3_Conn_drain_output (conn);
    }

  /* Next allocation should fail */
  uint64_t push_id;
  ASSERT_EQ (-(int)H3_ID_ERROR,
             SocketHTTP3_Conn_allocate_push_id (conn, &push_id));

  Arena_dispose (&arena);
}

TEST (h3_push_cancel_unknown)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_server_conn_push_ready (arena, 5);

  /* Register peer control */
  SocketHTTP3_StreamMap_register (conn->stream_map, 2, H3_STREAM_TYPE_CONTROL);

  /* Feed CANCEL_PUSH for unknown push_id on already-registered control */
  uint8_t buf[16];
  size_t len = build_cancel_push_frame (buf, sizeof (buf), 99);
  ASSERT (len > 0);

  /* Should be silently ignored (no error) */
  int rc = SocketHTTP3_Conn_feed_stream (conn, 2, buf, len, 0);
  ASSERT_EQ (0, rc);

  Arena_dispose (&arena);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

#else /* !SOCKET_HAS_H3_PUSH */

int
main (void)
{
  return 0;
}

#endif /* SOCKET_HAS_H3_PUSH */

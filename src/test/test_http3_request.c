/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_http3_request.c
 * @brief Unit tests for HTTP/3 request/response exchange (RFC 9114 §4).
 */

#include "core/Arena.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP3.h"
#include "http/SocketHTTP3-constants.h"
#include "http/SocketHTTP3-frame.h"
#include "http/SocketHTTP3-private.h"
#include "http/SocketHTTP3-request.h"
#include "http/qpack/SocketQPACK.h"
#include "quic/SocketQUICVarInt.h"
#include "test/Test.h"

#include <string.h>

/* ============================================================================
 * Test Helpers
 * ============================================================================
 */

static int
add_pseudo (SocketHTTP_Headers_T h, const char *name, const char *value)
{
  return SocketHTTP_Headers_add_pseudo_n (
      h, name, strlen (name), value, value ? strlen (value) : 0);
}

static SocketHTTP3_Conn_T
make_client_conn (Arena_T arena)
{
  SocketHTTP3_ConnConfig config;
  SocketHTTP3_ConnConfig_defaults (&config, H3_ROLE_CLIENT);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &config);
  SocketHTTP3_Conn_init (conn);
  SocketHTTP3_Conn_drain_output (conn);
  return conn;
}

static SocketHTTP_Headers_T
make_get_headers (Arena_T arena)
{
  SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
  add_pseudo (h, ":method", "GET");
  add_pseudo (h, ":scheme", "https");
  add_pseudo (h, ":path", "/");
  add_pseudo (h, ":authority", "example.com");
  return h;
}

static SocketHTTP_Headers_T
make_post_headers (Arena_T arena)
{
  SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
  add_pseudo (h, ":method", "POST");
  add_pseudo (h, ":scheme", "https");
  add_pseudo (h, ":path", "/submit");
  add_pseudo (h, ":authority", "example.com");
  SocketHTTP_Headers_add (h, "content-type", "application/json");
  return h;
}

/**
 * @brief Build a QPACK-encoded HEADERS frame for a response.
 *
 * Uses static-table-only encoding.
 */
static size_t
build_response_frame (uint8_t *buf,
                      size_t buflen,
                      const SocketHTTP_Headers_T headers)
{
  /* QPACK-encode the headers */
  unsigned char qpack_buf[4096];
  size_t qpos = 0;

  /* Prefix: RIC=0, Base=0 */
  size_t prefix_len;
  if (SocketQPACK_encode_prefix (
          0, 0, 1, qpack_buf, sizeof (qpack_buf), &prefix_len)
      != QPACK_OK)
    return 0;
  qpos += prefix_len;

  size_t count = SocketHTTP_Headers_count (headers);
  for (size_t i = 0; i < count; i++)
    {
      const SocketHTTP_Header *h = SocketHTTP_Headers_at (headers, i);
      size_t written;

      /* Try exact match in static table */
      int found_exact
          = h3_find_static_exact (h->name, h->name_len, h->value, h->value_len);
      if (found_exact >= 0)
        {
          if (SocketQPACK_encode_indexed_field (qpack_buf + qpos,
                                                sizeof (qpack_buf) - qpos,
                                                (uint64_t)found_exact,
                                                true,
                                                &written)
              != QPACK_OK)
            return 0;
          qpos += written;
          continue;
        }

      /* Try name match */
      int found_name = h3_find_static_name (h->name, h->name_len);
      if (found_name >= 0)
        {
          if (SocketQPACK_encode_literal_name_ref (
                  qpack_buf + qpos,
                  sizeof (qpack_buf) - qpos,
                  true,
                  (uint64_t)found_name,
                  false,
                  (const unsigned char *)h->value,
                  h->value_len,
                  false,
                  &written)
              != QPACK_OK)
            return 0;
          qpos += written;
          continue;
        }

      /* Literal */
      if (SocketQPACK_encode_literal_field_literal_name (
              qpack_buf + qpos,
              sizeof (qpack_buf) - qpos,
              (const unsigned char *)h->name,
              h->name_len,
              false,
              (const unsigned char *)h->value,
              h->value_len,
              false,
              false,
              &written)
          != QPACK_OK)
        return 0;
      qpos += written;
    }

  /* Wrap in HEADERS frame */
  size_t pos = 0;
  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_HEADERS, qpos, buf + pos, buflen - pos);
  if (hdr_len < 0)
    return 0;
  pos += (size_t)hdr_len;
  memcpy (buf + pos, qpack_buf, qpos);
  pos += qpos;
  return pos;
}

/**
 * @brief Build a DATA frame.
 */
static size_t
build_data_frame (uint8_t *buf,
                  size_t buflen,
                  const void *data,
                  size_t data_len)
{
  size_t pos = 0;
  int hdr_len = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_DATA, data_len, buf + pos, buflen - pos);
  if (hdr_len < 0)
    return 0;
  pos += (size_t)hdr_len;
  if (data_len > 0)
    {
      memcpy (buf + pos, data, data_len);
      pos += data_len;
    }
  return pos;
}

/* ============================================================================
 * Test 1: Send GET request (headers only, end_stream=1)
 * ============================================================================
 */

TEST (h3_req_send_get)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn (arena);

  SocketHTTP3_Request_T req = SocketHTTP3_Request_new (conn);
  ASSERT_NOT_NULL (req);
  ASSERT_EQ (0ULL, SocketHTTP3_Request_stream_id (req));
  ASSERT_EQ (H3_REQ_SEND_IDLE, SocketHTTP3_Request_send_state (req));

  SocketHTTP_Headers_T h = make_get_headers (arena);
  int rc = SocketHTTP3_Request_send_headers (req, h, 1);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (H3_REQ_SEND_DONE, SocketHTTP3_Request_send_state (req));

  /* Check output was queued */
  ASSERT_NE (0ULL, SocketHTTP3_Conn_output_count (conn));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 2: Send POST request (headers + data + end_stream)
 * ============================================================================
 */

TEST (h3_req_send_post)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn (arena);

  SocketHTTP3_Request_T req = SocketHTTP3_Request_new (conn);
  ASSERT_NOT_NULL (req);

  SocketHTTP_Headers_T h = make_post_headers (arena);
  int rc = SocketHTTP3_Request_send_headers (req, h, 0);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (H3_REQ_SEND_HEADERS_SENT, SocketHTTP3_Request_send_state (req));
  SocketHTTP3_Conn_drain_output (conn);

  const char *body = "{\"key\":\"value\"}";
  rc = SocketHTTP3_Request_send_data (req, body, strlen (body), 1);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (H3_REQ_SEND_DONE, SocketHTTP3_Request_send_state (req));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 3: Send request with trailers
 * ============================================================================
 */

TEST (h3_req_send_trailers)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn (arena);

  SocketHTTP3_Request_T req = SocketHTTP3_Request_new (conn);
  SocketHTTP_Headers_T h = make_post_headers (arena);
  SocketHTTP3_Request_send_headers (req, h, 0);
  SocketHTTP3_Conn_drain_output (conn);

  const char *body = "data";
  SocketHTTP3_Request_send_data (req, body, 4, 0);
  SocketHTTP3_Conn_drain_output (conn);
  ASSERT_EQ (H3_REQ_SEND_BODY_SENT, SocketHTTP3_Request_send_state (req));

  SocketHTTP_Headers_T trailers = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_add (trailers, "x-checksum", "abc123");

  int rc = SocketHTTP3_Request_send_trailers (req, trailers);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (H3_REQ_SEND_TRAILERS_SENT, SocketHTTP3_Request_send_state (req));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 4: Receive 200 response with body
 * ============================================================================
 */

TEST (h3_req_recv_200_with_body)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn (arena);
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new (conn);

  /* Send GET request */
  SocketHTTP_Headers_T h = make_get_headers (arena);
  SocketHTTP3_Request_send_headers (req, h, 1);
  SocketHTTP3_Conn_drain_output (conn);

  /* Build response: HEADERS(200) + DATA("hello") */
  uint8_t frame_buf[512];
  SocketHTTP_Headers_T resp_h = SocketHTTP_Headers_new (arena);
  add_pseudo (resp_h, ":status", "200");
  SocketHTTP_Headers_add (resp_h, "content-length", "5");

  size_t hlen = build_response_frame (frame_buf, sizeof (frame_buf), resp_h);
  ASSERT_NE (0ULL, hlen);

  /* Feed HEADERS */
  int rc = SocketHTTP3_Request_feed (req, frame_buf, hlen, 0);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (H3_REQ_RECV_HEADERS_RECEIVED,
             SocketHTTP3_Request_recv_state (req));

  /* Check headers */
  SocketHTTP_Headers_T out_h = NULL;
  int status = 0;
  rc = SocketHTTP3_Request_recv_headers (req, &out_h, &status);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (200, status);
  ASSERT_NOT_NULL (out_h);

  /* Feed DATA + FIN */
  uint8_t data_buf[64];
  size_t dlen = build_data_frame (data_buf, sizeof (data_buf), "hello", 5);
  rc = SocketHTTP3_Request_feed (req, data_buf, dlen, 1);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (H3_REQ_RECV_COMPLETE, SocketHTTP3_Request_recv_state (req));

  /* Read data */
  char rbuf[32];
  int end = 0;
  ssize_t n = SocketHTTP3_Request_recv_data (req, rbuf, sizeof (rbuf), &end);
  ASSERT_EQ (5, (int)n);
  ASSERT_EQ (1, end);
  ASSERT_EQ (0, memcmp (rbuf, "hello", 5));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 5: Receive interim 100 response followed by 200
 * ============================================================================
 */

TEST (h3_req_recv_100_then_200)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn (arena);
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new (conn);

  SocketHTTP_Headers_T h = make_post_headers (arena);
  SocketHTTP3_Request_send_headers (req, h, 0);
  SocketHTTP3_Conn_drain_output (conn);

  /* Feed 100 Continue */
  uint8_t frame_buf[512];
  SocketHTTP_Headers_T h100 = SocketHTTP_Headers_new (arena);
  add_pseudo (h100, ":status", "100");
  size_t len = build_response_frame (frame_buf, sizeof (frame_buf), h100);

  int rc = SocketHTTP3_Request_feed (req, frame_buf, len, 0);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (H3_REQ_RECV_HEADERS_RECEIVED,
             SocketHTTP3_Request_recv_state (req));

  int status = 0;
  SocketHTTP3_Request_recv_headers (req, NULL, &status);
  ASSERT_EQ (100, status);

  /* Feed 200 OK */
  SocketHTTP_Headers_T h200 = SocketHTTP_Headers_new (arena);
  add_pseudo (h200, ":status", "200");
  len = build_response_frame (frame_buf, sizeof (frame_buf), h200);

  rc = SocketHTTP3_Request_feed (req, frame_buf, len, 1);
  ASSERT_EQ (0, rc);

  SocketHTTP3_Request_recv_headers (req, NULL, &status);
  ASSERT_EQ (200, status);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 6: Request cancellation
 * ============================================================================
 */

TEST (h3_req_cancel)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn (arena);
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new (conn);

  int rc = SocketHTTP3_Request_cancel (req);
  ASSERT_EQ (0, rc);

  /* Operations after cancel should fail */
  SocketHTTP_Headers_T h = make_get_headers (arena);
  rc = SocketHTTP3_Request_send_headers (req, h, 1);
  ASSERT_EQ (-(int)H3_REQUEST_CANCELLED, rc);

  /* Double cancel returns error */
  rc = SocketHTTP3_Request_cancel (req);
  ASSERT_EQ (-1, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 7: Malformed request — missing :method
 * ============================================================================
 */

TEST (h3_req_validate_missing_method)
{
  Arena_T arena = Arena_new ();

  SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
  add_pseudo (h, ":scheme", "https");
  add_pseudo (h, ":path", "/");

  int rc = SocketHTTP3_validate_request_headers (h);
  ASSERT_EQ (-(int)H3_MESSAGE_ERROR, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 8: Malformed request — uppercase header name
 * ============================================================================
 */

TEST (h3_req_validate_uppercase)
{
  Arena_T arena = Arena_new ();

  SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
  add_pseudo (h, ":method", "GET");
  add_pseudo (h, ":scheme", "https");
  add_pseudo (h, ":path", "/");
  SocketHTTP_Headers_add (h, "Content-Type", "text/html");

  int rc = SocketHTTP3_validate_request_headers (h);
  ASSERT_EQ (-(int)H3_MESSAGE_ERROR, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 9: Malformed request — Connection header present
 * ============================================================================
 */

TEST (h3_req_validate_connection_header)
{
  Arena_T arena = Arena_new ();

  SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
  add_pseudo (h, ":method", "GET");
  add_pseudo (h, ":scheme", "https");
  add_pseudo (h, ":path", "/");
  SocketHTTP_Headers_add (h, "connection", "keep-alive");

  int rc = SocketHTTP3_validate_request_headers (h);
  ASSERT_EQ (-(int)H3_MESSAGE_ERROR, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 10: Malformed response — missing :status
 * ============================================================================
 */

TEST (h3_req_validate_resp_missing_status)
{
  Arena_T arena = Arena_new ();

  SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
  SocketHTTP_Headers_add (h, "content-type", "text/html");

  int rc = SocketHTTP3_validate_response_headers (h);
  ASSERT_EQ (-(int)H3_MESSAGE_ERROR, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 11: Pseudo-header after regular header
 * ============================================================================
 */

TEST (h3_req_validate_pseudo_after_regular)
{
  Arena_T arena = Arena_new ();

  SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
  add_pseudo (h, ":method", "GET");
  SocketHTTP_Headers_add (h, "host", "example.com");
  add_pseudo (h, ":path", "/");

  int rc = SocketHTTP3_validate_request_headers (h);
  ASSERT_EQ (-(int)H3_MESSAGE_ERROR, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 12: Content-Length mismatch
 * ============================================================================
 */

TEST (h3_req_content_length_mismatch)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn (arena);
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new (conn);

  SocketHTTP_Headers_T h = make_get_headers (arena);
  SocketHTTP3_Request_send_headers (req, h, 1);
  SocketHTTP3_Conn_drain_output (conn);

  /* Response with content-length: 10, but only 5 bytes of data */
  uint8_t frame_buf[512];
  SocketHTTP_Headers_T resp_h = SocketHTTP_Headers_new (arena);
  add_pseudo (resp_h, ":status", "200");
  SocketHTTP_Headers_add (resp_h, "content-length", "10");
  size_t hlen = build_response_frame (frame_buf, sizeof (frame_buf), resp_h);

  SocketHTTP3_Request_feed (req, frame_buf, hlen, 0);

  /* Feed DATA with only 5 bytes, then FIN */
  uint8_t data_buf[64];
  size_t dlen = build_data_frame (data_buf, sizeof (data_buf), "hello", 5);
  int rc = SocketHTTP3_Request_feed (req, data_buf, dlen, 1);
  ASSERT_EQ (-(int)H3_MESSAGE_ERROR, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 13: CONNECT method (only :method and :authority)
 * ============================================================================
 */

TEST (h3_req_validate_connect)
{
  Arena_T arena = Arena_new ();

  /* Valid CONNECT */
  SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
  add_pseudo (h, ":method", "CONNECT");
  add_pseudo (h, ":authority", "proxy.example.com:443");
  int rc = SocketHTTP3_validate_request_headers (h);
  ASSERT_EQ (0, rc);

  /* Invalid CONNECT with :scheme */
  SocketHTTP_Headers_T h2 = SocketHTTP_Headers_new (arena);
  add_pseudo (h2, ":method", "CONNECT");
  add_pseudo (h2, ":authority", "proxy.example.com:443");
  add_pseudo (h2, ":scheme", "https");
  rc = SocketHTTP3_validate_request_headers (h2);
  ASSERT_EQ (-(int)H3_MESSAGE_ERROR, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 14: DATA before HEADERS on receive
 * ============================================================================
 */

TEST (h3_req_data_before_headers)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn (arena);
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new (conn);

  SocketHTTP_Headers_T h = make_get_headers (arena);
  SocketHTTP3_Request_send_headers (req, h, 1);
  SocketHTTP3_Conn_drain_output (conn);

  /* Feed DATA frame before HEADERS */
  uint8_t data_buf[64];
  size_t dlen = build_data_frame (data_buf, sizeof (data_buf), "data", 4);
  int rc = SocketHTTP3_Request_feed (req, data_buf, dlen, 0);
  ASSERT_EQ (-(int)H3_FRAME_UNEXPECTED, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 15: Cookie header concatenation
 * ============================================================================
 */

TEST (h3_req_cookie_concatenation)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn (arena);
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new (conn);

  SocketHTTP_Headers_T h = make_get_headers (arena);
  SocketHTTP3_Request_send_headers (req, h, 1);
  SocketHTTP3_Conn_drain_output (conn);

  /* Build response with multiple cookie headers */
  SocketHTTP_Headers_T resp_h = SocketHTTP_Headers_new (arena);
  add_pseudo (resp_h, ":status", "200");
  SocketHTTP_Headers_add (resp_h, "cookie", "a=1");
  SocketHTTP_Headers_add (resp_h, "cookie", "b=2");

  uint8_t frame_buf[512];
  size_t hlen = build_response_frame (frame_buf, sizeof (frame_buf), resp_h);

  int rc = SocketHTTP3_Request_feed (req, frame_buf, hlen, 1);
  ASSERT_EQ (0, rc);

  /* Verify cookies are concatenated */
  SocketHTTP_Headers_T out_h = NULL;
  SocketHTTP3_Request_recv_headers (req, &out_h, NULL);
  ASSERT_NOT_NULL (out_h);

  const char *cookie_val = SocketHTTP_Headers_get_n (out_h, "cookie", 6);
  ASSERT_NOT_NULL (cookie_val);
  ASSERT_EQ (0, strcmp (cookie_val, "a=1; b=2"));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 16: Multiple requests on same connection
 * ============================================================================
 */

TEST (h3_req_multiple_requests)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn (arena);

  SocketHTTP3_Request_T req0 = SocketHTTP3_Request_new (conn);
  SocketHTTP3_Request_T req1 = SocketHTTP3_Request_new (conn);
  SocketHTTP3_Request_T req2 = SocketHTTP3_Request_new (conn);

  ASSERT_NOT_NULL (req0);
  ASSERT_NOT_NULL (req1);
  ASSERT_NOT_NULL (req2);

  ASSERT_EQ (0ULL, SocketHTTP3_Request_stream_id (req0));
  ASSERT_EQ (4ULL, SocketHTTP3_Request_stream_id (req1));
  ASSERT_EQ (8ULL, SocketHTTP3_Request_stream_id (req2));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 17: NULL parameter handling
 * ============================================================================
 */

TEST (h3_req_null_params)
{
  ASSERT_NULL (SocketHTTP3_Request_new (NULL));
  ASSERT_EQ (-1, SocketHTTP3_Request_send_headers (NULL, NULL, 0));
  ASSERT_EQ (-1, SocketHTTP3_Request_send_data (NULL, NULL, 0, 0));
  ASSERT_EQ (-1, SocketHTTP3_Request_send_trailers (NULL, NULL));
  ASSERT_EQ (-1, SocketHTTP3_Request_recv_headers (NULL, NULL, NULL));
  ASSERT_EQ (-1, (int)SocketHTTP3_Request_recv_data (NULL, NULL, 0, NULL));
  ASSERT_EQ (-1, SocketHTTP3_Request_cancel (NULL));
  ASSERT_EQ (UINT64_MAX, SocketHTTP3_Request_stream_id (NULL));

  /* Validation with NULL */
  ASSERT_EQ (-(int)H3_MESSAGE_ERROR,
             SocketHTTP3_validate_request_headers (NULL));
  ASSERT_EQ (-(int)H3_MESSAGE_ERROR,
             SocketHTTP3_validate_response_headers (NULL));
}

/* ============================================================================
 * Test 18: State machine violations — double send_headers
 * ============================================================================
 */

TEST (h3_req_double_send_headers)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn (arena);
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new (conn);

  SocketHTTP_Headers_T h = make_get_headers (arena);
  int rc = SocketHTTP3_Request_send_headers (req, h, 0);
  ASSERT_EQ (0, rc);

  /* Second send_headers should fail */
  rc = SocketHTTP3_Request_send_headers (req, h, 0);
  ASSERT_NE (0, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 19: DATA after end_stream
 * ============================================================================
 */

TEST (h3_req_data_after_end_stream)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn (arena);
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new (conn);

  SocketHTTP_Headers_T h = make_get_headers (arena);
  SocketHTTP3_Request_send_headers (req, h, 1); /* end_stream=1 */

  /* DATA after end_stream should fail */
  int rc = SocketHTTP3_Request_send_data (req, "data", 4, 0);
  ASSERT_NE (0, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 20: Status 101 rejection (§4.5)
 * ============================================================================
 */

TEST (h3_req_status_101_rejected)
{
  Arena_T arena = Arena_new ();

  SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
  add_pseudo (h, ":status", "101");

  int rc = SocketHTTP3_validate_response_headers (h);
  ASSERT_EQ (-(int)H3_MESSAGE_ERROR, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 21: FIN before HEADERS
 * ============================================================================
 */

TEST (h3_req_fin_before_headers)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Conn_T conn = make_client_conn (arena);
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new (conn);

  SocketHTTP_Headers_T h = make_get_headers (arena);
  SocketHTTP3_Request_send_headers (req, h, 1);
  SocketHTTP3_Conn_drain_output (conn);

  /* FIN with no data at all */
  int rc = SocketHTTP3_Request_feed (req, NULL, 0, 1);
  ASSERT_EQ (-(int)H3_REQUEST_INCOMPLETE, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 22: Valid request headers pass validation
 * ============================================================================
 */

TEST (h3_req_validate_valid_request)
{
  Arena_T arena = Arena_new ();

  SocketHTTP_Headers_T h = make_get_headers (arena);
  int rc = SocketHTTP3_validate_request_headers (h);
  ASSERT_EQ (0, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 23: Valid response headers pass validation
 * ============================================================================
 */

TEST (h3_req_validate_valid_response)
{
  Arena_T arena = Arena_new ();

  SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
  add_pseudo (h, ":status", "200");
  SocketHTTP_Headers_add (h, "content-type", "text/html");

  int rc = SocketHTTP3_validate_response_headers (h);
  ASSERT_EQ (0, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 24: TE header with "trailers" value is allowed
 * ============================================================================
 */

TEST (h3_req_validate_te_trailers)
{
  Arena_T arena = Arena_new ();

  SocketHTTP_Headers_T h = SocketHTTP_Headers_new (arena);
  add_pseudo (h, ":method", "GET");
  add_pseudo (h, ":scheme", "https");
  add_pseudo (h, ":path", "/");
  SocketHTTP_Headers_add (h, "te", "trailers");

  int rc = SocketHTTP3_validate_request_headers (h);
  ASSERT_EQ (0, rc);

  /* TE with other value should fail */
  SocketHTTP_Headers_T h2 = SocketHTTP_Headers_new (arena);
  add_pseudo (h2, ":method", "GET");
  add_pseudo (h2, ":scheme", "https");
  add_pseudo (h2, ":path", "/");
  SocketHTTP_Headers_add (h2, "te", "gzip");

  rc = SocketHTTP3_validate_request_headers (h2);
  ASSERT_EQ (-(int)H3_MESSAGE_ERROR, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test 25: QPACK static table get accessor
 * ============================================================================
 */

TEST (h3_qpack_static_table_get)
{
  const char *name, *value;
  size_t nlen, vlen;

  /* Index 0: :authority "" */
  SocketQPACK_Result res
      = SocketQPACK_static_table_get (0, &name, &nlen, &value, &vlen);
  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (10ULL, nlen);
  ASSERT_EQ (0, memcmp (name, ":authority", 10));
  ASSERT_EQ (0ULL, vlen);

  /* Index 25: :status 200 */
  res = SocketQPACK_static_table_get (25, &name, &nlen, &value, &vlen);
  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (7ULL, nlen);
  ASSERT_EQ (0, memcmp (name, ":status", 7));
  ASSERT_EQ (3ULL, vlen);
  ASSERT_EQ (0, memcmp (value, "200", 3));

  /* Out of bounds */
  res = SocketQPACK_static_table_get (99, NULL, NULL, NULL, NULL);
  ASSERT_EQ (QPACK_ERR_INVALID_INDEX, res);

  /* NULL output params are OK */
  res = SocketQPACK_static_table_get (1, NULL, NULL, NULL, NULL);
  ASSERT_EQ (QPACK_OK, res);
}

/* ============================================================================
 * Entry Point
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

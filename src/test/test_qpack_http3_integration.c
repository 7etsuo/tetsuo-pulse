/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_http3_integration.c
 * @brief Integration tests for HTTP/3 header encoding scenarios.
 *
 * Tests realistic HTTP/3 request/response header patterns using QPACK,
 * including:
 * - Standard HTTP/3 request headers
 * - Standard HTTP/3 response headers
 * - Pseudo-headers (:method, :path, :status, etc.)
 * - Common header combinations
 */

#include <string.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACK.h"
#include "test/Test.h"

TEST (qpack_http3_simple_get_request)
{
  /* Encode a simple GET request:
   * :method: GET
   * :scheme: https
   * :path: /
   * :authority: example.com
   */
  Arena_T arena = Arena_new ();
  unsigned char buf[512];
  size_t offset = 0;
  size_t written = 0;

  /* Prefix: RIC=0, Base=0 (all static) */
  SocketQPACK_Result result = SocketQPACK_encode_prefix (
      0, 0, 128, buf + offset, sizeof (buf) - offset, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* :method: GET (static index 17) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 17, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* :scheme: https (static index 23) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 23, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* :path: / (static index 1) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 1, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* :authority: example.com (literal with name reference, static index 0) */
  result = SocketQPACK_encode_literal_name_ref (
      buf + offset,
      sizeof (buf) - offset,
      true,
      0,
      false,
      (const unsigned char *)"example.com",
      11,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  ASSERT (offset > 0);
  ASSERT (offset < 100); /* Efficient encoding */

  /* Decode and verify prefix */
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;
  size_t decode_offset = 0;

  result = SocketQPACK_decode_prefix (buf, offset, 128, 0, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (prefix.required_insert_count, 0);
  decode_offset += consumed;

  /* Decode :method: GET */
  uint64_t index = 0;
  int is_static = 0;
  result = SocketQPACK_decode_indexed_field (buf + decode_offset,
                                             offset - decode_offset,
                                             &index,
                                             &is_static,
                                             &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (is_static, 1);
  ASSERT_EQ (index, 17);
  decode_offset += consumed;

  /* Decode :scheme: https */
  result = SocketQPACK_decode_indexed_field (buf + decode_offset,
                                             offset - decode_offset,
                                             &index,
                                             &is_static,
                                             &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (is_static, 1);
  ASSERT_EQ (index, 23);
  decode_offset += consumed;

  /* Decode :path: / */
  result = SocketQPACK_decode_indexed_field (buf + decode_offset,
                                             offset - decode_offset,
                                             &index,
                                             &is_static,
                                             &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (is_static, 1);
  ASSERT_EQ (index, 1);
  decode_offset += consumed;

  /* Decode :authority: example.com */
  SocketQPACK_LiteralNameRef name_ref;
  result = SocketQPACK_decode_literal_name_ref (
      buf + decode_offset, offset - decode_offset, &name_ref, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_ref.is_static, true);
  ASSERT_EQ (name_ref.name_index, 0);
  ASSERT_EQ (name_ref.value_len, 11);
  ASSERT (memcmp (name_ref.value, "example.com", 11) == 0);

  Arena_dispose (&arena);
}

TEST (qpack_http3_post_request_with_content_type)
{
  /* Encode a POST request with body:
   * :method: POST
   * :scheme: https
   * :path: /api/users
   * :authority: api.example.com
   * content-type: application/json
   * content-length: 42
   */
  unsigned char buf[512];
  size_t offset = 0;
  size_t written = 0;

  /* Prefix: RIC=0, Base=0 */
  SocketQPACK_Result result = SocketQPACK_encode_prefix (
      0, 0, 128, buf + offset, sizeof (buf) - offset, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* :method: POST (static index 20) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 20, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* :scheme: https (static index 23) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 23, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* :path: /api/users (literal with name ref, static index 1) */
  result = SocketQPACK_encode_literal_name_ref (
      buf + offset,
      sizeof (buf) - offset,
      true,
      1,
      false,
      (const unsigned char *)"/api/users",
      10,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* :authority: api.example.com */
  result = SocketQPACK_encode_literal_name_ref (
      buf + offset,
      sizeof (buf) - offset,
      true,
      0,
      false,
      (const unsigned char *)"api.example.com",
      15,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* content-type: application/json (static index 31 is text/html, use 52) */
  /* Static index 52 is content-type without value */
  result = SocketQPACK_encode_literal_name_ref (
      buf + offset,
      sizeof (buf) - offset,
      true,
      52,
      false,
      (const unsigned char *)"application/json",
      16,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* content-length: 42 (literal with literal name) */
  result = SocketQPACK_encode_literal_field_literal_name (
      buf + offset,
      sizeof (buf) - offset,
      (const unsigned char *)"content-length",
      14,
      false,
      (const unsigned char *)"42",
      2,
      false,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  ASSERT (offset > 0);
  ASSERT (offset < 150);
}

TEST (qpack_http3_options_preflight)
{
  /* Encode an OPTIONS preflight request:
   * :method: OPTIONS
   * :scheme: https
   * :path: /api/users
   * :authority: api.example.com
   * access-control-request-method: POST
   * access-control-request-headers: content-type
   * origin: https://example.com
   */
  unsigned char buf[512];
  size_t offset = 0;
  size_t written = 0;

  /* Prefix */
  SocketQPACK_Result result = SocketQPACK_encode_prefix (
      0, 0, 128, buf + offset, sizeof (buf) - offset, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* :method: OPTIONS (static index 19) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 19, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* :scheme: https */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 23, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* :path and :authority as literals */
  result = SocketQPACK_encode_literal_name_ref (
      buf + offset,
      sizeof (buf) - offset,
      true,
      1,
      false,
      (const unsigned char *)"/api/users",
      10,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  result = SocketQPACK_encode_literal_name_ref (
      buf + offset,
      sizeof (buf) - offset,
      true,
      0,
      false,
      (const unsigned char *)"api.example.com",
      15,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* CORS headers as literal with literal name */
  result = SocketQPACK_encode_literal_field_literal_name (
      buf + offset,
      sizeof (buf) - offset,
      (const unsigned char *)"access-control-request-method",
      29,
      true,
      (const unsigned char *)"POST",
      4,
      false,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  result = SocketQPACK_encode_literal_field_literal_name (
      buf + offset,
      sizeof (buf) - offset,
      (const unsigned char *)"access-control-request-headers",
      30,
      true,
      (const unsigned char *)"content-type",
      12,
      false,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* origin (static index 90) */
  result = SocketQPACK_encode_literal_name_ref (
      buf + offset,
      sizeof (buf) - offset,
      true,
      90,
      false,
      (const unsigned char *)"https://example.com",
      19,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  ASSERT (offset > 0);
}

TEST (qpack_http3_200_response)
{
  /* Encode a 200 OK response:
   * :status: 200
   * content-type: text/html
   * content-length: 1234
   */
  unsigned char buf[256];
  size_t offset = 0;
  size_t written = 0;

  /* Prefix */
  SocketQPACK_Result result = SocketQPACK_encode_prefix (
      0, 0, 128, buf + offset, sizeof (buf) - offset, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* :status: 200 (static index 25) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 25, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* content-type: text/html;charset=utf-8 (static index 31) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 31, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* content-length: 1234 */
  result = SocketQPACK_encode_literal_field_literal_name (
      buf + offset,
      sizeof (buf) - offset,
      (const unsigned char *)"content-length",
      14,
      true,
      (const unsigned char *)"1234",
      4,
      false,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  ASSERT (offset > 0);
  ASSERT (offset < 50); /* Very compact */
}

TEST (qpack_http3_301_redirect)
{
  /* Encode a 301 redirect response:
   * :status: 301
   * location: https://example.com/new-path
   */
  unsigned char buf[256];
  size_t offset = 0;
  size_t written = 0;

  /* Prefix */
  SocketQPACK_Result result = SocketQPACK_encode_prefix (
      0, 0, 128, buf + offset, sizeof (buf) - offset, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* :status: 301 - not in static table, use literal with name ref */
  /* Static index 24 is :status (no value) */
  result = SocketQPACK_encode_literal_name_ref (buf + offset,
                                                sizeof (buf) - offset,
                                                true,
                                                24,
                                                false,
                                                (const unsigned char *)"301",
                                                3,
                                                false,
                                                &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* location (static index 12) */
  result = SocketQPACK_encode_literal_name_ref (
      buf + offset,
      sizeof (buf) - offset,
      true,
      12,
      false,
      (const unsigned char *)"https://example.com/new-path",
      28,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  ASSERT (offset > 0);
}

TEST (qpack_http3_404_response)
{
  /* Encode a 404 Not Found response:
   * :status: 404
   * content-type: text/plain
   */
  unsigned char buf[256];
  size_t offset = 0;
  size_t written = 0;

  /* Prefix */
  SocketQPACK_Result result = SocketQPACK_encode_prefix (
      0, 0, 128, buf + offset, sizeof (buf) - offset, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* :status: 404 (static index 27) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 27, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* content-type: text/plain;charset=utf-8 (static index 35) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 35, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* Very compact: should be just a few bytes */
  ASSERT (offset > 0);
  ASSERT (offset < 20);
}

TEST (qpack_http3_204_no_content)
{
  /* Encode a 204 No Content response:
   * :status: 204
   */
  unsigned char buf[64];
  size_t offset = 0;
  size_t written = 0;

  /* Prefix */
  SocketQPACK_Result result = SocketQPACK_encode_prefix (
      0, 0, 128, buf + offset, sizeof (buf) - offset, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* :status: 204 (static index 26) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 26, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* Minimal: just prefix + one indexed field */
  ASSERT_EQ (offset, 3); /* 2 bytes prefix + 1 byte indexed */
}

TEST (qpack_http3_500_error_response)
{
  /* Encode a 500 Internal Server Error response:
   * :status: 500
   * content-type: application/json
   * x-request-id: abc123
   */
  unsigned char buf[256];
  size_t offset = 0;
  size_t written = 0;

  /* Prefix */
  SocketQPACK_Result result = SocketQPACK_encode_prefix (
      0, 0, 128, buf + offset, sizeof (buf) - offset, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* :status: 500 (static index 28) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 28, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* content-type: application/json - use literal with name ref */
  result = SocketQPACK_encode_literal_name_ref (
      buf + offset,
      sizeof (buf) - offset,
      true,
      52,
      false,
      (const unsigned char *)"application/json",
      16,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* x-request-id: abc123 (literal with literal name) */
  result = SocketQPACK_encode_literal_field_literal_name (
      buf + offset,
      sizeof (buf) - offset,
      (const unsigned char *)"x-request-id",
      12,
      true,
      (const unsigned char *)"abc123",
      6,
      false,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  ASSERT (offset > 0);
}

TEST (qpack_http3_cache_headers)
{
  /* Encode cache-related headers:
   * cache-control: no-cache
   * etag: "abc123"
   * last-modified: Wed, 21 Oct 2015 07:28:00 GMT
   */
  unsigned char buf[512];
  size_t offset = 0;
  size_t written = 0;

  /* Prefix */
  SocketQPACK_Result result = SocketQPACK_encode_prefix (
      0, 0, 128, buf + offset, sizeof (buf) - offset, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* cache-control: no-cache (static index 42) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 42, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* etag (static index 54) */
  result = SocketQPACK_encode_literal_name_ref (
      buf + offset,
      sizeof (buf) - offset,
      true,
      54,
      false,
      (const unsigned char *)"\"abc123\"",
      8,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* last-modified (static index 10) */
  result = SocketQPACK_encode_literal_name_ref (
      buf + offset,
      sizeof (buf) - offset,
      true,
      10,
      false,
      (const unsigned char *)"Wed, 21 Oct 2015 07:28:00 GMT",
      29,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  ASSERT (offset > 0);
}

TEST (qpack_http3_security_headers)
{
  /* Encode security-related headers:
   * strict-transport-security: max-age=31536000
   * x-content-type-options: nosniff
   * x-frame-options: DENY
   */
  unsigned char buf[512];
  size_t offset = 0;
  size_t written = 0;

  /* Prefix */
  SocketQPACK_Result result = SocketQPACK_encode_prefix (
      0, 0, 128, buf + offset, sizeof (buf) - offset, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* strict-transport-security (static index 97) */
  result = SocketQPACK_encode_literal_name_ref (
      buf + offset,
      sizeof (buf) - offset,
      true,
      97,
      false,
      (const unsigned char *)"max-age=31536000",
      16,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* x-content-type-options: nosniff (static index 61) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 61, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* x-frame-options: deny (static index 74) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 74, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  ASSERT (offset > 0);
}

TEST (qpack_http3_sensitive_headers)
{
  /* Encode sensitive headers with never-index flag:
   * authorization: Bearer token123
   * cookie: session=abc123
   * set-cookie: session=xyz789; HttpOnly; Secure
   */
  unsigned char buf[512];
  size_t offset = 0;
  size_t written = 0;

  /* Prefix */
  SocketQPACK_Result result = SocketQPACK_encode_prefix (
      0, 0, 128, buf + offset, sizeof (buf) - offset, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* authorization with never_indexed=true (static index 75) */
  result = SocketQPACK_encode_literal_name_ref (
      buf + offset,
      sizeof (buf) - offset,
      true,
      75,
      true, /* never_indexed */
      (const unsigned char *)"Bearer token123",
      15,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* cookie with never_indexed=true (static index 5) */
  result = SocketQPACK_encode_literal_name_ref (
      buf + offset,
      sizeof (buf) - offset,
      true,
      5,
      true, /* never_indexed */
      (const unsigned char *)"session=abc123",
      14,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* set-cookie with never_indexed=true (literal name) */
  result = SocketQPACK_encode_literal_field_literal_name (
      buf + offset,
      sizeof (buf) - offset,
      (const unsigned char *)"set-cookie",
      10,
      true,
      (const unsigned char *)"session=xyz789; HttpOnly; Secure",
      32,
      false,
      true, /* never_indexed */
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* Decode and verify never-indexed flags */
  size_t decode_offset = 0;
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  result = SocketQPACK_decode_prefix (buf, offset, 128, 0, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  decode_offset += consumed;

  /* Verify authorization never-indexed */
  SocketQPACK_LiteralNameRef name_ref;
  result = SocketQPACK_decode_literal_name_ref (
      buf + decode_offset, offset - decode_offset, &name_ref, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_ref.never_indexed, true);
  ASSERT_EQ (name_ref.name_index, 75);
  decode_offset += consumed;

  /* Verify cookie never-indexed */
  result = SocketQPACK_decode_literal_name_ref (
      buf + decode_offset, offset - decode_offset, &name_ref, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_ref.never_indexed, true);
  ASSERT_EQ (name_ref.name_index, 5);
  decode_offset += consumed;

  /* Verify set-cookie never-indexed */
  unsigned char name_out[64];
  unsigned char value_out[128];
  size_t name_len = 0;
  size_t value_len = 0;
  bool never_indexed = false;
  result
      = SocketQPACK_decode_literal_field_literal_name (buf + decode_offset,
                                                       offset - decode_offset,
                                                       name_out,
                                                       sizeof (name_out),
                                                       &name_len,
                                                       value_out,
                                                       sizeof (value_out),
                                                       &value_len,
                                                       &never_indexed,
                                                       &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (never_indexed, true);
  ASSERT_EQ (name_len, 10);
  ASSERT (memcmp (name_out, "set-cookie", 10) == 0);
}

TEST (qpack_http3_accept_headers)
{
  /* Encode accept headers:
   * accept: application/json
   * accept-language: en-US,en;q=0.9
   * accept-encoding: gzip, deflate, br
   */
  unsigned char buf[512];
  size_t offset = 0;
  size_t written = 0;

  /* Prefix */
  SocketQPACK_Result result = SocketQPACK_encode_prefix (
      0, 0, 128, buf + offset, sizeof (buf) - offset, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* accept: application/json (static index 29) */
  result = SocketQPACK_encode_literal_name_ref (
      buf + offset,
      sizeof (buf) - offset,
      true,
      29,
      false,
      (const unsigned char *)"application/json",
      16,
      true, /* Huffman */
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* accept-language (static index 72) */
  result = SocketQPACK_encode_literal_name_ref (
      buf + offset,
      sizeof (buf) - offset,
      true,
      72,
      false,
      (const unsigned char *)"en-US,en;q=0.9",
      14,
      true, /* Huffman */
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* accept-encoding: gzip, deflate, br (static index 46) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 46, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  ASSERT (offset > 0);
}

TEST (qpack_http3_repeated_headers_with_dynamic)
{
  /* Simulate encoding repeated requests where dynamic table helps */
  Arena_T arena = Arena_new ();
  unsigned char buf[512];
  size_t written = 0;

  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  /* Insert common headers into dynamic table */
  ASSERT_EQ (SocketQPACK_Table_insert_literal (
                 table, "x-request-id", 12, "req-001", 7),
             QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_insert_literal (
                 table, "x-correlation-id", 16, "corr-001", 8),
             QPACK_OK);

  /* Encode with dynamic table references */
  size_t offset = 0;

  /* Prefix: RIC=2, Base=2 (need both entries) */
  SocketQPACK_Result result = SocketQPACK_encode_prefix (
      2, 2, 128, buf + offset, sizeof (buf) - offset, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* Reference dynamic entry 0 (relative index 1) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 1, 0, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* Reference dynamic entry 1 (relative index 0) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 0, 0, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* Verify decoding */
  size_t decode_offset = 0;
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  result = SocketQPACK_decode_prefix (buf, offset, 128, 5, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (prefix.required_insert_count, 2);
  decode_offset += consumed;

  /* Decode dynamic references */
  uint64_t index = 0;
  int is_static = 0;

  result = SocketQPACK_decode_indexed_field (buf + decode_offset,
                                             offset - decode_offset,
                                             &index,
                                             &is_static,
                                             &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (is_static, 0);
  ASSERT_EQ (index, 1);
  decode_offset += consumed;

  result = SocketQPACK_decode_indexed_field (buf + decode_offset,
                                             offset - decode_offset,
                                             &index,
                                             &is_static,
                                             &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (is_static, 0);
  ASSERT_EQ (index, 0);

  Arena_dispose (&arena);
}

TEST (qpack_http3_compression_efficiency_static)
{
  /* Verify that static table references are compact */
  unsigned char buf[64];
  size_t written = 0;

  /* :method: GET should be 1 byte */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 17, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 1);

  /* :status: 200 should be 1 byte */
  result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 25, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 1);

  /* Static index 98 (max) should be 2 bytes */
  result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 98, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 2);
}

TEST (qpack_http3_huffman_vs_literal)
{
  unsigned char huffman_buf[256];
  unsigned char literal_buf[256];
  size_t huffman_written = 0;
  size_t literal_written = 0;

  /* Test header that should compress well */
  const unsigned char *value = (const unsigned char *)"www.example.com";
  size_t value_len = 15;

  /* Encode with Huffman */
  SocketQPACK_Result result
      = SocketQPACK_encode_literal_name_ref (huffman_buf,
                                             sizeof (huffman_buf),
                                             true,
                                             0,
                                             false,
                                             value,
                                             value_len,
                                             true, /* Huffman */
                                             &huffman_written);
  ASSERT_EQ (result, QPACK_OK);

  /* Encode without Huffman */
  result = SocketQPACK_encode_literal_name_ref (literal_buf,
                                                sizeof (literal_buf),
                                                true,
                                                0,
                                                false,
                                                value,
                                                value_len,
                                                false, /* No Huffman */
                                                &literal_written);
  ASSERT_EQ (result, QPACK_OK);

  /* Huffman should be smaller or equal */
  ASSERT (huffman_written <= literal_written);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

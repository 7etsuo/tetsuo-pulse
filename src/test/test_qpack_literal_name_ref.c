/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_literal_name_ref.c
 * @brief Unit tests for QPACK Literal Field Line with Name Reference
 *        (RFC 9204 Section 4.5.4)
 *
 * Tests encoding, decoding, and validation of the Literal Field Line with
 * Name Reference representation.
 */

#include <string.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACK.h"
#include "test/Test.h"

TEST (qpack_literal_name_ref_encode_null_output)
{
  size_t written = 999;
  SocketQPACK_Result result
      = SocketQPACK_encode_literal_name_ref (NULL,
                                             16,
                                             true,
                                             0,
                                             false,
                                             (const unsigned char *)"value",
                                             5,
                                             false,
                                             &written);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_literal_name_ref_encode_null_written)
{
  unsigned char buf[32];
  SocketQPACK_Result result
      = SocketQPACK_encode_literal_name_ref (buf,
                                             sizeof (buf),
                                             true,
                                             0,
                                             false,
                                             (const unsigned char *)"value",
                                             5,
                                             false,
                                             NULL);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_literal_name_ref_encode_null_value_with_len)
{
  unsigned char buf[32];
  size_t written;
  SocketQPACK_Result result = SocketQPACK_encode_literal_name_ref (
      buf, sizeof (buf), true, 0, false, NULL, 5, false, &written);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_literal_name_ref_encode_zero_buffer)
{
  unsigned char buf[1];
  size_t written;
  SocketQPACK_Result result
      = SocketQPACK_encode_literal_name_ref (buf,
                                             0,
                                             true,
                                             0,
                                             false,
                                             (const unsigned char *)"value",
                                             5,
                                             false,
                                             &written);
  ASSERT_EQ (result, QPACK_ERR_TABLE_SIZE);
}

TEST (qpack_literal_name_ref_encode_static_basic)
{
  unsigned char buf[32];
  size_t written = 0;

  /* Static table index 17 (:method = GET), value "GET" */
  SocketQPACK_Result result
      = SocketQPACK_encode_literal_name_ref (buf,
                                             sizeof (buf),
                                             true,
                                             17,
                                             false,
                                             (const unsigned char *)"GET",
                                             3,
                                             false,
                                             &written);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT (written >= 2); /* At least pattern byte + value length byte */

  /* First byte: 01 N=0 T=1 index=17 (needs continuation since 17 >= 15) */
  /* Pattern: 0101xxxx where xxxx is first 4 bits of index */
  ASSERT_EQ ((buf[0] & 0xC0), 0x40); /* Pattern 01 */
  ASSERT_EQ ((buf[0] & 0x20), 0x00); /* N=0 */
  ASSERT_EQ ((buf[0] & 0x10), 0x10); /* T=1 (static) */
}

TEST (qpack_literal_name_ref_encode_static_never_indexed)
{
  unsigned char buf[32];
  size_t written = 0;

  /* Static table index 5 (cookie), never-indexed */
  SocketQPACK_Result result
      = SocketQPACK_encode_literal_name_ref (buf,
                                             sizeof (buf),
                                             true,
                                             5,
                                             true,
                                             (const unsigned char *)"secret",
                                             6,
                                             false,
                                             &written);

  ASSERT_EQ (result, QPACK_OK);

  /* First byte: 01 N=1 T=1 index=5 */
  ASSERT_EQ ((buf[0] & 0xC0), 0x40); /* Pattern 01 */
  ASSERT_EQ ((buf[0] & 0x20), 0x20); /* N=1 (never-indexed) */
  ASSERT_EQ ((buf[0] & 0x10), 0x10); /* T=1 (static) */
  ASSERT_EQ ((buf[0] & 0x0F), 5);    /* Index = 5 */
}

TEST (qpack_literal_name_ref_encode_dynamic_basic)
{
  unsigned char buf[32];
  size_t written = 0;

  /* Dynamic table index 0 (field-relative), value "bar" */
  SocketQPACK_Result result
      = SocketQPACK_encode_literal_name_ref (buf,
                                             sizeof (buf),
                                             false,
                                             0,
                                             false,
                                             (const unsigned char *)"bar",
                                             3,
                                             false,
                                             &written);

  ASSERT_EQ (result, QPACK_OK);

  /* First byte: 01 N=0 T=0 index=0 */
  ASSERT_EQ ((buf[0] & 0xC0), 0x40); /* Pattern 01 */
  ASSERT_EQ ((buf[0] & 0x20), 0x00); /* N=0 */
  ASSERT_EQ ((buf[0] & 0x10), 0x00); /* T=0 (dynamic) */
  ASSERT_EQ ((buf[0] & 0x0F), 0);    /* Index = 0 */
}

TEST (qpack_literal_name_ref_encode_empty_value)
{
  unsigned char buf[32];
  size_t written = 0;

  /* Static table index 0 (:authority), empty value */
  SocketQPACK_Result result = SocketQPACK_encode_literal_name_ref (
      buf, sizeof (buf), true, 0, false, NULL, 0, false, &written);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 2); /* Pattern byte + value length (0) */

  /* First byte: 01 N=0 T=1 index=0 */
  ASSERT_EQ (buf[0], 0x50); /* 01010000 */
  /* Second byte: H=0 length=0 */
  ASSERT_EQ (buf[1], 0x00);
}

TEST (qpack_literal_name_ref_encode_large_index)
{
  unsigned char buf[32];
  size_t written = 0;

  /* Static table index 98 (last entry, x-frame-options: sameorigin) */
  SocketQPACK_Result result
      = SocketQPACK_encode_literal_name_ref (buf,
                                             sizeof (buf),
                                             true,
                                             98,
                                             false,
                                             (const unsigned char *)"test",
                                             4,
                                             false,
                                             &written);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT (written > 2); /* Needs continuation bytes for index 98 */

  /* First byte should have index overflow (>= 15) */
  ASSERT_EQ ((buf[0] & 0x0F), 0x0F); /* Index prefix = 15 (overflow) */
}

TEST (qpack_literal_name_ref_encode_buffer_too_small)
{
  unsigned char buf[2];
  size_t written = 0;

  /* Try to encode with buffer too small for index + value */
  SocketQPACK_Result result = SocketQPACK_encode_literal_name_ref (
      buf,
      sizeof (buf),
      true,
      0,
      false,
      (const unsigned char *)"this is a long value",
      20,
      false,
      &written);

  ASSERT_EQ (result, QPACK_ERR_TABLE_SIZE);
}

TEST (qpack_literal_name_ref_decode_null_result)
{
  unsigned char buf[] = { 0x50, 0x03, 'f', 'o', 'o' };
  size_t consumed = 999;

  SocketQPACK_Result result = SocketQPACK_decode_literal_name_ref (
      buf, sizeof (buf), NULL, &consumed);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_literal_name_ref_decode_null_consumed)
{
  unsigned char buf[] = { 0x50, 0x03, 'f', 'o', 'o' };
  SocketQPACK_LiteralNameRef decoded;

  SocketQPACK_Result result
      = SocketQPACK_decode_literal_name_ref (buf, sizeof (buf), &decoded, NULL);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_literal_name_ref_decode_empty_input)
{
  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 999;

  SocketQPACK_Result result
      = SocketQPACK_decode_literal_name_ref (NULL, 0, &decoded, &consumed);
  ASSERT_EQ (result, QPACK_INCOMPLETE);
  ASSERT_EQ (consumed, 0);
}

TEST (qpack_literal_name_ref_decode_static_basic)
{
  /* Encoded: Static index 5, N=0, value "cookie-value" */
  unsigned char buf[]
      = { 0x55, /* 01010101 = pattern 01, N=0, T=1, index=5 */
          0x0C, /* H=0, length=12 */
          'c',  'o', 'o', 'k', 'i', 'e', '-', 'v', 'a', 'l', 'u', 'e' };

  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_literal_name_ref (
      buf, sizeof (buf), &decoded, &consumed);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, sizeof (buf));
  ASSERT_EQ (decoded.name_index, 5);
  ASSERT_EQ (decoded.is_static, true);
  ASSERT_EQ (decoded.never_indexed, false);
  ASSERT_EQ (decoded.value_huffman, false);
  ASSERT_EQ (decoded.value_len, 12);
  ASSERT (memcmp (decoded.value, "cookie-value", 12) == 0);
}

TEST (qpack_literal_name_ref_decode_static_never_indexed)
{
  /* Encoded: Static index 5, N=1, value "secret" */
  unsigned char buf[] = { 0x75, /* 01110101 = pattern 01, N=1, T=1, index=5 */
                          0x06, /* H=0, length=6 */
                          's',  'e', 'c', 'r', 'e', 't' };

  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_literal_name_ref (
      buf, sizeof (buf), &decoded, &consumed);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded.name_index, 5);
  ASSERT_EQ (decoded.is_static, true);
  ASSERT_EQ (decoded.never_indexed, true);
  ASSERT_EQ (decoded.value_len, 6);
}

TEST (qpack_literal_name_ref_decode_dynamic_basic)
{
  /* Encoded: Dynamic index 3, N=0, value "test" */
  unsigned char buf[] = { 0x43, /* 01000011 = pattern 01, N=0, T=0, index=3 */
                          0x04, /* H=0, length=4 */
                          't',  'e', 's', 't' };

  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_literal_name_ref (
      buf, sizeof (buf), &decoded, &consumed);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded.name_index, 3);
  ASSERT_EQ (decoded.is_static, false);
  ASSERT_EQ (decoded.never_indexed, false);
  ASSERT_EQ (decoded.value_len, 4);
}

TEST (qpack_literal_name_ref_decode_empty_value)
{
  /* Encoded: Static index 0 (:authority), empty value */
  unsigned char buf[] = { 0x50, /* 01010000 = pattern 01, N=0, T=1, index=0 */
                          0x00 /* H=0, length=0 */ };

  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_literal_name_ref (
      buf, sizeof (buf), &decoded, &consumed);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 2);
  ASSERT_EQ (decoded.name_index, 0);
  ASSERT_EQ (decoded.is_static, true);
  ASSERT_EQ (decoded.value_len, 0);
}

TEST (qpack_literal_name_ref_decode_large_index)
{
  /* Encoded: Static index 98 (uses continuation byte) */
  unsigned char buf[]
      = { 0x5F, /* 01011111 = pattern 01, N=0, T=1, index=15 (overflow) */
          0x53, /* Continuation: 98 - 15 = 83 = 0x53 */
          0x03, /* H=0, length=3 */
          'f',  'o', 'o' };

  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_literal_name_ref (
      buf, sizeof (buf), &decoded, &consumed);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded.name_index, 98);
  ASSERT_EQ (decoded.is_static, true);
}

TEST (qpack_literal_name_ref_decode_incomplete_index)
{
  /* Index needs continuation but not present */
  unsigned char buf[] = { 0x5F /* Overflow index, needs more bytes */ };

  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_literal_name_ref (
      buf, sizeof (buf), &decoded, &consumed);

  ASSERT_EQ (result, QPACK_INCOMPLETE);
}

TEST (qpack_literal_name_ref_decode_incomplete_value_len)
{
  /* Index complete but no value length byte */
  unsigned char buf[] = { 0x50 /* pattern 01, N=0, T=1, index=0 */ };

  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_literal_name_ref (
      buf, sizeof (buf), &decoded, &consumed);

  ASSERT_EQ (result, QPACK_INCOMPLETE);
}

TEST (qpack_literal_name_ref_decode_incomplete_value)
{
  /* Value length says 10 but only 3 bytes present */
  unsigned char buf[] = { 0x50, /* pattern 01, N=0, T=1, index=0 */
                          0x0A, /* H=0, length=10 */
                          'a',
                          'b',
                          'c' };

  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_literal_name_ref (
      buf, sizeof (buf), &decoded, &consumed);

  ASSERT_EQ (result, QPACK_INCOMPLETE);
}

TEST (qpack_literal_name_ref_decode_wrong_pattern)
{
  /* Wrong pattern: 10xxxxxx instead of 01xxxxxx */
  unsigned char buf[] = { 0x80, /* Wrong pattern */ 0x03, 'f', 'o', 'o' };

  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_literal_name_ref (
      buf, sizeof (buf), &decoded, &consumed);

  ASSERT_EQ (result, QPACK_ERR_INTERNAL);
}

TEST (qpack_literal_name_ref_roundtrip_static)
{
  unsigned char buf[64];
  size_t written = 0;
  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  /* Encode: static index 25 (:status=200), value "OK" */
  SocketQPACK_Result result
      = SocketQPACK_encode_literal_name_ref (buf,
                                             sizeof (buf),
                                             true,
                                             25,
                                             false,
                                             (const unsigned char *)"OK",
                                             2,
                                             false,
                                             &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode */
  result
      = SocketQPACK_decode_literal_name_ref (buf, written, &decoded, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, written);
  ASSERT_EQ (decoded.name_index, 25);
  ASSERT_EQ (decoded.is_static, true);
  ASSERT_EQ (decoded.never_indexed, false);
  ASSERT_EQ (decoded.value_len, 2);
  ASSERT (memcmp (decoded.value, "OK", 2) == 0);
}

TEST (qpack_literal_name_ref_roundtrip_dynamic)
{
  unsigned char buf[64];
  size_t written = 0;
  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  /* Encode: dynamic index 7, value "custom-value" */
  SocketQPACK_Result result = SocketQPACK_encode_literal_name_ref (
      buf,
      sizeof (buf),
      false,
      7,
      false,
      (const unsigned char *)"custom-value",
      12,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode */
  result
      = SocketQPACK_decode_literal_name_ref (buf, written, &decoded, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded.name_index, 7);
  ASSERT_EQ (decoded.is_static, false);
  ASSERT_EQ (decoded.value_len, 12);
}

TEST (qpack_literal_name_ref_roundtrip_never_indexed)
{
  unsigned char buf[64];
  size_t written = 0;
  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  /* Encode: static index 85 (authorization), never-indexed, value "Bearer
   * token" */
  SocketQPACK_Result result = SocketQPACK_encode_literal_name_ref (
      buf,
      sizeof (buf),
      true,
      85,
      true,
      (const unsigned char *)"Bearer token",
      12,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode */
  result
      = SocketQPACK_decode_literal_name_ref (buf, written, &decoded, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded.name_index, 85);
  ASSERT_EQ (decoded.is_static, true);
  ASSERT_EQ (decoded.never_indexed, true);
  ASSERT_EQ (decoded.value_len, 12);
}

TEST (qpack_literal_name_ref_roundtrip_empty_value)
{
  unsigned char buf[32];
  size_t written = 0;
  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  /* Encode: static index 0 (:authority), empty value */
  SocketQPACK_Result result = SocketQPACK_encode_literal_name_ref (
      buf, sizeof (buf), true, 0, false, NULL, 0, false, &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode */
  result
      = SocketQPACK_decode_literal_name_ref (buf, written, &decoded, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded.name_index, 0);
  ASSERT_EQ (decoded.is_static, true);
  ASSERT_EQ (decoded.value_len, 0);
}

TEST (qpack_literal_name_ref_encode_huffman)
{
  unsigned char buf[64];
  size_t written = 0;

  /* Encode with Huffman - "www.example.com" compresses well */
  SocketQPACK_Result result = SocketQPACK_encode_literal_name_ref (
      buf,
      sizeof (buf),
      true,
      0,
      false,
      (const unsigned char *)"www.example.com",
      15,
      true,
      &written);

  ASSERT_EQ (result, QPACK_OK);
  /* Huffman encoding should be used since it compresses */
  /* Value length byte should have H bit set */
  /* First byte is index, second+ is value length */
  ASSERT ((buf[1] & 0x80) == 0x80); /* H bit should be set */
}

TEST (qpack_literal_name_ref_decode_huffman_with_arena)
{
  Arena_T arena = Arena_new ();
  unsigned char buf[64];
  size_t written = 0;

  /* First encode with Huffman */
  SocketQPACK_Result result = SocketQPACK_encode_literal_name_ref (
      buf,
      sizeof (buf),
      true,
      0,
      false,
      (const unsigned char *)"www.example.com",
      15,
      true,
      &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode with arena for Huffman support */
  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  result = SocketQPACK_decode_literal_name_ref_arena (
      buf, written, arena, &decoded, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded.name_index, 0);
  ASSERT_EQ (decoded.is_static, true);
  ASSERT_EQ (decoded.value_len, 15);
  ASSERT (memcmp (decoded.value, "www.example.com", 15) == 0);

  Arena_dispose (&arena);
}

TEST (qpack_literal_name_ref_decode_arena_null)
{
  unsigned char buf[] = { 0x50, 0x00 };
  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_literal_name_ref_arena (
      buf, sizeof (buf), NULL, &decoded, &consumed);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_literal_name_ref_validate_static_valid)
{
  SocketQPACK_Result result = SocketQPACK_validate_literal_name_ref_index (
      true, 0, /* base (ignored for static) */ 0, /* dropped (ignored) */ 0);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_validate_literal_name_ref_index (true, 98, 0, 0);
  ASSERT_EQ (result, QPACK_OK);
}

TEST (qpack_literal_name_ref_validate_static_invalid)
{
  /* Index 99 is out of bounds (static table has 0-98) */
  SocketQPACK_Result result
      = SocketQPACK_validate_literal_name_ref_index (true, 99, 0, 0);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);

  result = SocketQPACK_validate_literal_name_ref_index (true, 1000, 0, 0);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);
}

TEST (qpack_literal_name_ref_validate_dynamic_valid)
{
  /* Base=10, dropped=0: valid indices are 0-9 (absolute 0-9) */
  SocketQPACK_Result result
      = SocketQPACK_validate_literal_name_ref_index (false, 0, 10, 0);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_validate_literal_name_ref_index (false, 9, 10, 0);
  ASSERT_EQ (result, QPACK_OK);
}

TEST (qpack_literal_name_ref_validate_dynamic_out_of_bounds)
{
  /* Base=10: index 10 is out of bounds */
  SocketQPACK_Result result
      = SocketQPACK_validate_literal_name_ref_index (false, 10, 10, 0);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);
}

TEST (qpack_literal_name_ref_validate_dynamic_evicted)
{
  /* Base=10, dropped=5: valid indices are 0-4 (absolute 5-9)
   * Index 5 would map to absolute 4, which is < dropped */
  SocketQPACK_Result result
      = SocketQPACK_validate_literal_name_ref_index (false, 9, 10, 5);
  /* rel=9, abs = 10 - 9 - 1 = 0, which is < dropped=5 */
  ASSERT_EQ (result, QPACK_ERR_EVICTED_INDEX);
}

TEST (qpack_literal_name_ref_resolve_static)
{
  const char *name = NULL;
  size_t name_len = 0;

  /* Index 0 is :authority */
  SocketQPACK_Result result = SocketQPACK_resolve_literal_name_ref (
      true, 0, 0, NULL, &name, &name_len);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_len, 10);
  ASSERT (memcmp (name, ":authority", 10) == 0);
}

TEST (qpack_literal_name_ref_resolve_static_method)
{
  const char *name = NULL;
  size_t name_len = 0;

  /* Index 17 is :method (GET) */
  SocketQPACK_Result result = SocketQPACK_resolve_literal_name_ref (
      true, 17, 0, NULL, &name, &name_len);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_len, 7);
  ASSERT (memcmp (name, ":method", 7) == 0);
}

TEST (qpack_literal_name_ref_resolve_static_invalid)
{
  const char *name = NULL;
  size_t name_len = 0;

  SocketQPACK_Result result = SocketQPACK_resolve_literal_name_ref (
      true, 99, 0, NULL, &name, &name_len);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);
}

TEST (qpack_literal_name_ref_resolve_null_params)
{
  const char *name = NULL;
  size_t name_len = 0;

  SocketQPACK_Result result = SocketQPACK_resolve_literal_name_ref (
      true, 0, 0, NULL, NULL, &name_len);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);

  result = SocketQPACK_resolve_literal_name_ref (true, 0, 0, NULL, &name, NULL);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_literal_name_ref_resolve_dynamic_null_table)
{
  const char *name = NULL;
  size_t name_len = 0;

  /* Dynamic table lookup requires non-NULL table */
  SocketQPACK_Result result = SocketQPACK_resolve_literal_name_ref (
      false, 0, 10, NULL, &name, &name_len);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_literal_name_ref_max_index_continuation)
{
  unsigned char buf[64];
  size_t written = 0;
  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  /* Test with large index that requires multiple continuation bytes */
  /* Index 1000 (way beyond static table, but valid for dynamic) */
  SocketQPACK_Result result
      = SocketQPACK_encode_literal_name_ref (buf,
                                             sizeof (buf),
                                             false,
                                             1000,
                                             false,
                                             (const unsigned char *)"v",
                                             1,
                                             false,
                                             &written);
  ASSERT_EQ (result, QPACK_OK);

  result
      = SocketQPACK_decode_literal_name_ref (buf, written, &decoded, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded.name_index, 1000);
  ASSERT_EQ (decoded.is_static, false);
}

TEST (qpack_literal_name_ref_large_value)
{
  unsigned char buf[512];
  size_t written = 0;
  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  /* Create a 200-byte value */
  unsigned char value[200];
  memset (value, 'x', sizeof (value));

  SocketQPACK_Result result
      = SocketQPACK_encode_literal_name_ref (buf,
                                             sizeof (buf),
                                             true,
                                             0,
                                             false,
                                             value,
                                             sizeof (value),
                                             false,
                                             &written);
  ASSERT_EQ (result, QPACK_OK);

  result
      = SocketQPACK_decode_literal_name_ref (buf, written, &decoded, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded.value_len, 200);
}

TEST (qpack_literal_name_ref_all_flags_combination)
{
  unsigned char buf[64];
  size_t written = 0;
  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  /* Test all flag combinations */
  struct
  {
    bool is_static;
    bool never_indexed;
  } combinations[]
      = { { false, false }, { false, true }, { true, false }, { true, true } };

  for (size_t i = 0; i < 4; i++)
    {
      written = 0;
      consumed = 0;

      SocketQPACK_Result result
          = SocketQPACK_encode_literal_name_ref (buf,
                                                 sizeof (buf),
                                                 combinations[i].is_static,
                                                 5,
                                                 combinations[i].never_indexed,
                                                 (const unsigned char *)"test",
                                                 4,
                                                 false,
                                                 &written);
      ASSERT_EQ (result, QPACK_OK);

      result = SocketQPACK_decode_literal_name_ref (
          buf, written, &decoded, &consumed);
      ASSERT_EQ (result, QPACK_OK);
      ASSERT_EQ (decoded.is_static, combinations[i].is_static);
      ASSERT_EQ (decoded.never_indexed, combinations[i].never_indexed);
    }
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

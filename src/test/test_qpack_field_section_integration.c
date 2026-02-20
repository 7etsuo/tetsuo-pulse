/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_field_section_integration.c
 * @brief Integration tests for QPACK Field Section encoding/decoding.
 *
 * Tests complete field section round-trips using all field line
 * representations defined in RFC 9204 Section 4.5.
 */

#include <string.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACK.h"
#include "test/Test.h"

/**
 * @brief Header field structure for test verification.
 */
typedef struct
{
  const char *name;
  size_t name_len;
  const char *value;
  size_t value_len;
} TestHeader;

TEST (qpack_integration_indexed_static_authority)
{
  /* Encode/decode :authority from static table (index 0) */
  unsigned char buf[32];
  size_t written = 0;
  uint64_t index = 0;
  int is_static = 0;
  size_t consumed = 0;

  /* Encode static index 0 (:authority) */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 0, 1, &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode */
  result = SocketQPACK_decode_indexed_field (
      buf, written, &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (is_static, 1);
  ASSERT_EQ (index, 0);
  ASSERT_EQ (consumed, written);
}

TEST (qpack_integration_indexed_static_content_type)
{
  /* Encode/decode content-type from static table (index 31) */
  unsigned char buf[32];
  size_t written = 0;
  uint64_t index = 0;
  int is_static = 0;
  size_t consumed = 0;

  /* Static index 31 is content-type: text/html;charset=utf-8 */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 31, 1, &written);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_decode_indexed_field (
      buf, written, &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (is_static, 1);
  ASSERT_EQ (index, 31);
}

TEST (qpack_integration_indexed_dynamic)
{
  /* Round-trip a dynamic table index reference */
  Arena_T arena = Arena_new ();
  unsigned char buf[32];
  size_t written = 0;
  uint64_t index = 0;
  int is_static = 0;
  size_t consumed = 0;

  /* Create dynamic table and insert an entry */
  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  SocketQPACK_Result result
      = SocketQPACK_Table_insert_literal (table, "x-custom", 8, "value123", 8);
  ASSERT_EQ (result, QPACK_OK);

  /* Encode dynamic index 0 (field-relative, references Base-1) */
  result = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 0, 0, &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode */
  result = SocketQPACK_decode_indexed_field (
      buf, written, &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (is_static, 0);
  ASSERT_EQ (index, 0);

  /* Resolve to absolute index with Base=1 (Insert Count) */
  uint64_t abs_index = 0;
  result
      = SocketQPACK_resolve_indexed_field (index, is_static, 1, 0, &abs_index);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (abs_index, 0); /* Base - relative - 1 = 1 - 0 - 1 = 0 */

  /* Look up from table */
  const char *name = NULL;
  size_t name_len = 0;
  const char *value = NULL;
  size_t value_len = 0;
  result = SocketQPACK_Table_get (
      table, abs_index, &name, &name_len, &value, &value_len);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_len, 8);
  ASSERT (memcmp (name, "x-custom", 8) == 0);
  ASSERT_EQ (value_len, 8);
  ASSERT (memcmp (value, "value123", 8) == 0);

  Arena_dispose (&arena);
}

TEST (qpack_integration_indexed_postbase)
{
  /* Round-trip an indexed field line with post-base index */
  Arena_T arena = Arena_new ();
  unsigned char buf[32];
  size_t written = 0;
  uint64_t post_base_index = 0;
  size_t consumed = 0;

  /* Create table and insert entry */
  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  SocketQPACK_Result result = SocketQPACK_Table_insert_literal (
      table, "x-header", 8, "post-base-value", 15);
  ASSERT_EQ (result, QPACK_OK);

  /* Encode post-base index 0 (references entry at Base) */
  result = SocketQPACK_encode_indexed_postbase (0, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode */
  result = SocketQPACK_decode_indexed_postbase (
      buf, written, &post_base_index, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (post_base_index, 0);
  ASSERT_EQ (consumed, written);

  /* Look up with Base=0 (entry was inserted after encoding started) */
  const char *name = NULL;
  size_t name_len = 0;
  const char *value = NULL;
  size_t value_len = 0;
  result = SocketQPACK_lookup_indexed_postbase (
      table, 0, post_base_index, &name, &name_len, &value, &value_len);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_len, 8);
  ASSERT (memcmp (name, "x-header", 8) == 0);
  ASSERT_EQ (value_len, 15);
  ASSERT (memcmp (value, "post-base-value", 15) == 0);

  Arena_dispose (&arena);
}

TEST (qpack_integration_indexed_postbase_multiple)
{
  /* Test multiple post-base references */
  Arena_T arena = Arena_new ();
  unsigned char buf[64];
  size_t offset = 0;
  size_t written = 0;

  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  /* Insert 3 entries */
  ASSERT_EQ (SocketQPACK_Table_insert_literal (table, "h1", 2, "v1", 2),
             QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_insert_literal (table, "h2", 2, "v2", 2),
             QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_insert_literal (table, "h3", 2, "v3", 2),
             QPACK_OK);

  /* Encode references to post-base indices 0, 1, 2 with Base=0 */
  for (uint64_t i = 0; i < 3; i++)
    {
      SocketQPACK_Result result = SocketQPACK_encode_indexed_postbase (
          i, buf + offset, sizeof (buf) - offset, &written);
      ASSERT_EQ (result, QPACK_OK);
      offset += written;
    }

  /* Decode and verify */
  size_t decode_offset = 0;
  for (uint64_t i = 0; i < 3; i++)
    {
      uint64_t pb_idx = 0;
      size_t consumed = 0;
      SocketQPACK_Result result = SocketQPACK_decode_indexed_postbase (
          buf + decode_offset, offset - decode_offset, &pb_idx, &consumed);
      ASSERT_EQ (result, QPACK_OK);
      ASSERT_EQ (pb_idx, i);
      decode_offset += consumed;
    }

  Arena_dispose (&arena);
}

TEST (qpack_integration_literal_name_ref_static)
{
  /* Round-trip literal field with name from static table */
  unsigned char buf[256];
  size_t written = 0;
  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  /* Static index 1 is :path */
  const unsigned char *value = (const unsigned char *)"/api/v1/users";
  size_t value_len = 13;

  SocketQPACK_Result result = SocketQPACK_encode_literal_name_ref (
      buf, sizeof (buf), true, 1, false, value, value_len, false, &written);
  ASSERT_EQ (result, QPACK_OK);

  result
      = SocketQPACK_decode_literal_name_ref (buf, written, &decoded, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, written);
  ASSERT_EQ (decoded.is_static, true);
  ASSERT_EQ (decoded.name_index, 1);
  ASSERT_EQ (decoded.never_indexed, false);
  ASSERT_EQ (decoded.value_len, value_len);
  ASSERT (memcmp (decoded.value, value, value_len) == 0);
}

TEST (qpack_integration_literal_name_ref_static_huffman)
{
  /* Round-trip literal field with Huffman-encoded value */
  Arena_T arena = Arena_new ();
  unsigned char buf[256];
  size_t written = 0;
  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  /* Static index 15 is accept-encoding */
  const unsigned char *value = (const unsigned char *)"gzip, deflate, br";
  size_t value_len = 17;

  SocketQPACK_Result result = SocketQPACK_encode_literal_name_ref (
      buf, sizeof (buf), true, 15, false, value, value_len, true, &written);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_decode_literal_name_ref_arena (
      buf, written, arena, &decoded, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, written);
  ASSERT_EQ (decoded.is_static, true);
  ASSERT_EQ (decoded.name_index, 15);
  ASSERT_EQ (decoded.value_len, value_len);
  ASSERT (memcmp (decoded.value, value, value_len) == 0);

  Arena_dispose (&arena);
}

TEST (qpack_integration_literal_name_ref_dynamic)
{
  /* Round-trip literal field with name from dynamic table */
  Arena_T arena = Arena_new ();
  unsigned char buf[256];
  size_t written = 0;
  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  /* Create table and insert entry */
  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  SocketQPACK_Result result = SocketQPACK_Table_insert_literal (
      table, "x-request-id", 12, "initial-value", 13);
  ASSERT_EQ (result, QPACK_OK);

  /* Encode literal with dynamic name reference (field-relative index 0) */
  const unsigned char *value = (const unsigned char *)"new-request-id-123";
  size_t value_len = 18;

  result = SocketQPACK_encode_literal_name_ref (
      buf, sizeof (buf), false, 0, false, value, value_len, false, &written);
  ASSERT_EQ (result, QPACK_OK);

  result
      = SocketQPACK_decode_literal_name_ref (buf, written, &decoded, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded.is_static, false);
  ASSERT_EQ (decoded.name_index, 0);
  ASSERT_EQ (decoded.value_len, value_len);
  ASSERT (memcmp (decoded.value, value, value_len) == 0);

  /* Resolve name from table (Base=1, relative index 0) */
  const char *name = NULL;
  size_t name_len = 0;
  result = SocketQPACK_resolve_literal_name_ref (
      false, decoded.name_index, 1, table, &name, &name_len);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_len, 12);
  ASSERT (memcmp (name, "x-request-id", 12) == 0);

  Arena_dispose (&arena);
}

TEST (qpack_integration_literal_name_ref_never_indexed)
{
  /* Test never-indexed flag for sensitive headers */
  unsigned char buf[256];
  size_t written = 0;
  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  /* Static index 75 is authorization */
  const unsigned char *value = (const unsigned char *)"Bearer token123";
  size_t value_len = 15;

  SocketQPACK_Result result
      = SocketQPACK_encode_literal_name_ref (buf,
                                             sizeof (buf),
                                             true,
                                             75,
                                             true, /* never_indexed = true */
                                             value,
                                             value_len,
                                             false,
                                             &written);
  ASSERT_EQ (result, QPACK_OK);

  result
      = SocketQPACK_decode_literal_name_ref (buf, written, &decoded, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded.never_indexed, true);
  ASSERT_EQ (decoded.is_static, true);
  ASSERT_EQ (decoded.name_index, 75);
}

TEST (qpack_integration_literal_postbase_name)
{
  /* Round-trip literal with post-base name reference */
  Arena_T arena = Arena_new ();
  unsigned char buf[256];
  size_t written = 0;
  SocketQPACK_LiteralPostBaseName decoded;
  size_t consumed = 0;

  /* Create table and insert entry */
  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  SocketQPACK_Result result = SocketQPACK_Table_insert_literal (
      table, "x-new-header", 12, "initial", 7);
  ASSERT_EQ (result, QPACK_OK);

  /* Encode literal with post-base name reference */
  const unsigned char *value = (const unsigned char *)"different-value";
  size_t value_len = 15;

  result = SocketQPACK_encode_literal_postbase_name (buf,
                                                     sizeof (buf),
                                                     0, /* post-base index 0 */
                                                     0, /* never_index = 0 */
                                                     value,
                                                     value_len,
                                                     0, /* use_huffman = 0 */
                                                     &written);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_decode_literal_postbase_name (
      buf, written, arena, &decoded, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, written);
  ASSERT_EQ (decoded.name_index, 0);
  ASSERT_EQ (decoded.never_index, 0);
  ASSERT_EQ (decoded.value_len, value_len);
  ASSERT (memcmp (decoded.value, value, value_len) == 0);

  /* Resolve name from post-base reference (Base=0) */
  const char *name = NULL;
  size_t name_len = 0;
  result = SocketQPACK_resolve_postbase_name (
      table, 0, decoded.name_index, &name, &name_len);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_len, 12);
  ASSERT (memcmp (name, "x-new-header", 12) == 0);

  Arena_dispose (&arena);
}

TEST (qpack_integration_literal_postbase_name_huffman)
{
  /* Round-trip literal with post-base name and Huffman value */
  Arena_T arena = Arena_new ();
  unsigned char buf[256];
  size_t written = 0;
  SocketQPACK_LiteralPostBaseName decoded;
  size_t consumed = 0;

  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  SocketQPACK_Result result = SocketQPACK_Table_insert_literal (
      table, "x-compression-test", 18, "dummy", 5);
  ASSERT_EQ (result, QPACK_OK);

  const unsigned char *value
      = (const unsigned char *)"this value compresses well";
  size_t value_len = 26;

  result = SocketQPACK_encode_literal_postbase_name (buf,
                                                     sizeof (buf),
                                                     0,
                                                     0,
                                                     value,
                                                     value_len,
                                                     1, /* use_huffman = 1 */
                                                     &written);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_decode_literal_postbase_name (
      buf, written, arena, &decoded, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded.value_len, value_len);
  ASSERT (memcmp (decoded.value, value, value_len) == 0);

  Arena_dispose (&arena);
}

TEST (qpack_integration_literal_literal_basic)
{
  /* Round-trip literal field with literal name and value */
  unsigned char buf[256];
  size_t written = 0;
  unsigned char name_out[64];
  unsigned char value_out[128];
  size_t name_len = 0;
  size_t value_len = 0;
  bool never_indexed = false;
  size_t consumed = 0;

  const unsigned char *name = (const unsigned char *)"x-custom-header";
  const unsigned char *value = (const unsigned char *)"custom-value-123";

  SocketQPACK_Result result = SocketQPACK_encode_literal_field_literal_name (
      buf, sizeof (buf), name, 15, false, value, 16, false, false, &written);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_decode_literal_field_literal_name (buf,
                                                          written,
                                                          name_out,
                                                          sizeof (name_out),
                                                          &name_len,
                                                          value_out,
                                                          sizeof (value_out),
                                                          &value_len,
                                                          &never_indexed,
                                                          &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, written);
  ASSERT_EQ (name_len, 15);
  ASSERT_EQ (value_len, 16);
  ASSERT_EQ (never_indexed, false);
  ASSERT (memcmp (name_out, name, 15) == 0);
  ASSERT (memcmp (value_out, value, 16) == 0);
}

TEST (qpack_integration_literal_literal_huffman_both)
{
  /* Round-trip with Huffman encoding for both name and value */
  unsigned char buf[256];
  size_t written = 0;
  unsigned char name_out[64];
  unsigned char value_out[128];
  size_t name_len = 0;
  size_t value_len = 0;
  bool never_indexed = false;
  size_t consumed = 0;

  const unsigned char *name = (const unsigned char *)"content-encoding";
  const unsigned char *value = (const unsigned char *)"gzip";

  SocketQPACK_Result result
      = SocketQPACK_encode_literal_field_literal_name (buf,
                                                       sizeof (buf),
                                                       name,
                                                       16,
                                                       true, /* name_huffman */
                                                       value,
                                                       4,
                                                       true, /* value_huffman */
                                                       false,
                                                       &written);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_decode_literal_field_literal_name (buf,
                                                          written,
                                                          name_out,
                                                          sizeof (name_out),
                                                          &name_len,
                                                          value_out,
                                                          sizeof (value_out),
                                                          &value_len,
                                                          &never_indexed,
                                                          &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_len, 16);
  ASSERT_EQ (value_len, 4);
  ASSERT (memcmp (name_out, name, 16) == 0);
  ASSERT (memcmp (value_out, value, 4) == 0);
}

TEST (qpack_integration_literal_literal_never_indexed)
{
  /* Test never-indexed flag for literal field line */
  unsigned char buf[256];
  size_t written = 0;
  unsigned char name_out[64];
  unsigned char value_out[128];
  size_t name_len = 0;
  size_t value_len = 0;
  bool never_indexed = false;
  size_t consumed = 0;

  const unsigned char *name = (const unsigned char *)"set-cookie";
  const unsigned char *value = (const unsigned char *)"session=secret123";

  SocketQPACK_Result result
      = SocketQPACK_encode_literal_field_literal_name (buf,
                                                       sizeof (buf),
                                                       name,
                                                       10,
                                                       false,
                                                       value,
                                                       17,
                                                       false,
                                                       true, /* never_indexed */
                                                       &written);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_decode_literal_field_literal_name (buf,
                                                          written,
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
  ASSERT (memcmp (name_out, name, 10) == 0);
}

TEST (qpack_integration_literal_literal_empty_value)
{
  /* Round-trip with empty value */
  unsigned char buf[256];
  size_t written = 0;
  unsigned char name_out[64];
  unsigned char value_out[128];
  size_t name_len = 0;
  size_t value_len = 0;
  bool never_indexed = false;
  size_t consumed = 0;

  const unsigned char *name = (const unsigned char *)"x-empty";

  SocketQPACK_Result result
      = SocketQPACK_encode_literal_field_literal_name (buf,
                                                       sizeof (buf),
                                                       name,
                                                       7,
                                                       false,
                                                       NULL,
                                                       0, /* empty value */
                                                       false,
                                                       false,
                                                       &written);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_decode_literal_field_literal_name (buf,
                                                          written,
                                                          name_out,
                                                          sizeof (name_out),
                                                          &name_len,
                                                          value_out,
                                                          sizeof (value_out),
                                                          &value_len,
                                                          &never_indexed,
                                                          &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_len, 7);
  ASSERT_EQ (value_len, 0);
  ASSERT (memcmp (name_out, name, 7) == 0);
}

TEST (qpack_integration_prefix_static_only)
{
  /* Prefix for field section using only static table (RIC=0, Base=0) */
  unsigned char buf[32];
  size_t written = 0;
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (0, 0, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_decode_prefix (buf, written, 128, 0, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (prefix.required_insert_count, 0);
  ASSERT_EQ (prefix.base, 0);
}

TEST (qpack_integration_prefix_with_dynamic)
{
  /* Prefix for field section using dynamic table entries */
  unsigned char buf[32];
  size_t written = 0;
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  /* RIC=10, Base=10 (references entries 0-9) */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (10, 10, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);

  result
      = SocketQPACK_decode_prefix (buf, written, 128, 15, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (prefix.required_insert_count, 10);
  ASSERT_EQ (prefix.base, 10);
}

TEST (qpack_integration_prefix_post_base)
{
  /* Prefix for field section with post-base references (Base < RIC) */
  unsigned char buf[32];
  size_t written = 0;
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  /* RIC=20, Base=15 (entries 15-19 are post-base) */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (20, 15, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);

  result
      = SocketQPACK_decode_prefix (buf, written, 128, 25, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (prefix.required_insert_count, 20);
  ASSERT_EQ (prefix.base, 15);
  /* delta_base should be negative */
  ASSERT (prefix.delta_base < 0);
}

TEST (qpack_integration_mixed_representations)
{
  /* Encode a field section with multiple representation types */
  Arena_T arena = Arena_new ();
  unsigned char buf[1024];
  size_t offset = 0;
  size_t written = 0;

  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  /* Insert some entries into dynamic table */
  ASSERT_EQ (
      SocketQPACK_Table_insert_literal (table, "x-custom-a", 10, "value-a", 7),
      QPACK_OK);
  ASSERT_EQ (
      SocketQPACK_Table_insert_literal (table, "x-custom-b", 10, "value-b", 7),
      QPACK_OK);

  /* 1. Encode prefix (RIC=2, Base=2) */
  SocketQPACK_Result result = SocketQPACK_encode_prefix (
      2, 2, 128, buf + offset, sizeof (buf) - offset, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* 2. Indexed Field Line - static (:method GET, index 17) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 17, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* 3. Indexed Field Line - dynamic (relative index 0 -> abs 1) */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 0, 0, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* 4. Literal with Name Reference - static (index 1 = :path) */
  result = SocketQPACK_encode_literal_name_ref (buf + offset,
                                                sizeof (buf) - offset,
                                                true,
                                                1,
                                                false,
                                                (const unsigned char *)"/api",
                                                4,
                                                false,
                                                &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* 5. Literal with Literal Name */
  result = SocketQPACK_encode_literal_field_literal_name (
      buf + offset,
      sizeof (buf) - offset,
      (const unsigned char *)"x-trace-id",
      10,
      false,
      (const unsigned char *)"abc123",
      6,
      false,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* Verify we encoded something reasonable */
  ASSERT (offset > 0);
  ASSERT (offset < sizeof (buf));

  /* Decode and verify the prefix */
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;
  size_t decode_offset = 0;

  result = SocketQPACK_decode_prefix (buf, offset, 128, 5, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (prefix.required_insert_count, 2);
  ASSERT_EQ (prefix.base, 2);
  decode_offset += consumed;

  /* Decode first indexed field (static) */
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

  /* Decode second indexed field (dynamic) */
  result = SocketQPACK_decode_indexed_field (buf + decode_offset,
                                             offset - decode_offset,
                                             &index,
                                             &is_static,
                                             &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (is_static, 0);
  ASSERT_EQ (index, 0);
  decode_offset += consumed;

  /* Decode literal with name reference */
  SocketQPACK_LiteralNameRef name_ref;
  result = SocketQPACK_decode_literal_name_ref (
      buf + decode_offset, offset - decode_offset, &name_ref, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_ref.is_static, true);
  ASSERT_EQ (name_ref.name_index, 1);
  ASSERT_EQ (name_ref.value_len, 4);
  ASSERT (memcmp (name_ref.value, "/api", 4) == 0);
  decode_offset += consumed;

  /* Decode literal with literal name */
  unsigned char name_out[64];
  unsigned char value_out[64];
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
  ASSERT_EQ (name_len, 10);
  ASSERT_EQ (value_len, 6);
  ASSERT (memcmp (name_out, "x-trace-id", 10) == 0);
  ASSERT (memcmp (value_out, "abc123", 6) == 0);
  decode_offset += consumed;

  /* Verify we consumed all bytes */
  ASSERT_EQ (decode_offset, offset);

  Arena_dispose (&arena);
}

TEST (qpack_integration_pattern_detection)
{
  /* Test correct pattern detection for all field line types */

  /* Indexed Field Line (1xxxxxxx) */
  ASSERT (SocketQPACK_is_indexed_field_line (0x80) != 0);
  ASSERT (SocketQPACK_is_indexed_field_line (0xC0) != 0);
  ASSERT (SocketQPACK_is_indexed_field_line (0xFF) != 0);

  /* Indexed Field Line with Post-Base (0001xxxx) */
  ASSERT (SocketQPACK_is_indexed_postbase (0x10) == true);
  ASSERT (SocketQPACK_is_indexed_postbase (0x1F) == true);
  ASSERT (SocketQPACK_is_indexed_postbase (0x00) == false);
  ASSERT (SocketQPACK_is_indexed_postbase (0x20) == false);

  /* Literal Field Line with Literal Name (001xxxxx) */
  ASSERT (SocketQPACK_is_literal_field_literal_name (0x20) == true);
  ASSERT (SocketQPACK_is_literal_field_literal_name (0x3F) == true);
  ASSERT (SocketQPACK_is_literal_field_literal_name (0x00) == false);
  ASSERT (SocketQPACK_is_literal_field_literal_name (0x40) == false);
}

TEST (qpack_integration_large_value)
{
  /* Test encoding/decoding of large header values */
  unsigned char buf[8192];
  size_t written = 0;
  unsigned char name_out[64];
  unsigned char value_out[4096];
  size_t name_len = 0;
  size_t value_len = 0;
  bool never_indexed = false;
  size_t consumed = 0;

  /* Create a large value (1000 bytes) */
  unsigned char large_value[1000];
  for (size_t i = 0; i < sizeof (large_value); i++)
    large_value[i] = (unsigned char)('a' + (i % 26));

  SocketQPACK_Result result = SocketQPACK_encode_literal_field_literal_name (
      buf,
      sizeof (buf),
      (const unsigned char *)"x-large-header",
      14,
      false,
      large_value,
      sizeof (large_value),
      false,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_decode_literal_field_literal_name (buf,
                                                          written,
                                                          name_out,
                                                          sizeof (name_out),
                                                          &name_len,
                                                          value_out,
                                                          sizeof (value_out),
                                                          &value_len,
                                                          &never_indexed,
                                                          &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_len, 14);
  ASSERT_EQ (value_len, sizeof (large_value));
  ASSERT (memcmp (name_out, "x-large-header", 14) == 0);
  ASSERT (memcmp (value_out, large_value, sizeof (large_value)) == 0);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

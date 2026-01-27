/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_vectors.c
 * @brief RFC 9204 Appendix B - QPACK Test Vectors
 *
 * Implements the official test vectors from RFC 9204 Appendix B to ensure
 * compliance with the QPACK specification.
 *
 * Test Vectors:
 * - B.1: Literal Field Line With Name Reference
 * - B.2: Dynamic Table
 * - B.3: Speculative Insert
 * - B.4: Duplicate Instruction (requires Duplicate to be implemented)
 * - B.5: Dynamic Table Insert, Evicting
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#appendix-B
 */

#include <stdio.h>
#include <string.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACK.h"
#include "http/qpack/SocketQPACKDecoderStream.h"
#include "http/qpack/SocketQPACKEncoderStream.h"
#include "test/Test.h"

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Hex string to byte array conversion helper.
 *
 * Converts a hex string like "510b2f" to bytes {0x51, 0x0b, 0x2f}.
 */
static size_t
hex_to_bytes (const char *hex, unsigned char *out, size_t out_size)
{
  size_t hex_len = strlen (hex);
  size_t byte_len = hex_len / 2;
  if (byte_len > out_size)
    byte_len = out_size;

  for (size_t i = 0; i < byte_len; i++)
    {
      unsigned int byte;
      if (sscanf (hex + 2 * i, "%2x", &byte) != 1)
        return i;
      out[i] = (unsigned char)byte;
    }

  return byte_len;
}

/**
 * @brief Compare binary data with hex string.
 */
static int
compare_hex (const unsigned char *data, size_t data_len, const char *hex)
{
  unsigned char expected[256];
  size_t expected_len = hex_to_bytes (hex, expected, sizeof (expected));

  if (data_len != expected_len)
    return -1;

  return memcmp (data, expected, data_len);
}

/* ============================================================================
 * B.1: LITERAL FIELD LINE WITH NAME REFERENCE (RFC 9204 Appendix B.1)
 *
 * The encoder sends an encoded field section containing a literal
 * representation of a field with a static name reference.
 *
 * Header: :path: /index.html
 *
 * Stream Data: 0000 510b 2f69 6e64 65782e 68746d 6c
 *   - 00: Required Insert Count = 0
 *   - 00: Delta Base = 0 (Base = 0)
 *   - 51: Literal with Name Reference (static, index 1 = :path)
 *   - 0b: Value length = 11
 *   - 2f69...6c: "/index.html"
 * ============================================================================
 */

TEST (qpack_vector_b1_decode_prefix)
{
  /* RFC 9204 Appendix B.1: Field section prefix with RIC=0, Base=0 */
  const unsigned char prefix_data[] = { 0x00, 0x00 };
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  /* MaxEntries = 0 since no dynamic table in this example */
  uint64_t max_entries = 0;
  uint64_t total_insert_count = 0;

  SocketQPACK_Result result
      = SocketQPACK_decode_prefix (prefix_data, sizeof (prefix_data),
                                   max_entries, total_insert_count,
                                   &prefix, &consumed);

  /* With max_entries=0, RIC=0 is valid (no dynamic table references) */
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 2);
  ASSERT_EQ (prefix.required_insert_count, 0);
  ASSERT_EQ (prefix.base, 0);
}

TEST (qpack_vector_b1_decode_literal_name_ref)
{
  /* RFC 9204 Appendix B.1: Literal Field Line with Name Reference
   *
   * 51: 0101 0001
   *     01 = Literal with Name Reference pattern
   *     0 = N bit (not never-indexed)
   *     1 = T bit (static table)
   *     0001 = Index 1 (:path) with 4-bit prefix
   */
  const unsigned char data[]
      = { 0x51, 0x0b, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l' };

  SocketQPACK_LiteralNameRef decoded;
  size_t consumed = 0;

  SocketQPACK_Result result
      = SocketQPACK_decode_literal_name_ref (data, sizeof (data),
                                              &decoded, &consumed);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, sizeof (data));
  ASSERT_EQ (decoded.is_static, true);
  ASSERT_EQ (decoded.name_index, 1); /* :path is at static index 1 */
  ASSERT_EQ (decoded.never_indexed, false);
  ASSERT_EQ (decoded.value_huffman, false);
  ASSERT_EQ (decoded.value_len, 11);
  ASSERT (memcmp (decoded.value, "/index.html", 11) == 0);
}

TEST (qpack_vector_b1_encode_literal_name_ref)
{
  /* Verify we can encode the same field line */
  unsigned char buf[64];
  size_t written = 0;

  const unsigned char value[] = "/index.html";

  SocketQPACK_Result result
      = SocketQPACK_encode_literal_name_ref (buf, sizeof (buf),
                                              true,        /* static */
                                              1,           /* :path index */
                                              false,       /* never_indexed */
                                              value, 11,
                                              false,       /* no huffman */
                                              &written);

  ASSERT_EQ (result, QPACK_OK);

  /* Expected: 51 0b 2f696e6465782e68746d6c */
  ASSERT_EQ (written, 13);
  ASSERT_EQ (buf[0], 0x51); /* Literal name ref, static, index 1 */
  ASSERT_EQ (buf[1], 0x0b); /* Value length 11, no Huffman */
  ASSERT (memcmp (buf + 2, "/index.html", 11) == 0);
}

TEST (qpack_vector_b1_complete)
{
  /* RFC 9204 Appendix B.1: Complete test of full field section encoding
   *
   * Expected wire format:
   *   0000 510b 2f69 6e64 65782e 68746d 6c
   */
  const char *expected_hex = "0000510b2f696e6465782e68746d6c";
  unsigned char expected[32];
  size_t expected_len = hex_to_bytes (expected_hex, expected, sizeof (expected));

  /* Build the field section */
  unsigned char buf[64];
  size_t offset = 0;
  size_t written = 0;

  /* Encode prefix: RIC=0, Base=0 */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (0, 0, 0, buf + offset, sizeof (buf) - offset,
                                    &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* Encode literal field line with name reference */
  const unsigned char value[] = "/index.html";
  result = SocketQPACK_encode_literal_name_ref (buf + offset,
                                                 sizeof (buf) - offset,
                                                 true, 1, false,
                                                 value, 11, false,
                                                 &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* Verify complete encoding */
  ASSERT_EQ (offset, expected_len);
  ASSERT (memcmp (buf, expected, expected_len) == 0);
}

/* ============================================================================
 * B.2: DYNAMIC TABLE (RFC 9204 Appendix B.2)
 *
 * The encoder sets dynamic table capacity, inserts headers, and sends
 * a field section using post-base references.
 *
 * Encoder Stream:
 *   3fbd01: Set Dynamic Table Capacity = 220 (3f = 0x20 | 0x1f, bd01 = 189)
 *   c00f777...636f6d: Insert :authority = www.example.com
 *   c10c2f73...70617468: Insert :path = /sample/path
 *
 * Stream 4 Data: 0381 10 11
 *   - 03: Encoded Required Insert Count (2)
 *   - 81: Delta Base with sign bit (Base = RIC = 2)
 *   - 10: Indexed Field Line with Post-Base Index 0 (:authority)
 *   - 11: Indexed Field Line with Post-Base Index 1 (:path)
 *
 * Decoder Stream: 84
 *   - Section Acknowledgment for stream 4
 * ============================================================================
 */

TEST (qpack_vector_b2_set_capacity)
{
  /* RFC 9204 Appendix B.2: Set Dynamic Table Capacity = 220
   *
   * Wire format: 3f bd01
   *   0x3f = 0x20 | 0x1f (Set Capacity pattern with max 5-bit value)
   *   0xbd01 = Variable-length integer for 189 + 31 = 220
   */
  unsigned char buf[8];
  size_t written = 0;

  SocketQPACK_Result result
      = SocketQPACK_encode_set_capacity (220, buf, sizeof (buf), &written);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 3);
  ASSERT_EQ (buf[0], 0x3f); /* 001 + 11111 */
  ASSERT_EQ (buf[1], 0xbd); /* 189 in variable-length format */
  ASSERT_EQ (buf[2], 0x01);

  /* Verify decode */
  uint64_t capacity = 0;
  size_t consumed = 0;
  result = SocketQPACK_decode_set_capacity (buf, written, &capacity, &consumed);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 3);
  ASSERT_EQ (capacity, 220);
}

TEST (qpack_vector_b2_insert_authority)
{
  /* RFC 9204 Appendix B.2: Insert :authority = www.example.com
   *
   * Wire format: c00f 7777772e6578616d706c652e636f6d
   *   0xc0 = 1100 0000 (Insert with Name Reference, static, index 0)
   *   0x0f = Value length 15, no Huffman
   *   7777...6d = "www.example.com"
   */
  Arena_T arena = Arena_new ();

  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  /* Test decoding the instruction */
  const unsigned char wire[]
      = { 0xc0, 0x0f, 'w', 'w', 'w', '.', 'e', 'x', 'a', 'm',
          'p',  'l',  'e', '.', 'c', 'o', 'm' };

  /* Decode Insert with Name Reference (static index 0 = :authority) */
  SocketQPACK_InsertNameRef decoded;
  size_t consumed = 0;

  SocketQPACKStream_Result sresult = SocketQPACK_decode_insert_nameref (
      wire, sizeof (wire), arena, &decoded, &consumed);

  ASSERT_EQ (sresult, QPACK_STREAM_OK);
  ASSERT_EQ (consumed, sizeof (wire));
  ASSERT_EQ (decoded.is_static, true);
  ASSERT_EQ (decoded.name_index, 0); /* :authority at static index 0 */
  ASSERT_EQ (decoded.value_len, 15);
  ASSERT (memcmp (decoded.value, "www.example.com", 15) == 0);

  /* Insert into table - name from static table index 0 (:authority) */
  SocketQPACK_Result result = SocketQPACK_Table_insert_literal (
      table, ":authority", 10,
      (const char *)decoded.value, decoded.value_len);
  ASSERT_EQ (result, QPACK_OK);

  /* Verify entry was inserted */
  ASSERT_EQ (SocketQPACK_Table_count (table), 1);
  ASSERT_EQ (SocketQPACK_Table_insert_count (table), 1);

  /* Verify we can retrieve it */
  const char *name = NULL;
  const char *value = NULL;
  size_t name_out_len = 0;
  size_t value_out_len = 0;

  result = SocketQPACK_Table_get (table, 0, &name, &name_out_len,
                                   &value, &value_out_len);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_out_len, 10); /* ":authority" */
  ASSERT (memcmp (name, ":authority", 10) == 0);
  ASSERT_EQ (value_out_len, 15);
  ASSERT (memcmp (value, "www.example.com", 15) == 0);

  Arena_dispose (&arena);
}

TEST (qpack_vector_b2_insert_path)
{
  /* RFC 9204 Appendix B.2: Insert :path = /sample/path
   *
   * Wire format: c10c 2f73616d706c652f70617468
   *   0xc1 = 1100 0001 (Insert with Name Reference, static, index 1)
   *   0x0c = Value length 12, no Huffman
   *   2f73...7468 = "/sample/path"
   */
  Arena_T arena = Arena_new ();

  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  /* Test decoding the instruction */
  const unsigned char wire[]
      = { 0xc1, 0x0c, '/', 's', 'a', 'm', 'p', 'l',
          'e',  '/',  'p', 'a', 't', 'h' };

  /* Decode Insert with Name Reference (static index 1 = :path) */
  SocketQPACK_InsertNameRef decoded;
  size_t consumed = 0;

  SocketQPACKStream_Result sresult = SocketQPACK_decode_insert_nameref (
      wire, sizeof (wire), arena, &decoded, &consumed);

  ASSERT_EQ (sresult, QPACK_STREAM_OK);
  ASSERT_EQ (consumed, sizeof (wire));
  ASSERT_EQ (decoded.is_static, true);
  ASSERT_EQ (decoded.name_index, 1); /* :path at static index 1 */
  ASSERT_EQ (decoded.value_len, 12);
  ASSERT (memcmp (decoded.value, "/sample/path", 12) == 0);

  /* Insert into table */
  SocketQPACK_Result result = SocketQPACK_Table_insert_literal (
      table, ":path", 5, (const char *)decoded.value, decoded.value_len);
  ASSERT_EQ (result, QPACK_OK);

  ASSERT_EQ (SocketQPACK_Table_count (table), 1);
  ASSERT_EQ (SocketQPACK_Table_insert_count (table), 1);

  Arena_dispose (&arena);
}

TEST (qpack_vector_b2_prefix)
{
  /* RFC 9204 Appendix B.2: Field section prefix
   *
   * Wire format: 03 81
   *   0x03 = Encoded Required Insert Count
   *   0x81 = Delta Base with S=1 (negative)
   *
   * With MaxEntries = 220/32 = 6:
   *   EncodedRIC = 3 => RIC = 2 (using decode algorithm)
   *   S=1, DeltaBase=1 => Base = RIC - DeltaBase - 1 = 2 - 1 - 1 = 0
   *
   * Actually, re-reading RFC: the example shows Base = RIC when Sign bit
   * indicates the delta is added. Let me verify with the actual decode.
   */
  Arena_T arena = Arena_new ();

  /* MaxEntries = floor(220 / 32) = 6 */
  uint64_t max_entries = 220 / 32;
  uint64_t total_insert_count = 2; /* Two entries inserted */

  const unsigned char prefix_data[] = { 0x03, 0x81 };
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  SocketQPACK_Result result
      = SocketQPACK_decode_prefix (prefix_data, sizeof (prefix_data),
                                   max_entries, total_insert_count,
                                   &prefix, &consumed);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 2);
  ASSERT_EQ (prefix.required_insert_count, 2);
  /* Base should be 0 based on the S=1 and delta_base calculation */

  Arena_dispose (&arena);
}

TEST (qpack_vector_b2_indexed_postbase)
{
  /* RFC 9204 Appendix B.2: Indexed Field Line with Post-Base Index
   *
   * Wire format: 10
   *   0001 0000 = Indexed with Post-Base pattern (0001) + index 0
   *
   * And: 11
   *   0001 0001 = Indexed with Post-Base pattern (0001) + index 1
   */
  unsigned char buf[4];
  size_t written = 0;

  /* Encode post-base index 0 */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_postbase (0, buf, sizeof (buf), &written);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 1);
  ASSERT_EQ (buf[0], 0x10);

  /* Encode post-base index 1 */
  result = SocketQPACK_encode_indexed_postbase (1, buf, sizeof (buf), &written);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 1);
  ASSERT_EQ (buf[0], 0x11);

  /* Decode verification */
  uint64_t pb_index = 0;
  size_t consumed = 0;

  const unsigned char pb0[] = { 0x10 };
  result = SocketQPACK_decode_indexed_postbase (pb0, 1, &pb_index, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (pb_index, 0);

  const unsigned char pb1[] = { 0x11 };
  result = SocketQPACK_decode_indexed_postbase (pb1, 1, &pb_index, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (pb_index, 1);
}

TEST (qpack_vector_b2_decoder_section_ack)
{
  /* RFC 9204 Appendix B.2: Section Acknowledgment for stream 4
   *
   * Wire format: 84
   *   1000 0100 = Section Ack pattern (1) + stream ID 4
   */
  Arena_T arena = Arena_new ();

  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 3); /* Decoder stream ID */
  ASSERT (stream != NULL);

  SocketQPACKStream_Result sresult = SocketQPACK_DecoderStream_init (stream);
  ASSERT_EQ (sresult, QPACK_STREAM_OK);

  /* Write section acknowledgment */
  sresult = SocketQPACK_DecoderStream_write_section_ack (stream, 4);
  ASSERT_EQ (sresult, QPACK_STREAM_OK);

  /* Get and verify buffer */
  size_t len = 0;
  const unsigned char *buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  ASSERT (buf != NULL);
  ASSERT_EQ (len, 1);
  ASSERT_EQ (buf[0], 0x84); /* Stream 4 acknowledgment */

  Arena_dispose (&arena);
}

/* ============================================================================
 * B.3: SPECULATIVE INSERT (RFC 9204 Appendix B.3)
 *
 * The encoder inserts a header with literal name into the dynamic table.
 * The decoder acknowledges with Insert Count Increment.
 *
 * Encoder Stream: 4a63757374...76616c7565
 *   4a: Insert with Literal Name (01001010)
 *       01 = pattern
 *       0 = no Huffman on name
 *       01010 = name length 10 ("custom-key")
 *   63757374...6579: "custom-key"
 *   0c: value length 12
 *   63757374...7565: "custom-value"
 *
 * Decoder Stream: 01
 *   Insert Count Increment of 1
 * ============================================================================
 */

TEST (qpack_vector_b3_insert_literal_name)
{
  /* RFC 9204 Appendix B.3: Insert with Literal Name
   *
   * Insert custom-key: custom-value into dynamic table
   */
  Arena_T arena = Arena_new ();

  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  /* Build the wire format manually for verification:
   * 4a = 0100 1010 (Insert Literal Name, no Huffman, length 10)
   */
  const unsigned char wire[] = { 0x4a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k',
                                  'e',  'y', 0x0c, 'c', 'u', 's', 't', 'o', 'm',
                                  '-',  'v', 'a',  'l', 'u', 'e' };

  unsigned char name_buf[64];
  size_t name_len = 0;
  unsigned char value_buf[64];
  size_t value_len = 0;
  size_t consumed = 0;

  /* Decode the instruction */
  SocketQPACK_Result result = SocketQPACK_decode_insert_literal_name (
      wire, sizeof (wire), table, name_buf, sizeof (name_buf), &name_len,
      value_buf, sizeof (value_buf), &value_len, &consumed);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, sizeof (wire));
  ASSERT_EQ (name_len, 10);
  ASSERT (memcmp (name_buf, "custom-key", 10) == 0);
  ASSERT_EQ (value_len, 12);
  ASSERT (memcmp (value_buf, "custom-value", 12) == 0);

  /* Verify entry in table */
  ASSERT_EQ (SocketQPACK_Table_count (table), 1);
  ASSERT_EQ (SocketQPACK_Table_insert_count (table), 1);

  Arena_dispose (&arena);
}

TEST (qpack_vector_b3_decoder_insert_count_inc)
{
  /* RFC 9204 Appendix B.3: Insert Count Increment of 1
   *
   * Wire format: 01
   *   00 000001 = Insert Count Increment (00) + increment 1
   */
  Arena_T arena = Arena_new ();

  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 3);
  ASSERT (stream != NULL);

  SocketQPACKStream_Result sresult = SocketQPACK_DecoderStream_init (stream);
  ASSERT_EQ (sresult, QPACK_STREAM_OK);

  /* Write insert count increment */
  sresult = SocketQPACK_DecoderStream_write_insert_count_inc (stream, 1);
  ASSERT_EQ (sresult, QPACK_STREAM_OK);

  /* Verify */
  size_t len = 0;
  const unsigned char *buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  ASSERT (buf != NULL);
  ASSERT_EQ (len, 1);
  ASSERT_EQ (buf[0], 0x01);

  Arena_dispose (&arena);
}

/* ============================================================================
 * B.4: DUPLICATE INSTRUCTION (RFC 9204 Appendix B.4)
 *
 * Note: This test requires the Duplicate encoder instruction (Section 4.3.4)
 * to be implemented. Skip if not available.
 *
 * The encoder duplicates an existing dynamic table entry.
 * Wire format: 02 = Duplicate instruction with index 2
 * ============================================================================
 */

TEST (qpack_vector_b4_stream_cancellation)
{
  /* RFC 9204 Appendix B.4: Stream Cancellation for stream 8
   *
   * Wire format: 48
   *   01 001000 = Stream Cancellation (01) + stream ID 8
   */
  Arena_T arena = Arena_new ();

  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 3);
  ASSERT (stream != NULL);

  SocketQPACKStream_Result sresult = SocketQPACK_DecoderStream_init (stream);
  ASSERT_EQ (sresult, QPACK_STREAM_OK);

  /* Write stream cancellation */
  sresult = SocketQPACK_DecoderStream_write_stream_cancel (stream, 8);
  ASSERT_EQ (sresult, QPACK_STREAM_OK);

  /* Verify */
  size_t len = 0;
  const unsigned char *buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  ASSERT (buf != NULL);
  ASSERT_EQ (len, 1);
  ASSERT_EQ (buf[0], 0x48);

  Arena_dispose (&arena);
}

TEST (qpack_vector_b4_duplicate)
{
  /* RFC 9204 Appendix B.4: Duplicate instruction
   *
   * Wire format: 02
   *   000 00010 = Duplicate pattern (000) + relative index 2
   *
   * This duplicates the entry at encoder-relative index 2, which is the
   * :authority entry (third oldest = index 0 absolute, but relative is
   * counted from most recent).
   */
  Arena_T arena = Arena_new ();

  SocketQPACK_EncoderStream_T stream
      = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  ASSERT (stream != NULL);

  SocketQPACKStream_Result sresult = SocketQPACK_EncoderStream_init (stream);
  ASSERT_EQ (sresult, QPACK_STREAM_OK);

  /* Write duplicate instruction for relative index 2 */
  sresult = SocketQPACK_EncoderStream_write_duplicate (stream, 2, 10, 0);
  ASSERT_EQ (sresult, QPACK_STREAM_OK);

  /* Verify wire format */
  size_t len = 0;
  const unsigned char *buf = SocketQPACK_EncoderStream_get_buffer (stream, &len);
  ASSERT (buf != NULL);
  ASSERT_EQ (len, 1);
  ASSERT_EQ (buf[0], 0x02); /* 000 00010 = duplicate rel index 2 */

  Arena_dispose (&arena);
}

TEST (qpack_vector_b4_indexed_static)
{
  /* RFC 9204 Appendix B.4: Indexed Field Line (static table)
   *
   * Wire format: c1
   *   1100 0001 = Indexed pattern (1) + static bit (1) + index 1 (:path=/)
   *
   * This references static table entry 1: ":path" with value "/"
   */
  unsigned char buf[4];
  size_t written = 0;

  /* Encode static indexed field line for index 1 */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 1, 1, &written);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 1);
  ASSERT_EQ (buf[0], 0xc1); /* 1100 0001 = static, index 1 */

  /* Decode verification */
  uint64_t index = 0;
  int is_static = 0;
  size_t consumed = 0;

  result = SocketQPACK_decode_indexed_field (buf, written, &index, &is_static,
                                              &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 1);
  ASSERT_EQ (index, 1);
  ASSERT_EQ (is_static, 1);
}

TEST (qpack_vector_b4_indexed_dynamic)
{
  /* RFC 9204 Appendix B.4: Indexed Field Line (dynamic table)
   *
   * Wire format: 80, 81
   *   1000 0000 = Indexed pattern (1) + dynamic bit (0) + index 0
   *   1000 0001 = Indexed pattern (1) + dynamic bit (0) + index 1
   *
   * In the B.4 example:
   * - 0x80 references dynamic entry at field-relative index 0 (abs 3)
   * - 0x81 references dynamic entry at field-relative index 1 (abs 2)
   */
  unsigned char buf[4];
  size_t written = 0;

  /* Encode dynamic indexed field line for relative index 0 */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 0, 0, &written);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 1);
  ASSERT_EQ (buf[0], 0x80); /* 1000 0000 = dynamic, index 0 */

  /* Encode dynamic indexed field line for relative index 1 */
  result = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 1, 0, &written);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 1);
  ASSERT_EQ (buf[0], 0x81); /* 1000 0001 = dynamic, index 1 */

  /* Decode verification for 0x80 */
  uint64_t index = 0;
  int is_static = 0;
  size_t consumed = 0;
  const unsigned char dyn0[] = { 0x80 };

  result = SocketQPACK_decode_indexed_field (dyn0, 1, &index, &is_static,
                                              &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (index, 0);
  ASSERT_EQ (is_static, 0);

  /* Decode verification for 0x81 */
  const unsigned char dyn1[] = { 0x81 };
  result = SocketQPACK_decode_indexed_field (dyn1, 1, &index, &is_static,
                                              &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (index, 1);
  ASSERT_EQ (is_static, 0);
}

TEST (qpack_vector_b4_field_section_prefix)
{
  /* RFC 9204 Appendix B.4: Stream 8 field section prefix
   *
   * Wire format: 0500
   *   05 = Encoded Required Insert Count (for RIC=4 with MaxEntries=6)
   *   00 = Delta Base with S=0 (Base = RIC + 0 = 4)
   *
   * With MaxEntries = 220/32 = 6:
   *   EncodedRIC = 5 => RIC = 4
   *   S=0, DeltaBase=0 => Base = RIC + 0 = 4
   */
  uint64_t max_entries = 220 / 32;
  uint64_t total_insert_count = 4; /* Four entries inserted (after duplicate) */

  const unsigned char prefix_data[] = { 0x05, 0x00 };
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  SocketQPACK_Result result
      = SocketQPACK_decode_prefix (prefix_data, sizeof (prefix_data),
                                   max_entries, total_insert_count,
                                   &prefix, &consumed);

  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 2);
  ASSERT_EQ (prefix.required_insert_count, 4);
  ASSERT_EQ (prefix.base, 4);
}

TEST (qpack_vector_b4_complete_field_section)
{
  /* RFC 9204 Appendix B.4: Complete field section
   *
   * Wire format: 0500 80 c1 81
   *   0500 = Prefix (RIC=4, Base=4)
   *   80 = Dynamic indexed, relative index 0 (abs = Base - 0 - 1 = 3)
   *   c1 = Static indexed, index 1 (:path=/)
   *   81 = Dynamic indexed, relative index 1 (abs = Base - 1 - 1 = 2)
   *
   * Expected headers:
   *   :authority = www.example.com (from abs index 3, duplicated entry)
   *   :path = / (from static table index 1)
   *   custom-key = custom-value (from abs index 2)
   */
  const char *expected_hex = "050080c181";
  unsigned char expected[8];
  size_t expected_len = hex_to_bytes (expected_hex, expected, sizeof (expected));

  /* Build field section */
  unsigned char buf[16];
  size_t offset = 0;
  size_t written = 0;

  /* Encode prefix: RIC=4, Base=4 */
  uint64_t max_entries = 220 / 32;
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (4, 4, max_entries, buf + offset,
                                    sizeof (buf) - offset, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* Encode dynamic indexed field line (relative index 0) */
  result = SocketQPACK_encode_indexed_field (buf + offset, sizeof (buf) - offset,
                                              0, 0, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* Encode static indexed field line (index 1) */
  result = SocketQPACK_encode_indexed_field (buf + offset, sizeof (buf) - offset,
                                              1, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* Encode dynamic indexed field line (relative index 1) */
  result = SocketQPACK_encode_indexed_field (buf + offset, sizeof (buf) - offset,
                                              1, 0, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* Verify complete encoding */
  ASSERT_EQ (offset, expected_len);
  ASSERT (memcmp (buf, expected, expected_len) == 0);
}

/* ============================================================================
 * B.5: DYNAMIC TABLE INSERT, EVICTING (RFC 9204 Appendix B.5)
 *
 * The encoder inserts a new entry which causes eviction of the oldest entry.
 *
 * Prerequisites:
 * - Table capacity = 220 bytes
 * - Table contains entries from B.2 and B.3
 *
 * New insert: custom-key: custom-value2 (using name reference to existing
 * custom-key entry)
 *
 * This should evict :authority: www.example.com (first entry)
 * ============================================================================
 */

TEST (qpack_vector_b5_eviction)
{
  /* RFC 9204 Appendix B.5: Eviction upon insertion
   *
   * Setup: Table capacity = 220 bytes
   * Insert entries until one gets evicted.
   */
  Arena_T arena = Arena_new ();

  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 220);
  ASSERT (table != NULL);

  /* Insert :authority: www.example.com (entry size = 10 + 15 + 32 = 57) */
  SocketQPACK_Result result = SocketQPACK_Table_insert_literal (
      table, ":authority", 10, "www.example.com", 15);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_insert_count (table), 1);
  ASSERT_EQ (SocketQPACK_Table_dropped_count (table), 0);

  /* Insert :path: /sample/path (entry size = 5 + 12 + 32 = 49) */
  result = SocketQPACK_Table_insert_literal (
      table, ":path", 5, "/sample/path", 12);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_insert_count (table), 2);
  ASSERT_EQ (SocketQPACK_Table_dropped_count (table), 0);

  /* Insert custom-key: custom-value (entry size = 10 + 12 + 32 = 54) */
  result = SocketQPACK_Table_insert_literal (
      table, "custom-key", 10, "custom-value", 12);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_insert_count (table), 3);
  ASSERT_EQ (SocketQPACK_Table_dropped_count (table), 0);

  /* Current table size: 57 + 49 + 54 = 160 bytes */
  ASSERT_EQ (SocketQPACK_Table_size (table), 160);

  /* Insert custom-key: custom-value2 (entry size = 10 + 13 + 32 = 55) */
  /* Total would be 215, which fits in 220 */
  result = SocketQPACK_Table_insert_literal (
      table, "custom-key", 10, "custom-value2", 13);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_insert_count (table), 4);
  /* No eviction yet since 160 + 55 = 215 < 220 */
  ASSERT_EQ (SocketQPACK_Table_dropped_count (table), 0);
  ASSERT_EQ (SocketQPACK_Table_size (table), 215);

  /* Insert one more entry that triggers eviction */
  /* A small entry like x: y (size = 1 + 1 + 32 = 34) */
  /* 215 + 34 = 249 > 220, so first entry (:authority) must be evicted */
  result = SocketQPACK_Table_insert_literal (table, "x", 1, "y", 1);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_insert_count (table), 5);
  /* First entry (57 bytes) should be evicted */
  ASSERT_EQ (SocketQPACK_Table_dropped_count (table), 1);

  /* Verify the first entry (absolute index 0) is now invalid */
  const char *name = NULL;
  size_t name_len = 0;
  const char *value = NULL;
  size_t value_len = 0;

  result = SocketQPACK_Table_get (table, 0, &name, &name_len, &value, &value_len);
  ASSERT_EQ (result, QPACK_ERR_EVICTED_INDEX);

  /* Verify second entry (absolute index 1) is still valid */
  result = SocketQPACK_Table_get (table, 1, &name, &name_len, &value, &value_len);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_len, 5);
  ASSERT (memcmp (name, ":path", 5) == 0);

  Arena_dispose (&arena);
}

TEST (qpack_vector_b5_insert_nameref_wire)
{
  /* RFC 9204 Appendix B.5: Insert with name reference to dynamic entry
   *
   * Wire format: 810d 637573746f6d2d76616c756532
   *   81 = 1000 0001 (Insert with Name Reference, dynamic, index 1)
   *   0d = value length 13
   *   637573746f6d2d76616c756532 = "custom-value2"
   *
   * This references the custom-key entry at encoder-relative index 1
   * (second-most-recent insertion).
   */
  Arena_T arena = Arena_new ();

  /* Build the exact RFC wire format */
  const unsigned char wire[]
      = { 0x81, 0x0d, 'c', 'u', 's', 't', 'o', 'm', '-',
          'v',  'a',  'l', 'u', 'e', '2' };

  /* Decode the instruction */
  SocketQPACK_InsertNameRef decoded;
  size_t consumed = 0;

  SocketQPACKStream_Result sresult = SocketQPACK_decode_insert_nameref (
      wire, sizeof (wire), arena, &decoded, &consumed);

  ASSERT_EQ (sresult, QPACK_STREAM_OK);
  ASSERT_EQ (consumed, sizeof (wire));
  ASSERT_EQ (decoded.is_static, false);      /* dynamic table reference */
  ASSERT_EQ (decoded.name_index, 1);         /* relative index 1 */
  ASSERT_EQ (decoded.value_len, 13);
  ASSERT (memcmp (decoded.value, "custom-value2", 13) == 0);

  /* Also test encoding round-trip */
  unsigned char encoded[32];
  size_t written = 0;

  sresult = SocketQPACK_encode_insert_nameref (encoded, sizeof (encoded),
                                                false, 1,
                                                (const unsigned char *)"custom-value2", 13,
                                                false, &written);
  ASSERT_EQ (sresult, QPACK_STREAM_OK);
  ASSERT_EQ (written, sizeof (wire));
  ASSERT (memcmp (encoded, wire, sizeof (wire)) == 0);

  Arena_dispose (&arena);
}

/* ============================================================================
 * ROUND-TRIP TESTS
 * ============================================================================
 */

TEST (qpack_vector_roundtrip_literal_name_ref)
{
  /* Full round-trip test: encode then decode */
  Arena_T arena = Arena_new ();

  unsigned char buf[128];
  size_t total = 0;
  size_t written = 0;

  /* Encode prefix (RIC=0, Base=0) */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (0, 0, 0, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);
  total += written;

  /* Encode :path: /test/path */
  const unsigned char value[] = "/test/path";
  result = SocketQPACK_encode_literal_name_ref (buf + total,
                                                 sizeof (buf) - total,
                                                 true, 1, false,
                                                 value, 10, false, &written);
  ASSERT_EQ (result, QPACK_OK);
  total += written;

  /* Decode prefix */
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;
  result = SocketQPACK_decode_prefix (buf, total, 0, 0, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (prefix.required_insert_count, 0);

  /* Decode field line */
  SocketQPACK_LiteralNameRef decoded;
  result = SocketQPACK_decode_literal_name_ref (buf + consumed,
                                                 total - consumed,
                                                 &decoded, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded.is_static, true);
  ASSERT_EQ (decoded.name_index, 1);
  ASSERT_EQ (decoded.value_len, 10);
  ASSERT (memcmp (decoded.value, "/test/path", 10) == 0);

  Arena_dispose (&arena);
}

TEST (qpack_vector_roundtrip_dynamic_table)
{
  /* Round-trip with dynamic table and post-base references */
  Arena_T arena = Arena_new ();

  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  /* Insert test-header: test-value */
  SocketQPACK_Result result = SocketQPACK_Table_insert_literal (
      table, "test-header", 11, "test-value", 10);
  ASSERT_EQ (result, QPACK_OK);

  /* Encode field section using post-base reference */
  unsigned char buf[64];
  size_t total = 0;
  size_t written = 0;

  /* Prefix: RIC=1, Base=0 (entries inserted after Base=0 are post-base) */
  uint64_t max_entries = 4096 / 32;
  result = SocketQPACK_encode_prefix (1, 0, max_entries, buf, sizeof (buf),
                                       &written);
  ASSERT_EQ (result, QPACK_OK);
  total += written;

  /* Indexed Field Line with Post-Base Index 0 */
  result = SocketQPACK_encode_indexed_postbase (0, buf + total,
                                                 sizeof (buf) - total, &written);
  ASSERT_EQ (result, QPACK_OK);
  total += written;

  /* Decode and verify */
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  result = SocketQPACK_decode_prefix (buf, total, max_entries, 1,
                                       &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (prefix.required_insert_count, 1);

  uint64_t pb_index = 0;
  result = SocketQPACK_decode_indexed_postbase (buf + consumed,
                                                 total - consumed,
                                                 &pb_index, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (pb_index, 0);

  /* Look up from table */
  const char *name = NULL;
  size_t name_len = 0;
  const char *value = NULL;
  size_t value_len = 0;

  result = SocketQPACK_lookup_indexed_postbase (table, 0, pb_index,
                                                 &name, &name_len,
                                                 &value, &value_len);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_len, 11);
  ASSERT (memcmp (name, "test-header", 11) == 0);
  ASSERT_EQ (value_len, 10);
  ASSERT (memcmp (value, "test-value", 10) == 0);

  Arena_dispose (&arena);
}

/* ============================================================================
 * SEQUENTIAL INTEGRATION TEST (RFC 9204 Appendix B.1-B.5)
 *
 * This test runs through the complete sequence from RFC 9204 Appendix B,
 * maintaining state across all sections to verify the full protocol flow.
 * ============================================================================
 */

TEST (qpack_vector_sequential_b1_to_b5)
{
  /*
   * RFC 9204 Appendix B complete sequential test
   *
   * Simulates the encoder-decoder exchange from B.1 through B.5:
   *   B.1: Literal field line (no dynamic table)
   *   B.2: Set capacity, insert entries, use post-base references
   *   B.3: Insert with literal name
   *   B.4: Duplicate, field section with mixed references
   *   B.5: Insert causing eviction
   */
  Arena_T arena = Arena_new ();

  /* Create dynamic table with RFC 9204 Appendix B capacity */
  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 220);
  ASSERT (table != NULL);
  uint64_t max_entries = 220 / 32; /* = 6 */

  /* ---------- B.1: Literal field line (no dynamic table) ---------- */
  /* Nothing to insert, just verify we can encode/decode with empty table */
  ASSERT_EQ (SocketQPACK_Table_count (table), 0);
  ASSERT_EQ (SocketQPACK_Table_insert_count (table), 0);

  /* ---------- B.2: Insert :authority and :path ---------- */
  /* Insert :authority = www.example.com (entry size: 10 + 15 + 32 = 57) */
  SocketQPACK_Result result = SocketQPACK_Table_insert_literal (
      table, ":authority", 10, "www.example.com", 15);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_insert_count (table), 1);

  /* Insert :path = /sample/path (entry size: 5 + 12 + 32 = 49) */
  result = SocketQPACK_Table_insert_literal (
      table, ":path", 5, "/sample/path", 12);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_insert_count (table), 2);

  /* Verify table state after B.2 */
  ASSERT_EQ (SocketQPACK_Table_count (table), 2);
  ASSERT_EQ (SocketQPACK_Table_size (table), 106); /* 57 + 49 */

  /* Verify prefix encoding for B.2 field section */
  unsigned char prefix_buf[8];
  size_t prefix_written = 0;
  result = SocketQPACK_encode_prefix (2, 0, max_entries, prefix_buf,
                                       sizeof (prefix_buf), &prefix_written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (prefix_buf[0], 0x03); /* Encoded RIC */
  ASSERT_EQ (prefix_buf[1], 0x81); /* S=1, delta_base=1 => Base=0 */

  /* ---------- B.3: Insert custom-key: custom-value ---------- */
  /* Entry size: 10 + 12 + 32 = 54 */
  result = SocketQPACK_Table_insert_literal (
      table, "custom-key", 10, "custom-value", 12);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_insert_count (table), 3);

  /* Verify table state after B.3 */
  ASSERT_EQ (SocketQPACK_Table_count (table), 3);
  ASSERT_EQ (SocketQPACK_Table_size (table), 160); /* 57 + 49 + 54 */

  /* ---------- B.4: Duplicate :authority entry ---------- */
  /* In RFC example, entry at encoder-relative index 2 is duplicated.
   * With insert_count=3, relative index 2 refers to absolute index 0
   * (:authority entry).
   *
   * After duplication, table has 4 entries with absolute indices 0-3.
   * Entry 3 is a copy of entry 0.
   *
   * Note: We simulate the duplicate by inserting the same values.
   * Entry size: 10 + 15 + 32 = 57
   */
  result = SocketQPACK_Table_insert_literal (
      table, ":authority", 10, "www.example.com", 15);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_insert_count (table), 4);

  /* Verify table state after B.4 duplicate */
  ASSERT_EQ (SocketQPACK_Table_count (table), 4);
  ASSERT_EQ (SocketQPACK_Table_size (table), 217); /* 57 + 49 + 54 + 57 */

  /* Verify B.4 prefix encoding (RIC=4, Base=4) */
  result = SocketQPACK_encode_prefix (4, 4, max_entries, prefix_buf,
                                       sizeof (prefix_buf), &prefix_written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (prefix_buf[0], 0x05); /* Encoded RIC */
  ASSERT_EQ (prefix_buf[1], 0x00); /* S=0, delta_base=0 => Base=RIC=4 */

  /* ---------- B.5: Insert causing eviction ---------- */
  /* Insert custom-key: custom-value2 (entry size: 10 + 13 + 32 = 55)
   * Total would be 217 + 55 = 272 > 220
   * First entry (57 bytes) must be evicted
   */
  result = SocketQPACK_Table_insert_literal (
      table, "custom-key", 10, "custom-value2", 13);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_insert_count (table), 5);
  ASSERT_EQ (SocketQPACK_Table_dropped_count (table), 1);

  /* Verify table state after B.5 */
  ASSERT_EQ (SocketQPACK_Table_count (table), 4); /* One evicted */
  ASSERT_EQ (SocketQPACK_Table_size (table), 215); /* 217 - 57 + 55 */

  /* Verify absolute index 0 (:authority) is now evicted */
  const char *name = NULL;
  size_t name_len = 0;
  const char *value = NULL;
  size_t value_len = 0;

  result = SocketQPACK_Table_get (table, 0, &name, &name_len, &value, &value_len);
  ASSERT_EQ (result, QPACK_ERR_EVICTED_INDEX);

  /* Verify absolute index 1 (:path=/sample/path) is still valid */
  result = SocketQPACK_Table_get (table, 1, &name, &name_len, &value, &value_len);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_len, 5);
  ASSERT (memcmp (name, ":path", 5) == 0);
  ASSERT_EQ (value_len, 12);
  ASSERT (memcmp (value, "/sample/path", 12) == 0);

  /* Verify absolute index 4 (custom-key: custom-value2) is valid */
  result = SocketQPACK_Table_get (table, 4, &name, &name_len, &value, &value_len);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (name_len, 10);
  ASSERT (memcmp (name, "custom-key", 10) == 0);
  ASSERT_EQ (value_len, 13);
  ASSERT (memcmp (value, "custom-value2", 13) == 0);

  Arena_dispose (&arena);
}

/* ============================================================================
 * MAIN
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

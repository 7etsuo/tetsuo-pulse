/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_connid.c - QUIC Connection ID unit tests (RFC 9000 §5.1)
 *
 * Tests Connection ID structure, generation, comparison, encoding/decoding,
 * and utility functions.
 */

#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICConnectionID.h"
#include "test/Test.h"

/* ============================================================================
 * Constant Value Tests
 * ============================================================================
 */

TEST (quic_connid_max_len)
{
  ASSERT_EQ (QUIC_CONNID_MAX_LEN, 20);
}

TEST (quic_connid_min_len)
{
  ASSERT_EQ (QUIC_CONNID_MIN_LEN, 1);
}

TEST (quic_connid_reset_token_len)
{
  ASSERT_EQ (QUIC_STATELESS_RESET_TOKEN_LEN, 16);
}

TEST (quic_connid_initial_sequence)
{
  ASSERT_EQ (QUIC_CONNID_INITIAL_SEQUENCE, 0);
}

TEST (quic_connid_preferred_address_sequence)
{
  ASSERT_EQ (QUIC_CONNID_PREFERRED_ADDRESS_SEQUENCE, 1);
}

TEST (quic_connid_default_limit)
{
  ASSERT_EQ (QUIC_CONNID_DEFAULT_LIMIT, 2);
}

/* ============================================================================
 * Initialization Tests
 * ============================================================================
 */

TEST (quic_connid_init)
{
  SocketQUICConnectionID_T cid;

  SocketQUICConnectionID_init (&cid);

  ASSERT_EQ (cid.len, 0);
  ASSERT_EQ (cid.sequence, 0);
  ASSERT_EQ (cid.has_reset_token, 0);
}

TEST (quic_connid_init_null)
{
  /* Should not crash */
  SocketQUICConnectionID_init (NULL);
}

TEST (quic_connid_set_basic)
{
  SocketQUICConnectionID_T cid;
  const uint8_t data[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };

  SocketQUICConnectionID_Result res
      = SocketQUICConnectionID_set (&cid, data, sizeof (data));

  ASSERT_EQ (res, QUIC_CONNID_OK);
  ASSERT_EQ (cid.len, 5);
  ASSERT (memcmp (cid.data, data, 5) == 0);
}

TEST (quic_connid_set_max_len)
{
  SocketQUICConnectionID_T cid;
  uint8_t data[20];

  memset (data, 0xAB, sizeof (data));

  SocketQUICConnectionID_Result res
      = SocketQUICConnectionID_set (&cid, data, 20);

  ASSERT_EQ (res, QUIC_CONNID_OK);
  ASSERT_EQ (cid.len, 20);
}

TEST (quic_connid_set_zero_len)
{
  SocketQUICConnectionID_T cid;

  SocketQUICConnectionID_Result res = SocketQUICConnectionID_set (&cid, NULL, 0);

  ASSERT_EQ (res, QUIC_CONNID_OK);
  ASSERT_EQ (cid.len, 0);
}

TEST (quic_connid_set_too_long)
{
  SocketQUICConnectionID_T cid;
  uint8_t data[25] = { 0 };

  SocketQUICConnectionID_Result res
      = SocketQUICConnectionID_set (&cid, data, 21);

  ASSERT_EQ (res, QUIC_CONNID_ERROR_LENGTH);
}

TEST (quic_connid_set_null)
{
  SocketQUICConnectionID_Result res
      = SocketQUICConnectionID_set (NULL, NULL, 0);

  ASSERT_EQ (res, QUIC_CONNID_ERROR_NULL);
}

TEST (quic_connid_set_null_data_nonzero_len)
{
  SocketQUICConnectionID_T cid;

  /* len > 0 but data == NULL should return error (not create zero-filled CID) */
  SocketQUICConnectionID_Result res
      = SocketQUICConnectionID_set (&cid, NULL, 8);

  ASSERT_EQ (res, QUIC_CONNID_ERROR_NULL);
}

/* ============================================================================
 * Generation Tests
 * ============================================================================
 */

TEST (quic_connid_generate_basic)
{
  SocketQUICConnectionID_T cid;

  SocketQUICConnectionID_Result res = SocketQUICConnectionID_generate (&cid, 8);

  ASSERT_EQ (res, QUIC_CONNID_OK);
  ASSERT_EQ (cid.len, 8);
}

TEST (quic_connid_generate_max_len)
{
  SocketQUICConnectionID_T cid;

  SocketQUICConnectionID_Result res = SocketQUICConnectionID_generate (&cid, 20);

  ASSERT_EQ (res, QUIC_CONNID_OK);
  ASSERT_EQ (cid.len, 20);
}

TEST (quic_connid_generate_zero_len)
{
  SocketQUICConnectionID_T cid;

  SocketQUICConnectionID_Result res = SocketQUICConnectionID_generate (&cid, 0);

  ASSERT_EQ (res, QUIC_CONNID_OK);
  ASSERT_EQ (cid.len, 0);
}

TEST (quic_connid_generate_too_long)
{
  SocketQUICConnectionID_T cid;

  SocketQUICConnectionID_Result res = SocketQUICConnectionID_generate (&cid, 21);

  ASSERT_EQ (res, QUIC_CONNID_ERROR_LENGTH);
}

TEST (quic_connid_generate_null)
{
  SocketQUICConnectionID_Result res = SocketQUICConnectionID_generate (NULL, 8);

  ASSERT_EQ (res, QUIC_CONNID_ERROR_NULL);
}

TEST (quic_connid_generate_unique)
{
  SocketQUICConnectionID_T cid1, cid2;

  SocketQUICConnectionID_generate (&cid1, 8);
  SocketQUICConnectionID_generate (&cid2, 8);

  /* Two random CIDs should be different (with overwhelming probability) */
  ASSERT (!SocketQUICConnectionID_equal (&cid1, &cid2));
}

TEST (quic_connid_generate_reset_token)
{
  SocketQUICConnectionID_T cid;

  SocketQUICConnectionID_init (&cid);
  ASSERT_EQ (cid.has_reset_token, 0);

  SocketQUICConnectionID_Result res
      = SocketQUICConnectionID_generate_reset_token (&cid);

  ASSERT_EQ (res, QUIC_CONNID_OK);
  ASSERT_EQ (cid.has_reset_token, 1);
}

TEST (quic_connid_generate_reset_token_null)
{
  SocketQUICConnectionID_Result res
      = SocketQUICConnectionID_generate_reset_token (NULL);

  ASSERT_EQ (res, QUIC_CONNID_ERROR_NULL);
}

/* ============================================================================
 * Comparison Tests
 * ============================================================================
 */

TEST (quic_connid_equal_same)
{
  SocketQUICConnectionID_T cid1, cid2;
  const uint8_t data[] = { 0x01, 0x02, 0x03, 0x04 };

  SocketQUICConnectionID_set (&cid1, data, 4);
  SocketQUICConnectionID_set (&cid2, data, 4);

  ASSERT (SocketQUICConnectionID_equal (&cid1, &cid2));
}

TEST (quic_connid_equal_different_data)
{
  SocketQUICConnectionID_T cid1, cid2;
  const uint8_t data1[] = { 0x01, 0x02, 0x03, 0x04 };
  const uint8_t data2[] = { 0x01, 0x02, 0x03, 0x05 };

  SocketQUICConnectionID_set (&cid1, data1, 4);
  SocketQUICConnectionID_set (&cid2, data2, 4);

  ASSERT (!SocketQUICConnectionID_equal (&cid1, &cid2));
}

TEST (quic_connid_equal_different_len)
{
  SocketQUICConnectionID_T cid1, cid2;
  const uint8_t data[] = { 0x01, 0x02, 0x03, 0x04 };

  SocketQUICConnectionID_set (&cid1, data, 4);
  SocketQUICConnectionID_set (&cid2, data, 3);

  ASSERT (!SocketQUICConnectionID_equal (&cid1, &cid2));
}

TEST (quic_connid_equal_zero_len)
{
  SocketQUICConnectionID_T cid1, cid2;

  SocketQUICConnectionID_set (&cid1, NULL, 0);
  SocketQUICConnectionID_set (&cid2, NULL, 0);

  ASSERT (SocketQUICConnectionID_equal (&cid1, &cid2));
}

TEST (quic_connid_equal_null)
{
  SocketQUICConnectionID_T cid;

  SocketQUICConnectionID_init (&cid);

  ASSERT (!SocketQUICConnectionID_equal (NULL, &cid));
  ASSERT (!SocketQUICConnectionID_equal (&cid, NULL));
  ASSERT (!SocketQUICConnectionID_equal (NULL, NULL));
}

TEST (quic_connid_equal_raw)
{
  SocketQUICConnectionID_T cid;
  const uint8_t data[] = { 0xAA, 0xBB, 0xCC };

  SocketQUICConnectionID_set (&cid, data, 3);

  ASSERT (SocketQUICConnectionID_equal_raw (&cid, data, 3));
  ASSERT (!SocketQUICConnectionID_equal_raw (&cid, data, 2));
}

TEST (quic_connid_equal_raw_null)
{
  SocketQUICConnectionID_T cid;

  SocketQUICConnectionID_init (&cid);

  ASSERT (!SocketQUICConnectionID_equal_raw (NULL, NULL, 0));
}

TEST (quic_connid_copy)
{
  SocketQUICConnectionID_T src, dst;
  const uint8_t data[] = { 0x11, 0x22, 0x33, 0x44, 0x55 };

  SocketQUICConnectionID_set (&src, data, 5);
  src.sequence = 42;
  src.has_reset_token = 1;
  memset (src.stateless_reset_token, 0xAB, 16);

  SocketQUICConnectionID_Result res = SocketQUICConnectionID_copy (&dst, &src);

  ASSERT_EQ (res, QUIC_CONNID_OK);
  ASSERT (SocketQUICConnectionID_equal (&dst, &src));
  ASSERT_EQ (dst.sequence, 42);
  ASSERT_EQ (dst.has_reset_token, 1);
}

TEST (quic_connid_copy_null)
{
  SocketQUICConnectionID_T cid;

  SocketQUICConnectionID_init (&cid);

  ASSERT_EQ (SocketQUICConnectionID_copy (NULL, &cid), QUIC_CONNID_ERROR_NULL);
  ASSERT_EQ (SocketQUICConnectionID_copy (&cid, NULL), QUIC_CONNID_ERROR_NULL);
}

/* ============================================================================
 * Wire Format Tests
 * ============================================================================
 */

TEST (quic_connid_encode_length)
{
  SocketQUICConnectionID_T cid;
  uint8_t buf[1];

  SocketQUICConnectionID_generate (&cid, 8);

  size_t n = SocketQUICConnectionID_encode_length (&cid, buf, sizeof (buf));

  ASSERT_EQ (n, 1);
  ASSERT_EQ (buf[0], 8);
}

TEST (quic_connid_encode)
{
  SocketQUICConnectionID_T cid;
  const uint8_t data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
  uint8_t buf[20];

  SocketQUICConnectionID_set (&cid, data, 4);

  size_t n = SocketQUICConnectionID_encode (&cid, buf, sizeof (buf));

  ASSERT_EQ (n, 4);
  ASSERT (memcmp (buf, data, 4) == 0);
}

TEST (quic_connid_encode_zero_len)
{
  SocketQUICConnectionID_T cid;
  uint8_t buf[1];

  SocketQUICConnectionID_set (&cid, NULL, 0);

  size_t n = SocketQUICConnectionID_encode (&cid, buf, sizeof (buf));

  ASSERT_EQ (n, 0); /* Nothing to write for zero-length CID */
}

TEST (quic_connid_encode_buffer_too_small)
{
  SocketQUICConnectionID_T cid;
  uint8_t buf[2];

  SocketQUICConnectionID_generate (&cid, 8);

  size_t n = SocketQUICConnectionID_encode (&cid, buf, sizeof (buf));

  ASSERT_EQ (n, 0);
}

TEST (quic_connid_encode_with_length)
{
  SocketQUICConnectionID_T cid;
  const uint8_t data[] = { 0x11, 0x22, 0x33 };
  uint8_t buf[10];

  SocketQUICConnectionID_set (&cid, data, 3);

  size_t n = SocketQUICConnectionID_encode_with_length (&cid, buf, sizeof (buf));

  ASSERT_EQ (n, 4);
  ASSERT_EQ (buf[0], 3);
  ASSERT (memcmp (buf + 1, data, 3) == 0);
}

TEST (quic_connid_encode_with_length_zero)
{
  SocketQUICConnectionID_T cid;
  uint8_t buf[10];

  SocketQUICConnectionID_set (&cid, NULL, 0);

  size_t n = SocketQUICConnectionID_encode_with_length (&cid, buf, sizeof (buf));

  ASSERT_EQ (n, 1);
  ASSERT_EQ (buf[0], 0);
}

TEST (quic_connid_decode)
{
  SocketQUICConnectionID_T cid;
  const uint8_t wire[] = { 0x04, 0xAA, 0xBB, 0xCC, 0xDD };
  size_t consumed = 0;

  SocketQUICConnectionID_Result res
      = SocketQUICConnectionID_decode (wire, sizeof (wire), &cid, &consumed);

  ASSERT_EQ (res, QUIC_CONNID_OK);
  ASSERT_EQ (consumed, 5);
  ASSERT_EQ (cid.len, 4);
  ASSERT (memcmp (cid.data, wire + 1, 4) == 0);
}

TEST (quic_connid_decode_zero_len)
{
  SocketQUICConnectionID_T cid;
  const uint8_t wire[] = { 0x00 };
  size_t consumed = 0;

  SocketQUICConnectionID_Result res
      = SocketQUICConnectionID_decode (wire, sizeof (wire), &cid, &consumed);

  ASSERT_EQ (res, QUIC_CONNID_OK);
  ASSERT_EQ (consumed, 1);
  ASSERT_EQ (cid.len, 0);
}

TEST (quic_connid_decode_max_len)
{
  SocketQUICConnectionID_T cid;
  uint8_t wire[21];
  size_t consumed = 0;

  wire[0] = 20;
  memset (wire + 1, 0xFF, 20);

  SocketQUICConnectionID_Result res
      = SocketQUICConnectionID_decode (wire, sizeof (wire), &cid, &consumed);

  ASSERT_EQ (res, QUIC_CONNID_OK);
  ASSERT_EQ (consumed, 21);
  ASSERT_EQ (cid.len, 20);
}

TEST (quic_connid_decode_incomplete)
{
  SocketQUICConnectionID_T cid;
  const uint8_t wire[] = { 0x04, 0xAA, 0xBB };
  size_t consumed = 0;

  SocketQUICConnectionID_Result res
      = SocketQUICConnectionID_decode (wire, sizeof (wire), &cid, &consumed);

  ASSERT_EQ (res, QUIC_CONNID_ERROR_INCOMPLETE);
}

TEST (quic_connid_decode_too_long)
{
  SocketQUICConnectionID_T cid;
  const uint8_t wire[] = { 21, 0x00 }; /* Length 21 > max 20 */
  size_t consumed = 0;

  SocketQUICConnectionID_Result res
      = SocketQUICConnectionID_decode (wire, sizeof (wire), &cid, &consumed);

  ASSERT_EQ (res, QUIC_CONNID_ERROR_LENGTH);
}

TEST (quic_connid_decode_fixed)
{
  SocketQUICConnectionID_T cid;
  const uint8_t wire[] = { 0x11, 0x22, 0x33, 0x44 };

  SocketQUICConnectionID_Result res
      = SocketQUICConnectionID_decode_fixed (wire, sizeof (wire), &cid, 4);

  ASSERT_EQ (res, QUIC_CONNID_OK);
  ASSERT_EQ (cid.len, 4);
  ASSERT (memcmp (cid.data, wire, 4) == 0);
}

TEST (quic_connid_decode_fixed_incomplete)
{
  SocketQUICConnectionID_T cid;
  const uint8_t wire[] = { 0x11, 0x22 };

  SocketQUICConnectionID_Result res
      = SocketQUICConnectionID_decode_fixed (wire, sizeof (wire), &cid, 4);

  ASSERT_EQ (res, QUIC_CONNID_ERROR_INCOMPLETE);
}

/* ============================================================================
 * Utility Tests
 * ============================================================================
 */

TEST (quic_connid_hash)
{
  SocketQUICConnectionID_T cid1, cid2;
  const uint8_t data[] = { 0x01, 0x02, 0x03, 0x04 };

  SocketQUICConnectionID_set (&cid1, data, 4);
  SocketQUICConnectionID_set (&cid2, data, 4);

  ASSERT_EQ (SocketQUICConnectionID_hash (&cid1),
             SocketQUICConnectionID_hash (&cid2));
}

TEST (quic_connid_hash_different)
{
  SocketQUICConnectionID_T cid1, cid2;

  SocketQUICConnectionID_generate (&cid1, 8);
  SocketQUICConnectionID_generate (&cid2, 8);

  /* Different CIDs should have different hashes (with high probability) */
  ASSERT (SocketQUICConnectionID_hash (&cid1)
          != SocketQUICConnectionID_hash (&cid2));
}

TEST (quic_connid_hash_empty)
{
  SocketQUICConnectionID_T cid;

  SocketQUICConnectionID_set (&cid, NULL, 0);

  ASSERT_EQ (SocketQUICConnectionID_hash (&cid), 0);
}

TEST (quic_connid_hash_null)
{
  ASSERT_EQ (SocketQUICConnectionID_hash (NULL), 0);
}

TEST (quic_connid_is_empty)
{
  SocketQUICConnectionID_T cid;

  SocketQUICConnectionID_set (&cid, NULL, 0);
  ASSERT (SocketQUICConnectionID_is_empty (&cid));

  SocketQUICConnectionID_generate (&cid, 4);
  ASSERT (!SocketQUICConnectionID_is_empty (&cid));
}

TEST (quic_connid_is_empty_null)
{
  ASSERT (SocketQUICConnectionID_is_empty (NULL));
}

TEST (quic_connid_is_valid_length)
{
  ASSERT (SocketQUICConnectionID_is_valid_length (0));
  ASSERT (SocketQUICConnectionID_is_valid_length (1));
  ASSERT (SocketQUICConnectionID_is_valid_length (20));
  ASSERT (!SocketQUICConnectionID_is_valid_length (21));
  ASSERT (!SocketQUICConnectionID_is_valid_length (100));
}

TEST (quic_connid_to_hex)
{
  SocketQUICConnectionID_T cid;
  const uint8_t data[] = { 0xAB, 0xCD, 0xEF };
  char buf[20];

  SocketQUICConnectionID_set (&cid, data, 3);

  int n = SocketQUICConnectionID_to_hex (&cid, buf, sizeof (buf));

  ASSERT (n > 0);
  ASSERT (strcmp (buf, "ab:cd:ef") == 0);
}

TEST (quic_connid_to_hex_empty)
{
  SocketQUICConnectionID_T cid;
  char buf[20];

  SocketQUICConnectionID_set (&cid, NULL, 0);

  int n = SocketQUICConnectionID_to_hex (&cid, buf, sizeof (buf));

  ASSERT (n > 0);
  ASSERT (strcmp (buf, "empty") == 0);
}

TEST (quic_connid_to_hex_buffer_small)
{
  SocketQUICConnectionID_T cid;
  char buf[3];

  SocketQUICConnectionID_generate (&cid, 8);

  int n = SocketQUICConnectionID_to_hex (&cid, buf, sizeof (buf));

  ASSERT_EQ (n, -1);
}

TEST (quic_connid_result_string)
{
  ASSERT (strcmp (SocketQUICConnectionID_result_string (QUIC_CONNID_OK), "OK")
          == 0);
  ASSERT (strstr (SocketQUICConnectionID_result_string (QUIC_CONNID_ERROR_NULL),
                  "NULL")
          != NULL);
  ASSERT (
      strstr (SocketQUICConnectionID_result_string (QUIC_CONNID_ERROR_LENGTH),
              "length")
      != NULL);
}

/* ============================================================================
 * Round-Trip Tests
 * ============================================================================
 */

TEST (quic_connid_encode_decode_roundtrip)
{
  SocketQUICConnectionID_T original, decoded;
  uint8_t buf[25];
  size_t consumed;

  SocketQUICConnectionID_generate (&original, 12);

  size_t encoded = SocketQUICConnectionID_encode_with_length (&original, buf,
                                                              sizeof (buf));
  ASSERT (encoded > 0);

  SocketQUICConnectionID_Result res
      = SocketQUICConnectionID_decode (buf, encoded, &decoded, &consumed);

  ASSERT_EQ (res, QUIC_CONNID_OK);
  ASSERT_EQ (consumed, encoded);
  ASSERT (SocketQUICConnectionID_equal (&original, &decoded));
}

TEST (quic_connid_roundtrip_all_lengths)
{
  for (size_t len = 0; len <= 20; len++)
    {
      SocketQUICConnectionID_T original, decoded;
      uint8_t buf[25];
      size_t consumed;

      SocketQUICConnectionID_generate (&original, len);

      size_t encoded = SocketQUICConnectionID_encode_with_length (&original, buf,
                                                                  sizeof (buf));

      SocketQUICConnectionID_Result res
          = SocketQUICConnectionID_decode (buf, encoded, &decoded, &consumed);

      ASSERT_EQ (res, QUIC_CONNID_OK);
      ASSERT (SocketQUICConnectionID_equal (&original, &decoded));
    }
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

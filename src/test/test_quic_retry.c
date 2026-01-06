/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_retry.c - QUIC Retry Packet Integrity Tests (RFC 9001 §5.8)
 *
 * Tests Retry packet integrity tag computation and verification.
 * Uses official test vectors from RFC 9001 Appendix A.4.
 */

#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICPacket.h"
#include "test/Test.h"

/* ============================================================================
 * RFC 9001 Appendix A.4 Test Vector
 *
 * Original Destination Connection ID (client DCID):
 *   0x8394c8f03e515708
 *
 * Complete Retry packet (36 bytes):
 *   ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba
 *
 * Breakdown:
 *   ff                 - First byte (Long header, Retry type)
 *   00000001           - Version (QUIC v1)
 *   00                 - DCID Length (0)
 *   08                 - SCID Length (8)
 *   f067a5502a4262b5   - SCID
 *   746f6b656e         - Retry Token ("token")
 *   04a265ba2eff4d829058fb3f0f2496ba - Integrity Tag (16 bytes)
 *
 * Packet without tag (20 bytes):
 *   ff000000010008f067a5502a4262b5746f6b656e
 * ============================================================================
 */

/* Client's Original Destination Connection ID */
static const uint8_t RFC_ODCID[]
    = { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

/* Complete Retry packet with integrity tag */
static const uint8_t RFC_RETRY_PACKET[] = { 0xff, /* First byte */
                                            0x00,
                                            0x00,
                                            0x00,
                                            0x01, /* Version: QUIC v1 */
                                            0x00, /* DCID Length: 0 */
                                            0x08, /* SCID Length: 8 */
                                            0xf0,
                                            0x67,
                                            0xa5,
                                            0x50,
                                            0x2a,
                                            0x42,
                                            0x62,
                                            0xb5, /* SCID */
                                            0x74,
                                            0x6f,
                                            0x6b,
                                            0x65,
                                            0x6e, /* Retry Token: "token" */
                                            /* Integrity Tag (16 bytes) */
                                            0x04,
                                            0xa2,
                                            0x65,
                                            0xba,
                                            0x2e,
                                            0xff,
                                            0x4d,
                                            0x82,
                                            0x90,
                                            0x58,
                                            0xfb,
                                            0x3f,
                                            0x0f,
                                            0x24,
                                            0x96,
                                            0xba };

/* Expected integrity tag */
static const uint8_t RFC_EXPECTED_TAG[]
    = { 0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82,
        0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba };

/* Retry packet without integrity tag (for compute_retry_tag) */
static const uint8_t RFC_RETRY_PACKET_NO_TAG[] = {
  0xff,                                           /* First byte */
  0x00, 0x00, 0x00, 0x01,                         /* Version: QUIC v1 */
  0x00,                                           /* DCID Length: 0 */
  0x08,                                           /* SCID Length: 8 */
  0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, /* SCID */
  0x74, 0x6f, 0x6b, 0x65, 0x6e                    /* Retry Token: "token" */
};

/* ============================================================================
 * RFC Test Vector Tests
 * ============================================================================
 */

TEST (quic_retry_tag_rfc_test_vector_compute)
{
  SocketQUICConnectionID_T odcid;
  uint8_t computed_tag[QUIC_RETRY_INTEGRITY_TAG_LEN];
  SocketQUICPacket_Result result;

  /* Setup ODCID from RFC test vector */
  SocketQUICConnectionID_init (&odcid);
  odcid.len = sizeof (RFC_ODCID);
  memcpy (odcid.data, RFC_ODCID, sizeof (RFC_ODCID));

  /* Compute the tag */
  result = SocketQUICPacket_compute_retry_tag (&odcid,
                                               RFC_RETRY_PACKET_NO_TAG,
                                               sizeof (RFC_RETRY_PACKET_NO_TAG),
                                               computed_tag);

  ASSERT_EQ (result, QUIC_PACKET_OK);
  ASSERT_EQ (
      memcmp (computed_tag, RFC_EXPECTED_TAG, QUIC_RETRY_INTEGRITY_TAG_LEN), 0);
}

TEST (quic_retry_tag_rfc_test_vector_verify)
{
  SocketQUICConnectionID_T odcid;
  SocketQUICPacket_Result result;

  /* Setup ODCID from RFC test vector */
  SocketQUICConnectionID_init (&odcid);
  odcid.len = sizeof (RFC_ODCID);
  memcpy (odcid.data, RFC_ODCID, sizeof (RFC_ODCID));

  /* Verify the complete packet */
  result = SocketQUICPacket_verify_retry_tag (
      &odcid, RFC_RETRY_PACKET, sizeof (RFC_RETRY_PACKET));

  ASSERT_EQ (result, QUIC_PACKET_OK);
}

/* ============================================================================
 * Basic Functionality Tests
 * ============================================================================
 */

TEST (quic_retry_tag_compute_basic)
{
  SocketQUICConnectionID_T odcid;
  uint8_t tag1[QUIC_RETRY_INTEGRITY_TAG_LEN];
  uint8_t tag2[QUIC_RETRY_INTEGRITY_TAG_LEN];
  SocketQUICPacket_Result result;

  /* Simple Retry packet structure */
  uint8_t retry_packet[] = {
    0xff,                   /* First byte */
    0x00, 0x00, 0x00, 0x01, /* Version */
    0x00,                   /* DCID len */
    0x04,                   /* SCID len */
    0x01, 0x02, 0x03, 0x04, /* SCID */
    0xAA, 0xBB, 0xCC, 0xDD  /* Token */
  };

  /* Setup ODCID */
  SocketQUICConnectionID_init (&odcid);
  odcid.len = 4;
  odcid.data[0] = 0xDE;
  odcid.data[1] = 0xAD;
  odcid.data[2] = 0xBE;
  odcid.data[3] = 0xEF;

  /* Compute tag twice - should be deterministic */
  result = SocketQUICPacket_compute_retry_tag (
      &odcid, retry_packet, sizeof (retry_packet), tag1);
  ASSERT_EQ (result, QUIC_PACKET_OK);

  result = SocketQUICPacket_compute_retry_tag (
      &odcid, retry_packet, sizeof (retry_packet), tag2);
  ASSERT_EQ (result, QUIC_PACKET_OK);

  /* Tags should be identical */
  ASSERT_EQ (memcmp (tag1, tag2, QUIC_RETRY_INTEGRITY_TAG_LEN), 0);
}

TEST (quic_retry_tag_verify_invalid)
{
  SocketQUICConnectionID_T odcid;
  SocketQUICPacket_Result result;

  /* Copy RFC packet and corrupt the tag */
  uint8_t corrupted_packet[sizeof (RFC_RETRY_PACKET)];
  memcpy (corrupted_packet, RFC_RETRY_PACKET, sizeof (RFC_RETRY_PACKET));

  /* Corrupt last byte of tag */
  corrupted_packet[sizeof (corrupted_packet) - 1] ^= 0xFF;

  /* Setup ODCID */
  SocketQUICConnectionID_init (&odcid);
  odcid.len = sizeof (RFC_ODCID);
  memcpy (odcid.data, RFC_ODCID, sizeof (RFC_ODCID));

  /* Verification should fail */
  result = SocketQUICPacket_verify_retry_tag (
      &odcid, corrupted_packet, sizeof (corrupted_packet));
  ASSERT_EQ (result, QUIC_PACKET_ERROR_INVALID);
}

/* ============================================================================
 * Edge Case Tests
 * ============================================================================
 */

TEST (quic_retry_tag_null_params)
{
  SocketQUICConnectionID_T odcid;
  uint8_t tag[QUIC_RETRY_INTEGRITY_TAG_LEN];
  uint8_t packet[20] = { 0 };
  SocketQUICPacket_Result result;

  SocketQUICConnectionID_init (&odcid);
  odcid.len = 4;

  /* NULL odcid */
  result
      = SocketQUICPacket_compute_retry_tag (NULL, packet, sizeof (packet), tag);
  ASSERT_EQ (result, QUIC_PACKET_ERROR_NULL);

  /* NULL packet */
  result = SocketQUICPacket_compute_retry_tag (&odcid, NULL, 20, tag);
  ASSERT_EQ (result, QUIC_PACKET_ERROR_NULL);

  /* NULL tag */
  result = SocketQUICPacket_compute_retry_tag (
      &odcid, packet, sizeof (packet), NULL);
  ASSERT_EQ (result, QUIC_PACKET_ERROR_NULL);

  /* NULL odcid for verify */
  result = SocketQUICPacket_verify_retry_tag (NULL, packet, sizeof (packet));
  ASSERT_EQ (result, QUIC_PACKET_ERROR_NULL);

  /* NULL packet for verify */
  result = SocketQUICPacket_verify_retry_tag (&odcid, NULL, 20);
  ASSERT_EQ (result, QUIC_PACKET_ERROR_NULL);
}

TEST (quic_retry_tag_empty_odcid)
{
  SocketQUICConnectionID_T odcid;
  uint8_t tag[QUIC_RETRY_INTEGRITY_TAG_LEN];
  SocketQUICPacket_Result result;

  /* Retry packet */
  uint8_t packet[] = {
    0xff,                   /* First byte */
    0x00, 0x00, 0x00, 0x01, /* Version */
    0x00,                   /* DCID len */
    0x04,                   /* SCID len */
    0x01, 0x02, 0x03, 0x04  /* SCID */
  };

  /* Zero-length ODCID is valid per RFC */
  SocketQUICConnectionID_init (&odcid);
  odcid.len = 0;

  result = SocketQUICPacket_compute_retry_tag (
      &odcid, packet, sizeof (packet), tag);
  ASSERT_EQ (result, QUIC_PACKET_OK);
}

TEST (quic_retry_tag_max_odcid)
{
  SocketQUICConnectionID_T odcid;
  uint8_t tag[QUIC_RETRY_INTEGRITY_TAG_LEN];
  SocketQUICPacket_Result result;

  /* Retry packet */
  uint8_t packet[] = {
    0xff,                   /* First byte */
    0x00, 0x00, 0x00, 0x01, /* Version */
    0x00,                   /* DCID len */
    0x04,                   /* SCID len */
    0x01, 0x02, 0x03, 0x04  /* SCID */
  };

  /* Maximum ODCID (20 bytes) */
  SocketQUICConnectionID_init (&odcid);
  odcid.len = QUIC_CONNID_MAX_LEN;
  for (uint8_t i = 0; i < QUIC_CONNID_MAX_LEN; i++)
    odcid.data[i] = i;

  result = SocketQUICPacket_compute_retry_tag (
      &odcid, packet, sizeof (packet), tag);
  ASSERT_EQ (result, QUIC_PACKET_OK);
}

TEST (quic_retry_tag_short_packet)
{
  SocketQUICConnectionID_T odcid;
  SocketQUICPacket_Result result;

  /* Packet too short to contain integrity tag */
  uint8_t short_packet[QUIC_RETRY_INTEGRITY_TAG_LEN - 1] = { 0 };

  SocketQUICConnectionID_init (&odcid);
  odcid.len = 4;
  odcid.data[0] = 0x01;

  result = SocketQUICPacket_verify_retry_tag (
      &odcid, short_packet, sizeof (short_packet));
  ASSERT_EQ (result, QUIC_PACKET_ERROR_TRUNCATED);
}

TEST (quic_retry_tag_different_odcid_different_tag)
{
  SocketQUICConnectionID_T odcid1, odcid2;
  uint8_t tag1[QUIC_RETRY_INTEGRITY_TAG_LEN];
  uint8_t tag2[QUIC_RETRY_INTEGRITY_TAG_LEN];
  SocketQUICPacket_Result result;

  /* Same retry packet */
  uint8_t packet[] = {
    0xff,                   /* First byte */
    0x00, 0x00, 0x00, 0x01, /* Version */
    0x00,                   /* DCID len */
    0x04,                   /* SCID len */
    0x01, 0x02, 0x03, 0x04  /* SCID */
  };

  /* Two different ODCIDs */
  SocketQUICConnectionID_init (&odcid1);
  odcid1.len = 4;
  memset (odcid1.data, 0xAA, 4);

  SocketQUICConnectionID_init (&odcid2);
  odcid2.len = 4;
  memset (odcid2.data, 0xBB, 4);

  /* Compute tags with different ODCIDs */
  result = SocketQUICPacket_compute_retry_tag (
      &odcid1, packet, sizeof (packet), tag1);
  ASSERT_EQ (result, QUIC_PACKET_OK);

  result = SocketQUICPacket_compute_retry_tag (
      &odcid2, packet, sizeof (packet), tag2);
  ASSERT_EQ (result, QUIC_PACKET_OK);

  /* Tags should be different */
  int tags_equal = (memcmp (tag1, tag2, QUIC_RETRY_INTEGRITY_TAG_LEN) == 0);
  ASSERT_EQ (tags_equal, 0);
}

TEST (quic_retry_tag_compute_then_verify)
{
  SocketQUICConnectionID_T odcid;
  uint8_t tag[QUIC_RETRY_INTEGRITY_TAG_LEN];
  SocketQUICPacket_Result result;

  /* Retry packet without tag */
  uint8_t packet_no_tag[] = {
    0xff,                   /* First byte */
    0x00, 0x00, 0x00, 0x01, /* Version */
    0x00,                   /* DCID len */
    0x04,                   /* SCID len */
    0x01, 0x02, 0x03, 0x04, /* SCID */
    0xDE, 0xAD, 0xBE, 0xEF  /* Token */
  };

  /* Full packet with space for tag */
  uint8_t full_packet[sizeof (packet_no_tag) + QUIC_RETRY_INTEGRITY_TAG_LEN];

  SocketQUICConnectionID_init (&odcid);
  odcid.len = 8;
  for (uint8_t i = 0; i < 8; i++)
    odcid.data[i] = i + 0x10;

  /* Compute tag */
  result = SocketQUICPacket_compute_retry_tag (
      &odcid, packet_no_tag, sizeof (packet_no_tag), tag);
  ASSERT_EQ (result, QUIC_PACKET_OK);

  /* Build complete packet */
  memcpy (full_packet, packet_no_tag, sizeof (packet_no_tag));
  memcpy (
      full_packet + sizeof (packet_no_tag), tag, QUIC_RETRY_INTEGRITY_TAG_LEN);

  /* Verify should pass */
  result = SocketQUICPacket_verify_retry_tag (
      &odcid, full_packet, sizeof (full_packet));
  ASSERT_EQ (result, QUIC_PACKET_OK);
}

/* ============================================================================
 * Boundary Condition Tests
 * ============================================================================
 */

TEST (quic_retry_tag_packet_at_max_size)
{
  SocketQUICConnectionID_T odcid;
  uint8_t tag[QUIC_RETRY_INTEGRITY_TAG_LEN];
  SocketQUICPacket_Result result;

  /* Create a packet exactly at the 1500 byte limit */
  uint8_t large_packet[1500];
  memset (large_packet, 0xAB, sizeof (large_packet));

  /* Set valid header structure */
  large_packet[0] = 0xff; /* Long header, Retry type */
  large_packet[1] = 0x00;
  large_packet[2] = 0x00;
  large_packet[3] = 0x00;
  large_packet[4] = 0x01; /* Version */
  large_packet[5] = 0x00; /* DCID len */
  large_packet[6] = 0x04; /* SCID len */

  SocketQUICConnectionID_init (&odcid);
  odcid.len = 8;
  memset (odcid.data, 0x42, 8);

  /* Should succeed at exactly 1500 bytes */
  result = SocketQUICPacket_compute_retry_tag (
      &odcid, large_packet, sizeof (large_packet), tag);
  ASSERT_EQ (result, QUIC_PACKET_OK);
}

TEST (quic_retry_tag_packet_exceeds_max_size)
{
  SocketQUICConnectionID_T odcid;
  uint8_t tag[QUIC_RETRY_INTEGRITY_TAG_LEN];
  SocketQUICPacket_Result result;

  /* Create a packet that exceeds 1500 byte limit */
  uint8_t oversized_packet[1501];
  memset (oversized_packet, 0xAB, sizeof (oversized_packet));

  SocketQUICConnectionID_init (&odcid);
  odcid.len = 4;

  /* Should fail with buffer error */
  result = SocketQUICPacket_compute_retry_tag (
      &odcid, oversized_packet, sizeof (oversized_packet), tag);
  ASSERT_EQ (result, QUIC_PACKET_ERROR_BUFFER);
}

TEST (quic_retry_tag_packet_exactly_tag_size)
{
  SocketQUICConnectionID_T odcid;
  SocketQUICPacket_Result result;

  /* Packet exactly 16 bytes (tag size) - minimal valid for verify */
  uint8_t minimal_packet[QUIC_RETRY_INTEGRITY_TAG_LEN];
  memset (minimal_packet, 0x00, sizeof (minimal_packet));

  SocketQUICConnectionID_init (&odcid);
  odcid.len = 4;
  memset (odcid.data, 0x11, 4);

  /* Verify with 16-byte packet means 0-byte payload + 16-byte tag */
  /* This should work (verification will fail due to wrong tag, but no crash) */
  result = SocketQUICPacket_verify_retry_tag (
      &odcid, minimal_packet, sizeof (minimal_packet));

  /* Tag won't match, so should return INVALID */
  ASSERT_EQ (result, QUIC_PACKET_ERROR_INVALID);
}

TEST (quic_retry_tag_wrong_odcid_verification)
{
  SocketQUICConnectionID_T correct_odcid;
  SocketQUICConnectionID_T wrong_odcid;
  SocketQUICPacket_Result result;

  /* Use RFC test vector packet with correct tag */
  /* But verify with wrong ODCID - should fail */

  SocketQUICConnectionID_init (&correct_odcid);
  correct_odcid.len = sizeof (RFC_ODCID);
  memcpy (correct_odcid.data, RFC_ODCID, sizeof (RFC_ODCID));

  /* Create wrong ODCID (different from RFC vector) */
  SocketQUICConnectionID_init (&wrong_odcid);
  wrong_odcid.len = sizeof (RFC_ODCID);
  memset (wrong_odcid.data, 0xFF, sizeof (RFC_ODCID)); /* All 0xFF */

  /* Verify with correct ODCID should pass */
  result = SocketQUICPacket_verify_retry_tag (
      &correct_odcid, RFC_RETRY_PACKET, sizeof (RFC_RETRY_PACKET));
  ASSERT_EQ (result, QUIC_PACKET_OK);

  /* Verify with wrong ODCID should fail */
  result = SocketQUICPacket_verify_retry_tag (
      &wrong_odcid, RFC_RETRY_PACKET, sizeof (RFC_RETRY_PACKET));
  ASSERT_EQ (result, QUIC_PACKET_ERROR_INVALID);
}

TEST (quic_retry_tag_single_bit_flip_in_tag)
{
  SocketQUICConnectionID_T odcid;
  SocketQUICPacket_Result result;

  /* Copy RFC packet */
  uint8_t packet[sizeof (RFC_RETRY_PACKET)];
  memcpy (packet, RFC_RETRY_PACKET, sizeof (RFC_RETRY_PACKET));

  SocketQUICConnectionID_init (&odcid);
  odcid.len = sizeof (RFC_ODCID);
  memcpy (odcid.data, RFC_ODCID, sizeof (RFC_ODCID));

  /* Verify original is valid */
  result = SocketQUICPacket_verify_retry_tag (&odcid, packet, sizeof (packet));
  ASSERT_EQ (result, QUIC_PACKET_OK);

  /* Flip single bit in tag (first byte of tag, bit 0) */
  packet[sizeof (packet) - QUIC_RETRY_INTEGRITY_TAG_LEN] ^= 0x01;

  /* Should now fail */
  result = SocketQUICPacket_verify_retry_tag (&odcid, packet, sizeof (packet));
  ASSERT_EQ (result, QUIC_PACKET_ERROR_INVALID);
}

TEST (quic_retry_tag_single_bit_flip_in_packet_body)
{
  SocketQUICConnectionID_T odcid;
  SocketQUICPacket_Result result;

  /* Copy RFC packet */
  uint8_t packet[sizeof (RFC_RETRY_PACKET)];
  memcpy (packet, RFC_RETRY_PACKET, sizeof (RFC_RETRY_PACKET));

  SocketQUICConnectionID_init (&odcid);
  odcid.len = sizeof (RFC_ODCID);
  memcpy (odcid.data, RFC_ODCID, sizeof (RFC_ODCID));

  /* Verify original is valid */
  result = SocketQUICPacket_verify_retry_tag (&odcid, packet, sizeof (packet));
  ASSERT_EQ (result, QUIC_PACKET_OK);

  /* Flip single bit in packet body (version byte, bit 0) */
  packet[1] ^= 0x01;

  /* Should now fail - tag was computed over original data */
  result = SocketQUICPacket_verify_retry_tag (&odcid, packet, sizeof (packet));
  ASSERT_EQ (result, QUIC_PACKET_ERROR_INVALID);
}

TEST (quic_retry_tag_single_bit_flip_in_retry_token)
{
  SocketQUICConnectionID_T odcid;
  SocketQUICPacket_Result result;

  /* Copy RFC packet */
  uint8_t packet[sizeof (RFC_RETRY_PACKET)];
  memcpy (packet, RFC_RETRY_PACKET, sizeof (RFC_RETRY_PACKET));

  SocketQUICConnectionID_init (&odcid);
  odcid.len = sizeof (RFC_ODCID);
  memcpy (odcid.data, RFC_ODCID, sizeof (RFC_ODCID));

  /* Flip bit in Retry Token ("token" starts at offset 15) */
  packet[15] ^= 0x01;

  /* Should fail */
  result = SocketQUICPacket_verify_retry_tag (&odcid, packet, sizeof (packet));
  ASSERT_EQ (result, QUIC_PACKET_ERROR_INVALID);
}

TEST (quic_retry_tag_all_zeros_packet)
{
  SocketQUICConnectionID_T odcid;
  uint8_t tag[QUIC_RETRY_INTEGRITY_TAG_LEN];
  SocketQUICPacket_Result result;

  /* All zeros packet */
  uint8_t zeros[64] = { 0 };

  SocketQUICConnectionID_init (&odcid);
  odcid.len = 0; /* Empty ODCID */

  /* Should compute successfully (even if packet is malformed) */
  result
      = SocketQUICPacket_compute_retry_tag (&odcid, zeros, sizeof (zeros), tag);
  ASSERT_EQ (result, QUIC_PACKET_OK);

  /* Tag should not be all zeros (AEAD output is pseudorandom) */
  int all_zeros = 1;
  for (int i = 0; i < QUIC_RETRY_INTEGRITY_TAG_LEN; i++)
    {
      if (tag[i] != 0)
        {
          all_zeros = 0;
          break;
        }
    }
  ASSERT_EQ (all_zeros, 0);
}

TEST (quic_retry_tag_empty_packet)
{
  SocketQUICConnectionID_T odcid;
  uint8_t tag[QUIC_RETRY_INTEGRITY_TAG_LEN];
  SocketQUICPacket_Result result;

  SocketQUICConnectionID_init (&odcid);
  odcid.len = 4;
  memset (odcid.data, 0xAA, 4);

  /* Empty packet (0 bytes) - should still work for compute */
  uint8_t empty_packet[1] = { 0 }; /* Need at least 1 byte for valid pointer */

  result = SocketQUICPacket_compute_retry_tag (&odcid, empty_packet, 0, tag);
  ASSERT_EQ (result, QUIC_PACKET_OK);
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

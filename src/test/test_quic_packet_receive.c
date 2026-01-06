/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_packet_receive.c - QUIC packet reception unit tests
 *
 * Tests for RFC 9001 Section 5.5 packet reception and
 * RFC 9000 Appendix A packet number decoding.
 */

#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICPacket.h"
#include "quic/SocketQUICCrypto.h"
#include "quic/SocketQUICConstants.h"
#include "test/Test.h"

/* ============================================================================
 * Packet Number Decoding Tests (RFC 9000 Appendix A)
 * ============================================================================
 */

/**
 * Test basic PN decoding with 1-byte truncated PN.
 * Window size = 256, half window = 128.
 */
TEST (quic_pn_decode_1byte_basic)
{
  /* First packet: truncated_pn=0, largest=0, expect full_pn=0 */
  uint64_t pn = SocketQUICPacket_decode_pn (0, 1, 0);
  ASSERT_EQ (pn, 0ULL);

  /* Second packet: truncated_pn=1, largest=0, expect full_pn=1 */
  pn = SocketQUICPacket_decode_pn (1, 1, 0);
  ASSERT_EQ (pn, 1ULL);

  /* Normal sequence: truncated_pn=5, largest=4, expect full_pn=5 */
  pn = SocketQUICPacket_decode_pn (5, 1, 4);
  ASSERT_EQ (pn, 5ULL);
}

/**
 * Test 1-byte PN decoding with window wrap-around.
 * When truncated_pn < expected_pn and difference > half_window,
 * we need to add pn_win to candidate.
 */
TEST (quic_pn_decode_1byte_wrap_forward)
{
  /*
   * Scenario: largest_pn = 255, truncated_pn = 1
   * expected_pn = 256, pn_win = 256, pn_hwin = 128
   * candidate = (256 & ~0xFF) | 1 = 256 | 1 = 257
   * candidate (257) is within expected_pn (256) + pn_hwin (128), so no adjust
   * Result: 257
   */
  uint64_t pn = SocketQUICPacket_decode_pn (1, 1, 255);
  ASSERT_EQ (pn, 257ULL);
}

/**
 * Test 1-byte PN decoding with backward wrap.
 * When candidate > expected_pn + half_window, subtract pn_win.
 */
TEST (quic_pn_decode_1byte_wrap_backward)
{
  /*
   * Scenario: largest_pn = 256, truncated_pn = 255
   * expected_pn = 257, pn_win = 256, pn_hwin = 128
   * candidate = (257 & ~0xFF) | 255 = 256 | 255 = 511
   * 511 > 257 + 128 (385), and 511 >= 256
   * So subtract: 511 - 256 = 255
   * Result: 255
   */
  uint64_t pn = SocketQUICPacket_decode_pn (255, 1, 256);
  ASSERT_EQ (pn, 255ULL);
}

/**
 * Test 2-byte PN decoding.
 * Window size = 65536, half window = 32768.
 */
TEST (quic_pn_decode_2byte_basic)
{
  /* Simple case: truncated_pn=1000, largest=999, expect 1000 */
  uint64_t pn = SocketQUICPacket_decode_pn (1000, 2, 999);
  ASSERT_EQ (pn, 1000ULL);

  /* Large value: truncated_pn=0xABCD, largest=0xABCC */
  pn = SocketQUICPacket_decode_pn (0xABCD, 2, 0xABCC);
  ASSERT_EQ (pn, 0xABCDULL);
}

/**
 * Test 2-byte PN decoding with wrap-around at 64K boundary.
 */
TEST (quic_pn_decode_2byte_wrap)
{
  /*
   * Scenario: largest_pn = 0xFFFF (65535), truncated_pn = 0x0001
   * expected_pn = 0x10000, pn_win = 0x10000, pn_hwin = 0x8000
   * candidate = (0x10000 & ~0xFFFF) | 0x0001 = 0x10000 | 1 = 0x10001
   * Result: 0x10001 (65537)
   */
  uint64_t pn = SocketQUICPacket_decode_pn (0x0001, 2, 0xFFFF);
  ASSERT_EQ (pn, 0x10001ULL);
}

/**
 * Test 4-byte PN decoding (full 32-bit truncated PN).
 * This is the maximum truncated PN size in QUIC.
 */
TEST (quic_pn_decode_4byte_basic)
{
  /* Simple case */
  uint64_t pn = SocketQUICPacket_decode_pn (0x12345678, 4, 0x12345677);
  ASSERT_EQ (pn, 0x12345678ULL);

  /* Large 64-bit result */
  pn = SocketQUICPacket_decode_pn (0x00000001, 4, 0xFFFFFFFF);
  ASSERT_EQ (pn, 0x100000001ULL);
}

/**
 * Test invalid pn_length values.
 */
TEST (quic_pn_decode_invalid_length)
{
  /* pn_length = 0 should return 0 */
  uint64_t pn = SocketQUICPacket_decode_pn (100, 0, 50);
  ASSERT_EQ (pn, 0ULL);

  /* pn_length = 5 should return 0 */
  pn = SocketQUICPacket_decode_pn (100, 5, 50);
  ASSERT_EQ (pn, 0ULL);
}

/**
 * Test out-of-order packet reception.
 * Per RFC 9001 §5.7, packets may arrive out of order.
 */
TEST (quic_pn_decode_out_of_order)
{
  /*
   * Scenario: Received packets 0, 1, 2, 5 (skipped 3, 4)
   * largest_pn = 5, now receive truncated_pn = 3
   * expected_pn = 6, candidate = 3
   * 3 < 6 - 128, so... wait, with 1-byte PN, half_window = 128
   * 3 is within expected_pn - pn_hwin (6 - 128 < 0, so ~0)
   * Result should be 3
   */
  uint64_t pn = SocketQUICPacket_decode_pn (3, 1, 5);
  ASSERT_EQ (pn, 3ULL);

  /* Receive packet 4 */
  pn = SocketQUICPacket_decode_pn (4, 1, 5);
  ASSERT_EQ (pn, 4ULL);
}

/**
 * Test 3-byte PN decoding.
 * Window size = 16777216 (2^24), half window = 8388608.
 */
TEST (quic_pn_decode_3byte_basic)
{
  /* Simple case */
  uint64_t pn = SocketQUICPacket_decode_pn (0x123456, 3, 0x123455);
  ASSERT_EQ (pn, 0x123456ULL);

  /* Wrap at 16M boundary */
  pn = SocketQUICPacket_decode_pn (0x000001, 3, 0xFFFFFF);
  ASSERT_EQ (pn, 0x1000001ULL);
}

/**
 * Test 3-byte PN decoding with backward wrap.
 */
TEST (quic_pn_decode_3byte_wrap_backward)
{
  /*
   * Scenario: largest_pn = 0x1000000 (16777216), truncated_pn = 0xFFFFFF
   * expected_pn = 0x1000001, pn_win = 0x1000000, pn_hwin = 0x800000
   * candidate = (0x1000001 & ~0xFFFFFF) | 0xFFFFFF = 0x1000000 | 0xFFFFFF = 0x1FFFFFF
   * 0x1FFFFFF > 0x1000001 + 0x800000 (0x1800001), so subtract pn_win
   * Result: 0xFFFFFF
   */
  uint64_t pn = SocketQUICPacket_decode_pn (0xFFFFFF, 3, 0x1000000);
  ASSERT_EQ (pn, 0xFFFFFFULL);
}

/**
 * Test PN decoding with large packet numbers.
 * Verify 4-byte encoding handles large values correctly.
 */
TEST (quic_pn_decode_large_pn)
{
  /* Large PN values with 4-byte encoding */
  uint64_t pn;

  /* Simple increment at large value */
  pn = SocketQUICPacket_decode_pn (0x80000001, 4, 0x80000000);
  ASSERT_EQ (pn, 0x80000001ULL);

  /* Wrap at 4-byte boundary */
  pn = SocketQUICPacket_decode_pn (0x00000001, 4, 0xFFFFFFFF);
  ASSERT_EQ (pn, 0x100000001ULL);

  /* Value near 2^32 - 1 */
  pn = SocketQUICPacket_decode_pn (0xFFFFFFFF, 4, 0xFFFFFFFE);
  ASSERT_EQ (pn, 0xFFFFFFFFULL);

  /* Multi-billion PN (common in long-lived connections) */
  pn = SocketQUICPacket_decode_pn (0x12345678, 4, 0x112345677);
  ASSERT_EQ (pn, 0x112345678ULL);
}

/**
 * Test PN decoding with largest_pn = 0 (first packet).
 */
TEST (quic_pn_decode_first_packet)
{
  /* First packet ever, all PN lengths */
  ASSERT_EQ (SocketQUICPacket_decode_pn (0, 1, 0), 0ULL);
  ASSERT_EQ (SocketQUICPacket_decode_pn (0, 2, 0), 0ULL);
  ASSERT_EQ (SocketQUICPacket_decode_pn (0, 3, 0), 0ULL);
  ASSERT_EQ (SocketQUICPacket_decode_pn (0, 4, 0), 0ULL);

  /* Non-zero first PN */
  ASSERT_EQ (SocketQUICPacket_decode_pn (42, 1, 0), 42ULL);
  ASSERT_EQ (SocketQUICPacket_decode_pn (1000, 2, 0), 1000ULL);
}

/* ============================================================================
 * Receive Context Tests
 * ============================================================================
 */

/**
 * Test receive context initialization.
 */
TEST (quic_receive_init_zeros_state)
{
  SocketQUICReceive_T ctx;

  /* Fill with garbage first */
  memset (&ctx, 0xFF, sizeof (ctx));

  SocketQUICReceive_init (&ctx);

  /* Verify initialization */
  ASSERT_EQ (ctx.initialized, 1);
  ASSERT_EQ (ctx.decryption_failures, 0ULL);
  ASSERT_NULL (ctx.initial_keys);
  ASSERT_NULL (ctx.handshake_keys);
  ASSERT_NULL (ctx.key_update);

  for (int i = 0; i < QUIC_PN_SPACE_COUNT; i++)
    {
      ASSERT_EQ (ctx.spaces[i].largest_pn, 0ULL);
      ASSERT_EQ (ctx.spaces[i].has_received, 0);
    }
}

/**
 * Test NULL pointer handling in init.
 */
TEST (quic_receive_init_null_safe)
{
  /* Should not crash */
  SocketQUICReceive_init (NULL);
}

/**
 * Test setting Initial keys.
 */
TEST (quic_receive_set_initial_keys)
{
  SocketQUICReceive_T ctx;
  SocketQUICInitialKeys_T keys;

  SocketQUICReceive_init (&ctx);
  SocketQUICInitialKeys_init (&keys);

  SocketQUICReceive_Result result
      = SocketQUICReceive_set_initial_keys (&ctx, &keys);

  ASSERT_EQ (result, QUIC_RECEIVE_OK);
  ASSERT_EQ (ctx.initial_keys, &keys);
}

/**
 * Test NULL pointer handling in key setters.
 */
TEST (quic_receive_set_keys_null)
{
  SocketQUICInitialKeys_T keys;
  SocketQUICInitialKeys_init (&keys);

  SocketQUICReceive_Result result
      = SocketQUICReceive_set_initial_keys (NULL, &keys);
  ASSERT_EQ (result, QUIC_RECEIVE_ERROR_NULL);
}

/**
 * Test get_largest_pn before any packets received.
 */
TEST (quic_receive_get_largest_pn_no_packets)
{
  SocketQUICReceive_T ctx;
  uint64_t pn;

  SocketQUICReceive_init (&ctx);

  /* Should return 0 (no packets received) */
  int result
      = SocketQUICReceive_get_largest_pn (&ctx, QUIC_PN_SPACE_INITIAL, &pn);
  ASSERT_EQ (result, 0);
}

/**
 * Test get_largest_pn with invalid space.
 */
TEST (quic_receive_get_largest_pn_invalid_space)
{
  SocketQUICReceive_T ctx;
  uint64_t pn;

  SocketQUICReceive_init (&ctx);

  /* Invalid space should return 0 */
  int result = SocketQUICReceive_get_largest_pn (&ctx, QUIC_PN_SPACE_COUNT, &pn);
  ASSERT_EQ (result, 0);

  result = SocketQUICReceive_get_largest_pn (&ctx, -1, &pn);
  ASSERT_EQ (result, 0);
}

/* ============================================================================
 * Result String Tests
 * ============================================================================
 */

/**
 * Test result string function returns valid strings.
 */
TEST (quic_receive_result_string_valid)
{
  const char *str;

  str = SocketQUICReceive_result_string (QUIC_RECEIVE_OK);
  ASSERT_NOT_NULL (str);
  ASSERT (strcmp (str, "OK") == 0);

  str = SocketQUICReceive_result_string (QUIC_RECEIVE_ERROR_NULL);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "NULL") != NULL);

  str = SocketQUICReceive_result_string (QUIC_RECEIVE_ERROR_DECRYPT);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "decrypt") != NULL);
}

/**
 * Test result string for invalid/unknown codes.
 */
TEST (quic_receive_result_string_unknown)
{
  const char *str = SocketQUICReceive_result_string (999);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Unknown") != NULL);
}

/* ============================================================================
 * Packet Reception Error Cases
 * ============================================================================
 */

/**
 * Test receive with NULL context.
 */
TEST (quic_receive_packet_null_ctx)
{
  uint8_t packet[100] = { 0 };
  SocketQUICReceiveResult_T result;

  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (NULL, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_NULL);
}

/**
 * Test receive with NULL packet.
 */
TEST (quic_receive_packet_null_packet)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  SocketQUICReceive_init (&ctx);

  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, NULL, 100, 8, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_NULL);
}

/**
 * Test receive with NULL result.
 */
TEST (quic_receive_packet_null_result)
{
  SocketQUICReceive_T ctx;
  uint8_t packet[100] = { 0 };

  SocketQUICReceive_init (&ctx);

  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, NULL);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_NULL);
}

/**
 * Test receive with uninitialized context.
 */
TEST (quic_receive_packet_uninitialized)
{
  SocketQUICReceive_T ctx;
  uint8_t packet[100] = { 0 };
  SocketQUICReceiveResult_T result;

  /* Zero out but don't call init */
  memset (&ctx, 0, sizeof (ctx));

  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_NULL);
}

/**
 * Test receive with empty packet.
 */
TEST (quic_receive_packet_empty)
{
  SocketQUICReceive_T ctx;
  uint8_t packet[1] = { 0 };
  SocketQUICReceiveResult_T result;

  SocketQUICReceive_init (&ctx);

  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, 0, 8, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_TRUNCATED);
}

/**
 * Test receive with long header but truncated packet.
 */
TEST (quic_receive_packet_truncated_long_header)
{
  SocketQUICReceive_T ctx;
  /* Long header flag set but only 5 bytes (need at least 7) */
  uint8_t packet[5] = { 0xC0, 0x00, 0x00, 0x00, 0x01 };
  SocketQUICReceiveResult_T result;

  SocketQUICReceive_init (&ctx);

  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_TRUNCATED);
}

/**
 * Test receive Initial packet without keys.
 */
TEST (quic_receive_initial_no_keys)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  /* Minimal Initial packet header:
   * 0xC0 = Long header, Initial type
   * Version = 0x00000001
   * DCID len = 8
   * DCID = 8 bytes
   * SCID len = 0
   * Token len = 0
   * Payload length = 2 (varint)
   * PN = 1 byte (protected)
   * Payload + tag = rest
   */
  uint8_t packet[100];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xC0; /* Long header, Initial */
  packet[1] = 0x00;
  packet[2] = 0x00;
  packet[3] = 0x00;
  packet[4] = 0x01;  /* Version 1 */
  packet[5] = 0x08;  /* DCID len = 8 */
  packet[14] = 0x00; /* SCID len = 0 */
  packet[15] = 0x10; /* Token len = 0 (varint) */

  SocketQUICReceive_init (&ctx);

  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_NO_KEYS);
}

/**
 * Test receive short header (1-RTT) without keys.
 */
TEST (quic_receive_1rtt_no_keys)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  /* Short header: first bit = 0 */
  uint8_t packet[100];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0x40; /* Short header */
  /* DCID follows (8 bytes) */
  /* PN follows (protected) */

  SocketQUICReceive_init (&ctx);

  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_NO_KEYS);
}

/* ============================================================================
 * Malformed Input Tests
 * ============================================================================
 */

/**
 * Test receive with oversized DCID in long header (> 20 bytes).
 */
TEST (quic_receive_oversized_dcid_long)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  uint8_t packet[100];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xC0;                /* Long header, Initial */
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01; /* Version 1 */
  packet[5] = 0x15;                   /* DCID len = 21 (invalid, max is 20) */

  SocketQUICReceive_init (&ctx);

  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_HEADER);
}

/**
 * Test receive with oversized SCID in long header.
 */
TEST (quic_receive_oversized_scid_long)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  uint8_t packet[100];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xC0;                /* Long header, Initial */
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01; /* Version 1 */
  packet[5] = 0x08;                   /* DCID len = 8 */
  /* DCID bytes 6-13 */
  packet[14] = 0x15;                  /* SCID len = 21 (invalid) */

  SocketQUICReceive_init (&ctx);

  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_HEADER);
}

/**
 * Test receive with oversized dcid_len for short header.
 */
TEST (quic_receive_oversized_dcid_short)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  uint8_t packet[100];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0x40; /* Short header */

  SocketQUICReceive_init (&ctx);

  /* dcid_len = 21, which exceeds QUIC_CONNID_MAX_LEN (20) */
  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 21, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_HEADER);
}

/**
 * Test receive with Retry packet type (not supported for protected receive).
 */
TEST (quic_receive_retry_packet)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  uint8_t packet[100];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xF0;                   /* Long header, Retry type (bits 4-5 = 11) */
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01; /* Version 1 */
  packet[5] = 0x08;                   /* DCID len */

  SocketQUICReceive_init (&ctx);

  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_HEADER);
}

/**
 * Test receive with DCID extending past packet boundary.
 */
TEST (quic_receive_dcid_past_boundary)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  uint8_t packet[10];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xC0;                   /* Long header */
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01; /* Version 1 */
  packet[5] = 0x14;                   /* DCID len = 20, but packet only 10 bytes */

  SocketQUICReceive_init (&ctx);

  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_HEADER);
}

/* ============================================================================
 * Edge Case Tests
 * ============================================================================
 */

/**
 * Test receive with zero-length DCID (valid per RFC 9000).
 */
TEST (quic_receive_zero_length_dcid)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  uint8_t packet[100];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xC0;                   /* Long header, Initial */
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01; /* Version 1 */
  packet[5] = 0x00;                   /* DCID len = 0 */
  packet[6] = 0x00;                   /* SCID len = 0 */
  packet[7] = 0x00;                   /* Token len = 0 (varint) */
  packet[8] = 0x10;                   /* Length = 16 (varint) */

  SocketQUICReceive_init (&ctx);

  /* No keys, but header parsing should succeed */
  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 0, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_NO_KEYS);
  ASSERT_EQ (result.dcid.len, 0);
  ASSERT_EQ (result.scid.len, 0);
}

/**
 * Test receive with maximum length connection IDs (20 bytes each).
 */
TEST (quic_receive_max_length_cids)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  uint8_t packet[100];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xC0;                   /* Long header, Initial */
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01; /* Version 1 */
  packet[5] = 0x14;                   /* DCID len = 20 (max) */
  /* DCID = 20 bytes at offset 6-25 */
  for (int i = 0; i < 20; i++)
    packet[6 + i] = (uint8_t)(i + 1);

  packet[26] = 0x14;                  /* SCID len = 20 (max) */
  /* SCID = 20 bytes at offset 27-46 */
  for (int i = 0; i < 20; i++)
    packet[27 + i] = (uint8_t)(i + 0x80);

  packet[47] = 0x00;                  /* Token len = 0 */
  packet[48] = 0x10;                  /* Length = 16 */

  SocketQUICReceive_init (&ctx);

  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 20, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_NO_KEYS);
  ASSERT_EQ (result.dcid.len, 20);
  ASSERT_EQ (result.scid.len, 20);

  /* Verify DCID content */
  for (int i = 0; i < 20; i++)
    ASSERT_EQ (result.dcid.data[i], (uint8_t)(i + 1));

  /* Verify SCID content */
  for (int i = 0; i < 20; i++)
    ASSERT_EQ (result.scid.data[i], (uint8_t)(i + 0x80));
}

/**
 * Test receive correctly identifies packet type.
 */
TEST (quic_receive_packet_type_identification)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  uint8_t packet[100];
  memset (packet, 0, sizeof (packet));

  SocketQUICReceive_init (&ctx);

  /* Initial (type = 0) */
  packet[0] = 0xC0;
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01;
  packet[5] = 0x08;
  packet[14] = 0x00;
  packet[15] = 0x10;
  SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (result.type, QUIC_PACKET_TYPE_INITIAL);
  ASSERT_EQ (result.pn_space, QUIC_PN_SPACE_INITIAL);

  /* 0-RTT (type = 1) */
  packet[0] = 0xD0;
  SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (result.type, QUIC_PACKET_TYPE_0RTT);
  ASSERT_EQ (result.pn_space, QUIC_PN_SPACE_APPLICATION);

  /* Handshake (type = 2) */
  packet[0] = 0xE0;
  SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (result.type, QUIC_PACKET_TYPE_HANDSHAKE);
  ASSERT_EQ (result.pn_space, QUIC_PN_SPACE_HANDSHAKE);

  /* Short header (1-RTT) */
  packet[0] = 0x40;
  SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (result.type, QUIC_PACKET_TYPE_1RTT);
  ASSERT_EQ (result.pn_space, QUIC_PN_SPACE_APPLICATION);
}

/**
 * Test short header spin bit extraction.
 */
TEST (quic_receive_spin_bit)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  uint8_t packet[100];
  memset (packet, 0, sizeof (packet));

  SocketQUICReceive_init (&ctx);

  /* Spin bit = 0 */
  packet[0] = 0x40;
  SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (result.spin_bit, 0);

  /* Spin bit = 1 (bit 5 set) */
  packet[0] = 0x60;
  SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (result.spin_bit, 1);
}

/* ============================================================================
 * Edge Case Tests: Token and VarInt
 * ============================================================================
 */

/**
 * Test receive Initial packet with large token (2-byte varint length).
 */
TEST (quic_receive_large_token_2byte_varint)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  /* Initial packet with 64-byte token (requires 2-byte varint: 0x40 | 64) */
  uint8_t packet[200];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xC0;                   /* Long header, Initial */
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01; /* Version 1 */
  packet[5] = 0x08;                   /* DCID len = 8 */
  /* DCID = 8 bytes at offset 6-13 */
  packet[14] = 0x00;                  /* SCID len = 0 */
  packet[15] = 0x40;                  /* Token len = 64 (2-byte varint: 0x40xx) */
  packet[16] = 0x40;                  /* 0x4040 = 64 */
  /* Token = 64 bytes at offset 17-80 */
  packet[81] = 0x10;                  /* Length = 16 (varint) */

  SocketQUICReceive_init (&ctx);

  /* Should parse header successfully (no keys = NO_KEYS error) */
  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_NO_KEYS);
  ASSERT_EQ (result.type, QUIC_PACKET_TYPE_INITIAL);
}

/**
 * Test receive Initial packet with very large token (4-byte varint length).
 */
TEST (quic_receive_large_token_4byte_varint)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  /* Token length = 16384 (requires 4-byte varint: 0x80 00 40 00) */
  /* This is impractical but tests the varint parser */
  uint8_t packet[100];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xC0;                   /* Long header, Initial */
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01; /* Version 1 */
  packet[5] = 0x00;                   /* DCID len = 0 */
  packet[6] = 0x00;                   /* SCID len = 0 */
  /* Token len = 16384 using 4-byte varint: 0x80004000 */
  packet[7] = 0x80;
  packet[8] = 0x00;
  packet[9] = 0x40;
  packet[10] = 0x00;

  SocketQUICReceive_init (&ctx);

  /* Token extends past packet boundary -> HEADER error */
  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 0, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_HEADER);
}

/**
 * Test receive Initial packet with 2-byte Length field.
 */
TEST (quic_receive_2byte_length_varint)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  /* Length = 200 (requires 2-byte varint: 0x40C8) */
  uint8_t packet[250];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xC0;                   /* Long header, Initial */
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01; /* Version 1 */
  packet[5] = 0x08;                   /* DCID len = 8 */
  /* DCID at 6-13 */
  packet[14] = 0x00;                  /* SCID len = 0 */
  packet[15] = 0x00;                  /* Token len = 0 */
  packet[16] = 0x40;                  /* Length = 200 (2-byte varint) */
  packet[17] = 0xC8;                  /* 0x40C8 = 200 */

  SocketQUICReceive_init (&ctx);

  /* Header parses successfully, no keys */
  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_NO_KEYS);
  ASSERT_EQ (result.type, QUIC_PACKET_TYPE_INITIAL);
}

/**
 * Test receive with truncated varint in token length.
 */
TEST (quic_receive_truncated_token_varint)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  uint8_t packet[20];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xC0;                   /* Long header, Initial */
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01; /* Version 1 */
  packet[5] = 0x00;                   /* DCID len = 0 */
  packet[6] = 0x00;                   /* SCID len = 0 */
  /* 2-byte varint but only 1 byte available */
  packet[7] = 0x40;

  SocketQUICReceive_init (&ctx);

  /* Packet truncated during varint decode */
  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, 8, 0, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_HEADER);
}

/* ============================================================================
 * Key Setter Tests
 * ============================================================================
 */

/**
 * Test setting 0-RTT keys.
 */
TEST (quic_receive_set_0rtt_keys)
{
  SocketQUICReceive_T ctx;
  SocketQUICPacketKeys_T keys;

  SocketQUICReceive_init (&ctx);
  SocketQUICPacketKeys_init (&keys);

  SocketQUICReceive_Result result
      = SocketQUICReceive_set_0rtt_keys (&ctx, &keys);

  ASSERT_EQ (result, QUIC_RECEIVE_OK);
  ASSERT_EQ (ctx.zero_rtt_keys, &keys);
}

/**
 * Test 0-RTT key setter with NULL context.
 */
TEST (quic_receive_set_0rtt_keys_null)
{
  SocketQUICPacketKeys_T keys;
  SocketQUICPacketKeys_init (&keys);

  SocketQUICReceive_Result result
      = SocketQUICReceive_set_0rtt_keys (NULL, &keys);
  ASSERT_EQ (result, QUIC_RECEIVE_ERROR_NULL);
}

/**
 * Test setting all key types.
 */
TEST (quic_receive_set_all_keys)
{
  SocketQUICReceive_T ctx;
  SocketQUICInitialKeys_T initial;
  SocketQUICPacketKeys_T handshake;
  SocketQUICPacketKeys_T zero_rtt;
  SocketQUICKeyUpdate_T key_update;

  SocketQUICReceive_init (&ctx);
  SocketQUICInitialKeys_init (&initial);
  SocketQUICPacketKeys_init (&handshake);
  SocketQUICPacketKeys_init (&zero_rtt);
  SocketQUICKeyUpdate_init (&key_update);

  ASSERT_EQ (SocketQUICReceive_set_initial_keys (&ctx, &initial), QUIC_RECEIVE_OK);
  ASSERT_EQ (SocketQUICReceive_set_handshake_keys (&ctx, &handshake), QUIC_RECEIVE_OK);
  ASSERT_EQ (SocketQUICReceive_set_0rtt_keys (&ctx, &zero_rtt), QUIC_RECEIVE_OK);
  ASSERT_EQ (SocketQUICReceive_set_1rtt_keys (&ctx, &key_update), QUIC_RECEIVE_OK);

  ASSERT_EQ (ctx.initial_keys, &initial);
  ASSERT_EQ (ctx.handshake_keys, &handshake);
  ASSERT_EQ (ctx.zero_rtt_keys, &zero_rtt);
  ASSERT_EQ (ctx.key_update, &key_update);
}

/* ============================================================================
 * Packet Type Recognition Tests (0-RTT, Handshake)
 * ============================================================================
 */

/**
 * Test 0-RTT packet requires keys.
 */
TEST (quic_receive_0rtt_no_keys)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  uint8_t packet[100];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xD0;                   /* Long header, 0-RTT type (bits 4-5 = 01) */
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01; /* Version 1 */
  packet[5] = 0x08;                   /* DCID len = 8 */
  /* DCID at 6-13 */
  packet[14] = 0x00;                  /* SCID len = 0 */
  packet[15] = 0x10;                  /* Length = 16 */

  SocketQUICReceive_init (&ctx);

  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_NO_KEYS);
  ASSERT_EQ (result.type, QUIC_PACKET_TYPE_0RTT);
  ASSERT_EQ (result.pn_space, QUIC_PN_SPACE_APPLICATION);
}

/**
 * Test Handshake packet requires keys.
 */
TEST (quic_receive_handshake_no_keys)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;

  uint8_t packet[100];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xE0;                   /* Long header, Handshake type (bits 4-5 = 10) */
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01; /* Version 1 */
  packet[5] = 0x08;                   /* DCID len = 8 */
  /* DCID at 6-13 */
  packet[14] = 0x00;                  /* SCID len = 0 */
  packet[15] = 0x10;                  /* Length = 16 */

  SocketQUICReceive_init (&ctx);

  SocketQUICReceive_Result r
      = SocketQUICReceive_packet (&ctx, packet, sizeof (packet), 8, 1, &result);
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_NO_KEYS);
  ASSERT_EQ (result.type, QUIC_PACKET_TYPE_HANDSHAKE);
  ASSERT_EQ (result.pn_space, QUIC_PN_SPACE_HANDSHAKE);
}

/* ============================================================================
 * Integration Tests with Real Encryption
 * ============================================================================
 */

/**
 * Test complete Initial packet reception with derived keys.
 *
 * Uses RFC 9001 Appendix A.1 test vector DCID to derive keys,
 * then creates a properly protected packet and decrypts it.
 */
TEST (quic_receive_initial_integration)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;
  SocketQUICInitialKeys_T keys;
  SocketQUICConnectionID_T dcid;

  /* RFC 9001 Appendix A.1 test vector DCID */
  static const uint8_t test_dcid[] = {
    0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08
  };
  dcid.len = sizeof (test_dcid);
  memcpy (dcid.data, test_dcid, dcid.len);

  /* Derive Initial keys */
  SocketQUICCrypto_Result cr
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);
  ASSERT_EQ (cr, QUIC_CRYPTO_OK);

  /* Create a minimal Initial packet and protect it */
  uint8_t packet[200];
  memset (packet, 0, sizeof (packet));

  /* Build unprotected header */
  packet[0] = 0xC3;                   /* Long header, Initial, PN len = 4 (0-1 bits = 11) */
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01; /* Version 1 */
  packet[5] = 0x08;                   /* DCID len = 8 */
  memcpy (packet + 6, test_dcid, 8);  /* DCID */
  packet[14] = 0x00;                  /* SCID len = 0 */
  packet[15] = 0x00;                  /* Token len = 0 */

  /* Length field: PN (4) + payload (16) + tag (16) = 36 = 0x24 */
  packet[16] = 0x24;

  /* PN = 0 (4 bytes at offset 17-20) */
  packet[17] = 0x00;
  packet[18] = 0x00;
  packet[19] = 0x00;
  packet[20] = 0x00;

  /* Payload: CRYPTO frame with "Hello" (just padding for test) */
  size_t pn_offset = 17;
  size_t header_len = 21;
  uint8_t plaintext[16] = { 0x06, 0x00, 0x05, 'H', 'e', 'l', 'l', 'o',
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  /* Create SocketQUICPacketKeys_T from Initial keys for encryption */
  SocketQUICPacketKeys_T client_keys;
  SocketQUICPacketKeys_init (&client_keys);
  memcpy (client_keys.key, keys.client_key, QUIC_INITIAL_KEY_LEN);
  memcpy (client_keys.iv, keys.client_iv, QUIC_INITIAL_IV_LEN);
  memcpy (client_keys.hp_key, keys.client_hp_key, QUIC_INITIAL_HP_KEY_LEN);
  client_keys.key_len = QUIC_INITIAL_KEY_LEN;
  client_keys.hp_len = QUIC_INITIAL_HP_KEY_LEN;
  client_keys.aead = QUIC_AEAD_AES_128_GCM;

  /* Encrypt using client Initial keys (we're receiving as server) */
  size_t ciphertext_len = sizeof (plaintext) + 16;
  SocketQUICCrypto_Result encrypt_result = SocketQUICCrypto_encrypt_payload (
      &client_keys, 0, packet, header_len, plaintext, sizeof (plaintext),
      packet + header_len, &ciphertext_len);
  ASSERT_EQ (encrypt_result, QUIC_CRYPTO_OK);

  size_t packet_len = header_len + ciphertext_len;

  /* Apply header protection */
  SocketQUICCrypto_Result hp_result = SocketQUICCrypto_protect_header (
      client_keys.hp_key, client_keys.hp_len, client_keys.aead,
      packet, packet_len, pn_offset);
  ASSERT_EQ (hp_result, QUIC_CRYPTO_OK);

  /* Now receive the packet */
  SocketQUICReceive_init (&ctx);
  SocketQUICReceive_set_initial_keys (&ctx, &keys);

  SocketQUICReceive_Result r = SocketQUICReceive_packet (
      &ctx, packet, packet_len, 8, 1, &result);

  ASSERT_EQ (r, QUIC_RECEIVE_OK);
  ASSERT_EQ (result.type, QUIC_PACKET_TYPE_INITIAL);
  ASSERT_EQ (result.packet_number, 0ULL);
  ASSERT_EQ (result.payload_len, sizeof (plaintext));

  /* Verify decrypted content matches */
  ASSERT_EQ (memcmp (result.payload, plaintext, sizeof (plaintext)), 0);

  /* Verify largest_pn was updated */
  uint64_t largest;
  int has_pn = SocketQUICReceive_get_largest_pn (&ctx, QUIC_PN_SPACE_INITIAL, &largest);
  ASSERT_EQ (has_pn, 1);
  ASSERT_EQ (largest, 0ULL);

  SocketQUICInitialKeys_clear (&keys);
}

/**
 * Test Initial packet reception with non-zero packet number.
 */
TEST (quic_receive_initial_pn_sequence)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;
  SocketQUICInitialKeys_T keys;
  SocketQUICConnectionID_T dcid;

  /* Use RFC test DCID */
  static const uint8_t test_dcid[] = {
    0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08
  };
  dcid.len = sizeof (test_dcid);
  memcpy (dcid.data, test_dcid, dcid.len);

  SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);

  SocketQUICReceive_init (&ctx);
  SocketQUICReceive_set_initial_keys (&ctx, &keys);

  /* Create SocketQUICPacketKeys_T from Initial keys */
  SocketQUICPacketKeys_T client_keys;
  SocketQUICPacketKeys_init (&client_keys);
  memcpy (client_keys.key, keys.client_key, QUIC_INITIAL_KEY_LEN);
  memcpy (client_keys.iv, keys.client_iv, QUIC_INITIAL_IV_LEN);
  memcpy (client_keys.hp_key, keys.client_hp_key, QUIC_INITIAL_HP_KEY_LEN);
  client_keys.key_len = QUIC_INITIAL_KEY_LEN;
  client_keys.hp_len = QUIC_INITIAL_HP_KEY_LEN;
  client_keys.aead = QUIC_AEAD_AES_128_GCM;

  /* Create and receive packets with increasing PNs */
  for (uint64_t pn = 0; pn < 5; pn++)
    {
      uint8_t packet[200];
      memset (packet, 0, sizeof (packet));

      /* Header with 1-byte PN (sufficient for small values) */
      packet[0] = 0xC0;               /* PN len = 1 (bits 0-1 = 00) */
      packet[1] = 0x00; packet[2] = 0x00;
      packet[3] = 0x00; packet[4] = 0x01;
      packet[5] = 0x08;
      memcpy (packet + 6, test_dcid, 8);
      packet[14] = 0x00;
      packet[15] = 0x00;
      packet[16] = 0x21;              /* Length = 33 (1 PN + 16 payload + 16 tag) */
      packet[17] = (uint8_t)pn;       /* Truncated PN */

      size_t pn_offset = 17;
      size_t header_len = 18;
      uint8_t plaintext[16] = { 0 };
      plaintext[0] = (uint8_t)pn;     /* Mark payload with PN for verification */

      size_t ct_len = 32;
      SocketQUICCrypto_encrypt_payload (&client_keys, pn, packet, header_len,
                                        plaintext, 16, packet + header_len, &ct_len);
      SocketQUICCrypto_protect_header (client_keys.hp_key, client_keys.hp_len,
                                       client_keys.aead, packet, header_len + ct_len,
                                       pn_offset);

      SocketQUICReceive_Result r = SocketQUICReceive_packet (
          &ctx, packet, header_len + ct_len, 8, 1, &result);

      ASSERT_EQ (r, QUIC_RECEIVE_OK);
      ASSERT_EQ (result.packet_number, pn);
      ASSERT_EQ (result.payload[0], (uint8_t)pn);
    }

  /* Verify largest PN */
  uint64_t largest;
  SocketQUICReceive_get_largest_pn (&ctx, QUIC_PN_SPACE_INITIAL, &largest);
  ASSERT_EQ (largest, 4ULL);

  SocketQUICInitialKeys_clear (&keys);
}

/**
 * Test Initial packet with wrong keys fails decryption.
 */
TEST (quic_receive_initial_wrong_keys)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;
  SocketQUICInitialKeys_T correct_keys, wrong_keys;
  SocketQUICConnectionID_T dcid1, dcid2;

  /* Two different DCIDs produce different keys */
  static const uint8_t dcid1_data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  static const uint8_t dcid2_data[] = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };

  dcid1.len = 8;
  memcpy (dcid1.data, dcid1_data, 8);
  dcid2.len = 8;
  memcpy (dcid2.data, dcid2_data, 8);

  SocketQUICCrypto_derive_initial_keys (&dcid1, QUIC_VERSION_1, &correct_keys);
  SocketQUICCrypto_derive_initial_keys (&dcid2, QUIC_VERSION_1, &wrong_keys);

  /* Create SocketQUICPacketKeys_T from correct keys */
  SocketQUICPacketKeys_T correct_client;
  SocketQUICPacketKeys_init (&correct_client);
  memcpy (correct_client.key, correct_keys.client_key, QUIC_INITIAL_KEY_LEN);
  memcpy (correct_client.iv, correct_keys.client_iv, QUIC_INITIAL_IV_LEN);
  memcpy (correct_client.hp_key, correct_keys.client_hp_key, QUIC_INITIAL_HP_KEY_LEN);
  correct_client.key_len = QUIC_INITIAL_KEY_LEN;
  correct_client.hp_len = QUIC_INITIAL_HP_KEY_LEN;
  correct_client.aead = QUIC_AEAD_AES_128_GCM;

  /* Create packet with correct_keys */
  uint8_t packet[200];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xC0;
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01;
  packet[5] = 0x08;
  memcpy (packet + 6, dcid1_data, 8);
  packet[14] = 0x00;
  packet[15] = 0x00;
  packet[16] = 0x21;
  packet[17] = 0x00;

  uint8_t plaintext[16] = { 0 };
  size_t ct_len = 32;
  SocketQUICCrypto_encrypt_payload (&correct_client, 0, packet, 18,
                                    plaintext, 16, packet + 18, &ct_len);
  SocketQUICCrypto_protect_header (correct_client.hp_key,
                                   correct_client.hp_len,
                                   correct_client.aead,
                                   packet, 18 + ct_len, 17);

  /* Try to receive with wrong_keys */
  SocketQUICReceive_init (&ctx);
  SocketQUICReceive_set_initial_keys (&ctx, &wrong_keys);

  SocketQUICReceive_Result r = SocketQUICReceive_packet (
      &ctx, packet, 18 + ct_len, 8, 1, &result);

  /* Should fail decryption */
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_DECRYPT);

  /* Decryption failure should be counted */
  ASSERT_EQ (ctx.decryption_failures, 1ULL);

  /* Largest PN should NOT be updated on failure */
  uint64_t pn;
  int has = SocketQUICReceive_get_largest_pn (&ctx, QUIC_PN_SPACE_INITIAL, &pn);
  ASSERT_EQ (has, 0);

  SocketQUICInitialKeys_clear (&correct_keys);
  SocketQUICInitialKeys_clear (&wrong_keys);
}

/**
 * Test Handshake packet integration with derived keys.
 */
TEST (quic_receive_handshake_integration)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;
  SocketQUICPacketKeys_T keys;

  /* Create test secret and derive keys */
  uint8_t secret[32];
  memset (secret, 0x42, sizeof (secret));

  SocketQUICCrypto_derive_packet_keys (secret, sizeof (secret),
                                       QUIC_AEAD_AES_128_GCM, &keys);

  /* Build Handshake packet */
  uint8_t packet[200];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xE0;                   /* Long header, Handshake, PN len = 1 */
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01; /* Version 1 */
  packet[5] = 0x08;                   /* DCID len = 8 */
  /* DCID at 6-13 */
  packet[14] = 0x00;                  /* SCID len = 0 */
  packet[15] = 0x21;                  /* Length = 33 (1 PN + 16 + 16) */
  packet[16] = 0x00;                  /* PN = 0 */

  size_t pn_offset = 16;
  size_t header_len = 17;
  uint8_t plaintext[16] = { 0x06, 0x00, 0x05, 'T', 'e', 's', 't', '!',
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  size_t ct_len = 32;
  SocketQUICCrypto_encrypt_payload (&keys, 0, packet, header_len,
                                    plaintext, 16, packet + header_len, &ct_len);
  SocketQUICCrypto_protect_header_ex (&keys, packet, header_len + ct_len, pn_offset);

  /* Receive */
  SocketQUICReceive_init (&ctx);
  SocketQUICReceive_set_handshake_keys (&ctx, &keys);

  SocketQUICReceive_Result r = SocketQUICReceive_packet (
      &ctx, packet, header_len + ct_len, 8, 1, &result);

  ASSERT_EQ (r, QUIC_RECEIVE_OK);
  ASSERT_EQ (result.type, QUIC_PACKET_TYPE_HANDSHAKE);
  ASSERT_EQ (result.pn_space, QUIC_PN_SPACE_HANDSHAKE);
  ASSERT_EQ (result.packet_number, 0ULL);
  ASSERT_EQ (result.payload_len, 16);
  ASSERT_EQ (memcmp (result.payload, plaintext, 16), 0);

  /* Verify Handshake space updated */
  uint64_t pn;
  int has = SocketQUICReceive_get_largest_pn (&ctx, QUIC_PN_SPACE_HANDSHAKE, &pn);
  ASSERT_EQ (has, 1);
  ASSERT_EQ (pn, 0ULL);

  SocketQUICPacketKeys_clear (&keys);
}

/**
 * Test 0-RTT packet integration.
 */
TEST (quic_receive_0rtt_integration)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;
  SocketQUICPacketKeys_T keys;

  /* Derive 0-RTT keys from test secret */
  uint8_t secret[32];
  memset (secret, 0x55, sizeof (secret));
  SocketQUICCrypto_derive_packet_keys (secret, sizeof (secret),
                                       QUIC_AEAD_AES_128_GCM, &keys);

  /* Build 0-RTT packet */
  uint8_t packet[200];
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xD0;                   /* Long header, 0-RTT, PN len = 1 */
  packet[1] = 0x00; packet[2] = 0x00;
  packet[3] = 0x00; packet[4] = 0x01; /* Version 1 */
  packet[5] = 0x08;                   /* DCID len = 8 */
  /* DCID at 6-13 */
  packet[14] = 0x00;                  /* SCID len = 0 */
  packet[15] = 0x21;                  /* Length */
  packet[16] = 0x00;                  /* PN = 0 */

  size_t pn_offset = 16;
  size_t header_len = 17;
  uint8_t plaintext[16] = { 0 };

  size_t ct_len = 32;
  SocketQUICCrypto_encrypt_payload (&keys, 0, packet, header_len,
                                    plaintext, 16, packet + header_len, &ct_len);
  SocketQUICCrypto_protect_header_ex (&keys, packet, header_len + ct_len, pn_offset);

  /* Receive */
  SocketQUICReceive_init (&ctx);
  SocketQUICReceive_set_0rtt_keys (&ctx, &keys);

  SocketQUICReceive_Result r = SocketQUICReceive_packet (
      &ctx, packet, header_len + ct_len, 8, 1, &result);

  ASSERT_EQ (r, QUIC_RECEIVE_OK);
  ASSERT_EQ (result.type, QUIC_PACKET_TYPE_0RTT);
  ASSERT_EQ (result.pn_space, QUIC_PN_SPACE_APPLICATION);
  ASSERT_EQ (result.packet_number, 0ULL);

  /* 0-RTT uses Application space */
  uint64_t pn;
  int has = SocketQUICReceive_get_largest_pn (&ctx, QUIC_PN_SPACE_APPLICATION, &pn);
  ASSERT_EQ (has, 1);
  ASSERT_EQ (pn, 0ULL);

  SocketQUICPacketKeys_clear (&keys);
}

/**
 * Test 1-RTT packet integration with key update state.
 */
TEST (quic_receive_1rtt_integration)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;
  SocketQUICKeyUpdate_T ku;

  /* Initialize key update state with test secrets */
  uint8_t write_secret[32], read_secret[32];
  memset (write_secret, 0xAA, sizeof (write_secret));
  memset (read_secret, 0xBB, sizeof (read_secret));

  SocketQUICKeyUpdate_init (&ku);
  SocketQUICCrypto_Result cr = SocketQUICKeyUpdate_set_initial_keys (
      &ku, write_secret, read_secret, 32, QUIC_AEAD_AES_128_GCM);
  ASSERT_EQ (cr, QUIC_CRYPTO_OK);

  /* Build 1-RTT (short header) packet */
  uint8_t dcid[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  uint8_t packet[200];
  memset (packet, 0, sizeof (packet));

  /* Short header: fixed bit (1), spin (0), reserved (0), key phase (0), PN len (0 = 1 byte) */
  packet[0] = 0x40;                   /* 0100 0000: short header, key phase 0 */
  memcpy (packet + 1, dcid, 8);       /* DCID */
  packet[9] = 0x00;                   /* PN = 0 */

  size_t pn_offset = 9;
  size_t header_len = 10;
  uint8_t plaintext[16] = { 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  /* Encrypt with write keys (we're receiving, so use peer's write = our read) */
  size_t ct_len = 32;
  SocketQUICCrypto_encrypt_payload (&ku.read_keys, 0, packet, header_len,
                                    plaintext, 16, packet + header_len, &ct_len);
  SocketQUICCrypto_protect_header_ex (&ku.read_keys, packet, header_len + ct_len, pn_offset);

  /* Receive */
  SocketQUICReceive_init (&ctx);
  SocketQUICReceive_set_1rtt_keys (&ctx, &ku);

  SocketQUICReceive_Result r = SocketQUICReceive_packet (
      &ctx, packet, header_len + ct_len, 8, 0, &result);

  ASSERT_EQ (r, QUIC_RECEIVE_OK);
  ASSERT_EQ (result.type, QUIC_PACKET_TYPE_1RTT);
  ASSERT_EQ (result.pn_space, QUIC_PN_SPACE_APPLICATION);
  ASSERT_EQ (result.packet_number, 0ULL);
  ASSERT_EQ (result.key_phase, 0);
  ASSERT_EQ (result.payload_len, 16);

  /* Verify Application space updated */
  uint64_t pn;
  int has = SocketQUICReceive_get_largest_pn (&ctx, QUIC_PN_SPACE_APPLICATION, &pn);
  ASSERT_EQ (has, 1);
  ASSERT_EQ (pn, 0ULL);

  /* Verify decryption was counted */
  ASSERT_EQ (ku.packets_decrypted, 1ULL);

  SocketQUICKeyUpdate_clear (&ku);
}

/**
 * Test out-of-order packet reception across multiple packets.
 */
TEST (quic_receive_out_of_order_packets)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;
  SocketQUICInitialKeys_T keys;
  SocketQUICConnectionID_T dcid;

  static const uint8_t test_dcid[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
  dcid.len = 8;
  memcpy (dcid.data, test_dcid, 8);

  SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);

  SocketQUICReceive_init (&ctx);
  SocketQUICReceive_set_initial_keys (&ctx, &keys);

  /* Create SocketQUICPacketKeys_T from Initial keys */
  SocketQUICPacketKeys_T client_keys;
  SocketQUICPacketKeys_init (&client_keys);
  memcpy (client_keys.key, keys.client_key, QUIC_INITIAL_KEY_LEN);
  memcpy (client_keys.iv, keys.client_iv, QUIC_INITIAL_IV_LEN);
  memcpy (client_keys.hp_key, keys.client_hp_key, QUIC_INITIAL_HP_KEY_LEN);
  client_keys.key_len = QUIC_INITIAL_KEY_LEN;
  client_keys.hp_len = QUIC_INITIAL_HP_KEY_LEN;
  client_keys.aead = QUIC_AEAD_AES_128_GCM;

  /* Receive packets in order: 0, 1, 5, 3, 4 (skip 2) */
  uint64_t pn_sequence[] = { 0, 1, 5, 3, 4 };

  for (size_t i = 0; i < sizeof (pn_sequence) / sizeof (pn_sequence[0]); i++)
    {
      uint64_t pn = pn_sequence[i];
      uint8_t packet[200];
      memset (packet, 0, sizeof (packet));

      packet[0] = 0xC0;
      packet[1] = 0x00; packet[2] = 0x00;
      packet[3] = 0x00; packet[4] = 0x01;
      packet[5] = 0x08;
      memcpy (packet + 6, test_dcid, 8);
      packet[14] = 0x00;
      packet[15] = 0x00;
      packet[16] = 0x21;
      packet[17] = (uint8_t)pn;

      uint8_t plaintext[16] = { 0 };
      size_t ct_len = 32;
      SocketQUICCrypto_encrypt_payload (&client_keys, pn, packet, 18,
                                        plaintext, 16, packet + 18, &ct_len);
      SocketQUICCrypto_protect_header (client_keys.hp_key, client_keys.hp_len,
                                       client_keys.aead, packet, 50, 17);

      SocketQUICReceive_Result r = SocketQUICReceive_packet (
          &ctx, packet, 50, 8, 1, &result);

      ASSERT_EQ (r, QUIC_RECEIVE_OK);
      ASSERT_EQ (result.packet_number, pn);
    }

  /* largest_pn should be 5 (highest received) */
  uint64_t largest;
  SocketQUICReceive_get_largest_pn (&ctx, QUIC_PN_SPACE_INITIAL, &largest);
  ASSERT_EQ (largest, 5ULL);

  SocketQUICInitialKeys_clear (&keys);
}

/* ============================================================================
 * Key Phase Tests (RFC 9001 §6)
 * ============================================================================
 */

/**
 * Test receiving 1-RTT packet with key phase 1 (peer-initiated key update).
 *
 * When we receive a packet with a different key phase than our current phase,
 * we must use the pre-computed next read keys to decrypt.
 */
TEST (quic_receive_1rtt_key_phase_change)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;
  SocketQUICKeyUpdate_T ku;

  /* Initialize with phase 0 */
  uint8_t write_secret[32], read_secret[32];
  memset (write_secret, 0xAA, sizeof (write_secret));
  memset (read_secret, 0xBB, sizeof (read_secret));

  SocketQUICKeyUpdate_init (&ku);
  SocketQUICKeyUpdate_set_initial_keys (&ku, write_secret, read_secret, 32,
                                        QUIC_AEAD_AES_128_GCM);

  /* Verify initial state: phase 0, next_read_keys pre-computed */
  ASSERT_EQ (ku.key_phase, 0);
  ASSERT_EQ (ku.next_read_keys_valid, 1);

  /* Build 1-RTT packet with key phase 1 (peer initiated update) */
  uint8_t dcid[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  uint8_t packet[200];
  memset (packet, 0, sizeof (packet));

  /* Short header with key phase bit SET (bit 2 = 0x04) */
  packet[0] = 0x44; /* 0100 0100: short header, key phase 1 */
  memcpy (packet + 1, dcid, 8);
  packet[9] = 0x00; /* PN = 0 */

  size_t pn_offset = 9;
  size_t header_len = 10;
  uint8_t plaintext[16] = { 0x07, 0x00, 0x00, 0x00 };

  /* Encrypt with NEXT read keys (peer's new AEAD keys = our next_read_keys) */
  size_t ct_len = 32;
  SocketQUICCrypto_encrypt_payload (&ku.next_read_keys, 0, packet, header_len,
                                    plaintext, 16, packet + header_len, &ct_len);
  /* HP key doesn't change with key update - use current read_keys HP */
  SocketQUICCrypto_protect_header (ku.read_keys.hp_key, ku.read_keys.hp_len,
                                   ku.read_keys.aead, packet,
                                   header_len + ct_len, pn_offset);

  /* Receive */
  SocketQUICReceive_init (&ctx);
  SocketQUICReceive_set_1rtt_keys (&ctx, &ku);

  SocketQUICReceive_Result r = SocketQUICReceive_packet (
      &ctx, packet, header_len + ct_len, 8, 0, &result);

  ASSERT_EQ (r, QUIC_RECEIVE_OK);
  ASSERT_EQ (result.type, QUIC_PACKET_TYPE_1RTT);
  ASSERT_EQ (result.key_phase, 1);
  ASSERT_EQ (result.packet_number, 0ULL);
  ASSERT_EQ (result.payload_len, 16);

  /* Verify key update state was updated */
  ASSERT_EQ (ku.key_phase, 1);
  ASSERT_EQ (ku.generation, 1);

  SocketQUICKeyUpdate_clear (&ku);
}

/**
 * Test receiving delayed packet with same key phase but low PN.
 *
 * After processing packets at phase 0, if we receive a packet with a lower PN,
 * it should still decrypt using current keys (RFC 9001 §6.5).
 */
TEST (quic_receive_1rtt_delayed_packet_same_phase)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;
  SocketQUICKeyUpdate_T ku;

  uint8_t write_secret[32], read_secret[32];
  memset (write_secret, 0xCC, sizeof (write_secret));
  memset (read_secret, 0xDD, sizeof (read_secret));

  SocketQUICKeyUpdate_init (&ku);
  SocketQUICKeyUpdate_set_initial_keys (&ku, write_secret, read_secret, 32,
                                        QUIC_AEAD_AES_128_GCM);

  SocketQUICReceive_init (&ctx);
  SocketQUICReceive_set_1rtt_keys (&ctx, &ku);

  uint8_t dcid[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

  /* First, receive packet with PN=5 */
  {
    uint8_t packet[200];
    memset (packet, 0, sizeof (packet));
    packet[0] = 0x40; /* Key phase 0 */
    memcpy (packet + 1, dcid, 8);
    packet[9] = 0x05; /* PN = 5 */

    size_t pn_offset = 9;
    size_t header_len = 10;
    uint8_t plaintext[16] = { 0x05 };

    size_t ct_len = 32;
    SocketQUICCrypto_encrypt_payload (&ku.read_keys, 5, packet, header_len,
                                      plaintext, 16, packet + header_len, &ct_len);
    SocketQUICCrypto_protect_header (ku.read_keys.hp_key, ku.read_keys.hp_len,
                                     ku.read_keys.aead, packet,
                                     header_len + ct_len, pn_offset);

    SocketQUICReceive_Result r = SocketQUICReceive_packet (
        &ctx, packet, header_len + ct_len, 8, 0, &result);
    ASSERT_EQ (r, QUIC_RECEIVE_OK);
    ASSERT_EQ (result.packet_number, 5ULL);
  }

  /* Now receive delayed packet with PN=2 (lower than largest seen) */
  {
    uint8_t packet[200];
    memset (packet, 0, sizeof (packet));
    packet[0] = 0x40; /* Key phase 0 */
    memcpy (packet + 1, dcid, 8);
    packet[9] = 0x02; /* PN = 2 */

    size_t pn_offset = 9;
    size_t header_len = 10;
    uint8_t plaintext[16] = { 0x02 };

    size_t ct_len = 32;
    SocketQUICCrypto_encrypt_payload (&ku.read_keys, 2, packet, header_len,
                                      plaintext, 16, packet + header_len, &ct_len);
    SocketQUICCrypto_protect_header (ku.read_keys.hp_key, ku.read_keys.hp_len,
                                     ku.read_keys.aead, packet,
                                     header_len + ct_len, pn_offset);

    SocketQUICReceive_Result r = SocketQUICReceive_packet (
        &ctx, packet, header_len + ct_len, 8, 0, &result);
    ASSERT_EQ (r, QUIC_RECEIVE_OK);
    ASSERT_EQ (result.packet_number, 2ULL);
    ASSERT_EQ (result.payload[0], 0x02);
  }

  /* largest_pn should still be 5 */
  uint64_t pn;
  SocketQUICReceive_get_largest_pn (&ctx, QUIC_PN_SPACE_APPLICATION, &pn);
  ASSERT_EQ (pn, 5ULL);

  SocketQUICKeyUpdate_clear (&ku);
}

/**
 * Test multiple key phase transitions.
 *
 * Verifies key phase toggles correctly through multiple updates.
 */
TEST (quic_receive_1rtt_multiple_key_updates)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;
  SocketQUICKeyUpdate_T ku;

  uint8_t write_secret[32], read_secret[32];
  memset (write_secret, 0xEE, sizeof (write_secret));
  memset (read_secret, 0xFF, sizeof (read_secret));

  SocketQUICKeyUpdate_init (&ku);
  SocketQUICKeyUpdate_set_initial_keys (&ku, write_secret, read_secret, 32,
                                        QUIC_AEAD_AES_128_GCM);

  SocketQUICReceive_init (&ctx);
  SocketQUICReceive_set_1rtt_keys (&ctx, &ku);

  uint8_t dcid[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

  /* Receive packets with alternating key phases (simulating peer updates) */
  for (int update = 0; update < 3; update++)
    {
      int expected_phase = (update + 1) % 2; /* 1, 0, 1 */
      uint8_t packet[200];
      memset (packet, 0, sizeof (packet));

      /* Set key phase bit based on expected phase */
      packet[0] = expected_phase ? 0x44 : 0x40;
      memcpy (packet + 1, dcid, 8);
      packet[9] = (uint8_t)(update + 1); /* PN = 1, 2, 3 */

      size_t pn_offset = 9;
      size_t header_len = 10;
      uint8_t plaintext[16] = { (uint8_t)update };

      /* Get the appropriate AEAD keys for this phase */
      const SocketQUICPacketKeys_T *encrypt_keys;
      SocketQUICKeyUpdate_get_read_keys (&ku, expected_phase, update + 1,
                                         &encrypt_keys);

      size_t ct_len = 32;
      SocketQUICCrypto_encrypt_payload (encrypt_keys, update + 1, packet,
                                        header_len, plaintext, 16,
                                        packet + header_len, &ct_len);
      /* HP key doesn't change - always use current read_keys HP */
      SocketQUICCrypto_protect_header (ku.read_keys.hp_key, ku.read_keys.hp_len,
                                       ku.read_keys.aead, packet,
                                       header_len + ct_len, pn_offset);

      SocketQUICReceive_Result r = SocketQUICReceive_packet (
          &ctx, packet, header_len + ct_len, 8, 0, &result);

      ASSERT_EQ (r, QUIC_RECEIVE_OK);
      ASSERT_EQ (result.key_phase, expected_phase);
      ASSERT_EQ (result.packet_number, (uint64_t)(update + 1));
    }

  /* Final state: phase 1, generation 3 */
  ASSERT_EQ (ku.key_phase, 1);
  ASSERT_EQ (ku.generation, 3);

  SocketQUICKeyUpdate_clear (&ku);
}

/**
 * Test 1-RTT with wrong key phase keys fails.
 *
 * If we don't have valid next_read_keys for a different phase,
 * decryption should fail.
 */
TEST (quic_receive_1rtt_wrong_keys_fail)
{
  SocketQUICReceive_T ctx;
  SocketQUICReceiveResult_T result;
  SocketQUICKeyUpdate_T ku;

  uint8_t write_secret[32], read_secret[32];
  memset (write_secret, 0x11, sizeof (write_secret));
  memset (read_secret, 0x22, sizeof (read_secret));

  SocketQUICKeyUpdate_init (&ku);
  SocketQUICKeyUpdate_set_initial_keys (&ku, write_secret, read_secret, 32,
                                        QUIC_AEAD_AES_128_GCM);

  /* Create completely different keys for encryption */
  uint8_t wrong_write[32], wrong_read[32];
  memset (wrong_write, 0x99, sizeof (wrong_write));
  memset (wrong_read, 0xAA, sizeof (wrong_read));

  SocketQUICKeyUpdate_T wrong_ku;
  SocketQUICKeyUpdate_init (&wrong_ku);
  SocketQUICKeyUpdate_set_initial_keys (&wrong_ku, wrong_write, wrong_read, 32,
                                        QUIC_AEAD_AES_128_GCM);

  /* Build packet encrypted with wrong keys */
  uint8_t dcid[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  uint8_t packet[200];
  memset (packet, 0, sizeof (packet));

  packet[0] = 0x40;
  memcpy (packet + 1, dcid, 8);
  packet[9] = 0x00;

  size_t pn_offset = 9;
  size_t header_len = 10;
  uint8_t plaintext[16] = { 0 };

  size_t ct_len = 32;
  SocketQUICCrypto_encrypt_payload (&wrong_ku.read_keys, 0, packet, header_len,
                                    plaintext, 16, packet + header_len, &ct_len);
  SocketQUICCrypto_protect_header_ex (&wrong_ku.read_keys, packet,
                                      header_len + ct_len, pn_offset);

  /* Receive with correct ku (should fail) */
  SocketQUICReceive_init (&ctx);
  SocketQUICReceive_set_1rtt_keys (&ctx, &ku);

  SocketQUICReceive_Result r = SocketQUICReceive_packet (
      &ctx, packet, header_len + ct_len, 8, 0, &result);

  /* Should fail decryption */
  ASSERT_EQ (r, QUIC_RECEIVE_ERROR_DECRYPT);

  /* Decryption failures should be counted */
  ASSERT (ctx.decryption_failures > 0 || ku.decryption_failures > 0);

  SocketQUICKeyUpdate_clear (&ku);
  SocketQUICKeyUpdate_clear (&wrong_ku);
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

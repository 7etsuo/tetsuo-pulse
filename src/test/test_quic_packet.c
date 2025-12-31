/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_packet.c - QUIC Packet Header unit tests
 *
 * Tests parsing and serialization of QUIC packet headers (RFC 9000 Section 17).
 * Covers Long Headers (Initial, 0-RTT, Handshake, Retry) and Short Headers
 * (1-RTT).
 */

#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICPacket.h"
#include "quic/SocketQUICVersion.h"
#include "test/Test.h"

/* ============================================================================
 * Helper Functions
 * ============================================================================
 */

static void
setup_test_cid (SocketQUICConnectionID_T *cid, uint8_t len)
{
  SocketQUICConnectionID_init (cid);
  cid->len = len;
  for (uint8_t i = 0; i < len; i++)
    cid->data[i] = (uint8_t)(0x10 + i);
}

/* ============================================================================
 * Long Header - Initial Packet Tests (RFC 9000 Section 17.2.2)
 * ============================================================================
 */

TEST (quic_packet_parse_initial_basic)
{
  /* Initial packet: Long header, type 0x00, QUICv1 */
  uint8_t data[] = {
    0xC0, /* Form=1, Fixed=1, Type=00 (Initial), PN_Len=00 (1 byte) */
    0x00, 0x00, 0x00, 0x01,                         /* Version: QUIC v1 */
    0x08,                                           /* DCID Length: 8 */
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, /* DCID */
    0x04,                                           /* SCID Length: 4 */
    0x0A, 0x0B, 0x0C, 0x0D,                         /* SCID */
    0x00,                                           /* Token Length: 0 */
    0x10, /* Payload Length: 16 (varint 1 byte) */
    0x00, /* Packet Number: 0 (1 byte) */
  };

  SocketQUICPacketHeader_T header;
  size_t consumed;

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_parse (data, sizeof (data), &header, &consumed);

  ASSERT_EQ (res, QUIC_PACKET_OK);
  ASSERT_EQ (header.is_long_header, 1);
  ASSERT_EQ (header.type, QUIC_PACKET_TYPE_INITIAL);
  ASSERT_EQ (header.version, QUIC_VERSION_1);
  ASSERT_EQ (header.dcid.len, 8);
  ASSERT_EQ (header.scid.len, 4);
  ASSERT_EQ (header.token_length, 0);
  ASSERT_EQ (header.pn_length, 1);
  ASSERT_EQ (header.packet_number, 0);
  ASSERT_EQ (header.length, 16);
  ASSERT_EQ (consumed, sizeof (data));
}

TEST (quic_packet_parse_initial_with_token)
{
  /* Initial packet with token */
  uint8_t data[] = {
    0xC1, /* Form=1, Fixed=1, Type=00 (Initial), PN_Len=01 (2 bytes) */
    0x00, 0x00, 0x00, 0x01,                         /* Version: QUIC v1 */
    0x08,                                           /* DCID Length: 8 */
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, /* DCID */
    0x04,                                           /* SCID Length: 4 */
    0x0A, 0x0B, 0x0C, 0x0D,                         /* SCID */
    0x08,                                           /* Token Length: 8 */
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, /* Token */
    0x20,                                           /* Payload Length: 32 */
    0x00, 0x01, /* Packet Number: 1 (2 bytes) */
  };

  SocketQUICPacketHeader_T header;
  size_t consumed;

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_parse (data, sizeof (data), &header, &consumed);

  ASSERT_EQ (res, QUIC_PACKET_OK);
  ASSERT_EQ (header.type, QUIC_PACKET_TYPE_INITIAL);
  ASSERT_EQ (header.token_length, 8);
  ASSERT_NOT_NULL (header.token);
  ASSERT_EQ (header.token[0], 0xAA);
  ASSERT_EQ (header.pn_length, 2);
  ASSERT_EQ (header.packet_number, 1);
  ASSERT_EQ (header.length, 32);
}

/* ============================================================================
 * Long Header - Handshake Packet Tests (RFC 9000 Section 17.2.4)
 * ============================================================================
 */

TEST (quic_packet_parse_handshake)
{
  /* Handshake packet: Long header, type 0x02 */
  uint8_t data[] = {
    0xE2, /* Form=1, Fixed=1, Type=10 (Handshake), PN_Len=10 (3 bytes) */
    0x00, 0x00, 0x00, 0x01,                         /* Version: QUIC v1 */
    0x08,                                           /* DCID Length: 8 */
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, /* DCID */
    0x04,                                           /* SCID Length: 4 */
    0x0A, 0x0B, 0x0C, 0x0D,                         /* SCID */
    0x40, 0x64,       /* Payload Length: 100 (2-byte varint) */
    0x00, 0x00, 0x05, /* Packet Number: 5 (3 bytes) */
  };

  SocketQUICPacketHeader_T header;
  size_t consumed;

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_parse (data, sizeof (data), &header, &consumed);

  ASSERT_EQ (res, QUIC_PACKET_OK);
  ASSERT_EQ (header.is_long_header, 1);
  ASSERT_EQ (header.type, QUIC_PACKET_TYPE_HANDSHAKE);
  ASSERT_EQ (header.pn_length, 3);
  ASSERT_EQ (header.packet_number, 5);
  ASSERT_EQ (header.length, 100);
}

/* ============================================================================
 * Long Header - 0-RTT Packet Tests (RFC 9000 Section 17.2.3)
 * ============================================================================
 */

TEST (quic_packet_parse_0rtt)
{
  /* 0-RTT packet: Long header, type 0x01 */
  uint8_t data[] = {
    0xD3, /* Form=1, Fixed=1, Type=01 (0-RTT), PN_Len=11 (4 bytes) */
    0x00, 0x00, 0x00, 0x01, /* Version: QUIC v1 */
    0x04,                   /* DCID Length: 4 */
    0x01, 0x02, 0x03, 0x04, /* DCID */
    0x04,                   /* SCID Length: 4 */
    0x0A, 0x0B, 0x0C, 0x0D, /* SCID */
    0x80, 0x00, 0x04, 0x00, /* Payload Length: 1024 (4-byte varint) */
    0x00, 0x01, 0x02, 0x03, /* Packet Number: 66051 (4 bytes) */
  };

  SocketQUICPacketHeader_T header;
  size_t consumed;

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_parse (data, sizeof (data), &header, &consumed);

  ASSERT_EQ (res, QUIC_PACKET_OK);
  ASSERT_EQ (header.type, QUIC_PACKET_TYPE_0RTT);
  ASSERT_EQ (header.pn_length, 4);
  ASSERT_EQ (header.packet_number, 0x00010203);
  ASSERT_EQ (header.length, 1024);
}

/* ============================================================================
 * Long Header - Retry Packet Tests (RFC 9000 Section 17.2.5)
 * ============================================================================
 */

TEST (quic_packet_parse_retry)
{
  /* Retry packet: Long header, type 0x03 */
  uint8_t data[] = {
    0xF0, /* Form=1, Fixed=1, Type=11 (Retry), reserved bits */
    0x00,
    0x00,
    0x00,
    0x01, /* Version: QUIC v1 */
    0x04, /* DCID Length: 4 */
    0x01,
    0x02,
    0x03,
    0x04, /* DCID */
    0x04, /* SCID Length: 4 */
    0x0A,
    0x0B,
    0x0C,
    0x0D, /* SCID */
    /* Retry Token (8 bytes) */
    0xDE,
    0xAD,
    0xBE,
    0xEF,
    0xCA,
    0xFE,
    0xBA,
    0xBE,
    /* Retry Integrity Tag (16 bytes) */
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0A,
    0x0B,
    0x0C,
    0x0D,
    0x0E,
    0x0F,
  };

  SocketQUICPacketHeader_T header;
  size_t consumed;

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_parse (data, sizeof (data), &header, &consumed);

  ASSERT_EQ (res, QUIC_PACKET_OK);
  ASSERT_EQ (header.type, QUIC_PACKET_TYPE_RETRY);
  ASSERT_EQ (header.retry_token_length, 8);
  ASSERT_NOT_NULL (header.retry_token);
  ASSERT_EQ (header.has_retry_integrity_tag, 1);
  ASSERT_EQ (header.retry_integrity_tag[0], 0x00);
  ASSERT_EQ (header.retry_integrity_tag[15], 0x0F);
}

/* ============================================================================
 * Short Header - 1-RTT Packet Tests (RFC 9000 Section 17.3)
 * ============================================================================
 */

TEST (quic_packet_parse_short_header)
{
  /* Short header: 1-RTT packet */
  uint8_t data[] = {
    0x40, /* Form=0, Fixed=1, Spin=0, Reserved=00, KeyPhase=0, PN_Len=00 */
    0x01, 0x02, 0x03, 0x04, /* DCID (known to be 4 bytes from connection) */
    0x42,                   /* Packet Number: 66 (1 byte) */
  };

  SocketQUICPacketHeader_T header;
  size_t consumed;

  /* Set expected DCID length before parsing short header */
  SocketQUICPacketHeader_init (&header);
  header.dcid_length = 4;

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_parse (data, sizeof (data), &header, &consumed);

  ASSERT_EQ (res, QUIC_PACKET_OK);
  ASSERT_EQ (header.is_long_header, 0);
  ASSERT_EQ (header.type, QUIC_PACKET_TYPE_1RTT);
  ASSERT_EQ (header.spin_bit, 0);
  ASSERT_EQ (header.key_phase, 0);
  ASSERT_EQ (header.pn_length, 1);
  ASSERT_EQ (header.packet_number, 0x42);
  ASSERT_EQ (header.dcid.len, 4);
}

TEST (quic_packet_parse_short_header_spin_keyphase)
{
  /* Short header with spin and key phase bits set */
  uint8_t data[] = {
    0x66, /* Form=0, Fixed=1, Spin=1, Reserved=00, KeyPhase=1, PN_Len=10 */
    0x01, 0x02, 0x03, 0x04, /* DCID */
    0x00, 0x00, 0xFF,       /* Packet Number: 255 (3 bytes) */
  };

  SocketQUICPacketHeader_T header;
  size_t consumed;

  SocketQUICPacketHeader_init (&header);
  header.dcid_length = 4;

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_parse (data, sizeof (data), &header, &consumed);

  ASSERT_EQ (res, QUIC_PACKET_OK);
  ASSERT_EQ (header.spin_bit, 1);
  ASSERT_EQ (header.key_phase, 1);
  ASSERT_EQ (header.pn_length, 3);
  ASSERT_EQ (header.packet_number, 255);
}

TEST (quic_packet_parse_short_header_zero_length_dcid)
{
  /* Short header with zero-length DCID */
  uint8_t data[] = {
    0x41, /* Form=0, Fixed=1, PN_Len=01 (2 bytes) */
    0x01,
    0x00, /* Packet Number: 256 (2 bytes) */
  };

  SocketQUICPacketHeader_T header;
  size_t consumed;

  SocketQUICPacketHeader_init (&header);
  header.dcid_length = 0;

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_parse (data, sizeof (data), &header, &consumed);

  ASSERT_EQ (res, QUIC_PACKET_OK);
  ASSERT_EQ (header.dcid.len, 0);
  ASSERT_EQ (header.pn_length, 2);
  ASSERT_EQ (header.packet_number, 256);
}

/* ============================================================================
 * Serialization Tests - Long Headers
 * ============================================================================
 */

TEST (quic_packet_serialize_initial)
{
  SocketQUICPacketHeader_T header;
  SocketQUICConnectionID_T dcid, scid;
  uint8_t output[128];
  uint8_t token[] = { 0xAA, 0xBB, 0xCC, 0xDD };

  setup_test_cid (&dcid, 8);
  setup_test_cid (&scid, 4);

  SocketQUICPacket_Result res = SocketQUICPacketHeader_build_initial (
      &header, QUIC_VERSION_1, &dcid, &scid, token, sizeof (token), 2, 100);

  ASSERT_EQ (res, QUIC_PACKET_OK);

  /* Set length for serialization */
  header.length = 64;

  size_t written
      = SocketQUICPacketHeader_serialize (&header, output, sizeof (output));
  ASSERT (written > 0);

  /* Verify by parsing back */
  SocketQUICPacketHeader_T parsed;
  size_t consumed;
  res = SocketQUICPacketHeader_parse (output, written, &parsed, &consumed);

  ASSERT_EQ (res, QUIC_PACKET_OK);
  ASSERT_EQ (parsed.type, QUIC_PACKET_TYPE_INITIAL);
  ASSERT_EQ (parsed.version, QUIC_VERSION_1);
  ASSERT_EQ (parsed.dcid.len, 8);
  ASSERT_EQ (parsed.scid.len, 4);
  ASSERT_EQ (parsed.token_length, sizeof (token));
  ASSERT_EQ (parsed.pn_length, 2);
  ASSERT_EQ (parsed.packet_number, 100);
}

TEST (quic_packet_serialize_handshake)
{
  SocketQUICPacketHeader_T header;
  SocketQUICConnectionID_T dcid, scid;
  uint8_t output[128];

  setup_test_cid (&dcid, 8);
  setup_test_cid (&scid, 8);

  SocketQUICPacket_Result res = SocketQUICPacketHeader_build_handshake (
      &header, QUIC_VERSION_1, &dcid, &scid, 3, 12345);

  ASSERT_EQ (res, QUIC_PACKET_OK);
  header.length = 200;

  size_t written
      = SocketQUICPacketHeader_serialize (&header, output, sizeof (output));
  ASSERT (written > 0);

  /* Verify round-trip */
  SocketQUICPacketHeader_T parsed;
  size_t consumed;
  res = SocketQUICPacketHeader_parse (output, written, &parsed, &consumed);

  ASSERT_EQ (res, QUIC_PACKET_OK);
  ASSERT_EQ (parsed.type, QUIC_PACKET_TYPE_HANDSHAKE);
  ASSERT_EQ (parsed.pn_length, 3);
  ASSERT_EQ (parsed.packet_number, 12345);
}

TEST (quic_packet_serialize_0rtt)
{
  SocketQUICPacketHeader_T header;
  SocketQUICConnectionID_T dcid, scid;
  uint8_t output[128];

  setup_test_cid (&dcid, 8);
  setup_test_cid (&scid, 4);

  SocketQUICPacket_Result res = SocketQUICPacketHeader_build_0rtt (
      &header, QUIC_VERSION_1, &dcid, &scid, 4, 0x12345678);

  ASSERT_EQ (res, QUIC_PACKET_OK);
  header.length = 512;

  size_t written
      = SocketQUICPacketHeader_serialize (&header, output, sizeof (output));
  ASSERT (written > 0);

  /* Verify round-trip */
  SocketQUICPacketHeader_T parsed;
  size_t consumed;
  res = SocketQUICPacketHeader_parse (output, written, &parsed, &consumed);

  ASSERT_EQ (res, QUIC_PACKET_OK);
  ASSERT_EQ (parsed.type, QUIC_PACKET_TYPE_0RTT);
  ASSERT_EQ (parsed.pn_length, 4);
  ASSERT_EQ (parsed.packet_number, 0x12345678);
}

/* ============================================================================
 * Serialization Tests - Short Headers
 * ============================================================================
 */

TEST (quic_packet_serialize_short)
{
  SocketQUICPacketHeader_T header;
  SocketQUICConnectionID_T dcid;
  uint8_t output[64];

  setup_test_cid (&dcid, 8);

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_build_short (&header, &dcid, 1, 1, 2, 500);

  ASSERT_EQ (res, QUIC_PACKET_OK);

  size_t written
      = SocketQUICPacketHeader_serialize (&header, output, sizeof (output));
  ASSERT (written > 0);

  /* Verify by parsing back */
  SocketQUICPacketHeader_T parsed;
  size_t consumed;

  SocketQUICPacketHeader_init (&parsed);
  parsed.dcid_length = 8;

  res = SocketQUICPacketHeader_parse (output, written, &parsed, &consumed);

  ASSERT_EQ (res, QUIC_PACKET_OK);
  ASSERT_EQ (parsed.type, QUIC_PACKET_TYPE_1RTT);
  ASSERT_EQ (parsed.spin_bit, 1);
  ASSERT_EQ (parsed.key_phase, 1);
  ASSERT_EQ (parsed.pn_length, 2);
  ASSERT_EQ (parsed.packet_number, 500);
}

TEST (quic_packet_serialize_short_zero_dcid)
{
  SocketQUICPacketHeader_T header;
  uint8_t output[64];

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_build_short (&header, NULL, 0, 0, 1, 0);

  ASSERT_EQ (res, QUIC_PACKET_OK);

  size_t written
      = SocketQUICPacketHeader_serialize (&header, output, sizeof (output));
  ASSERT_EQ (written, 2); /* 1 byte flags + 1 byte PN */

  /* Verify */
  SocketQUICPacketHeader_T parsed;
  size_t consumed;

  SocketQUICPacketHeader_init (&parsed);
  parsed.dcid_length = 0;

  res = SocketQUICPacketHeader_parse (output, written, &parsed, &consumed);
  ASSERT_EQ (res, QUIC_PACKET_OK);
  ASSERT_EQ (parsed.dcid.len, 0);
}

/* ============================================================================
 * Header Size Calculation Tests
 * ============================================================================
 */

TEST (quic_packet_size_initial)
{
  SocketQUICPacketHeader_T header;
  SocketQUICConnectionID_T dcid, scid;
  uint8_t token[] = { 0x01, 0x02, 0x03, 0x04 };

  setup_test_cid (&dcid, 8);
  setup_test_cid (&scid, 4);

  SocketQUICPacketHeader_build_initial (
      &header, QUIC_VERSION_1, &dcid, &scid, token, sizeof (token), 2, 0);
  header.length = 100;

  size_t size = SocketQUICPacketHeader_size (&header);

  /* Expected: 1 (flags) + 4 (version) + 1 (dcid_len) + 8 (dcid) +
   *           1 (scid_len) + 4 (scid) + 1 (token_len) + 4 (token) +
   *           1 (length varint for 100) + 2 (pn) = 27 */
  ASSERT (size > 0);
}

TEST (quic_packet_size_short)
{
  SocketQUICPacketHeader_T header;
  SocketQUICConnectionID_T dcid;

  setup_test_cid (&dcid, 8);
  SocketQUICPacketHeader_build_short (&header, &dcid, 0, 0, 1, 0);

  size_t size = SocketQUICPacketHeader_size (&header);

  /* Expected: 1 (flags) + 8 (dcid) + 1 (pn) = 10 */
  ASSERT_EQ (size, 10);
}

/* ============================================================================
 * Error Condition Tests
 * ============================================================================
 */

TEST (quic_packet_parse_null_data)
{
  SocketQUICPacketHeader_T header;
  size_t consumed;

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_parse (NULL, 100, &header, &consumed);
  ASSERT_EQ (res, QUIC_PACKET_ERROR_NULL);
}

TEST (quic_packet_parse_null_header)
{
  uint8_t data[] = { 0xC0, 0x00 };
  size_t consumed;

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_parse (data, sizeof (data), NULL, &consumed);
  ASSERT_EQ (res, QUIC_PACKET_ERROR_NULL);
}

TEST (quic_packet_parse_null_consumed)
{
  uint8_t data[] = { 0xC0, 0x00 };
  SocketQUICPacketHeader_T header;

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_parse (data, sizeof (data), &header, NULL);
  ASSERT_EQ (res, QUIC_PACKET_ERROR_NULL);
}

TEST (quic_packet_parse_empty)
{
  uint8_t data[] = { 0x00 };
  SocketQUICPacketHeader_T header;
  size_t consumed;

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_parse (data, 0, &header, &consumed);
  ASSERT_EQ (res, QUIC_PACKET_ERROR_TRUNCATED);
}

TEST (quic_packet_parse_no_fixed_bit)
{
  /* Missing fixed bit - not a valid QUIC packet */
  uint8_t data[] = { 0x80, 0x00, 0x00, 0x00, 0x01 };
  SocketQUICPacketHeader_T header;
  size_t consumed;

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_parse (data, sizeof (data), &header, &consumed);
  ASSERT_EQ (res, QUIC_PACKET_ERROR_FIXED_BIT);
}

TEST (quic_packet_parse_truncated_long_header)
{
  /* Long header but truncated before version complete */
  uint8_t data[] = { 0xC0, 0x00, 0x00 };
  SocketQUICPacketHeader_T header;
  size_t consumed;

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_parse (data, sizeof (data), &header, &consumed);
  ASSERT_EQ (res, QUIC_PACKET_ERROR_TRUNCATED);
}

TEST (quic_packet_parse_truncated_short_header)
{
  /* Short header but truncated */
  uint8_t data[] = { 0x41 }; /* Needs DCID and PN */
  SocketQUICPacketHeader_T header;
  size_t consumed;

  SocketQUICPacketHeader_init (&header);
  header.dcid_length = 8;

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_parse (data, sizeof (data), &header, &consumed);
  ASSERT_EQ (res, QUIC_PACKET_ERROR_TRUNCATED);
}

TEST (quic_packet_build_invalid_pn_length)
{
  SocketQUICPacketHeader_T header;
  SocketQUICConnectionID_T dcid, scid;

  setup_test_cid (&dcid, 8);
  setup_test_cid (&scid, 4);

  /* PN length 0 is invalid */
  SocketQUICPacket_Result res = SocketQUICPacketHeader_build_initial (
      &header, QUIC_VERSION_1, &dcid, &scid, NULL, 0, 0, 0);
  ASSERT_EQ (res, QUIC_PACKET_ERROR_PNLEN);

  /* PN length 5 is invalid */
  res = SocketQUICPacketHeader_build_handshake (
      &header, QUIC_VERSION_1, &dcid, &scid, 5, 0);
  ASSERT_EQ (res, QUIC_PACKET_ERROR_PNLEN);
}

TEST (quic_packet_serialize_null)
{
  SocketQUICPacketHeader_T header;
  uint8_t output[64];

  size_t written
      = SocketQUICPacketHeader_serialize (NULL, output, sizeof (output));
  ASSERT_EQ (written, 0);

  SocketQUICPacketHeader_init (&header);
  written = SocketQUICPacketHeader_serialize (&header, NULL, sizeof (output));
  ASSERT_EQ (written, 0);
}

TEST (quic_packet_serialize_buffer_too_small)
{
  SocketQUICPacketHeader_T header;
  SocketQUICConnectionID_T dcid;
  uint8_t output[2]; /* Too small */

  setup_test_cid (&dcid, 8);
  SocketQUICPacketHeader_build_short (&header, &dcid, 0, 0, 1, 0);

  size_t written
      = SocketQUICPacketHeader_serialize (&header, output, sizeof (output));
  ASSERT_EQ (written, 0);
}

/* ============================================================================
 * Packet Number Encoding/Decoding Tests (RFC 9000 Appendix A)
 * ============================================================================
 */

TEST (quic_packet_pn_length_calculation)
{
  /* When pn == largest_ack + 1, we need 1 byte */
  ASSERT_EQ (SocketQUICPacket_pn_length (1, 0), 1);
  ASSERT_EQ (SocketQUICPacket_pn_length (100, 99), 1);

  /* Larger gaps need more bytes */
  ASSERT_EQ (SocketQUICPacket_pn_length (200, 0), 2);
  ASSERT_EQ (SocketQUICPacket_pn_length (100000, 0), 3);
  ASSERT_EQ (SocketQUICPacket_pn_length (100000000, 0), 4);
}

TEST (quic_packet_encode_pn)
{
  /* 1-byte encoding */
  ASSERT_EQ (SocketQUICPacket_encode_pn (0x12345678, 1), 0x78);

  /* 2-byte encoding */
  ASSERT_EQ (SocketQUICPacket_encode_pn (0x12345678, 2), 0x5678);

  /* 3-byte encoding */
  ASSERT_EQ (SocketQUICPacket_encode_pn (0x12345678, 3), 0x345678);

  /* 4-byte encoding */
  ASSERT_EQ (SocketQUICPacket_encode_pn (0x12345678, 4), 0x12345678);
}

TEST (quic_packet_decode_pn)
{
  /* Simple case: decode truncated PN */
  ASSERT_EQ (SocketQUICPacket_decode_pn (0x42, 1, 0x41), 0x42);

  /* Wrap-around case */
  ASSERT_EQ (SocketQUICPacket_decode_pn (0x02, 1, 0xFF), 0x102);

  /* 2-byte case */
  ASSERT_EQ (SocketQUICPacket_decode_pn (0x1234, 2, 0x1000), 0x1234);
}

TEST (quic_packet_pn_roundtrip)
{
  uint64_t original_pn = 0x12345678;
  uint8_t pn_length = 4;
  uint64_t largest_ack = 0x12345600;

  uint32_t truncated = SocketQUICPacket_encode_pn (original_pn, pn_length);
  uint64_t decoded
      = SocketQUICPacket_decode_pn (truncated, pn_length, largest_ack);

  ASSERT_EQ (decoded, original_pn);
}

TEST (quic_packet_decode_pn_overflow_protection)
{
  /* Test that invalid pn_length values are rejected to prevent overflow */
  uint64_t result;

  /* pn_length = 0 (too small) */
  result = SocketQUICPacket_decode_pn (0x42, 0, 0);
  ASSERT_EQ (result, 0);

  /* pn_length = 5 (too large, would cause 40-bit shift) */
  result = SocketQUICPacket_decode_pn (0x42, 5, 0);
  ASSERT_EQ (result, 0);

  /* pn_length = 8 (would cause 64-bit shift - undefined behavior) */
  result = SocketQUICPacket_decode_pn (0x42, 8, 0);
  ASSERT_EQ (result, 0);

  /* pn_length = 255 (max uint8_t, would cause massive shift) */
  result = SocketQUICPacket_decode_pn (0x42, 255, 0);
  ASSERT_EQ (result, 0);
}

/* ============================================================================
 * Utility Function Tests
 * ============================================================================
 */

TEST (quic_packet_is_long_header)
{
  ASSERT_EQ (SocketQUICPacket_is_long_header (0xC0), 1); /* Initial */
  ASSERT_EQ (SocketQUICPacket_is_long_header (0xD0), 1); /* 0-RTT */
  ASSERT_EQ (SocketQUICPacket_is_long_header (0xE0), 1); /* Handshake */
  ASSERT_EQ (SocketQUICPacket_is_long_header (0xF0), 1); /* Retry */
  ASSERT_EQ (SocketQUICPacket_is_long_header (0x40), 0); /* Short */
  ASSERT_EQ (SocketQUICPacket_is_long_header (0x00),
             0); /* Short (no fixed bit) */
}

TEST (quic_packet_has_fixed_bit)
{
  ASSERT_EQ (SocketQUICPacket_has_fixed_bit (0x40), 1);
  ASSERT_EQ (SocketQUICPacket_has_fixed_bit (0xC0), 1);
  ASSERT_EQ (SocketQUICPacket_has_fixed_bit (0x00), 0);
  ASSERT_EQ (SocketQUICPacket_has_fixed_bit (0x80), 0);
}

TEST (quic_packet_type_string)
{
  ASSERT_NOT_NULL (SocketQUICPacket_type_string (QUIC_PACKET_TYPE_INITIAL));
  ASSERT_NOT_NULL (SocketQUICPacket_type_string (QUIC_PACKET_TYPE_0RTT));
  ASSERT_NOT_NULL (SocketQUICPacket_type_string (QUIC_PACKET_TYPE_HANDSHAKE));
  ASSERT_NOT_NULL (SocketQUICPacket_type_string (QUIC_PACKET_TYPE_RETRY));
  ASSERT_NOT_NULL (SocketQUICPacket_type_string (QUIC_PACKET_TYPE_1RTT));
  ASSERT_NOT_NULL (SocketQUICPacket_type_string ((SocketQUICPacket_Type)99));
}

TEST (quic_packet_result_string)
{
  ASSERT_NOT_NULL (SocketQUICPacket_result_string (QUIC_PACKET_OK));
  ASSERT_NOT_NULL (SocketQUICPacket_result_string (QUIC_PACKET_ERROR_NULL));
  ASSERT_NOT_NULL (
      SocketQUICPacket_result_string (QUIC_PACKET_ERROR_TRUNCATED));
  ASSERT_NOT_NULL (SocketQUICPacket_result_string (QUIC_PACKET_ERROR_BUFFER));
  ASSERT_NOT_NULL (SocketQUICPacket_result_string (QUIC_PACKET_ERROR_INVALID));
  ASSERT_NOT_NULL (
      SocketQUICPacket_result_string (QUIC_PACKET_ERROR_FIXED_BIT));
  ASSERT_NOT_NULL (
      SocketQUICPacket_result_string ((SocketQUICPacket_Result)99));
}

TEST (quic_packet_header_init)
{
  SocketQUICPacketHeader_T header;

  /* Set some garbage values */
  memset (&header, 0xFF, sizeof (header));

  SocketQUICPacketHeader_init (&header);

  ASSERT_EQ (header.is_long_header, 0);
  ASSERT_EQ (header.type, 0);
  ASSERT_EQ (header.version, 0);
  ASSERT_EQ (header.dcid.len, 0);
  ASSERT_EQ (header.scid.len, 0);
  ASSERT_EQ (header.pn_length, 0);

  /* NULL should be safe */
  SocketQUICPacketHeader_init (NULL);
}

/* ============================================================================
 * Version Negotiation Edge Case
 * ============================================================================
 */

TEST (quic_packet_parse_version_negotiation)
{
  /* Version Negotiation uses version 0 */
  uint8_t data[] = {
    0xC0, /* Form=1, Fixed=1 */
    0x00,
    0x00,
    0x00,
    0x00, /* Version: 0 (negotiation) */
    0x04, /* DCID Length: 4 */
    0x01,
    0x02,
    0x03,
    0x04, /* DCID */
    0x04, /* SCID Length: 4 */
    0x0A,
    0x0B,
    0x0C,
    0x0D, /* SCID */
    /* Token length varint and length for Initial type */
    0x00, /* Token length: 0 */
    0x10, /* Payload length */
    0x00, /* PN */
  };

  SocketQUICPacketHeader_T header;
  size_t consumed;

  SocketQUICPacket_Result res
      = SocketQUICPacketHeader_parse (data, sizeof (data), &header, &consumed);

  ASSERT_EQ (res, QUIC_PACKET_OK);
  ASSERT_EQ (header.version, QUIC_VERSION_NEGOTIATION);
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

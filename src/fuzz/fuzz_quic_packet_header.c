/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_packet_header.c - libFuzzer for QUIC Packet Header (RFC 9000)
 *
 * Fuzzes QUIC packet header parsing and serialization (RFC 9000 Section 17).
 * Tests long and short header formats, packet types, and roundtrip
 * verification.
 *
 * Targets:
 * - Long header parsing (Initial, 0-RTT, Handshake, Retry)
 * - Short header parsing (1-RTT)
 * - Header form detection
 * - Fixed bit validation
 * - Connection ID handling
 * - Packet number encoding/decoding
 * - Roundtrip verification
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make
 * fuzz_quic_packet_header
 * ./fuzz_quic_packet_header -fork=16 -max_len=1024
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICPacket.h"
#include "quic/SocketQUICVersion.h"

/**
 * @brief Operations to fuzz
 */
enum FuzzOp
{
  OP_PARSE_LONG_HEADER = 0,
  OP_PARSE_SHORT_HEADER,
  OP_BUILD_INITIAL,
  OP_BUILD_HANDSHAKE,
  OP_BUILD_0RTT,
  OP_BUILD_SHORT,
  OP_ROUNDTRIP_INITIAL,
  OP_ROUNDTRIP_HANDSHAKE,
  OP_ROUNDTRIP_SHORT,
  OP_PN_ENCODE_DECODE,
  OP_TYPE_DETECTION,
  OP_HEADER_SIZE,
  OP_MAX
};

/**
 * @brief Read 32-bit value from byte array (little-endian)
 */
static uint32_t
read_u32 (const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/**
 * @brief Read 64-bit value from byte array (little-endian)
 */
static uint64_t
read_u64 (const uint8_t *p)
{
  return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[7] << 56);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 17)
    return 0;

  uint8_t op = data[0] % OP_MAX;
  uint32_t val32 = read_u32 (data + 1);
  uint64_t val64 = read_u64 (data + 5);

  SocketQUICPacket_Result res;
  SocketQUICPacketHeader_T header;
  size_t consumed = 0;
  uint8_t output[256];

  switch (op)
    {
    case OP_PARSE_LONG_HEADER:
      {
        /* Try parsing as long header packet */
        if (size > 17)
          {
            SocketQUICPacketHeader_init (&header);
            res = SocketQUICPacketHeader_parse (
                data + 17, size - 17, &header, &consumed);
            (void)res;
            (void)header.type;
            (void)header.version;
            (void)header.dcid.len;
            (void)header.scid.len;
          }
      }
      break;

    case OP_PARSE_SHORT_HEADER:
      {
        /* Try parsing as short header packet */
        if (size > 17)
          {
            SocketQUICPacketHeader_init (&header);
            /* Set expected DCID length for short header parsing */
            header.dcid_length = data[13] % 21; /* 0-20 bytes */
            res = SocketQUICPacketHeader_parse (
                data + 17, size - 17, &header, &consumed);
            (void)res;
            (void)header.spin_bit;
            (void)header.key_phase;
          }
      }
      break;

    case OP_BUILD_INITIAL:
      {
        /* Build an Initial packet header */
        SocketQUICPacketHeader_init (&header);

        /* Create connection IDs from fuzz data */
        SocketQUICConnectionID_T dcid = { 0 };
        SocketQUICConnectionID_T scid = { 0 };
        dcid.len = data[13] % 21;
        scid.len = data[14] % 21;
        if (dcid.len > 0 && size > 17 + dcid.len)
          memcpy (dcid.data, data + 17, dcid.len);
        if (scid.len > 0 && size > 17 + dcid.len + scid.len)
          memcpy (scid.data, data + 17 + dcid.len, scid.len);

        uint8_t pn_length = (data[15] % 4) + 1;
        uint32_t pn = val32 % 0x3FFFFFFF;

        res = SocketQUICPacketHeader_build_initial (
            &header, QUIC_VERSION_1, &dcid, &scid, NULL, 0, pn_length, pn);
        (void)res;

        /* Serialize if build succeeded */
        if (res == QUIC_PACKET_OK)
          {
            size_t header_size = SocketQUICPacketHeader_size (&header);
            (void)header_size;
            size_t written = SocketQUICPacketHeader_serialize (
                &header, output, sizeof (output));
            (void)written;
          }
      }
      break;

    case OP_BUILD_HANDSHAKE:
      {
        SocketQUICPacketHeader_init (&header);

        SocketQUICConnectionID_T dcid = { 0 };
        SocketQUICConnectionID_T scid = { 0 };
        dcid.len = data[13] % 21;
        scid.len = data[14] % 21;

        uint8_t pn_length = (data[15] % 4) + 1;
        uint32_t pn = val32 % 0x3FFFFFFF;

        res = SocketQUICPacketHeader_build_handshake (
            &header, QUIC_VERSION_1, &dcid, &scid, pn_length, pn);
        (void)res;

        if (res == QUIC_PACKET_OK)
          {
            size_t written = SocketQUICPacketHeader_serialize (
                &header, output, sizeof (output));
            (void)written;
          }
      }
      break;

    case OP_BUILD_0RTT:
      {
        SocketQUICPacketHeader_init (&header);

        SocketQUICConnectionID_T dcid = { 0 };
        SocketQUICConnectionID_T scid = { 0 };
        dcid.len = data[13] % 21;
        scid.len = data[14] % 21;

        uint8_t pn_length = (data[15] % 4) + 1;
        uint32_t pn = val32 % 0x3FFFFFFF;

        res = SocketQUICPacketHeader_build_0rtt (
            &header, QUIC_VERSION_1, &dcid, &scid, pn_length, pn);
        (void)res;

        if (res == QUIC_PACKET_OK)
          {
            size_t written = SocketQUICPacketHeader_serialize (
                &header, output, sizeof (output));
            (void)written;
          }
      }
      break;

    case OP_BUILD_SHORT:
      {
        SocketQUICPacketHeader_init (&header);

        SocketQUICConnectionID_T dcid = { 0 };
        dcid.len = data[13] % 21;

        int spin_bit = data[14] & 1;
        int key_phase = (data[14] >> 1) & 1;
        uint8_t pn_length = (data[15] % 4) + 1;
        uint32_t pn = val32 % 0x3FFFFFFF;

        res = SocketQUICPacketHeader_build_short (
            &header, &dcid, spin_bit, key_phase, pn_length, pn);
        (void)res;

        if (res == QUIC_PACKET_OK)
          {
            size_t written = SocketQUICPacketHeader_serialize (
                &header, output, sizeof (output));
            (void)written;
          }
      }
      break;

    case OP_ROUNDTRIP_INITIAL:
      {
        /* Build, serialize, then parse Initial packet */
        SocketQUICPacketHeader_init (&header);

        SocketQUICConnectionID_T dcid = { 0 };
        SocketQUICConnectionID_T scid = { 0 };
        dcid.len = (data[13] % 8) + 4; /* 4-11 bytes */
        scid.len = (data[14] % 8) + 4;

        uint8_t pn_length = (data[15] % 4) + 1;
        uint32_t pn = val32 % 0xFFFF;

        res = SocketQUICPacketHeader_build_initial (
            &header, QUIC_VERSION_1, &dcid, &scid, NULL, 0, pn_length, pn);

        if (res == QUIC_PACKET_OK)
          {
            size_t written = SocketQUICPacketHeader_serialize (
                &header, output, sizeof (output));
            if (written > 0)
              {
                SocketQUICPacketHeader_T parsed;
                SocketQUICPacketHeader_init (&parsed);
                res = SocketQUICPacketHeader_parse (
                    output, written, &parsed, &consumed);
                (void)parsed.type;
                (void)parsed.is_long_header;
              }
          }
        (void)res;
      }
      break;

    case OP_ROUNDTRIP_HANDSHAKE:
      {
        SocketQUICPacketHeader_init (&header);

        SocketQUICConnectionID_T dcid = { 0 };
        SocketQUICConnectionID_T scid = { 0 };
        dcid.len = (data[13] % 8) + 4;
        scid.len = (data[14] % 8) + 4;

        uint8_t pn_length = (data[15] % 4) + 1;
        uint32_t pn = val32 % 0xFFFF;

        res = SocketQUICPacketHeader_build_handshake (
            &header, QUIC_VERSION_1, &dcid, &scid, pn_length, pn);

        if (res == QUIC_PACKET_OK)
          {
            size_t written = SocketQUICPacketHeader_serialize (
                &header, output, sizeof (output));
            if (written > 0)
              {
                SocketQUICPacketHeader_T parsed;
                SocketQUICPacketHeader_init (&parsed);
                res = SocketQUICPacketHeader_parse (
                    output, written, &parsed, &consumed);
                (void)parsed.type;
              }
          }
        (void)res;
      }
      break;

    case OP_ROUNDTRIP_SHORT:
      {
        SocketQUICPacketHeader_init (&header);

        SocketQUICConnectionID_T dcid = { 0 };
        dcid.len = (data[13] % 8) + 4;

        int spin_bit = data[14] & 1;
        int key_phase = (data[14] >> 1) & 1;
        uint8_t pn_length = (data[15] % 4) + 1;
        uint32_t pn = val32 % 0xFFFF;

        res = SocketQUICPacketHeader_build_short (
            &header, &dcid, spin_bit, key_phase, pn_length, pn);

        if (res == QUIC_PACKET_OK)
          {
            size_t written = SocketQUICPacketHeader_serialize (
                &header, output, sizeof (output));
            if (written > 0)
              {
                SocketQUICPacketHeader_T parsed;
                SocketQUICPacketHeader_init (&parsed);
                parsed.dcid_length = dcid.len; /* Required for short header */
                res = SocketQUICPacketHeader_parse (
                    output, written, &parsed, &consumed);
                (void)parsed.spin_bit;
                (void)parsed.key_phase;
              }
          }
        (void)res;
      }
      break;

    case OP_PN_ENCODE_DECODE:
      {
        /* Test packet number encoding and decoding */
        uint64_t pn = (val64 % 0x3FFFFFFFFFFF) + 1; /* Ensure non-zero */
        uint64_t largest_ack = (val32 % pn) + 1;

        for (uint8_t pn_len = 1; pn_len <= 4; pn_len++)
          {
            uint32_t truncated = SocketQUICPacket_encode_pn (pn, pn_len);
            uint64_t decoded
                = SocketQUICPacket_decode_pn (truncated, pn_len, largest_ack);
            (void)decoded;
          }

        /* Test pn_length calculation */
        uint8_t required_len = SocketQUICPacket_pn_length (pn, largest_ack);
        (void)required_len;
      }
      break;

    case OP_TYPE_DETECTION:
      {
        /* Test header form and type detection on all input bytes */
        for (size_t i = 0; i < size && i < 256; i++)
          {
            int is_long = SocketQUICPacket_is_long_header (data[i]);
            int has_fixed = SocketQUICPacket_has_fixed_bit (data[i]);
            (void)is_long;
            (void)has_fixed;

            if (is_long)
              {
                SocketQUICPacket_Type type
                    = SocketQUICPacket_parse_long_type (data[i]);
                (void)type;
              }
          }
      }
      break;

    case OP_HEADER_SIZE:
      {
        /* Test header size calculation for various configurations */
        SocketQUICPacketHeader_init (&header);
        header.is_long_header = data[13] & 1;
        header.type = (SocketQUICPacket_Type)(data[14] % 5);
        header.dcid.len = data[15] % 21;
        header.scid.len = (data[16] % 21);
        header.pn_length = (data[13] % 4) + 1;

        size_t hdr_size = SocketQUICPacketHeader_size (&header);
        (void)hdr_size;
      }
      break;

    default:
      break;
    }

  /* Always try to parse raw fuzz data as a packet header */
  if (size > 1)
    {
      SocketQUICPacketHeader_init (&header);
      header.dcid_length = 8; /* Assume 8-byte DCID for short header */
      res = SocketQUICPacketHeader_parse (data, size, &header, &consumed);
      (void)res;
      (void)header.type;
    }

  /* Test string functions */
  {
    const char *s1 = SocketQUICPacket_type_string (QUIC_PACKET_TYPE_INITIAL);
    const char *s2 = SocketQUICPacket_type_string (QUIC_PACKET_TYPE_RETRY);
    const char *s3 = SocketQUICPacket_result_string (QUIC_PACKET_OK);
    const char *s4 = SocketQUICPacket_result_string (QUIC_PACKET_ERROR_INVALID);
    (void)s1;
    (void)s2;
    (void)s3;
    (void)s4;
  }

  /* NULL pointer tests */
  {
    res = SocketQUICPacketHeader_parse (NULL, 0, &header, &consumed);
    (void)res;

    res = SocketQUICPacketHeader_parse (data, size, NULL, &consumed);
    (void)res;

    size_t sz = SocketQUICPacketHeader_size (NULL);
    (void)sz;

    sz = SocketQUICPacketHeader_serialize (NULL, output, sizeof (output));
    (void)sz;

    sz = SocketQUICPacketHeader_serialize (&header, NULL, 0);
    (void)sz;
  }

  return 0;
}

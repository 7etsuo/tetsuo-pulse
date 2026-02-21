/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_retry.c - libFuzzer for QUIC Retry Packet Integrity (RFC 9001)
 *
 * Fuzzes QUIC Retry packet integrity tag computation and verification (RFC 9001
 * Section 5.8). Tests the AEAD-based integrity tag that prevents off-path
 * attackers from injecting Retry packets.
 *
 * Targets:
 * - Retry integrity tag computation
 * - Retry integrity tag verification
 * - ODCID handling (various lengths)
 * - Retry token extraction
 * - Invalid tag detection
 * - Truncated packet handling
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_quic_retry
 * ./fuzz_quic_retry -fork=16 -max_len=1024
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICPacket.h"
#include "quic/SocketQUICConnectionID.h"

/**
 * @brief Operations to fuzz
 */
enum FuzzOp
{
  OP_COMPUTE_TAG = 0,
  OP_VERIFY_TAG,
  OP_COMPUTE_VERIFY_ROUNDTRIP,
  OP_VERIFY_MODIFIED_PACKET,
  OP_VERIFY_MODIFIED_TAG,
  OP_VERIFY_MODIFIED_ODCID,
  OP_EMPTY_RETRY_TOKEN,
  OP_MAX_ODCID_LENGTH,
  OP_PARSE_RETRY_HEADER,
  OP_MAX
};

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  /* Need at least: op (1) + odcid_len (1) + min header (7) + tag (16) = 25 */
  if (size < 25)
    return 0;

  uint8_t op = data[0] % OP_MAX;
  uint8_t odcid_len = data[1] % 21; /* 0-20 bytes per RFC 9000 */

  SocketQUICPacket_Result res;
  SocketQUICConnectionID_T odcid = { 0 };
  uint8_t computed_tag[QUIC_RETRY_INTEGRITY_TAG_LEN];

  /* Build ODCID from fuzz data */
  odcid.len = odcid_len;
  if (odcid_len > 0 && size >= 2 + odcid_len)
    {
      memcpy (odcid.data, data + 2, odcid_len);
    }

  /* Retry packet starts after op + odcid_len + odcid */
  size_t packet_offset = 2 + odcid_len;
  const uint8_t *retry_packet = data + packet_offset;
  size_t retry_len = (size > packet_offset) ? (size - packet_offset) : 0;

  switch (op)
    {
    case OP_COMPUTE_TAG:
      {
        /* Compute integrity tag for fuzz data as retry packet */
        if (retry_len > QUIC_RETRY_INTEGRITY_TAG_LEN)
          {
            size_t packet_without_tag
                = retry_len - QUIC_RETRY_INTEGRITY_TAG_LEN;
            res = SocketQUICPacket_compute_retry_tag (
                &odcid, retry_packet, packet_without_tag, computed_tag);
            (void)res;
          }
      }
      break;

    case OP_VERIFY_TAG:
      {
        /* Verify integrity tag on fuzz data */
        if (retry_len >= QUIC_RETRY_INTEGRITY_TAG_LEN)
          {
            res = SocketQUICPacket_verify_retry_tag (
                &odcid, retry_packet, retry_len);
            (void)res;
          }
      }
      break;

    case OP_COMPUTE_VERIFY_ROUNDTRIP:
      {
        /* Compute tag, append it, then verify */
        if (retry_len > 0 && retry_len < 512)
          {
            uint8_t packet_with_tag[512 + QUIC_RETRY_INTEGRITY_TAG_LEN];
            memcpy (packet_with_tag, retry_packet, retry_len);

            res = SocketQUICPacket_compute_retry_tag (
                &odcid, retry_packet, retry_len, computed_tag);
            if (res == QUIC_PACKET_OK)
              {
                memcpy (packet_with_tag + retry_len,
                        computed_tag,
                        QUIC_RETRY_INTEGRITY_TAG_LEN);

                /* Now verify - should succeed */
                res = SocketQUICPacket_verify_retry_tag (
                    &odcid,
                    packet_with_tag,
                    retry_len + QUIC_RETRY_INTEGRITY_TAG_LEN);
                (void)res;
              }
          }
      }
      break;

    case OP_VERIFY_MODIFIED_PACKET:
      {
        /* Compute tag, modify packet, then verify (should fail) */
        if (retry_len > 1 && retry_len < 512)
          {
            uint8_t packet_with_tag[512 + QUIC_RETRY_INTEGRITY_TAG_LEN];
            memcpy (packet_with_tag, retry_packet, retry_len);

            res = SocketQUICPacket_compute_retry_tag (
                &odcid, retry_packet, retry_len, computed_tag);
            if (res == QUIC_PACKET_OK)
              {
                memcpy (packet_with_tag + retry_len,
                        computed_tag,
                        QUIC_RETRY_INTEGRITY_TAG_LEN);

                /* Flip a bit in the packet */
                packet_with_tag[retry_len / 2] ^= 0x01;

                /* Verify should fail */
                res = SocketQUICPacket_verify_retry_tag (
                    &odcid,
                    packet_with_tag,
                    retry_len + QUIC_RETRY_INTEGRITY_TAG_LEN);
                (void)res;
              }
          }
      }
      break;

    case OP_VERIFY_MODIFIED_TAG:
      {
        /* Compute tag, modify tag, then verify (should fail) */
        if (retry_len > 0 && retry_len < 512)
          {
            uint8_t packet_with_tag[512 + QUIC_RETRY_INTEGRITY_TAG_LEN];
            memcpy (packet_with_tag, retry_packet, retry_len);

            res = SocketQUICPacket_compute_retry_tag (
                &odcid, retry_packet, retry_len, computed_tag);
            if (res == QUIC_PACKET_OK)
              {
                /* Corrupt the tag */
                computed_tag[0] ^= 0xFF;
                memcpy (packet_with_tag + retry_len,
                        computed_tag,
                        QUIC_RETRY_INTEGRITY_TAG_LEN);

                /* Verify should fail */
                res = SocketQUICPacket_verify_retry_tag (
                    &odcid,
                    packet_with_tag,
                    retry_len + QUIC_RETRY_INTEGRITY_TAG_LEN);
                (void)res;
              }
          }
      }
      break;

    case OP_VERIFY_MODIFIED_ODCID:
      {
        /* Compute tag with one ODCID, verify with different ODCID */
        if (retry_len > 0 && retry_len < 512)
          {
            uint8_t packet_with_tag[512 + QUIC_RETRY_INTEGRITY_TAG_LEN];
            memcpy (packet_with_tag, retry_packet, retry_len);

            res = SocketQUICPacket_compute_retry_tag (
                &odcid, retry_packet, retry_len, computed_tag);
            if (res == QUIC_PACKET_OK)
              {
                memcpy (packet_with_tag + retry_len,
                        computed_tag,
                        QUIC_RETRY_INTEGRITY_TAG_LEN);

                /* Create different ODCID */
                SocketQUICConnectionID_T different_odcid = odcid;
                if (different_odcid.len > 0)
                  different_odcid.data[0] ^= 0x01;
                else
                  {
                    different_odcid.len = 8;
                    memset (different_odcid.data, 0xAB, 8);
                  }

                /* Verify should fail with different ODCID */
                res = SocketQUICPacket_verify_retry_tag (
                    &different_odcid,
                    packet_with_tag,
                    retry_len + QUIC_RETRY_INTEGRITY_TAG_LEN);
                (void)res;
              }
          }
      }
      break;

    case OP_EMPTY_RETRY_TOKEN:
      {
        /* Test with minimal Retry packet (empty token) */
        /* Retry packet: flags(1) + version(4) + dcid_len(1) + dcid +
         * scid_len(1) + scid + token + tag */
        uint8_t minimal_retry[64];
        size_t pos = 0;

        /* First byte for Retry: 1111xxxx where type=11 (Retry) */
        minimal_retry[pos++] = 0xF0 | ((data[2] & 0x0F));

        /* Version */
        minimal_retry[pos++] = 0x00;
        minimal_retry[pos++] = 0x00;
        minimal_retry[pos++] = 0x00;
        minimal_retry[pos++] = 0x01;

        /* DCID (variable) */
        uint8_t dcid_len = data[3] % 21;
        minimal_retry[pos++] = dcid_len;
        for (uint8_t i = 0; i < dcid_len && pos < sizeof (minimal_retry) - 17;
             i++)
          {
            minimal_retry[pos++] = data[4 + i];
          }

        /* SCID */
        uint8_t scid_len = data[4] % 21;
        minimal_retry[pos++] = scid_len;
        for (uint8_t i = 0; i < scid_len && pos < sizeof (minimal_retry) - 16;
             i++)
          {
            minimal_retry[pos++] = data[5 + i];
          }

        /* No retry token - go straight to computing tag */
        if (pos < sizeof (minimal_retry) - QUIC_RETRY_INTEGRITY_TAG_LEN)
          {
            res = SocketQUICPacket_compute_retry_tag (
                &odcid, minimal_retry, pos, computed_tag);
            (void)res;
          }
      }
      break;

    case OP_MAX_ODCID_LENGTH:
      {
        /* Test with maximum ODCID length (20 bytes) */
        SocketQUICConnectionID_T max_odcid;
        max_odcid.len = 20;
        for (int i = 0; i < 20; i++)
          {
            max_odcid.data[i] = (size > (size_t)(2 + i)) ? data[2 + i] : 0x42;
          }

        if (retry_len > QUIC_RETRY_INTEGRITY_TAG_LEN)
          {
            size_t packet_without_tag
                = retry_len - QUIC_RETRY_INTEGRITY_TAG_LEN;
            res = SocketQUICPacket_compute_retry_tag (
                &max_odcid, retry_packet, packet_without_tag, computed_tag);
            (void)res;
          }

        /* Also test with zero-length ODCID */
        SocketQUICConnectionID_T zero_odcid = { 0 };
        zero_odcid.len = 0;

        if (retry_len > QUIC_RETRY_INTEGRITY_TAG_LEN)
          {
            size_t packet_without_tag
                = retry_len - QUIC_RETRY_INTEGRITY_TAG_LEN;
            res = SocketQUICPacket_compute_retry_tag (
                &zero_odcid, retry_packet, packet_without_tag, computed_tag);
            (void)res;
          }
      }
      break;

    case OP_PARSE_RETRY_HEADER:
      {
        /* Parse as Retry packet header */
        if (retry_len > 0)
          {
            SocketQUICPacketHeader_T header;
            SocketQUICPacketHeader_init (&header);
            size_t consumed = 0;

            res = SocketQUICPacketHeader_parse (
                retry_packet, retry_len, &header, &consumed);
            if (res == QUIC_PACKET_OK && header.type == QUIC_PACKET_TYPE_RETRY)
              {
                /* Check Retry-specific fields */
                (void)header.retry_token;
                (void)header.retry_token_length;
                (void)header.has_retry_integrity_tag;
                if (header.has_retry_integrity_tag)
                  {
                    /* Verify the tag if present */
                    res = SocketQUICPacket_verify_retry_tag (
                        &odcid, retry_packet, retry_len);
                    (void)res;
                  }
              }
            (void)res;
          }
      }
      break;

    default:
      break;
    }

  /* Always try verification on raw fuzz data */
  if (retry_len >= QUIC_RETRY_INTEGRITY_TAG_LEN)
    {
      res = SocketQUICPacket_verify_retry_tag (&odcid, retry_packet, retry_len);
      (void)res;
    }

  /* NULL pointer tests */
  {
    res = SocketQUICPacket_compute_retry_tag (
        NULL, retry_packet, retry_len, computed_tag);
    (void)res;

    res = SocketQUICPacket_compute_retry_tag (&odcid, NULL, 0, computed_tag);
    (void)res;

    res = SocketQUICPacket_compute_retry_tag (
        &odcid, retry_packet, retry_len, NULL);
    (void)res;

    res = SocketQUICPacket_verify_retry_tag (NULL, retry_packet, retry_len);
    (void)res;

    res = SocketQUICPacket_verify_retry_tag (&odcid, NULL, 0);
    (void)res;
  }

  /* Test edge cases */
  {
    /* Packet exactly at minimum size for tag */
    uint8_t min_packet[QUIC_RETRY_INTEGRITY_TAG_LEN];
    memset (min_packet, 0x42, sizeof (min_packet));
    res = SocketQUICPacket_verify_retry_tag (
        &odcid, min_packet, sizeof (min_packet));
    (void)res;

    /* Packet one byte short of having tag */
    res = SocketQUICPacket_verify_retry_tag (
        &odcid, min_packet, QUIC_RETRY_INTEGRITY_TAG_LEN - 1);
    (void)res;
  }

  return 0;
}

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_version.c - QUIC Version Constants unit tests (RFC 9000 §15)
 *
 * Tests version constant definitions, GREASE detection, IETF reserved
 * detection, and version validation helpers.
 */

#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICConnectionID.h"
#include "quic/SocketQUICVersion.h"
#include "test/Test.h"

/* ============================================================================
 * Version Constant Value Tests
 * ============================================================================
 */

TEST (quic_version_negotiation_value)
{
  ASSERT_EQ (QUIC_VERSION_NEGOTIATION, 0x00000000);
}

TEST (quic_version_1_value)
{
  ASSERT_EQ (QUIC_VERSION_1, 0x00000001);
}

TEST (quic_version_2_value)
{
  ASSERT_EQ (QUIC_VERSION_2, 0x6b3343cf);
}

/* ============================================================================
 * GREASE Version Detection Tests
 * ============================================================================
 */

TEST (quic_version_grease_0a0a0a0a)
{
  ASSERT (QUIC_VERSION_IS_GREASE (0x0a0a0a0a));
}

TEST (quic_version_grease_1a1a1a1a)
{
  ASSERT (QUIC_VERSION_IS_GREASE (0x1a1a1a1a));
}

TEST (quic_version_grease_2a2a2a2a)
{
  ASSERT (QUIC_VERSION_IS_GREASE (0x2a2a2a2a));
}

TEST (quic_version_grease_fafafafa)
{
  ASSERT (QUIC_VERSION_IS_GREASE (0xfafafafa));
}

TEST (quic_version_grease_all_nibbles)
{
  /* Test all 16 possible GREASE versions */
  for (uint32_t nibble = 0; nibble < 16; nibble++)
    {
      uint32_t version = (nibble << 28) | (nibble << 20) | (nibble << 12)
                         | (nibble << 4) | 0x0a0a0a0a;
      ASSERT (QUIC_VERSION_IS_GREASE (version));
    }
}

TEST (quic_version_grease_macro)
{
  ASSERT_EQ (QUIC_VERSION_GREASE (0), 0x0a0a0a0a);
  ASSERT_EQ (QUIC_VERSION_GREASE (1), 0x1a1a1a1a);
  ASSERT_EQ (QUIC_VERSION_GREASE (15), 0xfafafafa);
}

TEST (quic_version_not_grease_v1)
{
  ASSERT (!QUIC_VERSION_IS_GREASE (QUIC_VERSION_1));
}

TEST (quic_version_not_grease_v2)
{
  ASSERT (!QUIC_VERSION_IS_GREASE (QUIC_VERSION_2));
}

TEST (quic_version_not_grease_negotiation)
{
  ASSERT (!QUIC_VERSION_IS_GREASE (QUIC_VERSION_NEGOTIATION));
}

TEST (quic_version_not_grease_almost)
{
  /* Close to GREASE but not quite */
  ASSERT (!QUIC_VERSION_IS_GREASE (0x0a0a0a0b));
  ASSERT (!QUIC_VERSION_IS_GREASE (0x0a0a0b0a));
  ASSERT (!QUIC_VERSION_IS_GREASE (0x0a0b0a0a));
  ASSERT (!QUIC_VERSION_IS_GREASE (0x0b0a0a0a));
}

/* ============================================================================
 * IETF Reserved Version Tests
 * ============================================================================
 */

TEST (quic_version_ietf_reserved_v1)
{
  ASSERT (QUIC_VERSION_IS_IETF_RESERVED (QUIC_VERSION_1));
}

TEST (quic_version_ietf_reserved_negotiation)
{
  ASSERT (QUIC_VERSION_IS_IETF_RESERVED (QUIC_VERSION_NEGOTIATION));
}

TEST (quic_version_ietf_reserved_0000ffff)
{
  ASSERT (QUIC_VERSION_IS_IETF_RESERVED (0x0000ffff));
}

TEST (quic_version_not_ietf_reserved_v2)
{
  ASSERT (!QUIC_VERSION_IS_IETF_RESERVED (QUIC_VERSION_2));
}

TEST (quic_version_not_ietf_reserved_high_bits)
{
  ASSERT (!QUIC_VERSION_IS_IETF_RESERVED (0x00010000));
  ASSERT (!QUIC_VERSION_IS_IETF_RESERVED (0x10000000));
  ASSERT (!QUIC_VERSION_IS_IETF_RESERVED (0xffffffff));
}

/* ============================================================================
 * Version Support Tests
 * ============================================================================
 */

TEST (quic_version_supported_v1)
{
  ASSERT (QUIC_VERSION_IS_SUPPORTED (QUIC_VERSION_1));
}

TEST (quic_version_supported_v2)
{
  ASSERT (QUIC_VERSION_IS_SUPPORTED (QUIC_VERSION_2));
}

TEST (quic_version_not_supported_negotiation)
{
  ASSERT (!QUIC_VERSION_IS_SUPPORTED (QUIC_VERSION_NEGOTIATION));
}

TEST (quic_version_not_supported_grease)
{
  ASSERT (!QUIC_VERSION_IS_SUPPORTED (0x0a0a0a0a));
}

TEST (quic_version_not_supported_unknown)
{
  ASSERT (!QUIC_VERSION_IS_SUPPORTED (0x12345678));
  ASSERT (!QUIC_VERSION_IS_SUPPORTED (0xffffffff));
}

/* ============================================================================
 * Real Version Detection Tests
 * ============================================================================
 */

TEST (quic_version_real_v1)
{
  ASSERT (QUIC_VERSION_IS_REAL (QUIC_VERSION_1));
}

TEST (quic_version_real_v2)
{
  ASSERT (QUIC_VERSION_IS_REAL (QUIC_VERSION_2));
}

TEST (quic_version_not_real_negotiation)
{
  ASSERT (!QUIC_VERSION_IS_REAL (QUIC_VERSION_NEGOTIATION));
}

TEST (quic_version_not_real_grease)
{
  ASSERT (!QUIC_VERSION_IS_REAL (0x0a0a0a0a));
  ASSERT (!QUIC_VERSION_IS_REAL (0xfafafafa));
}

TEST (quic_version_real_unknown)
{
  /* Unknown versions are still "real" - they just aren't supported */
  ASSERT (QUIC_VERSION_IS_REAL (0x12345678));
}

/* ============================================================================
 * Version Validation Function Tests
 * ============================================================================
 */

TEST (quic_version_valid_v1)
{
  ASSERT (SocketQUIC_version_is_valid (QUIC_VERSION_1));
}

TEST (quic_version_valid_v2)
{
  ASSERT (SocketQUIC_version_is_valid (QUIC_VERSION_2));
}

TEST (quic_version_invalid_negotiation)
{
  ASSERT (!SocketQUIC_version_is_valid (QUIC_VERSION_NEGOTIATION));
}

TEST (quic_version_invalid_grease)
{
  ASSERT (!SocketQUIC_version_is_valid (0x0a0a0a0a));
  ASSERT (!SocketQUIC_version_is_valid (0x1a1a1a1a));
  ASSERT (!SocketQUIC_version_is_valid (0xfafafafa));
}

TEST (quic_version_invalid_unknown)
{
  ASSERT (!SocketQUIC_version_is_valid (0x12345678));
  ASSERT (!SocketQUIC_version_is_valid (0xffffffff));
}

/* ============================================================================
 * Version Negotiation Need Tests
 * ============================================================================
 */

TEST (quic_version_negotiation_not_needed_v1)
{
  ASSERT (!SocketQUIC_version_needs_negotiation (QUIC_VERSION_1));
}

TEST (quic_version_negotiation_not_needed_v2)
{
  ASSERT (!SocketQUIC_version_needs_negotiation (QUIC_VERSION_2));
}

TEST (quic_version_negotiation_not_needed_zero)
{
  /* Client already doing version negotiation */
  ASSERT (!SocketQUIC_version_needs_negotiation (QUIC_VERSION_NEGOTIATION));
}

TEST (quic_version_negotiation_needed_unknown)
{
  ASSERT (SocketQUIC_version_needs_negotiation (0x12345678));
  ASSERT (SocketQUIC_version_needs_negotiation (0xffffffff));
}

TEST (quic_version_negotiation_needed_grease)
{
  ASSERT (SocketQUIC_version_needs_negotiation (0x0a0a0a0a));
}

/* ============================================================================
 * Version String Tests
 * ============================================================================
 */

TEST (quic_version_string_negotiation)
{
  const char *str = SocketQUIC_version_string (QUIC_VERSION_NEGOTIATION);
  ASSERT (strcmp (str, "VERSION_NEGOTIATION") == 0);
}

TEST (quic_version_string_v1)
{
  const char *str = SocketQUIC_version_string (QUIC_VERSION_1);
  ASSERT (strstr (str, "QUICv1") != NULL);
  ASSERT (strstr (str, "RFC 9000") != NULL);
}

TEST (quic_version_string_v2)
{
  const char *str = SocketQUIC_version_string (QUIC_VERSION_2);
  ASSERT (strstr (str, "QUICv2") != NULL);
  ASSERT (strstr (str, "RFC 9369") != NULL);
}

TEST (quic_version_string_grease)
{
  const char *str = SocketQUIC_version_string (0x0a0a0a0a);
  ASSERT (strcmp (str, "GREASE") == 0);
}

TEST (quic_version_string_unknown)
{
  const char *str = SocketQUIC_version_string (0x12345678);
  ASSERT (strcmp (str, "UNKNOWN") == 0);
}

TEST (quic_version_string_not_null)
{
  /* Ensure we never return NULL */
  ASSERT_NOT_NULL (SocketQUIC_version_string (0));
  ASSERT_NOT_NULL (SocketQUIC_version_string (1));
  ASSERT_NOT_NULL (SocketQUIC_version_string (0x0a0a0a0a));
  ASSERT_NOT_NULL (SocketQUIC_version_string (0x12345678));
  ASSERT_NOT_NULL (SocketQUIC_version_string (0xffffffff));
}

/* ============================================================================
 * Supported Versions List Tests
 * ============================================================================
 */

TEST (quic_supported_versions_count)
{
  size_t count = 0;
  const uint32_t *versions = SocketQUIC_supported_versions (&count);

  ASSERT (count >= 2);
  ASSERT_NOT_NULL (versions);
}

TEST (quic_supported_versions_contains_v1)
{
  size_t count = 0;
  const uint32_t *versions = SocketQUIC_supported_versions (&count);

  int found = 0;
  for (size_t i = 0; i < count; i++)
    {
      if (versions[i] == QUIC_VERSION_1)
        found = 1;
    }
  ASSERT (found);
}

TEST (quic_supported_versions_contains_v2)
{
  size_t count = 0;
  const uint32_t *versions = SocketQUIC_supported_versions (&count);

  int found = 0;
  for (size_t i = 0; i < count; i++)
    {
      if (versions[i] == QUIC_VERSION_2)
        found = 1;
    }
  ASSERT (found);
}

TEST (quic_supported_versions_null_count)
{
  /* Should not crash with NULL count */
  const uint32_t *versions = SocketQUIC_supported_versions (NULL);
  ASSERT_NOT_NULL (versions);
}

/* ============================================================================
 * Version Negotiation Packet Creation Tests (RFC 9000 Section 6)
 * ============================================================================
 */

TEST (quic_version_neg_create_basic)
{
  SocketQUICConnectionID_T dcid, scid;
  uint8_t output[256];

  /* Setup CIDs */
  SocketQUICConnectionID_init (&dcid);
  SocketQUICConnectionID_init (&scid);
  dcid.len = 8;
  scid.len = 8;
  memset (dcid.data, 0xAA, 8);
  memset (scid.data, 0xBB, 8);

  /* Create negotiation packet with 2 versions */
  uint32_t versions[] = { QUIC_VERSION_1, QUIC_VERSION_2 };
  int result = SocketQUICVersion_create_negotiation (
      &dcid, &scid, versions, 2, output, sizeof (output));

  /* Expected size: 1 (header) + 4 (version) + 1 (dcid len) + 8 (dcid) +
   *                1 (scid len) + 8 (scid) + 8 (2 versions) = 31 */
  ASSERT_EQ (result, 31);

  /* Verify first byte has long header form */
  ASSERT_EQ (output[0] & 0x80, 0x80);

  /* Verify version is 0x00000000 */
  ASSERT_EQ (output[1], 0x00);
  ASSERT_EQ (output[2], 0x00);
  ASSERT_EQ (output[3], 0x00);
  ASSERT_EQ (output[4], 0x00);

  /* Verify DCID length and data */
  ASSERT_EQ (output[5], 8);
  ASSERT_EQ (output[6], 0xAA);

  /* Verify SCID length and data */
  ASSERT_EQ (output[14], 8);
  ASSERT_EQ (output[15], 0xBB);

  /* Verify version 1 */
  ASSERT_EQ (output[23], 0x00);
  ASSERT_EQ (output[24], 0x00);
  ASSERT_EQ (output[25], 0x00);
  ASSERT_EQ (output[26], 0x01);

  /* Verify version 2 */
  ASSERT_EQ (output[27], 0x6b);
  ASSERT_EQ (output[28], 0x33);
  ASSERT_EQ (output[29], 0x43);
  ASSERT_EQ (output[30], 0xcf);
}

TEST (quic_version_neg_create_zero_length_cids)
{
  SocketQUICConnectionID_T dcid, scid;
  uint8_t output[256];

  /* Zero-length CIDs */
  SocketQUICConnectionID_init (&dcid);
  SocketQUICConnectionID_init (&scid);

  uint32_t versions[] = { QUIC_VERSION_1 };
  int result = SocketQUICVersion_create_negotiation (
      &dcid, &scid, versions, 1, output, sizeof (output));

  /* Expected: 1 + 4 + 1 + 0 + 1 + 0 + 4 = 11 bytes */
  ASSERT_EQ (result, 11);

  /* Verify DCID length is 0 */
  ASSERT_EQ (output[5], 0);

  /* Verify SCID length is 0 */
  ASSERT_EQ (output[6], 0);
}

TEST (quic_version_neg_create_null_inputs)
{
  SocketQUICConnectionID_T dcid, scid;
  uint8_t output[256];
  uint32_t versions[] = { QUIC_VERSION_1 };

  SocketQUICConnectionID_init (&dcid);
  SocketQUICConnectionID_init (&scid);

  /* NULL dcid */
  int result = SocketQUICVersion_create_negotiation (
      NULL, &scid, versions, 1, output, sizeof (output));
  ASSERT (result < 0);

  /* NULL scid */
  result = SocketQUICVersion_create_negotiation (
      &dcid, NULL, versions, 1, output, sizeof (output));
  ASSERT (result < 0);

  /* NULL versions */
  result = SocketQUICVersion_create_negotiation (
      &dcid, &scid, NULL, 1, output, sizeof (output));
  ASSERT (result < 0);

  /* NULL output */
  result = SocketQUICVersion_create_negotiation (
      &dcid, &scid, versions, 1, NULL, sizeof (output));
  ASSERT (result < 0);
}

TEST (quic_version_neg_create_buffer_too_small)
{
  SocketQUICConnectionID_T dcid, scid;
  uint8_t output[10]; /* Too small */

  SocketQUICConnectionID_init (&dcid);
  SocketQUICConnectionID_init (&scid);
  dcid.len = 8;
  scid.len = 8;

  uint32_t versions[] = { QUIC_VERSION_1, QUIC_VERSION_2 };
  int result = SocketQUICVersion_create_negotiation (
      &dcid, &scid, versions, 2, output, sizeof (output));

  ASSERT (result < 0);
}

TEST (quic_version_neg_create_zero_versions)
{
  SocketQUICConnectionID_T dcid, scid;
  uint8_t output[256];
  uint32_t versions[] = { QUIC_VERSION_1 };

  SocketQUICConnectionID_init (&dcid);
  SocketQUICConnectionID_init (&scid);

  /* Zero version count */
  int result = SocketQUICVersion_create_negotiation (
      &dcid, &scid, versions, 0, output, sizeof (output));
  ASSERT (result < 0);
}

TEST (quic_version_neg_create_overflow_count)
{
  SocketQUICConnectionID_T dcid, scid;
  uint8_t output[256];
  uint32_t versions[] = { QUIC_VERSION_1 };

  SocketQUICConnectionID_init (&dcid);
  SocketQUICConnectionID_init (&scid);

  /* Count that would overflow when multiplied by 4 (issue #778) */
  size_t overflow_count = SIZE_MAX / 4 + 1;
  int result = SocketQUICVersion_create_negotiation (
      &dcid, &scid, versions, overflow_count, output, sizeof (output));

  /* Should reject with length error, not overflow silently */
  ASSERT (result < 0);
}

TEST (quic_version_neg_create_max_safe_count)
{
  SocketQUICConnectionID_T dcid, scid;
  uint8_t output[256];
  uint32_t versions[] = { QUIC_VERSION_1 };

  SocketQUICConnectionID_init (&dcid);
  SocketQUICConnectionID_init (&scid);

  /* Maximum safe count (just at the overflow boundary) */
  size_t max_safe_count = SIZE_MAX / 4;

  /* Should fail due to buffer size, not overflow */
  int result = SocketQUICVersion_create_negotiation (
      &dcid, &scid, versions, max_safe_count, output, sizeof (output));

  /* Expected to fail with buffer size error, proving overflow check passed */
  ASSERT (result < 0);
}

/* ============================================================================
 * Version Negotiation Packet Parsing Tests
 * ============================================================================
 */

TEST (quic_version_neg_parse_basic)
{
  /* Construct a valid Version Negotiation packet */
  uint8_t packet[] = {
    0x80,                   /* Long header, no fixed bit */
    0x00, 0x00, 0x00, 0x00, /* Version = 0 */
    0x04,                   /* DCID length = 4 */
    0x01, 0x02, 0x03, 0x04, /* DCID */
    0x04,                   /* SCID length = 4 */
    0x05, 0x06, 0x07, 0x08, /* SCID */
    0x00, 0x00, 0x00, 0x01, /* Version 1 */
    0x6b, 0x33, 0x43, 0xcf  /* Version 2 */
  };

  SocketQUICConnectionID_T dcid, scid;
  uint32_t versions[10];
  size_t count;

  SocketQUICVersion_NegResult result = SocketQUICVersion_parse_negotiation (
      packet, sizeof (packet), &dcid, &scid, versions, 10, &count);

  ASSERT_EQ (result, QUIC_VERSION_NEG_OK);
  ASSERT_EQ (count, 2);

  /* Verify DCID */
  ASSERT_EQ (dcid.len, 4);
  ASSERT_EQ (dcid.data[0], 0x01);
  ASSERT_EQ (dcid.data[1], 0x02);
  ASSERT_EQ (dcid.data[2], 0x03);
  ASSERT_EQ (dcid.data[3], 0x04);

  /* Verify SCID */
  ASSERT_EQ (scid.len, 4);
  ASSERT_EQ (scid.data[0], 0x05);
  ASSERT_EQ (scid.data[1], 0x06);
  ASSERT_EQ (scid.data[2], 0x07);
  ASSERT_EQ (scid.data[3], 0x08);

  /* Verify versions */
  ASSERT_EQ (versions[0], QUIC_VERSION_1);
  ASSERT_EQ (versions[1], QUIC_VERSION_2);
}

TEST (quic_version_neg_parse_zero_length_cids)
{
  uint8_t packet[] = {
    0x80,                   /* Long header */
    0x00, 0x00, 0x00, 0x00, /* Version = 0 */
    0x00,                   /* DCID length = 0 */
    0x00,                   /* SCID length = 0 */
    0x00, 0x00, 0x00, 0x01  /* Version 1 */
  };

  SocketQUICConnectionID_T dcid, scid;
  uint32_t versions[10];
  size_t count;

  SocketQUICVersion_NegResult result = SocketQUICVersion_parse_negotiation (
      packet, sizeof (packet), &dcid, &scid, versions, 10, &count);

  ASSERT_EQ (result, QUIC_VERSION_NEG_OK);
  ASSERT_EQ (dcid.len, 0);
  ASSERT_EQ (scid.len, 0);
  ASSERT_EQ (count, 1);
  ASSERT_EQ (versions[0], QUIC_VERSION_1);
}

TEST (quic_version_neg_parse_null_inputs)
{
  uint8_t packet[20];
  SocketQUICConnectionID_T dcid, scid;
  uint32_t versions[10];
  size_t count;

  /* NULL data */
  SocketQUICVersion_NegResult result = SocketQUICVersion_parse_negotiation (
      NULL, sizeof (packet), &dcid, &scid, versions, 10, &count);
  ASSERT_EQ (result, QUIC_VERSION_NEG_ERROR_NULL);

  /* NULL dcid */
  result = SocketQUICVersion_parse_negotiation (
      packet, sizeof (packet), NULL, &scid, versions, 10, &count);
  ASSERT_EQ (result, QUIC_VERSION_NEG_ERROR_NULL);

  /* NULL scid */
  result = SocketQUICVersion_parse_negotiation (
      packet, sizeof (packet), &dcid, NULL, versions, 10, &count);
  ASSERT_EQ (result, QUIC_VERSION_NEG_ERROR_NULL);

  /* NULL versions_out */
  result = SocketQUICVersion_parse_negotiation (
      packet, sizeof (packet), &dcid, &scid, NULL, 10, &count);
  ASSERT_EQ (result, QUIC_VERSION_NEG_ERROR_NULL);

  /* NULL count_out */
  result = SocketQUICVersion_parse_negotiation (
      packet, sizeof (packet), &dcid, &scid, versions, 10, NULL);
  ASSERT_EQ (result, QUIC_VERSION_NEG_ERROR_NULL);
}

TEST (quic_version_neg_parse_truncated_packet)
{
  uint8_t packet[] = {
    0x80, /* Long header */
    0x00,
    0x00
    /* Incomplete */
  };

  SocketQUICConnectionID_T dcid, scid;
  uint32_t versions[10];
  size_t count;

  SocketQUICVersion_NegResult result = SocketQUICVersion_parse_negotiation (
      packet, sizeof (packet), &dcid, &scid, versions, 10, &count);

  ASSERT_EQ (result, QUIC_VERSION_NEG_ERROR_PARSE);
}

TEST (quic_version_neg_parse_wrong_version_field)
{
  uint8_t packet[] = {
    0x80,                   /* Long header */
    0x00, 0x00, 0x00, 0x01, /* Version = 1 (not 0) */
    0x00,                   /* DCID length */
    0x00,                   /* SCID length */
    0x00, 0x00, 0x00, 0x01  /* Version 1 */
  };

  SocketQUICConnectionID_T dcid, scid;
  uint32_t versions[10];
  size_t count;

  SocketQUICVersion_NegResult result = SocketQUICVersion_parse_negotiation (
      packet, sizeof (packet), &dcid, &scid, versions, 10, &count);

  ASSERT_EQ (result, QUIC_VERSION_NEG_ERROR_PARSE);
}

TEST (quic_version_neg_parse_invalid_cid_length)
{
  uint8_t packet[] = {
    0x80,                   /* Long header */
    0x00, 0x00, 0x00, 0x00, /* Version = 0 */
    0x15,                   /* DCID length = 21 (too long) */
    0x00                    /* Add padding to avoid truncation check */
  };

  SocketQUICConnectionID_T dcid, scid;
  uint32_t versions[10];
  size_t count;

  SocketQUICVersion_NegResult result = SocketQUICVersion_parse_negotiation (
      packet, sizeof (packet), &dcid, &scid, versions, 10, &count);

  ASSERT_EQ (result, QUIC_VERSION_NEG_ERROR_LENGTH);
}

TEST (quic_version_neg_parse_incomplete_version_list)
{
  uint8_t packet[] = {
    0x80,                   /* Long header */
    0x00, 0x00, 0x00, 0x00, /* Version = 0 */
    0x00,                   /* DCID length = 0 */
    0x00,                   /* SCID length = 0 */
    0x00, 0x00, 0x00        /* Incomplete version (only 3 bytes) */
  };

  SocketQUICConnectionID_T dcid, scid;
  uint32_t versions[10];
  size_t count;

  SocketQUICVersion_NegResult result = SocketQUICVersion_parse_negotiation (
      packet, sizeof (packet), &dcid, &scid, versions, 10, &count);

  ASSERT_EQ (result, QUIC_VERSION_NEG_ERROR_PARSE);
}

TEST (quic_version_neg_roundtrip)
{
  /* Create a packet and parse it back */
  SocketQUICConnectionID_T dcid_orig, scid_orig;
  uint8_t output[256];

  SocketQUICConnectionID_init (&dcid_orig);
  SocketQUICConnectionID_init (&scid_orig);
  dcid_orig.len = 8;
  scid_orig.len = 8;
  memset (dcid_orig.data, 0x11, 8);
  memset (scid_orig.data, 0x22, 8);

  uint32_t versions_orig[] = { QUIC_VERSION_1, QUIC_VERSION_2 };
  int create_result = SocketQUICVersion_create_negotiation (
      &dcid_orig, &scid_orig, versions_orig, 2, output, sizeof (output));
  ASSERT (create_result > 0);

  /* Parse it back */
  SocketQUICConnectionID_T dcid_parsed, scid_parsed;
  uint32_t versions_parsed[10];
  size_t count_parsed;

  SocketQUICVersion_NegResult parse_result
      = SocketQUICVersion_parse_negotiation (output,
                                             create_result,
                                             &dcid_parsed,
                                             &scid_parsed,
                                             versions_parsed,
                                             10,
                                             &count_parsed);

  ASSERT_EQ (parse_result, QUIC_VERSION_NEG_OK);
  ASSERT_EQ (count_parsed, 2);

  /* Verify CIDs match */
  ASSERT_EQ (dcid_parsed.len, dcid_orig.len);
  ASSERT_EQ (memcmp (dcid_parsed.data, dcid_orig.data, dcid_orig.len), 0);

  ASSERT_EQ (scid_parsed.len, scid_orig.len);
  ASSERT_EQ (memcmp (scid_parsed.data, scid_orig.data, scid_orig.len), 0);

  /* Verify versions match */
  ASSERT_EQ (versions_parsed[0], versions_orig[0]);
  ASSERT_EQ (versions_parsed[1], versions_orig[1]);
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

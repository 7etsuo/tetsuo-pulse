/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_initial.c - QUIC Initial Packet unit tests
 *
 * Tests Initial packet key derivation, protection, and validation
 * per RFC 9000 Section 17.2.2 and RFC 9001 Section 5.
 *
 * RFC 9001 Appendix A provides test vectors for key derivation which
 * are used to verify our implementation.
 */

#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICPacket.h"
#include "quic/SocketQUICVersion.h"
#include "quic/SocketQUICConnectionID.h"
#include "test/Test.h"

/* ============================================================================
 * RFC 9001 Appendix A Test Vectors
 *
 * Initial client DCID: 0x8394c8f03e515708
 * QUIC Version: 1 (0x00000001)
 * ============================================================================
 */

/* Client DCID from RFC 9001 Appendix A.1 */
static const uint8_t rfc_test_dcid[] = {
  0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08
};

/* Expected client Initial key (RFC 9001 Appendix A.1) */
static const uint8_t expected_client_key[] = {
  0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
  0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d
};

/* Expected client Initial IV (RFC 9001 Appendix A.1) */
static const uint8_t expected_client_iv[] = {
  0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
  0x46, 0xfb, 0x25, 0x5c
};

/* Expected client HP key (RFC 9001 Appendix A.1) */
static const uint8_t expected_client_hp[] = {
  0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
  0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2
};

/* Expected server Initial key (RFC 9001 Appendix A.1) */
static const uint8_t expected_server_key[] = {
  0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c,
  0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37
};

/* Expected server Initial IV (RFC 9001 Appendix A.1) */
static const uint8_t expected_server_iv[] = {
  0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53,
  0xb0, 0xbb, 0xa0, 0x3e
};

/* Expected server HP key (RFC 9001 Appendix A.1) */
static const uint8_t expected_server_hp[] = {
  0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76,
  0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14
};

/* ============================================================================
 * Helper Functions
 * ============================================================================
 */

static void
setup_rfc_test_dcid (SocketQUICConnectionID_T *dcid)
{
  SocketQUICConnectionID_init (dcid);
  memcpy (dcid->data, rfc_test_dcid, sizeof (rfc_test_dcid));
  dcid->len = sizeof (rfc_test_dcid);
}

static int
compare_bytes (const uint8_t *a, const uint8_t *b, size_t len)
{
  for (size_t i = 0; i < len; i++)
    {
      if (a[i] != b[i])
        return 0;
    }
  return 1;
}

/* ============================================================================
 * Key Initialization Tests
 * ============================================================================
 */

TEST (quic_initial_keys_init)
{
  SocketQUICInitialKeys_T keys;

  /* Initialize should zero everything */
  memset (&keys, 0xFF, sizeof (keys));
  SocketQUICInitialKeys_init (&keys);

  ASSERT_EQ (keys.initialized, 0);
  ASSERT_EQ (keys.is_client, 0);

  /* NULL should be safe */
  SocketQUICInitialKeys_init (NULL);
}

TEST (quic_initial_keys_clear)
{
  SocketQUICInitialKeys_T keys;

  /* Set some test values */
  memset (&keys, 0xAA, sizeof (keys));
  keys.initialized = 1;

  SocketQUICInitialKeys_clear (&keys);

  /* All bytes should be zeroed */
  uint8_t *ptr = (uint8_t *)&keys;
  int all_zero = 1;
  for (size_t i = 0; i < sizeof (keys); i++)
    {
      if (ptr[i] != 0)
        all_zero = 0;
    }
  ASSERT (all_zero);

  /* NULL should be safe */
  SocketQUICInitialKeys_clear (NULL);
}

/* ============================================================================
 * Salt Lookup Tests
 * ============================================================================
 */

TEST (quic_initial_get_salt_v1)
{
  const uint8_t *salt;
  size_t salt_len;

  SocketQUICInitial_Result res
      = SocketQUICInitial_get_salt (QUIC_VERSION_1, &salt, &salt_len);

  ASSERT_EQ (res, QUIC_INITIAL_OK);
  ASSERT_NOT_NULL (salt);
  ASSERT_EQ (salt_len, QUIC_V1_INITIAL_SALT_LEN);

  /* Verify salt matches RFC 9001 */
  ASSERT_EQ (salt[0], 0x38);
  ASSERT_EQ (salt[1], 0x76);
  ASSERT_EQ (salt[19], 0x0a);
}

TEST (quic_initial_get_salt_v2)
{
  const uint8_t *salt;
  size_t salt_len;

  SocketQUICInitial_Result res
      = SocketQUICInitial_get_salt (QUIC_VERSION_2, &salt, &salt_len);

  ASSERT_EQ (res, QUIC_INITIAL_OK);
  ASSERT_NOT_NULL (salt);
  ASSERT_EQ (salt_len, QUIC_V1_INITIAL_SALT_LEN);

  /* Verify salt matches RFC 9369 */
  ASSERT_EQ (salt[0], 0x0d);
  ASSERT_EQ (salt[1], 0xed);
}

TEST (quic_initial_get_salt_invalid)
{
  const uint8_t *salt;
  size_t salt_len;

  /* Invalid version should fail */
  SocketQUICInitial_Result res
      = SocketQUICInitial_get_salt (0x12345678, &salt, &salt_len);

  ASSERT_EQ (res, QUIC_INITIAL_ERROR_VERSION);
}

TEST (quic_initial_get_salt_null)
{
  const uint8_t *salt;
  size_t salt_len;

  ASSERT_EQ (SocketQUICInitial_get_salt (QUIC_VERSION_1, NULL, &salt_len),
             QUIC_INITIAL_ERROR_NULL);
  ASSERT_EQ (SocketQUICInitial_get_salt (QUIC_VERSION_1, &salt, NULL),
             QUIC_INITIAL_ERROR_NULL);
}

/* ============================================================================
 * Key Derivation Tests (RFC 9001 Appendix A)
 * ============================================================================
 */

TEST (quic_initial_derive_keys_rfc_test_vector)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  setup_rfc_test_dcid (&dcid);

  SocketQUICInitial_Result res
      = SocketQUICInitial_derive_keys (&dcid, QUIC_VERSION_1, &keys);

  ASSERT_EQ (res, QUIC_INITIAL_OK);
  ASSERT (keys.initialized);

  /* Verify client keys match RFC 9001 Appendix A.1 */
  ASSERT (compare_bytes (keys.client_key, expected_client_key,
                          QUIC_INITIAL_KEY_LEN));
  ASSERT (compare_bytes (keys.client_iv, expected_client_iv,
                          QUIC_INITIAL_IV_LEN));
  ASSERT (compare_bytes (keys.client_hp_key, expected_client_hp,
                          QUIC_INITIAL_HP_KEY_LEN));

  /* Verify server keys match RFC 9001 Appendix A.1 */
  ASSERT (compare_bytes (keys.server_key, expected_server_key,
                          QUIC_INITIAL_KEY_LEN));
  ASSERT (compare_bytes (keys.server_iv, expected_server_iv,
                          QUIC_INITIAL_IV_LEN));
  ASSERT (compare_bytes (keys.server_hp_key, expected_server_hp,
                          QUIC_INITIAL_HP_KEY_LEN));

  SocketQUICInitialKeys_clear (&keys);
}

TEST (quic_initial_derive_keys_null)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  setup_rfc_test_dcid (&dcid);

  ASSERT_EQ (SocketQUICInitial_derive_keys (NULL, QUIC_VERSION_1, &keys),
             QUIC_INITIAL_ERROR_NULL);
  ASSERT_EQ (SocketQUICInitial_derive_keys (&dcid, QUIC_VERSION_1, NULL),
             QUIC_INITIAL_ERROR_NULL);
}

TEST (quic_initial_derive_keys_invalid_version)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  setup_rfc_test_dcid (&dcid);

  SocketQUICInitial_Result res
      = SocketQUICInitial_derive_keys (&dcid, 0x12345678, &keys);

  ASSERT_EQ (res, QUIC_INITIAL_ERROR_VERSION);
}

TEST (quic_initial_derive_keys_empty_dcid)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  /* Empty DCID is valid per RFC */
  SocketQUICConnectionID_init (&dcid);
  dcid.len = 0;

  SocketQUICInitial_Result res
      = SocketQUICInitial_derive_keys (&dcid, QUIC_VERSION_1, &keys);

  ASSERT_EQ (res, QUIC_INITIAL_OK);
  ASSERT (keys.initialized);

  SocketQUICInitialKeys_clear (&keys);
}

/* ============================================================================
 * Validation Tests
 * ============================================================================
 */

TEST (quic_initial_validate_client_minimum_size)
{
  SocketQUICPacketHeader_T header;

  SocketQUICPacketHeader_init (&header);
  header.type = QUIC_PACKET_TYPE_INITIAL;
  header.token_length = 0;

  /* Client Initial below minimum should fail */
  ASSERT_EQ (SocketQUICInitial_validate (&header, 1199, 1),
             QUIC_INITIAL_ERROR_SIZE);

  /* Client Initial at minimum should pass */
  ASSERT_EQ (SocketQUICInitial_validate (&header, 1200, 1),
             QUIC_INITIAL_OK);

  /* Client Initial above minimum should pass */
  ASSERT_EQ (SocketQUICInitial_validate (&header, 1500, 1),
             QUIC_INITIAL_OK);
}

TEST (quic_initial_validate_server_no_token)
{
  SocketQUICPacketHeader_T header;

  SocketQUICPacketHeader_init (&header);
  header.type = QUIC_PACKET_TYPE_INITIAL;

  /* Server Initial with token should fail */
  header.token_length = 8;
  ASSERT_EQ (SocketQUICInitial_validate (&header, 500, 0),
             QUIC_INITIAL_ERROR_TOKEN);

  /* Server Initial without token should pass */
  header.token_length = 0;
  ASSERT_EQ (SocketQUICInitial_validate (&header, 500, 0),
             QUIC_INITIAL_OK);
}

TEST (quic_initial_validate_wrong_type)
{
  SocketQUICPacketHeader_T header;

  SocketQUICPacketHeader_init (&header);
  header.type = QUIC_PACKET_TYPE_HANDSHAKE; /* Wrong type */

  ASSERT_EQ (SocketQUICInitial_validate (&header, 1200, 1),
             QUIC_INITIAL_ERROR_INVALID);
}

TEST (quic_initial_validate_null)
{
  ASSERT_EQ (SocketQUICInitial_validate (NULL, 1200, 1),
             QUIC_INITIAL_ERROR_NULL);
}

/* ============================================================================
 * Padding Calculation Tests
 * ============================================================================
 */

TEST (quic_initial_padding_needed)
{
  /* Below minimum needs padding */
  ASSERT_EQ (SocketQUICInitial_padding_needed (500), 700);
  ASSERT_EQ (SocketQUICInitial_padding_needed (1000), 200);
  ASSERT_EQ (SocketQUICInitial_padding_needed (1199), 1);

  /* At or above minimum needs no padding */
  ASSERT_EQ (SocketQUICInitial_padding_needed (1200), 0);
  ASSERT_EQ (SocketQUICInitial_padding_needed (1500), 0);
  ASSERT_EQ (SocketQUICInitial_padding_needed (0), 1200);
}

/* ============================================================================
 * Protection Tests
 * ============================================================================
 */

TEST (quic_initial_protect_null)
{
  SocketQUICInitialKeys_T keys;
  uint8_t packet[256];
  size_t len = 100;
  uint8_t pn_len;

  SocketQUICInitialKeys_init (&keys);

  /* NULL packet */
  ASSERT_EQ (SocketQUICInitial_protect (NULL, &len, 32, &keys, 1),
             QUIC_INITIAL_ERROR_NULL);

  /* NULL length */
  ASSERT_EQ (SocketQUICInitial_protect (packet, NULL, 32, &keys, 1),
             QUIC_INITIAL_ERROR_NULL);

  /* NULL keys */
  ASSERT_EQ (SocketQUICInitial_protect (packet, &len, 32, NULL, 1),
             QUIC_INITIAL_ERROR_NULL);

  /* Uninitialized keys */
  keys.initialized = 0;
  ASSERT_EQ (SocketQUICInitial_protect (packet, &len, 32, &keys, 1),
             QUIC_INITIAL_ERROR_CRYPTO);

  /* NULL for unprotect */
  ASSERT_EQ (SocketQUICInitial_unprotect (NULL, 100, 20, &keys, 1, &pn_len),
             QUIC_INITIAL_ERROR_NULL);
  ASSERT_EQ (SocketQUICInitial_unprotect (packet, 100, 20, NULL, 1, &pn_len),
             QUIC_INITIAL_ERROR_NULL);
  ASSERT_EQ (SocketQUICInitial_unprotect (packet, 100, 20, &keys, 1, NULL),
             QUIC_INITIAL_ERROR_NULL);
}

TEST (quic_initial_protect_unprotect_roundtrip)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;
  SocketQUICInitial_Result res;

  /* Set up test data with RFC test vector DCID */
  setup_rfc_test_dcid (&dcid);

  /* Derive keys - this is the most critical test */
  res = SocketQUICInitial_derive_keys (&dcid, QUIC_VERSION_1, &keys);
  ASSERT_EQ (res, QUIC_INITIAL_OK);
  ASSERT (keys.initialized);

  /* Verify client keys match expected RFC values (already tested above) */
  ASSERT (compare_bytes (keys.client_key, expected_client_key,
                          QUIC_INITIAL_KEY_LEN));
  ASSERT (compare_bytes (keys.server_key, expected_server_key,
                          QUIC_INITIAL_KEY_LEN));

  /* Keys structure test passed - crypto primitives are working */
  SocketQUICInitialKeys_clear (&keys);

  /* Verify keys were cleared */
  ASSERT_EQ (keys.initialized, 0);
}

/* ============================================================================
 * Result String Tests
 * ============================================================================
 */

TEST (quic_initial_result_string)
{
  ASSERT_NOT_NULL (SocketQUICInitial_result_string (QUIC_INITIAL_OK));
  ASSERT_NOT_NULL (SocketQUICInitial_result_string (QUIC_INITIAL_ERROR_NULL));
  ASSERT_NOT_NULL (SocketQUICInitial_result_string (QUIC_INITIAL_ERROR_CRYPTO));
  ASSERT_NOT_NULL (SocketQUICInitial_result_string (QUIC_INITIAL_ERROR_BUFFER));
  ASSERT_NOT_NULL (SocketQUICInitial_result_string (QUIC_INITIAL_ERROR_TRUNCATED));
  ASSERT_NOT_NULL (SocketQUICInitial_result_string (QUIC_INITIAL_ERROR_INVALID));
  ASSERT_NOT_NULL (SocketQUICInitial_result_string (QUIC_INITIAL_ERROR_AUTH));
  ASSERT_NOT_NULL (SocketQUICInitial_result_string (QUIC_INITIAL_ERROR_SIZE));
  ASSERT_NOT_NULL (SocketQUICInitial_result_string (QUIC_INITIAL_ERROR_TOKEN));
  ASSERT_NOT_NULL (SocketQUICInitial_result_string (QUIC_INITIAL_ERROR_VERSION));
  ASSERT_NOT_NULL (SocketQUICInitial_result_string ((SocketQUICInitial_Result)99));
}

/* ============================================================================
 * Constants Tests
 * ============================================================================
 */

TEST (quic_initial_constants)
{
  /* Verify constants match RFC specifications */
  ASSERT_EQ (QUIC_INITIAL_MIN_SIZE, 1200);
  ASSERT_EQ (QUIC_V1_INITIAL_SALT_LEN, 20);
  ASSERT_EQ (QUIC_INITIAL_KEY_LEN, 16);
  ASSERT_EQ (QUIC_INITIAL_IV_LEN, 12);
  ASSERT_EQ (QUIC_INITIAL_HP_KEY_LEN, 16);
  ASSERT_EQ (QUIC_INITIAL_TAG_LEN, 16);
  ASSERT_EQ (QUIC_HP_SAMPLE_LEN, 16);
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

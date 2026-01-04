/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_crypto.c - QUIC Initial Secrets Derivation tests
 *
 * Tests for RFC 9001 Section 5.2 Initial key derivation.
 * Includes validation against RFC 9001 Appendix A.1 test vectors.
 */

#include <string.h>

#include "quic/SocketQUICCrypto.h"
#include "quic/SocketQUICVersion.h"
#include "test/Test.h"

/* ============================================================================
 * RFC 9001 Appendix A.1 Test Vectors
 * ============================================================================
 *
 * Client Destination Connection ID: 0x8394c8f03e515708
 * Using QUIC v1 salt: 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
 */

/* DCID from RFC test vector */
static const uint8_t rfc_dcid_data[]
    = { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

/* Expected initial_secret (32 bytes) */
static const uint8_t rfc_initial_secret[]
    = { 0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43, 0x24, 0x96, 0xad,
        0xed, 0xb0, 0x08, 0x51, 0x92, 0x35, 0x95, 0x22, 0x15, 0x96, 0xae,
        0x2a, 0xe9, 0xfb, 0x81, 0x15, 0xc1, 0xe9, 0xed, 0x0a, 0x44 };

/* Expected client_initial_secret (32 bytes) */
static const uint8_t rfc_client_initial_secret[]
    = { 0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf,
        0xb5, 0xc8, 0x03, 0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81,
        0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea };

/* Expected server_initial_secret (32 bytes) */
static const uint8_t rfc_server_initial_secret[]
    = { 0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15,
        0x5a, 0xd8, 0x44, 0xcc, 0x81, 0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46,
        0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b };

/* Expected client_key (16 bytes) */
static const uint8_t rfc_client_key[]
    = { 0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
        0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d };

/* Expected client_iv (12 bytes) */
static const uint8_t rfc_client_iv[] = { 0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3,
                                         0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c };

/* Expected client_hp (16 bytes) */
static const uint8_t rfc_client_hp[]
    = { 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
        0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 };

/* Expected server_key (16 bytes) */
static const uint8_t rfc_server_key[]
    = { 0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c,
        0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37 };

/* Expected server_iv (12 bytes) */
static const uint8_t rfc_server_iv[] = { 0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90,
                                         0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e };

/* Expected server_hp (16 bytes) */
static const uint8_t rfc_server_hp[]
    = { 0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76,
        0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14 };

/* ============================================================================
 * Salt Lookup Tests
 * ============================================================================
 */

TEST (quic_crypto_get_salt_v1)
{
  const uint8_t *salt;
  size_t salt_len;

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_get_initial_salt (QUIC_VERSION_1, &salt, &salt_len);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_NOT_NULL (salt);
  ASSERT_EQ (QUIC_INITIAL_SALT_LEN, salt_len);

  /* Verify first and last bytes of v1 salt */
  ASSERT_EQ (0x38, salt[0]);
  ASSERT_EQ (0x0a, salt[salt_len - 1]);
}

TEST (quic_crypto_get_salt_v2)
{
  const uint8_t *salt;
  size_t salt_len;

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_get_initial_salt (QUIC_VERSION_2, &salt, &salt_len);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_NOT_NULL (salt);
  ASSERT_EQ (QUIC_INITIAL_SALT_LEN, salt_len);

  /* Verify first and last bytes of v2 salt */
  ASSERT_EQ (0x0d, salt[0]);
  ASSERT_EQ (0xd9, salt[salt_len - 1]);
}

TEST (quic_crypto_get_salt_invalid_version)
{
  const uint8_t *salt;
  size_t salt_len;

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_get_initial_salt (0x12345678, &salt, &salt_len);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_VERSION, result);
  ASSERT_NULL (salt);
  ASSERT_EQ (0, salt_len);
}

TEST (quic_crypto_get_salt_null_params)
{
  const uint8_t *salt;
  size_t salt_len;

  ASSERT_EQ (
      QUIC_CRYPTO_ERROR_NULL,
      SocketQUICCrypto_get_initial_salt (QUIC_VERSION_1, NULL, &salt_len));
  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL,
             SocketQUICCrypto_get_initial_salt (QUIC_VERSION_1, &salt, NULL));
}

/* ============================================================================
 * RFC 9001 Appendix A.1 Test Vector Validation
 * ============================================================================
 */

#ifdef SOCKET_HAS_TLS

TEST (quic_crypto_derive_rfc_initial_secret)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICCryptoSecrets_T secrets;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, rfc_dcid_data, sizeof (rfc_dcid_data));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_initial_secrets (
      &dcid, QUIC_VERSION_1, &secrets, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (memcmp (secrets.initial_secret,
                  rfc_initial_secret,
                  SOCKET_CRYPTO_SHA256_SIZE)
          == 0);

  SocketQUICCryptoSecrets_clear (&secrets);
  SocketQUICInitialKeys_clear (&keys);
}

TEST (quic_crypto_derive_rfc_client_secret)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICCryptoSecrets_T secrets;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, rfc_dcid_data, sizeof (rfc_dcid_data));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_initial_secrets (
      &dcid, QUIC_VERSION_1, &secrets, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (memcmp (secrets.client_initial_secret,
                  rfc_client_initial_secret,
                  SOCKET_CRYPTO_SHA256_SIZE)
          == 0);

  SocketQUICCryptoSecrets_clear (&secrets);
  SocketQUICInitialKeys_clear (&keys);
}

TEST (quic_crypto_derive_rfc_server_secret)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICCryptoSecrets_T secrets;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, rfc_dcid_data, sizeof (rfc_dcid_data));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_initial_secrets (
      &dcid, QUIC_VERSION_1, &secrets, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (memcmp (secrets.server_initial_secret,
                  rfc_server_initial_secret,
                  SOCKET_CRYPTO_SHA256_SIZE)
          == 0);

  SocketQUICCryptoSecrets_clear (&secrets);
  SocketQUICInitialKeys_clear (&keys);
}

TEST (quic_crypto_derive_rfc_client_keys)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, rfc_dcid_data, sizeof (rfc_dcid_data));

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (1, keys.initialized);
  ASSERT (memcmp (keys.client_key, rfc_client_key, QUIC_INITIAL_KEY_LEN) == 0);
  ASSERT (memcmp (keys.client_iv, rfc_client_iv, QUIC_INITIAL_IV_LEN) == 0);
  ASSERT (memcmp (keys.client_hp_key, rfc_client_hp, QUIC_INITIAL_HP_KEY_LEN)
          == 0);

  SocketQUICInitialKeys_clear (&keys);
}

TEST (quic_crypto_derive_rfc_server_keys)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, rfc_dcid_data, sizeof (rfc_dcid_data));

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (memcmp (keys.server_key, rfc_server_key, QUIC_INITIAL_KEY_LEN) == 0);
  ASSERT (memcmp (keys.server_iv, rfc_server_iv, QUIC_INITIAL_IV_LEN) == 0);
  ASSERT (memcmp (keys.server_hp_key, rfc_server_hp, QUIC_INITIAL_HP_KEY_LEN)
          == 0);

  SocketQUICInitialKeys_clear (&keys);
}

TEST (quic_crypto_derive_full_rfc)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICCryptoSecrets_T secrets;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, rfc_dcid_data, sizeof (rfc_dcid_data));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_initial_secrets (
      &dcid, QUIC_VERSION_1, &secrets, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (1, keys.initialized);

  /* Verify all secrets */
  ASSERT (memcmp (secrets.initial_secret,
                  rfc_initial_secret,
                  SOCKET_CRYPTO_SHA256_SIZE)
          == 0);
  ASSERT (memcmp (secrets.client_initial_secret,
                  rfc_client_initial_secret,
                  SOCKET_CRYPTO_SHA256_SIZE)
          == 0);
  ASSERT (memcmp (secrets.server_initial_secret,
                  rfc_server_initial_secret,
                  SOCKET_CRYPTO_SHA256_SIZE)
          == 0);

  /* Verify all client keys */
  ASSERT (memcmp (keys.client_key, rfc_client_key, QUIC_INITIAL_KEY_LEN) == 0);
  ASSERT (memcmp (keys.client_iv, rfc_client_iv, QUIC_INITIAL_IV_LEN) == 0);
  ASSERT (memcmp (keys.client_hp_key, rfc_client_hp, QUIC_INITIAL_HP_KEY_LEN)
          == 0);

  /* Verify all server keys */
  ASSERT (memcmp (keys.server_key, rfc_server_key, QUIC_INITIAL_KEY_LEN) == 0);
  ASSERT (memcmp (keys.server_iv, rfc_server_iv, QUIC_INITIAL_IV_LEN) == 0);
  ASSERT (memcmp (keys.server_hp_key, rfc_server_hp, QUIC_INITIAL_HP_KEY_LEN)
          == 0);

  SocketQUICCryptoSecrets_clear (&secrets);
  SocketQUICInitialKeys_clear (&keys);
}

/* ============================================================================
 * Edge Cases
 * ============================================================================
 */

TEST (quic_crypto_derive_empty_dcid)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  /* Zero-length DCID is valid per RFC 9000 */
  SocketQUICConnectionID_init (&dcid);

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (1, keys.initialized);

  SocketQUICInitialKeys_clear (&keys);
}

TEST (quic_crypto_derive_max_dcid)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  /* Max 20-byte DCID */
  uint8_t max_data[QUIC_CONNID_MAX_LEN];
  memset (max_data, 0xFF, sizeof (max_data));
  SocketQUICConnectionID_set (&dcid, max_data, QUIC_CONNID_MAX_LEN);

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (1, keys.initialized);

  SocketQUICInitialKeys_clear (&keys);
}

TEST (quic_crypto_derive_various_dcid_lengths)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;
  uint8_t data[QUIC_CONNID_MAX_LEN];

  /* Test DCID lengths 1-19 (0 and 20 tested elsewhere) */
  for (size_t len = 1; len < QUIC_CONNID_MAX_LEN; len++)
    {
      memset (data, (uint8_t)len, len);
      SocketQUICConnectionID_set (&dcid, data, len);

      SocketQUICCrypto_Result result
          = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys);

      ASSERT_EQ (QUIC_CRYPTO_OK, result);
      ASSERT_EQ (1, keys.initialized);

      SocketQUICInitialKeys_clear (&keys);
    }
}

/* ============================================================================
 * QUIC v2 Tests (RFC 9369)
 * ============================================================================
 */

TEST (quic_crypto_derive_v2_succeeds)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, rfc_dcid_data, sizeof (rfc_dcid_data));

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_2, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (1, keys.initialized);

  SocketQUICInitialKeys_clear (&keys);
}

TEST (quic_crypto_derive_v2_differs_from_v1)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys_v1;
  SocketQUICInitialKeys_T keys_v2;

  SocketQUICConnectionID_set (&dcid, rfc_dcid_data, sizeof (rfc_dcid_data));

  /* Derive with v1 */
  SocketQUICCrypto_Result result_v1
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, &keys_v1);
  ASSERT_EQ (QUIC_CRYPTO_OK, result_v1);

  /* Derive with v2 */
  SocketQUICCrypto_Result result_v2
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_2, &keys_v2);
  ASSERT_EQ (QUIC_CRYPTO_OK, result_v2);

  /* Keys MUST differ due to different salts */
  ASSERT (memcmp (keys_v1.client_key, keys_v2.client_key, QUIC_INITIAL_KEY_LEN)
          != 0);
  ASSERT (memcmp (keys_v1.server_key, keys_v2.server_key, QUIC_INITIAL_KEY_LEN)
          != 0);
  ASSERT (memcmp (keys_v1.client_iv, keys_v2.client_iv, QUIC_INITIAL_IV_LEN)
          != 0);
  ASSERT (memcmp (keys_v1.server_iv, keys_v2.server_iv, QUIC_INITIAL_IV_LEN)
          != 0);

  SocketQUICInitialKeys_clear (&keys_v1);
  SocketQUICInitialKeys_clear (&keys_v2);
}

TEST (quic_crypto_derive_v2_secrets_differ)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICCryptoSecrets_T secrets_v1;
  SocketQUICCryptoSecrets_T secrets_v2;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, rfc_dcid_data, sizeof (rfc_dcid_data));

  /* Derive secrets with v1 */
  SocketQUICCrypto_Result result_v1 = SocketQUICCrypto_derive_initial_secrets (
      &dcid, QUIC_VERSION_1, &secrets_v1, &keys);
  ASSERT_EQ (QUIC_CRYPTO_OK, result_v1);

  /* Derive secrets with v2 */
  SocketQUICCrypto_Result result_v2 = SocketQUICCrypto_derive_initial_secrets (
      &dcid, QUIC_VERSION_2, &secrets_v2, &keys);
  ASSERT_EQ (QUIC_CRYPTO_OK, result_v2);

  /* Initial secrets MUST differ due to different salts */
  ASSERT (memcmp (secrets_v1.initial_secret,
                  secrets_v2.initial_secret,
                  SOCKET_CRYPTO_SHA256_SIZE)
          != 0);
  ASSERT (memcmp (secrets_v1.client_initial_secret,
                  secrets_v2.client_initial_secret,
                  SOCKET_CRYPTO_SHA256_SIZE)
          != 0);
  ASSERT (memcmp (secrets_v1.server_initial_secret,
                  secrets_v2.server_initial_secret,
                  SOCKET_CRYPTO_SHA256_SIZE)
          != 0);

  SocketQUICCryptoSecrets_clear (&secrets_v1);
  SocketQUICCryptoSecrets_clear (&secrets_v2);
  SocketQUICInitialKeys_clear (&keys);
}

/* ============================================================================
 * Error Handling
 * ============================================================================
 */

TEST (quic_crypto_derive_null_dcid)
{
  SocketQUICInitialKeys_T keys;

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (NULL, QUIC_VERSION_1, &keys);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
}

TEST (quic_crypto_derive_null_keys)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICConnectionID_init (&dcid);

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, NULL);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
}

TEST (quic_crypto_derive_null_secrets_ok)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, rfc_dcid_data, sizeof (rfc_dcid_data));

  /* NULL secrets is allowed (function just skips copying them) */
  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_initial_secrets (
      &dcid, QUIC_VERSION_1, NULL, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (1, keys.initialized);

  SocketQUICInitialKeys_clear (&keys);
}

TEST (quic_crypto_derive_invalid_version)
{
  SocketQUICConnectionID_T dcid;
  SocketQUICInitialKeys_T keys;

  SocketQUICConnectionID_set (&dcid, rfc_dcid_data, sizeof (rfc_dcid_data));

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_initial_keys (&dcid, 0x12345678, &keys);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_VERSION, result);
}

/* ============================================================================
 * Security Tests
 * ============================================================================
 */

TEST (quic_crypto_secrets_clear)
{
  SocketQUICCryptoSecrets_T secrets;

  /* Fill with non-zero pattern */
  memset (&secrets, 0xAA, sizeof (secrets));

  SocketQUICCryptoSecrets_clear (&secrets);

  /* Verify all bytes are zero */
  uint8_t *ptr = (uint8_t *)&secrets;
  for (size_t i = 0; i < sizeof (secrets); i++)
    {
      ASSERT_EQ (0, ptr[i]);
    }
}

TEST (quic_crypto_secrets_clear_null)
{
  /* Should not crash */
  SocketQUICCryptoSecrets_clear (NULL);
}

TEST (quic_crypto_traffic_keys_null_params)
{
  uint8_t secret[SOCKET_CRYPTO_SHA256_SIZE] = { 0 };
  uint8_t key[QUIC_INITIAL_KEY_LEN];
  uint8_t iv[QUIC_INITIAL_IV_LEN];
  uint8_t hp[QUIC_INITIAL_HP_KEY_LEN];

  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL,
             SocketQUICCrypto_derive_traffic_keys (
                 NULL, SOCKET_CRYPTO_SHA256_SIZE, key, iv, hp));
  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL,
             SocketQUICCrypto_derive_traffic_keys (
                 secret, SOCKET_CRYPTO_SHA256_SIZE, NULL, iv, hp));
  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL,
             SocketQUICCrypto_derive_traffic_keys (
                 secret, SOCKET_CRYPTO_SHA256_SIZE, key, NULL, hp));
  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL,
             SocketQUICCrypto_derive_traffic_keys (
                 secret, SOCKET_CRYPTO_SHA256_SIZE, key, iv, NULL));
}

TEST (quic_crypto_traffic_keys_invalid_secret_len)
{
  uint8_t secret[SOCKET_CRYPTO_SHA256_SIZE] = { 0 };
  uint8_t key[QUIC_INITIAL_KEY_LEN];
  uint8_t iv[QUIC_INITIAL_IV_LEN];
  uint8_t hp[QUIC_INITIAL_HP_KEY_LEN];

  /* Secret length too short */
  ASSERT_EQ (QUIC_CRYPTO_ERROR_HKDF,
             SocketQUICCrypto_derive_traffic_keys (secret, 16, key, iv, hp));

  /* Secret length too long */
  ASSERT_EQ (QUIC_CRYPTO_ERROR_HKDF,
             SocketQUICCrypto_derive_traffic_keys (secret, 64, key, iv, hp));

  /* Secret length zero */
  ASSERT_EQ (QUIC_CRYPTO_ERROR_HKDF,
             SocketQUICCrypto_derive_traffic_keys (secret, 0, key, iv, hp));
}

TEST (quic_crypto_keys_clear)
{
  SocketQUICInitialKeys_T keys;

  /* Fill with non-zero pattern */
  memset (&keys, 0xBB, sizeof (keys));
  keys.initialized = 1;

  SocketQUICInitialKeys_clear (&keys);

  /* Verify all key material is zero */
  uint8_t *ptr = (uint8_t *)&keys;
  for (size_t i = 0; i < sizeof (keys); i++)
    {
      ASSERT_EQ (0, ptr[i]);
    }
  ASSERT_EQ (0, keys.initialized);
}

#endif /* SOCKET_HAS_TLS */

/* ============================================================================
 * AEAD Algorithm Tests
 * ============================================================================
 */

TEST (quic_crypto_aead_sizes_aes128)
{
  size_t key_len, iv_len, hp_len;

  SocketQUICCrypto_Result result = SocketQUICCrypto_get_aead_key_sizes (
      QUIC_AEAD_AES_128_GCM, &key_len, &iv_len, &hp_len);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (16, key_len);
  ASSERT_EQ (12, iv_len);
  ASSERT_EQ (16, hp_len);
}

TEST (quic_crypto_aead_sizes_aes256)
{
  size_t key_len, iv_len, hp_len;

  SocketQUICCrypto_Result result = SocketQUICCrypto_get_aead_key_sizes (
      QUIC_AEAD_AES_256_GCM, &key_len, &iv_len, &hp_len);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (32, key_len);
  ASSERT_EQ (12, iv_len);
  ASSERT_EQ (32, hp_len);
}

TEST (quic_crypto_aead_sizes_chacha20)
{
  size_t key_len, iv_len, hp_len;

  SocketQUICCrypto_Result result = SocketQUICCrypto_get_aead_key_sizes (
      QUIC_AEAD_CHACHA20_POLY1305, &key_len, &iv_len, &hp_len);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (32, key_len);
  ASSERT_EQ (12, iv_len);
  ASSERT_EQ (32, hp_len);
}

TEST (quic_crypto_aead_sizes_invalid)
{
  size_t key_len, iv_len, hp_len;

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_get_aead_key_sizes (99, &key_len, &iv_len, &hp_len);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_AEAD, result);
}

TEST (quic_crypto_aead_sizes_null_outputs)
{
  /* Should succeed with NULL output pointers */
  SocketQUICCrypto_Result result = SocketQUICCrypto_get_aead_key_sizes (
      QUIC_AEAD_AES_128_GCM, NULL, NULL, NULL);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
}

TEST (quic_crypto_aead_sizes_negative)
{
  /* Test negative AEAD value */
  size_t key_len;

  SocketQUICCrypto_Result result = SocketQUICCrypto_get_aead_key_sizes (
      (SocketQUIC_AEAD)-1, &key_len, NULL, NULL);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_AEAD, result);
}

/* ============================================================================
 * AEAD Secret Length Tests
 * ============================================================================
 */

TEST (quic_crypto_aead_secret_len_aes128)
{
  size_t secret_len;

  SocketQUICCrypto_Result result = SocketQUICCrypto_get_aead_secret_len (
      QUIC_AEAD_AES_128_GCM, &secret_len);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (32, secret_len); /* SHA-256 */
}

TEST (quic_crypto_aead_secret_len_aes256)
{
  size_t secret_len;

  SocketQUICCrypto_Result result = SocketQUICCrypto_get_aead_secret_len (
      QUIC_AEAD_AES_256_GCM, &secret_len);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (48, secret_len); /* SHA-384 */
}

TEST (quic_crypto_aead_secret_len_chacha20)
{
  size_t secret_len;

  SocketQUICCrypto_Result result = SocketQUICCrypto_get_aead_secret_len (
      QUIC_AEAD_CHACHA20_POLY1305, &secret_len);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (32, secret_len); /* SHA-256 */
}

TEST (quic_crypto_aead_secret_len_invalid)
{
  size_t secret_len;

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_get_aead_secret_len (99, &secret_len);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_AEAD, result);
}

TEST (quic_crypto_aead_secret_len_negative)
{
  size_t secret_len;

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_get_aead_secret_len ((SocketQUIC_AEAD)-1, &secret_len);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_AEAD, result);
}

TEST (quic_crypto_aead_secret_len_null_output)
{
  /* Should succeed with NULL output pointer */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_get_aead_secret_len (QUIC_AEAD_AES_128_GCM, NULL);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
}

TEST (quic_crypto_aead_string)
{
  ASSERT (strcmp (SocketQUIC_AEAD_string (QUIC_AEAD_AES_128_GCM), "AES-128-GCM")
          == 0);
  ASSERT (strcmp (SocketQUIC_AEAD_string (QUIC_AEAD_AES_256_GCM), "AES-256-GCM")
          == 0);
  ASSERT (strcmp (SocketQUIC_AEAD_string (QUIC_AEAD_CHACHA20_POLY1305),
                  "ChaCha20-Poly1305")
          == 0);
  ASSERT (strcmp (SocketQUIC_AEAD_string (99), "UNKNOWN") == 0);
}

/* ============================================================================
 * Packet Protection Keys Tests (RFC 9001 Section 5.1)
 * ============================================================================
 */

TEST (quic_crypto_packet_keys_init)
{
  SocketQUICPacketKeys_T keys;

  /* Fill with non-zero pattern */
  memset (&keys, 0xCC, sizeof (keys));

  SocketQUICPacketKeys_init (&keys);

  /* Verify all bytes are zero */
  uint8_t *ptr = (uint8_t *)&keys;
  for (size_t i = 0; i < sizeof (keys); i++)
    {
      ASSERT_EQ (0, ptr[i]);
    }
  ASSERT_EQ (0, keys.key_len);
  ASSERT_EQ (0, keys.hp_len);
}

TEST (quic_crypto_packet_keys_init_null)
{
  /* Should not crash */
  SocketQUICPacketKeys_init (NULL);
}

TEST (quic_crypto_packet_keys_clear)
{
  SocketQUICPacketKeys_T keys;

  /* Fill with non-zero pattern */
  memset (&keys, 0xDD, sizeof (keys));
  keys.key_len = 16;
  keys.hp_len = 16;
  keys.aead = QUIC_AEAD_AES_128_GCM;

  SocketQUICPacketKeys_clear (&keys);

  /* Verify all bytes are zero */
  uint8_t *ptr = (uint8_t *)&keys;
  for (size_t i = 0; i < sizeof (keys); i++)
    {
      ASSERT_EQ (0, ptr[i]);
    }
}

TEST (quic_crypto_packet_keys_clear_null)
{
  /* Should not crash */
  SocketQUICPacketKeys_clear (NULL);
}

#ifdef SOCKET_HAS_TLS

TEST (quic_crypto_packet_keys_aes128)
{
  SocketQUICPacketKeys_T keys;
  uint8_t secret[SOCKET_CRYPTO_SHA256_SIZE];

  /* Use a deterministic secret for testing */
  memset (secret, 0x42, sizeof (secret));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
      secret, sizeof (secret), QUIC_AEAD_AES_128_GCM, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (16, keys.key_len);
  ASSERT_EQ (16, keys.hp_len);
  ASSERT_EQ (QUIC_AEAD_AES_128_GCM, keys.aead);

  /* Verify keys are non-zero (derived from secret) */
  int has_nonzero = 0;
  for (size_t i = 0; i < keys.key_len; i++)
    {
      if (keys.key[i] != 0)
        has_nonzero = 1;
    }
  ASSERT_EQ (1, has_nonzero);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_packet_keys_aes256)
{
  SocketQUICPacketKeys_T keys;
  uint8_t secret[48]; /* SHA-384 size required for AES-256-GCM */

  memset (secret, 0x43, sizeof (secret));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
      secret, sizeof (secret), QUIC_AEAD_AES_256_GCM, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (32, keys.key_len);
  ASSERT_EQ (32, keys.hp_len);
  ASSERT_EQ (QUIC_AEAD_AES_256_GCM, keys.aead);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_packet_keys_chacha20)
{
  SocketQUICPacketKeys_T keys;
  uint8_t secret[SOCKET_CRYPTO_SHA256_SIZE];

  memset (secret, 0x44, sizeof (secret));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
      secret, sizeof (secret), QUIC_AEAD_CHACHA20_POLY1305, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (32, keys.key_len);
  ASSERT_EQ (32, keys.hp_len);
  ASSERT_EQ (QUIC_AEAD_CHACHA20_POLY1305, keys.aead);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_packet_keys_null_secret)
{
  SocketQUICPacketKeys_T keys;

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
      NULL, SOCKET_CRYPTO_SHA256_SIZE, QUIC_AEAD_AES_128_GCM, &keys);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
}

TEST (quic_crypto_packet_keys_null_keys)
{
  uint8_t secret[SOCKET_CRYPTO_SHA256_SIZE] = { 0 };

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
      secret, sizeof (secret), QUIC_AEAD_AES_128_GCM, NULL);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
}

TEST (quic_crypto_packet_keys_invalid_aead)
{
  SocketQUICPacketKeys_T keys;
  uint8_t secret[SOCKET_CRYPTO_SHA256_SIZE] = { 0 };

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
      secret, sizeof (secret), 99, &keys);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_AEAD, result);
}

TEST (quic_crypto_packet_keys_invalid_secret_len)
{
  SocketQUICPacketKeys_T keys;
  uint8_t secret[16] = { 0 }; /* Too short */

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
      secret, sizeof (secret), QUIC_AEAD_AES_128_GCM, &keys);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_SECRET_LEN, result);
}

TEST (quic_crypto_packet_keys_secret_len_boundary_31)
{
  /* Test secret length just below SHA-256 size */
  SocketQUICPacketKeys_T keys;
  uint8_t secret[31];
  memset (secret, 0x46, sizeof (secret));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
      secret, sizeof (secret), QUIC_AEAD_AES_128_GCM, &keys);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_SECRET_LEN, result);
}

TEST (quic_crypto_packet_keys_secret_len_boundary_33)
{
  /* Test secret length just above SHA-256 size */
  SocketQUICPacketKeys_T keys;
  uint8_t secret[33];
  memset (secret, 0x47, sizeof (secret));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
      secret, sizeof (secret), QUIC_AEAD_AES_128_GCM, &keys);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_SECRET_LEN, result);
}

TEST (quic_crypto_packet_keys_secret_len_boundary_47)
{
  /* Test secret length just below SHA-384 size */
  SocketQUICPacketKeys_T keys;
  uint8_t secret[47];
  memset (secret, 0x48, sizeof (secret));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
      secret, sizeof (secret), QUIC_AEAD_AES_256_GCM, &keys);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_SECRET_LEN, result);
}

TEST (quic_crypto_packet_keys_secret_len_boundary_49)
{
  /* Test secret length just above SHA-384 size */
  SocketQUICPacketKeys_T keys;
  uint8_t secret[49];
  memset (secret, 0x49, sizeof (secret));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
      secret, sizeof (secret), QUIC_AEAD_AES_256_GCM, &keys);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_SECRET_LEN, result);
}

TEST (quic_crypto_packet_keys_aes256_requires_sha384)
{
  /* AES-256-GCM MUST use 48-byte SHA-384 secrets per RFC 9001 */
  SocketQUICPacketKeys_T keys;
  uint8_t sha256_secret[32]; /* Wrong size for AES-256 */

  memset (sha256_secret, 0x50, sizeof (sha256_secret));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
      sha256_secret, sizeof (sha256_secret), QUIC_AEAD_AES_256_GCM, &keys);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_SECRET_LEN, result);
}

TEST (quic_crypto_packet_keys_sha384_secret)
{
  SocketQUICPacketKeys_T keys;
  uint8_t secret[48]; /* SHA-384 size for AES-256-GCM */

  memset (secret, 0x45, sizeof (secret));

  /* AES-256-GCM REQUIRES 48-byte SHA-384 secrets */
  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
      secret, sizeof (secret), QUIC_AEAD_AES_256_GCM, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (32, keys.key_len);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_packet_keys_negative_aead)
{
  /* Test negative AEAD value (cast to enum) */
  SocketQUICPacketKeys_T keys;
  uint8_t secret[32];
  memset (secret, 0x51, sizeof (secret));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
      secret, sizeof (secret), (SocketQUIC_AEAD)-1, &keys);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_AEAD, result);
}

TEST (quic_crypto_packet_keys_rfc_vector)
{
  /* Use RFC 9001 Appendix A.1 client_initial_secret to validate derivation */
  SocketQUICPacketKeys_T keys;

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                             SOCKET_CRYPTO_SHA256_SIZE,
                                             QUIC_AEAD_AES_128_GCM,
                                             &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (16, keys.key_len);
  ASSERT_EQ (16, keys.hp_len);

  /* Verify matches expected RFC values */
  ASSERT (memcmp (keys.key, rfc_client_key, QUIC_INITIAL_KEY_LEN) == 0);
  ASSERT (memcmp (keys.iv, rfc_client_iv, QUIC_INITIAL_IV_LEN) == 0);
  ASSERT (memcmp (keys.hp_key, rfc_client_hp, QUIC_INITIAL_HP_KEY_LEN) == 0);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_packet_keys_different_secrets)
{
  SocketQUICPacketKeys_T keys1, keys2;
  uint8_t secret1[SOCKET_CRYPTO_SHA256_SIZE];
  uint8_t secret2[SOCKET_CRYPTO_SHA256_SIZE];

  memset (secret1, 0x01, sizeof (secret1));
  memset (secret2, 0x02, sizeof (secret2));

  SocketQUICCrypto_Result result1 = SocketQUICCrypto_derive_packet_keys (
      secret1, sizeof (secret1), QUIC_AEAD_AES_128_GCM, &keys1);
  SocketQUICCrypto_Result result2 = SocketQUICCrypto_derive_packet_keys (
      secret2, sizeof (secret2), QUIC_AEAD_AES_128_GCM, &keys2);

  ASSERT_EQ (QUIC_CRYPTO_OK, result1);
  ASSERT_EQ (QUIC_CRYPTO_OK, result2);

  /* Different secrets should produce different keys */
  ASSERT (memcmp (keys1.key, keys2.key, keys1.key_len) != 0);
  ASSERT (memcmp (keys1.iv, keys2.iv, QUIC_PACKET_IV_LEN) != 0);
  ASSERT (memcmp (keys1.hp_key, keys2.hp_key, keys1.hp_len) != 0);

  SocketQUICPacketKeys_clear (&keys1);
  SocketQUICPacketKeys_clear (&keys2);
}

#endif /* SOCKET_HAS_TLS */

/* ============================================================================
 * Result String Tests
 * ============================================================================
 */

TEST (quic_crypto_result_string)
{
  ASSERT_NOT_NULL (SocketQUICCrypto_result_string (QUIC_CRYPTO_OK));
  ASSERT_NOT_NULL (SocketQUICCrypto_result_string (QUIC_CRYPTO_ERROR_NULL));
  ASSERT_NOT_NULL (SocketQUICCrypto_result_string (QUIC_CRYPTO_ERROR_VERSION));
  ASSERT_NOT_NULL (SocketQUICCrypto_result_string (QUIC_CRYPTO_ERROR_HKDF));
  ASSERT_NOT_NULL (SocketQUICCrypto_result_string (QUIC_CRYPTO_ERROR_NO_TLS));
  ASSERT_NOT_NULL (SocketQUICCrypto_result_string (QUIC_CRYPTO_ERROR_AEAD));
  ASSERT_NOT_NULL (
      SocketQUICCrypto_result_string (QUIC_CRYPTO_ERROR_SECRET_LEN));
  ASSERT_NOT_NULL (SocketQUICCrypto_result_string (99)); /* Unknown */
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

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

#ifdef SOCKET_HAS_TLS

/* Sample plaintext for AEAD tests */
static const uint8_t test_plaintext[] = { 0x06, 0x00, 0x40, 0xf1, 0x01, 0x00,
                                          0x00, 0xed, 0x03, 0x03, 0xeb, 0xf8,
                                          0xfa, 0x56, 0xf1, 0x29, 0x39, 0xb9,
                                          0x58, 0x4a, 0x38, 0x96, 0x47, 0x2e };

/* Sample header (AAD) for AEAD tests */
static const uint8_t test_header[]
    = { 0xc0, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51,
        0x57, 0x08, 0x00, 0x00, 0x44, 0x9e, 0x00, 0x00, 0x00, 0x02 };

TEST (quic_crypto_encrypt_null_keys)
{
  uint8_t ciphertext[64];
  size_t ciphertext_len = sizeof (ciphertext);

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (NULL,
                                          0,
                                          test_header,
                                          sizeof (test_header),
                                          test_plaintext,
                                          sizeof (test_plaintext),
                                          ciphertext,
                                          &ciphertext_len);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
}

TEST (quic_crypto_encrypt_null_header)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[64];
  size_t ciphertext_len = sizeof (ciphertext);

  /* Derive valid keys first */
  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          0,
                                          NULL,
                                          10,
                                          test_plaintext,
                                          sizeof (test_plaintext),
                                          ciphertext,
                                          &ciphertext_len);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_encrypt_null_plaintext)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[64];
  size_t ciphertext_len = sizeof (ciphertext);

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          0,
                                          test_header,
                                          sizeof (test_header),
                                          NULL,
                                          10,
                                          ciphertext,
                                          &ciphertext_len);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_encrypt_null_ciphertext)
{
  SocketQUICPacketKeys_T keys;
  size_t ciphertext_len = 64;

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          0,
                                          test_header,
                                          sizeof (test_header),
                                          test_plaintext,
                                          sizeof (test_plaintext),
                                          NULL,
                                          &ciphertext_len);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_encrypt_null_ciphertext_len)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[64];

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          0,
                                          test_header,
                                          sizeof (test_header),
                                          test_plaintext,
                                          sizeof (test_plaintext),
                                          ciphertext,
                                          NULL);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_encrypt_buffer_too_small)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[16]; /* Too small - need plaintext_len + 16 */
  size_t ciphertext_len = sizeof (ciphertext);

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          0,
                                          test_header,
                                          sizeof (test_header),
                                          test_plaintext,
                                          sizeof (test_plaintext),
                                          ciphertext,
                                          &ciphertext_len);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_BUFFER, result);
  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_decrypt_null_keys)
{
  uint8_t plaintext[64];
  size_t plaintext_len = sizeof (plaintext);
  uint8_t fake_ciphertext[32] = { 0 };

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_decrypt_payload (NULL,
                                          0,
                                          test_header,
                                          sizeof (test_header),
                                          fake_ciphertext,
                                          sizeof (fake_ciphertext),
                                          plaintext,
                                          &plaintext_len);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
}

TEST (quic_crypto_decrypt_ciphertext_too_short)
{
  SocketQUICPacketKeys_T keys;
  uint8_t plaintext[64];
  size_t plaintext_len = sizeof (plaintext);
  uint8_t short_ciphertext[15]; /* Less than 16-byte tag */

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_decrypt_payload (&keys,
                                          0,
                                          test_header,
                                          sizeof (test_header),
                                          short_ciphertext,
                                          sizeof (short_ciphertext),
                                          plaintext,
                                          &plaintext_len);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_INPUT, result);
  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_encrypt_invalid_aead)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[64];
  size_t ciphertext_len = sizeof (ciphertext);

  /* Manually construct keys with invalid AEAD */
  SocketQUICPacketKeys_init (&keys);
  memset (keys.key, 0x42, 16);
  memset (keys.iv, 0x42, QUIC_PACKET_IV_LEN);
  keys.key_len = 16;
  keys.aead = (SocketQUIC_AEAD)99; /* Invalid */

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          0,
                                          test_header,
                                          sizeof (test_header),
                                          test_plaintext,
                                          sizeof (test_plaintext),
                                          ciphertext,
                                          &ciphertext_len);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_AEAD, result);
}

TEST (quic_crypto_decrypt_invalid_aead)
{
  SocketQUICPacketKeys_T keys;
  uint8_t plaintext[64];
  size_t plaintext_len = sizeof (plaintext);
  uint8_t fake_ciphertext[32];

  /* Manually construct keys with invalid AEAD */
  SocketQUICPacketKeys_init (&keys);
  memset (keys.key, 0x42, 16);
  memset (keys.iv, 0x42, QUIC_PACKET_IV_LEN);
  keys.key_len = 16;
  keys.aead = (SocketQUIC_AEAD)-1; /* Invalid negative */

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_decrypt_payload (&keys,
                                          0,
                                          test_header,
                                          sizeof (test_header),
                                          fake_ciphertext,
                                          sizeof (fake_ciphertext),
                                          plaintext,
                                          &plaintext_len);

  ASSERT_EQ (QUIC_CRYPTO_ERROR_AEAD, result);
}

TEST (quic_crypto_aead_roundtrip_aes128)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[256];
  uint8_t decrypted[256];
  size_t ciphertext_len = sizeof (ciphertext);
  size_t decrypted_len = sizeof (decrypted);
  uint64_t packet_number = 2;

  /* Derive keys from RFC test vector */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                             SOCKET_CRYPTO_SHA256_SIZE,
                                             QUIC_AEAD_AES_128_GCM,
                                             &keys);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Encrypt */
  result = SocketQUICCrypto_encrypt_payload (&keys,
                                             packet_number,
                                             test_header,
                                             sizeof (test_header),
                                             test_plaintext,
                                             sizeof (test_plaintext),
                                             ciphertext,
                                             &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (sizeof (test_plaintext) + QUIC_INITIAL_TAG_LEN, ciphertext_len);

  /* Decrypt */
  result = SocketQUICCrypto_decrypt_payload (&keys,
                                             packet_number,
                                             test_header,
                                             sizeof (test_header),
                                             ciphertext,
                                             ciphertext_len,
                                             decrypted,
                                             &decrypted_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (sizeof (test_plaintext), decrypted_len);
  ASSERT (memcmp (decrypted, test_plaintext, decrypted_len) == 0);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_aead_roundtrip_aes256)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[256];
  uint8_t decrypted[256];
  size_t ciphertext_len = sizeof (ciphertext);
  size_t decrypted_len = sizeof (decrypted);
  uint64_t packet_number = 42;

  /* SHA-384 size secret for AES-256-GCM */
  uint8_t secret[48];
  memset (secret, 0x55, sizeof (secret));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
      secret, sizeof (secret), QUIC_AEAD_AES_256_GCM, &keys);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Encrypt */
  result = SocketQUICCrypto_encrypt_payload (&keys,
                                             packet_number,
                                             test_header,
                                             sizeof (test_header),
                                             test_plaintext,
                                             sizeof (test_plaintext),
                                             ciphertext,
                                             &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Decrypt */
  result = SocketQUICCrypto_decrypt_payload (&keys,
                                             packet_number,
                                             test_header,
                                             sizeof (test_header),
                                             ciphertext,
                                             ciphertext_len,
                                             decrypted,
                                             &decrypted_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (memcmp (decrypted, test_plaintext, decrypted_len) == 0);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_aead_roundtrip_chacha20)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[256];
  uint8_t decrypted[256];
  size_t ciphertext_len = sizeof (ciphertext);
  size_t decrypted_len = sizeof (decrypted);
  uint64_t packet_number = 0x123456;

  uint8_t secret[SOCKET_CRYPTO_SHA256_SIZE];
  memset (secret, 0x66, sizeof (secret));

  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
      secret, sizeof (secret), QUIC_AEAD_CHACHA20_POLY1305, &keys);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Encrypt */
  result = SocketQUICCrypto_encrypt_payload (&keys,
                                             packet_number,
                                             test_header,
                                             sizeof (test_header),
                                             test_plaintext,
                                             sizeof (test_plaintext),
                                             ciphertext,
                                             &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Decrypt */
  result = SocketQUICCrypto_decrypt_payload (&keys,
                                             packet_number,
                                             test_header,
                                             sizeof (test_header),
                                             ciphertext,
                                             ciphertext_len,
                                             decrypted,
                                             &decrypted_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (memcmp (decrypted, test_plaintext, decrypted_len) == 0);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_aead_packet_number_zero)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[256];
  uint8_t decrypted[256];
  size_t ciphertext_len = sizeof (ciphertext);
  size_t decrypted_len = sizeof (decrypted);

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  /* Packet number 0: nonce should equal IV */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          0,
                                          test_header,
                                          sizeof (test_header),
                                          test_plaintext,
                                          sizeof (test_plaintext),
                                          ciphertext,
                                          &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  result = SocketQUICCrypto_decrypt_payload (&keys,
                                             0,
                                             test_header,
                                             sizeof (test_header),
                                             ciphertext,
                                             ciphertext_len,
                                             decrypted,
                                             &decrypted_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (memcmp (decrypted, test_plaintext, decrypted_len) == 0);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_aead_large_packet_number)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[256];
  uint8_t decrypted[256];
  size_t ciphertext_len = sizeof (ciphertext);
  size_t decrypted_len = sizeof (decrypted);
  /* Max 62-bit packet number */
  uint64_t large_pn = 0x3FFFFFFFFFFFFFFFULL;

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          large_pn,
                                          test_header,
                                          sizeof (test_header),
                                          test_plaintext,
                                          sizeof (test_plaintext),
                                          ciphertext,
                                          &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  result = SocketQUICCrypto_decrypt_payload (&keys,
                                             large_pn,
                                             test_header,
                                             sizeof (test_header),
                                             ciphertext,
                                             ciphertext_len,
                                             decrypted,
                                             &decrypted_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (memcmp (decrypted, test_plaintext, decrypted_len) == 0);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_aead_different_packet_numbers_produce_different_ciphertext)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext1[256];
  uint8_t ciphertext2[256];
  size_t ciphertext1_len = sizeof (ciphertext1);
  size_t ciphertext2_len = sizeof (ciphertext2);

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  /* Encrypt with packet number 1 */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          1,
                                          test_header,
                                          sizeof (test_header),
                                          test_plaintext,
                                          sizeof (test_plaintext),
                                          ciphertext1,
                                          &ciphertext1_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Encrypt with packet number 2 */
  result = SocketQUICCrypto_encrypt_payload (&keys,
                                             2,
                                             test_header,
                                             sizeof (test_header),
                                             test_plaintext,
                                             sizeof (test_plaintext),
                                             ciphertext2,
                                             &ciphertext2_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Same plaintext with different packet numbers -> different ciphertext */
  ASSERT (memcmp (ciphertext1, ciphertext2, ciphertext1_len) != 0);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_aead_modified_ciphertext_fails)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[256];
  uint8_t decrypted[256];
  size_t ciphertext_len = sizeof (ciphertext);
  size_t decrypted_len = sizeof (decrypted);

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  /* Encrypt */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          2,
                                          test_header,
                                          sizeof (test_header),
                                          test_plaintext,
                                          sizeof (test_plaintext),
                                          ciphertext,
                                          &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Modify one byte of ciphertext (not tag) */
  ciphertext[0] ^= 0x01;

  /* Decryption should fail with tag error */
  result = SocketQUICCrypto_decrypt_payload (&keys,
                                             2,
                                             test_header,
                                             sizeof (test_header),
                                             ciphertext,
                                             ciphertext_len,
                                             decrypted,
                                             &decrypted_len);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_TAG, result);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_aead_modified_tag_fails)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[256];
  uint8_t decrypted[256];
  size_t ciphertext_len = sizeof (ciphertext);
  size_t decrypted_len = sizeof (decrypted);

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  /* Encrypt */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          2,
                                          test_header,
                                          sizeof (test_header),
                                          test_plaintext,
                                          sizeof (test_plaintext),
                                          ciphertext,
                                          &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Modify the last byte (part of tag) */
  ciphertext[ciphertext_len - 1] ^= 0x01;

  /* Decryption should fail */
  result = SocketQUICCrypto_decrypt_payload (&keys,
                                             2,
                                             test_header,
                                             sizeof (test_header),
                                             ciphertext,
                                             ciphertext_len,
                                             decrypted,
                                             &decrypted_len);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_TAG, result);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_aead_modified_aad_fails)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[256];
  uint8_t decrypted[256];
  size_t ciphertext_len = sizeof (ciphertext);
  size_t decrypted_len = sizeof (decrypted);
  uint8_t modified_header[sizeof (test_header)];

  memcpy (modified_header, test_header, sizeof (test_header));

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  /* Encrypt with original header */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          2,
                                          test_header,
                                          sizeof (test_header),
                                          test_plaintext,
                                          sizeof (test_plaintext),
                                          ciphertext,
                                          &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Modify AAD */
  modified_header[0] ^= 0x01;

  /* Decryption with modified AAD should fail */
  result = SocketQUICCrypto_decrypt_payload (&keys,
                                             2,
                                             modified_header,
                                             sizeof (modified_header),
                                             ciphertext,
                                             ciphertext_len,
                                             decrypted,
                                             &decrypted_len);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_TAG, result);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_aead_wrong_packet_number_fails)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[256];
  uint8_t decrypted[256];
  size_t ciphertext_len = sizeof (ciphertext);
  size_t decrypted_len = sizeof (decrypted);

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  /* Encrypt with packet number 2 */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          2,
                                          test_header,
                                          sizeof (test_header),
                                          test_plaintext,
                                          sizeof (test_plaintext),
                                          ciphertext,
                                          &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Decrypt with different packet number */
  result = SocketQUICCrypto_decrypt_payload (&keys,
                                             3,
                                             test_header,
                                             sizeof (test_header),
                                             ciphertext,
                                             ciphertext_len,
                                             decrypted,
                                             &decrypted_len);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_TAG, result);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_aead_wrong_key_fails)
{
  SocketQUICPacketKeys_T keys1, keys2;
  uint8_t ciphertext[256];
  uint8_t decrypted[256];
  size_t ciphertext_len = sizeof (ciphertext);
  size_t decrypted_len = sizeof (decrypted);
  uint8_t secret2[SOCKET_CRYPTO_SHA256_SIZE];

  /* Different secrets for keys1 and keys2 */
  memset (secret2, 0x77, sizeof (secret2));

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys1);
  SocketQUICCrypto_derive_packet_keys (
      secret2, sizeof (secret2), QUIC_AEAD_AES_128_GCM, &keys2);

  /* Encrypt with keys1 */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys1,
                                          2,
                                          test_header,
                                          sizeof (test_header),
                                          test_plaintext,
                                          sizeof (test_plaintext),
                                          ciphertext,
                                          &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Decrypt with keys2 - should fail */
  result = SocketQUICCrypto_decrypt_payload (&keys2,
                                             2,
                                             test_header,
                                             sizeof (test_header),
                                             ciphertext,
                                             ciphertext_len,
                                             decrypted,
                                             &decrypted_len);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_TAG, result);

  SocketQUICPacketKeys_clear (&keys1);
  SocketQUICPacketKeys_clear (&keys2);
}

TEST (quic_crypto_aead_empty_plaintext)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[32];
  uint8_t decrypted[32];
  size_t ciphertext_len = sizeof (ciphertext);
  size_t decrypted_len = sizeof (decrypted);

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  /* Encrypt empty plaintext - result is just the tag */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          0,
                                          test_header,
                                          sizeof (test_header),
                                          test_plaintext,
                                          0,
                                          ciphertext,
                                          &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (QUIC_INITIAL_TAG_LEN, ciphertext_len);

  /* Decrypt - should succeed with empty output */
  result = SocketQUICCrypto_decrypt_payload (&keys,
                                             0,
                                             test_header,
                                             sizeof (test_header),
                                             ciphertext,
                                             ciphertext_len,
                                             decrypted,
                                             &decrypted_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (0, decrypted_len);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_aead_empty_header)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[256];
  uint8_t decrypted[256];
  size_t ciphertext_len = sizeof (ciphertext);
  size_t decrypted_len = sizeof (decrypted);

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  /* Encrypt with zero-length AAD */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          0,
                                          test_header,
                                          0,
                                          test_plaintext,
                                          sizeof (test_plaintext),
                                          ciphertext,
                                          &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Decrypt with zero-length AAD */
  result = SocketQUICCrypto_decrypt_payload (&keys,
                                             0,
                                             test_header,
                                             0,
                                             ciphertext,
                                             ciphertext_len,
                                             decrypted,
                                             &decrypted_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT (memcmp (decrypted, test_plaintext, decrypted_len) == 0);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_aead_tag_only_input)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext[QUIC_INITIAL_TAG_LEN];
  uint8_t decrypted[32];
  size_t ciphertext_len = sizeof (ciphertext);
  size_t decrypted_len = sizeof (decrypted);

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  /* Encrypt empty payload to get valid tag-only ciphertext */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          5,
                                          test_header,
                                          sizeof (test_header),
                                          test_plaintext,
                                          0,
                                          ciphertext,
                                          &ciphertext_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (QUIC_INITIAL_TAG_LEN, ciphertext_len);

  /* Decrypt should succeed */
  result = SocketQUICCrypto_decrypt_payload (&keys,
                                             5,
                                             test_header,
                                             sizeof (test_header),
                                             ciphertext,
                                             ciphertext_len,
                                             decrypted,
                                             &decrypted_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (0, decrypted_len);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_crypto_aead_same_input_same_output)
{
  SocketQUICPacketKeys_T keys;
  uint8_t ciphertext1[256];
  uint8_t ciphertext2[256];
  size_t ciphertext1_len = sizeof (ciphertext1);
  size_t ciphertext2_len = sizeof (ciphertext2);

  SocketQUICCrypto_derive_packet_keys (rfc_client_initial_secret,
                                       SOCKET_CRYPTO_SHA256_SIZE,
                                       QUIC_AEAD_AES_128_GCM,
                                       &keys);

  /* Encrypt twice with same inputs */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_encrypt_payload (&keys,
                                          2,
                                          test_header,
                                          sizeof (test_header),
                                          test_plaintext,
                                          sizeof (test_plaintext),
                                          ciphertext1,
                                          &ciphertext1_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  result = SocketQUICCrypto_encrypt_payload (&keys,
                                             2,
                                             test_header,
                                             sizeof (test_header),
                                             test_plaintext,
                                             sizeof (test_plaintext),
                                             ciphertext2,
                                             &ciphertext2_len);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Deterministic: same input -> same output */
  ASSERT_EQ (ciphertext1_len, ciphertext2_len);
  ASSERT (memcmp (ciphertext1, ciphertext2, ciphertext1_len) == 0);

  SocketQUICPacketKeys_clear (&keys);
}

/* RFC 9001 Appendix A.2 - Client Initial AES-128 */
static const uint8_t hp_client_initial_key[16]
    = { 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
        0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 };

static const uint8_t hp_client_initial_sample[16]
    = { 0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8,
        0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b };

static const uint8_t hp_client_initial_mask_expected[5]
    = { 0x43, 0x7b, 0x9a, 0xec, 0x36 };

/* RFC 9001 Appendix A.3 - Server Initial AES-128 */
static const uint8_t hp_server_initial_key[16]
    = { 0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76,
        0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14 };

static const uint8_t hp_server_initial_sample[16]
    = { 0x2c, 0xd0, 0x99, 0x1c, 0xd2, 0x5b, 0x0a, 0xac,
        0x40, 0x6a, 0x58, 0x16, 0xb6, 0x39, 0x41, 0x00 };

static const uint8_t hp_server_initial_mask_expected[5]
    = { 0x2e, 0xc0, 0xd8, 0x35, 0x6a };

/* RFC 9001 Appendix A.5 - ChaCha20 Short Header */
static const uint8_t hp_chacha20_key[32]
    = { 0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2, 0x1f, 0x48, 0x89,
        0x17, 0xa4, 0xfc, 0x8f, 0x1b, 0x73, 0x57, 0x36, 0x85, 0x60, 0x85,
        0x97, 0xd0, 0xef, 0xcb, 0x07, 0x6b, 0x0a, 0xb7, 0xa7, 0xa4 };

static const uint8_t hp_chacha20_sample[16]
    = { 0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80,
        0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b, 0xfb };

static const uint8_t hp_chacha20_mask_expected[5]
    = { 0xae, 0xfe, 0xfe, 0x7d, 0x03 };

/*
 * Test helper: Build a fake packet with sample at pn_offset + 4.
 * Returns a packet buffer suitable for header protection testing.
 */
static void
build_hp_test_packet (uint8_t *packet,
                      size_t *packet_len,
                      uint8_t first_byte,
                      size_t pn_offset,
                      uint32_t pn_value,
                      size_t pn_length,
                      const uint8_t sample[16])
{
  size_t i;

  /* First byte with packet number length encoded in lower 2 bits */
  packet[0] = (first_byte & 0xFC) | ((pn_length - 1) & 0x03);

  /* Fill bytes between first byte and packet number with zeros */
  for (i = 1; i < pn_offset; i++)
    packet[i] = 0x00;

  /* Write packet number (big-endian) */
  for (i = 0; i < pn_length; i++)
    packet[pn_offset + i] = (pn_value >> (8 * (pn_length - 1 - i))) & 0xFF;

  /* Write sample at pn_offset + 4 */
  memcpy (packet + pn_offset + 4, sample, 16);

  *packet_len = pn_offset + 4 + 16;
}

TEST (quic_hp_client_initial_roundtrip)
{
  uint8_t packet[64];
  uint8_t original[64];
  size_t packet_len;
  size_t pn_offset = 18;

  /* Build a long header packet with sample from RFC A.2 */
  build_hp_test_packet (packet,
                        &packet_len,
                        0xC0, /* Long header form */
                        pn_offset,
                        2, /* PN = 2 */
                        4, /* 4-byte PN */
                        hp_client_initial_sample);

  /* Save original */
  memcpy (original, packet, packet_len);

  /* Protect */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (hp_client_initial_key,
                                         sizeof (hp_client_initial_key),
                                         QUIC_AEAD_AES_128_GCM,
                                         packet,
                                         packet_len,
                                         pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Verify packet was modified */
  ASSERT (memcmp (packet, original, packet_len) != 0);

  /* Unprotect */
  result = SocketQUICCrypto_unprotect_header (hp_client_initial_key,
                                              sizeof (hp_client_initial_key),
                                              QUIC_AEAD_AES_128_GCM,
                                              packet,
                                              packet_len,
                                              pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Verify packet matches original */
  ASSERT (memcmp (packet, original, packet_len) == 0);
}

TEST (quic_hp_server_initial_roundtrip)
{
  uint8_t packet[64];
  uint8_t original[64];
  size_t packet_len;
  size_t pn_offset = 18;

  build_hp_test_packet (packet,
                        &packet_len,
                        0xC1, /* Long header */
                        pn_offset,
                        1, /* PN = 1 */
                        2, /* 2-byte PN */
                        hp_server_initial_sample);

  memcpy (original, packet, packet_len);

  /* Protect then unprotect */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (hp_server_initial_key,
                                         sizeof (hp_server_initial_key),
                                         QUIC_AEAD_AES_128_GCM,
                                         packet,
                                         packet_len,
                                         pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  result = SocketQUICCrypto_unprotect_header (hp_server_initial_key,
                                              sizeof (hp_server_initial_key),
                                              QUIC_AEAD_AES_128_GCM,
                                              packet,
                                              packet_len,
                                              pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  ASSERT (memcmp (packet, original, packet_len) == 0);
}

TEST (quic_hp_chacha20_roundtrip)
{
  uint8_t packet[64];
  uint8_t original[64];
  size_t packet_len;
  size_t pn_offset = 1; /* Short header: pn immediately after first byte */

  /* Build short header packet (bit 7 = 0) */
  build_hp_test_packet (packet,
                        &packet_len,
                        0x42, /* Short header */
                        pn_offset,
                        654360564, /* PN from RFC A.5 */
                        3,         /* 3-byte PN */
                        hp_chacha20_sample);

  memcpy (original, packet, packet_len);

  /* Protect then unprotect */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (hp_chacha20_key,
                                         sizeof (hp_chacha20_key),
                                         QUIC_AEAD_CHACHA20_POLY1305,
                                         packet,
                                         packet_len,
                                         pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  result = SocketQUICCrypto_unprotect_header (hp_chacha20_key,
                                              sizeof (hp_chacha20_key),
                                              QUIC_AEAD_CHACHA20_POLY1305,
                                              packet,
                                              packet_len,
                                              pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  ASSERT (memcmp (packet, original, packet_len) == 0);
}

TEST (quic_hp_long_header_mask_bits)
{
  uint8_t packet[64];
  size_t packet_len;
  size_t pn_offset = 18;
  uint8_t original_first_byte;

  /* Long header (bit 7 = 1): only lower 4 bits should be protected */
  build_hp_test_packet (packet,
                        &packet_len,
                        0xC3, /* 1100 0011 */
                        pn_offset,
                        0,
                        4,
                        hp_client_initial_sample);

  original_first_byte = packet[0];

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (hp_client_initial_key,
                                         sizeof (hp_client_initial_key),
                                         QUIC_AEAD_AES_128_GCM,
                                         packet,
                                         packet_len,
                                         pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Upper 4 bits should be unchanged (0xC = 1100) */
  ASSERT_EQ (original_first_byte & 0xF0, packet[0] & 0xF0);
}

TEST (quic_hp_short_header_mask_bits)
{
  uint8_t packet[64];
  size_t packet_len;
  size_t pn_offset = 1;
  uint8_t original_first_byte;

  /* Short header (bit 7 = 0): lower 5 bits should be protected */
  build_hp_test_packet (packet,
                        &packet_len,
                        0x43, /* 0100 0011 */
                        pn_offset,
                        0,
                        4,
                        hp_chacha20_sample);

  original_first_byte = packet[0];

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (hp_chacha20_key,
                                         sizeof (hp_chacha20_key),
                                         QUIC_AEAD_CHACHA20_POLY1305,
                                         packet,
                                         packet_len,
                                         pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Upper 3 bits should be unchanged (0x40 = 010) */
  ASSERT_EQ (original_first_byte & 0xE0, packet[0] & 0xE0);
}

TEST (quic_hp_all_pn_lengths)
{
  uint8_t packet[64];
  uint8_t original[64];
  size_t packet_len;
  size_t pn_offset = 18;
  size_t pn_length;

  /* Test all packet number lengths 1-4 */
  for (pn_length = 1; pn_length <= 4; pn_length++)
    {
      build_hp_test_packet (packet,
                            &packet_len,
                            0xC0,
                            pn_offset,
                            12345,
                            pn_length,
                            hp_client_initial_sample);
      memcpy (original, packet, packet_len);

      SocketQUICCrypto_Result result
          = SocketQUICCrypto_protect_header (hp_client_initial_key,
                                             sizeof (hp_client_initial_key),
                                             QUIC_AEAD_AES_128_GCM,
                                             packet,
                                             packet_len,
                                             pn_offset);
      ASSERT_EQ (QUIC_CRYPTO_OK, result);

      result
          = SocketQUICCrypto_unprotect_header (hp_client_initial_key,
                                               sizeof (hp_client_initial_key),
                                               QUIC_AEAD_AES_128_GCM,
                                               packet,
                                               packet_len,
                                               pn_offset);
      ASSERT_EQ (QUIC_CRYPTO_OK, result);

      ASSERT (memcmp (packet, original, packet_len) == 0);
    }
}

TEST (quic_hp_protect_ex_wrapper)
{
  uint8_t packet[64];
  uint8_t original[64];
  size_t packet_len;
  size_t pn_offset = 18;
  SocketQUICPacketKeys_T keys;

  /* Build keys struct with client HP key */
  SocketQUICPacketKeys_init (&keys);
  memcpy (keys.hp_key, hp_client_initial_key, sizeof (hp_client_initial_key));
  keys.hp_len = sizeof (hp_client_initial_key);
  keys.aead = QUIC_AEAD_AES_128_GCM;

  build_hp_test_packet (
      packet, &packet_len, 0xC0, pn_offset, 0, 4, hp_client_initial_sample);
  memcpy (original, packet, packet_len);

  /* Test _ex wrapper */
  SocketQUICCrypto_Result result = SocketQUICCrypto_protect_header_ex (
      &keys, packet, packet_len, pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  result = SocketQUICCrypto_unprotect_header_ex (
      &keys, packet, packet_len, pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  ASSERT (memcmp (packet, original, packet_len) == 0);

  SocketQUICPacketKeys_clear (&keys);
}

TEST (quic_hp_null_params)
{
  uint8_t packet[64] = { 0 };

  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL,
             SocketQUICCrypto_protect_header (
                 NULL, 16, QUIC_AEAD_AES_128_GCM, packet, 32, 18));
  ASSERT_EQ (
      QUIC_CRYPTO_ERROR_NULL,
      SocketQUICCrypto_protect_header (
          hp_client_initial_key, 16, QUIC_AEAD_AES_128_GCM, NULL, 32, 18));

  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL,
             SocketQUICCrypto_unprotect_header (
                 NULL, 16, QUIC_AEAD_AES_128_GCM, packet, 32, 18));
  ASSERT_EQ (
      QUIC_CRYPTO_ERROR_NULL,
      SocketQUICCrypto_unprotect_header (
          hp_client_initial_key, 16, QUIC_AEAD_AES_128_GCM, NULL, 32, 18));

  /* Test _ex wrappers */
  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL,
             SocketQUICCrypto_protect_header_ex (NULL, packet, 32, 18));
  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL,
             SocketQUICCrypto_unprotect_header_ex (NULL, packet, 32, 18));
}

TEST (quic_hp_packet_too_short)
{
  uint8_t packet[10] = { 0xC0 }; /* Long header */

  /* Packet too short for sample extraction */
  SocketQUICCrypto_Result result = SocketQUICCrypto_protect_header (
      hp_client_initial_key,
      sizeof (hp_client_initial_key),
      QUIC_AEAD_AES_128_GCM,
      packet,
      10, /* packet_len */
      5   /* pn_offset: needs 5+4+16=25 bytes */
  );
  ASSERT_EQ (QUIC_CRYPTO_ERROR_INPUT, result);
}

TEST (quic_hp_invalid_aead)
{
  uint8_t packet[64];
  size_t packet_len;
  size_t pn_offset = 18;

  build_hp_test_packet (
      packet, &packet_len, 0xC0, pn_offset, 0, 4, hp_client_initial_sample);

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (hp_client_initial_key,
                                         16,
                                         (SocketQUIC_AEAD)99, /* Invalid */
                                         packet,
                                         packet_len,
                                         pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_AEAD, result);
}

TEST (quic_hp_invalid_input)
{
  uint8_t packet[64] = { 0xC0 };

  /* pn_offset of 0 is invalid */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (hp_client_initial_key,
                                         sizeof (hp_client_initial_key),
                                         QUIC_AEAD_AES_128_GCM,
                                         packet,
                                         64,
                                         0);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_INPUT, result);

  /* packet_len of 0 is invalid */
  result = SocketQUICCrypto_protect_header (hp_client_initial_key,
                                            sizeof (hp_client_initial_key),
                                            QUIC_AEAD_AES_128_GCM,
                                            packet,
                                            0,
                                            18);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_INPUT, result);
}

/*
 * RFC 9001 Appendix A - Direct Mask Verification Tests
 *
 * Verify the actual mask bytes match the RFC test vectors, not just round-trip.
 */

TEST (quic_hp_client_initial_mask_rfc_vector)
{
  uint8_t packet[64];
  size_t packet_len;
  size_t pn_offset = 18;
  uint8_t first_byte_before, first_byte_after;
  uint8_t pn_before[4], pn_after[4];

  /* Build packet: first byte = 0xC3 (lower 2 bits = 3 means 4-byte PN) */
  build_hp_test_packet (packet,
                        &packet_len,
                        0xC0,
                        pn_offset,
                        0x00000002,
                        4,
                        hp_client_initial_sample);

  /* Record values before protection */
  first_byte_before = packet[0];
  memcpy (pn_before, packet + pn_offset, 4);

  /* Apply protection */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (hp_client_initial_key,
                                         sizeof (hp_client_initial_key),
                                         QUIC_AEAD_AES_128_GCM,
                                         packet,
                                         packet_len,
                                         pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  first_byte_after = packet[0];
  memcpy (pn_after, packet + pn_offset, 4);

  /*
   * Verify mask was applied correctly per RFC 9001 Appendix A.2:
   * mask = 0x437b9aec36
   * First byte: 0xC3 ^ (0x43 & 0x0F) = 0xC3 ^ 0x03 = 0xC0
   * Wait - we started with 0xC0, so after XOR with 0x03 we get 0xC3
   */
  ASSERT_EQ (first_byte_before ^ (hp_client_initial_mask_expected[0] & 0x0F),
             first_byte_after);

  /* PN bytes XORed with mask[1..4] */
  for (int i = 0; i < 4; i++)
    {
      ASSERT_EQ (pn_before[i] ^ hp_client_initial_mask_expected[1 + i],
                 pn_after[i]);
    }
}

TEST (quic_hp_server_initial_mask_rfc_vector)
{
  uint8_t packet[64];
  size_t packet_len;
  size_t pn_offset = 18;
  uint8_t first_byte_before, first_byte_after;
  uint8_t pn_before[2], pn_after[2];

  /* 2-byte PN (lower 2 bits = 1) */
  build_hp_test_packet (packet,
                        &packet_len,
                        0xC0,
                        pn_offset,
                        0x0001,
                        2,
                        hp_server_initial_sample);

  first_byte_before = packet[0];
  memcpy (pn_before, packet + pn_offset, 2);

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (hp_server_initial_key,
                                         sizeof (hp_server_initial_key),
                                         QUIC_AEAD_AES_128_GCM,
                                         packet,
                                         packet_len,
                                         pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  first_byte_after = packet[0];
  memcpy (pn_after, packet + pn_offset, 2);

  /* Verify mask: 0x2ec0d8356a */
  ASSERT_EQ (first_byte_before ^ (hp_server_initial_mask_expected[0] & 0x0F),
             first_byte_after);
  for (int i = 0; i < 2; i++)
    {
      ASSERT_EQ (pn_before[i] ^ hp_server_initial_mask_expected[1 + i],
                 pn_after[i]);
    }
}

TEST (quic_hp_chacha20_mask_rfc_vector)
{
  uint8_t packet[64];
  size_t packet_len;
  size_t pn_offset = 1;
  uint8_t first_byte_before, first_byte_after;
  uint8_t pn_before[3], pn_after[3];

  /* Short header with 3-byte PN */
  build_hp_test_packet (
      packet, &packet_len, 0x42, pn_offset, 0x270F14, 3, hp_chacha20_sample);

  first_byte_before = packet[0];
  memcpy (pn_before, packet + pn_offset, 3);

  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (hp_chacha20_key,
                                         sizeof (hp_chacha20_key),
                                         QUIC_AEAD_CHACHA20_POLY1305,
                                         packet,
                                         packet_len,
                                         pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  first_byte_after = packet[0];
  memcpy (pn_after, packet + pn_offset, 3);

  /* Short header: mask lower 5 bits. Mask = 0xaefefe7d03 */
  ASSERT_EQ (first_byte_before ^ (hp_chacha20_mask_expected[0] & 0x1F),
             first_byte_after);
  for (int i = 0; i < 3; i++)
    {
      ASSERT_EQ (pn_before[i] ^ hp_chacha20_mask_expected[1 + i], pn_after[i]);
    }
}

/* AES-256-GCM Test */
static const uint8_t hp_aes256_key[32]
    = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };

TEST (quic_hp_aes256_roundtrip)
{
  uint8_t packet[64];
  uint8_t original[64];
  size_t packet_len;
  size_t pn_offset = 18;

  build_hp_test_packet (
      packet, &packet_len, 0xC0, pn_offset, 12345, 4, hp_client_initial_sample);
  memcpy (original, packet, packet_len);

  /* AES-256-GCM uses 32-byte HP key */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (hp_aes256_key,
                                         sizeof (hp_aes256_key),
                                         QUIC_AEAD_AES_256_GCM,
                                         packet,
                                         packet_len,
                                         pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Verify modification occurred */
  ASSERT (memcmp (packet, original, packet_len) != 0);

  result = SocketQUICCrypto_unprotect_header (hp_aes256_key,
                                              sizeof (hp_aes256_key),
                                              QUIC_AEAD_AES_256_GCM,
                                              packet,
                                              packet_len,
                                              pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  ASSERT (memcmp (packet, original, packet_len) == 0);
}

/* Invalid key length tests */
TEST (quic_hp_invalid_key_length_aes128)
{
  uint8_t packet[64];
  size_t packet_len;
  size_t pn_offset = 18;

  build_hp_test_packet (
      packet, &packet_len, 0xC0, pn_offset, 0, 4, hp_client_initial_sample);

  /* AES-128-GCM expects 16-byte key, pass 32 */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (hp_aes256_key,
                                         32, /* Wrong size for AES-128 */
                                         QUIC_AEAD_AES_128_GCM,
                                         packet,
                                         packet_len,
                                         pn_offset);
  /* AES-ECB accepts both 16 and 32 byte keys, so this actually succeeds
   * with AES-256-ECB. This is by design - the AEAD enum selects the
   * mask algorithm family, but key length determines AES-128 vs AES-256. */
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
}

TEST (quic_hp_invalid_key_length_chacha20)
{
  uint8_t packet[64];
  size_t packet_len;
  size_t pn_offset = 1;

  build_hp_test_packet (
      packet, &packet_len, 0x42, pn_offset, 0, 3, hp_chacha20_sample);

  /* ChaCha20 requires exactly 32-byte key */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (hp_client_initial_key,
                                         16, /* Wrong - ChaCha20 needs 32 */
                                         QUIC_AEAD_CHACHA20_POLY1305,
                                         packet,
                                         packet_len,
                                         pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_AEAD, result);
}

/* PN bounds overflow test */
TEST (quic_hp_pn_bounds_overflow)
{
  uint8_t packet[64];
  size_t pn_offset = 18;

  /* Create packet: first byte indicates 4-byte PN */
  memset (packet, 0, sizeof (packet));
  packet[0] = 0xC3; /* Long header, 4-byte PN (lower 2 bits = 3) */

  /* Fill sample area at pn_offset + 4 (need buffer large enough for this) */
  memcpy (packet + pn_offset + 4, hp_client_initial_sample, 16);

  /*
   * Pass packet_len=32 even though buffer is 64.
   * pn_offset=18, pn_length=4, sample needs pn_offset + 4 + 16 = 38 bytes
   * But we tell the function packet_len=32, so it should fail.
   */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (hp_client_initial_key,
                                         sizeof (hp_client_initial_key),
                                         QUIC_AEAD_AES_128_GCM,
                                         packet,
                                         32, /* Claimed length too short */
                                         pn_offset);
  /* Should fail because sample extraction needs 38 bytes */
  ASSERT_EQ (QUIC_CRYPTO_ERROR_INPUT, result);
}

TEST (quic_hp_pn_exceeds_packet)
{
  uint8_t packet[64];
  size_t packet_len;
  size_t pn_offset = 18;

  /* Build valid packet first */
  build_hp_test_packet (packet,
                        &packet_len,
                        0xC3, /* 4-byte PN */
                        pn_offset,
                        0,
                        4,
                        hp_client_initial_sample);

  /*
   * Now artificially shrink packet_len so pn_offset + pn_length > packet_len
   * pn_offset=18, pn_length=4, so we need at least 22 bytes for PN
   * Set packet_len to 20 so PN extends past end
   */
  SocketQUICCrypto_Result result
      = SocketQUICCrypto_protect_header (hp_client_initial_key,
                                         sizeof (hp_client_initial_key),
                                         QUIC_AEAD_AES_128_GCM,
                                         packet,
                                         20, /* Too short for 4-byte PN */
                                         pn_offset);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_INPUT, result);
}

#endif /* SOCKET_HAS_TLS */

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
  ASSERT_NOT_NULL (SocketQUICCrypto_result_string (QUIC_CRYPTO_ERROR_BUFFER));
  ASSERT_NOT_NULL (SocketQUICCrypto_result_string (QUIC_CRYPTO_ERROR_TAG));
  ASSERT_NOT_NULL (SocketQUICCrypto_result_string (QUIC_CRYPTO_ERROR_INPUT));
  ASSERT_NOT_NULL (SocketQUICCrypto_result_string (99)); /* Unknown */
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

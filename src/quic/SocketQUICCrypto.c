/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQUICCrypto.c - QUIC Initial Secrets Derivation (RFC 9001 Section 5.2)
 *
 * Implements key derivation for QUIC Initial packets. Keys are derived from
 * the client's Destination Connection ID using HKDF per RFC 9001:
 *
 *   initial_secret = HKDF-Extract(salt, DCID)
 *   client_secret = HKDF-Expand-Label(initial_secret, "client in", "")
 *   server_secret = HKDF-Expand-Label(initial_secret, "server in", "")
 *   key = HKDF-Expand-Label(secret, "quic key", "")
 *   iv  = HKDF-Expand-Label(secret, "quic iv", "")
 *   hp  = HKDF-Expand-Label(secret, "quic hp", "")
 */

#include "quic/SocketQUICCrypto.h"

#include <string.h>

#include "quic/SocketQUICConstants.h"
#include "quic/SocketQUICVersion.h"

#ifdef SOCKET_HAS_TLS
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#endif

/* ============================================================================
 * Constants - RFC 9001 Section 5.2
 * ============================================================================
 */

/**
 * QUIC v1 Initial salt (RFC 9001 Section 5.2).
 * 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
 */
static const uint8_t quic_v1_initial_salt[QUIC_INITIAL_SALT_LEN]
    = { 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a };

/**
 * QUIC v2 Initial salt (RFC 9369).
 * 0x0dede3def700a6db819381be6e269dcbf9bd2ed9
 */
static const uint8_t quic_v2_initial_salt[QUIC_INITIAL_SALT_LEN]
    = { 0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
        0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9 };

/* HKDF-Expand-Label labels (RFC 9001 Section 5.1) */
static const char label_client_in[] = "client in";
static const char label_server_in[] = "server in";
static const char label_quic_key[] = "quic key";
static const char label_quic_iv[] = "quic iv";
static const char label_quic_hp[] = "quic hp";

/* Compile-time string length for labels */
#define STRLEN_LIT(s) (sizeof (s) - 1)

/* ============================================================================
 * Result String Table
 * ============================================================================
 */

static const char *result_strings[]
    = { [QUIC_CRYPTO_OK] = "OK",
        [QUIC_CRYPTO_ERROR_NULL] = "NULL pointer argument",
        [QUIC_CRYPTO_ERROR_VERSION] = "Unsupported QUIC version",
        [QUIC_CRYPTO_ERROR_HKDF] = "HKDF operation failed",
        [QUIC_CRYPTO_ERROR_NO_TLS] = "TLS support not available",
        [QUIC_CRYPTO_ERROR_AEAD] = "Invalid AEAD algorithm",
        [QUIC_CRYPTO_ERROR_SECRET_LEN] = "Secret length mismatch for AEAD",
        [QUIC_CRYPTO_ERROR_BUFFER] = "Output buffer too small",
        [QUIC_CRYPTO_ERROR_TAG] = "AEAD tag verification failed",
        [QUIC_CRYPTO_ERROR_INPUT] = "Invalid input" };

/* ============================================================================
 * AEAD Algorithm Tables (RFC 9001 Section 5.1)
 * ============================================================================
 */

/**
 * AEAD algorithm parameters per RFC 9001 Section 5.1.
 *
 * Each TLS 1.3 cipher suite specifies:
 *   - AEAD key/IV/HP sizes
 *   - Hash function for HKDF (determines secret length)
 *
 * TLS_AES_128_GCM_SHA256:       SHA-256, 32-byte secrets
 * TLS_AES_256_GCM_SHA384:       SHA-384, 48-byte secrets
 * TLS_CHACHA20_POLY1305_SHA256: SHA-256, 32-byte secrets
 */
static const struct
{
  size_t key_len;
  size_t iv_len;
  size_t hp_len;
  size_t secret_len;    /**< Required secret length (hash output size) */
  const char *hash_alg; /**< OpenSSL hash algorithm name */
} aead_params[QUIC_AEAD_COUNT] = {
  [QUIC_AEAD_AES_128_GCM] = { 16, 12, 16, 32, "SHA256" },
  [QUIC_AEAD_AES_256_GCM] = { 32, 12, 32, 48, "SHA384" },
  [QUIC_AEAD_CHACHA20_POLY1305] = { 32, 12, 32, 32, "SHA256" },
};

/**
 * Human-readable names for AEAD algorithms.
 */
static const char *aead_strings[QUIC_AEAD_COUNT] = {
  [QUIC_AEAD_AES_128_GCM] = "AES-128-GCM",
  [QUIC_AEAD_AES_256_GCM] = "AES-256-GCM",
  [QUIC_AEAD_CHACHA20_POLY1305] = "ChaCha20-Poly1305",
};

#define RESULT_COUNT (sizeof (result_strings) / sizeof (result_strings[0]))

const char *
SocketQUICCrypto_result_string (SocketQUICCrypto_Result result)
{
  if ((size_t)result < RESULT_COUNT && result_strings[result] != NULL)
    return result_strings[result];
  return "UNKNOWN";
}

/* ============================================================================
 * HKDF Functions (RFC 5869, RFC 8446) - OpenSSL 3.x API
 * ============================================================================
 */

#ifdef SOCKET_HAS_TLS

/**
 * HKDF-Extract using SHA-256.
 */
static int
hkdf_extract (const uint8_t *salt,
              size_t salt_len,
              const uint8_t *ikm,
              size_t ikm_len,
              uint8_t *prk,
              size_t prk_len)
{
  EVP_KDF *kdf = NULL;
  EVP_KDF_CTX *kctx = NULL;
  OSSL_PARAM params[5];
  int result = -1;
  int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;

  kdf = EVP_KDF_fetch (NULL, "HKDF", NULL);
  if (kdf == NULL)
    goto cleanup;

  kctx = EVP_KDF_CTX_new (kdf);
  if (kctx == NULL)
    goto cleanup;

  params[0]
      = OSSL_PARAM_construct_utf8_string (OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
  params[1] = OSSL_PARAM_construct_octet_string (
      OSSL_KDF_PARAM_KEY, (void *)ikm, ikm_len);
  params[2] = OSSL_PARAM_construct_octet_string (
      OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
  params[3] = OSSL_PARAM_construct_int (OSSL_KDF_PARAM_MODE, &mode);
  params[4] = OSSL_PARAM_construct_end ();

  if (EVP_KDF_derive (kctx, prk, prk_len, params) <= 0)
    goto cleanup;

  result = 0;

cleanup:
  EVP_KDF_CTX_free (kctx);
  EVP_KDF_free (kdf);
  return result;
}

/**
 * Build HKDF label structure per RFC 8446 Section 7.1.
 */
static int
build_hkdf_label (const char *label,
                  size_t label_len,
                  const uint8_t *context,
                  size_t context_len,
                  size_t output_len,
                  uint8_t *hkdf_label,
                  size_t *hkdf_label_len)
{
  *hkdf_label_len = 0;

  /* Length (2 bytes, big-endian) */
  hkdf_label[(*hkdf_label_len)++] = (uint8_t)((output_len >> 8) & 0xFF);
  hkdf_label[(*hkdf_label_len)++] = (uint8_t)(output_len & 0xFF);

  /* Label length and "tls13 " prefix + actual label */
  size_t full_label_len = QUIC_HKDF_TLS13_PREFIX_LEN + label_len;
  hkdf_label[(*hkdf_label_len)++] = (uint8_t)full_label_len;

  /* Check space for "tls13 " prefix */
  if (*hkdf_label_len + QUIC_HKDF_TLS13_PREFIX_LEN > QUIC_HKDF_LABEL_MAX_SIZE)
    return -1;
  memcpy (hkdf_label + *hkdf_label_len, "tls13 ", QUIC_HKDF_TLS13_PREFIX_LEN);
  *hkdf_label_len += QUIC_HKDF_TLS13_PREFIX_LEN;

  /* Check space for label */
  if (*hkdf_label_len + label_len > QUIC_HKDF_LABEL_MAX_SIZE)
    return -1;
  memcpy (hkdf_label + *hkdf_label_len, label, label_len);
  *hkdf_label_len += label_len;

  /* Context length and context */
  hkdf_label[(*hkdf_label_len)++] = (uint8_t)context_len;
  if (context_len > 0)
    {
      if (*hkdf_label_len + context_len > QUIC_HKDF_LABEL_MAX_SIZE)
        return -1;
      memcpy (hkdf_label + *hkdf_label_len, context, context_len);
      *hkdf_label_len += context_len;
    }

  return 0;
}

/**
 * HKDF-Expand-Label for TLS 1.3 / QUIC with configurable hash.
 *
 * @param secret      Input secret.
 * @param secret_len  Secret length.
 * @param hash_alg    OpenSSL hash algorithm name ("SHA256" or "SHA384").
 * @param label       HKDF label (without "tls13 " prefix).
 * @param label_len   Label length.
 * @param context     Context data (usually empty for QUIC).
 * @param context_len Context length.
 * @param output      Output buffer.
 * @param output_len  Desired output length.
 *
 * @return 0 on success, -1 on failure.
 */
static int
hkdf_expand_label_ex (const uint8_t *secret,
                      size_t secret_len,
                      const char *hash_alg,
                      const char *label,
                      size_t label_len,
                      const uint8_t *context,
                      size_t context_len,
                      uint8_t *output,
                      size_t output_len)
{
  EVP_KDF *kdf = NULL;
  EVP_KDF_CTX *kctx = NULL;
  OSSL_PARAM params[5];
  uint8_t hkdf_label[QUIC_HKDF_LABEL_MAX_SIZE];
  size_t hkdf_label_len = 0;
  int result = -1;
  int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;

  if (build_hkdf_label (label,
                        label_len,
                        context,
                        context_len,
                        output_len,
                        hkdf_label,
                        &hkdf_label_len)
      < 0)
    goto cleanup;

  kdf = EVP_KDF_fetch (NULL, "HKDF", NULL);
  if (kdf == NULL)
    goto cleanup;

  kctx = EVP_KDF_CTX_new (kdf);
  if (kctx == NULL)
    goto cleanup;

  params[0] = OSSL_PARAM_construct_utf8_string (
      OSSL_KDF_PARAM_DIGEST, (char *)hash_alg, 0);
  params[1] = OSSL_PARAM_construct_octet_string (
      OSSL_KDF_PARAM_KEY, (void *)secret, secret_len);
  params[2] = OSSL_PARAM_construct_octet_string (
      OSSL_KDF_PARAM_INFO, hkdf_label, hkdf_label_len);
  params[3] = OSSL_PARAM_construct_int (OSSL_KDF_PARAM_MODE, &mode);
  params[4] = OSSL_PARAM_construct_end ();

  if (EVP_KDF_derive (kctx, output, output_len, params) <= 0)
    goto cleanup;

  result = 0;

cleanup:
  EVP_KDF_CTX_free (kctx);
  EVP_KDF_free (kdf);
  SocketCrypto_secure_clear (hkdf_label, sizeof (hkdf_label));
  return result;
}

/**
 * HKDF-Expand-Label for TLS 1.3 / QUIC (SHA-256 only).
 *
 * Convenience wrapper for Initial packet derivation which always uses SHA-256.
 */
static int
hkdf_expand_label (const uint8_t *secret,
                   size_t secret_len,
                   const char *label,
                   size_t label_len,
                   const uint8_t *context,
                   size_t context_len,
                   uint8_t *output,
                   size_t output_len)
{
  return hkdf_expand_label_ex (secret,
                               secret_len,
                               "SHA256",
                               label,
                               label_len,
                               context,
                               context_len,
                               output,
                               output_len);
}

#endif /* SOCKET_HAS_TLS */

/* ============================================================================
 * Salt Access
 * ============================================================================
 */

SocketQUICCrypto_Result
SocketQUICCrypto_get_initial_salt (uint32_t version,
                                   const uint8_t **salt,
                                   size_t *salt_len)
{
  if (salt == NULL || salt_len == NULL)
    return QUIC_CRYPTO_ERROR_NULL;

  switch (version)
    {
    case QUIC_VERSION_1:
      *salt = quic_v1_initial_salt;
      *salt_len = QUIC_INITIAL_SALT_LEN;
      return QUIC_CRYPTO_OK;

    case QUIC_VERSION_2:
      *salt = quic_v2_initial_salt;
      *salt_len = QUIC_INITIAL_SALT_LEN;
      return QUIC_CRYPTO_OK;

    default:
      *salt = NULL;
      *salt_len = 0;
      return QUIC_CRYPTO_ERROR_VERSION;
    }
}

/* ============================================================================
 * Security Functions
 * ============================================================================
 */

void
SocketQUICCryptoSecrets_clear (SocketQUICCryptoSecrets_T *secrets)
{
  if (secrets == NULL)
    return;
  SocketCrypto_secure_clear (secrets, sizeof (*secrets));
}

/* ============================================================================
 * Traffic Keys Derivation
 * ============================================================================
 */

SocketQUICCrypto_Result
SocketQUICCrypto_derive_traffic_keys (const uint8_t *secret,
                                      size_t secret_len,
                                      uint8_t *key,
                                      uint8_t *iv,
                                      uint8_t *hp_key)
{
#ifdef SOCKET_HAS_TLS
  if (secret == NULL || key == NULL || iv == NULL || hp_key == NULL)
    return QUIC_CRYPTO_ERROR_NULL;

  if (secret_len != SOCKET_CRYPTO_SHA256_SIZE)
    return QUIC_CRYPTO_ERROR_HKDF;

  /* Derive key */
  if (hkdf_expand_label (secret,
                         secret_len,
                         label_quic_key,
                         STRLEN_LIT (label_quic_key),
                         NULL,
                         0,
                         key,
                         QUIC_INITIAL_KEY_LEN)
      < 0)
    return QUIC_CRYPTO_ERROR_HKDF;

  /* Derive IV */
  if (hkdf_expand_label (secret,
                         secret_len,
                         label_quic_iv,
                         STRLEN_LIT (label_quic_iv),
                         NULL,
                         0,
                         iv,
                         QUIC_INITIAL_IV_LEN)
      < 0)
    return QUIC_CRYPTO_ERROR_HKDF;

  /* Derive header protection key */
  if (hkdf_expand_label (secret,
                         secret_len,
                         label_quic_hp,
                         STRLEN_LIT (label_quic_hp),
                         NULL,
                         0,
                         hp_key,
                         QUIC_INITIAL_HP_KEY_LEN)
      < 0)
    return QUIC_CRYPTO_ERROR_HKDF;

  return QUIC_CRYPTO_OK;

#else
  (void)secret;
  (void)secret_len;
  (void)key;
  (void)iv;
  (void)hp_key;
  return QUIC_CRYPTO_ERROR_NO_TLS;
#endif
}

/* ============================================================================
 * Initial Secrets Derivation
 * ============================================================================
 */

SocketQUICCrypto_Result
SocketQUICCrypto_derive_initial_secrets (const SocketQUICConnectionID_T *dcid,
                                         uint32_t version,
                                         SocketQUICCryptoSecrets_T *secrets,
                                         SocketQUICInitialKeys_T *keys)
{
#ifdef SOCKET_HAS_TLS
  const uint8_t *salt;
  size_t salt_len;
  uint8_t local_initial_secret[SOCKET_CRYPTO_SHA256_SIZE];
  uint8_t local_client_secret[SOCKET_CRYPTO_SHA256_SIZE];
  uint8_t local_server_secret[SOCKET_CRYPTO_SHA256_SIZE];
  SocketQUICCrypto_Result result = QUIC_CRYPTO_ERROR_HKDF;

  if (dcid == NULL || keys == NULL)
    return QUIC_CRYPTO_ERROR_NULL;

  /* Initialize output structures */
  SocketQUICInitialKeys_init (keys);
  if (secrets != NULL)
    memset (secrets, 0, sizeof (*secrets));

  /* Get version-specific salt */
  result = SocketQUICCrypto_get_initial_salt (version, &salt, &salt_len);
  if (result != QUIC_CRYPTO_OK)
    return result;

  /* Step 1: initial_secret = HKDF-Extract(salt, DCID) */
  if (hkdf_extract (salt,
                    salt_len,
                    dcid->data,
                    dcid->len,
                    local_initial_secret,
                    SOCKET_CRYPTO_SHA256_SIZE)
      < 0)
    {
      result = QUIC_CRYPTO_ERROR_HKDF;
      goto cleanup;
    }

  /* Step 2: client_initial_secret = HKDF-Expand-Label(..., "client in", "") */
  if (hkdf_expand_label (local_initial_secret,
                         SOCKET_CRYPTO_SHA256_SIZE,
                         label_client_in,
                         STRLEN_LIT (label_client_in),
                         NULL,
                         0,
                         local_client_secret,
                         SOCKET_CRYPTO_SHA256_SIZE)
      < 0)
    {
      result = QUIC_CRYPTO_ERROR_HKDF;
      goto cleanup;
    }

  /* Step 3: server_initial_secret = HKDF-Expand-Label(..., "server in", "") */
  if (hkdf_expand_label (local_initial_secret,
                         SOCKET_CRYPTO_SHA256_SIZE,
                         label_server_in,
                         STRLEN_LIT (label_server_in),
                         NULL,
                         0,
                         local_server_secret,
                         SOCKET_CRYPTO_SHA256_SIZE)
      < 0)
    {
      result = QUIC_CRYPTO_ERROR_HKDF;
      goto cleanup;
    }

  /* Copy intermediate secrets if requested */
  if (secrets != NULL)
    {
      memcpy (secrets->initial_secret,
              local_initial_secret,
              SOCKET_CRYPTO_SHA256_SIZE);
      memcpy (secrets->client_initial_secret,
              local_client_secret,
              SOCKET_CRYPTO_SHA256_SIZE);
      memcpy (secrets->server_initial_secret,
              local_server_secret,
              SOCKET_CRYPTO_SHA256_SIZE);
    }

  /* Step 4: Derive client keys */
  result = SocketQUICCrypto_derive_traffic_keys (local_client_secret,
                                                 SOCKET_CRYPTO_SHA256_SIZE,
                                                 keys->client_key,
                                                 keys->client_iv,
                                                 keys->client_hp_key);
  if (result != QUIC_CRYPTO_OK)
    goto cleanup;

  /* Step 5: Derive server keys */
  result = SocketQUICCrypto_derive_traffic_keys (local_server_secret,
                                                 SOCKET_CRYPTO_SHA256_SIZE,
                                                 keys->server_key,
                                                 keys->server_iv,
                                                 keys->server_hp_key);
  if (result != QUIC_CRYPTO_OK)
    {
      SocketQUICInitialKeys_clear (keys);
      goto cleanup;
    }

  keys->initialized = 1;
  result = QUIC_CRYPTO_OK;

cleanup:
  SocketCrypto_secure_clear (local_initial_secret,
                             sizeof (local_initial_secret));
  SocketCrypto_secure_clear (local_client_secret, sizeof (local_client_secret));
  SocketCrypto_secure_clear (local_server_secret, sizeof (local_server_secret));
  return result;

#else
  (void)dcid;
  (void)version;
  (void)secrets;
  (void)keys;
  return QUIC_CRYPTO_ERROR_NO_TLS;
#endif
}

SocketQUICCrypto_Result
SocketQUICCrypto_derive_initial_keys (const SocketQUICConnectionID_T *dcid,
                                      uint32_t version,
                                      SocketQUICInitialKeys_T *keys)
{
  return SocketQUICCrypto_derive_initial_secrets (dcid, version, NULL, keys);
}

/* ============================================================================
 * AEAD Algorithm Functions
 * ============================================================================
 */

const char *
SocketQUIC_AEAD_string (SocketQUIC_AEAD aead)
{
  if (aead >= 0 && aead < QUIC_AEAD_COUNT)
    return aead_strings[aead];
  return "UNKNOWN";
}

SocketQUICCrypto_Result
SocketQUICCrypto_get_aead_key_sizes (SocketQUIC_AEAD aead,
                                     size_t *key_len,
                                     size_t *iv_len,
                                     size_t *hp_len)
{
  if (aead < 0 || aead >= QUIC_AEAD_COUNT)
    return QUIC_CRYPTO_ERROR_AEAD;

  if (key_len != NULL)
    *key_len = aead_params[aead].key_len;
  if (iv_len != NULL)
    *iv_len = aead_params[aead].iv_len;
  if (hp_len != NULL)
    *hp_len = aead_params[aead].hp_len;

  return QUIC_CRYPTO_OK;
}

SocketQUICCrypto_Result
SocketQUICCrypto_get_aead_secret_len (SocketQUIC_AEAD aead, size_t *secret_len)
{
  if (aead < 0 || aead >= QUIC_AEAD_COUNT)
    return QUIC_CRYPTO_ERROR_AEAD;

  if (secret_len != NULL)
    *secret_len = aead_params[aead].secret_len;

  return QUIC_CRYPTO_OK;
}

/* ============================================================================
 * Packet Protection Keys (RFC 9001 Section 5.1)
 * ============================================================================
 */

void
SocketQUICPacketKeys_init (SocketQUICPacketKeys_T *keys)
{
  if (keys == NULL)
    return;
  memset (keys, 0, sizeof (*keys));
}

void
SocketQUICPacketKeys_clear (SocketQUICPacketKeys_T *keys)
{
  if (keys == NULL)
    return;
  SocketCrypto_secure_clear (keys, sizeof (*keys));
}

SocketQUICCrypto_Result
SocketQUICCrypto_derive_packet_keys (const uint8_t *secret,
                                     size_t secret_len,
                                     SocketQUIC_AEAD aead,
                                     SocketQUICPacketKeys_T *keys)
{
#ifdef SOCKET_HAS_TLS
  size_t key_len, iv_len, hp_len;
  const char *hash_alg;

  if (secret == NULL || keys == NULL)
    return QUIC_CRYPTO_ERROR_NULL;

  /* Validate AEAD algorithm */
  if (aead < 0 || aead >= QUIC_AEAD_COUNT)
    return QUIC_CRYPTO_ERROR_AEAD;

  /* Get algorithm parameters from dispatch table */
  key_len = aead_params[aead].key_len;
  iv_len = aead_params[aead].iv_len;
  hp_len = aead_params[aead].hp_len;
  hash_alg = aead_params[aead].hash_alg;

  /* Validate secret length matches AEAD requirement (RFC 9001 §5.1) */
  if (secret_len != aead_params[aead].secret_len)
    return QUIC_CRYPTO_ERROR_SECRET_LEN;

  /* Initialize output structure */
  SocketQUICPacketKeys_init (keys);

  /* Derive AEAD key using algorithm-specific hash */
  if (hkdf_expand_label_ex (secret,
                            secret_len,
                            hash_alg,
                            label_quic_key,
                            STRLEN_LIT (label_quic_key),
                            NULL,
                            0,
                            keys->key,
                            key_len)
      < 0)
    {
      SocketQUICPacketKeys_clear (keys);
      return QUIC_CRYPTO_ERROR_HKDF;
    }

  /* Derive IV */
  if (hkdf_expand_label_ex (secret,
                            secret_len,
                            hash_alg,
                            label_quic_iv,
                            STRLEN_LIT (label_quic_iv),
                            NULL,
                            0,
                            keys->iv,
                            iv_len)
      < 0)
    {
      SocketQUICPacketKeys_clear (keys);
      return QUIC_CRYPTO_ERROR_HKDF;
    }

  /* Derive header protection key */
  if (hkdf_expand_label_ex (secret,
                            secret_len,
                            hash_alg,
                            label_quic_hp,
                            STRLEN_LIT (label_quic_hp),
                            NULL,
                            0,
                            keys->hp_key,
                            hp_len)
      < 0)
    {
      SocketQUICPacketKeys_clear (keys);
      return QUIC_CRYPTO_ERROR_HKDF;
    }

  keys->key_len = key_len;
  keys->hp_len = hp_len;
  keys->aead = aead;

  return QUIC_CRYPTO_OK;

#else
  (void)secret;
  (void)secret_len;
  (void)aead;
  (void)keys;
  return QUIC_CRYPTO_ERROR_NO_TLS;
#endif
}

/* ============================================================================
 * AEAD Packet Payload Encryption/Decryption (RFC 9001 Section 5.3)
 * ============================================================================
 */

/**
 * Form AEAD nonce by XORing IV with packet number (RFC 9001 §5.3).
 *
 * The 62-bit packet number is left-padded with zeros to 12 bytes,
 * then XORed with the IV.
 */
static void
quic_form_nonce (const uint8_t iv[QUIC_PACKET_IV_LEN],
                 uint64_t packet_number,
                 uint8_t nonce[QUIC_PACKET_IV_LEN])
{
  /* Copy IV to nonce */
  memcpy (nonce, iv, QUIC_PACKET_IV_LEN);

  /* XOR packet number (big-endian) into last 8 bytes of nonce */
  for (int i = 0; i < 8; i++)
    {
      nonce[QUIC_PACKET_IV_LEN - 1 - i]
          ^= (uint8_t)(packet_number >> (8 * i));
    }
}

/**
 * Map QUIC AEAD enum to SocketCrypto AEAD enum.
 */
static SocketCrypto_AeadAlg
quic_aead_to_crypto_alg (SocketQUIC_AEAD aead)
{
  static const SocketCrypto_AeadAlg map[QUIC_AEAD_COUNT] = {
    [QUIC_AEAD_AES_128_GCM] = SOCKET_CRYPTO_AEAD_AES_128_GCM,
    [QUIC_AEAD_AES_256_GCM] = SOCKET_CRYPTO_AEAD_AES_256_GCM,
    [QUIC_AEAD_CHACHA20_POLY1305] = SOCKET_CRYPTO_AEAD_CHACHA20_POLY1305,
  };
  return map[aead];
}

SocketQUICCrypto_Result
SocketQUICCrypto_encrypt_payload (const SocketQUICPacketKeys_T *keys,
                                  uint64_t packet_number,
                                  const uint8_t *header,
                                  size_t header_len,
                                  const uint8_t *plaintext,
                                  size_t plaintext_len,
                                  uint8_t *ciphertext,
                                  size_t *ciphertext_len)
{
#ifdef SOCKET_HAS_TLS
  uint8_t nonce[QUIC_PACKET_IV_LEN];
  uint8_t tag[SOCKET_CRYPTO_AEAD_TAG_SIZE];
  size_t required_size;
  SocketCrypto_AeadAlg alg;

  /* Parameter validation */
  if (keys == NULL || ciphertext == NULL || ciphertext_len == NULL)
    return QUIC_CRYPTO_ERROR_NULL;

  /* Header can be zero-length but not NULL */
  if (header == NULL && header_len > 0)
    return QUIC_CRYPTO_ERROR_NULL;

  /* Plaintext can be zero-length (auth-only) but not NULL if len > 0 */
  if (plaintext == NULL && plaintext_len > 0)
    return QUIC_CRYPTO_ERROR_NULL;

  /* Validate AEAD algorithm */
  if (keys->aead < 0 || keys->aead >= QUIC_AEAD_COUNT)
    return QUIC_CRYPTO_ERROR_AEAD;

  /* Check output buffer size */
  required_size = plaintext_len + SOCKET_CRYPTO_AEAD_TAG_SIZE;
  if (*ciphertext_len < required_size)
    return QUIC_CRYPTO_ERROR_BUFFER;

  /* Form nonce: IV XOR packet_number (RFC 9001 §5.3) */
  quic_form_nonce (keys->iv, packet_number, nonce);

  /* Map QUIC AEAD to SocketCrypto AEAD */
  alg = quic_aead_to_crypto_alg (keys->aead);

  /* Perform AEAD encryption */
  SocketCrypto_aead_encrypt (alg,
                             keys->key,
                             keys->key_len,
                             nonce,
                             QUIC_PACKET_IV_LEN,
                             plaintext,
                             plaintext_len,
                             header,
                             header_len,
                             ciphertext,
                             tag);

  /* Append tag to ciphertext */
  memcpy (ciphertext + plaintext_len, tag, SOCKET_CRYPTO_AEAD_TAG_SIZE);

  /* Set output length */
  *ciphertext_len = required_size;

  /* Clear sensitive data */
  SocketCrypto_secure_clear (nonce, sizeof (nonce));

  return QUIC_CRYPTO_OK;

#else
  (void)keys;
  (void)packet_number;
  (void)header;
  (void)header_len;
  (void)plaintext;
  (void)plaintext_len;
  (void)ciphertext;
  (void)ciphertext_len;
  return QUIC_CRYPTO_ERROR_NO_TLS;
#endif
}

SocketQUICCrypto_Result
SocketQUICCrypto_decrypt_payload (const SocketQUICPacketKeys_T *keys,
                                  uint64_t packet_number,
                                  const uint8_t *header,
                                  size_t header_len,
                                  const uint8_t *ciphertext,
                                  size_t ciphertext_len,
                                  uint8_t *plaintext,
                                  size_t *plaintext_len)
{
#ifdef SOCKET_HAS_TLS
  uint8_t nonce[QUIC_PACKET_IV_LEN];
  size_t payload_len;
  int decrypt_result;
  SocketCrypto_AeadAlg alg;

  /* Parameter validation */
  if (keys == NULL || plaintext == NULL || plaintext_len == NULL)
    return QUIC_CRYPTO_ERROR_NULL;

  /* Header can be zero-length but not NULL */
  if (header == NULL && header_len > 0)
    return QUIC_CRYPTO_ERROR_NULL;

  /* Ciphertext must be at least tag size */
  if (ciphertext == NULL || ciphertext_len < SOCKET_CRYPTO_AEAD_TAG_SIZE)
    return QUIC_CRYPTO_ERROR_INPUT;

  /* Validate AEAD algorithm */
  if (keys->aead < 0 || keys->aead >= QUIC_AEAD_COUNT)
    return QUIC_CRYPTO_ERROR_AEAD;

  /* Calculate payload length (ciphertext minus tag) */
  payload_len = ciphertext_len - SOCKET_CRYPTO_AEAD_TAG_SIZE;

  /* Check output buffer size */
  if (*plaintext_len < payload_len)
    return QUIC_CRYPTO_ERROR_BUFFER;

  /* Form nonce: IV XOR packet_number (RFC 9001 §5.3) */
  quic_form_nonce (keys->iv, packet_number, nonce);

  /* Map QUIC AEAD to SocketCrypto AEAD */
  alg = quic_aead_to_crypto_alg (keys->aead);

  /* Perform AEAD decryption with tag verification */
  decrypt_result
      = SocketCrypto_aead_decrypt (alg,
                                   keys->key,
                                   keys->key_len,
                                   nonce,
                                   QUIC_PACKET_IV_LEN,
                                   ciphertext,
                                   payload_len,
                                   header,
                                   header_len,
                                   ciphertext + payload_len, /* tag at end */
                                   plaintext);

  /* Clear sensitive data */
  SocketCrypto_secure_clear (nonce, sizeof (nonce));

  /* Check for authentication failure */
  if (decrypt_result != 0)
    return QUIC_CRYPTO_ERROR_TAG;

  /* Set output length */
  *plaintext_len = payload_len;

  return QUIC_CRYPTO_OK;

#else
  (void)keys;
  (void)packet_number;
  (void)header;
  (void)header_len;
  (void)ciphertext;
  (void)ciphertext_len;
  (void)plaintext;
  (void)plaintext_len;
  return QUIC_CRYPTO_ERROR_NO_TLS;
#endif
}

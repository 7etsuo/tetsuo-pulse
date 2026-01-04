/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* Cryptographic utilities - OpenSSL wrappers with /dev/urandom fallback */

#include "core/SocketCrypto.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

#if SOCKET_HAS_TLS
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#else
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#endif

#define WEBSOCKET_KEY_RANDOM_BYTES 16 /* 16 bytes = 128 bits per RFC 6455 */
#define WEBSOCKET_KEY_BASE64_LEN (SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE - 1)
#define WEBSOCKET_CONCAT_BUFFER_SIZE \
  64 /* key(24) + GUID(36) + null(1), rounded */
#define BASE64_BLOCK_SIZE 4
#define BASE64_INVALID_CHAR 255
#define BASE64_MAX_PADDING 2

const Except_T SocketCrypto_Failed
    = { &SocketCrypto_Failed, "Cryptographic operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketCrypto);

#define SOCKET_CRYPTO_CHECK_INPUT(ptr, len, name)                \
  do                                                             \
    {                                                            \
      if (!(ptr) && (len) > 0)                                   \
        SOCKET_RAISE_MSG (SocketCrypto,                          \
                          SocketCrypto_Failed,                   \
                          "%s: NULL input with non-zero length", \
                          name);                                 \
    }                                                            \
  while (0)

#define SOCKET_CRYPTO_REQUIRE_TLS                                   \
  do                                                                \
    {                                                               \
      SOCKET_RAISE_MSG (SocketCrypto,                               \
                        SocketCrypto_Failed,                        \
                        "%s requires TLS support (SOCKET_HAS_TLS)", \
                        __func__);                                  \
    }                                                               \
  while (0)

#define SOCKET_CRYPTO_RAISE_FAILED(name) \
  SOCKET_RAISE_MSG (                     \
      SocketCrypto, SocketCrypto_Failed, "%s computation failed", name)

static const char base64_alphabet[]
    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Maps ASCII to 6-bit value, 255 = invalid */
/* clang-format off */
static const unsigned char base64_decode_table[256] = {
  /* 0x00-0x0F */ 255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  /* 0x10-0x1F */ 255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  /* 0x20-0x2F */ 255,255,255,255,255,255,255,255,255,255,255, 62,255, 62,255, 63,
  /* 0x30-0x3F */  52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,255,255,255,
  /* 0x40-0x4F */ 255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
  /* 0x50-0x5F */  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255, 63,
  /* 0x60-0x6F */ 255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  /* 0x70-0x7F */  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,
  /* 0x80-0xFF - high ASCII all invalid */
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255
};
/* clang-format on */

static const char hex_lower[] = "0123456789abcdef";
static const char hex_upper[] = "0123456789ABCDEF";

#if SOCKET_HAS_TLS
static void
crypto_evp_digest (const EVP_MD *md,
                   const void *input,
                   size_t input_len,
                   unsigned char *output,
                   const char *algo_name)
{
  EVP_MD_CTX *volatile ctx = NULL;

  TRY
  {
    ctx = EVP_MD_CTX_new ();
    if (!ctx)
      SOCKET_RAISE_MSG (SocketCrypto,
                        SocketCrypto_Failed,
                        "%s: Failed to create context",
                        algo_name);

    if (EVP_DigestInit_ex (ctx, md, NULL) != 1
        || EVP_DigestUpdate (ctx, input, input_len) != 1
        || EVP_DigestFinal_ex (ctx, output, NULL) != 1)
      SOCKET_CRYPTO_RAISE_FAILED (algo_name);
  }
  FINALLY
  {
    if (ctx)
      EVP_MD_CTX_free (ctx);
  }
  END_TRY;
}
#endif

void
SocketCrypto_sha1 (const void *input,
                   size_t input_len,
                   unsigned char output[SOCKET_CRYPTO_SHA1_SIZE])
{
  assert (output);
  SOCKET_CRYPTO_CHECK_INPUT (input, input_len, "SHA-1");
  if (input_len > 0 && !SocketSecurity_check_size (input_len))
    SOCKET_RAISE_MSG (SocketCrypto,
                      SocketCrypto_Failed,
                      "SHA-1: input too large: %zu > %zu",
                      (size_t)input_len,
                      (size_t)SOCKET_SECURITY_MAX_ALLOCATION);

#if SOCKET_HAS_TLS
  crypto_evp_digest (EVP_sha1 (), input, input_len, output, "SHA-1");
#else
  (void)output;
  SOCKET_CRYPTO_REQUIRE_TLS;
#endif
}

void
SocketCrypto_sha256 (const void *input,
                     size_t input_len,
                     unsigned char output[SOCKET_CRYPTO_SHA256_SIZE])
{
  assert (output);
  SOCKET_CRYPTO_CHECK_INPUT (input, input_len, "SHA-256");
  if (input_len > 0 && !SocketSecurity_check_size (input_len))
    SOCKET_RAISE_MSG (SocketCrypto,
                      SocketCrypto_Failed,
                      "SHA-256: input too large: %zu > %zu",
                      (size_t)input_len,
                      (size_t)SOCKET_SECURITY_MAX_ALLOCATION);

#if SOCKET_HAS_TLS
  crypto_evp_digest (EVP_sha256 (), input, input_len, output, "SHA-256");
#else
  (void)output;
  SOCKET_CRYPTO_REQUIRE_TLS;
#endif
}

void
SocketCrypto_md5 (const void *input,
                  size_t input_len,
                  unsigned char output[SOCKET_CRYPTO_MD5_SIZE])
{
  assert (output);
  SOCKET_CRYPTO_CHECK_INPUT (input, input_len, "MD5");
  if (input_len > 0 && !SocketSecurity_check_size (input_len))
    SOCKET_RAISE_MSG (SocketCrypto,
                      SocketCrypto_Failed,
                      "MD5: input too large: %zu > %zu",
                      (size_t)input_len,
                      (size_t)SOCKET_SECURITY_MAX_ALLOCATION);

#if SOCKET_HAS_TLS
  crypto_evp_digest (EVP_md5 (), input, input_len, output, "MD5");
#else
  (void)output;
  SOCKET_CRYPTO_REQUIRE_TLS;
#endif
}

void
SocketCrypto_hmac_sha256 (const void *key,
                          size_t key_len,
                          const void *data,
                          size_t data_len,
                          unsigned char output[SOCKET_CRYPTO_SHA256_SIZE])
{
  assert (output);

  SOCKET_CRYPTO_CHECK_INPUT (key, key_len, "HMAC-SHA256 key");
  SOCKET_CRYPTO_CHECK_INPUT (data, data_len, "HMAC-SHA256 data");
  if (!SocketSecurity_check_size (data_len))
    {
      SOCKET_RAISE_MSG (SocketCrypto,
                        SocketCrypto_Failed,
                        "HMAC-SHA256: data too large: %zu > %zu",
                        (size_t)data_len,
                        (size_t)SOCKET_SECURITY_MAX_ALLOCATION);
    }

#if SOCKET_HAS_TLS
  /*
   * Security: Validate key_len fits in int for OpenSSL HMAC API.
   * Keys exceeding INT_MAX would be truncated on cast, potentially
   * weakening the MAC. In practice, HMAC keys should be 32-64 bytes;
   * longer keys are internally hashed anyway.
   */
  if (!SocketSecurity_check_size (key_len))
    {
      SOCKET_RAISE_MSG (SocketCrypto,
                        SocketCrypto_Failed,
                        "HMAC-SHA256: key too large: %zu > %zu",
                        (size_t)key_len,
                        (size_t)SOCKET_SECURITY_MAX_ALLOCATION);
    }
  if (key_len > (size_t)INT_MAX)
    SOCKET_RAISE_MSG (SocketCrypto,
                      SocketCrypto_Failed,
                      "HMAC-SHA256: Key length %zu exceeds INT_MAX",
                      key_len);

  unsigned int hmac_len = 0;
  unsigned char *result = HMAC (EVP_sha256 (),
                                key,
                                (int)key_len,
                                (const unsigned char *)data,
                                data_len,
                                output,
                                &hmac_len);

  if (!result || hmac_len != SOCKET_CRYPTO_SHA256_SIZE)
    SOCKET_CRYPTO_RAISE_FAILED ("HMAC-SHA256");
#else
  (void)output;
  SOCKET_CRYPTO_REQUIRE_TLS;
#endif
}

/* ============================================================================
 * HKDF Functions (RFC 5869, RFC 8446 §7.1)
 * ============================================================================
 */

#define HKDF_LABEL_PREFIX "tls13 "
#define HKDF_LABEL_PREFIX_LEN 6
#define HKDF_MAX_LABEL_LEN 255
#define HKDF_MAX_OUTPUT_LEN 255
#define HKDF_MAX_INFO_LEN 512

/*
 * build_expand_input - Build HMAC input for one HKDF-Expand iteration
 *
 * Constructs: T(i-1) | info | counter
 *
 * Returns: Length of constructed input.
 */
static size_t
build_expand_input (unsigned char *out,
                    const unsigned char *t_prev,
                    size_t t_prev_len,
                    const unsigned char *info,
                    size_t info_len,
                    unsigned char counter)
{
  size_t pos = 0;

  if (t_prev_len > 0)
    {
      memcpy (out, t_prev, t_prev_len);
      pos = t_prev_len;
    }

  memcpy (&out[pos], info, info_len);
  pos += info_len;
  out[pos++] = counter;

  return pos;
}

/*
 * copy_expand_output - Copy expansion block to output buffer
 *
 * Copies up to hash_len bytes from block to output at offset.
 * Returns: Number of bytes copied.
 */
static size_t
copy_expand_output (unsigned char *output,
                    size_t offset,
                    size_t output_len,
                    const unsigned char *block,
                    size_t hash_len)
{
  size_t remaining = output_len - offset;
  size_t to_copy = (remaining < hash_len) ? remaining : hash_len;
  memcpy (&output[offset], block, to_copy);
  return to_copy;
}

/*
 * hkdf_expand - RFC 5869 §2.3 HKDF-Expand
 *
 * T(0) = empty string
 * T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
 * OKM = T(1) | T(2) | ... | T(N)
 */
static void
hkdf_expand (const unsigned char *prk,
             size_t prk_len,
             const unsigned char *info,
             size_t info_len,
             unsigned char *output,
             size_t output_len)
{
  unsigned char t[SOCKET_CRYPTO_SHA256_SIZE];
  unsigned char hmac_input[SOCKET_CRYPTO_SHA256_SIZE + HKDF_MAX_INFO_LEN + 1];
  unsigned char counter = 1;
  size_t t_len = 0;
  size_t offset = 0;

  while (offset < output_len)
    {
      size_t input_len
          = build_expand_input (hmac_input, t, t_len, info, info_len, counter);

      SocketCrypto_hmac_sha256 (prk, prk_len, hmac_input, input_len, t);
      t_len = SOCKET_CRYPTO_SHA256_SIZE;

      offset += copy_expand_output (output, offset, output_len, t, t_len);
      counter++;
    }

  SocketCrypto_secure_clear (hmac_input, sizeof (hmac_input));
  SocketCrypto_secure_clear (t, sizeof (t));
}

void
SocketCrypto_hkdf_extract (const void *salt,
                           size_t salt_len,
                           const void *ikm,
                           size_t ikm_len,
                           unsigned char prk[SOCKET_CRYPTO_SHA256_SIZE])
{
  assert (prk);
  SOCKET_CRYPTO_CHECK_INPUT (ikm, ikm_len, "HKDF-Extract IKM");

  /* RFC 5869 §2.2: If salt not provided, use HashLen zero bytes */
  static const unsigned char zero_salt[SOCKET_CRYPTO_SHA256_SIZE] = { 0 };

  const void *actual_salt = salt;
  size_t actual_salt_len = salt_len;

  if (!salt || salt_len == 0)
    {
      actual_salt = zero_salt;
      actual_salt_len = SOCKET_CRYPTO_SHA256_SIZE;
    }

  /* PRK = HMAC-SHA256(salt, IKM) */
  SocketCrypto_hmac_sha256 (actual_salt, actual_salt_len, ikm, ikm_len, prk);
}

/*
 * build_hkdf_label - Construct HkdfLabel structure per RFC 8446 §7.1
 *
 * struct {
 *   uint16 length = output_len;
 *   opaque label<7..255> = "tls13 " + label;
 *   opaque context<0..255> = context;
 * } HkdfLabel;
 *
 * Returns: Length of constructed label in bytes.
 */
static size_t
build_hkdf_label (unsigned char *out,
                  size_t output_len,
                  const char *label,
                  size_t label_len,
                  const void *context,
                  size_t context_len)
{
  size_t pos = 0;

  /* Length (2 bytes, big-endian) */
  out[pos++] = (unsigned char)(output_len >> 8);
  out[pos++] = (unsigned char)(output_len & 0xFF);

  /* Label: length byte + "tls13 " + label */
  size_t full_label_len = HKDF_LABEL_PREFIX_LEN + label_len;
  out[pos++] = (unsigned char)full_label_len;
  memcpy (&out[pos], HKDF_LABEL_PREFIX, HKDF_LABEL_PREFIX_LEN);
  pos += HKDF_LABEL_PREFIX_LEN;
  memcpy (&out[pos], label, label_len);
  pos += label_len;

  /* Context: length byte + context data */
  out[pos++] = (unsigned char)context_len;
  if (context_len > 0)
    {
      memcpy (&out[pos], context, context_len);
      pos += context_len;
    }

  return pos;
}

void
SocketCrypto_hkdf_expand_label (const unsigned char *prk,
                                size_t prk_len,
                                const char *label,
                                const void *context,
                                size_t context_len,
                                unsigned char *output,
                                size_t output_len)
{
  assert (prk && output);
  assert (label);

  size_t label_len = strlen (label);

  /* Validate lengths per RFC 8446 */
  if (output_len > HKDF_MAX_OUTPUT_LEN)
    SOCKET_RAISE_MSG (SocketCrypto,
                      SocketCrypto_Failed,
                      "HKDF-Expand-Label: output_len %zu > 255",
                      output_len);

  if (label_len + HKDF_LABEL_PREFIX_LEN > HKDF_MAX_LABEL_LEN)
    SOCKET_RAISE_MSG (
        SocketCrypto, SocketCrypto_Failed, "HKDF-Expand-Label: label too long");

  if (context_len > HKDF_MAX_LABEL_LEN)
    SOCKET_RAISE_MSG (SocketCrypto,
                      SocketCrypto_Failed,
                      "HKDF-Expand-Label: context too long");

  /* Build HkdfLabel structure */
  unsigned char hkdf_label[2 + 1 + HKDF_LABEL_PREFIX_LEN + 255 + 1 + 255];
  size_t hkdf_label_len = build_hkdf_label (
      hkdf_label, output_len, label, label_len, context, context_len);

  /* Expand and clear */
  hkdf_expand (prk, prk_len, hkdf_label, hkdf_label_len, output, output_len);
  SocketCrypto_secure_clear (hkdf_label, sizeof (hkdf_label));
}

/* ============================================================================
 * AEAD Functions (RFC 5116, RFC 9001 §5.3)
 * ============================================================================
 */

#if SOCKET_HAS_TLS
/**
 * Get EVP cipher for AEAD algorithm.
 */
static const EVP_CIPHER *
aead_get_cipher (SocketCrypto_AeadAlg alg)
{
  switch (alg)
    {
    case SOCKET_CRYPTO_AEAD_AES_128_GCM:
      return EVP_aes_128_gcm ();
    case SOCKET_CRYPTO_AEAD_AES_256_GCM:
      return EVP_aes_256_gcm ();
    case SOCKET_CRYPTO_AEAD_CHACHA20_POLY1305:
      return EVP_chacha20_poly1305 ();
    default:
      return NULL;
    }
}

/**
 * Get expected key length for AEAD algorithm.
 */
static size_t
aead_key_len (SocketCrypto_AeadAlg alg)
{
  switch (alg)
    {
    case SOCKET_CRYPTO_AEAD_AES_128_GCM:
      return SOCKET_CRYPTO_AES128_KEY_SIZE;
    case SOCKET_CRYPTO_AEAD_AES_256_GCM:
    case SOCKET_CRYPTO_AEAD_CHACHA20_POLY1305:
      return SOCKET_CRYPTO_AES256_KEY_SIZE;
    default:
      return 0;
    }
}

/**
 * Get algorithm name for error messages.
 */
static const char *
aead_name (SocketCrypto_AeadAlg alg)
{
  switch (alg)
    {
    case SOCKET_CRYPTO_AEAD_AES_128_GCM:
      return "AES-128-GCM";
    case SOCKET_CRYPTO_AEAD_AES_256_GCM:
      return "AES-256-GCM";
    case SOCKET_CRYPTO_AEAD_CHACHA20_POLY1305:
      return "ChaCha20-Poly1305";
    default:
      return "Unknown AEAD";
    }
}

/**
 * Validate AEAD parameters.
 */
static void
aead_validate_params (SocketCrypto_AeadAlg alg,
                      const unsigned char *key,
                      size_t key_len,
                      const unsigned char *nonce,
                      size_t nonce_len,
                      const char *op_name)
{
  if (!key)
    SOCKET_RAISE_MSG (
        SocketCrypto, SocketCrypto_Failed, "%s: NULL key", op_name);

  size_t expected_key_len = aead_key_len (alg);
  if (expected_key_len == 0)
    SOCKET_RAISE_MSG (SocketCrypto,
                      SocketCrypto_Failed,
                      "%s: Invalid algorithm %d",
                      op_name,
                      (int)alg);

  if (key_len != expected_key_len)
    SOCKET_RAISE_MSG (SocketCrypto,
                      SocketCrypto_Failed,
                      "%s: Invalid key length %zu (expected %zu)",
                      op_name,
                      key_len,
                      expected_key_len);

  if (!nonce)
    SOCKET_RAISE_MSG (
        SocketCrypto, SocketCrypto_Failed, "%s: NULL nonce", op_name);

  if (nonce_len != SOCKET_CRYPTO_AEAD_IV_SIZE)
    SOCKET_RAISE_MSG (SocketCrypto,
                      SocketCrypto_Failed,
                      "%s: Invalid nonce length %zu (expected %d)",
                      op_name,
                      nonce_len,
                      SOCKET_CRYPTO_AEAD_IV_SIZE);
}
#endif /* SOCKET_HAS_TLS */

void
SocketCrypto_aead_encrypt (SocketCrypto_AeadAlg alg,
                           const unsigned char *key,
                           size_t key_len,
                           const unsigned char *nonce,
                           size_t nonce_len,
                           const unsigned char *plaintext,
                           size_t plaintext_len,
                           const unsigned char *aad,
                           size_t aad_len,
                           unsigned char *ciphertext,
                           unsigned char tag[SOCKET_CRYPTO_AEAD_TAG_SIZE])
{
  assert (tag);

  SOCKET_CRYPTO_CHECK_INPUT (
      plaintext, plaintext_len, "AEAD encrypt plaintext");
  SOCKET_CRYPTO_CHECK_INPUT (aad, aad_len, "AEAD encrypt AAD");

  if (plaintext_len > 0 && !SocketSecurity_check_size (plaintext_len))
    SOCKET_RAISE_MSG (SocketCrypto,
                      SocketCrypto_Failed,
                      "AEAD encrypt: plaintext too large: %zu",
                      plaintext_len);

  if (aad_len > 0 && !SocketSecurity_check_size (aad_len))
    SOCKET_RAISE_MSG (SocketCrypto,
                      SocketCrypto_Failed,
                      "AEAD encrypt: AAD too large: %zu",
                      aad_len);

#if SOCKET_HAS_TLS
  const char *name = aead_name (alg);
  aead_validate_params (alg, key, key_len, nonce, nonce_len, name);

  const EVP_CIPHER *cipher = aead_get_cipher (alg);
  EVP_CIPHER_CTX *volatile ctx = NULL;

  TRY
  {
    ctx = EVP_CIPHER_CTX_new ();
    if (!ctx)
      SOCKET_RAISE_MSG (SocketCrypto,
                        SocketCrypto_Failed,
                        "%s encrypt: Failed to create context",
                        name);

    /* Initialize encryption with cipher and NULL key/IV */
    if (EVP_EncryptInit_ex (ctx, cipher, NULL, NULL, NULL) != 1)
      SOCKET_RAISE_MSG (
          SocketCrypto, SocketCrypto_Failed, "%s encrypt: Init failed", name);

    /* Set IV length (must be before setting key/IV) */
    if (EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, NULL)
        != 1)
      SOCKET_RAISE_MSG (SocketCrypto,
                        SocketCrypto_Failed,
                        "%s encrypt: Set IV length failed",
                        name);

    /* Set key and IV */
    if (EVP_EncryptInit_ex (ctx, NULL, NULL, key, nonce) != 1)
      SOCKET_RAISE_MSG (SocketCrypto,
                        SocketCrypto_Failed,
                        "%s encrypt: Set key/IV failed",
                        name);

    int outlen;

    /* Process AAD (if any) */
    if (aad_len > 0)
      {
        if (EVP_EncryptUpdate (ctx, NULL, &outlen, aad, (int)aad_len) != 1)
          SOCKET_RAISE_MSG (SocketCrypto,
                            SocketCrypto_Failed,
                            "%s encrypt: AAD processing failed",
                            name);
      }

    /* Encrypt plaintext */
    if (plaintext_len > 0)
      {
        if (EVP_EncryptUpdate (
                ctx, ciphertext, &outlen, plaintext, (int)plaintext_len)
            != 1)
          SOCKET_RAISE_MSG (SocketCrypto,
                            SocketCrypto_Failed,
                            "%s encrypt: Encryption failed",
                            name);
      }

    /* Finalize (for GCM, no additional output)
     * Use dummy buffer when ciphertext is NULL to avoid UB from null+0 */
    unsigned char final_dummy;
    unsigned char *final_ptr
        = ciphertext ? ciphertext + plaintext_len : &final_dummy;
    if (EVP_EncryptFinal_ex (ctx, final_ptr, &outlen) != 1)
      SOCKET_RAISE_MSG (SocketCrypto,
                        SocketCrypto_Failed,
                        "%s encrypt: Finalize failed",
                        name);

    /* Get authentication tag */
    if (EVP_CIPHER_CTX_ctrl (
            ctx, EVP_CTRL_AEAD_GET_TAG, SOCKET_CRYPTO_AEAD_TAG_SIZE, tag)
        != 1)
      SOCKET_RAISE_MSG (SocketCrypto,
                        SocketCrypto_Failed,
                        "%s encrypt: Get tag failed",
                        name);
  }
  FINALLY
  {
    if (ctx)
      EVP_CIPHER_CTX_free (ctx);
  }
  END_TRY;
#else
  (void)alg;
  (void)key;
  (void)key_len;
  (void)nonce;
  (void)nonce_len;
  (void)plaintext;
  (void)plaintext_len;
  (void)aad;
  (void)aad_len;
  (void)ciphertext;
  (void)tag;
  SOCKET_CRYPTO_REQUIRE_TLS;
#endif
}

int
SocketCrypto_aead_decrypt (SocketCrypto_AeadAlg alg,
                           const unsigned char *key,
                           size_t key_len,
                           const unsigned char *nonce,
                           size_t nonce_len,
                           const unsigned char *ciphertext,
                           size_t ciphertext_len,
                           const unsigned char *aad,
                           size_t aad_len,
                           const unsigned char tag[SOCKET_CRYPTO_AEAD_TAG_SIZE],
                           unsigned char *plaintext)
{
  assert (tag);

  SOCKET_CRYPTO_CHECK_INPUT (
      ciphertext, ciphertext_len, "AEAD decrypt ciphertext");
  SOCKET_CRYPTO_CHECK_INPUT (aad, aad_len, "AEAD decrypt AAD");

  if (ciphertext_len > 0 && !SocketSecurity_check_size (ciphertext_len))
    SOCKET_RAISE_MSG (SocketCrypto,
                      SocketCrypto_Failed,
                      "AEAD decrypt: ciphertext too large: %zu",
                      ciphertext_len);

  if (aad_len > 0 && !SocketSecurity_check_size (aad_len))
    SOCKET_RAISE_MSG (SocketCrypto,
                      SocketCrypto_Failed,
                      "AEAD decrypt: AAD too large: %zu",
                      aad_len);

#if SOCKET_HAS_TLS
  const char *name = aead_name (alg);
  aead_validate_params (alg, key, key_len, nonce, nonce_len, name);

  const EVP_CIPHER *cipher = aead_get_cipher (alg);
  EVP_CIPHER_CTX *volatile ctx = NULL;
  volatile int result = -1;

  TRY
  {
    ctx = EVP_CIPHER_CTX_new ();
    if (!ctx)
      SOCKET_RAISE_MSG (SocketCrypto,
                        SocketCrypto_Failed,
                        "%s decrypt: Failed to create context",
                        name);

    /* Initialize decryption with cipher and NULL key/IV */
    if (EVP_DecryptInit_ex (ctx, cipher, NULL, NULL, NULL) != 1)
      SOCKET_RAISE_MSG (
          SocketCrypto, SocketCrypto_Failed, "%s decrypt: Init failed", name);

    /* Set IV length */
    if (EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, NULL)
        != 1)
      SOCKET_RAISE_MSG (SocketCrypto,
                        SocketCrypto_Failed,
                        "%s decrypt: Set IV length failed",
                        name);

    /* Set key and IV */
    if (EVP_DecryptInit_ex (ctx, NULL, NULL, key, nonce) != 1)
      SOCKET_RAISE_MSG (SocketCrypto,
                        SocketCrypto_Failed,
                        "%s decrypt: Set key/IV failed",
                        name);

    int outlen;

    /* Process AAD (if any) */
    if (aad_len > 0)
      {
        if (EVP_DecryptUpdate (ctx, NULL, &outlen, aad, (int)aad_len) != 1)
          SOCKET_RAISE_MSG (SocketCrypto,
                            SocketCrypto_Failed,
                            "%s decrypt: AAD processing failed",
                            name);
      }

    /* Decrypt ciphertext */
    if (ciphertext_len > 0)
      {
        if (EVP_DecryptUpdate (
                ctx, plaintext, &outlen, ciphertext, (int)ciphertext_len)
            != 1)
          SOCKET_RAISE_MSG (SocketCrypto,
                            SocketCrypto_Failed,
                            "%s decrypt: Decryption failed",
                            name);
      }

    /* Set expected tag for verification */
    if (EVP_CIPHER_CTX_ctrl (ctx,
                             EVP_CTRL_AEAD_SET_TAG,
                             SOCKET_CRYPTO_AEAD_TAG_SIZE,
                             (void *)tag)
        != 1)
      SOCKET_RAISE_MSG (SocketCrypto,
                        SocketCrypto_Failed,
                        "%s decrypt: Set tag failed",
                        name);

    /* Finalize and verify tag (returns 0 on auth failure)
     * Use dummy buffer when plaintext is NULL to avoid UB from null+0 */
    unsigned char final_dummy;
    unsigned char *final_ptr
        = plaintext ? plaintext + ciphertext_len : &final_dummy;
    int final_len;
    if (EVP_DecryptFinal_ex (ctx, final_ptr, &final_len) == 1)
      result = 0; /* Success - tag verified */
    /* else result stays -1 (auth failure) */
  }
  FINALLY
  {
    if (ctx)
      EVP_CIPHER_CTX_free (ctx);
  }
  END_TRY;

  return result;
#else
  (void)alg;
  (void)key;
  (void)key_len;
  (void)nonce;
  (void)nonce_len;
  (void)ciphertext;
  (void)ciphertext_len;
  (void)aad;
  (void)aad_len;
  (void)tag;
  (void)plaintext;
  SOCKET_CRYPTO_REQUIRE_TLS;
  return -1;
#endif
}

size_t
SocketCrypto_base64_encoded_size (size_t input_len)
{
  /* ceil(input_len / 3) * 4 + 1 with overflow checks */
  if (input_len > SIZE_MAX - 2)
    return 0;

  size_t padded_groups = (input_len + 2) / 3;

  if (padded_groups > SIZE_MAX / 4)
    return 0;

  size_t encoded_len = padded_groups * 4;

  if (encoded_len > SIZE_MAX - 1)
    return 0;

  return encoded_len + 1;
}

size_t
SocketCrypto_base64_decoded_size (size_t input_len)
{
  /* ceil(input_len / 4) * 3 with overflow checks */
  if (input_len > SIZE_MAX - 3)
    return 0;

  size_t groups = (input_len + 3) / 4;

  if (groups > SIZE_MAX / 3)
    return 0;

  return groups * 3;
}

static void
base64_encode_triplet (const unsigned char *in, char *out)
{
  out[0] = base64_alphabet[in[0] >> 2];
  out[1] = base64_alphabet[((in[0] & 0x03) << 4) | (in[1] >> 4)];
  out[2] = base64_alphabet[((in[1] & 0x0F) << 2) | (in[2] >> 6)];
  out[3] = base64_alphabet[in[2] & 0x3F];
}

static void
base64_encode_remainder (const unsigned char *in, size_t remaining, char *out)
{
  out[0] = base64_alphabet[in[0] >> 2];

  if (remaining == 2)
    {
      out[1] = base64_alphabet[((in[0] & 0x03) << 4) | (in[1] >> 4)];
      out[2] = base64_alphabet[(in[1] & 0x0F) << 2];
    }
  else
    {
      out[1] = base64_alphabet[(in[0] & 0x03) << 4];
      out[2] = '=';
    }
  out[3] = '=';
}

ssize_t
SocketCrypto_base64_encode (const void *input,
                            size_t input_len,
                            char *output,
                            size_t output_size)
{
  const unsigned char *in = (const unsigned char *)input;
  size_t required_size;
  size_t out_pos = 0;
  size_t i;

  if (!output)
    return -1;

  if (!input && input_len > 0)
    return -1;

  if (input_len == 0)
    {
      if (output_size < 1)
        return -1;
      output[0] = '\0';
      return 0;
    }

  if (!SocketSecurity_check_size (input_len))
    return -1;

  required_size = SocketCrypto_base64_encoded_size (input_len);
  if (required_size == 0 || output_size < required_size)
    return -1;
  for (i = 0; i + 2 < input_len; i += 3)
    {
      base64_encode_triplet (in + i, output + out_pos);
      out_pos += 4;
    }

  if (i < input_len)
    {
      base64_encode_remainder (in + i, input_len - i, output + out_pos);
      out_pos += 4;
    }

  output[out_pos] = '\0';
  return (ssize_t)out_pos;
}

/* Check if character is ignorable whitespace (RFC 4648) */
static int
base64_is_whitespace (unsigned char c)
{
  return (c == ' ' || c == '\t' || c == '\n' || c == '\r');
}

static int
base64_decode_block (const unsigned char *buffer,
                     int padding_count,
                     unsigned char *output,
                     size_t *out_pos,
                     size_t output_size)
{
  int output_bytes = 3 - padding_count;

  if (*out_pos + (size_t)output_bytes > output_size)
    return -1;

  output[(*out_pos)++] = (buffer[0] << 2) | (buffer[1] >> 4);
  if (output_bytes >= 2)
    output[(*out_pos)++] = (buffer[1] << 4) | (buffer[2] >> 2);
  if (output_bytes >= 3)
    output[(*out_pos)++] = (buffer[2] << 6) | buffer[3];

  return 0;
}

/* Decode incomplete final block without padding (handles non-conformant input)
 */
static int
base64_decode_partial_block (unsigned char *buffer,
                             int buffer_pos,
                             unsigned char *output,
                             size_t *out_pos,
                             size_t output_size)
{
  int real_chars = buffer_pos;

  if (buffer_pos < 2)
    return -1;

  while (buffer_pos < BASE64_BLOCK_SIZE)
    buffer[buffer_pos++] = 0;

  if (*out_pos >= output_size)
    return -1;
  output[(*out_pos)++] = (buffer[0] << 2) | (buffer[1] >> 4);

  if (real_chars >= 3)
    {
      if (*out_pos >= output_size)
        return -1;
      output[(*out_pos)++] = (buffer[1] << 4) | (buffer[2] >> 2);
    }

  return 0;
}

/* Process one Base64 character: returns 0 (success), 1 (skip whitespace), -1
 * (error) */
static int
base64_decode_char (unsigned char c,
                    unsigned char *buffer,
                    int *buffer_pos,
                    int *padding_count,
                    unsigned char *output,
                    size_t *out_pos,
                    size_t output_size)
{
  if (base64_is_whitespace (c))
    return 1;

  if (c == '=')
    {
      (*padding_count)++;
      if (*padding_count > BASE64_MAX_PADDING)
        return -1;
      buffer[(*buffer_pos)++] = 0;

      if (*buffer_pos == BASE64_BLOCK_SIZE)
        {
          if (base64_decode_block (
                  buffer, *padding_count, output, out_pos, output_size)
              < 0)
            return -1;
          *buffer_pos = 0;
        }
      return 0;
    }

  if (*padding_count > 0)
    return -1;

  unsigned char val = base64_decode_table[c];
  if (val == BASE64_INVALID_CHAR)
    return -1;

  buffer[(*buffer_pos)++] = val;

  if (*buffer_pos == BASE64_BLOCK_SIZE)
    {
      if (base64_decode_block (buffer, 0, output, out_pos, output_size) < 0)
        return -1;
      *buffer_pos = 0;
      *padding_count = 0;
    }

  return 0;
}

/*
 * Maximum Base64 scan length to prevent unbounded strlen on untrusted input.
 *
 * 64KB (65536 bytes) chosen to balance security and practical use:
 * - Security: Prevents unbounded strnlen() scans on potentially malicious or
 *   non-NUL-terminated input, limiting CPU/memory exposure during validation
 * - Practical: Supports ~48KB of decoded data (base64 expands by ~4/3), which
 *   covers common use cases like API keys, tokens, certificates, and small
 *   embedded resources
 * - Conservative: Much smaller than SOCKET_SECURITY_MAX_ALLOCATION (256MB) as
 *   this is a preliminary scan limit, not the final allocation limit
 *
 * Larger base64 inputs must provide explicit length via the input_len parameter
 * rather than relying on NUL-termination scanning.
 */
#define BASE64_MAX_SCAN_LENGTH 65536

static int
base64_validate_input (const char *input, size_t *input_len)
{
  if (!input)
    return 0;

  if (*input_len == 0)
    {
      /* Use strnlen to prevent unbounded strlen scan on potentially
       * untrusted or non-NUL-terminated input */
      *input_len = strnlen (input, BASE64_MAX_SCAN_LENGTH);

      if (*input_len >= BASE64_MAX_SCAN_LENGTH)
        return -1; /* Likely not NUL-terminated or excessively long */
    }

  if (*input_len == 0)
    return 0;

  if (!SocketSecurity_check_size (*input_len))
    return -1;

  return 1;
}

ssize_t
SocketCrypto_base64_decode (const char *input,
                            size_t input_len,
                            unsigned char *output,
                            size_t output_size)
{
  size_t out_pos = 0;
  unsigned char buffer[BASE64_BLOCK_SIZE];
  int buffer_pos = 0;
  int padding_count = 0;
  size_t i;
  int valid;

  if (!output)
    return -1;

  valid = base64_validate_input (input, &input_len);
  if (valid <= 0)
    return valid;

  for (i = 0; i < input_len; i++)
    {
      int result = base64_decode_char ((unsigned char)input[i],
                                       buffer,
                                       &buffer_pos,
                                       &padding_count,
                                       output,
                                       &out_pos,
                                       output_size);
      if (result < 0)
        return -1;
    }

  if (buffer_pos > 0)
    {
      if (base64_decode_partial_block (
              buffer, buffer_pos, output, &out_pos, output_size)
          < 0)
        return -1;
    }

  return (ssize_t)out_pos;
}

void
SocketCrypto_hex_encode (const void *input,
                         size_t input_len,
                         char *output,
                         int lowercase)
{
  const unsigned char *in = (const unsigned char *)input;
  const char *alphabet = lowercase ? hex_lower : hex_upper;
  size_t i;

  assert (output);

  if (!input || input_len == 0)
    {
      output[0] = '\0';
      return;
    }

  if (!SocketSecurity_check_size (input_len))
    {
      SOCKET_RAISE_MSG (SocketCrypto,
                        SocketCrypto_Failed,
                        "hex_encode: input too large: %zu > %zu",
                        (size_t)input_len,
                        (size_t)SOCKET_SECURITY_MAX_ALLOCATION);
    }

  if (input_len > SIZE_MAX / 2)
    {
      SOCKET_RAISE_MSG (SocketCrypto,
                        SocketCrypto_Failed,
                        "hex_encode: input_len %zu causes index overflow",
                        input_len);
    }

  for (i = 0; i < input_len; i++)
    {
      output[i * 2] = alphabet[(in[i] >> 4) & 0x0F];
      output[i * 2 + 1] = alphabet[in[i] & 0x0F];
    }
  output[input_len * 2] = '\0';
}

/* Convert hex character to 4-bit nibble: 0-15 on success, -1 on invalid */
static int
hex_char_to_nibble (char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

ssize_t
SocketCrypto_hex_decode (const char *input,
                         size_t input_len,
                         unsigned char *output,
                         size_t output_size)
{
  size_t i;

  if (!input || !output)
    return -1;

  if (!SocketSecurity_check_size (input_len))
    return -1;

  if (output_size < input_len / 2)
    return -1;

  if (input_len % 2 != 0)
    return -1;

  for (i = 0; i < input_len / 2; i++)
    {
      int hi = hex_char_to_nibble (input[i * 2]);
      int lo = hex_char_to_nibble (input[i * 2 + 1]);

      if (hi < 0 || lo < 0)
        return -1;

      output[i] = (unsigned char)((hi << 4) | lo);
    }

  return (ssize_t)(input_len / 2);
}

#if !SOCKET_HAS_TLS
static pthread_mutex_t urand_mutex = PTHREAD_MUTEX_INITIALIZER;
static int urand_fd = -1;

/* Ensure /dev/urandom fd is open (caller must hold urand_mutex) */
static int
urandom_ensure_open (void)
{
  if (urand_fd >= 0)
    return urand_fd;

  urand_fd = open ("/dev/urandom", O_RDONLY);
  return urand_fd;
}

/* Read exactly len bytes from /dev/urandom, handling EINTR */
static int
urandom_read_all (int fd, unsigned char *buf, size_t len)
{
  size_t bytes_read = 0;

  while (bytes_read < len)
    {
      ssize_t n = read (fd, buf + bytes_read, len - bytes_read);
      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          return -1;
        }
      if (n == 0)
        return -1;
      bytes_read += (size_t)n;
    }

  return 0;
}
#endif

int
SocketCrypto_random_bytes (void *output, size_t len)
{
  if (!output)
    return -1;

  if (len == 0)
    return 0;

  if (!SocketSecurity_check_size (len))
    return -1;

#if SOCKET_HAS_TLS
  /* OpenSSL RAND_bytes takes int; ensure len fits even if MAX_ALLOCATION is
   * overridden to exceed INT_MAX */
  if (len > (size_t)INT_MAX)
    return -1;

  if (RAND_bytes ((unsigned char *)output, (int)len) != 1)
    return -1;
  return 0;
#else
  int result = -1;

  SOCKET_MUTEX_LOCK_OR_RAISE (&urand_mutex, SocketCrypto, SocketCrypto_Failed);
  int fd = urandom_ensure_open ();
  if (fd >= 0)
    result = urandom_read_all (fd, (unsigned char *)output, len);
  SOCKET_MUTEX_UNLOCK (&urand_mutex);

  return result;
#endif
}

uint32_t
SocketCrypto_random_uint32 (void)
{
  uint32_t value;

  if (SocketCrypto_random_bytes (&value, sizeof (value)) != 0)
    SOCKET_RAISE_MSG (
        SocketCrypto, SocketCrypto_Failed, "Random number generation failed");

  return value;
}

void
SocketCrypto_cleanup (void)
{
#if !SOCKET_HAS_TLS
  SOCKET_MUTEX_LOCK_OR_RAISE (&urand_mutex, SocketCrypto, SocketCrypto_Failed);
  if (urand_fd >= 0)
    {
      close (urand_fd);
      urand_fd = -1;
    }
  SOCKET_MUTEX_UNLOCK (&urand_mutex);
#endif
}

int
SocketCrypto_websocket_accept (const char *client_key,
                               char output[SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE])
{
  unsigned char sha1_hash[SOCKET_CRYPTO_SHA1_SIZE];
  char concat_buffer[WEBSOCKET_CONCAT_BUFFER_SIZE];
  size_t key_len;
  size_t guid_len;
  size_t concat_len;

  if (!client_key || !output)
    return -1;

  key_len = strlen (client_key);
  guid_len = strlen (SOCKET_CRYPTO_WEBSOCKET_GUID);

  if (key_len != WEBSOCKET_KEY_BASE64_LEN)
    return -1;

  concat_len = key_len + guid_len;
  if (concat_len >= sizeof (concat_buffer))
    return -1;

  memcpy (concat_buffer, client_key, key_len);
  memcpy (concat_buffer + key_len, SOCKET_CRYPTO_WEBSOCKET_GUID, guid_len + 1);

  volatile int result = -1;

  TRY
  {
    SocketCrypto_sha1 (concat_buffer, concat_len, sha1_hash);

    if (SocketCrypto_base64_encode (sha1_hash,
                                    SOCKET_CRYPTO_SHA1_SIZE,
                                    output,
                                    SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE)
        >= 0)
      result = 0;
  }
  EXCEPT (SocketCrypto_Failed)
  {
    result = -1;
  }
  FINALLY
  {
    SocketCrypto_secure_clear (concat_buffer, sizeof (concat_buffer));
    SocketCrypto_secure_clear (sha1_hash, sizeof (sha1_hash));
  }
  END_TRY;

  return result;
}

int
SocketCrypto_websocket_key (char output[SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE])
{
  unsigned char random_bytes[WEBSOCKET_KEY_RANDOM_BYTES];

  if (!output)
    return -1;

  if (SocketCrypto_random_bytes (random_bytes, sizeof (random_bytes)) != 0)
    return -1;

  if (SocketCrypto_base64_encode (random_bytes,
                                  sizeof (random_bytes),
                                  output,
                                  SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE)
      < 0)
    {
      SocketCrypto_secure_clear (random_bytes, sizeof (random_bytes));
      return -1;
    }

  SocketCrypto_secure_clear (random_bytes, sizeof (random_bytes));
  return 0;
}

int
SocketCrypto_secure_compare (const void *a, const void *b, size_t len)
{
  if (!a || !b)
    return 1;

  if (len == 0)
    return 0;

#if SOCKET_HAS_TLS
  return CRYPTO_memcmp (a, b, len);
#else
  const unsigned char *ua = (const unsigned char *)a;
  const unsigned char *ub = (const unsigned char *)b;
  unsigned char result = 0;
  size_t i;

  for (i = 0; i < len; i++)
    result |= ua[i] ^ ub[i];

  return result != 0;
#endif
}

void
SocketCrypto_secure_clear (void *ptr, size_t len)
{
  if (!ptr || len == 0)
    return;

#if SOCKET_HAS_TLS
  OPENSSL_cleanse (ptr, len);
#else
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  while (len--)
    *p++ = 0;
#endif
}

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQUICPacket-initial.c - QUIC Initial Packet Format (RFC 9000
 * Section 17.2.2)
 *
 * Implements Initial packet key derivation, protection, and validation.
 * Initial packets are the first packets exchanged between client and server
 * and use keys derived from the client's Destination Connection ID.
 *
 * Key derivation follows RFC 9001 Section 5.2:
 * 1. HKDF-Extract with version-specific salt and client DCID
 * 2. HKDF-Expand-Label for client/server secrets
 * 3. HKDF-Expand-Label for key, iv, and hp material
 *
 * Protection follows RFC 9001 Section 5.4:
 * 1. Encrypt payload with AES-128-GCM
 * 2. Apply AES-ECB header protection
 */

#include <string.h>

#include "quic/SocketQUICPacket.h"
#include "quic/SocketQUICCrypto.h"
#include "quic/SocketQUICVersion.h"
#include "quic/SocketQUICConstants.h"
#include "core/SocketCrypto.h"

#ifdef SOCKET_HAS_TLS
#include <openssl/evp.h>
#endif

/* ============================================================================
 * Constants - RFC 9001 Section 5.2
 * ============================================================================
 */

/**
 * @brief QUIC v1 Initial salt (RFC 9001 Section 5.2).
 *
 * 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
 */
static const uint8_t quic_v1_initial_salt[QUIC_V1_INITIAL_SALT_LEN]
    = { 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a };

/**
 * @brief QUIC v2 Initial salt (RFC 9369).
 *
 * 0x0dede3def700a6db819381be6e269dcbf9bd2ed9
 */
static const uint8_t quic_v2_initial_salt[QUIC_V1_INITIAL_SALT_LEN]
    = { 0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
        0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9 };

/* ============================================================================
 * Result String Table
 * ============================================================================
 */

static const char *result_strings[]
    = { [QUIC_INITIAL_OK] = "OK",
        [QUIC_INITIAL_ERROR_NULL] = "NULL pointer argument",
        [QUIC_INITIAL_ERROR_CRYPTO] = "Cryptographic operation failed",
        [QUIC_INITIAL_ERROR_BUFFER] = "Buffer too small",
        [QUIC_INITIAL_ERROR_TRUNCATED] = "Packet too short",
        [QUIC_INITIAL_ERROR_INVALID] = "Invalid packet format",
        [QUIC_INITIAL_ERROR_AUTH] = "AEAD authentication failed",
        [QUIC_INITIAL_ERROR_SIZE] = "Packet size below minimum",
        [QUIC_INITIAL_ERROR_TOKEN] = "Server Initial has non-zero token",
        [QUIC_INITIAL_ERROR_VERSION] = "Unsupported QUIC version" };

DEFINE_RESULT_STRING_FUNC (SocketQUICInitial, QUIC_INITIAL_ERROR_VERSION)

/* ============================================================================
 * Key Structure Functions
 * ============================================================================
 */

void
SocketQUICInitialKeys_init (SocketQUICInitialKeys_T *keys)
{
  if (keys == NULL)
    return;
  memset (keys, 0, sizeof (*keys));
}

void
SocketQUICInitialKeys_clear (SocketQUICInitialKeys_T *keys)
{
  if (keys == NULL)
    return;
  SocketCrypto_secure_clear (keys, sizeof (*keys));
}

/* ============================================================================
 * Salt Lookup
 * ============================================================================
 */

SocketQUICInitial_Result
SocketQUICInitial_get_salt (uint32_t version,
                            const uint8_t **salt,
                            size_t *salt_len)
{
  if (salt == NULL || salt_len == NULL)
    return QUIC_INITIAL_ERROR_NULL;

  switch (version)
    {
    case QUIC_VERSION_1:
      *salt = quic_v1_initial_salt;
      *salt_len = QUIC_V1_INITIAL_SALT_LEN;
      return QUIC_INITIAL_OK;

    case QUIC_VERSION_2:
      *salt = quic_v2_initial_salt;
      *salt_len = QUIC_V1_INITIAL_SALT_LEN;
      return QUIC_INITIAL_OK;

    default:
      *salt = NULL;
      *salt_len = 0;
      return QUIC_INITIAL_ERROR_VERSION;
    }
}

/* ============================================================================
 * Validation Functions
 * ============================================================================
 */

SocketQUICInitial_Result
SocketQUICInitial_validate (const SocketQUICPacketHeader_T *header,
                            size_t total_len,
                            int is_client)
{
  if (header == NULL)
    return QUIC_INITIAL_ERROR_NULL;

  /* Must be Initial packet type */
  if (header->type != QUIC_PACKET_TYPE_INITIAL)
    return QUIC_INITIAL_ERROR_INVALID;

  /* Client Initial packets must be at least 1200 bytes */
  if (is_client && total_len < QUIC_INITIAL_MIN_SIZE)
    return QUIC_INITIAL_ERROR_SIZE;

  /* Server Initial must have zero-length token */
  if (!is_client && header->token_length > 0)
    return QUIC_INITIAL_ERROR_TOKEN;

  return QUIC_INITIAL_OK;
}

size_t
SocketQUICInitial_padding_needed (size_t current_len)
{
  if (current_len >= QUIC_INITIAL_MIN_SIZE)
    return 0;
  return QUIC_INITIAL_MIN_SIZE - current_len;
}

/* ============================================================================
 * Key Derivation - Delegates to SocketQUICCrypto module
 * ============================================================================
 */

SocketQUICInitial_Result
SocketQUICInitial_derive_keys (const SocketQUICConnectionID_T *dcid,
                               uint32_t version,
                               SocketQUICInitialKeys_T *keys)
{
  SocketQUICCrypto_Result crypto_result
      = SocketQUICCrypto_derive_initial_keys (dcid, version, keys);

  /* Map crypto result to initial result */
  switch (crypto_result)
    {
    case QUIC_CRYPTO_OK:
      return QUIC_INITIAL_OK;
    case QUIC_CRYPTO_ERROR_NULL:
      return QUIC_INITIAL_ERROR_NULL;
    case QUIC_CRYPTO_ERROR_VERSION:
      return QUIC_INITIAL_ERROR_VERSION;
    case QUIC_CRYPTO_ERROR_HKDF:
    case QUIC_CRYPTO_ERROR_NO_TLS:
    default:
      return QUIC_INITIAL_ERROR_CRYPTO;
    }
}

/* ============================================================================
 * Packet Protection (RFC 9001 Section 5.4)
 * ============================================================================
 */

#ifdef SOCKET_HAS_TLS

/**
 * @brief Apply AES-ECB header protection.
 */
static int
apply_header_protection (uint8_t *packet,
                         size_t header_len,
                         const uint8_t *sample,
                         const uint8_t *hp_key)
{
  EVP_CIPHER_CTX *ctx = NULL;
  uint8_t mask[QUIC_HP_SAMPLE_LEN];
  int outlen;
  uint8_t pn_length;
  int result = -1;

  ctx = EVP_CIPHER_CTX_new ();
  if (ctx == NULL)
    goto cleanup;

  /* Generate mask using AES-ECB */
  if (EVP_EncryptInit_ex (ctx, EVP_aes_128_ecb (), NULL, hp_key, NULL) <= 0)
    goto cleanup;

  EVP_CIPHER_CTX_set_padding (ctx, 0);

  if (EVP_EncryptUpdate (ctx, mask, &outlen, sample, QUIC_HP_SAMPLE_LEN) <= 0)
    goto cleanup;

  /* Apply mask to first byte */
  if (packet[0] & 0x80)
    {
      /* Long header: mask bottom 4 bits */
      packet[0] ^= (mask[0] & QUIC_HP_LONG_HEADER_MASK);
    }
  else
    {
      /* Short header: mask bottom 5 bits */
      packet[0] ^= (mask[0] & QUIC_HP_SHORT_HEADER_MASK);
    }

  /* Get packet number length from first byte */
  pn_length = (packet[0] & 0x03) + 1;

  /* Apply mask to packet number bytes */
  for (uint8_t i = 0; i < pn_length; i++)
    packet[header_len - pn_length + i] ^= mask[1 + i];

  result = 0;

cleanup:
  if (ctx)
    EVP_CIPHER_CTX_free (ctx);
  SocketCrypto_secure_clear (mask, sizeof (mask));
  return result;
}

/**
 * @brief Construct nonce from IV and packet number.
 */
static void
construct_nonce (const uint8_t *iv, uint64_t pn, uint8_t *nonce)
{
  memcpy (nonce, iv, QUIC_INITIAL_IV_LEN);

  /* XOR packet number into last bytes of IV (big-endian) */
  for (int i = 0; i < (int)sizeof (uint64_t); i++)
    nonce[QUIC_INITIAL_IV_LEN - 1 - i] ^= (uint8_t)((pn >> (8 * i)) & 0xFF);
}

/**
 * @brief Remove header protection from QUIC Initial packet.
 *
 * @param packet Packet buffer (modified in place)
 * @param pn_offset Offset to packet number field
 * @param packet_len Total packet length
 * @param hp_key Header protection key
 * @param mask Output buffer for generated mask
 * @param pn_length Output for extracted packet number length
 * @return 0 on success, -1 on error
 */
static int
remove_header_protection (uint8_t *packet,
                          size_t pn_offset,
                          size_t packet_len,
                          const uint8_t *hp_key,
                          uint8_t *mask,
                          uint8_t *pn_length)
{
  EVP_CIPHER_CTX *ctx = NULL;
  const uint8_t *sample;
  int outlen;
  int result = -1;

  /* Sample location: 4 bytes after the start of PN field */
  sample = packet + pn_offset + QUIC_HP_SAMPLE_OFFSET;

  /* Ensure we have enough bytes for the sample */
  if (pn_offset + QUIC_HP_SAMPLE_OFFSET + QUIC_HP_SAMPLE_LEN > packet_len)
    return -1;

  /* Generate mask using AES-ECB */
  ctx = EVP_CIPHER_CTX_new ();
  if (ctx == NULL)
    goto cleanup;

  if (EVP_EncryptInit_ex (ctx, EVP_aes_128_ecb (), NULL, hp_key, NULL) <= 0)
    goto cleanup;

  EVP_CIPHER_CTX_set_padding (ctx, 0);

  if (EVP_EncryptUpdate (ctx, mask, &outlen, sample, QUIC_HP_SAMPLE_LEN) <= 0)
    goto cleanup;

  /* Remove header protection from first byte */
  if (packet[0] & 0x80)
    packet[0] ^= (mask[0] & 0x0F);
  else
    packet[0] ^= (mask[0] & 0x1F);

  /* Get packet number length */
  *pn_length = (packet[0] & 0x03) + 1;

  /* Remove header protection from packet number */
  for (uint8_t i = 0; i < *pn_length; i++)
    packet[pn_offset + i] ^= mask[1 + i];

  result = 0;

cleanup:
  if (ctx)
    EVP_CIPHER_CTX_free (ctx);
  return result;
}

/**
 * @brief Encrypt AEAD-protected payload of QUIC Initial packet.
 *
 * @param packet Packet buffer containing header (used as AAD)
 * @param header_len Length of packet header
 * @param payload Payload buffer (modified in place)
 * @param payload_len Length of payload (excluding auth tag)
 * @param key AEAD encryption key
 * @param nonce AEAD nonce
 * @return QUIC_INITIAL_OK on success, error code on failure
 */
static SocketQUICInitial_Result
encrypt_aead_payload (const uint8_t *packet,
                      size_t header_len,
                      uint8_t *payload,
                      size_t payload_len,
                      const uint8_t *key,
                      const uint8_t *nonce)
{
  EVP_CIPHER_CTX *ctx = NULL;
  int outlen;
  SocketQUICInitial_Result result = QUIC_INITIAL_ERROR_CRYPTO;

  /* Validate sizes before casting to int for OpenSSL */
  if (header_len > INT_MAX || payload_len > INT_MAX)
    return QUIC_INITIAL_ERROR_BUFFER;

  /* Create cipher context for encryption */
  ctx = EVP_CIPHER_CTX_new ();
  if (ctx == NULL)
    goto cleanup;

  /* Initialize AES-128-GCM encryption */
  if (EVP_EncryptInit_ex (ctx, EVP_aes_128_gcm (), NULL, NULL, NULL) <= 0)
    goto cleanup;

  if (EVP_CIPHER_CTX_ctrl (
          ctx, EVP_CTRL_GCM_SET_IVLEN, QUIC_INITIAL_IV_LEN, NULL)
      <= 0)
    goto cleanup;

  if (EVP_EncryptInit_ex (ctx, NULL, NULL, key, nonce) <= 0)
    goto cleanup;

  /* Add header as AAD (Associated Data) */
  if (EVP_EncryptUpdate (ctx, NULL, &outlen, packet, (int)header_len) <= 0)
    goto cleanup;

  /* Encrypt payload in-place */
  if (EVP_EncryptUpdate (ctx, payload, &outlen, payload, (int)payload_len) <= 0)
    goto cleanup;

  /* Finalize encryption */
  int final_len;
  if (EVP_EncryptFinal_ex (ctx, payload + outlen, &final_len) <= 0)
    goto cleanup;

  /* Get authentication tag and append to payload */
  if (EVP_CIPHER_CTX_ctrl (ctx,
                           EVP_CTRL_GCM_GET_TAG,
                           QUIC_INITIAL_TAG_LEN,
                           payload + payload_len)
      <= 0)
    goto cleanup;

  result = QUIC_INITIAL_OK;

cleanup:
  if (ctx)
    EVP_CIPHER_CTX_free (ctx);
  return result;
}

/**
 * @brief Decrypt AEAD-protected payload of QUIC Initial packet.
 *
 * @param packet Packet buffer containing header (used as AAD)
 * @param header_len Length of packet header
 * @param payload Payload buffer (modified in place)
 * @param payload_len Length of payload (excluding auth tag)
 * @param key AEAD encryption key
 * @param nonce AEAD nonce
 * @return QUIC_INITIAL_OK on success, error code on failure
 */
static SocketQUICInitial_Result
decrypt_aead_payload (const uint8_t *packet,
                      size_t header_len,
                      uint8_t *payload,
                      size_t payload_len,
                      const uint8_t *key,
                      const uint8_t *nonce)
{
  EVP_CIPHER_CTX *ctx = NULL;
  int outlen;
  SocketQUICInitial_Result result = QUIC_INITIAL_ERROR_CRYPTO;

  /* Validate sizes before casting to int for OpenSSL */
  if (header_len > INT_MAX || payload_len > INT_MAX)
    return QUIC_INITIAL_ERROR_BUFFER;

  /* Create cipher context for decryption */
  ctx = EVP_CIPHER_CTX_new ();
  if (ctx == NULL)
    goto cleanup;

  if (EVP_DecryptInit_ex (ctx, EVP_aes_128_gcm (), NULL, NULL, NULL) <= 0)
    goto cleanup;

  if (EVP_CIPHER_CTX_ctrl (
          ctx, EVP_CTRL_GCM_SET_IVLEN, QUIC_INITIAL_IV_LEN, NULL)
      <= 0)
    goto cleanup;

  if (EVP_DecryptInit_ex (ctx, NULL, NULL, key, nonce) <= 0)
    goto cleanup;

  /* Add header as AAD */
  if (EVP_DecryptUpdate (ctx, NULL, &outlen, packet, (int)header_len) <= 0)
    goto cleanup;

  /* Decrypt payload in-place */
  if (EVP_DecryptUpdate (ctx, payload, &outlen, payload, (int)payload_len) <= 0)
    goto cleanup;

  /* Set expected tag */
  if (EVP_CIPHER_CTX_ctrl (ctx,
                           EVP_CTRL_GCM_SET_TAG,
                           QUIC_INITIAL_TAG_LEN,
                           payload + payload_len)
      <= 0)
    goto cleanup;

  /* Verify tag and finalize */
  int final_len;
  if (EVP_DecryptFinal_ex (ctx, payload + outlen, &final_len) <= 0)
    {
      result = QUIC_INITIAL_ERROR_AUTH;
      goto cleanup;
    }

  result = QUIC_INITIAL_OK;

cleanup:
  if (ctx)
    EVP_CIPHER_CTX_free (ctx);
  return result;
}

/**
 * @brief Select appropriate keys based on packet direction.
 *
 * For protect operations (encryption), is_client indicates the sender:
 * - is_client=1: Use client keys (client sending to server)
 * - is_client=0: Use server keys (server sending to client)
 *
 * For unprotect operations (decryption), is_client indicates the receiver:
 * - is_client=1: Use server keys (client receiving from server)
 * - is_client=0: Use client keys (server receiving from client)
 *
 * @param keys Key material for both client and server
 * @param is_client 1 if using client perspective, 0 for server perspective
 * @param for_sender 1 if selecting sender keys, 0 if selecting receiver keys
 * @param out_key Output: selected encryption key
 * @param out_iv Output: selected IV
 * @param out_hp_key Output: selected header protection key
 */
static void
select_protection_keys (const SocketQUICInitialKeys_T *keys,
                        int is_client,
                        int for_sender,
                        const uint8_t **out_key,
                        const uint8_t **out_iv,
                        const uint8_t **out_hp_key)
{
  int use_client_keys = (for_sender ? is_client : !is_client);

  if (use_client_keys)
    {
      *out_key = keys->client_key;
      *out_iv = keys->client_iv;
      *out_hp_key = keys->client_hp_key;
    }
  else
    {
      *out_key = keys->server_key;
      *out_iv = keys->server_iv;
      *out_hp_key = keys->server_hp_key;
    }
}

#endif /* SOCKET_HAS_TLS */

SocketQUICInitial_Result
SocketQUICInitial_protect (uint8_t *packet,
                           size_t *packet_len,
                           size_t header_len,
                           const SocketQUICInitialKeys_T *keys,
                           int is_client)
{
#ifdef SOCKET_HAS_TLS
  const uint8_t *key;
  const uint8_t *iv;
  const uint8_t *hp_key;
  uint8_t nonce[QUIC_INITIAL_IV_LEN];
  uint8_t *payload;
  size_t payload_len;
  uint8_t pn_length;
  uint32_t pn;
  const uint8_t *sample;
  SocketQUICInitial_Result result;

  if (packet == NULL || packet_len == NULL || keys == NULL)
    return QUIC_INITIAL_ERROR_NULL;

  if (!keys->initialized)
    return QUIC_INITIAL_ERROR_CRYPTO;

  /* Select keys based on sender */
  select_protection_keys (keys, is_client, 1, &key, &iv, &hp_key);

  /* Get packet number from header */
  pn_length = (packet[0] & 0x03) + 1;
  pn = 0;
  for (uint8_t i = 0; i < pn_length; i++)
    pn = (pn << 8) | packet[header_len - pn_length + i];

  /* Payload starts after header */
  payload = packet + header_len;
  payload_len = *packet_len - header_len;

  /* Construct nonce */
  construct_nonce (iv, pn, nonce);

  /* Encrypt payload with AEAD */
  result = encrypt_aead_payload (
      packet, header_len, payload, payload_len, key, nonce);
  if (result != QUIC_INITIAL_OK)
    {
      SocketCrypto_secure_clear (nonce, sizeof (nonce));
      return result;
    }

  /* Update packet length to include tag */
  *packet_len += QUIC_INITIAL_TAG_LEN;

  /* Get sample for header protection (4 bytes after PN) */
  sample = payload + (QUIC_HP_SAMPLE_OFFSET - pn_length);

  /* Apply header protection */
  if (apply_header_protection (packet, header_len, sample, hp_key) < 0)
    {
      SocketCrypto_secure_clear (nonce, sizeof (nonce));
      return QUIC_INITIAL_ERROR_CRYPTO;
    }

  SocketCrypto_secure_clear (nonce, sizeof (nonce));
  return QUIC_INITIAL_OK;

#else
  (void)packet;
  (void)packet_len;
  (void)header_len;
  (void)keys;
  (void)is_client;
  return QUIC_INITIAL_ERROR_CRYPTO;
#endif
}

SocketQUICInitial_Result
SocketQUICInitial_unprotect (uint8_t *packet,
                             size_t packet_len,
                             size_t pn_offset,
                             const SocketQUICInitialKeys_T *keys,
                             int is_client,
                             uint8_t *pn_length)
{
#ifdef SOCKET_HAS_TLS
  const uint8_t *key;
  const uint8_t *iv;
  const uint8_t *hp_key;
  uint8_t nonce[QUIC_INITIAL_IV_LEN];
  uint8_t mask[QUIC_HP_SAMPLE_LEN];
  uint8_t *payload;
  size_t payload_len;
  size_t header_len;
  uint32_t pn;
  SocketQUICInitial_Result result;

  if (packet == NULL || keys == NULL || pn_length == NULL)
    return QUIC_INITIAL_ERROR_NULL;

  if (!keys->initialized)
    return QUIC_INITIAL_ERROR_CRYPTO;

  /* Select keys based on receiver (opposite of sender) */
  select_protection_keys (keys, is_client, 0, &key, &iv, &hp_key);

  /* Remove header protection and extract packet number length */
  if (remove_header_protection (
          packet, pn_offset, packet_len, hp_key, mask, pn_length)
      < 0)
    {
      SocketCrypto_secure_clear (mask, sizeof (mask));
      return QUIC_INITIAL_ERROR_TRUNCATED;
    }

  /* Extract packet number */
  pn = 0;
  for (uint8_t i = 0; i < *pn_length; i++)
    pn = (pn << 8) | packet[pn_offset + i];

  /* Calculate header length and payload bounds */
  header_len = pn_offset + *pn_length;
  payload = packet + header_len;
  payload_len = packet_len - header_len - QUIC_INITIAL_TAG_LEN;

  /* Construct nonce from IV and packet number */
  construct_nonce (iv, pn, nonce);

  /* Decrypt and authenticate payload */
  result = decrypt_aead_payload (
      packet, header_len, payload, payload_len, key, nonce);

  /* Clear sensitive data */
  SocketCrypto_secure_clear (nonce, sizeof (nonce));
  SocketCrypto_secure_clear (mask, sizeof (mask));

  return result;

#else
  (void)packet;
  (void)packet_len;
  (void)pn_offset;
  (void)keys;
  (void)is_client;
  (void)pn_length;
  return QUIC_INITIAL_ERROR_CRYPTO;
#endif
}

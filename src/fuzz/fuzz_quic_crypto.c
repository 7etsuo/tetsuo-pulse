/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_crypto.c - libFuzzer for QUIC Cryptographic Operations (RFC 9001)
 *
 * Fuzzes key derivation, packet protection, and header protection:
 * - Initial key derivation from DCID
 * - Traffic key derivation from secrets
 * - AEAD encryption/decryption
 * - Header protection/unprotection
 * - Key update operations
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_quic_crypto
 * ./fuzz_quic_crypto corpus/quic_crypto/ -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICCrypto.h"
#include "quic/SocketQUICConnectionID.h"

/* Operation types */
enum
{
  OP_DERIVE_INITIAL_KEYS,
  OP_DERIVE_TRAFFIC_KEYS,
  OP_DERIVE_PACKET_KEYS,
  OP_ENCRYPT_DECRYPT,
  OP_HEADER_PROTECTION,
  OP_KEY_UPDATE,
  OP_AEAD_SIZES,
  OP_RESULT_STRINGS,
  OP_MAX
};

/* Helper to read uint64_t from buffer */
static uint64_t
read_u64 (const uint8_t *data)
{
  uint64_t val = 0;
  for (int i = 0; i < 8; i++)
    val = (val << 8) | data[i];
  return val;
}

/* Helper to read uint32_t from buffer */
static uint32_t
read_u32 (const uint8_t *data)
{
  return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
         | ((uint32_t)data[2] << 8) | data[3];
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 17)
    return 0;

  uint8_t op = data[0] % OP_MAX;

  switch (op)
    {
    case OP_DERIVE_INITIAL_KEYS:
      {
        /* Test initial key derivation from DCID */
        if (size < 25)
          return 0;

        uint8_t dcid_len = (data[1] % 20) + 1; /* 1-20 bytes */
        if (size < (size_t)(2 + dcid_len + 4))
          return 0;

        SocketQUICConnectionID_T dcid;
        SocketQUICConnectionID_init (&dcid);
        SocketQUICConnectionID_set (&dcid, data + 2, dcid_len);

        uint32_t version = read_u32 (data + 2 + dcid_len);

        /* Try known versions */
        uint32_t versions[]
            = { QUIC_VERSION_1, QUIC_VERSION_2, version, 0, 0xFFFFFFFF };

        for (size_t i = 0; i < sizeof (versions) / sizeof (versions[0]); i++)
          {
            SocketQUICInitialKeys_T keys;
            SocketQUICCryptoSecrets_T secrets;

            SocketQUICCrypto_Result result
                = SocketQUICCrypto_derive_initial_keys (&dcid, versions[i],
                                                        &keys);
            (void)result;

            result = SocketQUICCrypto_derive_initial_secrets (&dcid,
                                                              versions[i],
                                                              &secrets, &keys);
            (void)result;

            /* Test with NULL secrets output */
            result = SocketQUICCrypto_derive_initial_secrets (&dcid,
                                                              versions[i], NULL,
                                                              &keys);
            (void)result;

            /* Clear secrets */
            SocketQUICCryptoSecrets_clear (&secrets);
          }

        /* Test NULL inputs */
        SocketQUICInitialKeys_T keys;
        SocketQUICCrypto_derive_initial_keys (NULL, QUIC_VERSION_1, &keys);
        SocketQUICCrypto_derive_initial_keys (&dcid, QUIC_VERSION_1, NULL);
        break;
      }

    case OP_DERIVE_TRAFFIC_KEYS:
      {
        /* Test traffic key derivation */
        if (size < 49)
          return 0;

        uint8_t secret[48];
        memcpy (secret, data + 1, 48);

        uint8_t key[32];
        uint8_t iv[12];
        uint8_t hp_key[32];

        /* Test with 32-byte secret (SHA-256) */
        SocketQUICCrypto_Result result = SocketQUICCrypto_derive_traffic_keys (
            secret, SOCKET_CRYPTO_SHA256_SIZE, key, iv, hp_key);
        (void)result;

        /* Test with 48-byte secret (SHA-384) */
        result = SocketQUICCrypto_derive_traffic_keys (secret, 48, key, iv,
                                                       hp_key);
        (void)result;

        /* Test with wrong sizes */
        result = SocketQUICCrypto_derive_traffic_keys (secret, 0, key, iv,
                                                       hp_key);
        (void)result;
        result = SocketQUICCrypto_derive_traffic_keys (secret, 16, key, iv,
                                                       hp_key);
        (void)result;

        /* Test NULL inputs */
        SocketQUICCrypto_derive_traffic_keys (NULL, 32, key, iv, hp_key);
        SocketQUICCrypto_derive_traffic_keys (secret, 32, NULL, iv, hp_key);
        break;
      }

    case OP_DERIVE_PACKET_KEYS:
      {
        /* Test packet key derivation for different AEAD algorithms */
        if (size < 50)
          return 0;

        uint8_t secret[48];
        memcpy (secret, data + 1, 48);
        uint8_t aead_idx = data[49] % (QUIC_AEAD_COUNT + 1);

        SocketQUICPacketKeys_T keys;
        SocketQUICPacketKeys_init (&keys);

        for (int aead = 0; aead < QUIC_AEAD_COUNT; aead++)
          {
            size_t secret_len = 0;
            SocketQUICCrypto_get_aead_secret_len ((SocketQUIC_AEAD)aead,
                                                  &secret_len);

            SocketQUICCrypto_Result result = SocketQUICCrypto_derive_packet_keys (
                secret, secret_len, (SocketQUIC_AEAD)aead, &keys);
            (void)result;

            /* Test with wrong secret length */
            result = SocketQUICCrypto_derive_packet_keys (
                secret, secret_len + 1, (SocketQUIC_AEAD)aead, &keys);
            (void)result;

            SocketQUICPacketKeys_clear (&keys);
          }

        /* Test invalid AEAD */
        SocketQUICCrypto_derive_packet_keys (secret, 32,
                                             (SocketQUIC_AEAD)aead_idx, &keys);
        SocketQUICCrypto_derive_packet_keys (secret, 32, (SocketQUIC_AEAD)255,
                                             &keys);

        /* Test NULL inputs */
        SocketQUICCrypto_derive_packet_keys (NULL, 32, QUIC_AEAD_AES_128_GCM,
                                             &keys);
        SocketQUICCrypto_derive_packet_keys (secret, 32, QUIC_AEAD_AES_128_GCM,
                                             NULL);
        break;
      }

    case OP_ENCRYPT_DECRYPT:
      {
        /* Test AEAD encryption and decryption */
        if (size < 100)
          return 0;

        /* Set up keys from fuzz data */
        SocketQUICPacketKeys_T keys;
        SocketQUICPacketKeys_init (&keys);

        memcpy (keys.key, data + 1, 32);
        memcpy (keys.iv, data + 33, 12);
        memcpy (keys.hp_key, data + 45, 32);
        keys.key_len = 16;
        keys.hp_len = 16;
        keys.aead = (SocketQUIC_AEAD)(data[77] % QUIC_AEAD_COUNT);

        uint64_t packet_number = read_u64 (data + 78);

        /* Header and plaintext from remaining data */
        size_t header_len = (data[86] % 20) + 1;
        size_t plaintext_len = (data[87] % 50) + 1;

        if (size < 88 + header_len + plaintext_len)
          return 0;

        const uint8_t *header = data + 88;
        const uint8_t *plaintext = data + 88 + header_len;

        uint8_t ciphertext[256];
        size_t ciphertext_len = sizeof (ciphertext);

        SocketQUICCrypto_Result result = SocketQUICCrypto_encrypt_payload (
            &keys, packet_number, header, header_len, plaintext, plaintext_len,
            ciphertext, &ciphertext_len);

        if (result == QUIC_CRYPTO_OK)
          {
            /* Try to decrypt what we encrypted */
            uint8_t decrypted[256];
            size_t decrypted_len = sizeof (decrypted);

            result = SocketQUICCrypto_decrypt_payload (&keys, packet_number,
                                                       header, header_len,
                                                       ciphertext, ciphertext_len,
                                                       decrypted, &decrypted_len);
            (void)result;
          }

        /* Test with fuzzed ciphertext directly */
        if (size >= 120)
          {
            uint8_t decrypted[256];
            size_t decrypted_len = sizeof (decrypted);
            result = SocketQUICCrypto_decrypt_payload (
                &keys, packet_number, header, header_len, data + 100,
                size - 100, decrypted, &decrypted_len);
            (void)result;
          }

        /* Test NULL and edge cases */
        SocketQUICCrypto_encrypt_payload (NULL, 0, header, header_len,
                                          plaintext, plaintext_len, ciphertext,
                                          &ciphertext_len);
        SocketQUICCrypto_encrypt_payload (&keys, 0, NULL, 0, plaintext,
                                          plaintext_len, ciphertext,
                                          &ciphertext_len);

        SocketQUICPacketKeys_clear (&keys);
        break;
      }

    case OP_HEADER_PROTECTION:
      {
        /* Test header protection operations */
        if (size < 80)
          return 0;

        uint8_t hp_key[32];
        memcpy (hp_key, data + 1, 32);

        uint8_t packet[256];
        size_t packet_len = (size - 40 > 256) ? 256 : (size - 40);
        if (packet_len < 21)
          packet_len = 21; /* Minimum for header protection */
        memcpy (packet, data + 33, packet_len);

        size_t pn_offset = (data[34] % (packet_len - 16)) + 1;
        if (pn_offset > packet_len - 16)
          pn_offset = 1;

        /* Test for each AEAD algorithm */
        for (int aead = 0; aead < QUIC_AEAD_COUNT; aead++)
          {
            size_t key_len = (aead == QUIC_AEAD_AES_128_GCM) ? 16 : 32;

            /* Make a copy for protect/unprotect roundtrip */
            uint8_t test_packet[256];
            memcpy (test_packet, packet, packet_len);

            SocketQUICCrypto_Result result = SocketQUICCrypto_protect_header (
                hp_key, key_len, (SocketQUIC_AEAD)aead, test_packet, packet_len,
                pn_offset);
            (void)result;

            /* Unprotect should restore original */
            result = SocketQUICCrypto_unprotect_header (
                hp_key, key_len, (SocketQUIC_AEAD)aead, test_packet, packet_len,
                pn_offset);
            (void)result;
          }

        /* Test the _ex variants with SocketQUICPacketKeys_T */
        SocketQUICPacketKeys_T keys;
        SocketQUICPacketKeys_init (&keys);
        memcpy (keys.hp_key, hp_key, 32);
        keys.hp_len = 16;
        keys.aead = QUIC_AEAD_AES_128_GCM;

        uint8_t test_packet2[256];
        memcpy (test_packet2, packet, packet_len);
        SocketQUICCrypto_protect_header_ex (&keys, test_packet2, packet_len,
                                            pn_offset);
        SocketQUICCrypto_unprotect_header_ex (&keys, test_packet2, packet_len,
                                              pn_offset);

        /* Test NULL and edge cases */
        SocketQUICCrypto_protect_header (NULL, 16, QUIC_AEAD_AES_128_GCM,
                                         test_packet2, packet_len, pn_offset);
        SocketQUICCrypto_protect_header (hp_key, 16, QUIC_AEAD_AES_128_GCM,
                                         NULL, 0, 0);
        SocketQUICCrypto_protect_header_ex (NULL, test_packet2, packet_len,
                                            pn_offset);
        break;
      }

    case OP_KEY_UPDATE:
      {
        /* Test key update state machine */
        if (size < 100)
          return 0;

        SocketQUICKeyUpdate_T state;
        SocketQUICKeyUpdate_init (&state);

        uint8_t write_secret[48];
        uint8_t read_secret[48];
        memcpy (write_secret, data + 1, 48);
        memcpy (read_secret, data + 49, 48);

        /* Test for each AEAD */
        for (int aead = 0; aead < QUIC_AEAD_COUNT; aead++)
          {
            size_t secret_len = 0;
            SocketQUICCrypto_get_aead_secret_len ((SocketQUIC_AEAD)aead,
                                                  &secret_len);

            SocketQUICKeyUpdate_init (&state);
            SocketQUICCrypto_Result result
                = SocketQUICKeyUpdate_set_initial_keys (
                    &state, write_secret, read_secret, secret_len,
                    (SocketQUIC_AEAD)aead);
            (void)result;

            /* Test can_initiate before any acks */
            int can = SocketQUICKeyUpdate_can_initiate (&state);
            (void)can;

            /* Record some packets */
            SocketQUICKeyUpdate_on_packet_sent (&state, 0);
            SocketQUICKeyUpdate_on_packet_sent (&state, 1);

            /* Record ACK - should enable key update */
            SocketQUICKeyUpdate_on_ack_received (&state, 0);
            can = SocketQUICKeyUpdate_can_initiate (&state);
            (void)can;

            /* Try to initiate key update */
            if (can)
              {
                result = SocketQUICKeyUpdate_initiate (&state);
                (void)result;
              }

            /* Test received key phase processing */
            int received_phase = data[97] & 1;
            result
                = SocketQUICKeyUpdate_process_received (&state, received_phase);
            (void)result;

            /* Get read keys for decryption */
            const SocketQUICPacketKeys_T *read_keys = NULL;
            result = SocketQUICKeyUpdate_get_read_keys (&state, received_phase,
                                                        100, &read_keys);
            (void)result;

            /* Test encryption/decryption counting */
            SocketQUICKeyUpdate_on_encrypt (&state);
            SocketQUICKeyUpdate_on_decrypt (&state);
            SocketQUICKeyUpdate_on_decrypt_failure (&state);

            /* Check limits */
            int conf_limit
                = SocketQUICKeyUpdate_confidentiality_limit_reached (&state);
            int int_limit
                = SocketQUICKeyUpdate_integrity_limit_exceeded (&state);
            (void)conf_limit;
            (void)int_limit;

            SocketQUICKeyUpdate_clear (&state);
          }

        /* Test derive_next_secret */
        uint8_t next_secret[48];
        SocketQUICCrypto_derive_next_secret (write_secret, 32,
                                             QUIC_AEAD_AES_128_GCM,
                                             next_secret);
        SocketQUICCrypto_derive_next_secret (write_secret, 48,
                                             QUIC_AEAD_AES_256_GCM,
                                             next_secret);

        /* Test NULL inputs */
        SocketQUICKeyUpdate_init (NULL);
        SocketQUICKeyUpdate_clear (NULL);
        SocketQUICKeyUpdate_set_initial_keys (NULL, write_secret, read_secret,
                                              32, QUIC_AEAD_AES_128_GCM);
        SocketQUICKeyUpdate_can_initiate (NULL);
        break;
      }

    case OP_AEAD_SIZES:
      {
        /* Test AEAD size query functions */
        for (int aead = 0; aead <= QUIC_AEAD_COUNT; aead++)
          {
            size_t key_len = 0, iv_len = 0, hp_len = 0, secret_len = 0;

            SocketQUICCrypto_get_aead_key_sizes ((SocketQUIC_AEAD)aead,
                                                 &key_len, &iv_len, &hp_len);
            SocketQUICCrypto_get_aead_secret_len ((SocketQUIC_AEAD)aead,
                                                  &secret_len);

            /* Test with NULL outputs */
            SocketQUICCrypto_get_aead_key_sizes ((SocketQUIC_AEAD)aead, NULL,
                                                 NULL, NULL);
            SocketQUICCrypto_get_aead_secret_len ((SocketQUIC_AEAD)aead, NULL);

            /* Test AEAD name */
            const char *name = SocketQUIC_AEAD_string ((SocketQUIC_AEAD)aead);
            (void)name;

            /* Test limits */
            uint64_t conf_limit
                = SocketQUICCrypto_get_confidentiality_limit ((SocketQUIC_AEAD)aead);
            uint64_t int_limit
                = SocketQUICCrypto_get_integrity_limit ((SocketQUIC_AEAD)aead);
            (void)conf_limit;
            (void)int_limit;
          }

        /* Test key phase helpers */
        uint8_t first_byte = data[1];
        int phase = SocketQUICCrypto_get_key_phase (first_byte);
        (void)phase;

        SocketQUICCrypto_set_key_phase (&first_byte, 0);
        SocketQUICCrypto_set_key_phase (&first_byte, 1);
        break;
      }

    case OP_RESULT_STRINGS:
      {
        /* Test result string functions */
        SocketQUICCrypto_Result results[]
            = { QUIC_CRYPTO_OK,       QUIC_CRYPTO_ERROR_NULL,
                QUIC_CRYPTO_ERROR_VERSION, QUIC_CRYPTO_ERROR_HKDF,
                QUIC_CRYPTO_ERROR_NO_TLS,  QUIC_CRYPTO_ERROR_AEAD,
                QUIC_CRYPTO_ERROR_SECRET_LEN, QUIC_CRYPTO_ERROR_BUFFER,
                QUIC_CRYPTO_ERROR_TAG,     QUIC_CRYPTO_ERROR_INPUT };

        for (size_t i = 0; i < sizeof (results) / sizeof (results[0]); i++)
          {
            const char *str = SocketQUICCrypto_result_string (results[i]);
            (void)str;
          }

        /* Test with fuzzed value */
        const char *str
            = SocketQUICCrypto_result_string ((SocketQUICCrypto_Result)data[1]);
        (void)str;

        /* Test salt access */
        const uint8_t *salt = NULL;
        size_t salt_len = 0;
        SocketQUICCrypto_get_initial_salt (QUIC_VERSION_1, &salt, &salt_len);
        SocketQUICCrypto_get_initial_salt (QUIC_VERSION_2, &salt, &salt_len);
        SocketQUICCrypto_get_initial_salt (0, &salt, &salt_len);
        SocketQUICCrypto_get_initial_salt (QUIC_VERSION_1, NULL, NULL);
        break;
      }
    }

  return 0;
}

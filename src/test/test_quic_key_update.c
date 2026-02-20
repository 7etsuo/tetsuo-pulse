/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_key_update.c - QUIC Key Update Mechanism tests
 *
 * Tests for RFC 9001 Section 6 Key Update mechanism including:
 * - Key derivation with "quic ku" label
 * - Key phase bit handling
 * - Key update initiation and response
 * - AEAD usage limits
 * - Key update permission tracking
 */

#include <string.h>

#include "quic/SocketQUICCrypto.h"
#include "test/Test.h"

/* 32-byte secret for AES-128-GCM (SHA-256) */
static const uint8_t test_write_secret_sha256[32]
    = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };

static const uint8_t test_read_secret_sha256[32]
    = { 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40 };

/* 48-byte secret for AES-256-GCM (SHA-384) */
static const uint8_t test_write_secret_sha384[48] = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
  0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
  0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30
};

static const uint8_t test_read_secret_sha384[48] = {
  0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
  0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
  0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
  0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60
};

TEST (key_update_init_null)
{
  /* Should not crash */
  SocketQUICKeyUpdate_init (NULL);
}

TEST (key_update_clear_null)
{
  /* Should not crash */
  SocketQUICKeyUpdate_clear (NULL);
}

TEST (key_update_init_zeroes_state)
{
  SocketQUICKeyUpdate_T state;

  /* Set to non-zero pattern */
  memset (&state, 0xFF, sizeof (state));

  SocketQUICKeyUpdate_init (&state);

  ASSERT_EQ (0, state.key_phase);
  ASSERT_EQ (0, state.generation);
  ASSERT_EQ (0, state.initialized);
  ASSERT_EQ (0, state.packets_encrypted);
  ASSERT_EQ (0, state.decryption_failures);
  ASSERT_EQ (UINT64_MAX, state.lowest_pn_current_phase);
}

TEST (key_phase_get_zero)
{
  uint8_t first_byte = 0x40; /* Short header without key phase */
  ASSERT_EQ (0, SocketQUICCrypto_get_key_phase (first_byte));
}

TEST (key_phase_get_one)
{
  uint8_t first_byte = 0x44; /* Short header with key phase bit set */
  ASSERT_EQ (1, SocketQUICCrypto_get_key_phase (first_byte));
}

TEST (key_phase_set_to_one)
{
  uint8_t first_byte = 0x40;
  SocketQUICCrypto_set_key_phase (&first_byte, 1);
  ASSERT_EQ (0x44, first_byte);
}

TEST (key_phase_set_to_zero)
{
  uint8_t first_byte = 0x44;
  SocketQUICCrypto_set_key_phase (&first_byte, 0);
  ASSERT_EQ (0x40, first_byte);
}

TEST (key_phase_preserves_other_bits)
{
  uint8_t first_byte = 0x5B; /* Various bits set */
  SocketQUICCrypto_set_key_phase (&first_byte, 1);
  ASSERT_EQ (0x5F, first_byte);

  SocketQUICCrypto_set_key_phase (&first_byte, 0);
  ASSERT_EQ (0x5B, first_byte);
}

TEST (aead_limits_aes_128_gcm)
{
  uint64_t conf
      = SocketQUICCrypto_get_confidentiality_limit (QUIC_AEAD_AES_128_GCM);
  uint64_t integ = SocketQUICCrypto_get_integrity_limit (QUIC_AEAD_AES_128_GCM);

  ASSERT_EQ (QUIC_AEAD_AES_GCM_CONFIDENTIALITY_LIMIT, conf);
  ASSERT_EQ (QUIC_AEAD_AES_GCM_INTEGRITY_LIMIT, integ);
}

TEST (aead_limits_aes_256_gcm)
{
  uint64_t conf
      = SocketQUICCrypto_get_confidentiality_limit (QUIC_AEAD_AES_256_GCM);
  uint64_t integ = SocketQUICCrypto_get_integrity_limit (QUIC_AEAD_AES_256_GCM);

  ASSERT_EQ (QUIC_AEAD_AES_GCM_CONFIDENTIALITY_LIMIT, conf);
  ASSERT_EQ (QUIC_AEAD_AES_GCM_INTEGRITY_LIMIT, integ);
}

TEST (aead_limits_chacha20)
{
  uint64_t conf = SocketQUICCrypto_get_confidentiality_limit (
      QUIC_AEAD_CHACHA20_POLY1305);
  uint64_t integ
      = SocketQUICCrypto_get_integrity_limit (QUIC_AEAD_CHACHA20_POLY1305);

  /* ChaCha20 has no practical confidentiality limit */
  ASSERT_EQ (UINT64_MAX, conf);
  ASSERT_EQ (QUIC_AEAD_CHACHA20_INTEGRITY_LIMIT, integ);
}

TEST (aead_limits_invalid)
{
  uint64_t conf = SocketQUICCrypto_get_confidentiality_limit (QUIC_AEAD_COUNT);
  uint64_t integ = SocketQUICCrypto_get_integrity_limit (QUIC_AEAD_COUNT);

  ASSERT_EQ (0, conf);
  ASSERT_EQ (0, integ);
}

#if SOCKET_HAS_TLS

/* Derive next secret tests */

TEST (derive_next_secret_null_current)
{
  uint8_t next[32];
  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_next_secret (
      NULL, 32, QUIC_AEAD_AES_128_GCM, next);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
}

TEST (derive_next_secret_null_output)
{
  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_next_secret (
      test_write_secret_sha256, 32, QUIC_AEAD_AES_128_GCM, NULL);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
}

TEST (derive_next_secret_invalid_aead)
{
  uint8_t next[32];
  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_next_secret (
      test_write_secret_sha256, 32, QUIC_AEAD_COUNT, next);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_AEAD, result);
}

TEST (derive_next_secret_wrong_len_aes128)
{
  uint8_t next[32];
  /* AES-128-GCM expects 32-byte secret, give 48 */
  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_next_secret (
      test_write_secret_sha384, 48, QUIC_AEAD_AES_128_GCM, next);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_SECRET_LEN, result);
}

TEST (derive_next_secret_aes128_gcm)
{
  uint8_t next[32];
  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_next_secret (
      test_write_secret_sha256, 32, QUIC_AEAD_AES_128_GCM, next);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Verify next secret differs from current */
  ASSERT (memcmp (next, test_write_secret_sha256, 32) != 0);
}

TEST (derive_next_secret_aes256_gcm)
{
  uint8_t next[48];
  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_next_secret (
      test_write_secret_sha384, 48, QUIC_AEAD_AES_256_GCM, next);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Verify next secret differs from current */
  ASSERT (memcmp (next, test_write_secret_sha384, 48) != 0);
}

TEST (derive_next_secret_chacha20)
{
  uint8_t next[32];
  SocketQUICCrypto_Result result = SocketQUICCrypto_derive_next_secret (
      test_write_secret_sha256, 32, QUIC_AEAD_CHACHA20_POLY1305, next);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Verify next secret differs from current */
  ASSERT (memcmp (next, test_write_secret_sha256, 32) != 0);
}

TEST (derive_next_secret_deterministic)
{
  uint8_t next1[32], next2[32];

  SocketQUICCrypto_derive_next_secret (
      test_write_secret_sha256, 32, QUIC_AEAD_AES_128_GCM, next1);
  SocketQUICCrypto_derive_next_secret (
      test_write_secret_sha256, 32, QUIC_AEAD_AES_128_GCM, next2);

  /* Same input should produce same output */
  ASSERT (memcmp (next1, next2, 32) == 0);
}

TEST (derive_next_secret_chain)
{
  uint8_t gen0[32], gen1[32], gen2[32];

  memcpy (gen0, test_write_secret_sha256, 32);

  SocketQUICCrypto_derive_next_secret (gen0, 32, QUIC_AEAD_AES_128_GCM, gen1);
  SocketQUICCrypto_derive_next_secret (gen1, 32, QUIC_AEAD_AES_128_GCM, gen2);

  /* Each generation should be unique */
  ASSERT (memcmp (gen0, gen1, 32) != 0);
  ASSERT (memcmp (gen1, gen2, 32) != 0);
  ASSERT (memcmp (gen0, gen2, 32) != 0);
}

/* Key update state tests */

TEST (key_update_set_initial_null_state)
{
  SocketQUICCrypto_Result result
      = SocketQUICKeyUpdate_set_initial_keys (NULL,
                                              test_write_secret_sha256,
                                              test_read_secret_sha256,
                                              32,
                                              QUIC_AEAD_AES_128_GCM);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
}

TEST (key_update_set_initial_null_write)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICCrypto_Result result = SocketQUICKeyUpdate_set_initial_keys (
      &state, NULL, test_read_secret_sha256, 32, QUIC_AEAD_AES_128_GCM);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
}

TEST (key_update_set_initial_null_read)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICCrypto_Result result = SocketQUICKeyUpdate_set_initial_keys (
      &state, test_write_secret_sha256, NULL, 32, QUIC_AEAD_AES_128_GCM);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
}

TEST (key_update_set_initial_invalid_aead)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICCrypto_Result result
      = SocketQUICKeyUpdate_set_initial_keys (&state,
                                              test_write_secret_sha256,
                                              test_read_secret_sha256,
                                              32,
                                              QUIC_AEAD_COUNT);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_AEAD, result);
}

TEST (key_update_set_initial_wrong_secret_len)
{
  SocketQUICKeyUpdate_T state;
  /* AES-128-GCM expects 32 bytes, give 48 */
  SocketQUICCrypto_Result result
      = SocketQUICKeyUpdate_set_initial_keys (&state,
                                              test_write_secret_sha384,
                                              test_read_secret_sha384,
                                              48,
                                              QUIC_AEAD_AES_128_GCM);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_SECRET_LEN, result);
}

TEST (key_update_set_initial_aes128)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICCrypto_Result result
      = SocketQUICKeyUpdate_set_initial_keys (&state,
                                              test_write_secret_sha256,
                                              test_read_secret_sha256,
                                              32,
                                              QUIC_AEAD_AES_128_GCM);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (1, state.initialized);
  ASSERT_EQ (0, state.key_phase);
  ASSERT_EQ (0, state.generation);
  ASSERT_EQ (0, state.update_permitted);
  ASSERT_EQ (1, state.next_read_keys_valid); /* Pre-computed */
  ASSERT_EQ (QUIC_AEAD_AES_128_GCM, state.aead);

  SocketQUICKeyUpdate_clear (&state);
}

TEST (key_update_set_initial_aes256)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICCrypto_Result result
      = SocketQUICKeyUpdate_set_initial_keys (&state,
                                              test_write_secret_sha384,
                                              test_read_secret_sha384,
                                              48,
                                              QUIC_AEAD_AES_256_GCM);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (1, state.initialized);
  ASSERT_EQ (QUIC_AEAD_AES_256_GCM, state.aead);
  ASSERT_EQ (48, state.write_secret_len);
  ASSERT_EQ (48, state.read_secret_len);

  SocketQUICKeyUpdate_clear (&state);
}

/* Key update permission tests */

TEST (key_update_cannot_initiate_before_ack)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  /* Initially cannot initiate (no ACK received) */
  ASSERT_EQ (0, SocketQUICKeyUpdate_can_initiate (&state));

  SocketQUICKeyUpdate_clear (&state);
}

TEST (key_update_can_initiate_after_ack)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  /* Send a packet and receive ACK */
  SocketQUICKeyUpdate_on_packet_sent (&state, 100);
  SocketQUICKeyUpdate_on_ack_received (&state, 100);

  ASSERT_EQ (1, SocketQUICKeyUpdate_can_initiate (&state));

  SocketQUICKeyUpdate_clear (&state);
}

TEST (key_update_can_initiate_null)
{
  ASSERT_EQ (0, SocketQUICKeyUpdate_can_initiate (NULL));
}

/* Key update initiation tests */

TEST (key_update_initiate_null)
{
  SocketQUICCrypto_Result result = SocketQUICKeyUpdate_initiate (NULL);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
}

TEST (key_update_initiate_uninitialized)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_init (&state);

  SocketQUICCrypto_Result result = SocketQUICKeyUpdate_initiate (&state);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_INPUT, result);
}

TEST (key_update_initiate_success)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  /* Save original key phase and keys */
  int orig_phase = state.key_phase;
  uint8_t orig_write_key[16];
  memcpy (orig_write_key, state.write_keys.key, 16);

  /* Initiate key update */
  SocketQUICCrypto_Result result = SocketQUICKeyUpdate_initiate (&state);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Key phase should toggle */
  ASSERT_EQ (orig_phase ? 0 : 1, state.key_phase);

  /* Generation should increment */
  ASSERT_EQ (1, state.generation);

  /* Keys should change */
  ASSERT (memcmp (state.write_keys.key, orig_write_key, 16) != 0);

  /* Previous read keys should be valid */
  ASSERT_EQ (1, state.prev_read_keys_valid);

  /* Next read keys should be pre-computed */
  ASSERT_EQ (1, state.next_read_keys_valid);

  /* Update permission should be reset */
  ASSERT_EQ (0, state.update_permitted);

  SocketQUICKeyUpdate_clear (&state);
}

TEST (key_update_initiate_multiple)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  /* First update */
  SocketQUICKeyUpdate_initiate (&state);
  ASSERT_EQ (1, state.key_phase);
  ASSERT_EQ (1, state.generation);

  /* Enable another update */
  SocketQUICKeyUpdate_on_packet_sent (&state, 200);
  SocketQUICKeyUpdate_on_ack_received (&state, 200);

  /* Second update */
  SocketQUICKeyUpdate_initiate (&state);
  ASSERT_EQ (0, state.key_phase); /* Toggles back */
  ASSERT_EQ (2, state.generation);

  /* Enable another update */
  SocketQUICKeyUpdate_on_packet_sent (&state, 300);
  SocketQUICKeyUpdate_on_ack_received (&state, 300);

  /* Third update */
  SocketQUICKeyUpdate_initiate (&state);
  ASSERT_EQ (1, state.key_phase);
  ASSERT_EQ (3, state.generation);

  SocketQUICKeyUpdate_clear (&state);
}

/* Key update response tests */

TEST (key_update_process_received_null)
{
  SocketQUICCrypto_Result result
      = SocketQUICKeyUpdate_process_received (NULL, 1);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
}

TEST (key_update_process_received_same_phase)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  /* Process packet with same key phase - should be no-op */
  SocketQUICCrypto_Result result
      = SocketQUICKeyUpdate_process_received (&state, 0);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (0, state.key_phase);
  ASSERT_EQ (0, state.generation);

  SocketQUICKeyUpdate_clear (&state);
}

TEST (key_update_process_received_different_phase)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  uint8_t orig_write_key[16];
  memcpy (orig_write_key, state.write_keys.key, 16);

  /* Process packet with different key phase */
  SocketQUICCrypto_Result result
      = SocketQUICKeyUpdate_process_received (&state, 1);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* Should respond by updating our keys */
  ASSERT_EQ (1, state.key_phase);
  ASSERT_EQ (1, state.generation);
  ASSERT (memcmp (state.write_keys.key, orig_write_key, 16) != 0);

  SocketQUICKeyUpdate_clear (&state);
}

/* Key selection tests */

TEST (key_update_get_read_keys_null)
{
  const SocketQUICPacketKeys_T *keys;
  SocketQUICCrypto_Result result
      = SocketQUICKeyUpdate_get_read_keys (NULL, 0, 0, &keys);
  ASSERT_EQ (QUIC_CRYPTO_ERROR_NULL, result);
}

TEST (key_update_get_read_keys_current_phase)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  const SocketQUICPacketKeys_T *keys;
  SocketQUICCrypto_Result result
      = SocketQUICKeyUpdate_get_read_keys (&state, 0, 100, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (&state.read_keys, keys);

  SocketQUICKeyUpdate_clear (&state);
}

TEST (key_update_get_read_keys_next_phase)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  const SocketQUICPacketKeys_T *keys;
  /* Request keys for different phase - should return next keys */
  SocketQUICCrypto_Result result
      = SocketQUICKeyUpdate_get_read_keys (&state, 1, 100, &keys);

  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (&state.next_read_keys, keys);

  SocketQUICKeyUpdate_clear (&state);
}

/* AEAD counter tests */

TEST (key_update_encrypt_counter)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  ASSERT_EQ (0, state.packets_encrypted);

  SocketQUICKeyUpdate_on_encrypt (&state);
  ASSERT_EQ (1, state.packets_encrypted);

  SocketQUICKeyUpdate_on_encrypt (&state);
  ASSERT_EQ (2, state.packets_encrypted);

  SocketQUICKeyUpdate_clear (&state);
}

TEST (key_update_decrypt_counter)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  ASSERT_EQ (0, state.packets_decrypted);

  SocketQUICKeyUpdate_on_decrypt (&state);
  ASSERT_EQ (1, state.packets_decrypted);

  SocketQUICKeyUpdate_clear (&state);
}

TEST (key_update_failure_counter)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  ASSERT_EQ (0, state.decryption_failures);

  SocketQUICKeyUpdate_on_decrypt_failure (&state);
  ASSERT_EQ (1, state.decryption_failures);

  SocketQUICKeyUpdate_on_decrypt_failure (&state);
  ASSERT_EQ (2, state.decryption_failures);

  SocketQUICKeyUpdate_clear (&state);
}

TEST (key_update_encrypt_counter_reset_on_update)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  /* Encrypt some packets */
  for (int i = 0; i < 100; i++)
    SocketQUICKeyUpdate_on_encrypt (&state);
  ASSERT_EQ (100, state.packets_encrypted);

  /* Initiate key update */
  SocketQUICKeyUpdate_initiate (&state);

  /* Counter should reset */
  ASSERT_EQ (0, state.packets_encrypted);

  SocketQUICKeyUpdate_clear (&state);
}

/* Limit check tests */

TEST (key_update_confidentiality_not_reached_initially)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  ASSERT_EQ (0, SocketQUICKeyUpdate_confidentiality_limit_reached (&state));

  SocketQUICKeyUpdate_clear (&state);
}

TEST (key_update_integrity_not_exceeded_initially)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  ASSERT_EQ (0, SocketQUICKeyUpdate_integrity_limit_exceeded (&state));

  SocketQUICKeyUpdate_clear (&state);
}

TEST (key_update_confidentiality_limit_check_null)
{
  ASSERT_EQ (0, SocketQUICKeyUpdate_confidentiality_limit_reached (NULL));
}

TEST (key_update_integrity_limit_check_null)
{
  ASSERT_EQ (0, SocketQUICKeyUpdate_integrity_limit_exceeded (NULL));
}

/* Packet number tracking tests */

TEST (key_update_packet_sent_tracking)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  ASSERT_EQ (UINT64_MAX, state.lowest_pn_current_phase);

  SocketQUICKeyUpdate_on_packet_sent (&state, 100);
  ASSERT_EQ (100, state.lowest_pn_current_phase);

  /* Higher PN shouldn't change lowest */
  SocketQUICKeyUpdate_on_packet_sent (&state, 200);
  ASSERT_EQ (100, state.lowest_pn_current_phase);

  /* Lower PN should update */
  SocketQUICKeyUpdate_on_packet_sent (&state, 50);
  ASSERT_EQ (50, state.lowest_pn_current_phase);

  SocketQUICKeyUpdate_clear (&state);
}

TEST (key_update_ack_received_tracking)
{
  SocketQUICKeyUpdate_T state;
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  ASSERT_EQ (0, state.highest_acked_pn);

  SocketQUICKeyUpdate_on_ack_received (&state, 50);
  ASSERT_EQ (50, state.highest_acked_pn);

  /* Higher ACK updates */
  SocketQUICKeyUpdate_on_ack_received (&state, 100);
  ASSERT_EQ (100, state.highest_acked_pn);

  /* Lower ACK doesn't change highest */
  SocketQUICKeyUpdate_on_ack_received (&state, 75);
  ASSERT_EQ (100, state.highest_acked_pn);

  SocketQUICKeyUpdate_clear (&state);
}

/* Full key update cycle test */

TEST (key_update_full_cycle)
{
  SocketQUICKeyUpdate_T state;

  /* Initialize with initial keys */
  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  /* Verify initial state */
  ASSERT_EQ (0, state.key_phase);
  ASSERT_EQ (0, state.generation);
  ASSERT_EQ (0, SocketQUICKeyUpdate_can_initiate (&state));

  /* Send packets and receive ACK to enable key update */
  SocketQUICKeyUpdate_on_packet_sent (&state, 0);
  SocketQUICKeyUpdate_on_packet_sent (&state, 1);
  SocketQUICKeyUpdate_on_ack_received (&state, 1);

  ASSERT_EQ (1, SocketQUICKeyUpdate_can_initiate (&state));

  /* Initiate key update */
  SocketQUICCrypto_Result result = SocketQUICKeyUpdate_initiate (&state);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (1, state.key_phase);
  ASSERT_EQ (1, state.generation);
  ASSERT_EQ (0, SocketQUICKeyUpdate_can_initiate (&state));

  /* Send more packets with new keys */
  SocketQUICKeyUpdate_on_packet_sent (&state, 2);
  SocketQUICKeyUpdate_on_packet_sent (&state, 3);
  SocketQUICKeyUpdate_on_ack_received (&state, 3);

  ASSERT_EQ (1, SocketQUICKeyUpdate_can_initiate (&state));

  /* Another key update */
  result = SocketQUICKeyUpdate_initiate (&state);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (0, state.key_phase);
  ASSERT_EQ (2, state.generation);

  SocketQUICKeyUpdate_clear (&state);
}

/* Peer-initiated key update test */

TEST (key_update_peer_initiated)
{
  SocketQUICKeyUpdate_T state;

  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  /* Peer sends packet with key phase 1 */
  const SocketQUICPacketKeys_T *keys;
  SocketQUICCrypto_Result result
      = SocketQUICKeyUpdate_get_read_keys (&state, 1, 100, &keys);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (&state.next_read_keys, keys);

  /* Process the key update (after successful decryption) */
  result = SocketQUICKeyUpdate_process_received (&state, 1);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);

  /* We should now be on key phase 1 */
  ASSERT_EQ (1, state.key_phase);
  ASSERT_EQ (1, state.generation);

  SocketQUICKeyUpdate_clear (&state);
}

/* AES-256-GCM full key update cycle */

TEST (key_update_full_cycle_aes256)
{
  SocketQUICKeyUpdate_T state;

  /* Initialize with AES-256-GCM (48-byte secrets) */
  SocketQUICCrypto_Result result
      = SocketQUICKeyUpdate_set_initial_keys (&state,
                                              test_write_secret_sha384,
                                              test_read_secret_sha384,
                                              48,
                                              QUIC_AEAD_AES_256_GCM);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (0, state.key_phase);
  ASSERT_EQ (0, state.generation);

  /* Enable and initiate first key update */
  SocketQUICKeyUpdate_on_packet_sent (&state, 0);
  SocketQUICKeyUpdate_on_ack_received (&state, 0);

  result = SocketQUICKeyUpdate_initiate (&state);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (1, state.key_phase);
  ASSERT_EQ (1, state.generation);

  /* Enable and initiate second key update */
  SocketQUICKeyUpdate_on_packet_sent (&state, 1);
  SocketQUICKeyUpdate_on_ack_received (&state, 1);

  result = SocketQUICKeyUpdate_initiate (&state);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (0, state.key_phase);
  ASSERT_EQ (2, state.generation);

  SocketQUICKeyUpdate_clear (&state);
}

/* ChaCha20-Poly1305 full key update cycle */

TEST (key_update_full_cycle_chacha20)
{
  SocketQUICKeyUpdate_T state;

  /* Initialize with ChaCha20-Poly1305 (32-byte secrets) */
  SocketQUICCrypto_Result result
      = SocketQUICKeyUpdate_set_initial_keys (&state,
                                              test_write_secret_sha256,
                                              test_read_secret_sha256,
                                              32,
                                              QUIC_AEAD_CHACHA20_POLY1305);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (0, state.key_phase);
  ASSERT_EQ (0, state.generation);

  /* Enable and initiate first key update */
  SocketQUICKeyUpdate_on_packet_sent (&state, 0);
  SocketQUICKeyUpdate_on_ack_received (&state, 0);

  result = SocketQUICKeyUpdate_initiate (&state);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (1, state.key_phase);
  ASSERT_EQ (1, state.generation);

  /* Enable and initiate second key update */
  SocketQUICKeyUpdate_on_packet_sent (&state, 1);
  SocketQUICKeyUpdate_on_ack_received (&state, 1);

  result = SocketQUICKeyUpdate_initiate (&state);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  ASSERT_EQ (0, state.key_phase);
  ASSERT_EQ (2, state.generation);

  SocketQUICKeyUpdate_clear (&state);
}

/* Header protection key constancy - HP key should NOT change on key update */

TEST (key_update_hp_key_unchanged)
{
  SocketQUICKeyUpdate_T state;

  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  /* Save original HP keys */
  uint8_t orig_write_hp[QUIC_PACKET_HP_MAX_LEN];
  uint8_t orig_read_hp[QUIC_PACKET_HP_MAX_LEN];
  memcpy (orig_write_hp, state.write_keys.hp_key, state.write_keys.hp_len);
  memcpy (orig_read_hp, state.read_keys.hp_key, state.read_keys.hp_len);
  size_t hp_len = state.write_keys.hp_len;

  /* Perform multiple key updates */
  for (int i = 0; i < 3; i++)
    {
      SocketQUICKeyUpdate_on_packet_sent (&state, (uint64_t)i * 10);
      SocketQUICKeyUpdate_on_ack_received (&state, (uint64_t)i * 10);
      SocketQUICKeyUpdate_initiate (&state);
    }

  /*
   * Per RFC 9001 §6: "The header protection key is not updated".
   * HP keys should remain constant across all key updates.
   */
  ASSERT (memcmp (state.write_keys.hp_key, orig_write_hp, hp_len) == 0);
  ASSERT (memcmp (state.read_keys.hp_key, orig_read_hp, hp_len) == 0);

  SocketQUICKeyUpdate_clear (&state);
}

/* Delayed packet decryption using previous keys */

TEST (key_update_delayed_packet_uses_prev_keys)
{
  SocketQUICKeyUpdate_T state;

  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  /* Send packets 0-10 with key phase 0 */
  for (uint64_t i = 0; i <= 10; i++)
    SocketQUICKeyUpdate_on_packet_sent (&state, i);

  SocketQUICKeyUpdate_on_ack_received (&state, 5);

  /* Initiate key update - now on key phase 1 */
  SocketQUICKeyUpdate_initiate (&state);
  ASSERT_EQ (1, state.key_phase);

  /* Send packets 11-20 with key phase 1 */
  for (uint64_t i = 11; i <= 20; i++)
    SocketQUICKeyUpdate_on_packet_sent (&state, i);

  /*
   * Now receive a delayed packet with phase 0 and PN < 11.
   * Per RFC 9001 §6.5, should use previous keys.
   */
  const SocketQUICPacketKeys_T *keys;
  SocketQUICCrypto_Result result;

  /* Delayed packet PN=8, phase=1 (matches current phase, but low PN) */
  result = SocketQUICKeyUpdate_get_read_keys (&state, 1, 8, &keys);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  /* Should select previous keys because PN < lowest_pn_current_phase */
  ASSERT_EQ (&state.prev_read_keys, keys);

  /* Recent packet PN=15, phase=1 */
  result = SocketQUICKeyUpdate_get_read_keys (&state, 1, 15, &keys);
  ASSERT_EQ (QUIC_CRYPTO_OK, result);
  /* Should select current keys */
  ASSERT_EQ (&state.read_keys, keys);

  SocketQUICKeyUpdate_clear (&state);
}

/* Verify clear actually zeroes secrets */

TEST (key_update_clear_zeroes_secrets)
{
  SocketQUICKeyUpdate_T state;

  SocketQUICKeyUpdate_set_initial_keys (&state,
                                        test_write_secret_sha256,
                                        test_read_secret_sha256,
                                        32,
                                        QUIC_AEAD_AES_128_GCM);

  /* Verify secrets are non-zero before clear */
  int write_nonzero = 0, read_nonzero = 0;
  for (size_t i = 0; i < 32; i++)
    {
      if (state.write_secret[i] != 0)
        write_nonzero = 1;
      if (state.read_secret[i] != 0)
        read_nonzero = 1;
    }
  ASSERT (write_nonzero);
  ASSERT (read_nonzero);

  /* Clear the state */
  SocketQUICKeyUpdate_clear (&state);

  /* Verify secrets are zeroed after clear */
  for (size_t i = 0; i < QUIC_SECRET_MAX_LEN; i++)
    {
      ASSERT_EQ (0, state.write_secret[i]);
      ASSERT_EQ (0, state.read_secret[i]);
      ASSERT_EQ (0, state.next_read_secret[i]);
    }

  /* Verify keys are zeroed */
  for (size_t i = 0; i < QUIC_PACKET_KEY_MAX_LEN; i++)
    {
      ASSERT_EQ (0, state.write_keys.key[i]);
      ASSERT_EQ (0, state.read_keys.key[i]);
    }

  ASSERT_EQ (0, state.initialized);
}

#endif /* SOCKET_HAS_TLS */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

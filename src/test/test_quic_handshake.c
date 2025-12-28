/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_handshake.c
 * @brief Unit tests for QUIC Handshake (RFC 9000 Section 7).
 */

#include "quic/SocketQUICHandshake.h"
#include "quic/SocketQUICConnection.h"
#include "quic/SocketQUICConnectionID.h"
#include "core/Arena.h"
#include "test/Test.h"

#include <stdint.h>
#include <string.h>

/* ============================================================================
 * Lifecycle Tests
 * ============================================================================
 */

TEST(handshake_new_client)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(conn);

  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(hs);
  ASSERT_EQ(QUIC_HANDSHAKE_STATE_IDLE, SocketQUICHandshake_get_state(hs));
  ASSERT_EQ(0, SocketQUICHandshake_is_complete(hs));
  ASSERT_EQ(0, SocketQUICHandshake_is_confirmed(hs));

  SocketQUICHandshake_free(&hs);
  ASSERT_NULL(hs);

  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
}

TEST(handshake_new_server)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL(conn);

  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL(hs);
  ASSERT_EQ(QUIC_HANDSHAKE_STATE_IDLE, SocketQUICHandshake_get_state(hs));

  SocketQUICHandshake_free(&hs);
  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
}

TEST(handshake_new_null_arena)
{
  SocketQUICConnection_T conn = NULL;
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(NULL, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NULL(hs);
}

TEST(handshake_new_null_connection)
{
  Arena_T arena = Arena_new();
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, NULL, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NULL(hs);
  Arena_dispose(&arena);
}

/* ============================================================================
 * Transport Parameters Tests
 * ============================================================================
 */

TEST(handshake_set_transport_params)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);

  SocketQUICTransportParams_T params;
  SocketQUICTransportParams_init(&params);
  params.max_idle_timeout = 30000;
  params.initial_max_data = 1000000;
  params.initial_max_streams_bidi = 100;

  SocketQUICHandshake_Result res = SocketQUICHandshake_set_transport_params(hs, &params);
  ASSERT_EQ(QUIC_HANDSHAKE_OK, res);

  SocketQUICHandshake_free(&hs);
  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
}

TEST(handshake_set_transport_params_null)
{
  SocketQUICHandshake_Result res = SocketQUICHandshake_set_transport_params(NULL, NULL);
  ASSERT_EQ(QUIC_HANDSHAKE_ERROR_NULL, res);
}

/* ============================================================================
 * Crypto Level String Tests
 * ============================================================================
 */

TEST(handshake_crypto_level_string)
{
  const char *str;

  str = SocketQUICHandshake_crypto_level_string(QUIC_CRYPTO_LEVEL_INITIAL);
  ASSERT(strcmp(str, "Initial") == 0);

  str = SocketQUICHandshake_crypto_level_string(QUIC_CRYPTO_LEVEL_0RTT);
  ASSERT(strcmp(str, "0-RTT") == 0);

  str = SocketQUICHandshake_crypto_level_string(QUIC_CRYPTO_LEVEL_HANDSHAKE);
  ASSERT(strcmp(str, "Handshake") == 0);

  str = SocketQUICHandshake_crypto_level_string(QUIC_CRYPTO_LEVEL_APPLICATION);
  ASSERT(strcmp(str, "Application") == 0);
}

TEST(handshake_state_string)
{
  const char *str;

  str = SocketQUICHandshake_state_string(QUIC_HANDSHAKE_STATE_IDLE);
  ASSERT(strcmp(str, "Idle") == 0);

  str = SocketQUICHandshake_state_string(QUIC_HANDSHAKE_STATE_INITIAL);
  ASSERT(strcmp(str, "Initial") == 0);

  str = SocketQUICHandshake_state_string(QUIC_HANDSHAKE_STATE_HANDSHAKE);
  ASSERT(strcmp(str, "Handshake") == 0);

  str = SocketQUICHandshake_state_string(QUIC_HANDSHAKE_STATE_COMPLETE);
  ASSERT(strcmp(str, "Complete") == 0);

  str = SocketQUICHandshake_state_string(QUIC_HANDSHAKE_STATE_CONFIRMED);
  ASSERT(strcmp(str, "Confirmed") == 0);

  str = SocketQUICHandshake_state_string(QUIC_HANDSHAKE_STATE_FAILED);
  ASSERT(strcmp(str, "Failed") == 0);
}

TEST(handshake_result_string)
{
  const char *str;

  str = SocketQUICHandshake_result_string(QUIC_HANDSHAKE_OK);
  ASSERT(strcmp(str, "OK") == 0);

  str = SocketQUICHandshake_result_string(QUIC_HANDSHAKE_ERROR_NULL);
  ASSERT(strcmp(str, "NULL argument") == 0);

  str = SocketQUICHandshake_result_string(QUIC_HANDSHAKE_ERROR_STATE);
  ASSERT(strcmp(str, "Invalid state") == 0);

  str = SocketQUICHandshake_result_string(QUIC_HANDSHAKE_ERROR_TLS);
  ASSERT(strcmp(str, "TLS error") == 0);
}

/* ============================================================================
 * Key Management Tests
 * ============================================================================
 */

TEST(handshake_has_keys_initial)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);

  /* No keys initially */
  ASSERT_EQ(0, SocketQUICHandshake_has_keys(hs, QUIC_CRYPTO_LEVEL_INITIAL));
  ASSERT_EQ(0, SocketQUICHandshake_has_keys(hs, QUIC_CRYPTO_LEVEL_HANDSHAKE));
  ASSERT_EQ(0, SocketQUICHandshake_has_keys(hs, QUIC_CRYPTO_LEVEL_APPLICATION));

  SocketQUICHandshake_free(&hs);
  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
}

TEST(handshake_get_keys_null)
{
  void *keys = SocketQUICHandshake_get_keys(NULL, QUIC_CRYPTO_LEVEL_INITIAL);
  ASSERT_NULL(keys);
}

TEST(handshake_discard_keys_null)
{
  /* Should not crash */
  SocketQUICHandshake_discard_keys(NULL, QUIC_CRYPTO_LEVEL_INITIAL);
}

TEST(handshake_discard_keys_secure_clear)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);

  /* Simulate key material allocation (for testing secure clearing) */
  /* In production, this would be done by derive_keys() */
  const size_t test_key_size = 64;
  uint8_t *test_keys = Arena_alloc(arena, test_key_size, __FILE__, __LINE__);
  memset(test_keys, 0xAA, test_key_size); /* Fill with test pattern */

  /* Manually set key pointer (normally done by derive_keys) */
  hs->keys[QUIC_CRYPTO_LEVEL_INITIAL] = test_keys;
  hs->keys_available[QUIC_CRYPTO_LEVEL_INITIAL] = 1;

  /* Verify key is set */
  ASSERT_NOT_NULL(hs->keys[QUIC_CRYPTO_LEVEL_INITIAL]);
  ASSERT_EQ(1, SocketQUICHandshake_has_keys(hs, QUIC_CRYPTO_LEVEL_INITIAL));

  /* Discard keys - should securely zero the memory */
  SocketQUICHandshake_discard_keys(hs, QUIC_CRYPTO_LEVEL_INITIAL);

  /* Verify key pointer is cleared */
  ASSERT_NULL(hs->keys[QUIC_CRYPTO_LEVEL_INITIAL]);
  ASSERT_EQ(0, SocketQUICHandshake_has_keys(hs, QUIC_CRYPTO_LEVEL_INITIAL));

  /* Verify memory was zeroed (first 64 bytes should be 0) */
  int all_zeroed = 1;
  for (size_t i = 0; i < test_key_size; i++) {
    if (test_keys[i] != 0) {
      all_zeroed = 0;
      break;
    }
  }
  ASSERT_EQ(1, all_zeroed);

  SocketQUICHandshake_free(&hs);
  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
}

/* ============================================================================
 * State Query Tests
 * ============================================================================
 */

TEST(handshake_get_state_null)
{
  SocketQUICHandshakeState state = SocketQUICHandshake_get_state(NULL);
  ASSERT_EQ(QUIC_HANDSHAKE_STATE_FAILED, state);
}

TEST(handshake_is_complete_null)
{
  ASSERT_EQ(0, SocketQUICHandshake_is_complete(NULL));
}

TEST(handshake_is_confirmed_null)
{
  ASSERT_EQ(0, SocketQUICHandshake_is_confirmed(NULL));
}

TEST(handshake_get_peer_params_null)
{
  const SocketQUICTransportParams_T *params = SocketQUICHandshake_get_peer_params(NULL);
  ASSERT_NULL(params);
}

TEST(handshake_get_peer_params_not_received)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);

  /* Params not yet received */
  const SocketQUICTransportParams_T *params = SocketQUICHandshake_get_peer_params(hs);
  ASSERT_NULL(params);

  SocketQUICHandshake_free(&hs);
  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
}

/* ============================================================================
 * CRYPTO Frame Processing Tests (Stub - needs TLS integration)
 * ============================================================================
 */

TEST(handshake_process_crypto_null)
{
  SocketQUICHandshake_Result res = SocketQUICHandshake_process_crypto(NULL, NULL);
  ASSERT_EQ(QUIC_HANDSHAKE_ERROR_NULL, res);
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================
 */

int
main(void)
{
  Test_run_all();
  return Test_get_failures() > 0 ? 1 : 0;
}

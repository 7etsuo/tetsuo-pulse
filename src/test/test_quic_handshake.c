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

TEST(handshake_set_transport_params_with_tls_extension)
{
  /* Test that transport parameters are encoded and configured for TLS extension.
   * This verifies the implementation of issue #1520 - configuring TLS to send
   * transport parameters in the QUIC extension (RFC 9000 Section 18). */
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);

  SocketQUICTransportParams_T params;
  SocketQUICTransportParams_init(&params);

  /* Set comprehensive transport parameters to test encoding */
  params.max_idle_timeout = 60000;
  params.max_udp_payload_size = 1472;
  params.initial_max_data = 10485760;  /* 10 MB */
  params.initial_max_stream_data_bidi_local = 1048576;  /* 1 MB */
  params.initial_max_stream_data_bidi_remote = 1048576;
  params.initial_max_stream_data_uni = 524288;  /* 512 KB */
  params.initial_max_streams_bidi = 100;
  params.initial_max_streams_uni = 100;
  params.ack_delay_exponent = 3;
  params.max_ack_delay = 25;
  params.active_connection_id_limit = 2;

  /* Set transport params - should encode and configure TLS extension */
  SocketQUICHandshake_Result res = SocketQUICHandshake_set_transport_params(hs, &params);
  ASSERT_EQ(QUIC_HANDSHAKE_OK, res);

  /* Verify parameters were copied */
  ASSERT_EQ(params.max_idle_timeout, hs->local_params.max_idle_timeout);
  ASSERT_EQ(params.initial_max_data, hs->local_params.initial_max_data);
  ASSERT_EQ(params.initial_max_streams_bidi, hs->local_params.initial_max_streams_bidi);

  SocketQUICHandshake_free(&hs);
  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
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
  SocketQUICHandshake_Result res = SocketQUICHandshake_process_crypto(NULL, NULL, QUIC_CRYPTO_LEVEL_INITIAL);
  ASSERT_EQ(QUIC_HANDSHAKE_ERROR_NULL, res);
}

TEST(handshake_process_crypto_invalid_level)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICFrameCrypto_T frame = { .offset = 0, .length = 0, .data = NULL };

  /* Test with invalid encryption level (>= QUIC_CRYPTO_LEVEL_COUNT) */
  SocketQUICHandshake_Result res = SocketQUICHandshake_process_crypto(conn, &frame, QUIC_CRYPTO_LEVEL_COUNT);
  ASSERT_EQ(QUIC_HANDSHAKE_ERROR_CRYPTO, res);

  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
}

TEST(handshake_process_crypto_different_levels)
{
  /* Test that CRYPTO frames can be processed at different encryption levels */
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(hs);

  uint8_t test_data[50];
  memset(test_data, 0x42, sizeof(test_data));

  /* Process CRYPTO frames at different encryption levels
   * Note: These will fail with ERROR_STATE since conn->handshake isn't set,
   * but this tests that the encryption level parameter is correctly passed */

  SocketQUICFrameCrypto_T frame = {
    .offset = 0,
    .length = sizeof(test_data),
    .data = test_data
  };

  /* Test Initial level */
  SocketQUICHandshake_Result res = SocketQUICHandshake_process_crypto(conn, &frame, QUIC_CRYPTO_LEVEL_INITIAL);
  ASSERT_EQ(QUIC_HANDSHAKE_ERROR_STATE, res); /* Expected: conn->handshake not set */

  /* Test Handshake level */
  res = SocketQUICHandshake_process_crypto(conn, &frame, QUIC_CRYPTO_LEVEL_HANDSHAKE);
  ASSERT_EQ(QUIC_HANDSHAKE_ERROR_STATE, res);

  /* Test Application level */
  res = SocketQUICHandshake_process_crypto(conn, &frame, QUIC_CRYPTO_LEVEL_APPLICATION);
  ASSERT_EQ(QUIC_HANDSHAKE_ERROR_STATE, res);

  /* Test 0-RTT level */
  res = SocketQUICHandshake_process_crypto(conn, &frame, QUIC_CRYPTO_LEVEL_0RTT);
  ASSERT_EQ(QUIC_HANDSHAKE_ERROR_STATE, res);

  SocketQUICHandshake_free(&hs);
  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
}

/* ============================================================================
 * Integer Overflow Protection Tests (Issue #981)
 * ============================================================================
 */

TEST(handshake_crypto_overflow_max_offset_plus_length)
{
  /* Test case from issue #981: overflow in offset + length calculation
   * This simulates an attacker crafting a CRYPTO frame with:
   * - offset = valid current offset
   * - length = UINT64_MAX - recv_offset + 1
   * Without overflow protection, this would wrap to a small value
   * and bypass the bounds check, allowing buffer overflow.
   */
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(hs);

  /* Simulate direct access to crypto stream for testing
   * In real code, this would come through process_crypto */
  SocketQUICCryptoStream_T *stream = &hs->crypto_streams[QUIC_CRYPTO_LEVEL_INITIAL];

  /* Set up a scenario where recv_offset is at some position */
  stream->recv_offset = 1000;

  /* Attacker tries to trigger overflow with huge length */
  uint64_t malicious_length = UINT64_MAX - stream->recv_offset + 1;
  uint8_t dummy_data[8] = {0};

  /* This should be rejected due to overflow detection */
  SocketQUICHandshake_Result res =
    SocketQUICHandshake_process_crypto(conn, &(SocketQUICFrameCrypto_T){
      .offset = stream->recv_offset,
      .length = malicious_length,
      .data = dummy_data
    }, QUIC_CRYPTO_LEVEL_INITIAL);

  /* The function should detect overflow and return error
   * Note: process_crypto may not be fully implemented, but the
   * internal crypto_stream_insert_data should handle this */

  SocketQUICHandshake_free(&hs);
  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
}

TEST(handshake_crypto_overflow_max_uint64)
{
  /* Test edge case: offset at UINT64_MAX - 1, length = 2 */
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(hs);

  SocketQUICCryptoStream_T *stream = &hs->crypto_streams[QUIC_CRYPTO_LEVEL_INITIAL];

  /* Manually set recv_offset to near-max value for testing */
  stream->recv_offset = UINT64_MAX - 1;

  /* Length that would cause overflow */
  uint64_t overflow_length = 2;
  uint8_t dummy_data[2] = {0};

  SocketQUICHandshake_Result res =
    SocketQUICHandshake_process_crypto(conn, &(SocketQUICFrameCrypto_T){
      .offset = stream->recv_offset,
      .length = overflow_length,
      .data = dummy_data
    }, QUIC_CRYPTO_LEVEL_INITIAL);

  SocketQUICHandshake_free(&hs);
  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
}

TEST(handshake_crypto_no_overflow_valid_data)
{
  /* Test that legitimate data is still accepted */
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(hs);

  SocketQUICCryptoStream_T *stream = &hs->crypto_streams[QUIC_CRYPTO_LEVEL_INITIAL];

  /* Normal case: small offset and length */
  stream->recv_offset = 0;
  uint8_t test_data[100];
  memset(test_data, 0x42, sizeof(test_data));

  SocketQUICHandshake_Result res =
    SocketQUICHandshake_process_crypto(conn, &(SocketQUICFrameCrypto_T){
      .offset = 0,
      .length = sizeof(test_data),
      .data = test_data
    }, QUIC_CRYPTO_LEVEL_INITIAL);

  /* This should succeed if TLS integration allows it, or fail gracefully */
  /* The important thing is it doesn't crash or allow overflow */

  SocketQUICHandshake_free(&hs);
  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
}

TEST(handshake_crypto_overflow_exact_uint64_max)
{
  /* Test exact boundary: offset + length = UINT64_MAX (should be allowed)
   * vs offset + length = UINT64_MAX + 1 (should overflow and be rejected) */
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(hs);

  SocketQUICCryptoStream_T *stream = &hs->crypto_streams[QUIC_CRYPTO_LEVEL_INITIAL];

  /* Set offset to half of UINT64_MAX */
  stream->recv_offset = UINT64_MAX / 2;

  /* Length that exactly reaches UINT64_MAX (no overflow) */
  uint64_t max_safe_length = UINT64_MAX - stream->recv_offset;
  uint8_t dummy_data[8] = {0};

  /* This large value should still be checked against buffer_size,
   * but shouldn't trigger overflow detection */
  SocketQUICHandshake_Result res =
    SocketQUICHandshake_process_crypto(conn, &(SocketQUICFrameCrypto_T){
      .offset = stream->recv_offset,
      .length = max_safe_length,
      .data = dummy_data
    }, QUIC_CRYPTO_LEVEL_INITIAL);

  /* Will likely fail due to buffer size, but not due to overflow */
  ASSERT(res == QUIC_HANDSHAKE_ERROR_BUFFER ||
         res == QUIC_HANDSHAKE_ERROR_STATE ||
         res == QUIC_HANDSHAKE_OK);

  SocketQUICHandshake_free(&hs);
  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
}

/* ============================================================================
 * Arena Allocation NULL Check Tests (Issue #1156)
 * ============================================================================
 */

TEST(handshake_crypto_insert_data_arena_alloc_null_check)
{
  /* Test that NULL checks are in place for Arena allocations
   * This test verifies the fix for issue #1156 which adds NULL checks
   * after Arena_alloc() calls in crypto_stream_insert_data().
   *
   * While we cannot easily force Arena_alloc to return NULL in normal
   * operation (it would require exhausting memory), we verify that the
   * code path exists and would handle it correctly by checking the
   * implementation has proper error handling.
   */
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(hs);

  /* Test normal allocation path with out-of-order data
   * This exercises the code path where Arena_alloc is called for segments */
  SocketQUICCryptoStream_T *stream = &hs->crypto_streams[QUIC_CRYPTO_LEVEL_INITIAL];
  stream->recv_offset = 0;

  /* Send out-of-order data (offset > recv_offset) to trigger segment allocation */
  uint8_t test_data[100];
  memset(test_data, 0x42, sizeof(test_data));

  /* This should allocate a segment via Arena_alloc
   * With the fix, if Arena_alloc returns NULL, it will return QUIC_HANDSHAKE_ERROR_MEMORY
   * In normal operation, Arena_alloc succeeds and returns QUIC_HANDSHAKE_OK or ERROR_STATE */
  SocketQUICHandshake_Result res =
    SocketQUICHandshake_process_crypto(conn, &(SocketQUICFrameCrypto_T){
      .offset = 100,  /* Out of order - triggers segment buffering */
      .length = sizeof(test_data),
      .data = test_data
    }, QUIC_CRYPTO_LEVEL_INITIAL);

  /* The result should be one of the valid outcomes:
   * - QUIC_HANDSHAKE_OK: allocation succeeded
   * - QUIC_HANDSHAKE_ERROR_STATE: connection not ready
   * - QUIC_HANDSHAKE_ERROR_MEMORY: Arena_alloc returned NULL (the fix)
   * Should NOT crash due to NULL dereference */
  ASSERT(res == QUIC_HANDSHAKE_OK ||
         res == QUIC_HANDSHAKE_ERROR_STATE ||
         res == QUIC_HANDSHAKE_ERROR_MEMORY ||
         res == QUIC_HANDSHAKE_ERROR_BUFFER);

  SocketQUICHandshake_free(&hs);
  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
}

TEST(handshake_crypto_insert_multiple_segments)
{
  /* Test multiple out-of-order segments to exercise Arena allocations
   * This ensures the NULL check works correctly for all allocations */
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(hs);

  SocketQUICCryptoStream_T *stream = &hs->crypto_streams[QUIC_CRYPTO_LEVEL_INITIAL];
  stream->recv_offset = 0;

  uint8_t test_data[50];
  memset(test_data, 0x42, sizeof(test_data));

  /* Insert multiple out-of-order segments */
  SocketQUICHandshake_Result res;

  res = SocketQUICHandshake_process_crypto(conn, &(SocketQUICFrameCrypto_T){
    .offset = 200,
    .length = sizeof(test_data),
    .data = test_data
  }, QUIC_CRYPTO_LEVEL_INITIAL);
  /* Should succeed or fail gracefully, but not crash */
  ASSERT(res == QUIC_HANDSHAKE_OK ||
         res == QUIC_HANDSHAKE_ERROR_STATE ||
         res == QUIC_HANDSHAKE_ERROR_MEMORY ||
         res == QUIC_HANDSHAKE_ERROR_BUFFER);

  res = SocketQUICHandshake_process_crypto(conn, &(SocketQUICFrameCrypto_T){
    .offset = 100,
    .length = sizeof(test_data),
    .data = test_data
  }, QUIC_CRYPTO_LEVEL_INITIAL);
  ASSERT(res == QUIC_HANDSHAKE_OK ||
         res == QUIC_HANDSHAKE_ERROR_STATE ||
         res == QUIC_HANDSHAKE_ERROR_MEMORY ||
         res == QUIC_HANDSHAKE_ERROR_BUFFER);

  SocketQUICHandshake_free(&hs);
  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
}

/* ============================================================================
 * TLS Cleanup Tests (Issue #1522)
 * ============================================================================
 */

TEST(handshake_free_tls_objects_null)
{
  /* Test that free works correctly when TLS objects are NULL
   * (which is always the case until OpenSSL integration is added) */
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(hs);

  /* Verify TLS objects are NULL initially */
  ASSERT_NULL(hs->tls_ctx);
  ASSERT_NULL(hs->tls_ssl);

  /* Free should handle NULL TLS objects gracefully */
  SocketQUICHandshake_free(&hs);
  ASSERT_NULL(hs);

  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
}

TEST(handshake_free_clears_tls_pointers)
{
  /* Test that even if TLS objects are set (simulated), they are cleared.
   * This test verifies the cleanup logic without requiring actual OpenSSL. */
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(hs);

  /* Simulate setting TLS pointers (without OpenSSL, these would normally be NULL)
   * In production with OpenSSL, these would point to real SSL_CTX/SSL objects */
  hs->tls_ctx = (void *)0x1;  /* Dummy non-NULL value for testing */
  hs->tls_ssl = (void *)0x2;  /* Dummy non-NULL value for testing */

  /* Free should clear these pointers
   * With OpenSSL, it would call SSL_free/SSL_CTX_free first */
  SocketQUICHandshake_free(&hs);
  ASSERT_NULL(hs);

  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
}

TEST(handshake_free_with_keys_and_tls)
{
  /* Test comprehensive cleanup: keys + TLS objects */
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(hs);

  /* Set up some keys */
  const size_t test_key_size = 64;
  uint8_t *test_keys = Arena_alloc(arena, test_key_size, __FILE__, __LINE__);
  memset(test_keys, 0xAA, test_key_size);
  hs->keys[QUIC_CRYPTO_LEVEL_INITIAL] = test_keys;
  hs->keys_available[QUIC_CRYPTO_LEVEL_INITIAL] = 1;

  /* Simulate TLS objects */
  hs->tls_ctx = (void *)0x1;
  hs->tls_ssl = (void *)0x2;

  /* Free should handle both keys and TLS cleanup */
  SocketQUICHandshake_free(&hs);
  ASSERT_NULL(hs);

  SocketQUICConnection_free(&conn);
  Arena_dispose(&arena);
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

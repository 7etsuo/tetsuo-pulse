/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_0rtt.c
 * @brief Unit tests for QUIC 0-RTT early data (RFC 9001 Section 4.6).
 *
 * Tests cover:
 * - §4.6: 0-RTT state machine transitions
 * - §4.6.1: Session ticket validation (max_early_data_size sentinel)
 * - §4.6.2: Acceptance and rejection handling
 * - §4.6.2: HelloRetryRequest forces rejection
 * - §4.6.3: Transport parameter validation
 * - NULL pointer safety
 * - State transitions and invariants
 */

#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/SocketCrypto.h"
#include "quic/SocketQUICConnection.h"
#include "quic/SocketQUICHandshake.h"
#include "quic/SocketQUICTLS.h"
#include "quic/SocketQUICTransportParams.h"
#include "test/Test.h"

/* ============================================================================
 * Test Helpers
 * ============================================================================
 */

/**
 * @brief Create a test handshake context for 0-RTT testing.
 */
static SocketQUICHandshake_T
create_test_handshake (Arena_T arena,
                       SocketQUICConnection_T conn,
                       SocketQUICConnection_Role role)
{
  SocketQUICHandshake_T hs = SocketQUICHandshake_new (arena, conn, role);
  if (!hs)
    return NULL;

  /* Allocate mock keys for all levels */
  for (int i = 0; i < QUIC_CRYPTO_LEVEL_COUNT; i++)
    {
      hs->keys[i]
          = Arena_alloc (arena, QUIC_MAX_KEY_MATERIAL_SIZE, __FILE__, __LINE__);
      if (hs->keys[i])
        {
          memset (hs->keys[i], 0xAA, QUIC_MAX_KEY_MATERIAL_SIZE);
          hs->keys_available[i] = 1;
        }
    }

  return hs;
}

/**
 * @brief Create default transport parameters for testing.
 */
static void
init_test_params (SocketQUICTransportParams_T *params)
{
  SocketQUICTransportParams_init (params);
  params->initial_max_data = 1048576;
  params->initial_max_stream_data_bidi_local = 262144;
  params->initial_max_stream_data_bidi_remote = 262144;
  params->initial_max_stream_data_uni = 262144;
  params->initial_max_streams_bidi = 100;
  params->initial_max_streams_uni = 100;
  params->active_connection_id_limit = 8;
  params->disable_active_migration = 0;
}

/* ============================================================================
 * State Machine Tests
 * ============================================================================
 */

/* Test: Initial state is NONE */
TEST (zero_rtt_init_state_none)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Check initial state */
  ASSERT_EQ (SocketQUICHandshake_0rtt_get_state (hs), QUIC_0RTT_STATE_NONE);
  ASSERT_EQ (SocketQUICHandshake_0rtt_available (hs), 0);
  ASSERT_EQ (SocketQUICHandshake_0rtt_accepted (hs), 0);
  ASSERT_EQ (hs->hello_retry_received, 0);

  Arena_dispose (&arena);
}

/* Test: Setting ticket transitions to OFFERED */
TEST (zero_rtt_set_ticket_transitions_to_offered)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Create mock ticket */
  uint8_t ticket[64];
  memset (ticket, 0x42, sizeof (ticket));

  SocketQUICTransportParams_T params;
  init_test_params (&params);

  /* Set ticket */
  SocketQUICHandshake_Result res = SocketQUICHandshake_0rtt_set_ticket (
      hs, ticket, sizeof (ticket), &params, "h3", 2);
  ASSERT_EQ (res, QUIC_HANDSHAKE_OK);

  /* Check state transition */
  ASSERT_EQ (SocketQUICHandshake_0rtt_get_state (hs), QUIC_0RTT_STATE_OFFERED);
  ASSERT_EQ (SocketQUICHandshake_0rtt_available (hs), 1);

  /* Verify ticket was copied */
  ASSERT_NOT_NULL (hs->zero_rtt.ticket_data);
  ASSERT_EQ (hs->zero_rtt.ticket_len, sizeof (ticket));
  ASSERT_EQ (memcmp (hs->zero_rtt.ticket_data, ticket, sizeof (ticket)), 0);

  /* Verify params were saved */
  ASSERT_EQ (hs->zero_rtt.saved_params_valid, 1);
  ASSERT_EQ (hs->zero_rtt.saved_params.initial_max_data, params.initial_max_data);

  /* Verify ALPN was saved */
  ASSERT_EQ (hs->zero_rtt.saved_alpn_len, 2);
  ASSERT_EQ (memcmp (hs->zero_rtt.saved_alpn, "h3", 2), 0);

  Arena_dispose (&arena);
}

/* Test: 0-RTT not available without ticket */
TEST (zero_rtt_not_available_without_ticket)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Without ticket, should not be available */
  ASSERT_EQ (SocketQUICHandshake_0rtt_available (hs), 0);

  Arena_dispose (&arena);
}

/* Test: HRR forces 0-RTT rejection */
TEST (zero_rtt_disabled_by_hrr)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Set up ticket */
  uint8_t ticket[64];
  memset (ticket, 0x42, sizeof (ticket));
  SocketQUICTransportParams_T params;
  init_test_params (&params);

  SocketQUICHandshake_0rtt_set_ticket (
      hs, ticket, sizeof (ticket), &params, "h3", 2);
  ASSERT_EQ (SocketQUICHandshake_0rtt_get_state (hs), QUIC_0RTT_STATE_OFFERED);
  ASSERT_EQ (SocketQUICHandshake_0rtt_available (hs), 1);

  /* Receive HRR */
  SocketQUICHandshake_on_hello_retry_request (hs);

  /* Should now be rejected */
  ASSERT_EQ (hs->hello_retry_received, 1);
  ASSERT_EQ (SocketQUICHandshake_0rtt_get_state (hs), QUIC_0RTT_STATE_REJECTED);
  ASSERT_EQ (SocketQUICHandshake_0rtt_available (hs), 0);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Transport Parameter Validation Tests (RFC 9001 §4.6.3)
 * ============================================================================
 */

/* Test: Equal parameters are valid */
TEST (zero_rtt_param_validation_accepts_equal)
{
  SocketQUICTransportParams_T original, resumed;
  init_test_params (&original);
  init_test_params (&resumed);

  SocketQUICTLS_Result res
      = SocketQUICTLS_validate_0rtt_params (&original, &resumed);

  /* Skip test if TLS/QUIC support not available */
  if (res == QUIC_TLS_ERROR_NO_TLS)
    return;

  ASSERT_EQ (res, QUIC_TLS_OK);
}

/* Test: Increased parameters are valid */
TEST (zero_rtt_param_validation_accepts_increased)
{
  SocketQUICTransportParams_T original, resumed;
  init_test_params (&original);
  init_test_params (&resumed);

  /* Increase all limits */
  resumed.initial_max_data *= 2;
  resumed.initial_max_stream_data_bidi_local *= 2;
  resumed.initial_max_stream_data_bidi_remote *= 2;
  resumed.initial_max_stream_data_uni *= 2;
  resumed.initial_max_streams_bidi *= 2;
  resumed.initial_max_streams_uni *= 2;
  resumed.active_connection_id_limit *= 2;

  SocketQUICTLS_Result res
      = SocketQUICTLS_validate_0rtt_params (&original, &resumed);

  /* Skip test if TLS/QUIC support not available */
  if (res == QUIC_TLS_ERROR_NO_TLS)
    return;

  ASSERT_EQ (res, QUIC_TLS_OK);
}

/* Test: Reduced max_data is rejected */
TEST (zero_rtt_param_validation_rejects_decreased_max_data)
{
  SocketQUICTransportParams_T original, resumed;
  init_test_params (&original);
  init_test_params (&resumed);

  /* First check if TLS/QUIC support is available */
  SocketQUICTLS_Result probe
      = SocketQUICTLS_validate_0rtt_params (&original, &resumed);
  if (probe == QUIC_TLS_ERROR_NO_TLS)
    return;

  resumed.initial_max_data = original.initial_max_data / 2;

  SocketQUICTLS_Result res
      = SocketQUICTLS_validate_0rtt_params (&original, &resumed);
  ASSERT_EQ (res, QUIC_TLS_ERROR_TRANSPORT);
}

/* Test: Reduced stream limits are rejected */
TEST (zero_rtt_param_validation_rejects_decreased_stream_limits)
{
  SocketQUICTransportParams_T original, resumed;

  /* First check if TLS/QUIC support is available */
  init_test_params (&original);
  init_test_params (&resumed);
  SocketQUICTLS_Result probe
      = SocketQUICTLS_validate_0rtt_params (&original, &resumed);
  if (probe == QUIC_TLS_ERROR_NO_TLS)
    return;

  /* Test initial_max_stream_data_bidi_local */
  init_test_params (&original);
  init_test_params (&resumed);
  resumed.initial_max_stream_data_bidi_local
      = original.initial_max_stream_data_bidi_local / 2;
  ASSERT_EQ (SocketQUICTLS_validate_0rtt_params (&original, &resumed),
             QUIC_TLS_ERROR_TRANSPORT);

  /* Test initial_max_stream_data_bidi_remote */
  init_test_params (&original);
  init_test_params (&resumed);
  resumed.initial_max_stream_data_bidi_remote
      = original.initial_max_stream_data_bidi_remote / 2;
  ASSERT_EQ (SocketQUICTLS_validate_0rtt_params (&original, &resumed),
             QUIC_TLS_ERROR_TRANSPORT);

  /* Test initial_max_stream_data_uni */
  init_test_params (&original);
  init_test_params (&resumed);
  resumed.initial_max_stream_data_uni
      = original.initial_max_stream_data_uni / 2;
  ASSERT_EQ (SocketQUICTLS_validate_0rtt_params (&original, &resumed),
             QUIC_TLS_ERROR_TRANSPORT);

  /* Test initial_max_streams_bidi */
  init_test_params (&original);
  init_test_params (&resumed);
  resumed.initial_max_streams_bidi = original.initial_max_streams_bidi / 2;
  ASSERT_EQ (SocketQUICTLS_validate_0rtt_params (&original, &resumed),
             QUIC_TLS_ERROR_TRANSPORT);

  /* Test initial_max_streams_uni */
  init_test_params (&original);
  init_test_params (&resumed);
  resumed.initial_max_streams_uni = original.initial_max_streams_uni / 2;
  ASSERT_EQ (SocketQUICTLS_validate_0rtt_params (&original, &resumed),
             QUIC_TLS_ERROR_TRANSPORT);
}

/* Test: Migration disabled change is rejected */
TEST (zero_rtt_param_validation_rejects_migration_disabled)
{
  SocketQUICTransportParams_T original, resumed;
  init_test_params (&original);
  init_test_params (&resumed);

  /* First check if TLS/QUIC support is available */
  SocketQUICTLS_Result probe
      = SocketQUICTLS_validate_0rtt_params (&original, &resumed);
  if (probe == QUIC_TLS_ERROR_NO_TLS)
    return;

  original.disable_active_migration = 0;
  resumed.disable_active_migration = 1;

  SocketQUICTLS_Result res
      = SocketQUICTLS_validate_0rtt_params (&original, &resumed);
  ASSERT_EQ (res, QUIC_TLS_ERROR_TRANSPORT);
}

/* Test: Migration was already disabled is OK */
TEST (zero_rtt_param_validation_accepts_migration_already_disabled)
{
  SocketQUICTransportParams_T original, resumed;
  init_test_params (&original);
  init_test_params (&resumed);

  original.disable_active_migration = 1;
  resumed.disable_active_migration = 1;

  SocketQUICTLS_Result res
      = SocketQUICTLS_validate_0rtt_params (&original, &resumed);

  /* Skip test if TLS/QUIC support not available */
  if (res == QUIC_TLS_ERROR_NO_TLS)
    return;

  ASSERT_EQ (res, QUIC_TLS_OK);
}

/* Test: Reduced connection_id_limit is rejected */
TEST (zero_rtt_param_validation_rejects_decreased_cid_limit)
{
  SocketQUICTransportParams_T original, resumed;
  init_test_params (&original);
  init_test_params (&resumed);

  /* First check if TLS/QUIC support is available */
  SocketQUICTLS_Result probe
      = SocketQUICTLS_validate_0rtt_params (&original, &resumed);
  if (probe == QUIC_TLS_ERROR_NO_TLS)
    return;

  resumed.active_connection_id_limit = original.active_connection_id_limit / 2;

  SocketQUICTLS_Result res
      = SocketQUICTLS_validate_0rtt_params (&original, &resumed);
  ASSERT_EQ (res, QUIC_TLS_ERROR_TRANSPORT);
}

/* ============================================================================
 * Rejection Handling Tests
 * ============================================================================
 */

/* Test: Rejection discards 0-RTT keys */
TEST (zero_rtt_rejection_discards_keys)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Set up 0-RTT */
  uint8_t ticket[64];
  memset (ticket, 0x42, sizeof (ticket));
  SocketQUICTransportParams_T params;
  init_test_params (&params);

  SocketQUICHandshake_0rtt_set_ticket (
      hs, ticket, sizeof (ticket), &params, "h3", 2);

  /* Mark 0-RTT keys as available */
  hs->zero_rtt.keys_derived = 1;

  /* Handle rejection */
  SocketQUICHandshake_Result res
      = SocketQUICHandshake_0rtt_handle_rejection (hs);
  ASSERT_EQ (res, QUIC_HANDSHAKE_OK);

  /* Verify keys discarded */
  ASSERT_EQ (hs->zero_rtt_keys_discarded, 1);
  ASSERT_EQ (hs->zero_rtt.keys_derived, 0);
  ASSERT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_0RTT]);
  ASSERT_EQ (hs->keys_available[QUIC_CRYPTO_LEVEL_0RTT], 0);

  Arena_dispose (&arena);
}

/* Test: Rejection clears early data buffer */
TEST (zero_rtt_rejection_clears_buffer)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Set up 0-RTT with early data buffer */
  uint8_t ticket[64];
  memset (ticket, 0x42, sizeof (ticket));
  SocketQUICTransportParams_T params;
  init_test_params (&params);

  SocketQUICHandshake_0rtt_set_ticket (
      hs, ticket, sizeof (ticket), &params, "h3", 2);

  /* Allocate and populate early data buffer */
  hs->zero_rtt.early_data_capacity = 1024;
  hs->zero_rtt.early_data_buffer
      = Arena_alloc (arena, hs->zero_rtt.early_data_capacity, __FILE__, __LINE__);
  ASSERT_NOT_NULL (hs->zero_rtt.early_data_buffer);
  memset (hs->zero_rtt.early_data_buffer, 0x55, hs->zero_rtt.early_data_capacity);
  hs->zero_rtt.early_data_len = 512;

  /* Handle rejection */
  SocketQUICHandshake_0rtt_handle_rejection (hs);

  /* Verify buffer cleared */
  ASSERT_EQ (hs->zero_rtt.early_data_len, 0);

  Arena_dispose (&arena);
}

/* Test: Rejection updates state */
TEST (zero_rtt_rejection_updates_state)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Set up 0-RTT */
  uint8_t ticket[64];
  memset (ticket, 0x42, sizeof (ticket));
  SocketQUICTransportParams_T params;
  init_test_params (&params);

  SocketQUICHandshake_0rtt_set_ticket (
      hs, ticket, sizeof (ticket), &params, "h3", 2);
  ASSERT_EQ (SocketQUICHandshake_0rtt_get_state (hs), QUIC_0RTT_STATE_OFFERED);

  /* Handle rejection */
  SocketQUICHandshake_0rtt_handle_rejection (hs);

  /* Verify state */
  ASSERT_EQ (SocketQUICHandshake_0rtt_get_state (hs), QUIC_0RTT_STATE_REJECTED);
  ASSERT_EQ (SocketQUICHandshake_0rtt_accepted (hs), 0);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Ticket Storage Tests
 * ============================================================================
 */

/* Test: Ticket storage allocates copy */
TEST (zero_rtt_ticket_storage_allocates_copy)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Create ticket on stack */
  uint8_t ticket[128];
  for (size_t i = 0; i < sizeof (ticket); i++)
    ticket[i] = (uint8_t)i;

  SocketQUICTransportParams_T params;
  init_test_params (&params);

  SocketQUICHandshake_0rtt_set_ticket (
      hs, ticket, sizeof (ticket), &params, "h3", 2);

  /* Verify independent copy made */
  ASSERT_NOT_NULL (hs->zero_rtt.ticket_data);
  ASSERT_NE ((void *)hs->zero_rtt.ticket_data, (void *)ticket);
  ASSERT_EQ (hs->zero_rtt.ticket_len, sizeof (ticket));

  /* Modify original - should not affect stored copy */
  memset (ticket, 0xFF, sizeof (ticket));
  ASSERT_NE (hs->zero_rtt.ticket_data[0], 0xFF);
  ASSERT_EQ (hs->zero_rtt.ticket_data[0], 0);

  Arena_dispose (&arena);
}

/* ============================================================================
 * NULL Safety Tests
 * ============================================================================
 */

/* Test: All functions handle NULL gracefully */
TEST (zero_rtt_null_safety)
{
  SocketQUICTransportParams_T params;
  init_test_params (&params);
  uint8_t ticket[64] = { 0 };

  /* SocketQUICHandshake functions */
  SocketQUICHandshake_0rtt_init (NULL);
  ASSERT_EQ (SocketQUICHandshake_0rtt_available (NULL), 0);
  ASSERT_EQ (SocketQUICHandshake_0rtt_get_state (NULL), QUIC_0RTT_STATE_NONE);
  ASSERT_EQ (SocketQUICHandshake_0rtt_accepted (NULL), 0);

  ASSERT_EQ (SocketQUICHandshake_0rtt_set_ticket (NULL, ticket, 64, &params, "h3", 2),
             QUIC_HANDSHAKE_ERROR_NULL);

  ASSERT_EQ (SocketQUICHandshake_0rtt_handle_rejection (NULL),
             QUIC_HANDSHAKE_ERROR_NULL);

  SocketQUICHandshake_on_hello_retry_request (NULL);

  /* TLS validation with NULL */
  ASSERT_EQ (SocketQUICTLS_validate_0rtt_params (NULL, &params),
             QUIC_TLS_ERROR_NULL);
  ASSERT_EQ (SocketQUICTLS_validate_0rtt_params (&params, NULL),
             QUIC_TLS_ERROR_NULL);
}

/* Test: set_ticket rejects NULL ticket */
TEST (zero_rtt_set_ticket_null_ticket)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  SocketQUICTransportParams_T params;
  init_test_params (&params);

  /* NULL ticket should fail */
  ASSERT_EQ (
      SocketQUICHandshake_0rtt_set_ticket (hs, NULL, 64, &params, "h3", 2),
      QUIC_HANDSHAKE_ERROR_NULL);

  /* Zero-length ticket should fail */
  uint8_t ticket[64] = { 0 };
  ASSERT_EQ (
      SocketQUICHandshake_0rtt_set_ticket (hs, ticket, 0, &params, "h3", 2),
      QUIC_HANDSHAKE_ERROR_NULL);

  /* NULL params should fail */
  ASSERT_EQ (SocketQUICHandshake_0rtt_set_ticket (hs, ticket, 64, NULL, "h3", 2),
             QUIC_HANDSHAKE_ERROR_NULL);

  Arena_dispose (&arena);
}

/* ============================================================================
 * State Transition Tests
 * ============================================================================
 */

/* Test: Re-initializing 0-RTT resets state */
TEST (zero_rtt_reinit_resets_state)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Set up 0-RTT */
  uint8_t ticket[64];
  memset (ticket, 0x42, sizeof (ticket));
  SocketQUICTransportParams_T params;
  init_test_params (&params);

  SocketQUICHandshake_0rtt_set_ticket (
      hs, ticket, sizeof (ticket), &params, "h3", 2);
  hs->hello_retry_received = 1;

  ASSERT_EQ (SocketQUICHandshake_0rtt_get_state (hs), QUIC_0RTT_STATE_OFFERED);

  /* Re-initialize */
  SocketQUICHandshake_0rtt_init (hs);

  /* Verify reset */
  ASSERT_EQ (SocketQUICHandshake_0rtt_get_state (hs), QUIC_0RTT_STATE_NONE);
  ASSERT_EQ (hs->hello_retry_received, 0);
  ASSERT_EQ (hs->zero_rtt.saved_params_valid, 0);

  Arena_dispose (&arena);
}

/* Test: Available returns false after rejection */
TEST (zero_rtt_not_available_after_rejection)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Set up 0-RTT */
  uint8_t ticket[64];
  memset (ticket, 0x42, sizeof (ticket));
  SocketQUICTransportParams_T params;
  init_test_params (&params);

  SocketQUICHandshake_0rtt_set_ticket (
      hs, ticket, sizeof (ticket), &params, "h3", 2);
  ASSERT_EQ (SocketQUICHandshake_0rtt_available (hs), 1);

  /* Reject */
  SocketQUICHandshake_0rtt_handle_rejection (hs);

  /* Should no longer be available */
  ASSERT_EQ (SocketQUICHandshake_0rtt_available (hs), 0);

  Arena_dispose (&arena);
}

/* Test: ALPN too long is rejected */
TEST (zero_rtt_alpn_too_long)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  uint8_t ticket[64];
  memset (ticket, 0x42, sizeof (ticket));
  SocketQUICTransportParams_T params;
  init_test_params (&params);

  /* ALPN longer than buffer (256) should fail */
  char long_alpn[300];
  memset (long_alpn, 'a', sizeof (long_alpn));

  SocketQUICHandshake_Result res = SocketQUICHandshake_0rtt_set_ticket (
      hs, ticket, sizeof (ticket), &params, long_alpn, sizeof (long_alpn));
  ASSERT_EQ (res, QUIC_HANDSHAKE_ERROR_BUFFER);

  Arena_dispose (&arena);
}

/* Test: Oversized ticket is rejected (memory exhaustion prevention) */
TEST (zero_rtt_ticket_too_large)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  SocketQUICTransportParams_T params;
  init_test_params (&params);

  /* Ticket larger than 16KB should be rejected */
  uint8_t small_ticket[64];
  memset (small_ticket, 0x42, sizeof (small_ticket));

  /* Use a length that exceeds the limit but don't allocate that much */
  size_t oversized_len = 17 * 1024; /* > 16KB limit */

  SocketQUICHandshake_Result res = SocketQUICHandshake_0rtt_set_ticket (
      hs, small_ticket, oversized_len, &params, "h3", 2);
  ASSERT_EQ (res, QUIC_HANDSHAKE_ERROR_BUFFER);

  /* Verify state unchanged */
  ASSERT_EQ (SocketQUICHandshake_0rtt_get_state (hs), QUIC_0RTT_STATE_NONE);

  Arena_dispose (&arena);
}

/* Test: Double rejection is safe */
TEST (zero_rtt_double_rejection_safe)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Set up 0-RTT */
  uint8_t ticket[64];
  memset (ticket, 0x42, sizeof (ticket));
  SocketQUICTransportParams_T params;
  init_test_params (&params);

  SocketQUICHandshake_0rtt_set_ticket (
      hs, ticket, sizeof (ticket), &params, "h3", 2);
  hs->zero_rtt.keys_derived = 1;

  /* First rejection */
  SocketQUICHandshake_Result res1
      = SocketQUICHandshake_0rtt_handle_rejection (hs);
  ASSERT_EQ (res1, QUIC_HANDSHAKE_OK);
  ASSERT_EQ (SocketQUICHandshake_0rtt_get_state (hs), QUIC_0RTT_STATE_REJECTED);

  /* Second rejection should also be safe */
  SocketQUICHandshake_Result res2
      = SocketQUICHandshake_0rtt_handle_rejection (hs);
  ASSERT_EQ (res2, QUIC_HANDSHAKE_OK);
  ASSERT_EQ (SocketQUICHandshake_0rtt_get_state (hs), QUIC_0RTT_STATE_REJECTED);

  Arena_dispose (&arena);
}

/* Test: Ticket replacement clears old ticket securely */
TEST (zero_rtt_ticket_replacement)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  SocketQUICTransportParams_T params;
  init_test_params (&params);

  /* Set first ticket */
  uint8_t ticket1[64];
  memset (ticket1, 0x11, sizeof (ticket1));
  SocketQUICHandshake_Result res1 = SocketQUICHandshake_0rtt_set_ticket (
      hs, ticket1, sizeof (ticket1), &params, "h3", 2);
  ASSERT_EQ (res1, QUIC_HANDSHAKE_OK);

  uint8_t *old_ticket_ptr = hs->zero_rtt.ticket_data;
  ASSERT_NOT_NULL (old_ticket_ptr);
  ASSERT_EQ (hs->zero_rtt.ticket_data[0], 0x11);

  /* Set second ticket - should replace first */
  uint8_t ticket2[128];
  memset (ticket2, 0x22, sizeof (ticket2));
  SocketQUICHandshake_Result res2 = SocketQUICHandshake_0rtt_set_ticket (
      hs, ticket2, sizeof (ticket2), &params, "h3-29", 5);
  ASSERT_EQ (res2, QUIC_HANDSHAKE_OK);

  /* Verify new ticket is in place */
  ASSERT_EQ (hs->zero_rtt.ticket_len, sizeof (ticket2));
  ASSERT_EQ (hs->zero_rtt.ticket_data[0], 0x22);
  ASSERT_EQ (hs->zero_rtt.saved_alpn_len, 5);
  ASSERT_EQ (memcmp (hs->zero_rtt.saved_alpn, "h3-29", 5), 0);

  /* State should still be OFFERED */
  ASSERT_EQ (SocketQUICHandshake_0rtt_get_state (hs), QUIC_0RTT_STATE_OFFERED);

  Arena_dispose (&arena);
}

/* Test: TLS enable_session_tickets NULL handling */
TEST (zero_rtt_tls_enable_tickets_null)
{
  /* NULL handshake should return error */
  SocketQUICTLS_Result res = SocketQUICTLS_enable_session_tickets (NULL);
  ASSERT_EQ (res, QUIC_TLS_ERROR_NULL);
}

/* Test: TLS set_session NULL handling */
TEST (zero_rtt_tls_set_session_null)
{
  uint8_t ticket[64] = { 0 };

  /* NULL handshake */
  ASSERT_EQ (SocketQUICTLS_set_session (NULL, ticket, sizeof (ticket)),
             QUIC_TLS_ERROR_NULL);

  /* NULL ticket - need a valid handshake for this test */
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  ASSERT_EQ (SocketQUICTLS_set_session (hs, NULL, 64), QUIC_TLS_ERROR_NULL);
  ASSERT_EQ (SocketQUICTLS_set_session (hs, ticket, 0), QUIC_TLS_ERROR_NULL);

  Arena_dispose (&arena);
}

/* Test: TLS get_session_ticket NULL handling and size query */
TEST (zero_rtt_tls_get_ticket_null_and_size)
{
  size_t len = 0;
  uint8_t buffer[256];

  /* NULL handshake */
  ASSERT_EQ (SocketQUICTLS_get_session_ticket (NULL, buffer, &len),
             QUIC_TLS_ERROR_NULL);

  /* NULL len pointer */
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  ASSERT_EQ (SocketQUICTLS_get_session_ticket (hs, buffer, NULL),
             QUIC_TLS_ERROR_NULL);

  Arena_dispose (&arena);
}

/* Test: TLS early_data_accepted NULL handling */
TEST (zero_rtt_tls_early_data_accepted_null)
{
  /* NULL should return 0 (not accepted) */
  ASSERT_EQ (SocketQUICTLS_early_data_accepted (NULL), 0);
}

/* ============================================================================
 * Main Function
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

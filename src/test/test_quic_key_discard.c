/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_key_discard.c
 * @brief Unit tests for QUIC key discard logic (RFC 9001 Section 4.9).
 *
 * Tests cover:
 * - §4.9.1: Initial key discard (client/server timing)
 * - §4.9.2: Handshake key discard on confirmation
 * - §4.9.3: 0-RTT key discard timing
 * - Availability checks after key discard
 * - Idempotency of trigger functions
 * - NULL pointer safety
 * - Role-specific behavior
 */

#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/SocketCrypto.h"
#include "quic/SocketQUICConnection.h"
#include "quic/SocketQUICHandshake.h"
#include "test/Test.h"

/* ============================================================================
 * Test Helpers
 * ============================================================================
 */

/**
 * @brief Create a test handshake context with mock keys.
 */
static SocketQUICHandshake_T
create_test_handshake (Arena_T arena,
                       SocketQUICConnection_T conn,
                       SocketQUICConnection_Role role)
{
  SocketQUICHandshake_T hs = SocketQUICHandshake_new (arena, conn, role);
  if (!hs)
    return NULL;

  /* Allocate mock keys for all levels to test discard */
  for (int i = 0; i < QUIC_CRYPTO_LEVEL_COUNT; i++)
    {
      hs->keys[i]
          = Arena_alloc (arena, QUIC_MAX_KEY_MATERIAL_SIZE, __FILE__, __LINE__);
      if (hs->keys[i])
        {
          /* Fill with non-zero pattern to verify secure clearing */
          memset (hs->keys[i], 0xAA, QUIC_MAX_KEY_MATERIAL_SIZE);
          hs->keys_available[i] = 1;
        }
    }

  return hs;
}

/* ============================================================================
 * §4.9.1: Initial Key Discard Tests
 * ============================================================================
 */

/* Test: Client discards Initial keys when sending Handshake */
TEST (key_discard_client_initial_on_handshake_sent)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Initially Initial keys should be available */
  ASSERT (SocketQUICHandshake_can_send_initial (hs));
  ASSERT (SocketQUICHandshake_can_receive_initial (hs));
  ASSERT_EQ (hs->initial_keys_discarded, 0);
  ASSERT_EQ (hs->first_handshake_sent, 0);

  /* Simulate client sending first Handshake packet */
  SocketQUICHandshake_on_handshake_packet_sent (hs);

  /* Initial keys should now be discarded */
  ASSERT_EQ (hs->initial_keys_discarded, 1);
  ASSERT_EQ (hs->first_handshake_sent, 1);
  ASSERT_EQ (SocketQUICHandshake_can_send_initial (hs), 0);
  ASSERT_EQ (SocketQUICHandshake_can_receive_initial (hs), 0);
  ASSERT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_INITIAL]);
  ASSERT_EQ (hs->keys_available[QUIC_CRYPTO_LEVEL_INITIAL], 0);

  Arena_dispose (&arena);
}

/* Test: Server discards Initial keys when receiving Handshake */
TEST (key_discard_server_initial_on_handshake_received)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (hs);

  /* Initially Initial keys should be available */
  ASSERT (SocketQUICHandshake_can_send_initial (hs));
  ASSERT_EQ (hs->initial_keys_discarded, 0);
  ASSERT_EQ (hs->first_handshake_received, 0);

  /* Simulate server receiving first Handshake packet */
  SocketQUICHandshake_on_handshake_packet_received (hs);

  /* Initial keys should now be discarded */
  ASSERT_EQ (hs->initial_keys_discarded, 1);
  ASSERT_EQ (hs->first_handshake_received, 1);
  ASSERT_EQ (SocketQUICHandshake_can_send_initial (hs), 0);
  ASSERT_EQ (SocketQUICHandshake_can_receive_initial (hs), 0);
  ASSERT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_INITIAL]);

  Arena_dispose (&arena);
}

/* Test: Client ignores handshake_packet_received (server-only trigger) */
TEST (key_discard_client_ignores_handshake_received)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Call server trigger on client - should be no-op */
  SocketQUICHandshake_on_handshake_packet_received (hs);

  /* Initial keys should still be available */
  ASSERT (SocketQUICHandshake_can_send_initial (hs));
  ASSERT_EQ (hs->initial_keys_discarded, 0);
  ASSERT_NOT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_INITIAL]);

  Arena_dispose (&arena);
}

/* Test: Server ignores handshake_packet_sent (client-only trigger) */
TEST (key_discard_server_ignores_handshake_sent)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (hs);

  /* Call client trigger on server - should be no-op */
  SocketQUICHandshake_on_handshake_packet_sent (hs);

  /* Initial keys should still be available */
  ASSERT (SocketQUICHandshake_can_send_initial (hs));
  ASSERT_EQ (hs->initial_keys_discarded, 0);
  ASSERT_NOT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_INITIAL]);

  Arena_dispose (&arena);
}

/* ============================================================================
 * §4.9.2: Handshake Key Discard Tests
 * ============================================================================
 */

/* Test: Client discards Handshake keys on confirmation */
TEST (key_discard_client_handshake_on_confirmed)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Initially Handshake keys should be available */
  ASSERT (SocketQUICHandshake_can_send_handshake (hs));
  ASSERT (SocketQUICHandshake_can_receive_handshake (hs));
  ASSERT_EQ (hs->handshake_keys_discarded, 0);

  /* Simulate handshake confirmation */
  SocketQUICHandshake_on_confirmed (hs);

  /* Handshake keys should now be discarded */
  ASSERT_EQ (hs->handshake_keys_discarded, 1);
  ASSERT_EQ (SocketQUICHandshake_can_send_handshake (hs), 0);
  ASSERT_EQ (SocketQUICHandshake_can_receive_handshake (hs), 0);
  ASSERT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_HANDSHAKE]);
  ASSERT_EQ (hs->keys_available[QUIC_CRYPTO_LEVEL_HANDSHAKE], 0);

  /* State should be updated to CONFIRMED */
  ASSERT_EQ (hs->state, QUIC_HANDSHAKE_STATE_CONFIRMED);

  Arena_dispose (&arena);
}

/* Test: Server discards Handshake keys on confirmation */
TEST (key_discard_server_handshake_on_confirmed)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (hs);

  /* Initially Handshake keys should be available */
  ASSERT (SocketQUICHandshake_can_send_handshake (hs));
  ASSERT_EQ (hs->handshake_keys_discarded, 0);

  /* Simulate handshake confirmation */
  SocketQUICHandshake_on_confirmed (hs);

  /* Handshake keys should now be discarded */
  ASSERT_EQ (hs->handshake_keys_discarded, 1);
  ASSERT_EQ (SocketQUICHandshake_can_send_handshake (hs), 0);
  ASSERT_EQ (SocketQUICHandshake_can_receive_handshake (hs), 0);
  ASSERT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_HANDSHAKE]);
  ASSERT_EQ (hs->state, QUIC_HANDSHAKE_STATE_CONFIRMED);

  Arena_dispose (&arena);
}

/* ============================================================================
 * §4.9.3: 0-RTT Key Discard Tests
 * ============================================================================
 */

/* Test: Client discards 0-RTT keys when 1-RTT installed */
TEST (key_discard_client_0rtt_on_1rtt_installed)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Initially 0-RTT keys should be available */
  ASSERT_NOT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_0RTT]);
  ASSERT_EQ (hs->keys_available[QUIC_CRYPTO_LEVEL_0RTT], 1);
  ASSERT_EQ (hs->zero_rtt_keys_discarded, 0);

  /* Simulate 1-RTT keys being installed */
  SocketQUICHandshake_on_1rtt_keys_installed (hs);

  /* 0-RTT keys should now be discarded */
  ASSERT_EQ (hs->zero_rtt_keys_discarded, 1);
  ASSERT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_0RTT]);
  ASSERT_EQ (hs->keys_available[QUIC_CRYPTO_LEVEL_0RTT], 0);

  Arena_dispose (&arena);
}

/* Test: Server discards 0-RTT keys when 1-RTT packet received */
TEST (key_discard_server_0rtt_on_1rtt_received)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (hs);

  /* Initially 0-RTT keys should be available */
  ASSERT_NOT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_0RTT]);
  ASSERT_EQ (hs->zero_rtt_keys_discarded, 0);

  /* Simulate receiving 1-RTT packet */
  SocketQUICHandshake_on_1rtt_packet_received (hs);

  /* 0-RTT keys should now be discarded */
  ASSERT_EQ (hs->zero_rtt_keys_discarded, 1);
  ASSERT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_0RTT]);

  Arena_dispose (&arena);
}

/* Test: Client ignores 1rtt_packet_received (server-only trigger) */
TEST (key_discard_client_ignores_1rtt_received)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Call server trigger on client - should be no-op */
  SocketQUICHandshake_on_1rtt_packet_received (hs);

  /* 0-RTT keys should still be available */
  ASSERT_NOT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_0RTT]);
  ASSERT_EQ (hs->zero_rtt_keys_discarded, 0);

  Arena_dispose (&arena);
}

/* Test: Server ignores 1rtt_keys_installed (client-only trigger) */
TEST (key_discard_server_ignores_1rtt_installed)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (hs);

  /* Call client trigger on server - should be no-op */
  SocketQUICHandshake_on_1rtt_keys_installed (hs);

  /* 0-RTT keys should still be available */
  ASSERT_NOT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_0RTT]);
  ASSERT_EQ (hs->zero_rtt_keys_discarded, 0);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Idempotency Tests
 * ============================================================================
 */

/* Test: Multiple handshake_packet_sent calls are idempotent */
TEST (key_discard_handshake_sent_idempotent)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* First call should discard Initial keys */
  SocketQUICHandshake_on_handshake_packet_sent (hs);
  ASSERT_EQ (hs->initial_keys_discarded, 1);
  ASSERT_EQ (hs->first_handshake_sent, 1);

  /* Subsequent calls should be no-ops */
  SocketQUICHandshake_on_handshake_packet_sent (hs);
  SocketQUICHandshake_on_handshake_packet_sent (hs);
  SocketQUICHandshake_on_handshake_packet_sent (hs);

  /* State should remain unchanged */
  ASSERT_EQ (hs->initial_keys_discarded, 1);
  ASSERT_EQ (hs->first_handshake_sent, 1);

  Arena_dispose (&arena);
}

/* Test: Multiple on_confirmed calls are idempotent */
TEST (key_discard_confirmed_idempotent)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* First call should discard Handshake keys */
  SocketQUICHandshake_on_confirmed (hs);
  ASSERT_EQ (hs->handshake_keys_discarded, 1);
  ASSERT_EQ (hs->state, QUIC_HANDSHAKE_STATE_CONFIRMED);

  /* Subsequent calls should be no-ops */
  SocketQUICHandshake_on_confirmed (hs);
  SocketQUICHandshake_on_confirmed (hs);

  /* State should remain unchanged */
  ASSERT_EQ (hs->handshake_keys_discarded, 1);
  ASSERT_EQ (hs->state, QUIC_HANDSHAKE_STATE_CONFIRMED);

  Arena_dispose (&arena);
}

/* Test: Multiple 1rtt_keys_installed calls are idempotent */
TEST (key_discard_1rtt_installed_idempotent)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* First call should discard 0-RTT keys */
  SocketQUICHandshake_on_1rtt_keys_installed (hs);
  ASSERT_EQ (hs->zero_rtt_keys_discarded, 1);

  /* Subsequent calls should be no-ops */
  SocketQUICHandshake_on_1rtt_keys_installed (hs);
  SocketQUICHandshake_on_1rtt_keys_installed (hs);

  /* State should remain unchanged */
  ASSERT_EQ (hs->zero_rtt_keys_discarded, 1);

  Arena_dispose (&arena);
}

/* ============================================================================
 * NULL Pointer Safety Tests
 * ============================================================================
 */

/* Test: All trigger functions handle NULL safely */
TEST (key_discard_null_safety)
{
  /* All these should not crash */
  SocketQUICHandshake_on_handshake_packet_sent (NULL);
  SocketQUICHandshake_on_handshake_packet_received (NULL);
  SocketQUICHandshake_on_confirmed (NULL);
  SocketQUICHandshake_on_1rtt_keys_installed (NULL);
  SocketQUICHandshake_on_1rtt_packet_received (NULL);

  /* All availability checks should return 0 for NULL */
  ASSERT_EQ (SocketQUICHandshake_can_send_initial (NULL), 0);
  ASSERT_EQ (SocketQUICHandshake_can_receive_initial (NULL), 0);
  ASSERT_EQ (SocketQUICHandshake_can_send_handshake (NULL), 0);
  ASSERT_EQ (SocketQUICHandshake_can_receive_handshake (NULL), 0);
  ASSERT_EQ (SocketQUICHandshake_can_send_0rtt (NULL), 0);
  ASSERT_EQ (SocketQUICHandshake_can_receive_0rtt (NULL), 0);
}

/* ============================================================================
 * 0-RTT Availability Check Tests
 * ============================================================================
 */

/* Test: Client can send 0-RTT when keys available */
TEST (key_discard_client_can_send_0rtt)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Client should be able to send 0-RTT */
  ASSERT (SocketQUICHandshake_can_send_0rtt (hs));

  /* Client should NOT be able to receive 0-RTT (server-only) */
  ASSERT_EQ (SocketQUICHandshake_can_receive_0rtt (hs), 0);

  Arena_dispose (&arena);
}

/* Test: Server can receive 0-RTT when keys available */
TEST (key_discard_server_can_receive_0rtt)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (hs);

  /* Server should be able to receive 0-RTT */
  ASSERT (SocketQUICHandshake_can_receive_0rtt (hs));

  /* Server should NOT be able to send 0-RTT (client-only) */
  ASSERT_EQ (SocketQUICHandshake_can_send_0rtt (hs), 0);

  Arena_dispose (&arena);
}

/* Test: Client 0-RTT availability after discard */
TEST (key_discard_client_0rtt_availability_after_discard)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Initially can send 0-RTT */
  ASSERT (SocketQUICHandshake_can_send_0rtt (hs));

  /* After 1-RTT keys installed, 0-RTT discarded */
  SocketQUICHandshake_on_1rtt_keys_installed (hs);

  /* Now cannot send 0-RTT */
  ASSERT_EQ (SocketQUICHandshake_can_send_0rtt (hs), 0);

  Arena_dispose (&arena);
}

/* Test: Server 0-RTT availability after discard */
TEST (key_discard_server_0rtt_availability_after_discard)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (hs);

  /* Initially can receive 0-RTT */
  ASSERT (SocketQUICHandshake_can_receive_0rtt (hs));

  /* After 1-RTT packet received, 0-RTT discarded */
  SocketQUICHandshake_on_1rtt_packet_received (hs);

  /* Now cannot receive 0-RTT */
  ASSERT_EQ (SocketQUICHandshake_can_receive_0rtt (hs), 0);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Secure Memory Clearing Tests
 * ============================================================================
 */

/* Test: Verify key memory is zeroed after discard */
TEST (key_discard_secure_clear_verification)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Get pointer to key memory before discard */
  uint8_t *initial_key_ptr = (uint8_t *)hs->keys[QUIC_CRYPTO_LEVEL_INITIAL];
  ASSERT_NOT_NULL (initial_key_ptr);

  /* Verify key is filled with non-zero pattern (0xAA from
   * create_test_handshake)
   */
  int has_nonzero = 0;
  for (size_t i = 0; i < QUIC_MAX_KEY_MATERIAL_SIZE; i++)
    {
      if (initial_key_ptr[i] != 0)
        {
          has_nonzero = 1;
          break;
        }
    }
  ASSERT (has_nonzero);

  /* Discard Initial keys */
  SocketQUICHandshake_on_handshake_packet_sent (hs);

  /* Pointer should now be NULL */
  ASSERT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_INITIAL]);

  /* The original memory location should be zeroed by SocketCrypto_secure_clear.
   * Note: We still have access to initial_key_ptr (the raw pointer to arena
   * memory). After secure_clear, this memory should contain zeros.
   */
  int all_zero = 1;
  for (size_t i = 0; i < QUIC_MAX_KEY_MATERIAL_SIZE; i++)
    {
      if (initial_key_ptr[i] != 0)
        {
          all_zero = 0;
          break;
        }
    }
  ASSERT (all_zero);

  Arena_dispose (&arena);
}

/* Test: Verify Handshake key memory is zeroed after confirmation */
TEST (key_discard_secure_clear_handshake)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Get pointer to Handshake key memory */
  uint8_t *handshake_key_ptr = (uint8_t *)hs->keys[QUIC_CRYPTO_LEVEL_HANDSHAKE];
  ASSERT_NOT_NULL (handshake_key_ptr);

  /* Verify initial non-zero content */
  ASSERT_EQ (handshake_key_ptr[0], 0xAA);

  /* Discard via confirmation */
  SocketQUICHandshake_on_confirmed (hs);

  /* Memory should be zeroed */
  int all_zero = 1;
  for (size_t i = 0; i < QUIC_MAX_KEY_MATERIAL_SIZE; i++)
    {
      if (handshake_key_ptr[i] != 0)
        {
          all_zero = 0;
          break;
        }
    }
  ASSERT (all_zero);

  Arena_dispose (&arena);
}

/* Test: Verify 0-RTT key memory is zeroed after 1-RTT installed */
TEST (key_discard_secure_clear_0rtt)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Get pointer to 0-RTT key memory */
  uint8_t *zero_rtt_key_ptr = (uint8_t *)hs->keys[QUIC_CRYPTO_LEVEL_0RTT];
  ASSERT_NOT_NULL (zero_rtt_key_ptr);

  /* Verify initial non-zero content */
  ASSERT_EQ (zero_rtt_key_ptr[0], 0xAA);

  /* Discard via 1-RTT keys installed */
  SocketQUICHandshake_on_1rtt_keys_installed (hs);

  /* Memory should be zeroed */
  int all_zero = 1;
  for (size_t i = 0; i < QUIC_MAX_KEY_MATERIAL_SIZE; i++)
    {
      if (zero_rtt_key_ptr[i] != 0)
        {
          all_zero = 0;
          break;
        }
    }
  ASSERT (all_zero);

  Arena_dispose (&arena);
}

/* ============================================================================
 * General Availability Check Tests
 * ============================================================================
 */

/* Test: Availability checks return 0 when keys not available */
TEST (key_discard_availability_no_keys)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  /* Create handshake without setting up mock keys */
  SocketQUICHandshake_T hs
      = SocketQUICHandshake_new (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Keys are not available, so checks should return 0 */
  ASSERT_EQ (SocketQUICHandshake_can_send_initial (hs), 0);
  ASSERT_EQ (SocketQUICHandshake_can_receive_initial (hs), 0);
  ASSERT_EQ (SocketQUICHandshake_can_send_handshake (hs), 0);
  ASSERT_EQ (SocketQUICHandshake_can_receive_handshake (hs), 0);
  ASSERT_EQ (SocketQUICHandshake_can_send_0rtt (hs), 0);

  Arena_dispose (&arena);
}

/* Test: Server availability checks return 0 when keys not available */
TEST (key_discard_server_availability_no_keys)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (conn);

  /* Create handshake without setting up mock keys */
  SocketQUICHandshake_T hs
      = SocketQUICHandshake_new (arena, conn, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (hs);

  /* Keys are not available, so checks should return 0 */
  ASSERT_EQ (SocketQUICHandshake_can_send_initial (hs), 0);
  ASSERT_EQ (SocketQUICHandshake_can_receive_initial (hs), 0);
  ASSERT_EQ (SocketQUICHandshake_can_send_handshake (hs), 0);
  ASSERT_EQ (SocketQUICHandshake_can_receive_handshake (hs), 0);
  ASSERT_EQ (SocketQUICHandshake_can_receive_0rtt (hs), 0);

  Arena_dispose (&arena);
}

/* Test: Availability checks after discard return 0 even if keys_available set
 */
TEST (key_discard_availability_after_discard)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Both keys available and discard flag unset - can send/receive */
  ASSERT (SocketQUICHandshake_can_send_initial (hs));
  ASSERT (SocketQUICHandshake_can_receive_initial (hs));

  /* Discard Initial keys */
  SocketQUICHandshake_on_handshake_packet_sent (hs);

  /* Now cannot send/receive Initial */
  ASSERT_EQ (SocketQUICHandshake_can_send_initial (hs), 0);
  ASSERT_EQ (SocketQUICHandshake_can_receive_initial (hs), 0);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Complete Handshake Flow Test
 * ============================================================================
 */

/* Test: Full client handshake key lifecycle */
TEST (key_discard_full_client_flow)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Phase 1: All keys available initially */
  ASSERT (SocketQUICHandshake_can_send_initial (hs));
  ASSERT (SocketQUICHandshake_can_send_handshake (hs));
  ASSERT_NOT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_0RTT]);

  /* Phase 2: Client sends first Handshake - discard Initial keys */
  SocketQUICHandshake_on_handshake_packet_sent (hs);
  ASSERT_EQ (SocketQUICHandshake_can_send_initial (hs), 0);
  ASSERT (SocketQUICHandshake_can_send_handshake (hs)); /* Still have Handshake
                                                         */

  /* Phase 3: 1-RTT keys installed - discard 0-RTT keys */
  SocketQUICHandshake_on_1rtt_keys_installed (hs);
  ASSERT_EQ (hs->zero_rtt_keys_discarded, 1);
  ASSERT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_0RTT]);

  /* Phase 4: Handshake confirmed - discard Handshake keys */
  SocketQUICHandshake_on_confirmed (hs);
  ASSERT_EQ (SocketQUICHandshake_can_send_handshake (hs), 0);
  ASSERT_EQ (hs->state, QUIC_HANDSHAKE_STATE_CONFIRMED);

  /* Phase 5: Only Application (1-RTT) keys remain */
  ASSERT_NOT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_APPLICATION]);
  ASSERT_EQ (hs->keys_available[QUIC_CRYPTO_LEVEL_APPLICATION], 1);

  Arena_dispose (&arena);
}

/* Test: Full server handshake key lifecycle */
TEST (key_discard_full_server_flow)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (hs);

  /* Phase 1: All keys available initially */
  ASSERT (SocketQUICHandshake_can_send_initial (hs));
  ASSERT (SocketQUICHandshake_can_send_handshake (hs));
  ASSERT_NOT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_0RTT]);

  /* Phase 2: Server receives first Handshake - discard Initial keys */
  SocketQUICHandshake_on_handshake_packet_received (hs);
  ASSERT_EQ (SocketQUICHandshake_can_send_initial (hs), 0);
  ASSERT (SocketQUICHandshake_can_send_handshake (hs));

  /* Phase 3: Server receives 1-RTT packet - discard 0-RTT keys */
  SocketQUICHandshake_on_1rtt_packet_received (hs);
  ASSERT_EQ (hs->zero_rtt_keys_discarded, 1);
  ASSERT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_0RTT]);

  /* Phase 4: Handshake confirmed - discard Handshake keys */
  SocketQUICHandshake_on_confirmed (hs);
  ASSERT_EQ (SocketQUICHandshake_can_send_handshake (hs), 0);
  ASSERT_EQ (hs->state, QUIC_HANDSHAKE_STATE_CONFIRMED);

  /* Phase 5: Only Application (1-RTT) keys remain */
  ASSERT_NOT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_APPLICATION]);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Direct discard_keys Tests
 * ============================================================================
 */

/* Test: Direct discard_keys handles NULL safely */
TEST (key_discard_direct_null_safety)
{
  /* Should not crash */
  SocketQUICHandshake_discard_keys (NULL, QUIC_CRYPTO_LEVEL_INITIAL);
}

/* Test: Direct discard_keys handles invalid level */
TEST (key_discard_direct_invalid_level)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  SocketQUICHandshake_T hs
      = create_test_handshake (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Invalid level should be handled safely */
  SocketQUICHandshake_discard_keys (hs, QUIC_CRYPTO_LEVEL_COUNT);
  SocketQUICHandshake_discard_keys (hs, (SocketQUICCryptoLevel)99);

  /* Valid keys should still be available */
  ASSERT_NOT_NULL (hs->keys[QUIC_CRYPTO_LEVEL_INITIAL]);

  Arena_dispose (&arena);
}

/* Test: Direct discard_keys handles already NULL keys */
TEST (key_discard_direct_already_null)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (conn);

  /* Create handshake without mock keys (keys are NULL) */
  SocketQUICHandshake_T hs
      = SocketQUICHandshake_new (arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL (hs);

  /* Discarding NULL keys should not crash */
  SocketQUICHandshake_discard_keys (hs, QUIC_CRYPTO_LEVEL_INITIAL);
  SocketQUICHandshake_discard_keys (hs, QUIC_CRYPTO_LEVEL_HANDSHAKE);
  SocketQUICHandshake_discard_keys (hs, QUIC_CRYPTO_LEVEL_0RTT);
  SocketQUICHandshake_discard_keys (hs, QUIC_CRYPTO_LEVEL_APPLICATION);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

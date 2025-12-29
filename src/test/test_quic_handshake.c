/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_handshake.c
 * @brief Unit tests for QUIC handshake operations.
 */

#include <string.h>

#include "test/Test.h"
#include "core/Arena.h"
#include "quic/SocketQUICHandshake.h"
#include "quic/SocketQUICConnection.h"
#include "quic/SocketQUICConnectionID.h"

/**
 * @brief Test basic handshake creation and initialization.
 */
TEST(handshake_new)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(conn);

  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(hs);
  ASSERT_EQ(hs->arena, arena);
  ASSERT_EQ(hs->conn, conn);
  ASSERT_EQ(hs->role, QUIC_CONN_ROLE_CLIENT);
  ASSERT_EQ(hs->state, QUIC_HANDSHAKE_STATE_IDLE);

  SocketQUICHandshake_free(&hs);
  ASSERT_NULL(hs);

  Arena_dispose(&arena);
}

/**
 * @brief Test send_initial for client role.
 */
TEST(send_initial_client)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(conn);

  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(hs);

  /* Attach handshake to connection */
  conn->handshake = hs;

  /* Initialize connection with a valid DCID */
  SocketQUICConnectionID_T dcid;
  SocketQUICConnectionID_generate(&dcid, 8);
  conn->initial_dcid = dcid;

  /* Call send_initial - should succeed for client */
  SocketQUICHandshake_Result result = SocketQUICHandshake_send_initial(conn);
  ASSERT_EQ(result, QUIC_HANDSHAKE_OK);

  /* Verify state transitioned to INITIAL */
  ASSERT_EQ(hs->state, QUIC_HANDSHAKE_STATE_INITIAL);

  /* Verify Initial keys are marked as available */
  ASSERT_EQ(hs->keys_available[QUIC_CRYPTO_LEVEL_INITIAL], 1);

  SocketQUICHandshake_free(&hs);
  Arena_dispose(&arena);
}

/**
 * @brief Test send_initial rejects server role.
 */
TEST(send_initial_server_rejects)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL(conn);

  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL(hs);

  conn->handshake = hs;

  /* Server should not send Initial packets - this should fail */
  SocketQUICHandshake_Result result = SocketQUICHandshake_send_initial(conn);
  ASSERT_EQ(result, QUIC_HANDSHAKE_ERROR_STATE);

  SocketQUICHandshake_free(&hs);
  Arena_dispose(&arena);
}

/**
 * @brief Test send_initial with NULL connection.
 */
TEST(send_initial_null_conn)
{
  SocketQUICHandshake_Result result = SocketQUICHandshake_send_initial(NULL);
  ASSERT_EQ(result, QUIC_HANDSHAKE_ERROR_NULL);
}

/**
 * @brief Test send_initial with connection missing handshake context.
 */
TEST(send_initial_no_handshake)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT_NOT_NULL(conn);

  /* Don't attach handshake - should fail */
  conn->handshake = NULL;

  SocketQUICHandshake_Result result = SocketQUICHandshake_send_initial(conn);
  ASSERT_EQ(result, QUIC_HANDSHAKE_ERROR_STATE);

  Arena_dispose(&arena);
}

/**
 * @brief Test handshake state query functions.
 */
TEST(handshake_state_queries)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T hs = SocketQUICHandshake_new(arena, conn, QUIC_CONN_ROLE_CLIENT);

  ASSERT_EQ(hs->state, QUIC_HANDSHAKE_STATE_IDLE);
  ASSERT_EQ(SocketQUICHandshake_is_complete(hs), 0);
  ASSERT_EQ(SocketQUICHandshake_is_confirmed(hs), 0);

  /* Manually set state to complete */
  hs->state = QUIC_HANDSHAKE_STATE_COMPLETE;
  ASSERT_NE(SocketQUICHandshake_is_complete(hs), 0);
  ASSERT_EQ(SocketQUICHandshake_is_confirmed(hs), 0);

  /* Manually set state to confirmed */
  hs->state = QUIC_HANDSHAKE_STATE_CONFIRMED;
  ASSERT_NE(SocketQUICHandshake_is_complete(hs), 0);
  ASSERT_NE(SocketQUICHandshake_is_confirmed(hs), 0);

  SocketQUICHandshake_free(&hs);
  Arena_dispose(&arena);
}

/**
 * @brief Test utility string functions.
 */
TEST(handshake_strings)
{
  const char *level_str = SocketQUICHandshake_crypto_level_string(QUIC_CRYPTO_LEVEL_INITIAL);
  ASSERT(strcmp(level_str, "Initial") == 0);

  const char *state_str = SocketQUICHandshake_state_string(QUIC_HANDSHAKE_STATE_IDLE);
  ASSERT(strcmp(state_str, "Idle") == 0);

  const char *result_str = SocketQUICHandshake_result_string(QUIC_HANDSHAKE_OK);
  ASSERT(strcmp(result_str, "OK") == 0);
}

int
main(void)
{
  Test_run_all();
  return Test_get_failures();
}

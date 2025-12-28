/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_termination.c
 * @brief Test QUIC Connection Termination (RFC 9000 Section 10).
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "core/Arena.h"
#include "quic/SocketQUICConnection.h"

#define TEST_PTO_MS 100

static void
test_idle_timeout_disabled(void)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);

  /* Both sides set timeout to 0 (disabled) */
  SocketQUICConnection_set_idle_timeout(conn, 0, 0);
  assert(conn->idle_timeout_deadline_ms == 0);

  /* Reset timer should not set deadline */
  SocketQUICConnection_reset_idle_timer(conn, 1000);
  assert(conn->idle_timeout_deadline_ms == 0);

  /* Should never timeout */
  assert(SocketQUICConnection_check_idle_timeout(conn, 999999) == 0);

  Arena_dispose(&arena);
  printf("test_idle_timeout_disabled: PASS\n");
}

static void
test_idle_timeout_min_calculation(void)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_SERVER);

  /* Local timeout is 30000ms, peer is 60000ms */
  /* Effective timeout should be min = 30000ms */
  SocketQUICConnection_set_idle_timeout(conn, 30000, 60000);

  assert(conn->local_max_idle_timeout_ms == 30000);
  assert(conn->peer_max_idle_timeout_ms == 60000);
  assert(conn->idle_timeout_deadline_ms == 30000);

  /* Reset at time 1000ms */
  SocketQUICConnection_reset_idle_timer(conn, 1000);

  /* Deadline should be 1000 + 30000 = 31000 */
  assert(conn->idle_timeout_deadline_ms == 31000);

  /* Should not timeout before deadline */
  assert(SocketQUICConnection_check_idle_timeout(conn, 30999) == 0);

  /* Should timeout at deadline */
  assert(SocketQUICConnection_check_idle_timeout(conn, 31000) == 1);

  /* Should timeout after deadline */
  assert(SocketQUICConnection_check_idle_timeout(conn, 35000) == 1);

  Arena_dispose(&arena);
  printf("test_idle_timeout_min_calculation: PASS\n");
}

static void
test_idle_timer_reset_on_activity(void)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);

  SocketQUICConnection_set_idle_timeout(conn, 5000, 5000);
  SocketQUICConnection_reset_idle_timer(conn, 1000);

  /* Deadline at 1000 + 5000 = 6000 */
  assert(conn->idle_timeout_deadline_ms == 6000);

  /* Reset timer at 3000ms (before timeout) */
  SocketQUICConnection_reset_idle_timer(conn, 3000);

  /* New deadline should be 3000 + 5000 = 8000 */
  assert(conn->idle_timeout_deadline_ms == 8000);

  /* Should not timeout at old deadline */
  assert(SocketQUICConnection_check_idle_timeout(conn, 6000) == 0);

  /* Should timeout at new deadline */
  assert(SocketQUICConnection_check_idle_timeout(conn, 8000) == 1);

  Arena_dispose(&arena);
  printf("test_idle_timer_reset_on_activity: PASS\n");
}

static void
test_immediate_close_transitions(void)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_SERVER);

  /* Start in IDLE state */
  assert(conn->state == QUIC_CONN_STATE_IDLE);

  /* Initiate close with error code 0x00 (NO_ERROR) */
  SocketQUICConnection_initiate_close(conn, 0x00, 1000, TEST_PTO_MS);

  /* Should transition to CLOSING */
  assert(conn->state == QUIC_CONN_STATE_CLOSING);

  /* Closing deadline should be 1000 + 3*100 = 1300 */
  assert(conn->closing_deadline_ms == 1300);

  /* Should not be closed before deadline */
  assert(SocketQUICConnection_check_termination_deadline(conn, 1299) == 0);
  assert(conn->state == QUIC_CONN_STATE_CLOSING);

  /* Should close at deadline */
  assert(SocketQUICConnection_check_termination_deadline(conn, 1300) == 1);
  assert(conn->state == QUIC_CONN_STATE_CLOSED);

  Arena_dispose(&arena);
  printf("test_immediate_close_transitions: PASS\n");
}

static void
test_draining_state_transitions(void)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);

  conn->state = QUIC_CONN_STATE_ESTABLISHED;

  /* Receive CONNECTION_CLOSE, enter draining */
  SocketQUICConnection_enter_draining(conn, 2000, TEST_PTO_MS);

  /* Should transition to DRAINING */
  assert(conn->state == QUIC_CONN_STATE_DRAINING);

  /* Draining deadline should be 2000 + 3*100 = 2300 */
  assert(conn->draining_deadline_ms == 2300);

  /* Should not be closed before deadline */
  assert(SocketQUICConnection_check_termination_deadline(conn, 2299) == 0);
  assert(conn->state == QUIC_CONN_STATE_DRAINING);

  /* Should close at deadline */
  assert(SocketQUICConnection_check_termination_deadline(conn, 2300) == 1);
  assert(conn->state == QUIC_CONN_STATE_CLOSED);

  Arena_dispose(&arena);
  printf("test_draining_state_transitions: PASS\n");
}

static void
test_closing_or_draining_check(void)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_SERVER);

  /* Active states should return 0 */
  conn->state = QUIC_CONN_STATE_IDLE;
  assert(SocketQUICConnection_is_closing_or_draining(conn) == 0);

  conn->state = QUIC_CONN_STATE_HANDSHAKE;
  assert(SocketQUICConnection_is_closing_or_draining(conn) == 0);

  conn->state = QUIC_CONN_STATE_ESTABLISHED;
  assert(SocketQUICConnection_is_closing_or_draining(conn) == 0);

  /* Closing/draining states should return 1 */
  conn->state = QUIC_CONN_STATE_CLOSING;
  assert(SocketQUICConnection_is_closing_or_draining(conn) == 1);

  conn->state = QUIC_CONN_STATE_DRAINING;
  assert(SocketQUICConnection_is_closing_or_draining(conn) == 1);

  /* Closed state should return 0 (no longer terminating) */
  conn->state = QUIC_CONN_STATE_CLOSED;
  assert(SocketQUICConnection_is_closing_or_draining(conn) == 0);

  Arena_dispose(&arena);
  printf("test_closing_or_draining_check: PASS\n");
}

static void
test_stateless_reset_token(void)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);

  /* Initially no token set */
  assert(conn->has_stateless_reset_token == 0);

  /* Set token */
  uint8_t token[16];
  for (int i = 0; i < 16; i++)
    token[i] = (uint8_t)i;

  SocketQUICConnection_set_stateless_reset_token(conn, token);

  /* Token should be set */
  assert(conn->has_stateless_reset_token == 1);
  assert(memcmp(conn->stateless_reset_token, token, 16) == 0);

  Arena_dispose(&arena);
  printf("test_stateless_reset_token: PASS\n");
}

static void
test_stateless_reset_verification(void)
{
  uint8_t token[16];
  for (int i = 0; i < 16; i++)
    token[i] = (uint8_t)(0xAA + i);

  /* Create packet with token at end (40 bytes total) */
  uint8_t packet[40];
  memset(packet, 0x42, 24); /* Random data */
  memcpy(packet + 24, token, 16); /* Token at end */

  /* Should verify correctly */
  assert(SocketQUICConnection_verify_stateless_reset(packet, 40, token) == 1);

  /* Wrong token should fail */
  uint8_t wrong_token[16];
  memset(wrong_token, 0xFF, 16);
  assert(SocketQUICConnection_verify_stateless_reset(packet, 40, wrong_token)
         == 0);

  /* Packet too short should fail (< 38 bytes) */
  assert(SocketQUICConnection_verify_stateless_reset(packet, 37, token) == 0);

  /* Null inputs should fail */
  assert(SocketQUICConnection_verify_stateless_reset(NULL, 40, token) == 0);
  assert(SocketQUICConnection_verify_stateless_reset(packet, 40, NULL) == 0);

  printf("test_stateless_reset_verification: PASS\n");
}

static void
test_overflow_protection(void)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_SERVER);

  /* Test normal addition (no overflow) */
  SocketQUICConnection_set_idle_timeout(conn, 200, 200);
  SocketQUICConnection_reset_idle_timer(conn, 100);
  /* Deadline should be 100 + 200 = 300 */
  assert(conn->idle_timeout_deadline_ms == 300);

  /* Test overflow protection: base + offset > UINT64_MAX */
  SocketQUICConnection_set_idle_timeout(conn, 100, 100);
  SocketQUICConnection_reset_idle_timer(conn, UINT64_MAX - 50);
  /* Should saturate to UINT64_MAX, not wrap around */
  assert(conn->idle_timeout_deadline_ms == UINT64_MAX);

  /* Test edge case: UINT64_MAX + any value */
  SocketQUICConnection_set_idle_timeout(conn, 1, 1);
  SocketQUICConnection_reset_idle_timer(conn, UINT64_MAX);
  assert(conn->idle_timeout_deadline_ms == UINT64_MAX);

  /* Test closing deadline overflow */
  uint64_t near_max = UINT64_MAX - 100;
  SocketQUICConnection_initiate_close(conn, 0, near_max, 1000);
  assert(conn->closing_deadline_ms == UINT64_MAX);

  /* Test draining deadline overflow */
  Arena_T arena2 = Arena_new();
  SocketQUICConnection_T conn2
      = SocketQUICConnection_new(arena2, QUIC_CONN_ROLE_CLIENT);
  SocketQUICConnection_enter_draining(conn2, near_max, 1000);
  assert(conn2->draining_deadline_ms == UINT64_MAX);

  Arena_dispose(&arena);
  Arena_dispose(&arena2);
  printf("test_overflow_protection: PASS\n");
}

static void
test_no_double_transition(void)
{
  Arena_T arena = Arena_new();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new(arena, QUIC_CONN_ROLE_CLIENT);

  /* Enter closing state */
  SocketQUICConnection_initiate_close(conn, 0, 1000, TEST_PTO_MS);
  assert(conn->state == QUIC_CONN_STATE_CLOSING);
  uint64_t first_deadline = conn->closing_deadline_ms;

  /* Attempt to close again should not change deadline */
  SocketQUICConnection_initiate_close(conn, 1, 2000, TEST_PTO_MS);
  assert(conn->state == QUIC_CONN_STATE_CLOSING);
  assert(conn->closing_deadline_ms == first_deadline);

  /* Same for draining */
  Arena_T arena2 = Arena_new();
  SocketQUICConnection_T conn2
      = SocketQUICConnection_new(arena2, QUIC_CONN_ROLE_SERVER);

  SocketQUICConnection_enter_draining(conn2, 1000, TEST_PTO_MS);
  assert(conn2->state == QUIC_CONN_STATE_DRAINING);
  uint64_t first_drain = conn2->draining_deadline_ms;

  SocketQUICConnection_enter_draining(conn2, 2000, TEST_PTO_MS);
  assert(conn2->draining_deadline_ms == first_drain);

  Arena_dispose(&arena);
  Arena_dispose(&arena2);
  printf("test_no_double_transition: PASS\n");
}

int
main(void)
{
  printf("Running QUIC Connection Termination tests...\n\n");

  test_idle_timeout_disabled();
  test_idle_timeout_min_calculation();
  test_idle_timer_reset_on_activity();
  test_immediate_close_transitions();
  test_draining_state_transitions();
  test_closing_or_draining_check();
  test_stateless_reset_token();
  test_stateless_reset_verification();
  test_overflow_protection();
  test_no_double_transition();

  printf("\nAll tests PASSED!\n");
  return 0;
}

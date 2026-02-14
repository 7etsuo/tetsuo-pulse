/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_loss.c
 * @brief Unit tests for QUIC Loss Detection (RFC 9002).
 */

#include "quic/SocketQUICLoss.h"
#include "core/Arena.h"
#include "test/Test.h"

#include <string.h>

/* ============================================================================
 * RTT Tests
 * ============================================================================
 */

TEST (loss_init_rtt)
{
  SocketQUICLossRTT_T rtt;

  SocketQUICLoss_init_rtt (&rtt);

  ASSERT_EQ (QUIC_LOSS_INITIAL_RTT_US, rtt.smoothed_rtt);
  ASSERT_EQ (QUIC_LOSS_INITIAL_RTT_US / 2, rtt.rtt_var);
  ASSERT_EQ (0, rtt.min_rtt);
  ASSERT_EQ (0, rtt.latest_rtt);
  ASSERT_EQ (0, rtt.has_sample);
}

TEST (loss_update_rtt_first)
{
  SocketQUICLossRTT_T rtt;

  SocketQUICLoss_init_rtt (&rtt);

  /* First sample: 100ms */
  SocketQUICLoss_update_rtt (&rtt, 100000, 0, 0);

  ASSERT_EQ (100000, rtt.latest_rtt);
  ASSERT_EQ (100000, rtt.smoothed_rtt);
  ASSERT_EQ (50000, rtt.rtt_var); /* rtt_var = latest_rtt / 2 */
  ASSERT_EQ (100000, rtt.min_rtt);
  ASSERT (rtt.has_sample);
}

TEST (loss_update_rtt_subsequent)
{
  SocketQUICLossRTT_T rtt;

  SocketQUICLoss_init_rtt (&rtt);

  /* First sample: 100ms */
  SocketQUICLoss_update_rtt (&rtt, 100000, 0, 0);

  /* Second sample: 120ms */
  SocketQUICLoss_update_rtt (&rtt, 120000, 0, 0);

  ASSERT_EQ (120000, rtt.latest_rtt);
  ASSERT_EQ (100000, rtt.min_rtt); /* min unchanged */
  /* smoothed_rtt = 7/8 * 100000 + 1/8 * 120000 = 87500 + 15000 = 102500 */
  ASSERT (rtt.smoothed_rtt > 100000);
  ASSERT (rtt.smoothed_rtt < 120000);
}

TEST (loss_update_rtt_with_ack_delay)
{
  SocketQUICLossRTT_T rtt;

  SocketQUICLoss_init_rtt (&rtt);

  /* First sample */
  SocketQUICLoss_update_rtt (&rtt, 100000, 0, 0);

  /* Sample with ack_delay (for non-handshake) */
  SocketQUICLoss_update_rtt (&rtt, 130000, 10000, 0);

  /* ack_delay should be subtracted (but not below min_rtt) */
  ASSERT_EQ (130000, rtt.latest_rtt);
}

TEST (loss_update_rtt_min_update)
{
  SocketQUICLossRTT_T rtt;

  SocketQUICLoss_init_rtt (&rtt);

  SocketQUICLoss_update_rtt (&rtt, 100000, 0, 0);
  ASSERT_EQ (100000, rtt.min_rtt);

  SocketQUICLoss_update_rtt (&rtt, 80000, 0, 0);
  ASSERT_EQ (80000, rtt.min_rtt);

  SocketQUICLoss_update_rtt (&rtt, 90000, 0, 0);
  ASSERT_EQ (80000, rtt.min_rtt); /* Still 80000 */
}

/* ============================================================================
 * PTO Calculation Tests
 * ============================================================================
 */

TEST (loss_get_pto_initial)
{
  SocketQUICLossRTT_T rtt;
  uint64_t pto;

  SocketQUICLoss_init_rtt (&rtt);

  /* PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay */
  /* With initial values and no ack_delay:
   * PTO = 333000 + max(4*166500, 1000) + 0 = 333000 + 666000 = 999000 */
  pto = SocketQUICLoss_get_pto (&rtt, 0, 0);
  ASSERT_EQ (999000, pto);
}

TEST (loss_get_pto_with_ack_delay)
{
  SocketQUICLossRTT_T rtt;
  uint64_t pto;

  SocketQUICLoss_init_rtt (&rtt);

  /* With max_ack_delay = 25000 (25ms) */
  pto = SocketQUICLoss_get_pto (&rtt, 25000, 0);
  ASSERT_EQ (999000 + 25000, pto);
}

TEST (loss_get_pto_backoff)
{
  SocketQUICLossRTT_T rtt;
  uint64_t pto0, pto1, pto2;

  SocketQUICLoss_init_rtt (&rtt);

  pto0 = SocketQUICLoss_get_pto (&rtt, 0, 0);
  pto1 = SocketQUICLoss_get_pto (&rtt, 0, 1);
  pto2 = SocketQUICLoss_get_pto (&rtt, 0, 2);

  /* PTO should double with each pto_count */
  ASSERT_EQ (pto0 * 2, pto1);
  ASSERT_EQ (pto0 * 4, pto2);
}

TEST (loss_get_pto_max_backoff)
{
  SocketQUICLossRTT_T rtt;
  uint64_t pto_max, pto_over;

  SocketQUICLoss_init_rtt (&rtt);

  /* At max PTO count */
  pto_max = SocketQUICLoss_get_pto (&rtt, 0, QUIC_LOSS_MAX_PTO_COUNT);
  pto_over = SocketQUICLoss_get_pto (&rtt, 0, QUIC_LOSS_MAX_PTO_COUNT + 1);

  /* Should cap at max */
  ASSERT_EQ (pto_max, pto_over);
}

/* ============================================================================
 * Lifecycle Tests
 * ============================================================================
 */

TEST (loss_new)
{
  Arena_T arena;
  SocketQUICLossState_T state;

  arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  state = SocketQUICLoss_new (arena, 0, 25000);
  ASSERT_NOT_NULL (state);

  ASSERT_EQ (0, state->sent_count);
  ASSERT_EQ (0, state->bytes_in_flight);
  ASSERT_EQ (0, state->is_handshake_space);
  ASSERT_EQ (25000, state->max_ack_delay_us);

  Arena_dispose (&arena);
}

TEST (loss_new_handshake)
{
  Arena_T arena;
  SocketQUICLossState_T state;

  arena = Arena_new ();
  state = SocketQUICLoss_new (arena, 1, 0);
  ASSERT_NOT_NULL (state);

  ASSERT_EQ (1, state->is_handshake_space);

  Arena_dispose (&arena);
}

TEST (loss_new_null_arena)
{
  SocketQUICLossState_T state;

  state = SocketQUICLoss_new (NULL, 0, 0);
  ASSERT_NULL (state);
}

TEST (loss_reset)
{
  Arena_T arena;
  SocketQUICLossState_T state;

  arena = Arena_new ();
  state = SocketQUICLoss_new (arena, 0, 25000);

  /* Record a packet */
  SocketQUICLoss_on_packet_sent (state, 0, 1000000, 100, 1, 1, 0);
  ASSERT_EQ (1, state->sent_count);
  ASSERT_EQ (100, state->bytes_in_flight);

  /* Reset */
  SocketQUICLoss_reset (state);
  ASSERT_EQ (0, state->sent_count);
  ASSERT_EQ (0, state->bytes_in_flight);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Packet Sent Tests
 * ============================================================================
 */

TEST (loss_on_packet_sent)
{
  Arena_T arena;
  SocketQUICLossState_T state;
  SocketQUICLoss_Result res;

  arena = Arena_new ();
  state = SocketQUICLoss_new (arena, 0, 0);

  res = SocketQUICLoss_on_packet_sent (state, 0, 1000000, 100, 1, 1, 0);
  ASSERT_EQ (QUIC_LOSS_OK, res);

  ASSERT_EQ (1, state->sent_count);
  ASSERT_EQ (100, state->bytes_in_flight);
  ASSERT_EQ (0, state->largest_sent);

  Arena_dispose (&arena);
}

TEST (loss_on_packet_sent_multiple)
{
  Arena_T arena;
  SocketQUICLossState_T state;

  arena = Arena_new ();
  state = SocketQUICLoss_new (arena, 0, 0);

  SocketQUICLoss_on_packet_sent (state, 0, 1000000, 100, 1, 1, 0);
  SocketQUICLoss_on_packet_sent (state, 1, 1001000, 200, 1, 1, 0);
  SocketQUICLoss_on_packet_sent (state, 2, 1002000, 150, 0, 1, 0);

  ASSERT_EQ (3, state->sent_count);
  ASSERT_EQ (450, state->bytes_in_flight);
  ASSERT_EQ (2, state->largest_sent);

  Arena_dispose (&arena);
}

TEST (loss_on_packet_sent_null)
{
  SocketQUICLoss_Result res;

  res = SocketQUICLoss_on_packet_sent (NULL, 0, 1000000, 100, 1, 1, 0);
  ASSERT_EQ (QUIC_LOSS_ERROR_NULL, res);
}

TEST (loss_on_packet_sent_duplicate)
{
  Arena_T arena;
  SocketQUICLossState_T state;
  SocketQUICLoss_Result res;

  arena = Arena_new ();
  state = SocketQUICLoss_new (arena, 0, 0);

  res = SocketQUICLoss_on_packet_sent (state, 5, 1000000, 100, 1, 1, 0);
  ASSERT_EQ (QUIC_LOSS_OK, res);

  res = SocketQUICLoss_on_packet_sent (state, 5, 1001000, 200, 1, 1, 0);
  ASSERT_EQ (QUIC_LOSS_ERROR_DUPLICATE, res);

  Arena_dispose (&arena);
}

TEST (loss_on_packet_sent_not_in_flight)
{
  Arena_T arena;
  SocketQUICLossState_T state;

  arena = Arena_new ();
  state = SocketQUICLoss_new (arena, 0, 0);

  /* ACK-only packet: not in_flight */
  SocketQUICLoss_on_packet_sent (state, 0, 1000000, 50, 0, 0, 0);

  ASSERT_EQ (1, state->sent_count);
  ASSERT_EQ (0, state->bytes_in_flight); /* ACK-only doesn't count */

  Arena_dispose (&arena);
}

/* ============================================================================
 * ACK Processing Tests
 * ============================================================================
 */

static int lost_callback_count;
static uint64_t last_lost_pn;

static void
test_lost_callback (const SocketQUICLossSentPacket_T *packet, void *context)
{
  (void)context;
  lost_callback_count++;
  last_lost_pn = packet->packet_number;
}

TEST (loss_on_ack_received)
{
  Arena_T arena;
  SocketQUICLossState_T state;
  SocketQUICLossRTT_T rtt;
  SocketQUICLoss_Result res;
  size_t acked_count;
  size_t lost_count;

  arena = Arena_new ();
  state = SocketQUICLoss_new (arena, 0, 0);
  SocketQUICLoss_init_rtt (&rtt);

  /* Send packets */
  SocketQUICLoss_on_packet_sent (state, 0, 1000000, 100, 1, 1, 0);

  /* ACK packet 0 */
  SocketQUICFrameAck_T ack;
  memset (&ack, 0, sizeof (ack));
  ack.largest_ack = 0;
  ack.ack_delay = 1000;
  ack.first_range = 0;

  res = SocketQUICLoss_on_ack_received (
      state, &rtt, &ack, 1100000, NULL, NULL, NULL, &acked_count, &lost_count);
  ASSERT_EQ (QUIC_LOSS_OK, res);
  ASSERT_EQ (0, lost_count);
  ASSERT_EQ (1, acked_count);
  ASSERT_EQ (0, state->bytes_in_flight); /* Packet was acked */

  Arena_dispose (&arena);
}

TEST (loss_on_ack_received_null)
{
  SocketQUICLossRTT_T rtt;
  SocketQUICLoss_Result res;

  SocketQUICLoss_init_rtt (&rtt);

  SocketQUICFrameAck_T ack;
  memset (&ack, 0, sizeof (ack));

  res = SocketQUICLoss_on_ack_received (
      NULL, &rtt, &ack, 1000000, NULL, NULL, NULL, NULL, NULL);
  ASSERT_EQ (QUIC_LOSS_ERROR_NULL, res);
}

TEST (loss_on_ack_received_invalid_largest_ack)
{
  Arena_T arena;
  SocketQUICLossState_T state;
  SocketQUICLossRTT_T rtt;
  SocketQUICLoss_Result res;
  size_t acked_count = 123;
  size_t lost_count = 123;

  arena = Arena_new ();
  state = SocketQUICLoss_new (arena, 0, 0);
  SocketQUICLoss_init_rtt (&rtt);

  /* Track one sent packet: pn=0 */
  SocketQUICLoss_on_packet_sent (state, 0, 1000000, 100, 1, 1, 0);
  ASSERT_EQ (1, state->sent_count);

  /* Peer ACKs pn=1 which we never tracked as sent -> ignore */
  SocketQUICFrameAck_T ack;
  memset (&ack, 0, sizeof (ack));
  ack.largest_ack = 1;
  ack.ack_delay = 0;
  ack.first_range = 0;

  res = SocketQUICLoss_on_ack_received (state,
                                       &rtt,
                                       &ack,
                                       1100000,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &acked_count,
                                       &lost_count);
  ASSERT_EQ (QUIC_LOSS_OK, res);
  ASSERT_EQ (0, acked_count);
  ASSERT_EQ (0, lost_count);
  ASSERT_EQ (1, state->sent_count);
  ASSERT_EQ (100, state->bytes_in_flight);

  Arena_dispose (&arena);
}

TEST (loss_on_ack_packet_threshold)
{
  Arena_T arena;
  SocketQUICLossState_T state;
  SocketQUICLossRTT_T rtt;
  size_t lost_count;

  arena = Arena_new ();
  state = SocketQUICLoss_new (arena, 0, 0);
  SocketQUICLoss_init_rtt (&rtt);

  lost_callback_count = 0;
  last_lost_pn = UINT64_MAX;

  /* Send packets 0, 1, 2, 3 */
  for (uint64_t i = 0; i < 4; i++)
    SocketQUICLoss_on_packet_sent (state, i, 1000000 + i * 1000, 100, 1, 1, 0);

  /* ACK packet 3 only - packets 0 should be declared lost (threshold=3) */
  SocketQUICFrameAck_T ack;
  memset (&ack, 0, sizeof (ack));
  ack.largest_ack = 3;
  ack.ack_delay = 1000;
  ack.first_range = 0; /* Only ack packet 3 */

  SocketQUICLoss_on_ack_received (state,
                                  &rtt,
                                  &ack,
                                  1100000,
                                  NULL,
                                  test_lost_callback,
                                  NULL,
                                  NULL,
                                  &lost_count);

  /* Packet 0 should be declared lost (3 packets ahead) */
  ASSERT (lost_count >= 1);
  ASSERT (lost_callback_count >= 1);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Query Tests
 * ============================================================================
 */

TEST (loss_bytes_in_flight)
{
  Arena_T arena;
  SocketQUICLossState_T state;

  arena = Arena_new ();
  state = SocketQUICLoss_new (arena, 0, 0);

  ASSERT_EQ (0, SocketQUICLoss_bytes_in_flight (state));

  SocketQUICLoss_on_packet_sent (state, 0, 1000000, 100, 1, 1, 0);
  ASSERT_EQ (100, SocketQUICLoss_bytes_in_flight (state));

  SocketQUICLoss_on_packet_sent (state, 1, 1001000, 200, 1, 1, 0);
  ASSERT_EQ (300, SocketQUICLoss_bytes_in_flight (state));

  Arena_dispose (&arena);
}

TEST (loss_bytes_in_flight_null)
{
  ASSERT_EQ (0, SocketQUICLoss_bytes_in_flight (NULL));
}

TEST (loss_has_in_flight)
{
  Arena_T arena;
  SocketQUICLossState_T state;

  arena = Arena_new ();
  state = SocketQUICLoss_new (arena, 0, 0);

  ASSERT_EQ (0, SocketQUICLoss_has_in_flight (state));

  SocketQUICLoss_on_packet_sent (state, 0, 1000000, 100, 1, 1, 0);
  ASSERT (SocketQUICLoss_has_in_flight (state));

  Arena_dispose (&arena);
}

TEST (loss_has_in_flight_null)
{
  ASSERT_EQ (0, SocketQUICLoss_has_in_flight (NULL));
}

/* ============================================================================
 * Loss Time Tests
 * ============================================================================
 */

TEST (loss_get_loss_time_no_packets)
{
  Arena_T arena;
  SocketQUICLossState_T state;
  SocketQUICLossRTT_T rtt;
  uint64_t timeout;

  arena = Arena_new ();
  state = SocketQUICLoss_new (arena, 0, 0);
  SocketQUICLoss_init_rtt (&rtt);

  /* No packets in flight, no timeout */
  timeout = SocketQUICLoss_get_loss_time (state, &rtt, 0, 1000000);
  ASSERT_EQ (0, timeout);

  Arena_dispose (&arena);
}

TEST (loss_get_loss_time_with_packets)
{
  Arena_T arena;
  SocketQUICLossState_T state;
  SocketQUICLossRTT_T rtt;
  uint64_t timeout;

  arena = Arena_new ();
  state = SocketQUICLoss_new (arena, 0, 25000);
  SocketQUICLoss_init_rtt (&rtt);

  /* Send ack-eliciting packet */
  SocketQUICLoss_on_packet_sent (state, 0, 1000000, 100, 1, 1, 0);

  /* Should have PTO timeout */
  timeout = SocketQUICLoss_get_loss_time (state, &rtt, 0, 1000000);
  ASSERT (timeout > 1000000);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Loss Timeout Tests
 * ============================================================================
 */

TEST (loss_on_timeout_null)
{
  SocketQUICLossRTT_T rtt;
  SocketQUICLoss_Result res;

  SocketQUICLoss_init_rtt (&rtt);

  res = SocketQUICLoss_on_loss_timeout (NULL, &rtt, 1000000, NULL, NULL, NULL);
  ASSERT_EQ (QUIC_LOSS_ERROR_NULL, res);
}

TEST (loss_on_timeout_time_based)
{
  Arena_T arena;
  SocketQUICLossState_T state;
  SocketQUICLossRTT_T rtt;
  SocketQUICLoss_Result res;
  size_t lost_count;

  arena = Arena_new ();
  state = SocketQUICLoss_new (arena, 0, 0);
  SocketQUICLoss_init_rtt (&rtt);

  /* Set a known RTT */
  SocketQUICLoss_update_rtt (&rtt, 100000, 0, 0); /* 100ms */

  /* Send a packet */
  SocketQUICLoss_on_packet_sent (state, 0, 1000000, 100, 1, 1, 0);

  /* Set loss_time to trigger timeout */
  state->loss_time = 1100000;

  lost_callback_count = 0;

  /* Call timeout handler at time after loss_time */
  res = SocketQUICLoss_on_loss_timeout (
      state, &rtt, 1200000, test_lost_callback, NULL, &lost_count);
  ASSERT_EQ (QUIC_LOSS_OK, res);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Result String Test
 * ============================================================================
 */

TEST (loss_result_string)
{
  ASSERT (strcmp ("OK", SocketQUICLoss_result_string (QUIC_LOSS_OK)) == 0);
  ASSERT (strcmp ("NULL pointer argument",
                  SocketQUICLoss_result_string (QUIC_LOSS_ERROR_NULL))
          == 0);
  ASSERT (strcmp ("Unknown error", SocketQUICLoss_result_string (-1)) == 0);
}

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

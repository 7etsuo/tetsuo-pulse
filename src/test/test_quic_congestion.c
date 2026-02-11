/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_congestion.c
 * @brief Unit tests for QUIC NewReno Congestion Control (RFC 9002 §7).
 */

#include "quic/SocketQUICCongestion.h"
#include "quic/SocketQUICConstants.h"
#include "quic/SocketQUICLoss.h"
#include "core/Arena.h"
#include "test/Test.h"

#include <string.h>

/* ============================================================================
 * Initialization Tests
 * ============================================================================
 */

TEST (cc_init)
{
  Arena_T arena = Arena_new ();

  SocketQUICCongestion_T cc
      = SocketQUICCongestion_new (arena, QUIC_MAX_DATAGRAM_SIZE);
  ASSERT (cc != NULL);

  ASSERT_EQ (QUIC_INITIAL_CWND, SocketQUICCongestion_cwnd (cc));
  ASSERT_EQ (QUIC_MAX_CWND, SocketQUICCongestion_ssthresh (cc));
  ASSERT_EQ (QUIC_CC_SLOW_START, SocketQUICCongestion_phase (cc));

  Arena_dispose (&arena);
}

TEST (cc_init_null)
{
  SocketQUICCongestion_T cc = SocketQUICCongestion_new (NULL, 1200);
  ASSERT (cc == NULL);

  /* NULL cc should not crash */
  ASSERT_EQ (0, SocketQUICCongestion_cwnd (NULL));
  ASSERT_EQ (0, SocketQUICCongestion_ssthresh (NULL));
  ASSERT_EQ (QUIC_CC_SLOW_START, SocketQUICCongestion_phase (NULL));
}

/* ============================================================================
 * Sending Gate Tests
 * ============================================================================
 */

TEST (cc_can_send_under_cwnd)
{
  Arena_T arena = Arena_new ();

  SocketQUICCongestion_T cc
      = SocketQUICCongestion_new (arena, QUIC_MAX_DATAGRAM_SIZE);

  /* Initial cwnd = 12000. With 0 bytes in flight, should allow send. */
  ASSERT (SocketQUICCongestion_can_send (cc, 0, 1200));
  ASSERT (SocketQUICCongestion_can_send (cc, 10800, 1200));

  Arena_dispose (&arena);
}

TEST (cc_can_send_blocked)
{
  Arena_T arena = Arena_new ();

  SocketQUICCongestion_T cc
      = SocketQUICCongestion_new (arena, QUIC_MAX_DATAGRAM_SIZE);

  /* bytes_in_flight + packet_size > cwnd → blocked */
  ASSERT (!SocketQUICCongestion_can_send (cc, QUIC_INITIAL_CWND, 1));
  ASSERT (!SocketQUICCongestion_can_send (cc, 11000, 1200));

  /* NULL cc → allow (no CC = always allow) */
  ASSERT (SocketQUICCongestion_can_send (NULL, 999999, 1200));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Slow Start Tests
 * ============================================================================
 */

TEST (cc_slow_start_growth)
{
  Arena_T arena = Arena_new ();

  SocketQUICCongestion_T cc
      = SocketQUICCongestion_new (arena, QUIC_MAX_DATAGRAM_SIZE);

  size_t initial_cwnd = SocketQUICCongestion_cwnd (cc);
  ASSERT_EQ (QUIC_CC_SLOW_START, SocketQUICCongestion_phase (cc));

  /* ACK 1200 bytes — cwnd should increase by 1200 */
  SocketQUICCongestion_on_packets_acked (cc, 1200, 1000);
  ASSERT_EQ (initial_cwnd + 1200, SocketQUICCongestion_cwnd (cc));
  ASSERT_EQ (QUIC_CC_SLOW_START, SocketQUICCongestion_phase (cc));

  /* ACK another 2400 bytes */
  SocketQUICCongestion_on_packets_acked (cc, 2400, 2000);
  ASSERT_EQ (initial_cwnd + 1200 + 2400, SocketQUICCongestion_cwnd (cc));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Loss / Recovery Tests
 * ============================================================================
 */

TEST (cc_slow_start_exit_on_loss)
{
  Arena_T arena = Arena_new ();

  SocketQUICCongestion_T cc
      = SocketQUICCongestion_new (arena, QUIC_MAX_DATAGRAM_SIZE);

  /* Initial cwnd = 12000 */
  size_t cwnd_before = SocketQUICCongestion_cwnd (cc);

  /* Report loss — should enter recovery, halve cwnd */
  SocketQUICCongestion_on_packets_lost (cc, 1200, 500);

  ASSERT_EQ (QUIC_CC_RECOVERY, SocketQUICCongestion_phase (cc));

  /* cwnd should be cwnd_before / 2, but at least QUIC_MIN_CWND */
  size_t expected_cwnd = cwnd_before / 2;
  if (expected_cwnd < QUIC_MIN_CWND)
    expected_cwnd = QUIC_MIN_CWND;
  ASSERT_EQ (expected_cwnd, SocketQUICCongestion_cwnd (cc));
  ASSERT_EQ (expected_cwnd, SocketQUICCongestion_ssthresh (cc));

  Arena_dispose (&arena);
}

TEST (cc_recovery_no_cwnd_change)
{
  Arena_T arena = Arena_new ();

  SocketQUICCongestion_T cc
      = SocketQUICCongestion_new (arena, QUIC_MAX_DATAGRAM_SIZE);

  /* Enter recovery */
  SocketQUICCongestion_on_packets_lost (cc, 1200, 500);
  size_t cwnd_in_recovery = SocketQUICCongestion_cwnd (cc);
  ASSERT_EQ (QUIC_CC_RECOVERY, SocketQUICCongestion_phase (cc));

  /* Further losses during recovery (sent before recovery) don't reduce cwnd */
  SocketQUICCongestion_on_packets_lost (cc, 1200, 400);
  ASSERT_EQ (cwnd_in_recovery, SocketQUICCongestion_cwnd (cc));
  ASSERT_EQ (QUIC_CC_RECOVERY, SocketQUICCongestion_phase (cc));

  /* ACKs of pre-recovery packets don't grow cwnd */
  SocketQUICCongestion_on_packets_acked (cc, 1200, 300);
  ASSERT_EQ (cwnd_in_recovery, SocketQUICCongestion_cwnd (cc));

  Arena_dispose (&arena);
}

TEST (cc_recovery_exit)
{
  Arena_T arena = Arena_new ();

  SocketQUICCongestion_T cc
      = SocketQUICCongestion_new (arena, QUIC_MAX_DATAGRAM_SIZE);

  /* Enter recovery at time ~now */
  SocketQUICCongestion_on_packets_lost (cc, 1200, 500);
  ASSERT_EQ (QUIC_CC_RECOVERY, SocketQUICCongestion_phase (cc));
  size_t recovery_cwnd = SocketQUICCongestion_cwnd (cc);

  /* ACK of packet sent AFTER recovery start → exit to congestion avoidance */
  /* Use a very large time that is guaranteed to be after recovery_start */
  uint64_t future_sent_time = UINT64_MAX / 2;
  SocketQUICCongestion_on_packets_acked (cc, 1200, future_sent_time);

  ASSERT_EQ (QUIC_CC_CONGESTION_AVOID, SocketQUICCongestion_phase (cc));
  /* cwnd should have grown linearly from recovery_cwnd */
  ASSERT (SocketQUICCongestion_cwnd (cc) > recovery_cwnd);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Congestion Avoidance Tests
 * ============================================================================
 */

TEST (cc_congestion_avoidance_linear)
{
  Arena_T arena = Arena_new ();

  SocketQUICCongestion_T cc
      = SocketQUICCongestion_new (arena, QUIC_MAX_DATAGRAM_SIZE);

  /* Force into congestion avoidance: loss then ack of post-recovery packet */
  SocketQUICCongestion_on_packets_lost (cc, 1200, 100);
  SocketQUICCongestion_on_packets_acked (cc, 1200, UINT64_MAX / 2);
  ASSERT_EQ (QUIC_CC_CONGESTION_AVOID, SocketQUICCongestion_phase (cc));

  size_t cwnd_before = SocketQUICCongestion_cwnd (cc);

  /* ACK one full cwnd worth of data */
  SocketQUICCongestion_on_packets_acked (cc, cwnd_before, UINT64_MAX / 2 + 1);

  /* Linear growth: cwnd += max_datagram_size * acked_bytes / cwnd
   * = 1200 * cwnd / cwnd = 1200 */
  ASSERT_EQ (cwnd_before + QUIC_MAX_DATAGRAM_SIZE,
             SocketQUICCongestion_cwnd (cc));

  Arena_dispose (&arena);
}

/* ============================================================================
 * ECN Tests
 * ============================================================================
 */

TEST (cc_ecn_triggers_recovery)
{
  Arena_T arena = Arena_new ();

  SocketQUICCongestion_T cc
      = SocketQUICCongestion_new (arena, QUIC_MAX_DATAGRAM_SIZE);

  size_t cwnd_before = SocketQUICCongestion_cwnd (cc);
  ASSERT_EQ (QUIC_CC_SLOW_START, SocketQUICCongestion_phase (cc));

  /* ECN-CE signal → same as loss */
  SocketQUICCongestion_on_ecn_ce (cc, 500);

  ASSERT_EQ (QUIC_CC_RECOVERY, SocketQUICCongestion_phase (cc));
  ASSERT_EQ (cwnd_before / 2, SocketQUICCongestion_cwnd (cc));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Persistent Congestion Tests
 * ============================================================================
 */

TEST (cc_persistent_congestion)
{
  Arena_T arena = Arena_new ();

  SocketQUICCongestion_T cc
      = SocketQUICCongestion_new (arena, QUIC_MAX_DATAGRAM_SIZE);

  /* Grow cwnd first */
  SocketQUICCongestion_on_packets_acked (cc, 12000, 1000);
  ASSERT (SocketQUICCongestion_cwnd (cc) > QUIC_MIN_CWND);

  /* Persistent congestion → minimum window */
  SocketQUICCongestion_on_persistent_congestion (cc);
  ASSERT_EQ (QUIC_MIN_CWND, SocketQUICCongestion_cwnd (cc));
  ASSERT_EQ (QUIC_CC_SLOW_START, SocketQUICCongestion_phase (cc));

  Arena_dispose (&arena);
}

TEST (cc_min_cwnd)
{
  Arena_T arena = Arena_new ();

  SocketQUICCongestion_T cc
      = SocketQUICCongestion_new (arena, QUIC_MAX_DATAGRAM_SIZE);

  /* Repeatedly lose packets to drive cwnd down */
  for (int i = 0; i < 20; i++)
    {
      /* Each loss triggers recovery if not already in recovery.
       * Use increasing sent_time to ensure we're past recovery_start. */
      uint64_t t = (uint64_t)(i + 1) * 1000000000ULL;
      SocketQUICCongestion_on_packets_lost (cc, 1200, t);
      /* Exit recovery by acking a post-recovery packet */
      SocketQUICCongestion_on_packets_acked (cc, 1200, t + 1000000000ULL);
    }

  /* cwnd should never go below QUIC_MIN_CWND */
  ASSERT (SocketQUICCongestion_cwnd (cc) >= QUIC_MIN_CWND);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Persistent Duration Calculation Tests
 * ============================================================================
 */

TEST (cc_persistent_duration)
{
  SocketQUICLossRTT_T rtt;
  SocketQUICLoss_init_rtt (&rtt);

  /* Set known RTT values */
  SocketQUICLoss_update_rtt (&rtt, 100000, 0, 0);
  /* After first sample: smoothed_rtt=100000, rtt_var=50000 */

  uint64_t max_ack_delay = 25000; /* 25ms */

  uint64_t duration
      = SocketQUICCongestion_persistent_duration (&rtt, max_ack_delay);

  /* PTO = smoothed_rtt + max(4*rtt_var, granularity) + max_ack_delay
   *     = 100000 + max(200000, 1000) + 25000
   *     = 100000 + 200000 + 25000 = 325000
   * persistent = PTO * 3 = 975000 */
  ASSERT_EQ (975000, duration);

  /* No RTT sample → returns 0 */
  SocketQUICLossRTT_T no_sample;
  SocketQUICLoss_init_rtt (&no_sample);
  ASSERT_EQ (0, SocketQUICCongestion_persistent_duration (&no_sample, 25000));

  /* NULL → returns 0 */
  ASSERT_EQ (0, SocketQUICCongestion_persistent_duration (NULL, 25000));
}

/* ============================================================================
 * Reset Tests
 * ============================================================================
 */

TEST (cc_reset)
{
  Arena_T arena = Arena_new ();

  SocketQUICCongestion_T cc
      = SocketQUICCongestion_new (arena, QUIC_MAX_DATAGRAM_SIZE);

  /* Modify state */
  SocketQUICCongestion_on_packets_acked (cc, 12000, 1000);
  SocketQUICCongestion_on_packets_lost (cc, 1200, 500);

  /* Reset */
  SocketQUICCongestion_reset (cc);
  ASSERT_EQ (QUIC_INITIAL_CWND, SocketQUICCongestion_cwnd (cc));
  ASSERT_EQ (QUIC_MAX_CWND, SocketQUICCongestion_ssthresh (cc));
  ASSERT_EQ (QUIC_CC_SLOW_START, SocketQUICCongestion_phase (cc));

  /* Reset NULL should not crash */
  SocketQUICCongestion_reset (NULL);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Phase Name Tests
 * ============================================================================
 */

TEST (cc_phase_name)
{
  ASSERT_EQ (0,
             strcmp ("SLOW_START",
                     SocketQUICCongestion_phase_name (QUIC_CC_SLOW_START)));
  ASSERT_EQ (
      0,
      strcmp ("RECOVERY", SocketQUICCongestion_phase_name (QUIC_CC_RECOVERY)));
  ASSERT_EQ (
      0,
      strcmp ("CONGESTION_AVOIDANCE",
              SocketQUICCongestion_phase_name (QUIC_CC_CONGESTION_AVOID)));
  ASSERT_EQ (0, strcmp ("UNKNOWN", SocketQUICCongestion_phase_name (99)));
}

/* ============================================================================
 * Integration Test: Loss + Congestion Wired Together
 * ============================================================================
 */

static size_t integration_acked_bytes;
static uint64_t integration_latest_acked_time;
static size_t integration_lost_bytes;
static uint64_t integration_latest_lost_time;

static void
integration_acked_cb (const SocketQUICLossSentPacket_T *pkt, void *ctx)
{
  (void)ctx;
  if (pkt->in_flight)
    integration_acked_bytes += pkt->sent_bytes;
  if (pkt->sent_time_us > integration_latest_acked_time)
    integration_latest_acked_time = pkt->sent_time_us;
}

static void
integration_lost_cb (const SocketQUICLossSentPacket_T *pkt, void *ctx)
{
  (void)ctx;
  if (pkt->in_flight)
    integration_lost_bytes += pkt->sent_bytes;
  if (pkt->sent_time_us > integration_latest_lost_time)
    integration_latest_lost_time = pkt->sent_time_us;
}

TEST (cc_integration_send_ack_cycle)
{
  Arena_T arena = Arena_new ();

  /* Create loss state and congestion controller */
  SocketQUICLossState_T loss = SocketQUICLoss_new (arena, 0, 25000);
  ASSERT (loss != NULL);

  SocketQUICCongestion_T cc
      = SocketQUICCongestion_new (arena, QUIC_MAX_DATAGRAM_SIZE);
  ASSERT (cc != NULL);

  SocketQUICLossRTT_T rtt;
  SocketQUICLoss_init_rtt (&rtt);

  uint64_t base_time = 1000000;

  /* Send 5 packets */
  for (uint64_t i = 0; i < 5; i++)
    {
      SocketQUICLoss_on_packet_sent (
          loss, i, base_time + i * 10000, 1200, 1, 1, 0);
    }

  ASSERT_EQ (6000, SocketQUICLoss_bytes_in_flight (loss));
  size_t initial_cwnd = SocketQUICCongestion_cwnd (cc);

  /* ACK packets 0-4 */
  integration_acked_bytes = 0;
  integration_latest_acked_time = 0;
  integration_lost_bytes = 0;
  integration_latest_lost_time = 0;

  SocketQUICFrameAck_T ack;
  memset (&ack, 0, sizeof (ack));
  ack.largest_ack = 4;
  ack.ack_delay = 1000;
  ack.first_range = 4; /* Range [0, 4] */

  size_t acked_count = 0, lost_count = 0;
  SocketQUICLoss_on_ack_received (loss,
                                  &rtt,
                                  &ack,
                                  base_time + 100000,
                                  integration_acked_cb,
                                  integration_lost_cb,
                                  NULL,
                                  &acked_count,
                                  &lost_count);

  ASSERT_EQ (5, acked_count);
  ASSERT_EQ (6000, integration_acked_bytes);
  ASSERT_EQ (0, SocketQUICLoss_bytes_in_flight (loss));

  /* Notify congestion controller */
  if (integration_acked_bytes > 0)
    SocketQUICCongestion_on_packets_acked (
        cc, integration_acked_bytes, integration_latest_acked_time);

  /* In slow start, cwnd should have grown by acked_bytes */
  ASSERT_EQ (initial_cwnd + 6000, SocketQUICCongestion_cwnd (cc));
  ASSERT_EQ (QUIC_CC_SLOW_START, SocketQUICCongestion_phase (cc));

  /* Now send more packets and simulate loss */
  for (uint64_t i = 5; i < 15; i++)
    {
      SocketQUICLoss_on_packet_sent (
          loss, i, base_time + 200000 + i * 10000, 1200, 1, 1, 0);
    }

  size_t cwnd_before_loss = SocketQUICCongestion_cwnd (cc);

  /* ACK packet 14 only (skip 5-11 → they become lost by packet threshold) */
  integration_acked_bytes = 0;
  integration_latest_acked_time = 0;
  integration_lost_bytes = 0;
  integration_latest_lost_time = 0;

  memset (&ack, 0, sizeof (ack));
  ack.largest_ack = 14;
  ack.ack_delay = 1000;
  ack.first_range = 2; /* ACK range [12, 14] */

  SocketQUICLoss_on_ack_received (loss,
                                  &rtt,
                                  &ack,
                                  base_time + 400000,
                                  integration_acked_cb,
                                  integration_lost_cb,
                                  NULL,
                                  &acked_count,
                                  &lost_count);

  /* Some packets should be declared lost (pn <= 14 - 3 = 11 and not acked) */
  ASSERT (lost_count > 0);
  ASSERT (integration_lost_bytes > 0);

  /* Notify CC of acked and lost */
  if (integration_acked_bytes > 0)
    SocketQUICCongestion_on_packets_acked (
        cc, integration_acked_bytes, integration_latest_acked_time);
  if (integration_lost_bytes > 0)
    SocketQUICCongestion_on_packets_lost (
        cc, integration_lost_bytes, integration_latest_lost_time);

  /* Should have entered recovery and halved cwnd */
  ASSERT_EQ (QUIC_CC_RECOVERY, SocketQUICCongestion_phase (cc));
  ASSERT (SocketQUICCongestion_cwnd (cc) < cwnd_before_loss);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

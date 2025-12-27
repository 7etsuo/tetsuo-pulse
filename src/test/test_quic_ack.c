/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_ack.c
 * @brief Unit tests for QUIC ACK generation (RFC 9000 Section 13.2).
 */

#include "quic/SocketQUICAck.h"
#include "core/Arena.h"
#include "test/Test.h"

#include <string.h>

/* ============================================================================
 * Lifecycle Tests
 * ============================================================================
 */

TEST (ack_new)
{
  Arena_T arena;
  SocketQUICAckState_T state;

  arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  state = SocketQUICAck_new (arena, 0, 0);
  ASSERT_NOT_NULL (state);

  /* Check defaults */
  ASSERT_EQ (0, state->range_count);
  ASSERT_EQ (0, state->largest_received);
  ASSERT_EQ (0, state->ack_pending);
  ASSERT_EQ (0, state->ack_eliciting_count);
  ASSERT_EQ (0, state->is_handshake_space);
  ASSERT_EQ (QUIC_ACK_DEFAULT_MAX_DELAY_US, state->max_ack_delay_us);

  Arena_dispose (&arena);
}

TEST (ack_new_handshake)
{
  Arena_T arena;
  SocketQUICAckState_T state;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 1, 50000);
  ASSERT_NOT_NULL (state);

  ASSERT_EQ (1, state->is_handshake_space);
  ASSERT_EQ (50000, state->max_ack_delay_us);

  Arena_dispose (&arena);
}

TEST (ack_new_null_arena)
{
  SocketQUICAckState_T state;

  state = SocketQUICAck_new (NULL, 0, 0);
  ASSERT_NULL (state);
}

TEST (ack_reset)
{
  Arena_T arena;
  SocketQUICAckState_T state;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  /* Record some packets */
  SocketQUICAck_record_packet (state, 0, 1000, 1);
  SocketQUICAck_record_packet (state, 1, 2000, 1);
  ASSERT_EQ (2, state->ack_eliciting_count);
  ASSERT (state->range_count > 0);

  /* Reset */
  SocketQUICAck_reset (state);
  ASSERT_EQ (0, state->range_count);
  ASSERT_EQ (0, state->largest_received);
  ASSERT_EQ (0, state->ack_pending);
  ASSERT_EQ (0, state->ack_eliciting_count);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Packet Recording Tests
 * ============================================================================
 */

TEST (ack_record_single)
{
  Arena_T arena;
  SocketQUICAckState_T state;
  SocketQUICAck_Result res;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  res = SocketQUICAck_record_packet (state, 42, 1000000, 1);
  ASSERT_EQ (QUIC_ACK_OK, res);

  ASSERT_EQ (1, state->range_count);
  ASSERT_EQ (42, state->largest_received);
  ASSERT_EQ (1000000, state->largest_recv_time);
  ASSERT_EQ (1, state->ack_pending);
  ASSERT_EQ (1, state->ack_eliciting_count);

  Arena_dispose (&arena);
}

TEST (ack_record_null)
{
  SocketQUICAck_Result res;

  res = SocketQUICAck_record_packet (NULL, 0, 1000, 1);
  ASSERT_EQ (QUIC_ACK_ERROR_NULL, res);
}

TEST (ack_record_duplicate)
{
  Arena_T arena;
  SocketQUICAckState_T state;
  SocketQUICAck_Result res;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  res = SocketQUICAck_record_packet (state, 5, 1000, 1);
  ASSERT_EQ (QUIC_ACK_OK, res);

  res = SocketQUICAck_record_packet (state, 5, 2000, 1);
  ASSERT_EQ (QUIC_ACK_ERROR_DUPLICATE, res);

  Arena_dispose (&arena);
}

TEST (ack_record_consecutive)
{
  Arena_T arena;
  SocketQUICAckState_T state;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  /* Record 0, 1, 2 - should merge into single range */
  SocketQUICAck_record_packet (state, 0, 1000, 1);
  SocketQUICAck_record_packet (state, 1, 2000, 1);
  SocketQUICAck_record_packet (state, 2, 3000, 1);

  ASSERT_EQ (1, state->range_count);
  ASSERT_EQ (0, state->ranges[0].start);
  ASSERT_EQ (2, state->ranges[0].end);
  ASSERT_EQ (2, state->largest_received);

  Arena_dispose (&arena);
}

TEST (ack_record_gap)
{
  Arena_T arena;
  SocketQUICAckState_T state;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  /* Record 0, 2 with gap at 1 */
  SocketQUICAck_record_packet (state, 0, 1000, 1);
  SocketQUICAck_record_packet (state, 2, 2000, 1);

  ASSERT_EQ (2, state->range_count);

  Arena_dispose (&arena);
}

TEST (ack_record_merge_gap)
{
  Arena_T arena;
  SocketQUICAckState_T state;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  /* Record 0, 2, then 1 - should merge into one range */
  SocketQUICAck_record_packet (state, 0, 1000, 0);
  SocketQUICAck_record_packet (state, 2, 2000, 0);
  ASSERT_EQ (2, state->range_count);

  SocketQUICAck_record_packet (state, 1, 3000, 0);
  ASSERT_EQ (1, state->range_count);
  ASSERT_EQ (0, state->ranges[0].start);
  ASSERT_EQ (2, state->ranges[0].end);

  Arena_dispose (&arena);
}

TEST (ack_record_non_eliciting)
{
  Arena_T arena;
  SocketQUICAckState_T state;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  /* Non-ack-eliciting packet */
  SocketQUICAck_record_packet (state, 0, 1000, 0);

  ASSERT_EQ (0, state->ack_eliciting_count);
  /* Still recorded but no pending ACK required for non-eliciting */
  ASSERT_EQ (1, state->range_count);

  Arena_dispose (&arena);
}

/* ============================================================================
 * ECN Tests
 * ============================================================================
 */

TEST (ack_record_ecn)
{
  Arena_T arena;
  SocketQUICAckState_T state;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  SocketQUICAck_record_ecn (state, 1); /* ECT(0) */
  SocketQUICAck_record_ecn (state, 1);
  SocketQUICAck_record_ecn (state, 2); /* ECT(1) */
  SocketQUICAck_record_ecn (state, 3); /* CE */
  SocketQUICAck_record_ecn (state, 3);
  SocketQUICAck_record_ecn (state, 3);

  ASSERT_EQ (2, state->ecn_counts.ect0_count);
  ASSERT_EQ (1, state->ecn_counts.ect1_count);
  ASSERT_EQ (3, state->ecn_counts.ce_count);

  Arena_dispose (&arena);
}

TEST (ack_record_ecn_null)
{
  /* Should not crash */
  SocketQUICAck_record_ecn (NULL, 1);
}

/* ============================================================================
 * Should Send Tests
 * ============================================================================
 */

TEST (ack_should_send_empty)
{
  Arena_T arena;
  SocketQUICAckState_T state;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  /* No packets received */
  ASSERT_EQ (0, SocketQUICAck_should_send (state, 1000000));

  Arena_dispose (&arena);
}

TEST (ack_should_send_handshake)
{
  Arena_T arena;
  SocketQUICAckState_T state;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 1, 0); /* Handshake space */

  SocketQUICAck_record_packet (state, 0, 1000, 1);

  /* Handshake: always ACK immediately */
  ASSERT (SocketQUICAck_should_send (state, 1001));

  Arena_dispose (&arena);
}

TEST (ack_should_send_threshold)
{
  Arena_T arena;
  SocketQUICAckState_T state;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0); /* Application data */

  SocketQUICAck_record_packet (state, 0, 1000, 1);
  /* Below threshold */
  ASSERT_EQ (0, SocketQUICAck_should_send (state, 1001));

  SocketQUICAck_record_packet (state, 1, 2000, 1);
  /* At threshold (2 ack-eliciting) */
  ASSERT (SocketQUICAck_should_send (state, 2001));

  Arena_dispose (&arena);
}

TEST (ack_should_send_delay)
{
  Arena_T arena;
  SocketQUICAckState_T state;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 25000); /* 25ms max delay */

  SocketQUICAck_record_packet (state, 0, 1000000, 1); /* 1s */

  /* Before delay */
  ASSERT_EQ (0, SocketQUICAck_should_send (state, 1010000)); /* 1.01s */

  /* After delay */
  ASSERT (SocketQUICAck_should_send (state, 1030000)); /* 1.03s */

  Arena_dispose (&arena);
}

/* ============================================================================
 * Encode Tests
 * ============================================================================
 */

TEST (ack_encode_basic)
{
  Arena_T arena;
  SocketQUICAckState_T state;
  uint8_t buf[256];
  size_t len;
  SocketQUICAck_Result res;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  SocketQUICAck_record_packet (state, 5, 1000000, 1);

  res = SocketQUICAck_encode (state, 1000000, buf, sizeof (buf), &len);
  ASSERT_EQ (QUIC_ACK_OK, res);
  ASSERT (len > 0);

  /* Frame type should be 0x02 (ACK without ECN) */
  ASSERT_EQ (0x02, buf[0]);

  Arena_dispose (&arena);
}

TEST (ack_encode_empty)
{
  Arena_T arena;
  SocketQUICAckState_T state;
  uint8_t buf[256];
  size_t len;
  SocketQUICAck_Result res;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  /* No packets recorded */
  res = SocketQUICAck_encode (state, 1000000, buf, sizeof (buf), &len);
  ASSERT_EQ (QUIC_ACK_OK, res);
  ASSERT_EQ (0, len);

  Arena_dispose (&arena);
}

TEST (ack_encode_null)
{
  uint8_t buf[256];
  size_t len;
  SocketQUICAck_Result res;

  res = SocketQUICAck_encode (NULL, 1000000, buf, sizeof (buf), &len);
  ASSERT_EQ (QUIC_ACK_ERROR_NULL, res);
}

TEST (ack_encode_buffer_small)
{
  Arena_T arena;
  SocketQUICAckState_T state;
  uint8_t buf[1];
  size_t len;
  SocketQUICAck_Result res;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);
  SocketQUICAck_record_packet (state, 1000, 1000000, 1);

  /* Buffer too small */
  res = SocketQUICAck_encode (state, 1000000, buf, sizeof (buf), &len);
  ASSERT_EQ (QUIC_ACK_ERROR_BUFFER, res);

  Arena_dispose (&arena);
}

TEST (ack_encode_with_ecn)
{
  Arena_T arena;
  SocketQUICAckState_T state;
  uint8_t buf[256];
  size_t len;
  SocketQUICAck_Result res;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  SocketQUICAck_record_packet (state, 5, 1000000, 1);
  SocketQUICAck_record_ecn (state, 1); /* ECT(0) */
  state->ecn_validated = 1;

  res = SocketQUICAck_encode (state, 1000000, buf, sizeof (buf), &len);
  ASSERT_EQ (QUIC_ACK_OK, res);

  /* Frame type should be 0x03 (ACK with ECN) */
  ASSERT_EQ (0x03, buf[0]);

  Arena_dispose (&arena);
}

TEST (ack_encode_multiple_ranges)
{
  Arena_T arena;
  SocketQUICAckState_T state;
  uint8_t buf[256];
  size_t len;
  SocketQUICAck_Result res;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  /* Create gaps: 0, 2, 4 */
  SocketQUICAck_record_packet (state, 0, 1000, 0);
  SocketQUICAck_record_packet (state, 2, 2000, 0);
  SocketQUICAck_record_packet (state, 4, 3000, 0);

  ASSERT_EQ (3, state->range_count);

  res = SocketQUICAck_encode (state, 4000, buf, sizeof (buf), &len);
  ASSERT_EQ (QUIC_ACK_OK, res);
  ASSERT (len > 5); /* Should have gap+range pairs */

  Arena_dispose (&arena);
}

/* ============================================================================
 * Mark Sent Tests
 * ============================================================================
 */

TEST (ack_mark_sent)
{
  Arena_T arena;
  SocketQUICAckState_T state;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  SocketQUICAck_record_packet (state, 0, 1000, 1);
  SocketQUICAck_record_packet (state, 1, 2000, 1);
  ASSERT_EQ (1, state->ack_pending);
  ASSERT_EQ (2, state->ack_eliciting_count);

  SocketQUICAck_mark_sent (state, 3000);

  ASSERT_EQ (0, state->ack_pending);
  ASSERT_EQ (0, state->ack_eliciting_count);
  ASSERT_EQ (3000, state->last_ack_sent_time);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Query Tests
 * ============================================================================
 */

TEST (ack_get_largest)
{
  Arena_T arena;
  SocketQUICAckState_T state;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  ASSERT_EQ (0, SocketQUICAck_get_largest (state));

  SocketQUICAck_record_packet (state, 10, 1000, 0);
  ASSERT_EQ (10, SocketQUICAck_get_largest (state));

  SocketQUICAck_record_packet (state, 5, 2000, 0);
  ASSERT_EQ (10, SocketQUICAck_get_largest (state));

  SocketQUICAck_record_packet (state, 100, 3000, 0);
  ASSERT_EQ (100, SocketQUICAck_get_largest (state));

  Arena_dispose (&arena);
}

TEST (ack_contains)
{
  Arena_T arena;
  SocketQUICAckState_T state;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  SocketQUICAck_record_packet (state, 5, 1000, 0);
  SocketQUICAck_record_packet (state, 6, 2000, 0);
  SocketQUICAck_record_packet (state, 7, 3000, 0);

  ASSERT (SocketQUICAck_contains (state, 5));
  ASSERT (SocketQUICAck_contains (state, 6));
  ASSERT (SocketQUICAck_contains (state, 7));
  ASSERT_EQ (0, SocketQUICAck_contains (state, 4));
  ASSERT_EQ (0, SocketQUICAck_contains (state, 8));

  Arena_dispose (&arena);
}

TEST (ack_range_count)
{
  Arena_T arena;
  SocketQUICAckState_T state;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  ASSERT_EQ (0, SocketQUICAck_range_count (state));

  SocketQUICAck_record_packet (state, 0, 1000, 0);
  ASSERT_EQ (1, SocketQUICAck_range_count (state));

  SocketQUICAck_record_packet (state, 5, 2000, 0);
  ASSERT_EQ (2, SocketQUICAck_range_count (state));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Prune Tests
 * ============================================================================
 */

TEST (ack_prune)
{
  Arena_T arena;
  SocketQUICAckState_T state;
  size_t removed;

  arena = Arena_new ();
  state = SocketQUICAck_new (arena, 0, 0);

  /* Record packets with gaps to create multiple ranges */
  /* Range 1: 10-12, Range 2: 5-7, Range 3: 0-2 */
  for (uint64_t i = 10; i <= 12; i++)
    SocketQUICAck_record_packet (state, i, i * 1000, 0);
  for (uint64_t i = 5; i <= 7; i++)
    SocketQUICAck_record_packet (state, i, i * 1000, 0);
  for (uint64_t i = 0; i <= 2; i++)
    SocketQUICAck_record_packet (state, i, i * 1000, 0);

  ASSERT_EQ (3, state->range_count);
  ASSERT_EQ (12, state->largest_received);

  /* Prune keeping only ranges with start >= 5 */
  SocketQUICAck_prune (state, 5, &removed);

  /* Ranges 10-12 and 5-7 should be kept (start >= 5) */
  /* Range 0-2 should be removed (start=0 < 5) */
  ASSERT_EQ (1, removed);
  ASSERT (SocketQUICAck_contains (state, 10));
  ASSERT (SocketQUICAck_contains (state, 5));
  ASSERT_EQ (0, SocketQUICAck_contains (state, 0));

  Arena_dispose (&arena);
}

TEST (ack_prune_null)
{
  size_t removed = 99;

  SocketQUICAck_prune (NULL, 5, &removed);
  ASSERT_EQ (0, removed);
}

/* ============================================================================
 * Result String Test
 * ============================================================================
 */

TEST (ack_result_string)
{
  ASSERT (strcmp ("OK", SocketQUICAck_result_string (QUIC_ACK_OK)) == 0);
  ASSERT (strcmp ("NULL pointer argument",
                  SocketQUICAck_result_string (QUIC_ACK_ERROR_NULL))
          == 0);
  ASSERT (strcmp ("Unknown error", SocketQUICAck_result_string (-1)) == 0);
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

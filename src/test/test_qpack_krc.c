/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_krc.c
 * @brief Unit tests for QPACK Known Received Count (RFC 9204 Section 2.1.4)
 *
 * Tests the encoder's Known Received Count tracking functionality:
 * - KRC initialization
 * - Section Acknowledgment updates
 * - Insert Count Increment updates
 * - is_acknowledged() checks
 * - Stream Cancellation handling
 */

#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"
#include "test/Test.h"

/* ============================================================================
 * ENCODER CREATION TESTS
 * ============================================================================
 */

TEST (qpack_encoder_new_null_arena)
{
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (NULL, 4096);
  ASSERT_NULL (encoder);
}

TEST (qpack_encoder_new_success)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);
  Arena_dispose (&arena);
}

TEST (qpack_encoder_new_zero_table_size)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 0);
  ASSERT_NOT_NULL (encoder);
  Arena_dispose (&arena);
}

/* ============================================================================
 * KRC INITIALIZATION TESTS (Issue #3307 Test Plan Item 1)
 * ============================================================================
 */

TEST (qpack_krc_initialized_to_zero)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  uint64_t krc = SocketQPACK_Encoder_known_received_count (encoder);
  ASSERT_EQ (krc, 0);

  Arena_dispose (&arena);
}

TEST (qpack_krc_null_encoder_returns_zero)
{
  uint64_t krc = SocketQPACK_Encoder_known_received_count (NULL);
  ASSERT_EQ (krc, 0);
}

/* ============================================================================
 * INSERT COUNT TESTS
 * ============================================================================
 */

TEST (qpack_encoder_insert_count_initially_zero)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  uint64_t ic = SocketQPACK_Encoder_insert_count (encoder);
  ASSERT_EQ (ic, 0);

  Arena_dispose (&arena);
}

TEST (qpack_encoder_insert_count_null_returns_zero)
{
  uint64_t ic = SocketQPACK_Encoder_insert_count (NULL);
  ASSERT_EQ (ic, 0);
}

/* ============================================================================
 * IS_ACKNOWLEDGED TESTS (Issue #3307 Test Plan Item 5)
 * ============================================================================
 */

TEST (qpack_is_acknowledged_false_when_krc_zero)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  /* KRC=0, so index 0 is NOT acknowledged (0 < 0 is false) */
  ASSERT (!SocketQPACK_Encoder_is_acknowledged (encoder, 0));
  ASSERT (!SocketQPACK_Encoder_is_acknowledged (encoder, 1));
  ASSERT (!SocketQPACK_Encoder_is_acknowledged (encoder, 100));

  Arena_dispose (&arena);
}

TEST (qpack_is_acknowledged_null_encoder_returns_false)
{
  ASSERT (!SocketQPACK_Encoder_is_acknowledged (NULL, 0));
  ASSERT (!SocketQPACK_Encoder_is_acknowledged (NULL, 100));
}

/* ============================================================================
 * SECTION ACKNOWLEDGMENT TESTS (Issue #3307 Test Plan Items 2, 6)
 * ============================================================================
 */

TEST (qpack_section_ack_null_encoder)
{
  SocketQPACK_Result result = SocketQPACK_Encoder_on_section_ack (NULL, 1);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_section_ack_unknown_stream_fails)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  /* Attempt to ack a stream that was never registered */
  SocketQPACK_Result result = SocketQPACK_Encoder_on_section_ack (encoder, 42);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);

  Arena_dispose (&arena);
}

TEST (qpack_section_ack_updates_krc)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  /* Get the table and insert some entries */
  SocketQPACK_Table_T table = SocketQPACK_Encoder_get_table (encoder);
  ASSERT_NOT_NULL (table);

  /* Insert entries to advance insert_count */
  SocketQPACK_Result r1, r2, r3;
  r1 = SocketQPACK_Table_insert_literal (table, "name1", 5, "value1", 6);
  r2 = SocketQPACK_Table_insert_literal (table, "name2", 5, "value2", 6);
  r3 = SocketQPACK_Table_insert_literal (table, "name3", 5, "value3", 6);
  ASSERT_EQ (r1, QPACK_OK);
  ASSERT_EQ (r2, QPACK_OK);
  ASSERT_EQ (r3, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_insert_count (encoder), 3);

  /* Register a section with RIC=2 on stream 1 */
  SocketQPACK_Result result
      = SocketQPACK_Encoder_register_section (encoder, 1, 2);
  ASSERT_EQ (result, QPACK_OK);

  /* Acknowledge stream 1 */
  result = SocketQPACK_Encoder_on_section_ack (encoder, 1);
  ASSERT_EQ (result, QPACK_OK);

  /* KRC should now be 2 */
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 2);

  /* Indices 0 and 1 should be acknowledged, index 2 should not */
  ASSERT (SocketQPACK_Encoder_is_acknowledged (encoder, 0));
  ASSERT (SocketQPACK_Encoder_is_acknowledged (encoder, 1));
  ASSERT (!SocketQPACK_Encoder_is_acknowledged (encoder, 2));

  Arena_dispose (&arena);
}

TEST (qpack_section_ack_multiple_streams_highest_ric_wins)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  /* Get the table and insert entries */
  SocketQPACK_Table_T table = SocketQPACK_Encoder_get_table (encoder);
  ASSERT_NOT_NULL (table);

  {
    SocketQPACK_Result r;
    for (int i = 0; i < 5; i++)
      {
        r = SocketQPACK_Table_insert_literal (table, "name", 4, "value", 5);
        ASSERT_EQ (r, QPACK_OK);
      }
  }
  ASSERT_EQ (SocketQPACK_Encoder_insert_count (encoder), 5);

  /* Register sections with different RICs */
  ASSERT_EQ (SocketQPACK_Encoder_register_section (encoder, 1, 2), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_register_section (encoder, 2, 4), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_register_section (encoder, 3, 3), QPACK_OK);

  /* Ack stream 1 (RIC=2) - KRC becomes 2 */
  ASSERT_EQ (SocketQPACK_Encoder_on_section_ack (encoder, 1), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 2);

  /* Ack stream 2 (RIC=4) - KRC becomes 4 */
  ASSERT_EQ (SocketQPACK_Encoder_on_section_ack (encoder, 2), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 4);

  /* Ack stream 3 (RIC=3) - KRC stays 4 (never decreases) */
  ASSERT_EQ (SocketQPACK_Encoder_on_section_ack (encoder, 3), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 4);

  Arena_dispose (&arena);
}

/* ============================================================================
 * INSERT COUNT INCREMENT TESTS (Issue #3307 Test Plan Items 3, 7, 8)
 * ============================================================================
 */

TEST (qpack_insert_count_inc_null_encoder)
{
  SocketQPACK_Result result = SocketQPACK_Encoder_on_insert_count_inc (NULL, 1);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_insert_count_inc_zero_fails)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  /* Increment of 0 is an error per RFC 9204 Section 4.4.3 */
  SocketQPACK_Result result
      = SocketQPACK_Encoder_on_insert_count_inc (encoder, 0);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);

  /* KRC should remain 0 */
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 0);

  Arena_dispose (&arena);
}

TEST (qpack_insert_count_inc_exceeds_insert_count_fails)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  /* No entries inserted, so insert_count=0 */
  ASSERT_EQ (SocketQPACK_Encoder_insert_count (encoder), 0);

  /* Try to increment KRC by 1, but insert_count=0 */
  SocketQPACK_Result result
      = SocketQPACK_Encoder_on_insert_count_inc (encoder, 1);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);

  /* KRC should remain 0 */
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 0);

  Arena_dispose (&arena);
}

TEST (qpack_insert_count_inc_success)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  /* Insert 3 entries */
  SocketQPACK_Table_T table = SocketQPACK_Encoder_get_table (encoder);
  SocketQPACK_Result r1, r2, r3;
  r1 = SocketQPACK_Table_insert_literal (table, "name1", 5, "value1", 6);
  r2 = SocketQPACK_Table_insert_literal (table, "name2", 5, "value2", 6);
  r3 = SocketQPACK_Table_insert_literal (table, "name3", 5, "value3", 6);
  ASSERT_EQ (r1, QPACK_OK);
  ASSERT_EQ (r2, QPACK_OK);
  ASSERT_EQ (r3, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_insert_count (encoder), 3);

  /* Increment KRC by 2 */
  SocketQPACK_Result result
      = SocketQPACK_Encoder_on_insert_count_inc (encoder, 2);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 2);

  /* Increment by 1 more (total KRC=3) */
  result = SocketQPACK_Encoder_on_insert_count_inc (encoder, 1);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 3);

  /* Try to increment by 1 more - should fail (KRC would exceed insert_count) */
  result = SocketQPACK_Encoder_on_insert_count_inc (encoder, 1);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 3);

  Arena_dispose (&arena);
}

TEST (qpack_insert_count_inc_krc_equals_insert_count)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  /* Insert 5 entries */
  SocketQPACK_Table_T table = SocketQPACK_Encoder_get_table (encoder);
  {
    SocketQPACK_Result r;
    for (int i = 0; i < 5; i++)
      {
        r = SocketQPACK_Table_insert_literal (table, "name", 4, "value", 5);
        ASSERT_EQ (r, QPACK_OK);
      }
  }
  ASSERT_EQ (SocketQPACK_Encoder_insert_count (encoder), 5);

  /* Increment KRC to exactly insert_count */
  SocketQPACK_Result result
      = SocketQPACK_Encoder_on_insert_count_inc (encoder, 5);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 5);

  /* All entries should be acknowledged */
  for (uint64_t i = 0; i < 5; i++)
    ASSERT (SocketQPACK_Encoder_is_acknowledged (encoder, i));

  Arena_dispose (&arena);
}

/* ============================================================================
 * KRC NEVER DECREASES TEST (Issue #3307 Test Plan Item 4)
 * ============================================================================
 */

TEST (qpack_krc_never_decreases)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  /* Insert entries */
  SocketQPACK_Table_T table = SocketQPACK_Encoder_get_table (encoder);
  {
    SocketQPACK_Result r;
    for (int i = 0; i < 10; i++)
      {
        r = SocketQPACK_Table_insert_literal (table, "name", 4, "value", 5);
        ASSERT_EQ (r, QPACK_OK);
      }
  }

  /* Register streams with varying RICs */
  ASSERT_EQ (SocketQPACK_Encoder_register_section (encoder, 1, 8), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_register_section (encoder, 2, 5), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_register_section (encoder, 3, 3), QPACK_OK);

  /* Ack stream 1 (RIC=8) - KRC becomes 8 */
  ASSERT_EQ (SocketQPACK_Encoder_on_section_ack (encoder, 1), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 8);

  /* Ack stream 2 (RIC=5) - KRC stays 8 */
  ASSERT_EQ (SocketQPACK_Encoder_on_section_ack (encoder, 2), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 8);

  /* Ack stream 3 (RIC=3) - KRC stays 8 */
  ASSERT_EQ (SocketQPACK_Encoder_on_section_ack (encoder, 3), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 8);

  Arena_dispose (&arena);
}

/* ============================================================================
 * STREAM CANCELLATION TESTS
 * ============================================================================
 */

TEST (qpack_stream_cancel_null_encoder)
{
  SocketQPACK_Result result = SocketQPACK_Encoder_on_stream_cancel (NULL, 1);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_stream_cancel_unknown_stream_ok)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  /* Cancelling an unknown stream is idempotent (not an error) */
  SocketQPACK_Result result
      = SocketQPACK_Encoder_on_stream_cancel (encoder, 999);
  ASSERT_EQ (result, QPACK_OK);

  Arena_dispose (&arena);
}

TEST (qpack_stream_cancel_removes_pending)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  /* Insert entries */
  SocketQPACK_Table_T table = SocketQPACK_Encoder_get_table (encoder);
  {
    SocketQPACK_Result r;
    for (int i = 0; i < 5; i++)
      {
        r = SocketQPACK_Table_insert_literal (table, "name", 4, "value", 5);
        ASSERT_EQ (r, QPACK_OK);
      }
  }

  /* Register a section */
  ASSERT_EQ (SocketQPACK_Encoder_register_section (encoder, 1, 3), QPACK_OK);

  /* Cancel the stream */
  ASSERT_EQ (SocketQPACK_Encoder_on_stream_cancel (encoder, 1), QPACK_OK);

  /* Now trying to ack the stream should fail (it was removed) */
  SocketQPACK_Result result = SocketQPACK_Encoder_on_section_ack (encoder, 1);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);

  /* KRC should still be 0 (stream was cancelled, not acknowledged) */
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 0);

  Arena_dispose (&arena);
}

/* ============================================================================
 * REGISTER SECTION TESTS
 * ============================================================================
 */

TEST (qpack_register_section_null_encoder)
{
  SocketQPACK_Result result
      = SocketQPACK_Encoder_register_section (NULL, 1, 5);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_register_section_zero_ric_ok)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  /* RIC=0 means no dynamic table references - should succeed */
  SocketQPACK_Result result
      = SocketQPACK_Encoder_register_section (encoder, 1, 0);
  ASSERT_EQ (result, QPACK_OK);

  Arena_dispose (&arena);
}

TEST (qpack_register_section_same_stream_updates_ric)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  /* Insert entries */
  SocketQPACK_Table_T table = SocketQPACK_Encoder_get_table (encoder);
  {
    SocketQPACK_Result r;
    for (int i = 0; i < 10; i++)
      {
        r = SocketQPACK_Table_insert_literal (table, "name", 4, "value", 5);
        ASSERT_EQ (r, QPACK_OK);
      }
  }

  /* Register with RIC=3 */
  ASSERT_EQ (SocketQPACK_Encoder_register_section (encoder, 1, 3), QPACK_OK);

  /* Register same stream with higher RIC=7 - should update */
  ASSERT_EQ (SocketQPACK_Encoder_register_section (encoder, 1, 7), QPACK_OK);

  /* Ack the stream - KRC should be 7 (the higher RIC) */
  ASSERT_EQ (SocketQPACK_Encoder_on_section_ack (encoder, 1), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 7);

  Arena_dispose (&arena);
}

/* ============================================================================
 * GET TABLE TEST
 * ============================================================================
 */

TEST (qpack_encoder_get_table_null)
{
  SocketQPACK_Table_T table = SocketQPACK_Encoder_get_table (NULL);
  ASSERT_NULL (table);
}

TEST (qpack_encoder_get_table_success)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  SocketQPACK_Table_T table = SocketQPACK_Encoder_get_table (encoder);
  ASSERT_NOT_NULL (table);

  Arena_dispose (&arena);
}

/* ============================================================================
 * TABLE KNOWN_RECEIVED SYNC TEST
 * ============================================================================
 */

TEST (qpack_table_known_received_synced)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Encoder_T encoder = SocketQPACK_Encoder_new (arena, 4096);
  ASSERT_NOT_NULL (encoder);

  /* Insert entries */
  SocketQPACK_Table_T table = SocketQPACK_Encoder_get_table (encoder);
  {
    SocketQPACK_Result r;
    for (int i = 0; i < 5; i++)
      {
        r = SocketQPACK_Table_insert_literal (table, "name", 4, "value", 5);
        ASSERT_EQ (r, QPACK_OK);
      }
  }

  /* Register and ack a section */
  ASSERT_EQ (SocketQPACK_Encoder_register_section (encoder, 1, 3), QPACK_OK);
  ASSERT_EQ (SocketQPACK_Encoder_on_section_ack (encoder, 1), QPACK_OK);

  /* Table's known_received should match encoder's KRC */
  ASSERT_EQ (table->known_received, 3);
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 3);

  /* Increment via Insert Count Increment */
  ASSERT_EQ (SocketQPACK_Encoder_on_insert_count_inc (encoder, 2), QPACK_OK);

  /* Both should now be 5 */
  ASSERT_EQ (table->known_received, 5);
  ASSERT_EQ (SocketQPACK_Encoder_known_received_count (encoder), 5);

  Arena_dispose (&arena);
}

/* ============================================================================
 * MAIN
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

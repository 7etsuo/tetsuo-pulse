/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_krc.c
 * @brief Unit tests for QPACK Known Received Count (RFC 9204 Section 2.1.4).
 *
 * Tests cover:
 * - KRC initialization to 0
 * - KRC update via Section Acknowledgment
 * - KRC update via Insert Count Increment
 * - KRC never decreases
 * - is_acknowledged() returns correct values
 * - KRC remains <= insert_count
 * - Edge cases (overflow, zero increment, NULL parameters)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/qpack/SocketQPACK.h"

/* Simple test assertion macro */
#define TEST_ASSERT(cond, msg)                                               \
  do                                                                         \
    {                                                                        \
      if (!(cond))                                                           \
        {                                                                    \
          fprintf (stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); \
          exit (1);                                                          \
        }                                                                    \
    }                                                                        \
  while (0)

/* ============================================================================
 * KRC Initialization Tests
 * ============================================================================
 */

static void
test_krc_initialized_to_zero (void)
{
  Arena_T arena;
  SocketQPACK_Encoder_T encoder;

  printf ("  KRC initialized to 0... ");

  arena = Arena_new ();
  encoder = SocketQPACK_Encoder_new (arena, 4096);

  TEST_ASSERT (encoder != NULL, "Encoder should be created");
  TEST_ASSERT (SocketQPACK_Encoder_known_received_count (encoder) == 0,
               "KRC should be 0 initially");
  TEST_ASSERT (SocketQPACK_Encoder_insert_count (encoder) == 0,
               "Insert count should be 0 initially");

  SocketQPACK_Encoder_free (&encoder);
  TEST_ASSERT (encoder == NULL, "Encoder should be NULL after free");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Section Acknowledgment Tests
 * ============================================================================
 */

static void
test_section_ack_updates_krc (void)
{
  Arena_T arena;
  SocketQPACK_Encoder_T encoder;
  SocketQPACK_Result result;

  printf ("  Section Ack updates KRC... ");

  arena = Arena_new ();
  encoder = SocketQPACK_Encoder_new (arena, 4096);

  /* Simulate that insert_count is 10 (entries 0-9 exist) */
  /* We need to manually set insert_count for testing since we haven't
   * implemented the insert function yet. Access the struct directly. */
  struct SocketQPACK_Encoder
  {
    Arena_T arena;
    void *head;
    void *tail;
    size_t entry_count;
    size_t table_size;
    size_t max_table_size;
    size_t insert_count;
    size_t known_received_count;
  };
  ((struct SocketQPACK_Encoder *)encoder)->insert_count = 10;

  /* Section Ack with RIC=5 should update KRC to 5 */
  result = SocketQPACK_Encoder_on_section_ack (encoder, 5);
  TEST_ASSERT (result == QPACK_OK, "Section ack should succeed");
  TEST_ASSERT (SocketQPACK_Encoder_known_received_count (encoder) == 5,
               "KRC should be 5");

  /* Section Ack with RIC=8 should update KRC to 8 */
  result = SocketQPACK_Encoder_on_section_ack (encoder, 8);
  TEST_ASSERT (result == QPACK_OK, "Section ack should succeed");
  TEST_ASSERT (SocketQPACK_Encoder_known_received_count (encoder) == 8,
               "KRC should be 8");

  SocketQPACK_Encoder_free (&encoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_krc_never_decreases (void)
{
  Arena_T arena;
  SocketQPACK_Encoder_T encoder;
  SocketQPACK_Result result;

  printf ("  KRC never decreases... ");

  arena = Arena_new ();
  encoder = SocketQPACK_Encoder_new (arena, 4096);

  /* Set insert_count to 20 */
  struct SocketQPACK_Encoder
  {
    Arena_T arena;
    void *head;
    void *tail;
    size_t entry_count;
    size_t table_size;
    size_t max_table_size;
    size_t insert_count;
    size_t known_received_count;
  };
  ((struct SocketQPACK_Encoder *)encoder)->insert_count = 20;

  /* Set KRC to 10 via section ack */
  result = SocketQPACK_Encoder_on_section_ack (encoder, 10);
  TEST_ASSERT (result == QPACK_OK, "Section ack should succeed");
  TEST_ASSERT (SocketQPACK_Encoder_known_received_count (encoder) == 10,
               "KRC should be 10");

  /* Try to set KRC to 5 - should remain at 10 (never decreases) */
  result = SocketQPACK_Encoder_on_section_ack (encoder, 5);
  TEST_ASSERT (result == QPACK_OK, "Section ack with lower RIC should succeed");
  TEST_ASSERT (SocketQPACK_Encoder_known_received_count (encoder) == 10,
               "KRC should remain 10 (not decrease)");

  /* Set KRC to same value - should remain unchanged */
  result = SocketQPACK_Encoder_on_section_ack (encoder, 10);
  TEST_ASSERT (result == QPACK_OK, "Section ack with same RIC should succeed");
  TEST_ASSERT (SocketQPACK_Encoder_known_received_count (encoder) == 10,
               "KRC should remain 10");

  SocketQPACK_Encoder_free (&encoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_krc_clamped_to_insert_count (void)
{
  Arena_T arena;
  SocketQPACK_Encoder_T encoder;
  SocketQPACK_Result result;

  printf ("  KRC clamped to insert_count... ");

  arena = Arena_new ();
  encoder = SocketQPACK_Encoder_new (arena, 4096);

  /* Set insert_count to 10 */
  struct SocketQPACK_Encoder
  {
    Arena_T arena;
    void *head;
    void *tail;
    size_t entry_count;
    size_t table_size;
    size_t max_table_size;
    size_t insert_count;
    size_t known_received_count;
  };
  ((struct SocketQPACK_Encoder *)encoder)->insert_count = 10;

  /* Try to set KRC to 100 (exceeds insert_count) - should clamp to 10 */
  result = SocketQPACK_Encoder_on_section_ack (encoder, 100);
  TEST_ASSERT (result == QPACK_OK, "Section ack should succeed");
  TEST_ASSERT (SocketQPACK_Encoder_known_received_count (encoder) == 10,
               "KRC should be clamped to 10");

  SocketQPACK_Encoder_free (&encoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Insert Count Increment Tests
 * ============================================================================
 */

static void
test_insert_count_increment (void)
{
  Arena_T arena;
  SocketQPACK_Encoder_T encoder;
  SocketQPACK_Result result;

  printf ("  Insert Count Increment updates KRC... ");

  arena = Arena_new ();
  encoder = SocketQPACK_Encoder_new (arena, 4096);

  /* Set insert_count to 20 */
  struct SocketQPACK_Encoder
  {
    Arena_T arena;
    void *head;
    void *tail;
    size_t entry_count;
    size_t table_size;
    size_t max_table_size;
    size_t insert_count;
    size_t known_received_count;
  };
  ((struct SocketQPACK_Encoder *)encoder)->insert_count = 20;

  /* KRC starts at 0, increment by 5 -> KRC = 5 */
  result = SocketQPACK_Encoder_on_insert_count_inc (encoder, 5);
  TEST_ASSERT (result == QPACK_OK, "Insert count inc should succeed");
  TEST_ASSERT (SocketQPACK_Encoder_known_received_count (encoder) == 5,
               "KRC should be 5");

  /* Increment by 3 more -> KRC = 8 */
  result = SocketQPACK_Encoder_on_insert_count_inc (encoder, 3);
  TEST_ASSERT (result == QPACK_OK, "Insert count inc should succeed");
  TEST_ASSERT (SocketQPACK_Encoder_known_received_count (encoder) == 8,
               "KRC should be 8");

  SocketQPACK_Encoder_free (&encoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_insert_count_increment_zero_fails (void)
{
  Arena_T arena;
  SocketQPACK_Encoder_T encoder;
  SocketQPACK_Result result;

  printf ("  Insert Count Increment with 0 fails... ");

  arena = Arena_new ();
  encoder = SocketQPACK_Encoder_new (arena, 4096);

  /* Increment of 0 is invalid per RFC 9204 */
  result = SocketQPACK_Encoder_on_insert_count_inc (encoder, 0);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "Zero increment should fail");
  TEST_ASSERT (SocketQPACK_Encoder_known_received_count (encoder) == 0,
               "KRC should remain 0");

  SocketQPACK_Encoder_free (&encoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_insert_count_increment_clamped (void)
{
  Arena_T arena;
  SocketQPACK_Encoder_T encoder;
  SocketQPACK_Result result;

  printf ("  Insert Count Increment clamped to insert_count... ");

  arena = Arena_new ();
  encoder = SocketQPACK_Encoder_new (arena, 4096);

  /* Set insert_count to 10 */
  struct SocketQPACK_Encoder
  {
    Arena_T arena;
    void *head;
    void *tail;
    size_t entry_count;
    size_t table_size;
    size_t max_table_size;
    size_t insert_count;
    size_t known_received_count;
  };
  ((struct SocketQPACK_Encoder *)encoder)->insert_count = 10;

  /* Set KRC to 5 first */
  result = SocketQPACK_Encoder_on_section_ack (encoder, 5);
  TEST_ASSERT (result == QPACK_OK, "Section ack should succeed");

  /* Try to increment by 100 - should clamp to insert_count (10) */
  result = SocketQPACK_Encoder_on_insert_count_inc (encoder, 100);
  TEST_ASSERT (result == QPACK_OK, "Insert count inc should succeed");
  TEST_ASSERT (SocketQPACK_Encoder_known_received_count (encoder) == 10,
               "KRC should be clamped to 10");

  SocketQPACK_Encoder_free (&encoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * is_acknowledged Tests
 * ============================================================================
 */

static void
test_is_acknowledged_basic (void)
{
  Arena_T arena;
  SocketQPACK_Encoder_T encoder;
  SocketQPACK_Result result;

  printf ("  is_acknowledged returns correct values... ");

  arena = Arena_new ();
  encoder = SocketQPACK_Encoder_new (arena, 4096);

  /* Set insert_count to 10 */
  struct SocketQPACK_Encoder
  {
    Arena_T arena;
    void *head;
    void *tail;
    size_t entry_count;
    size_t table_size;
    size_t max_table_size;
    size_t insert_count;
    size_t known_received_count;
  };
  ((struct SocketQPACK_Encoder *)encoder)->insert_count = 10;

  /* KRC = 0 initially - nothing is acknowledged */
  TEST_ASSERT (!SocketQPACK_Encoder_is_acknowledged (encoder, 0),
               "Index 0 should not be acknowledged when KRC=0");
  TEST_ASSERT (!SocketQPACK_Encoder_is_acknowledged (encoder, 5),
               "Index 5 should not be acknowledged when KRC=0");

  /* Set KRC to 5 */
  result = SocketQPACK_Encoder_on_section_ack (encoder, 5);
  TEST_ASSERT (result == QPACK_OK, "Section ack should succeed");

  /* Indices 0-4 should be acknowledged (index < KRC) */
  TEST_ASSERT (SocketQPACK_Encoder_is_acknowledged (encoder, 0),
               "Index 0 should be acknowledged when KRC=5");
  TEST_ASSERT (SocketQPACK_Encoder_is_acknowledged (encoder, 4),
               "Index 4 should be acknowledged when KRC=5");

  /* Index 5 and above should NOT be acknowledged (index >= KRC) */
  TEST_ASSERT (!SocketQPACK_Encoder_is_acknowledged (encoder, 5),
               "Index 5 should NOT be acknowledged when KRC=5");
  TEST_ASSERT (!SocketQPACK_Encoder_is_acknowledged (encoder, 9),
               "Index 9 should NOT be acknowledged when KRC=5");

  SocketQPACK_Encoder_free (&encoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Edge Case Tests
 * ============================================================================
 */

static void
test_null_encoder_handling (void)
{
  printf ("  NULL encoder handling... ");

  /* All functions should handle NULL gracefully */
  TEST_ASSERT (SocketQPACK_Encoder_known_received_count (NULL) == 0,
               "KRC should be 0 for NULL encoder");
  TEST_ASSERT (SocketQPACK_Encoder_insert_count (NULL) == 0,
               "Insert count should be 0 for NULL encoder");
  TEST_ASSERT (SocketQPACK_Encoder_table_size (NULL) == 0,
               "Table size should be 0 for NULL encoder");
  TEST_ASSERT (SocketQPACK_Encoder_entry_count (NULL) == 0,
               "Entry count should be 0 for NULL encoder");
  TEST_ASSERT (!SocketQPACK_Encoder_is_acknowledged (NULL, 0),
               "is_acknowledged should return false for NULL encoder");
  TEST_ASSERT (SocketQPACK_Encoder_on_section_ack (NULL, 5)
                   == QPACK_ERR_NULL_PARAM,
               "Section ack should return error for NULL encoder");
  TEST_ASSERT (SocketQPACK_Encoder_on_insert_count_inc (NULL, 5)
                   == QPACK_ERR_NULL_PARAM,
               "Insert count inc should return error for NULL encoder");

  /* Free with NULL should not crash */
  SocketQPACK_Encoder_free (NULL);
  SocketQPACK_Encoder_T enc = NULL;
  SocketQPACK_Encoder_free (&enc);

  printf ("PASS\n");
}

static void
test_result_string (void)
{
  printf ("  Result string lookup... ");

  TEST_ASSERT (strcmp (SocketQPACK_result_string (QPACK_OK), "OK") == 0,
               "OK string");
  TEST_ASSERT (SocketQPACK_result_string (QPACK_ERR_INVALID_INDEX) != NULL,
               "Invalid index string should not be NULL");
  TEST_ASSERT (SocketQPACK_result_string (QPACK_ERR_NULL_PARAM) != NULL,
               "NULL param string should not be NULL");
  TEST_ASSERT (SocketQPACK_result_string ((SocketQPACK_Result)999) != NULL,
               "Unknown error string should not be NULL");

  printf ("PASS\n");
}

static void
test_multiple_acks_with_increasing_ric (void)
{
  Arena_T arena;
  SocketQPACK_Encoder_T encoder;
  SocketQPACK_Result result;

  printf ("  Multiple Section Acks with increasing RIC... ");

  arena = Arena_new ();
  encoder = SocketQPACK_Encoder_new (arena, 4096);

  /* Set insert_count to 100 */
  struct SocketQPACK_Encoder
  {
    Arena_T arena;
    void *head;
    void *tail;
    size_t entry_count;
    size_t table_size;
    size_t max_table_size;
    size_t insert_count;
    size_t known_received_count;
  };
  ((struct SocketQPACK_Encoder *)encoder)->insert_count = 100;

  /* Simulate multiple field sections being acknowledged in order */
  result = SocketQPACK_Encoder_on_section_ack (encoder, 10);
  TEST_ASSERT (result == QPACK_OK, "Section ack 10 should succeed");
  TEST_ASSERT (SocketQPACK_Encoder_known_received_count (encoder) == 10,
               "KRC should be 10");

  result = SocketQPACK_Encoder_on_section_ack (encoder, 25);
  TEST_ASSERT (result == QPACK_OK, "Section ack 25 should succeed");
  TEST_ASSERT (SocketQPACK_Encoder_known_received_count (encoder) == 25,
               "KRC should be 25");

  result = SocketQPACK_Encoder_on_section_ack (encoder, 50);
  TEST_ASSERT (result == QPACK_OK, "Section ack 50 should succeed");
  TEST_ASSERT (SocketQPACK_Encoder_known_received_count (encoder) == 50,
               "KRC should be 50");

  /* Out of order ack (lower RIC) should not decrease KRC */
  result = SocketQPACK_Encoder_on_section_ack (encoder, 30);
  TEST_ASSERT (result == QPACK_OK, "Out of order ack should succeed");
  TEST_ASSERT (SocketQPACK_Encoder_known_received_count (encoder) == 50,
               "KRC should remain 50");

  SocketQPACK_Encoder_free (&encoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================
 */

int
main (void)
{
  printf ("QPACK Known Received Count Unit Tests (RFC 9204 Section 2.1.4)\n");
  printf ("==============================================================\n\n");

  printf ("KRC Initialization Tests:\n");
  test_krc_initialized_to_zero ();

  printf ("\nSection Acknowledgment Tests:\n");
  test_section_ack_updates_krc ();
  test_krc_never_decreases ();
  test_krc_clamped_to_insert_count ();

  printf ("\nInsert Count Increment Tests:\n");
  test_insert_count_increment ();
  test_insert_count_increment_zero_fails ();
  test_insert_count_increment_clamped ();

  printf ("\nis_acknowledged Tests:\n");
  test_is_acknowledged_basic ();

  printf ("\nEdge Case Tests:\n");
  test_null_encoder_handling ();
  test_result_string ();
  test_multiple_acks_with_increasing_ric ();

  printf ("\n==============================================================\n");
  printf ("All QPACK Known Received Count tests passed!\n");

  return 0;
}

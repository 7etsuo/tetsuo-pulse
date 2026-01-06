/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_static.c
 * @brief Unit tests for QPACK Static Table (RFC 9204 Section 3.1)
 *
 * Tests the static table implementation including:
 * - Index-based retrieval (0-based, indices 0-98)
 * - Name+value exact matching
 * - Name-only matching
 * - Case-insensitive name comparison
 * - Invalid index handling
 * - All 99 entries match RFC 9204 Appendix A
 */

#include "http/SocketQPACK.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
 * Index Retrieval Tests
 * ============================================================================
 */

/**
 * Test index 0: :authority (empty value)
 */
static void
test_index_0_authority (void)
{
  SocketQPACK_StaticEntry entry;
  SocketQPACK_Result result;

  printf ("  Index 0 (:authority)... ");

  result = SocketQPACK_static_get (0, &entry);
  TEST_ASSERT (result == SOCKETQPACK_OK, "Should succeed");
  TEST_ASSERT (strcmp (entry.name, ":authority") == 0,
               "Name should be :authority");
  TEST_ASSERT (entry.name_len == 10, "Name length should be 10");
  TEST_ASSERT (entry.value_len == 0, "Value should be empty");

  printf ("PASS\n");
}

/**
 * Test index 17: :method = GET
 */
static void
test_index_17_method_get (void)
{
  SocketQPACK_StaticEntry entry;
  SocketQPACK_Result result;

  printf ("  Index 17 (:method = GET)... ");

  result = SocketQPACK_static_get (17, &entry);
  TEST_ASSERT (result == SOCKETQPACK_OK, "Should succeed");
  TEST_ASSERT (strcmp (entry.name, ":method") == 0, "Name should be :method");
  TEST_ASSERT (entry.name_len == 7, "Name length should be 7");
  TEST_ASSERT (strcmp (entry.value, "GET") == 0, "Value should be GET");
  TEST_ASSERT (entry.value_len == 3, "Value length should be 3");

  printf ("PASS\n");
}

/**
 * Test index 25: :status = 200
 */
static void
test_index_25_status_200 (void)
{
  SocketQPACK_StaticEntry entry;
  SocketQPACK_Result result;

  printf ("  Index 25 (:status = 200)... ");

  result = SocketQPACK_static_get (25, &entry);
  TEST_ASSERT (result == SOCKETQPACK_OK, "Should succeed");
  TEST_ASSERT (strcmp (entry.name, ":status") == 0, "Name should be :status");
  TEST_ASSERT (strcmp (entry.value, "200") == 0, "Value should be 200");

  printf ("PASS\n");
}

/**
 * Test index 98: x-frame-options = sameorigin (last entry)
 */
static void
test_index_98_x_frame_options (void)
{
  SocketQPACK_StaticEntry entry;
  SocketQPACK_Result result;

  printf ("  Index 98 (x-frame-options = sameorigin)... ");

  result = SocketQPACK_static_get (98, &entry);
  TEST_ASSERT (result == SOCKETQPACK_OK, "Should succeed");
  TEST_ASSERT (strcmp (entry.name, "x-frame-options") == 0,
               "Name should be x-frame-options");
  TEST_ASSERT (entry.name_len == 15, "Name length should be 15");
  TEST_ASSERT (strcmp (entry.value, "sameorigin") == 0,
               "Value should be sameorigin");
  TEST_ASSERT (entry.value_len == 10, "Value length should be 10");

  printf ("PASS\n");
}

/**
 * Test out-of-bounds index 99+ should fail
 */
static void
test_index_out_of_bounds (void)
{
  SocketQPACK_StaticEntry entry;
  SocketQPACK_Result result;

  printf ("  Index out of bounds (99+)... ");

  result = SocketQPACK_static_get (99, &entry);
  TEST_ASSERT (result == SOCKETQPACK_ERROR_INVALID_INDEX,
               "Index 99 should fail");

  result = SocketQPACK_static_get (100, &entry);
  TEST_ASSERT (result == SOCKETQPACK_ERROR_INVALID_INDEX,
               "Index 100 should fail");

  result = SocketQPACK_static_get (1000, &entry);
  TEST_ASSERT (result == SOCKETQPACK_ERROR_INVALID_INDEX,
               "Index 1000 should fail");

  printf ("PASS\n");
}

/**
 * Test NULL entry pointer should fail
 */
static void
test_null_entry_pointer (void)
{
  SocketQPACK_Result result;

  printf ("  NULL entry pointer... ");

  result = SocketQPACK_static_get (0, NULL);
  TEST_ASSERT (result == SOCKETQPACK_ERROR_INVALID_INDEX,
               "NULL entry should fail");

  printf ("PASS\n");
}

/* ============================================================================
 * Name+Value Lookup Tests
 * ============================================================================
 */

/**
 * Test exact name+value match
 */
static void
test_find_exact_match (void)
{
  int idx;

  printf ("  Find exact match (:method = GET)... ");

  idx = SocketQPACK_static_find (":method", 7, "GET", 3);
  TEST_ASSERT (idx == 17, "Should find at index 17");

  printf ("PASS\n");
}

/**
 * Test exact match for :status = 200
 */
static void
test_find_status_200 (void)
{
  int idx;

  printf ("  Find exact match (:status = 200)... ");

  idx = SocketQPACK_static_find (":status", 7, "200", 3);
  TEST_ASSERT (idx == 25, "Should find at index 25");

  printf ("PASS\n");
}

/**
 * Test exact match for content-type = application/json
 */
static void
test_find_content_type_json (void)
{
  int idx;

  printf ("  Find exact match (content-type = application/json)... ");

  idx = SocketQPACK_static_find ("content-type", 12, "application/json", 16);
  TEST_ASSERT (idx == 46, "Should find at index 46");

  printf ("PASS\n");
}

/**
 * Test name+value match not found
 */
static void
test_find_not_found (void)
{
  int idx;

  printf ("  Find not found (:method = PATCH)... ");

  idx = SocketQPACK_static_find (":method", 7, "PATCH", 5);
  TEST_ASSERT (idx == -1, "Should return -1 for not found");

  printf ("PASS\n");
}

/* ============================================================================
 * Name-Only Lookup Tests
 * ============================================================================
 */

/**
 * Test name-only match
 */
static void
test_find_name_only (void)
{
  int idx;

  printf ("  Find name only (:method)... ");

  idx = SocketQPACK_static_find_name (":method", 7);
  TEST_ASSERT (idx >= 15 && idx <= 21, "Should find :method (15-21)");

  printf ("PASS\n");
}

/**
 * Test name-only match for content-type
 */
static void
test_find_name_only_content_type (void)
{
  int idx;

  printf ("  Find name only (content-type)... ");

  idx = SocketQPACK_static_find_name ("content-type", 12);
  TEST_ASSERT (idx >= 44 && idx <= 54, "Should find content-type (44-54)");

  printf ("PASS\n");
}

/**
 * Test name-only match not found
 */
static void
test_find_name_not_found (void)
{
  int idx;

  printf ("  Find name not found (x-custom-header)... ");

  idx = SocketQPACK_static_find_name ("x-custom-header", 15);
  TEST_ASSERT (idx == -1, "Should return -1 for not found");

  printf ("PASS\n");
}

/* ============================================================================
 * Case-Insensitive Name Matching Tests
 * ============================================================================
 */

/**
 * Test case-insensitive name matching (uppercase)
 */
static void
test_case_insensitive_uppercase (void)
{
  int idx;

  printf ("  Case insensitive (CONTENT-TYPE)... ");

  idx = SocketQPACK_static_find_name ("CONTENT-TYPE", 12);
  TEST_ASSERT (idx >= 44 && idx <= 54, "Should find CONTENT-TYPE");

  printf ("PASS\n");
}

/**
 * Test case-insensitive name matching (mixed case)
 */
static void
test_case_insensitive_mixed (void)
{
  int idx;

  printf ("  Case insensitive (Content-Type)... ");

  idx = SocketQPACK_static_find_name ("Content-Type", 12);
  TEST_ASSERT (idx >= 44 && idx <= 54, "Should find Content-Type");

  printf ("PASS\n");
}

/**
 * Test case-insensitive with exact value match
 */
static void
test_case_insensitive_with_value (void)
{
  int idx;

  printf ("  Case insensitive name with exact value match... ");

  idx = SocketQPACK_static_find (
      "ACCEPT-ENCODING", 15, "gzip, deflate, br", 17);
  TEST_ASSERT (idx == 31, "Should find at index 31");

  printf ("PASS\n");
}

/* ============================================================================
 * Length Helper Tests
 * ============================================================================
 */

/**
 * Test name_len helper
 */
static void
test_name_len_helper (void)
{
  size_t len;

  printf ("  Name length helper... ");

  len = SocketQPACK_static_name_len (0);
  TEST_ASSERT (len == 10, ":authority name length should be 10");

  len = SocketQPACK_static_name_len (17);
  TEST_ASSERT (len == 7, ":method name length should be 7");

  len = SocketQPACK_static_name_len (99);
  TEST_ASSERT (len == 0, "Invalid index should return 0");

  printf ("PASS\n");
}

/**
 * Test value_len helper
 */
static void
test_value_len_helper (void)
{
  size_t len;

  printf ("  Value length helper... ");

  len = SocketQPACK_static_value_len (0);
  TEST_ASSERT (len == 0, ":authority value length should be 0");

  len = SocketQPACK_static_value_len (17);
  TEST_ASSERT (len == 3, "GET value length should be 3");

  len = SocketQPACK_static_value_len (99);
  TEST_ASSERT (len == 0, "Invalid index should return 0");

  printf ("PASS\n");
}

/* ============================================================================
 * Comprehensive Table Verification
 * ============================================================================
 */

/**
 * Verify all 99 entries have valid name/value strings
 */
static void
test_all_entries_valid (void)
{
  SocketQPACK_StaticEntry entry;
  SocketQPACK_Result result;

  printf ("  All 99 entries valid... ");

  for (size_t i = 0; i < SOCKETQPACK_STATIC_TABLE_SIZE; i++)
    {
      result = SocketQPACK_static_get (i, &entry);
      TEST_ASSERT (result == SOCKETQPACK_OK, "All indices should succeed");
      TEST_ASSERT (entry.name != NULL, "Name should not be NULL");
      TEST_ASSERT (entry.name_len > 0, "Name should not be empty");
      TEST_ASSERT (entry.value != NULL,
                   "Value should not be NULL (can be empty string)");
      TEST_ASSERT (strlen (entry.name) == entry.name_len,
                   "Name length should match strlen");
      TEST_ASSERT (strlen (entry.value) == entry.value_len,
                   "Value length should match strlen");
    }

  printf ("PASS\n");
}

/**
 * Verify specific RFC 9204 Appendix A entries
 */
static void
test_rfc9204_appendix_a_samples (void)
{
  SocketQPACK_StaticEntry entry;
  SocketQPACK_Result result;

  printf ("  RFC 9204 Appendix A samples... ");

  /* Index 1: :path = / */
  result = SocketQPACK_static_get (1, &entry);
  TEST_ASSERT (result == SOCKETQPACK_OK, "Index 1");
  TEST_ASSERT (strcmp (entry.name, ":path") == 0, ":path name");
  TEST_ASSERT (strcmp (entry.value, "/") == 0, ":path value");

  /* Index 26: :status = 304 */
  result = SocketQPACK_static_get (26, &entry);
  TEST_ASSERT (result == SOCKETQPACK_OK, "Index 26");
  TEST_ASSERT (strcmp (entry.name, ":status") == 0, ":status name");
  TEST_ASSERT (strcmp (entry.value, "304") == 0, ":status 304 value");

  /* Index 27: :status = 404 */
  result = SocketQPACK_static_get (27, &entry);
  TEST_ASSERT (result == SOCKETQPACK_OK, "Index 27");
  TEST_ASSERT (strcmp (entry.value, "404") == 0, ":status 404 value");

  /* Index 35: access-control-allow-origin = * */
  result = SocketQPACK_static_get (35, &entry);
  TEST_ASSERT (result == SOCKETQPACK_OK, "Index 35");
  TEST_ASSERT (strcmp (entry.name, "access-control-allow-origin") == 0,
               "access-control-allow-origin name");
  TEST_ASSERT (strcmp (entry.value, "*") == 0, "* value");

  /* Index 83: alt-svc = clear */
  result = SocketQPACK_static_get (83, &entry);
  TEST_ASSERT (result == SOCKETQPACK_OK, "Index 83");
  TEST_ASSERT (strcmp (entry.name, "alt-svc") == 0, "alt-svc name");
  TEST_ASSERT (strcmp (entry.value, "clear") == 0, "clear value");

  printf ("PASS\n");
}

/**
 * Test result string function
 */
static void
test_result_string (void)
{
  const char *str;

  printf ("  Result string... ");

  str = SocketQPACK_result_string (SOCKETQPACK_OK);
  TEST_ASSERT (str != NULL && strlen (str) > 0, "OK string");

  str = SocketQPACK_result_string (SOCKETQPACK_ERROR_INVALID_INDEX);
  TEST_ASSERT (str != NULL && strlen (str) > 0, "Invalid index string");

  str = SocketQPACK_result_string (SOCKETQPACK_ERROR_NOT_FOUND);
  TEST_ASSERT (str != NULL && strlen (str) > 0, "Not found string");

  printf ("PASS\n");
}

/**
 * Test invalid parameter handling
 */
static void
test_invalid_parameters (void)
{
  int idx;

  printf ("  Invalid parameters... ");

  /* NULL name */
  idx = SocketQPACK_static_find (NULL, 5, "value", 5);
  TEST_ASSERT (idx == -1, "NULL name should return -1");

  /* Zero name length */
  idx = SocketQPACK_static_find ("name", 0, "value", 5);
  TEST_ASSERT (idx == -1, "Zero name length should return -1");

  /* NULL name for find_name */
  idx = SocketQPACK_static_find_name (NULL, 5);
  TEST_ASSERT (idx == -1, "NULL name should return -1");

  /* Zero length for find_name */
  idx = SocketQPACK_static_find_name ("name", 0);
  TEST_ASSERT (idx == -1, "Zero length should return -1");

  printf ("PASS\n");
}

/**
 * Test finding entry with empty value
 */
static void
test_find_empty_value (void)
{
  int idx;

  printf ("  Find entry with empty value... ");

  /* :authority has empty value at index 0 */
  idx = SocketQPACK_static_find (":authority", 10, "", 0);
  TEST_ASSERT (idx == 0, "Should find :authority with empty value at index 0");

  /* cookie has empty value at index 5 */
  idx = SocketQPACK_static_find ("cookie", 6, "", 0);
  TEST_ASSERT (idx == 5, "Should find cookie with empty value at index 5");

  printf ("PASS\n");
}

/**
 * Test SIZE_MAX index handling
 */
static void
test_size_max_index (void)
{
  SocketQPACK_StaticEntry entry;
  SocketQPACK_Result result;
  size_t len;

  printf ("  SIZE_MAX index... ");

  result = SocketQPACK_static_get (SIZE_MAX, &entry);
  TEST_ASSERT (result == SOCKETQPACK_ERROR_INVALID_INDEX,
               "SIZE_MAX index should fail");

  len = SocketQPACK_static_name_len (SIZE_MAX);
  TEST_ASSERT (len == 0, "SIZE_MAX name_len should return 0");

  len = SocketQPACK_static_value_len (SIZE_MAX);
  TEST_ASSERT (len == 0, "SIZE_MAX value_len should return 0");

  printf ("PASS\n");
}

/**
 * Test pseudo-header lookups (names starting with ':')
 */
static void
test_pseudo_header_lookups (void)
{
  int idx;

  printf ("  Pseudo-header lookups... ");

  /* All pseudo-headers should be findable */
  idx = SocketQPACK_static_find_name (":authority", 10);
  TEST_ASSERT (idx == 0, ":authority should be at index 0");

  idx = SocketQPACK_static_find_name (":path", 5);
  TEST_ASSERT (idx == 1, ":path should be at index 1");

  idx = SocketQPACK_static_find_name (":method", 7);
  TEST_ASSERT (idx >= 15 && idx <= 21, ":method should be in 15-21");

  idx = SocketQPACK_static_find_name (":scheme", 7);
  TEST_ASSERT (idx >= 22 && idx <= 23, ":scheme should be in 22-23");

  idx = SocketQPACK_static_find_name (":status", 7);
  TEST_ASSERT (idx >= 24 && idx <= 71, ":status should be in valid range");

  /* Non-existent pseudo-header */
  idx = SocketQPACK_static_find_name (":invalid", 8);
  TEST_ASSERT (idx == -1, ":invalid should not be found");

  printf ("PASS\n");
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================
 */

int
main (void)
{
  printf ("QPACK Static Table Unit Tests (RFC 9204 Section 3.1)\n");
  printf ("====================================================\n\n");

  printf ("Index Retrieval Tests:\n");
  test_index_0_authority ();
  test_index_17_method_get ();
  test_index_25_status_200 ();
  test_index_98_x_frame_options ();
  test_index_out_of_bounds ();
  test_null_entry_pointer ();

  printf ("\nName+Value Lookup Tests:\n");
  test_find_exact_match ();
  test_find_status_200 ();
  test_find_content_type_json ();
  test_find_not_found ();

  printf ("\nName-Only Lookup Tests:\n");
  test_find_name_only ();
  test_find_name_only_content_type ();
  test_find_name_not_found ();

  printf ("\nCase-Insensitive Matching Tests:\n");
  test_case_insensitive_uppercase ();
  test_case_insensitive_mixed ();
  test_case_insensitive_with_value ();

  printf ("\nLength Helper Tests:\n");
  test_name_len_helper ();
  test_value_len_helper ();

  printf ("\nComprehensive Verification Tests:\n");
  test_all_entries_valid ();
  test_rfc9204_appendix_a_samples ();
  test_result_string ();
  test_invalid_parameters ();

  printf ("\nEdge Case Tests:\n");
  test_find_empty_value ();
  test_size_max_index ();
  test_pseudo_header_lookups ();

  printf ("\n====================================================\n");
  printf ("All QPACK Static Table tests passed!\n");

  return 0;
}

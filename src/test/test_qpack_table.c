/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_table.c
 * @brief Unit tests for QPACK Dynamic Table (RFC 9204 Section 3.2).
 *
 * Tests cover:
 * - Table creation and destruction
 * - Entry insertion and size calculation
 * - FIFO ordering and eviction
 * - Absolute index lookup
 * - Relative index lookup
 * - Post-base index conversion
 * - Capacity management
 * - Edge cases (empty table, overflow, etc.)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketQPACK-private.h"

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
 * Table Creation Tests
 * ============================================================================
 */

static void
test_table_new_default_config (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;

  printf ("  Table new with default config... ");

  arena = Arena_new ();
  TEST_ASSERT (arena != NULL, "Arena should be created");

  table = SocketQPACK_Table_new (NULL, arena);
  TEST_ASSERT (table != NULL, "Table should be created");
  TEST_ASSERT (SocketQPACK_Table_size (table) == 0, "Initial size should be 0");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 0,
               "Initial count should be 0");
  TEST_ASSERT (SocketQPACK_Table_insert_count (table) == 0,
               "Initial insert_count should be 0");
  TEST_ASSERT (SocketQPACK_Table_capacity (table)
                   == SOCKETQPACK_DEFAULT_MAX_CAPACITY,
               "Capacity should be default");

  SocketQPACK_Table_free (&table);
  TEST_ASSERT (table == NULL, "Table should be NULL after free");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_table_new_custom_config (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_TableConfig config;

  printf ("  Table new with custom config... ");

  arena = Arena_new ();

  SocketQPACK_table_config_defaults (&config);
  config.max_capacity = 1024;
  config.initial_capacity = 512;

  table = SocketQPACK_Table_new (&config, arena);
  TEST_ASSERT (table != NULL, "Table should be created");
  TEST_ASSERT (SocketQPACK_Table_capacity (table) == 512,
               "Capacity should be 512");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Entry Size Tests
 * ============================================================================
 */

static void
test_entry_size_calculation (void)
{
  size_t size;

  printf ("  Entry size calculation... ");

  /* name_len + value_len + 32 = entry size */
  size = SocketQPACK_Table_entry_size (10, 20);
  TEST_ASSERT (size == 62, "10 + 20 + 32 = 62");

  size = SocketQPACK_Table_entry_size (0, 0);
  TEST_ASSERT (size == 32, "0 + 0 + 32 = 32");

  size = SocketQPACK_Table_entry_size (100, 0);
  TEST_ASSERT (size == 132, "100 + 0 + 32 = 132");

  printf ("PASS\n");
}

/* ============================================================================
 * Insert Tests
 * ============================================================================
 */

static void
test_insert_single_entry (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Error err;

  printf ("  Insert single entry... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (NULL, arena);

  err = SocketQPACK_Table_insert (table, "custom-header", 13, "value", 5);
  TEST_ASSERT (err == QPACK_OK, "Insert should succeed");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 1, "Count should be 1");
  TEST_ASSERT (SocketQPACK_Table_insert_count (table) == 1,
               "Insert count should be 1");

  /* Size = 13 + 5 + 32 = 50 */
  TEST_ASSERT (SocketQPACK_Table_size (table) == 50, "Size should be 50");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_insert_multiple_entries (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Error err;

  printf ("  Insert multiple entries... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (NULL, arena);

  err = SocketQPACK_Table_insert (table, "name1", 5, "value1", 6);
  TEST_ASSERT (err == QPACK_OK, "First insert should succeed");

  err = SocketQPACK_Table_insert (table, "name2", 5, "value2", 6);
  TEST_ASSERT (err == QPACK_OK, "Second insert should succeed");

  err = SocketQPACK_Table_insert (table, "name3", 5, "value3", 6);
  TEST_ASSERT (err == QPACK_OK, "Third insert should succeed");

  TEST_ASSERT (SocketQPACK_Table_count (table) == 3, "Count should be 3");
  TEST_ASSERT (SocketQPACK_Table_insert_count (table) == 3,
               "Insert count should be 3");

  /* Each entry = 5 + 6 + 32 = 43, total = 129 */
  TEST_ASSERT (SocketQPACK_Table_size (table) == 129, "Size should be 129");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_insert_empty_strings (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Error err;

  printf ("  Insert with empty name and value... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (NULL, arena);

  err = SocketQPACK_Table_insert (table, "", 0, "", 0);
  TEST_ASSERT (err == QPACK_OK, "Insert should succeed");

  /* Size = 0 + 0 + 32 = 32 */
  TEST_ASSERT (SocketQPACK_Table_size (table) == 32, "Size should be 32");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_insert_entry_too_large (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_TableConfig config;
  SocketQPACK_Error err;

  printf ("  Insert entry larger than capacity... ");

  arena = Arena_new ();

  SocketQPACK_table_config_defaults (&config);
  config.max_capacity = 100;
  config.initial_capacity = 100;

  table = SocketQPACK_Table_new (&config, arena);

  /* Try to insert entry of size 50 + 50 + 32 = 132 > 100 */
  err = SocketQPACK_Table_insert (
      table,
      "12345678901234567890123456789012345678901234567890",
      50,
      "12345678901234567890123456789012345678901234567890",
      50);

  TEST_ASSERT (err == QPACK_ERROR_ENTRY_TOO_LARGE,
               "Should fail with too large");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 0,
               "Table should still be empty");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Eviction Tests
 * ============================================================================
 */

static void
test_eviction_on_insert (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_TableConfig config;
  SocketQPACK_Error err;

  printf ("  Eviction on insert... ");

  arena = Arena_new ();

  SocketQPACK_table_config_defaults (&config);
  config.max_capacity = 100;
  config.initial_capacity = 100;

  table = SocketQPACK_Table_new (&config, arena);

  /* Insert first entry: 10 + 10 + 32 = 52 bytes */
  err = SocketQPACK_Table_insert (table, "header1234", 10, "value12345", 10);
  TEST_ASSERT (err == QPACK_OK, "First insert should succeed");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 1, "Count should be 1");

  /* Insert second entry: same size, should evict first */
  err = SocketQPACK_Table_insert (table, "header5678", 10, "value67890", 10);
  TEST_ASSERT (err == QPACK_OK, "Second insert should succeed");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 1,
               "Count should still be 1 (evicted)");
  TEST_ASSERT (SocketQPACK_Table_insert_count (table) == 2,
               "Insert count should be 2");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_eviction_fifo_order (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_TableConfig config;
  SocketQPACK_Error err;
  const char *name, *value;
  size_t name_len, value_len;

  printf ("  FIFO eviction order... ");

  arena = Arena_new ();

  SocketQPACK_table_config_defaults (&config);
  config.max_capacity = 150;
  config.initial_capacity = 150;

  table = SocketQPACK_Table_new (&config, arena);

  /* Insert 3 entries (each 43 bytes = 5 + 6 + 32), total 129 */
  err = SocketQPACK_Table_insert (table, "name1", 5, "value1", 6);
  TEST_ASSERT (err == QPACK_OK, "First insert");
  err = SocketQPACK_Table_insert (table, "name2", 5, "value2", 6);
  TEST_ASSERT (err == QPACK_OK, "Second insert");
  err = SocketQPACK_Table_insert (table, "name3", 5, "value3", 6);
  TEST_ASSERT (err == QPACK_OK, "Third insert");

  TEST_ASSERT (SocketQPACK_Table_count (table) == 3, "Count should be 3");

  /* Insert fourth entry - should evict oldest (name1) */
  err = SocketQPACK_Table_insert (table, "name4", 5, "value4", 6);
  TEST_ASSERT (err == QPACK_OK, "Fourth insert");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 3,
               "Count should be 3 after eviction");

  /* Verify oldest (name1, abs_idx=0) was evicted */
  err = SocketQPACK_Table_get_absolute (
      table, 0, &name, &name_len, &value, &value_len);
  TEST_ASSERT (err == QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF,
               "Index 0 should be evicted");

  /* Verify name2 (abs_idx=1) is still there */
  err = SocketQPACK_Table_get_absolute (
      table, 1, &name, &name_len, &value, &value_len);
  TEST_ASSERT (err == QPACK_OK, "Index 1 should exist");
  TEST_ASSERT (strncmp (name, "name2", 5) == 0, "Should be name2");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Absolute Index Tests
 * ============================================================================
 */

static void
test_lookup_absolute_index (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Error err;
  const char *name, *value;
  size_t name_len, value_len;

  printf ("  Lookup by absolute index... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (NULL, arena);

  SocketQPACK_Table_insert (table, "header0", 7, "value0", 6);
  SocketQPACK_Table_insert (table, "header1", 7, "value1", 6);
  SocketQPACK_Table_insert (table, "header2", 7, "value2", 6);

  /* Absolute index 0 = first inserted */
  err = SocketQPACK_Table_get_absolute (
      table, 0, &name, &name_len, &value, &value_len);
  TEST_ASSERT (err == QPACK_OK, "Index 0 lookup should succeed");
  TEST_ASSERT (name_len == 7, "Name length should be 7");
  TEST_ASSERT (strncmp (name, "header0", 7) == 0, "Name should be header0");
  TEST_ASSERT (strncmp (value, "value0", 6) == 0, "Value should be value0");

  /* Absolute index 2 = last inserted */
  err = SocketQPACK_Table_get_absolute (
      table, 2, &name, &name_len, &value, &value_len);
  TEST_ASSERT (err == QPACK_OK, "Index 2 lookup should succeed");
  TEST_ASSERT (strncmp (name, "header2", 7) == 0, "Name should be header2");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_lookup_absolute_evicted (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_TableConfig config;
  SocketQPACK_Error err;
  const char *name, *value;
  size_t name_len, value_len;

  printf ("  Lookup evicted absolute index... ");

  arena = Arena_new ();

  SocketQPACK_table_config_defaults (&config);
  config.max_capacity = 100;
  config.initial_capacity = 100;

  table = SocketQPACK_Table_new (&config, arena);

  /* Insert and then evict by inserting more */
  SocketQPACK_Table_insert (table, "header0", 7, "value012345678", 14);
  /* Size = 7 + 14 + 32 = 53 */
  SocketQPACK_Table_insert (table, "header1", 7, "value112345678", 14);
  /* Total would be 106 > 100, so header0 evicted */

  err = SocketQPACK_Table_get_absolute (
      table, 0, &name, &name_len, &value, &value_len);
  TEST_ASSERT (err == QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF,
               "Evicted index should fail");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_lookup_absolute_future (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Error err;
  const char *name, *value;
  size_t name_len, value_len;

  printf ("  Lookup future absolute index... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (NULL, arena);

  SocketQPACK_Table_insert (table, "header", 6, "value", 5);
  /* insert_count = 1, so index 1 is future */

  err = SocketQPACK_Table_get_absolute (
      table, 1, &name, &name_len, &value, &value_len);
  TEST_ASSERT (err == QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF,
               "Future index should fail");

  err = SocketQPACK_Table_get_absolute (
      table, 100, &name, &name_len, &value, &value_len);
  TEST_ASSERT (err == QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF,
               "Far future index should fail");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Relative Index Tests
 * ============================================================================
 */

static void
test_lookup_relative_index (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Error err;
  const char *name, *value;
  size_t name_len, value_len;

  printf ("  Lookup by relative index... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (NULL, arena);

  SocketQPACK_Table_insert (table, "oldest", 6, "val0", 4);
  SocketQPACK_Table_insert (table, "middle", 6, "val1", 4);
  SocketQPACK_Table_insert (table, "newest", 6, "val2", 4);

  /* Relative index 0 = most recent (newest) */
  err = SocketQPACK_Table_get_relative (
      table, 0, &name, &name_len, &value, &value_len);
  TEST_ASSERT (err == QPACK_OK, "Rel 0 should succeed");
  TEST_ASSERT (strncmp (name, "newest", 6) == 0, "Rel 0 should be newest");

  /* Relative index 1 = second most recent (middle) */
  err = SocketQPACK_Table_get_relative (
      table, 1, &name, &name_len, &value, &value_len);
  TEST_ASSERT (err == QPACK_OK, "Rel 1 should succeed");
  TEST_ASSERT (strncmp (name, "middle", 6) == 0, "Rel 1 should be middle");

  /* Relative index 2 = oldest */
  err = SocketQPACK_Table_get_relative (
      table, 2, &name, &name_len, &value, &value_len);
  TEST_ASSERT (err == QPACK_OK, "Rel 2 should succeed");
  TEST_ASSERT (strncmp (name, "oldest", 6) == 0, "Rel 2 should be oldest");

  /* Relative index 3 = out of range */
  err = SocketQPACK_Table_get_relative (
      table, 3, &name, &name_len, &value, &value_len);
  TEST_ASSERT (err == QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF,
               "Rel 3 should fail");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Post-Base Index Tests
 * ============================================================================
 */

static void
test_post_base_to_absolute (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Error err;
  size_t abs_index;

  printf ("  Post-base to absolute conversion... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (NULL, arena);

  /* base = 5, post_base_index = 3 -> absolute = 8 */
  err = SocketQPACK_Table_post_base_to_absolute (table, 5, 3, &abs_index);
  TEST_ASSERT (err == QPACK_OK, "Conversion should succeed");
  TEST_ASSERT (abs_index == 8, "5 + 3 = 8");

  /* base = 0, post_base_index = 0 -> absolute = 0 */
  err = SocketQPACK_Table_post_base_to_absolute (table, 0, 0, &abs_index);
  TEST_ASSERT (err == QPACK_OK, "Zero conversion should succeed");
  TEST_ASSERT (abs_index == 0, "0 + 0 = 0");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Capacity Tests
 * ============================================================================
 */

static void
test_set_capacity_evicts (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_TableConfig config;

  printf ("  Set capacity triggers eviction... ");

  arena = Arena_new ();

  SocketQPACK_table_config_defaults (&config);
  config.max_capacity = 200;
  config.initial_capacity = 200;

  table = SocketQPACK_Table_new (&config, arena);

  /* Insert entries totaling ~130 bytes */
  SocketQPACK_Table_insert (table, "name1", 5, "value1", 6); /* 43 */
  SocketQPACK_Table_insert (table, "name2", 5, "value2", 6); /* 43 */
  SocketQPACK_Table_insert (table, "name3", 5, "value3", 6); /* 43 */

  TEST_ASSERT (SocketQPACK_Table_count (table) == 3, "Should have 3 entries");
  TEST_ASSERT (SocketQPACK_Table_size (table) == 129, "Size should be 129");

  /* Reduce capacity to 100 - should evict oldest */
  SocketQPACK_Table_set_capacity (table, 100);

  TEST_ASSERT (SocketQPACK_Table_capacity (table) == 100,
               "Capacity should be 100");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 2,
               "Should have 2 entries after eviction");
  TEST_ASSERT (SocketQPACK_Table_size (table) == 86, "Size should be 86");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_set_capacity_zero (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;

  printf ("  Set capacity to zero clears table... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (NULL, arena);

  SocketQPACK_Table_insert (table, "name", 4, "value", 5);
  SocketQPACK_Table_insert (table, "name2", 5, "value2", 6);

  TEST_ASSERT (SocketQPACK_Table_count (table) == 2, "Should have 2 entries");

  SocketQPACK_Table_set_capacity (table, 0);

  TEST_ASSERT (SocketQPACK_Table_count (table) == 0, "Should be empty");
  TEST_ASSERT (SocketQPACK_Table_size (table) == 0, "Size should be 0");
  TEST_ASSERT (SocketQPACK_Table_insert_count (table) == 2,
               "Insert count unchanged");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Edge Case Tests
 * ============================================================================
 */

static void
test_empty_table_lookup (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Error err;
  const char *name, *value;
  size_t name_len, value_len;

  printf ("  Lookup in empty table... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (NULL, arena);

  err = SocketQPACK_Table_get_absolute (
      table, 0, &name, &name_len, &value, &value_len);
  TEST_ASSERT (err == QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF,
               "Empty table abs lookup should fail");

  err = SocketQPACK_Table_get_relative (
      table, 0, &name, &name_len, &value, &value_len);
  TEST_ASSERT (err == QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF,
               "Empty table rel lookup should fail");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_insert_count_never_decreases (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_TableConfig config;
  size_t count_before, count_after;

  printf ("  Insert count never decreases after eviction... ");

  arena = Arena_new ();

  SocketQPACK_table_config_defaults (&config);
  config.max_capacity = 100;
  config.initial_capacity = 100;

  table = SocketQPACK_Table_new (&config, arena);

  /* Insert entries that will cause eviction */
  SocketQPACK_Table_insert (table, "name1", 5, "value1", 6);
  count_before = SocketQPACK_Table_insert_count (table);

  SocketQPACK_Table_insert (table, "name2", 5, "value2", 6);
  count_after = SocketQPACK_Table_insert_count (table);

  TEST_ASSERT (count_after > count_before, "Insert count should increase");

  /* Clear table by setting capacity to 0 */
  SocketQPACK_Table_set_capacity (table, 0);

  TEST_ASSERT (SocketQPACK_Table_insert_count (table) == count_after,
               "Insert count should not change after clear");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_error_string (void)
{
  printf ("  Error string lookup... ");

  TEST_ASSERT (strcmp (SocketQPACK_error_string (QPACK_OK), "OK") == 0,
               "OK string");
  TEST_ASSERT (SocketQPACK_error_string (QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF)
                   != NULL,
               "Invalid ref string");
  TEST_ASSERT (SocketQPACK_error_string (QPACK_ERROR_ENTRY_TOO_LARGE) != NULL,
               "Too large string");
  TEST_ASSERT (SocketQPACK_error_string ((SocketQPACK_Error)999) != NULL,
               "Unknown error string");

  printf ("PASS\n");
}

/* ============================================================================
 * Additional Edge Case Tests
 * ============================================================================
 */

/**
 * @brief Test entry size overflow protection.
 */
static void
test_entry_size_overflow (void)
{
  printf ("  Entry size overflow protection... ");

  /* SIZE_MAX values should return SIZE_MAX to indicate overflow */
  size_t result = SocketQPACK_Table_entry_size (SIZE_MAX, 0);
  TEST_ASSERT (result == SIZE_MAX, "overflow with SIZE_MAX name_len");

  result = SocketQPACK_Table_entry_size (0, SIZE_MAX);
  TEST_ASSERT (result == SIZE_MAX, "overflow with SIZE_MAX value_len");

  result = SocketQPACK_Table_entry_size (SIZE_MAX, SIZE_MAX);
  TEST_ASSERT (result == SIZE_MAX, "overflow with both SIZE_MAX");

  /* Large but valid values that would overflow when added */
  result = SocketQPACK_Table_entry_size (SIZE_MAX - 10, 100);
  TEST_ASSERT (result == SIZE_MAX, "overflow with near-max values");

  printf ("PASS\n");
}

/**
 * @brief Test NULL table parameter handling.
 */
static void
test_null_table_parameters (void)
{
  printf ("  NULL table parameter handling... ");

  /* All table functions should handle NULL gracefully */
  TEST_ASSERT (SocketQPACK_Table_capacity (NULL) == 0,
               "capacity with NULL table");
  TEST_ASSERT (SocketQPACK_Table_size (NULL) == 0, "size with NULL table");
  TEST_ASSERT (SocketQPACK_Table_count (NULL) == 0, "count with NULL table");
  TEST_ASSERT (SocketQPACK_Table_insert_count (NULL) == 0,
               "insert_count with NULL table");

  /* set_capacity with NULL should fail gracefully */
  SocketQPACK_Error err = SocketQPACK_Table_set_capacity (NULL, 1000);
  TEST_ASSERT (err == QPACK_ERROR_ALLOCATION_FAILED,
               "set_capacity with NULL table");

  /* insert with NULL table should fail */
  err = SocketQPACK_Table_insert (NULL, "name", 4, "value", 5);
  TEST_ASSERT (err == QPACK_ERROR_ALLOCATION_FAILED,
               "insert with NULL table");

  printf ("PASS\n");
}

/**
 * @brief Test NULL output pointer handling in lookup functions.
 */
static void
test_null_output_pointers (void)
{
  printf ("  NULL output pointer handling... ");

  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table = SocketQPACK_Table_new (NULL, arena);

  /* Insert an entry to lookup */
  SocketQPACK_Error err
      = SocketQPACK_Table_insert (table, "test", 4, "value", 5);
  TEST_ASSERT (err == QPACK_OK, "insert for NULL pointer test");

  const char *name, *value;
  size_t name_len, value_len;

  /* Test get_absolute with NULL outputs */
  err = SocketQPACK_Table_get_absolute (table, 0, NULL, &name_len, &value,
                                        &value_len);
  TEST_ASSERT (err == QPACK_ERROR_ALLOCATION_FAILED, "NULL name pointer");

  err = SocketQPACK_Table_get_absolute (table, 0, &name, NULL, &value,
                                        &value_len);
  TEST_ASSERT (err == QPACK_ERROR_ALLOCATION_FAILED, "NULL name_len pointer");

  err = SocketQPACK_Table_get_absolute (table, 0, &name, &name_len, NULL,
                                        &value_len);
  TEST_ASSERT (err == QPACK_ERROR_ALLOCATION_FAILED, "NULL value pointer");

  err = SocketQPACK_Table_get_absolute (table, 0, &name, &name_len, &value,
                                        NULL);
  TEST_ASSERT (err == QPACK_ERROR_ALLOCATION_FAILED, "NULL value_len pointer");

  /* Test get_relative with NULL outputs */
  err = SocketQPACK_Table_get_relative (table, 0, NULL, &name_len, &value,
                                        &value_len);
  TEST_ASSERT (err == QPACK_ERROR_ALLOCATION_FAILED,
               "NULL name in get_relative");

  /* Test post_base_to_absolute with NULL output */
  err = SocketQPACK_Table_post_base_to_absolute (table, 0, 0, NULL);
  TEST_ASSERT (err == QPACK_ERROR_ALLOCATION_FAILED,
               "NULL abs_index in post_base");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * @brief Test post-base index overflow protection.
 */
static void
test_post_base_overflow (void)
{
  printf ("  Post-base overflow protection... ");

  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table = SocketQPACK_Table_new (NULL, arena);

  size_t abs_index;
  SocketQPACK_Error err;

  /* Test overflow: SIZE_MAX + 1 would overflow */
  err = SocketQPACK_Table_post_base_to_absolute (table, SIZE_MAX, 1,
                                                 &abs_index);
  TEST_ASSERT (err == QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF,
               "overflow SIZE_MAX + 1");

  /* Test overflow: large values that sum to overflow */
  err = SocketQPACK_Table_post_base_to_absolute (table, SIZE_MAX / 2 + 1,
                                                 SIZE_MAX / 2 + 1, &abs_index);
  TEST_ASSERT (err == QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF,
               "overflow large sums");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * @brief Test capacity clamping to max_capacity.
 */
static void
test_capacity_clamping (void)
{
  printf ("  Capacity clamping to max... ");

  Arena_T arena = Arena_new ();

  /* Create table with small max_capacity */
  SocketQPACK_TableConfig config = { .max_capacity = 500,
                                     .initial_capacity = 500 };
  SocketQPACK_Table_T table = SocketQPACK_Table_new (&config, arena);

  /* Try to set capacity beyond max - should be clamped */
  SocketQPACK_Error err = SocketQPACK_Table_set_capacity (table, 1000);
  TEST_ASSERT (err == QPACK_OK, "set_capacity beyond max");
  TEST_ASSERT (SocketQPACK_Table_capacity (table) == 500,
               "capacity clamped to max");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * @brief Test eviction of multiple entries at once.
 */
static void
test_multi_entry_eviction (void)
{
  printf ("  Multi-entry eviction... ");

  Arena_T arena = Arena_new ();

  /* Small capacity to force eviction */
  SocketQPACK_TableConfig config = { .max_capacity = 200,
                                     .initial_capacity = 200 };
  SocketQPACK_Table_T table = SocketQPACK_Table_new (&config, arena);

  /* Insert several small entries */
  /* Entry size = 4 + 5 + 32 = 41 bytes each */
  SocketQPACK_Table_insert (table, "aa", 2, "bb", 2);   /* 36 bytes, idx 0 */
  SocketQPACK_Table_insert (table, "cc", 2, "dd", 2);   /* 36 bytes, idx 1 */
  SocketQPACK_Table_insert (table, "ee", 2, "ff", 2);   /* 36 bytes, idx 2 */
  SocketQPACK_Table_insert (table, "gg", 2, "hh", 2);   /* 36 bytes, idx 3 */
  SocketQPACK_Table_insert (table, "ii", 2, "jj", 2);   /* 36 bytes, idx 4 */
  TEST_ASSERT (SocketQPACK_Table_count (table) == 5, "5 entries inserted");

  /* Insert a larger entry that forces eviction of multiple entries */
  /* Entry size = 50 + 50 + 32 = 132 bytes */
  char big_name[51], big_value[51];
  memset (big_name, 'X', 50);
  big_name[50] = '\0';
  memset (big_value, 'Y', 50);
  big_value[50] = '\0';

  SocketQPACK_Error err
      = SocketQPACK_Table_insert (table, big_name, 50, big_value, 50);
  TEST_ASSERT (err == QPACK_OK, "large entry insert");

  /* Should have evicted oldest entries to make room */
  /* Verify oldest entries were evicted */
  const char *name, *value;
  size_t name_len, value_len;

  err = SocketQPACK_Table_get_absolute (table, 0, &name, &name_len, &value,
                                        &value_len);
  TEST_ASSERT (err == QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF,
               "entry 0 evicted");

  err = SocketQPACK_Table_get_absolute (table, 1, &name, &name_len, &value,
                                        &value_len);
  TEST_ASSERT (err == QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF,
               "entry 1 evicted");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * @brief Test NULL string with non-zero length rejection.
 */
static void
test_null_string_with_length (void)
{
  printf ("  NULL string with non-zero length... ");

  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table = SocketQPACK_Table_new (NULL, arena);

  /* NULL name with non-zero length should fail */
  SocketQPACK_Error err = SocketQPACK_Table_insert (table, NULL, 5, "value", 5);
  TEST_ASSERT (err == QPACK_ERROR_ALLOCATION_FAILED,
               "NULL name with length rejected");

  /* NULL value with non-zero length should fail */
  err = SocketQPACK_Table_insert (table, "name", 4, NULL, 5);
  TEST_ASSERT (err == QPACK_ERROR_ALLOCATION_FAILED,
               "NULL value with length rejected");

  /* NULL with zero length should be OK (empty string) */
  err = SocketQPACK_Table_insert (table, "", 0, "", 0);
  TEST_ASSERT (err == QPACK_OK, "empty strings OK");

  SocketQPACK_Table_free (&table);
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
  printf ("QPACK Dynamic Table Unit Tests (RFC 9204 Section 3.2)\n");
  printf ("=====================================================\n\n");

  printf ("Table Creation Tests:\n");
  test_table_new_default_config ();
  test_table_new_custom_config ();

  printf ("\nEntry Size Tests:\n");
  test_entry_size_calculation ();

  printf ("\nInsert Tests:\n");
  test_insert_single_entry ();
  test_insert_multiple_entries ();
  test_insert_empty_strings ();
  test_insert_entry_too_large ();

  printf ("\nEviction Tests:\n");
  test_eviction_on_insert ();
  test_eviction_fifo_order ();

  printf ("\nAbsolute Index Tests:\n");
  test_lookup_absolute_index ();
  test_lookup_absolute_evicted ();
  test_lookup_absolute_future ();

  printf ("\nRelative Index Tests:\n");
  test_lookup_relative_index ();

  printf ("\nPost-Base Index Tests:\n");
  test_post_base_to_absolute ();

  printf ("\nCapacity Tests:\n");
  test_set_capacity_evicts ();
  test_set_capacity_zero ();

  printf ("\nEdge Case Tests:\n");
  test_empty_table_lookup ();
  test_insert_count_never_decreases ();
  test_error_string ();
  test_entry_size_overflow ();
  test_null_table_parameters ();
  test_null_output_pointers ();
  test_post_base_overflow ();
  test_capacity_clamping ();
  test_multi_entry_eviction ();
  test_null_string_with_length ();

  printf ("\n=====================================================\n");
  printf ("All QPACK Dynamic Table tests passed!\n");

  return 0;
}

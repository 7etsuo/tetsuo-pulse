/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_hashtable.c - Generic hash table unit tests
 * Tests for the HashTable module.
 * Covers creation, insert, find, remove, iteration, and edge cases.
 */

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/HashTable.h"
#include "core/SocketUtil.h"
#include "test/Test.h"

/* ============================================================================
 * Test Entry Type
 * ============================================================================
 */

typedef struct TestEntry
{
  char key[64];
  int value;
  struct TestEntry *next;
} TestEntry;

/* ============================================================================
 * Hash Table Callbacks
 * ============================================================================
 */

static unsigned
test_hash (const void *key, unsigned seed, unsigned table_size)
{
  /* DJB2 hash with seed mixing */
  const char *str = (const char *)key;
  unsigned hash = 5381 ^ seed;
  int c;

  while ((c = *str++) != '\0')
    hash = ((hash << 5) + hash) + (unsigned)c;

  return table_size > 0 ? hash % table_size : hash;
}

static int
test_compare (const void *entry, const void *key)
{
  const TestEntry *e = (const TestEntry *)entry;
  return strcmp (e->key, (const char *)key);
}

static void **
test_next_ptr (void *entry)
{
  TestEntry *e = (TestEntry *)entry;
  return (void **)&e->next;
}

static HashTable_Config
make_config (size_t buckets)
{
  HashTable_Config config = { .bucket_count = buckets,
                              .hash_seed = 12345,
                              .hash = test_hash,
                              .compare = test_compare,
                              .next_ptr = test_next_ptr };
  return config;
}

static TestEntry *
make_entry (const char *key, int value)
{
  TestEntry *entry = calloc (1, sizeof (TestEntry));
  strncpy (entry->key, key, sizeof (entry->key) - 1);
  entry->value = value;
  entry->next = NULL;
  return entry;
}

/* ============================================================================
 * Basic Lifecycle Tests
 * ============================================================================
 */

TEST (hashtable_new_creates_table)
{
  HashTable_Config config = make_config (16);
  HashTable_T table = HashTable_new (NULL, &config);

  ASSERT_NOT_NULL (table);
  ASSERT_EQ (HashTable_bucket_count (table), (size_t)16);
  ASSERT_EQ (HashTable_seed (table), 12345u);

  HashTable_free (&table);
  ASSERT_NULL (table);
}

TEST (hashtable_new_with_arena)
{
  Arena_T arena = Arena_new ();
  HashTable_Config config = make_config (32);

  HashTable_T table = HashTable_new (arena, &config);
  ASSERT_NOT_NULL (table);
  ASSERT_EQ (HashTable_bucket_count (table), (size_t)32);

  /* Free with arena - should not crash */
  HashTable_free (&table);
  ASSERT_NULL (table);

  Arena_dispose (&arena);
}

TEST (hashtable_free_null_safe)
{
  HashTable_T table = NULL;
  HashTable_free (&table); /* Should not crash */
  HashTable_free (NULL);   /* Should not crash */
}

/* ============================================================================
 * Insert and Find Tests
 * ============================================================================
 */

TEST (hashtable_insert_and_find)
{
  HashTable_Config config = make_config (16);
  HashTable_T table = HashTable_new (NULL, &config);

  TestEntry *entry = make_entry ("test_key", 42);
  HashTable_insert (table, entry, entry->key);

  TestEntry *found = HashTable_find (table, "test_key", NULL);
  ASSERT_NOT_NULL (found);
  ASSERT_EQ (found->value, 42);
  ASSERT (strcmp (found->key, "test_key") == 0);

  HashTable_free (&table);
  free (entry);
}

TEST (hashtable_find_not_found)
{
  HashTable_Config config = make_config (16);
  HashTable_T table = HashTable_new (NULL, &config);

  TestEntry *entry = make_entry ("existing", 1);
  HashTable_insert (table, entry, entry->key);

  TestEntry *found = HashTable_find (table, "nonexistent", NULL);
  ASSERT_NULL (found);

  HashTable_free (&table);
  free (entry);
}

TEST (hashtable_multiple_entries)
{
  HashTable_Config config = make_config (16);
  HashTable_T table = HashTable_new (NULL, &config);

  TestEntry *entries[10];
  for (int i = 0; i < 10; i++)
    {
      char key[32];
      snprintf (key, sizeof (key), "key_%d", i);
      entries[i] = make_entry (key, i * 10);
      HashTable_insert (table, entries[i], entries[i]->key);
    }

  /* Verify all entries can be found */
  for (int i = 0; i < 10; i++)
    {
      char key[32];
      snprintf (key, sizeof (key), "key_%d", i);
      TestEntry *found = HashTable_find (table, key, NULL);
      ASSERT_NOT_NULL (found);
      ASSERT_EQ (found->value, i * 10);
    }

  HashTable_free (&table);
  for (int i = 0; i < 10; i++)
    free (entries[i]);
}

/* ============================================================================
 * Collision Handling Tests
 * ============================================================================
 */

TEST (hashtable_collision_handling)
{
  /* Use small bucket count to force collisions */
  HashTable_Config config = make_config (2);
  HashTable_T table = HashTable_new (NULL, &config);

  TestEntry *entries[5];
  for (int i = 0; i < 5; i++)
    {
      char key[32];
      snprintf (key, sizeof (key), "collision_%d", i);
      entries[i] = make_entry (key, i);
      HashTable_insert (table, entries[i], entries[i]->key);
    }

  /* All entries should be findable despite collisions */
  for (int i = 0; i < 5; i++)
    {
      char key[32];
      snprintf (key, sizeof (key), "collision_%d", i);
      TestEntry *found = HashTable_find (table, key, NULL);
      ASSERT_NOT_NULL (found);
      ASSERT_EQ (found->value, i);
    }

  HashTable_free (&table);
  for (int i = 0; i < 5; i++)
    free (entries[i]);
}

/* ============================================================================
 * Remove Tests
 * ============================================================================
 */

TEST (hashtable_remove_head)
{
  HashTable_Config config = make_config (16);
  HashTable_T table = HashTable_new (NULL, &config);

  TestEntry *entry = make_entry ("remove_me", 99);
  HashTable_insert (table, entry, entry->key);

  void *prev = NULL;
  TestEntry *found = HashTable_find (table, "remove_me", &prev);
  ASSERT_NOT_NULL (found);
  ASSERT_NULL (prev); /* Entry is at bucket head */

  HashTable_remove (table, found, prev, found->key);

  /* Should not be findable now */
  found = HashTable_find (table, "remove_me", NULL);
  ASSERT_NULL (found);

  HashTable_free (&table);
  free (entry);
}

TEST (hashtable_remove_middle)
{
  /* Use small bucket count to force collisions */
  HashTable_Config config = make_config (1);
  HashTable_T table = HashTable_new (NULL, &config);

  TestEntry *e1 = make_entry ("first", 1);
  TestEntry *e2 = make_entry ("second", 2);
  TestEntry *e3 = make_entry ("third", 3);

  HashTable_insert (table, e1, e1->key);
  HashTable_insert (table, e2, e2->key);
  HashTable_insert (table, e3, e3->key);

  /* Find middle entry (e2) */
  void *prev = NULL;
  TestEntry *found = HashTable_find (table, "second", &prev);
  ASSERT_NOT_NULL (found);
  ASSERT_EQ (found->value, 2);

  HashTable_remove (table, found, prev, found->key);

  /* e2 should not be findable */
  found = HashTable_find (table, "second", NULL);
  ASSERT_NULL (found);

  /* e1 and e3 should still be findable */
  found = HashTable_find (table, "first", NULL);
  ASSERT_NOT_NULL (found);
  found = HashTable_find (table, "third", NULL);
  ASSERT_NOT_NULL (found);

  HashTable_free (&table);
  free (e1);
  free (e2);
  free (e3);
}

/* ============================================================================
 * Iteration Tests
 * ============================================================================
 */

struct IterContext
{
  int count;
  int sum;
};

static int
iter_callback (void *entry, void *context)
{
  TestEntry *e = (TestEntry *)entry;
  struct IterContext *ctx = (struct IterContext *)context;
  ctx->count++;
  ctx->sum += e->value;
  return 0; /* Continue */
}

static int
iter_early_exit (void *entry, void *context)
{
  (void)entry;
  struct IterContext *ctx = (struct IterContext *)context;
  ctx->count++;
  return ctx->count >= 3 ? 1 : 0; /* Stop after 3 */
}

TEST (hashtable_foreach)
{
  HashTable_Config config = make_config (16);
  HashTable_T table = HashTable_new (NULL, &config);

  TestEntry *entries[5];
  int expected_sum = 0;
  for (int i = 0; i < 5; i++)
    {
      char key[32];
      snprintf (key, sizeof (key), "iter_%d", i);
      entries[i] = make_entry (key, i + 1);
      expected_sum += i + 1;
      HashTable_insert (table, entries[i], entries[i]->key);
    }

  struct IterContext ctx = { 0, 0 };
  HashTable_foreach (table, iter_callback, &ctx);

  ASSERT_EQ (ctx.count, 5);
  ASSERT_EQ (ctx.sum, expected_sum);

  HashTable_free (&table);
  for (int i = 0; i < 5; i++)
    free (entries[i]);
}

TEST (hashtable_foreach_early_exit)
{
  HashTable_Config config = make_config (16);
  HashTable_T table = HashTable_new (NULL, &config);

  TestEntry *entries[5];
  for (int i = 0; i < 5; i++)
    {
      char key[32];
      snprintf (key, sizeof (key), "exit_%d", i);
      entries[i] = make_entry (key, i);
      HashTable_insert (table, entries[i], entries[i]->key);
    }

  struct IterContext ctx = { 0, 0 };
  HashTable_foreach (table, iter_early_exit, &ctx);

  ASSERT_EQ (ctx.count, 3); /* Should stop after 3 */

  HashTable_free (&table);
  for (int i = 0; i < 5; i++)
    free (entries[i]);
}

/* ============================================================================
 * Clear Test
 * ============================================================================
 */

TEST (hashtable_clear)
{
  HashTable_Config config = make_config (16);
  HashTable_T table = HashTable_new (NULL, &config);

  TestEntry *entries[3];
  for (int i = 0; i < 3; i++)
    {
      char key[32];
      snprintf (key, sizeof (key), "clear_%d", i);
      entries[i] = make_entry (key, i);
      HashTable_insert (table, entries[i], entries[i]->key);
    }

  HashTable_clear (table);

  /* All entries should be gone from table's perspective */
  for (int i = 0; i < 3; i++)
    {
      char key[32];
      snprintf (key, sizeof (key), "clear_%d", i);
      TestEntry *found = HashTable_find (table, key, NULL);
      ASSERT_NULL (found);
    }

  HashTable_free (&table);
  /* Caller still needs to free entries */
  for (int i = 0; i < 3; i++)
    free (entries[i]);
}

/* ============================================================================
 * Exception Tests
 * ============================================================================
 */

TEST (hashtable_null_config_raises)
{
  volatile int raised = 0;
  TRY
  {
    HashTable_new (NULL, NULL);
  }
  EXCEPT (HashTable_Failed)
  {
    raised = 1;
  }
  END_TRY;
  ASSERT_EQ (raised, 1);
}

TEST (hashtable_zero_buckets_raises)
{
  volatile int raised = 0;
  HashTable_Config config = make_config (0);

  TRY
  {
    HashTable_new (NULL, &config);
  }
  EXCEPT (HashTable_Failed)
  {
    raised = 1;
  }
  END_TRY;
  ASSERT_EQ (raised, 1);
}

TEST (hashtable_null_hash_raises)
{
  volatile int raised = 0;
  HashTable_Config config = make_config (16);
  config.hash = NULL;

  TRY
  {
    HashTable_new (NULL, &config);
  }
  EXCEPT (HashTable_Failed)
  {
    raised = 1;
  }
  END_TRY;
  ASSERT_EQ (raised, 1);
}

TEST (hashtable_bucket_count_overflow_raises)
{
  volatile int raised = 0;
  HashTable_Config config = make_config (16);
  /* Set bucket_count to exceed UINT_MAX (4,294,967,295) */
  config.bucket_count = (size_t)UINT_MAX + 1;

  TRY
  {
    HashTable_new (NULL, &config);
  }
  EXCEPT (HashTable_Failed)
  {
    raised = 1;
  }
  END_TRY;
  ASSERT_EQ (raised, 1);
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

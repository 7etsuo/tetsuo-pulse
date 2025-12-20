/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * HashTable.c - Generic Intrusive Hash Table Implementation
 *
 * Part of the Socket Library
 *
 * Provides a reusable hash table with:
 * - Chained collision handling using caller's next pointer
 * - Configurable hash and comparison functions
 * - Arena or malloc allocation for bucket array
 * - O(1) average insert, find, remove operations
 *
 * Thread Safety:
 * - NOT built-in (caller must provide synchronization)
 * - New/free are safe across threads (independent instances)
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "core/HashTable.h"
#include "core/SocketUtil.h"

#define T HashTable_T

/* ============================================================================
 * Exception Definitions
 * ============================================================================
 */

const Except_T HashTable_Failed
    = { &HashTable_Failed, "Hash table operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (HashTable);

/* ============================================================================
 * Internal Structure
 * ============================================================================
 */

/**
 * struct T - Hash table internal structure
 */
struct T
{
  void **buckets;                  /**< Array of bucket head pointers */
  size_t bucket_count;             /**< Number of buckets */
  unsigned hash_seed;              /**< Hash seed for randomization */
  HashTable_HashFunc hash;         /**< Hash function */
  HashTable_CompareFunc compare;   /**< Key comparison function */
  HashTable_GetNextPtrFunc next_ptr; /**< Get entry's next pointer */
  Arena_T arena;                   /**< Arena for allocation (NULL=malloc) */
};

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * validate_config - Validate configuration parameters
 * @config: Configuration to validate
 *
 * Raises: HashTable_Failed on invalid config
 */
static void
validate_config (const HashTable_Config *config)
{
  if (config == NULL)
    SOCKET_RAISE_MSG (HashTable, HashTable_Failed, "NULL configuration");

  if (config->bucket_count == 0)
    SOCKET_RAISE_MSG (HashTable, HashTable_Failed,
                      "bucket_count must be > 0");

  if (config->hash == NULL)
    SOCKET_RAISE_MSG (HashTable, HashTable_Failed, "hash function required");

  if (config->compare == NULL)
    SOCKET_RAISE_MSG (HashTable, HashTable_Failed,
                      "compare function required");

  if (config->next_ptr == NULL)
    SOCKET_RAISE_MSG (HashTable, HashTable_Failed,
                      "next_ptr function required");
}

/**
 * allocate_buckets - Allocate bucket array
 * @arena: Arena or NULL for malloc
 * @count: Number of buckets
 *
 * Returns: Zeroed bucket array or NULL on failure
 */
static void **
allocate_buckets (Arena_T arena, size_t count)
{
  void **buckets;

  if (arena != NULL)
    buckets = Arena_calloc (arena, count, sizeof (void *), __FILE__, __LINE__);
  else
    buckets = calloc (count, sizeof (void *));

  return buckets;
}

/**
 * compute_bucket - Compute bucket index for key
 * @table: Hash table instance
 * @key: Key to hash
 *
 * Returns: Bucket index
 */
static unsigned
compute_bucket (T table, const void *key)
{
  return table->hash (key, table->hash_seed, (unsigned)table->bucket_count);
}

/**
 * get_next - Get next entry in chain
 * @table: Hash table instance
 * @entry: Current entry
 *
 * Returns: Next entry or NULL
 */
static void *
get_next (T table, void *entry)
{
  void **next_ptr = table->next_ptr (entry);
  return *next_ptr;
}

/**
 * set_next - Set next entry in chain
 * @table: Hash table instance
 * @entry: Entry to modify
 * @next: Value to set as next
 */
static void
set_next (T table, void *entry, void *next)
{
  void **next_ptr = table->next_ptr (entry);
  *next_ptr = next;
}

/* ============================================================================
 * Public API - Lifecycle
 * ============================================================================
 */

T
HashTable_new (Arena_T arena, const HashTable_Config *config)
{
  T table;

  validate_config (config);

  /* Allocate structure */
  if (arena != NULL)
    table = Arena_alloc (arena, sizeof (*table), __FILE__, __LINE__);
  else
    table = malloc (sizeof (*table));

  if (table == NULL)
    SOCKET_RAISE_MSG (HashTable, HashTable_Failed,
                      "Failed to allocate hash table");

  /* Initialize fields */
  table->bucket_count = config->bucket_count;
  table->hash_seed = config->hash_seed;
  table->hash = config->hash;
  table->compare = config->compare;
  table->next_ptr = config->next_ptr;
  table->arena = arena;

  /* Allocate buckets */
  table->buckets = allocate_buckets (arena, config->bucket_count);
  if (table->buckets == NULL)
    {
      if (arena == NULL)
        free (table);
      SOCKET_RAISE_MSG (HashTable, HashTable_Failed,
                        "Failed to allocate bucket array");
    }

  return table;
}

void
HashTable_free (T *table)
{
  T t;

  if (table == NULL || *table == NULL)
    return;

  t = *table;

  /* Only free if using malloc (not arena) */
  if (t->arena == NULL)
    {
      free (t->buckets);
      free (t);
    }

  *table = NULL;
}

/* ============================================================================
 * Public API - Operations
 * ============================================================================
 */

void *
HashTable_find (T table, const void *key, void **prev_out)
{
  unsigned bucket;
  void *entry;
  void *prev = NULL;

  assert (table != NULL);
  assert (key != NULL);

  bucket = compute_bucket (table, key);
  entry = table->buckets[bucket];

  while (entry != NULL)
    {
      if (table->compare (entry, key) == 0)
        {
          if (prev_out != NULL)
            *prev_out = prev;
          return entry;
        }
      prev = entry;
      entry = get_next (table, entry);
    }

  if (prev_out != NULL)
    *prev_out = NULL;
  return NULL;
}

void
HashTable_insert (T table, void *entry, const void *key)
{
  unsigned bucket;

  assert (table != NULL);
  assert (entry != NULL);
  assert (key != NULL);

  bucket = compute_bucket (table, key);

  /* Insert at head for O(1) */
  set_next (table, entry, table->buckets[bucket]);
  table->buckets[bucket] = entry;
}

void
HashTable_remove (T table, void *entry, void *prev, const void *key)
{
  unsigned bucket;

  assert (table != NULL);
  assert (entry != NULL);
  assert (key != NULL);

  bucket = compute_bucket (table, key);

  if (prev != NULL)
    {
      /* Entry is in middle/end of chain */
      set_next (table, prev, get_next (table, entry));
    }
  else
    {
      /* Entry is at bucket head */
      table->buckets[bucket] = get_next (table, entry);
    }

  /* Clear entry's next pointer for safety */
  set_next (table, entry, NULL);
}

void
HashTable_foreach (T table, HashTable_IterFunc func, void *context)
{
  size_t i;
  void *entry;
  void *next;

  assert (table != NULL);
  assert (func != NULL);

  for (i = 0; i < table->bucket_count; i++)
    {
      entry = table->buckets[i];
      while (entry != NULL)
        {
          /* Get next before callback in case callback modifies entry */
          next = get_next (table, entry);

          if (func (entry, context) != 0)
            return; /* Early exit requested */

          entry = next;
        }
    }
}

size_t
HashTable_bucket_count (T table)
{
  assert (table != NULL);
  return table->bucket_count;
}

unsigned
HashTable_seed (T table)
{
  assert (table != NULL);
  return table->hash_seed;
}

void
HashTable_clear (T table)
{
  assert (table != NULL);
  memset (table->buckets, 0, table->bucket_count * sizeof (void *));
}

#undef T

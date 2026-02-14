/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* Generic intrusive hash table with chained collision handling */

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "core/HashTable.h"
#include "core/SocketUtil.h"

#define T HashTable_T

const Except_T HashTable_Failed
    = { &HashTable_Failed, "Hash table operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (HashTable);

struct T
{
  void **buckets;
  size_t bucket_count;
  unsigned hash_seed;
  HashTable_HashFunc hash;
  HashTable_CompareFunc compare;
  HashTable_GetNextPtrFunc next_ptr;
  Arena_T arena; /* NULL=malloc */
};

static void
validate_config (const HashTable_Config *config)
{
  if (config == NULL)
    SOCKET_RAISE_MSG (HashTable, HashTable_Failed, "NULL configuration");

  if (config->bucket_count == 0)
    SOCKET_RAISE_MSG (HashTable, HashTable_Failed, "bucket_count must be > 0");

  if (config->hash == NULL)
    SOCKET_RAISE_MSG (HashTable, HashTable_Failed, "hash function required");

  if (config->compare == NULL)
    SOCKET_RAISE_MSG (HashTable, HashTable_Failed, "compare function required");

  if (config->next_ptr == NULL)
    SOCKET_RAISE_MSG (
        HashTable, HashTable_Failed, "next_ptr function required");
}

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

static unsigned
compute_bucket (T table, const void *key)
{
  unsigned bucket
      = table->hash (key, table->hash_seed, (unsigned)table->bucket_count);

  if (bucket >= table->bucket_count)
    bucket %= (unsigned)table->bucket_count;

  return bucket;
}

static void *
get_next (T table, void *entry)
{
  void **next_ptr = table->next_ptr (entry);
  return *next_ptr;
}

static void
set_next (T table, void *entry, void *next)
{
  void **next_ptr = table->next_ptr (entry);
  *next_ptr = next;
}

static void *
search_chain (T table, void *entry, const void *key, void **prev_out)
{
  void *prev = NULL;

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

static int
iterate_bucket (T table, void *entry, HashTable_IterFunc func, void *context)
{
  void *next;

  while (entry != NULL)
    {
      next = get_next (table, entry);

      if (func (entry, context) != 0)
        return 1;

      entry = next;
    }

  return 0;
}

T
HashTable_new (Arena_T arena, const HashTable_Config *config)
{
  T table;

  validate_config (config);

  /* Prevent integer overflow in compute_bucket() cast */
  if (config->bucket_count > UINT_MAX)
    SOCKET_RAISE_MSG (HashTable,
                      HashTable_Failed,
                      "bucket_count exceeds maximum of %u",
                      UINT_MAX);

  if (arena != NULL)
    table = Arena_alloc (arena, sizeof (*table), __FILE__, __LINE__);
  else
    table = malloc (sizeof (*table));

  if (table == NULL)
    SOCKET_RAISE_MSG (
        HashTable, HashTable_Failed, "Failed to allocate hash table");

  table->bucket_count = config->bucket_count;
  table->hash_seed = config->hash_seed;
  table->hash = config->hash;
  table->compare = config->compare;
  table->next_ptr = config->next_ptr;
  table->arena = arena;

  table->buckets = allocate_buckets (arena, config->bucket_count);
  if (table->buckets == NULL)
    {
      if (arena == NULL)
        free (table);
      SOCKET_RAISE_MSG (
          HashTable, HashTable_Failed, "Failed to allocate bucket array");
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

  if (t->arena == NULL) /* Only free if using malloc */
    {
      free (t->buckets);
      free (t);
    }

  *table = NULL;
}

void *
HashTable_find (T table, const void *key, void **prev_out)
{
  unsigned bucket;

  assert (table != NULL);
  assert (key != NULL);

  bucket = compute_bucket (table, key);

  return search_chain (table, table->buckets[bucket], key, prev_out);
}

void
HashTable_insert (T table, void *entry, const void *key)
{
  unsigned bucket;

  assert (table != NULL);
  assert (entry != NULL);
  assert (key != NULL);

  bucket = compute_bucket (table, key);

  set_next (table, entry, table->buckets[bucket]); /* Insert at head for O(1) */
  table->buckets[bucket] = entry;
}

void
HashTable_remove (T table, void *entry, void *prev, const void *key)
{
  unsigned bucket;
  void *current;
  void *actual_prev = NULL;

  assert (table != NULL);
  assert (entry != NULL);
  assert (key != NULL);

  (void)prev; /* Caller-provided prev can be stale/forged; recompute safely. */

  bucket = compute_bucket (table, key);

  current = table->buckets[bucket];
  while (current != NULL && current != entry)
    {
      actual_prev = current;
      current = get_next (table, current);
    }

  if (current == NULL)
    return;

  if (actual_prev != NULL)
    set_next (table, actual_prev, get_next (table, current));
  else
    table->buckets[bucket] = get_next (table, current);

  set_next (table, current, NULL);
}

void
HashTable_foreach (T table, HashTable_IterFunc func, void *context)
{
  size_t i;

  assert (table != NULL);
  assert (func != NULL);

  for (i = 0; i < table->bucket_count; i++)
    {
      if (iterate_bucket (table, table->buckets[i], func, context) != 0)
        return;
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

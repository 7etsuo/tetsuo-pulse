/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* Generic intrusive hash table with chained collision handling */

#include <assert.h>
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
  return table->hash (key, table->hash_seed, (unsigned)table->bucket_count);
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


T
HashTable_new (Arena_T arena, const HashTable_Config *config)
{
  T table;

  validate_config (config);

  if (arena != NULL)
    table = Arena_alloc (arena, sizeof (*table), __FILE__, __LINE__);
  else
    table = malloc (sizeof (*table));

  if (table == NULL)
    SOCKET_RAISE_MSG (HashTable, HashTable_Failed,
                      "Failed to allocate hash table");

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

  set_next (table, entry, table->buckets[bucket]); /* Insert at head for O(1) */
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
    set_next (table, prev, get_next (table, entry));
  else
    table->buckets[bucket] = get_next (table, entry);

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
          next = get_next (table, entry); /* Get next before callback modifies entry */

          if (func (entry, context) != 0)
            return;

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

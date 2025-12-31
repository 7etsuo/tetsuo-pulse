/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef HASHTABLE_INCLUDED
#define HASHTABLE_INCLUDED

/**
 * @file HashTable.h
 * @ingroup foundation
 * @brief Generic intrusive hash table with chained collision handling.
 *
 * Entries contain their own next pointer for chaining. O(1) average ops.
 * NOT thread-safe - caller must synchronize.
 *
 * @code{.c}
 * typedef struct MyEntry {
 *   char key[64];
 *   int value;
 *   struct MyEntry *next;  // Required for chaining
 * } MyEntry;
 *
 * static unsigned my_hash(const void *key, unsigned seed, unsigned size) {
 *   return hash_djb2(key, seed) % size;
 * }
 * static int my_cmp(const void *entry, const void *key) {
 *   return strcmp(((MyEntry*)entry)->key, (const char*)key);
 * }
 * static void **my_next(void *entry) {
 *   return (void**)&((MyEntry*)entry)->next;
 * }
 *
 * HashTable_Config cfg = { 256, seed, my_hash, my_cmp, my_next };
 * HashTable_T table = HashTable_new(arena, &cfg);
 * HashTable_insert(table, entry, entry->key);
 * MyEntry *found = HashTable_find(table, "key", NULL);
 * @endcode
 */

#include "core/Arena.h"
#include <stddef.h>

#define T HashTable_T
typedef struct T *T;

/** Hash function: returns bucket index (0 to table_size-1) */
typedef unsigned (*HashTable_HashFunc) (const void *key,
                                        unsigned seed,
                                        unsigned table_size);

/** Key comparison: returns 0 if match, non-zero otherwise */
typedef int (*HashTable_CompareFunc) (const void *entry, const void *key);

/** Get pointer to entry's next pointer for chaining */
typedef void **(*HashTable_GetNextPtrFunc) (void *entry);

/** Iterator callback: return non-zero to stop iteration */
typedef int (*HashTable_IterFunc) (void *entry, void *context);

/** Hash table configuration */
typedef struct HashTable_Config
{
  size_t bucket_count;               /**< Number of buckets */
  unsigned hash_seed;                /**< Seed for DoS resistance */
  HashTable_HashFunc hash;           /**< Hash function */
  HashTable_CompareFunc compare;     /**< Key comparison */
  HashTable_GetNextPtrFunc next_ptr; /**< Get entry's next pointer */
} HashTable_Config;

/**
 * Create a new hash table.
 * @param arena Arena for allocation (NULL for malloc)
 * @param config Configuration (copied)
 * @throws HashTable_Failed on error
 */
extern T HashTable_new (Arena_T arena, const HashTable_Config *config);

/**
 * Free a hash table. Does not free entries.
 * @param table Pointer to table (set to NULL)
 */
extern void HashTable_free (T *table);

/**
 * Find an entry by key.
 * @param prev_out If provided, set to previous entry for O(1) removal
 * @return Found entry or NULL
 */
extern void *HashTable_find (T table, const void *key, void **prev_out);

/**
 * Insert entry at bucket head. Does not check for duplicates.
 */
extern void HashTable_insert (T table, void *entry, const void *key);

/**
 * Remove entry. Use prev from HashTable_find for O(1) removal.
 * Does not free the entry.
 */
extern void
HashTable_remove (T table, void *entry, void *prev, const void *key);

/**
 * Iterate all entries. Stops if callback returns non-zero.
 */
extern void HashTable_foreach (T table, HashTable_IterFunc func, void *context);

/** Get bucket count */
extern size_t HashTable_bucket_count (T table);

/** Get hash seed */
extern unsigned HashTable_seed (T table);

/**
 * Clear all buckets. Does not free entries.
 */
extern void HashTable_clear (T table);

/** Exception raised on hash table errors */
extern const Except_T HashTable_Failed;

#undef T
#endif /* HASHTABLE_INCLUDED */

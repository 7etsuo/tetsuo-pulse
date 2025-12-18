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
 * @brief Generic intrusive hash table with chained collision handling
 *
 * Provides a reusable hash table implementation that works with any entry type.
 * The table is "intrusive" - entries contain their own next pointer for chaining.
 *
 * Features:
 * - Configurable bucket count
 * - Caller-provided hash and comparison functions
 * - O(1) average insert, find, remove
 * - Arena or malloc allocation for buckets
 * - Thread-safety: NOT built-in (caller provides synchronization)
 *
 * Usage pattern:
 * @code{.c}
 *   // Define entry type with next pointer
 *   typedef struct MyEntry {
 *     char key[64];
 *     int value;
 *     struct MyEntry *next;  // Required for chaining
 *   } MyEntry;
 *
 *   // Implement callbacks
 *   static unsigned my_hash(const void *key, unsigned seed, unsigned size) {
 *     return socket_util_hash_djb2_seeded(key, seed) % size;
 *   }
 *   static int my_compare(const void *entry, const void *key) {
 *     return strcmp(((MyEntry*)entry)->key, (const char*)key);
 *   }
 *   static void **my_next_ptr(void *entry) {
 *     return (void**)&((MyEntry*)entry)->next;
 *   }
 *
 *   // Create and use
 *   HashTable_Config config = {
 *     .bucket_count = 256,
 *     .hash_seed = random_seed,
 *     .hash = my_hash,
 *     .compare = my_compare,
 *     .get_next_ptr = my_next_ptr
 *   };
 *   HashTable_T table = HashTable_new(arena, &config);
 *   HashTable_insert(table, entry, entry->key);
 *   MyEntry *found = HashTable_find(table, "search_key", NULL);
 * @endcode
 *
 * @see Arena_T for memory management
 * @see SocketIPTracker for usage example
 */

#include "core/Arena.h"
#include <stddef.h>

#define T HashTable_T
typedef struct T *T;

/**
 * @brief Hash function type
 * @param key Key to hash
 * @param seed Hash seed for randomization
 * @param table_size Number of buckets
 * @return Bucket index (0 to table_size-1)
 */
typedef unsigned (*HashTable_HashFunc) (const void *key, unsigned seed,
                                        unsigned table_size);

/**
 * @brief Key comparison function type
 * @param entry Entry to compare
 * @param key Key to compare against
 * @return 0 if match, non-zero otherwise (like strcmp)
 */
typedef int (*HashTable_CompareFunc) (const void *entry, const void *key);

/**
 * @brief Get pointer to entry's next pointer (for chaining)
 * @param entry Entry to get next pointer from
 * @return Pointer to the entry's next pointer field
 *
 * This is used for intrusive chaining. For a struct like:
 *   struct Entry { ...; struct Entry *next; };
 * The implementation would be:
 *   return (void**)&((struct Entry*)entry)->next;
 */
typedef void **(*HashTable_GetNextPtrFunc) (void *entry);

/**
 * @brief Iterator callback function type
 * @param entry Current entry
 * @param context User context passed to foreach
 * @return 0 to continue iteration, non-zero to stop
 */
typedef int (*HashTable_IterFunc) (void *entry, void *context);

/**
 * @brief Hash table configuration
 */
typedef struct HashTable_Config
{
  size_t bucket_count; /**< Number of buckets (power of 2 recommended) */
  unsigned hash_seed;  /**< Seed for hash randomization (DoS resistance) */
  HashTable_HashFunc hash;           /**< Hash function */
  HashTable_CompareFunc compare;     /**< Key comparison function */
  HashTable_GetNextPtrFunc next_ptr; /**< Get entry's next pointer */
} HashTable_Config;

/**
 * @brief Create a new hash table
 * @param arena Arena for bucket allocation (NULL for malloc)
 * @param config Configuration (copied, caller may free)
 * @return New hash table instance
 *
 * @throws HashTable_Failed on allocation failure or invalid config
 *
 * Thread-safe: Yes (returns new instance)
 */
extern T HashTable_new (Arena_T arena, const HashTable_Config *config);

/**
 * @brief Free a hash table
 * @param table Pointer to table (set to NULL after free)
 *
 * Note: Only frees the bucket array, not the entries.
 * Caller is responsible for freeing entries (or using arena disposal).
 * Arena-allocated tables are freed when arena is disposed.
 *
 * Thread-safe: Yes (but caller must ensure no concurrent access)
 */
extern void HashTable_free (T *table);

/**
 * @brief Find an entry by key
 * @param table Hash table instance
 * @param key Key to search for
 * @param prev_out Optional output for previous entry (for O(1) removal)
 * @return Found entry or NULL
 *
 * If prev_out is provided, it will be set to:
 * - NULL if entry is at bucket head
 * - The previous entry in chain otherwise
 *
 * Thread-safe: No (caller must synchronize)
 */
extern void *HashTable_find (T table, const void *key, void **prev_out);

/**
 * @brief Insert an entry
 * @param table Hash table instance
 * @param entry Entry to insert (caller owns memory)
 * @param key Key for hashing (usually points into entry)
 *
 * Inserts at bucket head for O(1) operation.
 * Does NOT check for duplicates - caller should check first if needed.
 *
 * Thread-safe: No (caller must synchronize)
 */
extern void HashTable_insert (T table, void *entry, const void *key);

/**
 * @brief Remove an entry from the table
 * @param table Hash table instance
 * @param entry Entry to remove
 * @param prev Previous entry from find (NULL if at head)
 * @param key Key for bucket lookup
 *
 * Use with HashTable_find's prev_out for O(1) removal.
 * Does NOT free the entry - caller is responsible.
 *
 * Thread-safe: No (caller must synchronize)
 */
extern void HashTable_remove (T table, void *entry, void *prev,
                              const void *key);

/**
 * @brief Iterate over all entries
 * @param table Hash table instance
 * @param func Callback for each entry
 * @param context User context passed to callback
 *
 * Iterates all buckets, calling func for each entry.
 * If func returns non-zero, iteration stops immediately.
 *
 * Thread-safe: No (caller must synchronize)
 */
extern void HashTable_foreach (T table, HashTable_IterFunc func, void *context);

/**
 * @brief Get bucket count
 * @param table Hash table instance
 * @return Number of buckets
 */
extern size_t HashTable_bucket_count (T table);

/**
 * @brief Get hash seed
 * @param table Hash table instance
 * @return Hash seed value
 */
extern unsigned HashTable_seed (T table);

/**
 * @brief Clear all buckets (set to NULL)
 * @param table Hash table instance
 *
 * Does NOT free entries - only clears bucket pointers.
 * Use before freeing entries in arena mode.
 *
 * Thread-safe: No (caller must synchronize)
 */
extern void HashTable_clear (T table);

/**
 * @brief Exception raised on hash table errors
 */
extern const Except_T HashTable_Failed;

#undef T
#endif /* HASHTABLE_INCLUDED */

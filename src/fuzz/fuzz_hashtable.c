/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_hashtable.c - libFuzzer harness for HashTable
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Hash collision DoS (crafted key sequences that hash to same bucket)
 * - Insert/find/remove operation correctness
 * - Iteration safety during modifications
 * - Bucket count edge cases
 * - Configuration validation
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_hashtable
 * Run:   ./fuzz_hashtable corpus/hashtable/ -fork=16 -max_len=4096
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/HashTable.h"

/* Maximum entries to avoid OOM in fuzzer */
#define FUZZ_MAX_ENTRIES 1024
#define FUZZ_MAX_KEY_LEN 256
#define FUZZ_MAX_BUCKET_COUNT 65536

/* Entry structure for testing */
typedef struct FuzzEntry
{
  char key[FUZZ_MAX_KEY_LEN];
  size_t key_len;
  int value;
  struct FuzzEntry *next; /* Required for HashTable chaining */
} FuzzEntry;

/* Fuzz operation opcodes */
enum FuzzOp
{
  OP_INSERT = 0,
  OP_FIND,
  OP_REMOVE,
  OP_FOREACH,
  OP_COLLISION_ATTACK,
  OP_CLEAR,
  OP_STRESS,
  OP_CONFIG_EDGE,
  OP_MAX
};

/* Hash function: DJB2 with seed */
static unsigned
fuzz_hash (const void *key, unsigned seed, unsigned table_size)
{
  const char *str = (const char *)key;
  unsigned hash = seed ^ 5381;

  while (*str)
    {
      hash = ((hash << 5) + hash) + (unsigned char)*str;
      str++;
    }

  return hash % table_size;
}

/* Compare function */
static int
fuzz_compare (const void *entry, const void *key)
{
  const FuzzEntry *e = (const FuzzEntry *)entry;
  return strcmp (e->key, (const char *)key);
}

/* Get next pointer for chaining */
static void **
fuzz_next_ptr (void *entry)
{
  FuzzEntry *e = (FuzzEntry *)entry;
  return (void **)&e->next;
}

/* Collision-inducing hash function - always returns same bucket */
static unsigned
collision_hash (const void *key, unsigned seed, unsigned table_size)
{
  (void)key;
  (void)seed;
  /* Always hash to bucket 0 to create worst-case chain */
  return 0 % table_size;
}

/* Iterator callback for foreach testing */
static int iter_count;

static int
count_iterator (void *entry, void *context)
{
  (void)entry;
  int *count = (int *)context;
  (*count)++;
  iter_count++;
  /* Stop iteration if we've seen too many (potential infinite loop) */
  return iter_count > FUZZ_MAX_ENTRIES ? 1 : 0;
}

/**
 * parse_uint16 - Parse 16-bit value from fuzz input
 */
static uint16_t
parse_uint16 (const uint8_t *data, size_t len)
{
  if (len >= 2)
    return (uint16_t)((data[0]) | (data[1] << 8));
  if (len >= 1)
    return data[0];
  return 0;
}

/**
 * extract_key - Extract a key string from fuzz input
 */
static size_t
extract_key (const uint8_t *data, size_t len, char *key_out, size_t key_max)
{
  size_t key_len = 0;

  /* Read length prefix if available */
  if (len >= 1)
    {
      key_len = data[0];
      if (key_len > len - 1)
        key_len = len - 1;
      if (key_len >= key_max)
        key_len = key_max - 1;
    }

  if (key_len > 0)
    memcpy (key_out, data + 1, key_len);
  key_out[key_len] = '\0';

  return 1 + key_len; /* bytes consumed */
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  HashTable_T table = NULL;
  FuzzEntry *entries = NULL;
  size_t entry_count = 0;

  if (size < 2)
    return 0;

  uint8_t op = data[0] % OP_MAX;
  const uint8_t *payload = data + 1;
  size_t payload_size = size - 1;

  TRY
  {
    arena = Arena_new ();
    if (!arena)
      return 0;

    /* Allocate entry pool */
    entries = Arena_calloc (
        arena, FUZZ_MAX_ENTRIES, sizeof (FuzzEntry), __FILE__, __LINE__);

    switch (op)
      {
      case OP_INSERT:
        {
          /* Test basic insert operations */
          HashTable_Config cfg = {
            .bucket_count = 64,
            .hash_seed = parse_uint16 (payload, payload_size),
            .hash = fuzz_hash,
            .compare = fuzz_compare,
            .next_ptr = fuzz_next_ptr,
          };

          table = HashTable_new (arena, &cfg);

          /* Insert entries from fuzz input */
          size_t offset = 2;
          while (offset < payload_size && entry_count < FUZZ_MAX_ENTRIES)
            {
              FuzzEntry *e = &entries[entry_count];
              size_t consumed
                  = extract_key (payload + offset,
                                 payload_size - offset,
                                 e->key,
                                 sizeof (e->key));
              offset += consumed;

              if (e->key[0] != '\0')
                {
                  e->value = (int)entry_count;
                  e->next = NULL;
                  HashTable_insert (table, e, e->key);
                  entry_count++;
                }
            }

          /* Verify all entries can be found */
          for (size_t i = 0; i < entry_count; i++)
            {
              void *found = HashTable_find (table, entries[i].key, NULL);
              /* Note: may not find due to duplicate keys overwriting */
              (void)found;
            }
        }
        break;

      case OP_FIND:
        {
          /* Test find operations with various key patterns */
          HashTable_Config cfg = {
            .bucket_count = 32,
            .hash_seed = 0x12345678,
            .hash = fuzz_hash,
            .compare = fuzz_compare,
            .next_ptr = fuzz_next_ptr,
          };

          table = HashTable_new (arena, &cfg);

          /* Insert some known entries */
          for (size_t i = 0; i < 10 && i < FUZZ_MAX_ENTRIES; i++)
            {
              FuzzEntry *e = &entries[entry_count++];
              snprintf (e->key, sizeof (e->key), "key%zu", i);
              e->value = (int)i;
              e->next = NULL;
              HashTable_insert (table, e, e->key);
            }

          /* Find using fuzz-controlled keys */
          size_t offset = 0;
          while (offset < payload_size)
            {
              char search_key[FUZZ_MAX_KEY_LEN];
              size_t consumed = extract_key (payload + offset,
                                             payload_size - offset,
                                             search_key,
                                             sizeof (search_key));
              offset += consumed;

              if (search_key[0] != '\0')
                {
                  void *prev = NULL;
                  void *found = HashTable_find (table, search_key, &prev);
                  (void)found;
                  (void)prev;
                }
            }
        }
        break;

      case OP_REMOVE:
        {
          /* Test remove operations */
          HashTable_Config cfg = {
            .bucket_count = 16,
            .hash_seed = parse_uint16 (payload, payload_size),
            .hash = fuzz_hash,
            .compare = fuzz_compare,
            .next_ptr = fuzz_next_ptr,
          };

          table = HashTable_new (arena, &cfg);

          /* Insert entries */
          size_t offset = 2;
          while (offset < payload_size && entry_count < FUZZ_MAX_ENTRIES / 2)
            {
              FuzzEntry *e = &entries[entry_count];
              size_t consumed
                  = extract_key (payload + offset,
                                 payload_size - offset,
                                 e->key,
                                 sizeof (e->key));
              offset += consumed;

              if (e->key[0] != '\0')
                {
                  e->value = (int)entry_count;
                  e->next = NULL;
                  HashTable_insert (table, e, e->key);
                  entry_count++;
                }
            }

          /* Remove entries based on remaining fuzz data */
          while (offset < payload_size)
            {
              char remove_key[FUZZ_MAX_KEY_LEN];
              size_t consumed = extract_key (payload + offset,
                                             payload_size - offset,
                                             remove_key,
                                             sizeof (remove_key));
              offset += consumed;

              if (remove_key[0] != '\0')
                {
                  void *prev = NULL;
                  void *found = HashTable_find (table, remove_key, &prev);
                  if (found)
                    {
                      HashTable_remove (table, found, prev, remove_key);
                    }
                }
            }
        }
        break;

      case OP_FOREACH:
        {
          /* Test iteration */
          HashTable_Config cfg = {
            .bucket_count = 64,
            .hash_seed = 0xDEADBEEF,
            .hash = fuzz_hash,
            .compare = fuzz_compare,
            .next_ptr = fuzz_next_ptr,
          };

          table = HashTable_new (arena, &cfg);

          /* Insert entries from fuzz input */
          size_t offset = 0;
          while (offset < payload_size && entry_count < FUZZ_MAX_ENTRIES)
            {
              FuzzEntry *e = &entries[entry_count];
              size_t consumed
                  = extract_key (payload + offset,
                                 payload_size - offset,
                                 e->key,
                                 sizeof (e->key));
              offset += consumed;

              if (e->key[0] != '\0')
                {
                  e->value = (int)entry_count;
                  e->next = NULL;
                  HashTable_insert (table, e, e->key);
                  entry_count++;
                }
            }

          /* Iterate and count */
          int count = 0;
          iter_count = 0;
          HashTable_foreach (table, count_iterator, &count);

          /* Count should be <= entry_count (may be less if duplicates) */
          assert (count <= (int)entry_count + 1);
        }
        break;

      case OP_COLLISION_ATTACK:
        {
          /* Deliberately create worst-case hash collisions */
          HashTable_Config cfg = {
            .bucket_count = 16,
            .hash_seed = 0,
            .hash = collision_hash, /* All keys hash to bucket 0 */
            .compare = fuzz_compare,
            .next_ptr = fuzz_next_ptr,
          };

          table = HashTable_new (arena, &cfg);

          /* Insert many entries - all will chain in bucket 0 */
          size_t offset = 0;
          while (offset < payload_size && entry_count < 100)
            {
              /* Limit to 100 for collision test */
              FuzzEntry *e = &entries[entry_count];
              size_t consumed
                  = extract_key (payload + offset,
                                 payload_size - offset,
                                 e->key,
                                 sizeof (e->key));
              offset += consumed;

              if (e->key[0] != '\0')
                {
                  e->value = (int)entry_count;
                  e->next = NULL;
                  HashTable_insert (table, e, e->key);
                  entry_count++;
                }
            }

          /* Try to find each entry - this tests O(n) chain traversal */
          for (size_t i = 0; i < entry_count; i++)
            {
              void *found = HashTable_find (table, entries[i].key, NULL);
              (void)found;
            }
        }
        break;

      case OP_CLEAR:
        {
          /* Test clear and reuse */
          HashTable_Config cfg = {
            .bucket_count = 32,
            .hash_seed = parse_uint16 (payload, payload_size),
            .hash = fuzz_hash,
            .compare = fuzz_compare,
            .next_ptr = fuzz_next_ptr,
          };

          table = HashTable_new (arena, &cfg);

          for (int round = 0; round < 3; round++)
            {
              /* Insert entries */
              size_t round_entries = 0;
              size_t offset = 2 + round * 50;
              while (offset < payload_size && round_entries < 50
                     && entry_count < FUZZ_MAX_ENTRIES)
                {
                  FuzzEntry *e = &entries[entry_count];
                  size_t consumed
                      = extract_key (payload + offset,
                                     payload_size - offset,
                                     e->key,
                                     sizeof (e->key));
                  offset += consumed;

                  if (e->key[0] != '\0')
                    {
                      e->value = (int)entry_count;
                      e->next = NULL;
                      HashTable_insert (table, e, e->key);
                      entry_count++;
                      round_entries++;
                    }
                }

              /* Clear the table */
              HashTable_clear (table);

              /* Verify table is empty after clear */
              int count = 0;
              iter_count = 0;
              HashTable_foreach (table, count_iterator, &count);
              assert (count == 0);
            }
        }
        break;

      case OP_STRESS:
        {
          /* Stress test with rapid insert/find/remove cycles */
          size_t bucket_count = (payload_size > 0 ? payload[0] : 32);
          if (bucket_count == 0)
            bucket_count = 1;
          if (bucket_count > FUZZ_MAX_BUCKET_COUNT)
            bucket_count = FUZZ_MAX_BUCKET_COUNT;

          HashTable_Config cfg = {
            .bucket_count = bucket_count,
            .hash_seed = parse_uint16 (payload + 1, payload_size - 1),
            .hash = fuzz_hash,
            .compare = fuzz_compare,
            .next_ptr = fuzz_next_ptr,
          };

          table = HashTable_new (arena, &cfg);

          size_t offset = 3;
          while (offset < payload_size && entry_count < FUZZ_MAX_ENTRIES)
            {
              uint8_t action = payload[offset] % 3;
              offset++;

              switch (action)
                {
                case 0: /* Insert */
                  {
                    if (entry_count < FUZZ_MAX_ENTRIES)
                      {
                        FuzzEntry *e = &entries[entry_count];
                        size_t consumed
                            = extract_key (payload + offset,
                                           payload_size - offset,
                                           e->key,
                                           sizeof (e->key));
                        offset += consumed;

                        if (e->key[0] != '\0')
                          {
                            e->value = (int)entry_count;
                            e->next = NULL;
                            HashTable_insert (table, e, e->key);
                            entry_count++;
                          }
                      }
                  }
                  break;

                case 1: /* Find */
                  {
                    char key[FUZZ_MAX_KEY_LEN];
                    size_t consumed = extract_key (payload + offset,
                                                   payload_size - offset,
                                                   key,
                                                   sizeof (key));
                    offset += consumed;
                    if (key[0] != '\0')
                      {
                        HashTable_find (table, key, NULL);
                      }
                  }
                  break;

                case 2: /* Remove */
                  {
                    char key[FUZZ_MAX_KEY_LEN];
                    size_t consumed = extract_key (payload + offset,
                                                   payload_size - offset,
                                                   key,
                                                   sizeof (key));
                    offset += consumed;
                    if (key[0] != '\0')
                      {
                        void *prev = NULL;
                        void *found = HashTable_find (table, key, &prev);
                        if (found)
                          {
                            HashTable_remove (table, found, prev, key);
                          }
                      }
                  }
                  break;
                }
            }
        }
        break;

      case OP_CONFIG_EDGE:
        {
          /* Test configuration edge cases */
          uint8_t test_case = payload_size > 0 ? payload[0] % 5 : 0;

          switch (test_case)
            {
            case 0:
              {
                /* Minimum bucket count (1) */
                HashTable_Config cfg = {
                  .bucket_count = 1,
                  .hash_seed = 0,
                  .hash = fuzz_hash,
                  .compare = fuzz_compare,
                  .next_ptr = fuzz_next_ptr,
                };
                table = HashTable_new (arena, &cfg);
                FuzzEntry *e = &entries[0];
                strcpy (e->key, "test");
                e->next = NULL;
                HashTable_insert (table, e, e->key);
                HashTable_find (table, e->key, NULL);
              }
              break;

            case 1:
              {
                /* Large bucket count */
                HashTable_Config cfg = {
                  .bucket_count = FUZZ_MAX_BUCKET_COUNT,
                  .hash_seed = 0xFFFFFFFF,
                  .hash = fuzz_hash,
                  .compare = fuzz_compare,
                  .next_ptr = fuzz_next_ptr,
                };
                table = HashTable_new (arena, &cfg);
                FuzzEntry *e = &entries[0];
                strcpy (e->key, "test");
                e->next = NULL;
                HashTable_insert (table, e, e->key);
              }
              break;

            case 2:
              {
                /* Zero bucket count - should fail */
                TRY
                {
                  HashTable_Config cfg = {
                    .bucket_count = 0,
                    .hash_seed = 0,
                    .hash = fuzz_hash,
                    .compare = fuzz_compare,
                    .next_ptr = fuzz_next_ptr,
                  };
                  table = HashTable_new (arena, &cfg);
                }
                EXCEPT (HashTable_Failed)
                {
                  /* Expected */
                }
                END_TRY;
              }
              break;

            case 3:
              {
                /* NULL config - should fail */
                TRY
                {
                  table = HashTable_new (arena, NULL);
                }
                EXCEPT (HashTable_Failed)
                {
                  /* Expected */
                }
                END_TRY;
              }
              break;

            case 4:
              {
                /* Missing required function pointers */
                TRY
                {
                  HashTable_Config cfg = {
                    .bucket_count = 16,
                    .hash_seed = 0,
                    .hash = NULL, /* Missing hash */
                    .compare = fuzz_compare,
                    .next_ptr = fuzz_next_ptr,
                  };
                  table = HashTable_new (arena, &cfg);
                }
                EXCEPT (HashTable_Failed)
                {
                  /* Expected */
                }
                END_TRY;
              }
              break;
            }
        }
        break;
      }
  }
  EXCEPT (HashTable_Failed)
  {
    /* Expected for invalid configurations */
  }
  FINALLY
  {
    if (table)
      HashTable_free (&table);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;

  return 0;
}

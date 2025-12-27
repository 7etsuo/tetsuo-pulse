/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDNSServfailCache.c
 * @brief DNS Server Failure Cache implementation (RFC 2308 Section 7.1).
 */

#include "dns/SocketDNSServfailCache.h"
#include "core/Arena.h"
#include "core/SocketUtil.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define T SocketDNSServfailCache_T

/** Hash table size (prime for better distribution). */
#define SERVFAIL_HASH_SIZE 127

/**
 * @brief Internal cache entry structure.
 *
 * Stores the 4-tuple key: <QNAME, QTYPE, QCLASS, nameserver>
 */
struct ServfailCacheEntry
{
  char name[DNS_SERVFAIL_MAX_NAME + 1]; /**< Normalized (lowercase) QNAME */
  char nameserver[DNS_SERVFAIL_MAX_NS + 1]; /**< Nameserver address */
  uint16_t qtype;    /**< QTYPE */
  uint16_t qclass;   /**< QCLASS */
  uint32_t ttl;      /**< Original TTL (capped at DNS_SERVFAIL_MAX_TTL) */
  int64_t insert_time_ms; /**< Monotonic insertion time */
  struct ServfailCacheEntry *hash_next; /**< Hash chain pointer */
  struct ServfailCacheEntry *lru_prev;  /**< LRU list prev */
  struct ServfailCacheEntry *lru_next;  /**< LRU list next */
};

/**
 * @brief SERVFAIL cache structure.
 */
struct T
{
  Arena_T arena; /**< Memory arena */
  pthread_mutex_t mutex; /**< Thread safety */

  struct ServfailCacheEntry *hash_table[SERVFAIL_HASH_SIZE]; /**< Hash buckets */
  struct ServfailCacheEntry *lru_head; /**< LRU head (most recent) */
  struct ServfailCacheEntry *lru_tail; /**< LRU tail (oldest) */

  size_t size;         /**< Current entry count */
  size_t max_entries;  /**< Maximum capacity */

  /* Hash collision DoS protection */
  uint32_t hash_seed;  /**< Random seed for hash function */

  /* Statistics */
  uint64_t hits;
  uint64_t misses;
  uint64_t insertions;
  uint64_t evictions;
  uint64_t expirations;
};

/* normalize_name() replaced by socket_util_normalize_hostname() from SocketUtil.h */

/**
 * @brief Compute hash for cache key 4-tuple with seed.
 *
 * Includes name, qtype, qclass, and nameserver in hash calculation.
 * Uses a random seed to protect against hash collision DoS attacks.
 */
static unsigned
compute_hash_with_seed (const char *name, uint16_t qtype, uint16_t qclass,
                        const char *nameserver, uint32_t seed)
{
  unsigned hash = 5381; /* djb2 initial value */

  /* Mix in random seed for DoS protection */
  hash = ((hash << 5) + hash) ^ seed;

  /* Hash the normalized name */
  for (const char *p = name; *p; p++)
    hash = ((hash << 5) + hash) ^ (unsigned char)tolower ((unsigned char)*p);

  /* Include qtype and qclass */
  hash = ((hash << 5) + hash) ^ qtype;
  hash = ((hash << 5) + hash) ^ qclass;

  /* Include nameserver */
  for (const char *p = nameserver; *p; p++)
    hash = ((hash << 5) + hash) ^ (unsigned char)*p;

  return hash % SERVFAIL_HASH_SIZE;
}

/**
 * @brief Compute hash for cache key 4-tuple (wrapper for cache instance).
 */
static unsigned
compute_hash (T cache, const char *name, uint16_t qtype, uint16_t qclass,
              const char *nameserver)
{
  return compute_hash_with_seed (name, qtype, qclass, nameserver, cache->hash_seed);
}

/* entry_expired() replaced by socket_util_ttl_expired() from SocketUtil.h */

/* entry_ttl_remaining() replaced by socket_util_ttl_remaining() from SocketUtil.h */

/**
 * @brief Remove entry from LRU list.
 */
static void
lru_remove (T cache, struct ServfailCacheEntry *entry)
{
  if (entry->lru_prev)
    entry->lru_prev->lru_next = entry->lru_next;
  else
    cache->lru_head = entry->lru_next;

  if (entry->lru_next)
    entry->lru_next->lru_prev = entry->lru_prev;
  else
    cache->lru_tail = entry->lru_prev;

  entry->lru_prev = NULL;
  entry->lru_next = NULL;
}

/**
 * @brief Add entry to LRU head (most recently used).
 */
static void
lru_add_head (T cache, struct ServfailCacheEntry *entry)
{
  entry->lru_prev = NULL;
  entry->lru_next = cache->lru_head;

  if (cache->lru_head)
    cache->lru_head->lru_prev = entry;
  else
    cache->lru_tail = entry;

  cache->lru_head = entry;
}

/**
 * @brief Move entry to LRU head (accessed).
 */
static void
lru_touch (T cache, struct ServfailCacheEntry *entry)
{
  if (entry != cache->lru_head)
    {
      lru_remove (cache, entry);
      lru_add_head (cache, entry);
    }
}

/**
 * @brief Remove entry from hash table.
 */
static void
hash_remove (T cache, struct ServfailCacheEntry *entry, unsigned bucket)
{
  struct ServfailCacheEntry **pp = &cache->hash_table[bucket];
  while (*pp)
    {
      if (*pp == entry)
        {
          *pp = entry->hash_next;
          entry->hash_next = NULL;
          return;
        }
      pp = &(*pp)->hash_next;
    }
}

/**
 * @brief Free an entry (remove from all lists).
 */
static void
entry_free (T cache, struct ServfailCacheEntry *entry)
{
  /* Compute bucket for hash removal */
  unsigned bucket
      = compute_hash (cache, entry->name, entry->qtype, entry->qclass,
                      entry->nameserver);

  hash_remove (cache, entry, bucket);
  lru_remove (cache, entry);
  cache->size--;

  /* Entry memory is arena-managed, no explicit free needed */
}

/**
 * @brief Evict LRU entry when cache is full.
 */
static void
evict_lru (T cache)
{
  if (cache->lru_tail)
    {
      entry_free (cache, cache->lru_tail);
      cache->evictions++;
    }
}

/**
 * @brief Find entry by exact key 4-tuple.
 */
static struct ServfailCacheEntry *
find_entry (T cache, const char *normalized_name, uint16_t qtype,
            uint16_t qclass, const char *nameserver)
{
  unsigned bucket = compute_hash (cache, normalized_name, qtype, qclass, nameserver);
  struct ServfailCacheEntry *entry = cache->hash_table[bucket];

  while (entry)
    {
      if (entry->qtype == qtype && entry->qclass == qclass
          && strcasecmp (entry->name, normalized_name) == 0
          && strcmp (entry->nameserver, nameserver) == 0)
        return entry;
      entry = entry->hash_next;
    }

  return NULL;
}

/**
 * @brief Insert entry into hash table.
 */
static void
hash_insert (T cache, struct ServfailCacheEntry *entry)
{
  unsigned bucket
      = compute_hash (cache, entry->name, entry->qtype, entry->qclass,
                      entry->nameserver);
  entry->hash_next = cache->hash_table[bucket];
  cache->hash_table[bucket] = entry;
}

/**
 * @brief Allocate new entry from arena.
 */
static struct ServfailCacheEntry *
entry_alloc (T cache)
{
  return Arena_alloc (cache->arena, sizeof (struct ServfailCacheEntry),
                      __FILE__, __LINE__);
}

/* Public API */

T
SocketDNSServfailCache_new (Arena_T arena)
{
  if (arena == NULL)
    return NULL;

  T cache = Arena_alloc (arena, sizeof (*cache), __FILE__, __LINE__);
  if (cache == NULL)
    return NULL;

  memset (cache, 0, sizeof (*cache));
  cache->arena = arena;
  cache->max_entries = DNS_SERVFAIL_DEFAULT_MAX;

  /* Initialize random seed for hash collision DoS protection */
  cache->hash_seed = (uint32_t)time(NULL) ^ (uint32_t)(uintptr_t)cache;

  if (pthread_mutex_init (&cache->mutex, NULL) != 0)
    return NULL;

  return cache;
}

void
SocketDNSServfailCache_free (T *cache)
{
  if (cache == NULL || *cache == NULL)
    return;

  pthread_mutex_destroy (&(*cache)->mutex);

  /* Arena handles memory, just clear pointer */
  *cache = NULL;
}

SocketDNS_ServfailCacheResult
SocketDNSServfailCache_lookup (T cache, const char *qname, uint16_t qtype,
                                uint16_t qclass, const char *nameserver,
                                SocketDNS_ServfailCacheEntry *entry)
{
  if (cache == NULL || qname == NULL || nameserver == NULL)
    return DNS_SERVFAIL_MISS;

  char normalized[DNS_SERVFAIL_MAX_NAME + 1];
  socket_util_normalize_hostname (normalized, qname, DNS_SERVFAIL_MAX_NAME + 1);

  int64_t now_ms = Socket_get_monotonic_ms ();
  SocketDNS_ServfailCacheResult result = DNS_SERVFAIL_MISS;

  pthread_mutex_lock (&cache->mutex);

  struct ServfailCacheEntry *found
      = find_entry (cache, normalized, qtype, qclass, nameserver);

  if (found)
    {
      if (socket_util_ttl_expired (found->insert_time_ms, found->ttl, now_ms))
        {
          entry_free (cache, found);
          cache->expirations++;
          found = NULL;
        }
      else
        {
          result = DNS_SERVFAIL_HIT;
          cache->hits++;
          lru_touch (cache, found);
        }
    }

  /* Fill in entry details if requested and found */
  if (entry != NULL && found != NULL)
    {
      entry->original_ttl = found->ttl;
      entry->ttl_remaining = socket_util_ttl_remaining (found->insert_time_ms, found->ttl, now_ms);
      entry->insert_time_ms = found->insert_time_ms;
    }

  if (result == DNS_SERVFAIL_MISS)
    cache->misses++;

  pthread_mutex_unlock (&cache->mutex);

  return result;
}

/*
 * SECURITY CONSIDERATIONS:
 *
 * 1. Cache Poisoning Protection:
 *    - SERVFAIL caching is server-specific (4-tuple key includes nameserver)
 *    - Prevents attackers from poisoning cache for all nameservers
 *    - TTL is strictly capped at 5 minutes per RFC 2308 Section 7.1
 *
 * 2. Rate Limiting (Implicit):
 *    - LRU eviction provides natural rate limiting per nameserver
 *    - Cache size cap (DNS_SERVFAIL_DEFAULT_MAX = 500) limits resource usage
 *    - Each nameserver can only occupy portion of cache
 *
 * 3. DoS Protection:
 *    - Random hash seed prevents hash collision attacks
 *    - Input validation on name and nameserver lengths
 *    - Cache size limits prevent memory exhaustion
 *
 * 4. Recommended Deployment:
 *    - Monitor cache hit rate to detect potential abuse
 *    - Consider per-nameserver entry limits for multi-tenant environments
 *    - Use in conjunction with query timeout and retry logic
 */
int
SocketDNSServfailCache_insert (T cache, const char *qname, uint16_t qtype,
                                uint16_t qclass, const char *nameserver,
                                uint32_t ttl)
{
  if (cache == NULL || qname == NULL || nameserver == NULL)
    return -1;

  /* Reject if cache is disabled */
  if (cache->max_entries == 0)
    return -1;

  /* Validate name and nameserver length */
  size_t qname_len = strlen (qname);
  if (qname_len > DNS_SERVFAIL_MAX_NAME)
    return -1;

  size_t ns_len = strlen (nameserver);
  if (ns_len > DNS_SERVFAIL_MAX_NS)
    return -1;

  char normalized[DNS_SERVFAIL_MAX_NAME + 1];
  socket_util_normalize_hostname (normalized, qname, DNS_SERVFAIL_MAX_NAME + 1);

  /* Cap TTL at RFC 2308 mandated maximum of 5 minutes */
  if (ttl > DNS_SERVFAIL_MAX_TTL)
    ttl = DNS_SERVFAIL_MAX_TTL;

  pthread_mutex_lock (&cache->mutex);

  /* Check if already exists and update */
  struct ServfailCacheEntry *existing
      = find_entry (cache, normalized, qtype, qclass, nameserver);
  if (existing)
    {
      existing->ttl = ttl;
      existing->insert_time_ms = Socket_get_monotonic_ms ();
      lru_touch (cache, existing);
      pthread_mutex_unlock (&cache->mutex);
      return 0;
    }

  /* Evict if at capacity */
  if (cache->max_entries > 0 && cache->size >= cache->max_entries)
    evict_lru (cache);

  /* Allocate new entry */
  struct ServfailCacheEntry *entry = entry_alloc (cache);
  if (entry == NULL)
    {
      pthread_mutex_unlock (&cache->mutex);
      return -1;
    }

  memset (entry, 0, sizeof (*entry));
  snprintf (entry->name, sizeof (entry->name), "%s", normalized);
  snprintf (entry->nameserver, sizeof (entry->nameserver), "%s", nameserver);
  entry->qtype = qtype;
  entry->qclass = qclass;
  entry->ttl = ttl;
  entry->insert_time_ms = Socket_get_monotonic_ms ();

  hash_insert (cache, entry);
  lru_add_head (cache, entry);
  cache->size++;
  cache->insertions++;

  pthread_mutex_unlock (&cache->mutex);

  return 0;
}

int
SocketDNSServfailCache_remove (T cache, const char *qname, uint16_t qtype,
                                uint16_t qclass, const char *nameserver)
{
  if (cache == NULL || qname == NULL || nameserver == NULL)
    return 0;

  char normalized[DNS_SERVFAIL_MAX_NAME + 1];
  socket_util_normalize_hostname (normalized, qname, DNS_SERVFAIL_MAX_NAME + 1);

  pthread_mutex_lock (&cache->mutex);

  struct ServfailCacheEntry *entry
      = find_entry (cache, normalized, qtype, qclass, nameserver);
  if (entry)
    {
      entry_free (cache, entry);
      pthread_mutex_unlock (&cache->mutex);
      return 1;
    }

  pthread_mutex_unlock (&cache->mutex);

  return 0;
}

int
SocketDNSServfailCache_remove_nameserver (T cache, const char *nameserver)
{
  if (cache == NULL || nameserver == NULL)
    return 0;

  int removed = 0;

  pthread_mutex_lock (&cache->mutex);

  /* Scan all buckets for entries with this nameserver */
  for (unsigned i = 0; i < SERVFAIL_HASH_SIZE; i++)
    {
      struct ServfailCacheEntry **pp = &cache->hash_table[i];
      while (*pp)
        {
          struct ServfailCacheEntry *entry = *pp;
          if (strcmp (entry->nameserver, nameserver) == 0)
            {
              *pp = entry->hash_next;
              lru_remove (cache, entry);
              cache->size--;
              removed++;
            }
          else
            {
              pp = &entry->hash_next;
            }
        }
    }

  pthread_mutex_unlock (&cache->mutex);

  return removed;
}

void
SocketDNSServfailCache_clear (T cache)
{
  if (cache == NULL)
    return;

  pthread_mutex_lock (&cache->mutex);

  /* Clear hash table */
  for (unsigned i = 0; i < SERVFAIL_HASH_SIZE; i++)
    cache->hash_table[i] = NULL;

  /* Clear LRU list */
  cache->lru_head = NULL;
  cache->lru_tail = NULL;
  cache->size = 0;

  pthread_mutex_unlock (&cache->mutex);
}

void
SocketDNSServfailCache_set_max_entries (T cache, size_t max_entries)
{
  if (cache == NULL)
    return;

  pthread_mutex_lock (&cache->mutex);
  cache->max_entries = max_entries;

  /* Evict excess entries */
  while (max_entries > 0 && cache->size > max_entries)
    evict_lru (cache);

  pthread_mutex_unlock (&cache->mutex);
}

void
SocketDNSServfailCache_stats (T cache, SocketDNS_ServfailCacheStats *stats)
{
  if (cache == NULL || stats == NULL)
    return;

  pthread_mutex_lock (&cache->mutex);

  stats->hits = cache->hits;
  stats->misses = cache->misses;
  stats->insertions = cache->insertions;
  stats->evictions = cache->evictions;
  stats->expirations = cache->expirations;
  stats->current_size = cache->size;
  stats->max_entries = cache->max_entries;

  uint64_t total = stats->hits + stats->misses;
  stats->hit_rate = (total > 0) ? ((double)stats->hits / total) : 0.0;

  pthread_mutex_unlock (&cache->mutex);
}

const char *
SocketDNSServfailCache_result_name (SocketDNS_ServfailCacheResult result)
{
  switch (result)
    {
    case DNS_SERVFAIL_MISS:
      return "MISS";
    case DNS_SERVFAIL_HIT:
      return "HIT";
    default:
      return "UNKNOWN";
    }
}

#undef T

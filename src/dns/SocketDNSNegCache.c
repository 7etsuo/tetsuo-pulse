/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDNSNegCache.c
 * @brief DNS Negative Response Cache implementation (RFC 2308).
 */

#include "dns/SocketDNSNegCache.h"
#include "core/Arena.h"
#include "core/SocketUtil.h"

#include <ctype.h>
#include <pthread.h>
#include <string.h>
#include <strings.h>

#define T SocketDNSNegCache_T

/** Hash table size (prime for better distribution). */
#define NEGCACHE_HASH_SIZE 257

/**
 * @brief Internal cache entry structure.
 */
struct NegCacheEntry
{
  char name[DNS_NEGCACHE_MAX_NAME + 1]; /**< Normalized (lowercase) QNAME */
  uint16_t qtype;    /**< QTYPE (0 for NXDOMAIN, specific for NODATA) */
  uint16_t qclass;   /**< QCLASS */
  SocketDNS_NegCacheType type; /**< Entry type */
  uint32_t ttl;      /**< Original TTL */
  int64_t insert_time_ms; /**< Monotonic insertion time */
  struct NegCacheEntry *hash_next; /**< Hash chain pointer */
  struct NegCacheEntry *lru_prev;  /**< LRU list prev */
  struct NegCacheEntry *lru_next;  /**< LRU list next */
};

/**
 * @brief Negative cache structure.
 */
struct T
{
  Arena_T arena; /**< Memory arena */
  pthread_mutex_t mutex; /**< Thread safety */

  struct NegCacheEntry *hash_table[NEGCACHE_HASH_SIZE]; /**< Hash buckets */
  struct NegCacheEntry *lru_head; /**< LRU head (most recent) */
  struct NegCacheEntry *lru_tail; /**< LRU tail (oldest) */

  size_t size;         /**< Current entry count */
  size_t max_entries;  /**< Maximum capacity */
  uint32_t max_ttl;    /**< Maximum TTL allowed */

  /* Statistics */
  uint64_t hits;
  uint64_t misses;
  uint64_t nxdomain_hits;
  uint64_t nodata_hits;
  uint64_t insertions;
  uint64_t evictions;
  uint64_t expirations;
};

/**
 * @brief Normalize name to lowercase for case-insensitive lookup.
 */
static void
normalize_name (char *dest, const char *src, size_t max_len)
{
  size_t i;
  for (i = 0; src[i] && i < max_len; i++)
    dest[i] = (char)tolower ((unsigned char)src[i]);
  dest[i] = '\0';
}

/**
 * @brief Compute hash for cache key tuple.
 *
 * For NXDOMAIN: hash(name, 0, class)
 * For NODATA: hash(name, type, class)
 */
static unsigned
compute_hash (const char *name, uint16_t qtype, uint16_t qclass)
{
  unsigned hash = 5381; /* djb2 initial value */

  /* Hash the normalized name */
  for (const char *p = name; *p; p++)
    hash = ((hash << 5) + hash) ^ (unsigned char)tolower ((unsigned char)*p);

  /* Include qtype and qclass */
  hash = ((hash << 5) + hash) ^ qtype;
  hash = ((hash << 5) + hash) ^ qclass;

  return hash % NEGCACHE_HASH_SIZE;
}

/**
 * @brief Check if an entry has expired.
 */
static bool
entry_expired (const struct NegCacheEntry *entry, int64_t now_ms)
{
  int64_t age_ms = now_ms - entry->insert_time_ms;
  int64_t ttl_ms = (int64_t)entry->ttl * 1000;
  return age_ms >= ttl_ms;
}

/**
 * @brief Calculate remaining TTL.
 */
static uint32_t
entry_ttl_remaining (const struct NegCacheEntry *entry, int64_t now_ms)
{
  int64_t age_ms = now_ms - entry->insert_time_ms;
  int64_t ttl_ms = (int64_t)entry->ttl * 1000;
  int64_t remaining_ms = ttl_ms - age_ms;

  if (remaining_ms <= 0)
    return 0;

  return (uint32_t)(remaining_ms / 1000);
}

/**
 * @brief Remove entry from LRU list.
 */
static void
lru_remove (T cache, struct NegCacheEntry *entry)
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
lru_add_head (T cache, struct NegCacheEntry *entry)
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
lru_touch (T cache, struct NegCacheEntry *entry)
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
hash_remove (T cache, struct NegCacheEntry *entry, unsigned bucket)
{
  struct NegCacheEntry **pp = &cache->hash_table[bucket];
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
entry_free (T cache, struct NegCacheEntry *entry)
{
  /* Compute bucket for hash removal */
  unsigned bucket = compute_hash (entry->name, entry->qtype, entry->qclass);

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
 * @brief Find entry by exact key tuple.
 */
static struct NegCacheEntry *
find_entry (T cache, const char *normalized_name, uint16_t qtype,
            uint16_t qclass)
{
  unsigned bucket = compute_hash (normalized_name, qtype, qclass);
  struct NegCacheEntry *entry = cache->hash_table[bucket];

  while (entry)
    {
      if (entry->qtype == qtype && entry->qclass == qclass
          && strcasecmp (entry->name, normalized_name) == 0)
        return entry;
      entry = entry->hash_next;
    }

  return NULL;
}

/**
 * @brief Insert entry into hash table.
 */
static void
hash_insert (T cache, struct NegCacheEntry *entry)
{
  unsigned bucket = compute_hash (entry->name, entry->qtype, entry->qclass);
  entry->hash_next = cache->hash_table[bucket];
  cache->hash_table[bucket] = entry;
}

/**
 * @brief Allocate new entry from arena.
 */
static struct NegCacheEntry *
entry_alloc (T cache)
{
  return Arena_alloc (cache->arena, sizeof (struct NegCacheEntry), __FILE__,
                      __LINE__);
}

/* Public API */

T
SocketDNSNegCache_new (Arena_T arena)
{
  if (arena == NULL)
    return NULL;

  T cache = Arena_alloc (arena, sizeof (*cache), __FILE__, __LINE__);
  if (cache == NULL)
    return NULL;

  memset (cache, 0, sizeof (*cache));
  cache->arena = arena;
  cache->max_entries = DNS_NEGCACHE_DEFAULT_MAX;
  cache->max_ttl = DNS_NEGCACHE_DEFAULT_MAX_TTL;

  if (pthread_mutex_init (&cache->mutex, NULL) != 0)
    return NULL;

  return cache;
}

void
SocketDNSNegCache_free (T *cache)
{
  if (cache == NULL || *cache == NULL)
    return;

  pthread_mutex_destroy (&(*cache)->mutex);

  /* Arena handles memory, just clear pointer */
  *cache = NULL;
}

SocketDNS_NegCacheResult
SocketDNSNegCache_lookup (T cache, const char *qname, uint16_t qtype,
                          uint16_t qclass, SocketDNS_NegCacheEntry *entry)
{
  if (cache == NULL || qname == NULL)
    return DNS_NEG_MISS;

  char normalized[DNS_NEGCACHE_MAX_NAME + 1];
  normalize_name (normalized, qname, DNS_NEGCACHE_MAX_NAME);

  int64_t now_ms = Socket_get_monotonic_ms ();
  SocketDNS_NegCacheResult result = DNS_NEG_MISS;

  pthread_mutex_lock (&cache->mutex);

  /* First check for NXDOMAIN (qtype=0 matches any type) */
  struct NegCacheEntry *found = find_entry (cache, normalized, 0, qclass);
  if (found)
    {
      if (entry_expired (found, now_ms))
        {
          entry_free (cache, found);
          cache->expirations++;
          found = NULL;
        }
      else
        {
          result = DNS_NEG_HIT_NXDOMAIN;
          cache->hits++;
          cache->nxdomain_hits++;
          lru_touch (cache, found);
        }
    }

  /* If no NXDOMAIN, check for type-specific NODATA */
  if (result == DNS_NEG_MISS)
    {
      found = find_entry (cache, normalized, qtype, qclass);
      if (found)
        {
          if (entry_expired (found, now_ms))
            {
              entry_free (cache, found);
              cache->expirations++;
              found = NULL;
            }
          else
            {
              result = DNS_NEG_HIT_NODATA;
              cache->hits++;
              cache->nodata_hits++;
              lru_touch (cache, found);
            }
        }
    }

  /* Fill in entry details if requested and found */
  if (entry != NULL && found != NULL)
    {
      entry->type = found->type;
      entry->original_ttl = found->ttl;
      entry->ttl_remaining = entry_ttl_remaining (found, now_ms);
      entry->insert_time_ms = found->insert_time_ms;
    }

  if (result == DNS_NEG_MISS)
    cache->misses++;

  pthread_mutex_unlock (&cache->mutex);

  return result;
}

int
SocketDNSNegCache_insert_nxdomain (T cache, const char *qname, uint16_t qclass,
                                    uint32_t ttl)
{
  if (cache == NULL || qname == NULL)
    return -1;

  /* Reject if cache is disabled */
  if (cache->max_entries == 0)
    return -1;

  /* Validate name length before normalizing */
  size_t qname_len = strlen (qname);
  if (qname_len > DNS_NEGCACHE_MAX_NAME)
    return -1;

  char normalized[DNS_NEGCACHE_MAX_NAME + 1];
  normalize_name (normalized, qname, DNS_NEGCACHE_MAX_NAME);

  /* Cap TTL */
  if (ttl > cache->max_ttl)
    ttl = cache->max_ttl;

  pthread_mutex_lock (&cache->mutex);

  /* Check if already exists and update */
  struct NegCacheEntry *existing = find_entry (cache, normalized, 0, qclass);
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
  struct NegCacheEntry *entry = entry_alloc (cache);
  if (entry == NULL)
    {
      pthread_mutex_unlock (&cache->mutex);
      return -1;
    }

  memset (entry, 0, sizeof (*entry));
  strncpy (entry->name, normalized, DNS_NEGCACHE_MAX_NAME);
  entry->name[DNS_NEGCACHE_MAX_NAME] = '\0';
  entry->qtype = 0; /* NXDOMAIN uses qtype=0 */
  entry->qclass = qclass;
  entry->type = DNS_NEG_NXDOMAIN;
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
SocketDNSNegCache_insert_nodata (T cache, const char *qname, uint16_t qtype,
                                  uint16_t qclass, uint32_t ttl)
{
  if (cache == NULL || qname == NULL)
    return -1;

  /* qtype=0 is reserved for NXDOMAIN */
  if (qtype == 0)
    return -1;

  /* Reject if cache is disabled */
  if (cache->max_entries == 0)
    return -1;

  /* Validate name length before normalizing */
  size_t qname_len = strlen (qname);
  if (qname_len > DNS_NEGCACHE_MAX_NAME)
    return -1;

  char normalized[DNS_NEGCACHE_MAX_NAME + 1];
  normalize_name (normalized, qname, DNS_NEGCACHE_MAX_NAME);

  /* Cap TTL */
  if (ttl > cache->max_ttl)
    ttl = cache->max_ttl;

  pthread_mutex_lock (&cache->mutex);

  /* Check if already exists and update */
  struct NegCacheEntry *existing
      = find_entry (cache, normalized, qtype, qclass);
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
  struct NegCacheEntry *entry = entry_alloc (cache);
  if (entry == NULL)
    {
      pthread_mutex_unlock (&cache->mutex);
      return -1;
    }

  memset (entry, 0, sizeof (*entry));
  strncpy (entry->name, normalized, DNS_NEGCACHE_MAX_NAME);
  entry->name[DNS_NEGCACHE_MAX_NAME] = '\0';
  entry->qtype = qtype;
  entry->qclass = qclass;
  entry->type = DNS_NEG_NODATA;
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
SocketDNSNegCache_remove (T cache, const char *qname)
{
  if (cache == NULL || qname == NULL)
    return 0;

  char normalized[DNS_NEGCACHE_MAX_NAME + 1];
  normalize_name (normalized, qname, DNS_NEGCACHE_MAX_NAME);

  int removed = 0;

  pthread_mutex_lock (&cache->mutex);

  /* Scan all buckets for entries with this name */
  for (unsigned i = 0; i < NEGCACHE_HASH_SIZE; i++)
    {
      struct NegCacheEntry **pp = &cache->hash_table[i];
      while (*pp)
        {
          struct NegCacheEntry *entry = *pp;
          if (strcasecmp (entry->name, normalized) == 0)
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

int
SocketDNSNegCache_remove_nodata (T cache, const char *qname, uint16_t qtype,
                                  uint16_t qclass)
{
  if (cache == NULL || qname == NULL || qtype == 0)
    return 0;

  char normalized[DNS_NEGCACHE_MAX_NAME + 1];
  normalize_name (normalized, qname, DNS_NEGCACHE_MAX_NAME);

  pthread_mutex_lock (&cache->mutex);

  struct NegCacheEntry *entry = find_entry (cache, normalized, qtype, qclass);
  if (entry)
    {
      entry_free (cache, entry);
      pthread_mutex_unlock (&cache->mutex);
      return 1;
    }

  pthread_mutex_unlock (&cache->mutex);

  return 0;
}

void
SocketDNSNegCache_clear (T cache)
{
  if (cache == NULL)
    return;

  pthread_mutex_lock (&cache->mutex);

  /* Clear hash table */
  for (unsigned i = 0; i < NEGCACHE_HASH_SIZE; i++)
    cache->hash_table[i] = NULL;

  /* Clear LRU list */
  cache->lru_head = NULL;
  cache->lru_tail = NULL;
  cache->size = 0;

  pthread_mutex_unlock (&cache->mutex);
}

void
SocketDNSNegCache_set_max_entries (T cache, size_t max_entries)
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
SocketDNSNegCache_set_max_ttl (T cache, uint32_t max_ttl)
{
  if (cache == NULL)
    return;

  pthread_mutex_lock (&cache->mutex);
  cache->max_ttl = max_ttl;
  pthread_mutex_unlock (&cache->mutex);
}

void
SocketDNSNegCache_stats (T cache, SocketDNS_NegCacheStats *stats)
{
  if (cache == NULL || stats == NULL)
    return;

  pthread_mutex_lock (&cache->mutex);

  stats->hits = cache->hits;
  stats->misses = cache->misses;
  stats->nxdomain_hits = cache->nxdomain_hits;
  stats->nodata_hits = cache->nodata_hits;
  stats->insertions = cache->insertions;
  stats->evictions = cache->evictions;
  stats->expirations = cache->expirations;
  stats->current_size = cache->size;
  stats->max_entries = cache->max_entries;
  stats->max_ttl = cache->max_ttl;

  uint64_t total = stats->hits + stats->misses;
  stats->hit_rate = (total > 0) ? ((double)stats->hits / total) : 0.0;

  pthread_mutex_unlock (&cache->mutex);
}

const char *
SocketDNSNegCache_type_name (SocketDNS_NegCacheType type)
{
  switch (type)
    {
    case DNS_NEG_NXDOMAIN:
      return "NXDOMAIN";
    case DNS_NEG_NODATA:
      return "NODATA";
    default:
      return "UNKNOWN";
    }
}

const char *
SocketDNSNegCache_result_name (SocketDNS_NegCacheResult result)
{
  switch (result)
    {
    case DNS_NEG_MISS:
      return "MISS";
    case DNS_NEG_HIT_NXDOMAIN:
      return "HIT_NXDOMAIN";
    case DNS_NEG_HIT_NODATA:
      return "HIT_NODATA";
    default:
      return "UNKNOWN";
    }
}

#undef T

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
#include "dns/SocketDNSWire.h"
#include "core/Arena.h"
#include "core/SocketUtil.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <pthread.h>
#include <string.h>
#include <strings.h>

#define T SocketDNSNegCache_T

/** Hash table size (prime for better distribution). */
#define NEGCACHE_HASH_SIZE 257

/**
 * @brief Internal cache entry structure.
 *
 * Extended for RFC 2308 Section 6 compliance with cached SOA data.
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

  /* RFC 2308 Section 6: Cached SOA for authority section */
  int has_soa;       /**< Whether SOA data is present */
  char soa_name[DNS_NEGCACHE_MAX_SOA_NAME + 1];    /**< SOA owner name */
  unsigned char soa_rdata[DNS_NEGCACHE_MAX_SOA_RDATA]; /**< Raw SOA RDATA */
  size_t soa_rdlen;  /**< SOA RDATA length */
  uint32_t soa_ttl;  /**< Original SOA record TTL */
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

      /* Copy SOA data for RFC 2308 Section 6 compliance */
      entry->soa.has_soa = found->has_soa;
      if (found->has_soa)
        {
          strncpy (entry->soa.name, found->soa_name, DNS_NEGCACHE_MAX_SOA_NAME);
          entry->soa.name[DNS_NEGCACHE_MAX_SOA_NAME] = '\0';
          entry->soa.rdlen = found->soa_rdlen;
          if (found->soa_rdlen > 0 && found->soa_rdlen <= DNS_NEGCACHE_MAX_SOA_RDATA)
            memcpy (entry->soa.rdata, found->soa_rdata, found->soa_rdlen);
          entry->soa.original_ttl = found->soa_ttl;
        }
      else
        {
          memset (&entry->soa, 0, sizeof (entry->soa));
        }
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

/**
 * @brief Helper to copy SOA data to internal entry.
 */
static void
copy_soa_to_entry (struct NegCacheEntry *entry, const SocketDNS_CachedSOA *soa)
{
  if (soa == NULL || !soa->has_soa)
    {
      entry->has_soa = 0;
      return;
    }

  entry->has_soa = 1;
  strncpy (entry->soa_name, soa->name, DNS_NEGCACHE_MAX_SOA_NAME);
  entry->soa_name[DNS_NEGCACHE_MAX_SOA_NAME] = '\0';

  size_t rdlen = soa->rdlen;
  if (rdlen > DNS_NEGCACHE_MAX_SOA_RDATA)
    rdlen = DNS_NEGCACHE_MAX_SOA_RDATA;

  entry->soa_rdlen = rdlen;
  if (rdlen > 0)
    memcpy (entry->soa_rdata, soa->rdata, rdlen);

  entry->soa_ttl = soa->original_ttl;
}

int
SocketDNSNegCache_insert_nxdomain_with_soa (T cache, const char *qname,
                                             uint16_t qclass, uint32_t ttl,
                                             const SocketDNS_CachedSOA *soa)
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
      copy_soa_to_entry (existing, soa);
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
  copy_soa_to_entry (entry, soa);

  hash_insert (cache, entry);
  lru_add_head (cache, entry);
  cache->size++;
  cache->insertions++;

  pthread_mutex_unlock (&cache->mutex);

  return 0;
}

int
SocketDNSNegCache_insert_nodata_with_soa (T cache, const char *qname,
                                           uint16_t qtype, uint16_t qclass,
                                           uint32_t ttl,
                                           const SocketDNS_CachedSOA *soa)
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
      copy_soa_to_entry (existing, soa);
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
  copy_soa_to_entry (entry, soa);

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

/* RFC 2308 Section 6: Response Building */

int
SocketDNSNegCache_build_response (const SocketDNS_NegCacheEntry *entry,
                                   const char *qname, uint16_t qtype,
                                   uint16_t qclass, uint16_t query_id,
                                   unsigned char *buf, size_t buflen,
                                   size_t *written)
{
  if (entry == NULL || qname == NULL || buf == NULL)
    return -1;

  /* Need at least header + question + SOA RR space */
  if (buflen < DNS_HEADER_SIZE + 4 + DNS_MAX_NAME_LEN)
    return -1;

  size_t offset = 0;

  /* Build DNS response header */
  SocketDNS_Header header;
  memset (&header, 0, sizeof (header));
  header.id = query_id;
  header.qr = 1;     /* Response */
  header.opcode = 0; /* Standard query */
  header.aa = 0;     /* Not authoritative (cached) */
  header.tc = 0;     /* Not truncated */
  header.rd = 1;     /* Recursion desired (echo from query) */
  header.ra = 1;     /* Recursion available */
  header.z = 0;
  header.qdcount = 1; /* One question */
  header.ancount = 0; /* No answer records */
  header.arcount = 0; /* No additional records */

  /* Set RCODE based on entry type */
  if (entry->type == DNS_NEG_NXDOMAIN)
    header.rcode = DNS_RCODE_NXDOMAIN; /* NXDOMAIN = 3 */
  else
    header.rcode = DNS_RCODE_NOERROR; /* NODATA = 0 with empty answer */

  /* Set NSCOUNT based on whether we have SOA */
  header.nscount = entry->soa.has_soa ? 1 : 0;

  /* Encode header */
  if (SocketDNS_header_encode (&header, buf, buflen) != 0)
    return -1;
  offset += DNS_HEADER_SIZE;

  /* Encode question section */
  SocketDNS_Question question;
  SocketDNS_question_init (&question, qname, qtype);
  question.qclass = qclass;

  size_t question_len = 0;
  if (SocketDNS_question_encode (&question, buf + offset, buflen - offset,
                                  &question_len)
      != 0)
    return -1;
  offset += question_len;

  /* Add SOA to authority section if available (RFC 2308 Section 6) */
  if (entry->soa.has_soa && entry->soa.rdlen > 0)
    {
      /* Calculate decremented TTL per RFC 2308 Section 6 */
      uint32_t decremented_ttl = entry->ttl_remaining;

      /* Also cap at SOA's remaining TTL if it was higher originally */
      /* Use the minimum of entry TTL and SOA record TTL */
      if (entry->soa.original_ttl > 0)
        {
          /* SOA TTL should decrease at same rate as entry TTL */
          if (decremented_ttl > entry->soa.original_ttl)
            decremented_ttl = entry->soa.original_ttl;
        }

      /* Encode SOA owner name */
      size_t soa_name_len = 0;
      if (SocketDNS_name_encode (entry->soa.name, buf + offset, buflen - offset,
                                  &soa_name_len)
          != 0)
        return -1;
      offset += soa_name_len;

      /* Check space for TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA */
      if (offset + 10 + entry->soa.rdlen > buflen)
        return -1;

      /* TYPE = SOA (6) */
      buf[offset++] = 0;
      buf[offset++] = DNS_TYPE_SOA;

      /* CLASS = IN (1) */
      buf[offset++] = 0;
      buf[offset++] = (uint8_t)qclass;

      /* TTL - decremented per RFC 2308 Section 6 */
      buf[offset++] = (uint8_t)(decremented_ttl >> 24);
      buf[offset++] = (uint8_t)(decremented_ttl >> 16);
      buf[offset++] = (uint8_t)(decremented_ttl >> 8);
      buf[offset++] = (uint8_t)(decremented_ttl);

      /* RDLENGTH */
      buf[offset++] = (uint8_t)(entry->soa.rdlen >> 8);
      buf[offset++] = (uint8_t)(entry->soa.rdlen);

      /* RDATA (raw SOA data) */
      memcpy (buf + offset, entry->soa.rdata, entry->soa.rdlen);
      offset += entry->soa.rdlen;
    }

  if (written != NULL)
    *written = offset;

  return 0;
}

#undef T

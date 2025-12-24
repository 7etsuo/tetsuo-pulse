/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDNSCookie.c
 * @brief DNS Cookies implementation (RFC 7873).
 */

#include "dns/SocketDNSCookie.h"
#include "dns/SocketDNSWire.h"
#include "core/Arena.h"
#include <arpa/inet.h>
#include <string.h>
#include <sys/random.h>

#ifdef SOCKET_HAS_TLS
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#endif

#define T SocketDNSCookie_T

/* Exception definition */
const Except_T SocketDNSCookie_Failed
    = {&SocketDNSCookie_Failed, "DNS Cookie operation failed"};

/* Client secret size (256 bits for HMAC-SHA256) */
#define SECRET_SIZE 32

/* Internal cache entry with LRU tracking */
typedef struct CacheNode
{
  SocketDNSCookie_Entry entry;
  struct CacheNode *next;
  struct CacheNode *prev;
  time_t last_used;
} CacheNode;

/* Cookie cache structure */
struct T
{
  Arena_T arena;

  /* Client secret for cookie generation */
  uint8_t secret[SECRET_SIZE];
  time_t secret_created_at;
  int secret_lifetime;

  /* Previous secret for rollover period */
  uint8_t prev_secret[SECRET_SIZE];
  time_t prev_secret_valid_until;

  /* Cache configuration */
  size_t max_entries;
  int server_ttl;

  /* LRU cache implemented as doubly-linked list */
  CacheNode *head; /* Most recently used */
  CacheNode *tail; /* Least recently used */
  size_t count;

  /* Statistics */
  SocketDNSCookie_Stats stats;
};

/* Forward declarations */
static int generate_client_cookie (T cache, const struct sockaddr *server_addr,
                                   socklen_t addr_len,
                                   const struct sockaddr *client_addr,
                                   socklen_t client_len, uint8_t *cookie);
static int get_entropy (uint8_t *buf, size_t len);
static int constant_time_compare (const uint8_t *a, const uint8_t *b,
                                  size_t len);
static CacheNode *find_node (T cache, const struct sockaddr *addr,
                             socklen_t len);
static void move_to_front (T cache, CacheNode *node);
static void evict_lru (T cache);
static int addr_equal (const struct sockaddr *a, socklen_t alen,
                       const struct sockaddr *b, socklen_t blen);

/*
 * Create a new DNS Cookie cache
 */
T
SocketDNSCookie_new (Arena_T arena)
{
  T cache;

  if (arena == NULL)
    RAISE (SocketDNSCookie_Failed);

  cache = Arena_alloc (arena, sizeof (*cache), __FILE__, __LINE__);
  memset (cache, 0, sizeof (*cache));

  cache->arena = arena;
  cache->max_entries = DNS_COOKIE_CACHE_DEFAULT_SIZE;
  cache->server_ttl = DNS_COOKIE_SERVER_TTL_DEFAULT;
  cache->secret_lifetime = DNS_COOKIE_SECRET_LIFETIME_DEFAULT;

  /* Generate initial secret */
  if (get_entropy (cache->secret, SECRET_SIZE) != 0)
    RAISE (SocketDNSCookie_Failed);

  cache->secret_created_at = time (NULL);

  return cache;
}

/*
 * Dispose of a DNS Cookie cache
 */
void
SocketDNSCookie_free (T *cache)
{
  if (cache == NULL || *cache == NULL)
    return;

  /* Clear sensitive data */
  memset ((*cache)->secret, 0, SECRET_SIZE);
  memset ((*cache)->prev_secret, 0, SECRET_SIZE);

  /* Clear cache entries */
  CacheNode *node = (*cache)->head;
  while (node)
    {
      CacheNode *next = node->next;
      memset (&node->entry.server_cookie, 0, DNS_SERVER_COOKIE_MAX_SIZE);
      node = next;
    }

  *cache = NULL;
}

/*
 * Set client secret lifetime
 */
void
SocketDNSCookie_set_secret_lifetime (T cache, int lifetime_seconds)
{
  if (cache == NULL)
    return;

  if (lifetime_seconds < 60)
    lifetime_seconds = 60;
  if (lifetime_seconds > DNS_COOKIE_SECRET_LIFETIME_MAX)
    lifetime_seconds = DNS_COOKIE_SECRET_LIFETIME_MAX;

  cache->secret_lifetime = lifetime_seconds;
}

/*
 * Set maximum cache entries
 */
void
SocketDNSCookie_set_cache_size (T cache, size_t max_entries)
{
  if (cache == NULL)
    return;

  if (max_entries < 1)
    max_entries = 1;
  if (max_entries > DNS_COOKIE_CACHE_MAX_SIZE)
    max_entries = DNS_COOKIE_CACHE_MAX_SIZE;

  cache->max_entries = max_entries;

  /* Evict excess entries */
  while (cache->count > cache->max_entries)
    evict_lru (cache);
}

/*
 * Set server cookie TTL
 */
void
SocketDNSCookie_set_server_ttl (T cache, int ttl_seconds)
{
  if (cache == NULL)
    return;

  if (ttl_seconds < 60)
    ttl_seconds = 60;
  if (ttl_seconds > 86400)
    ttl_seconds = 86400;

  cache->server_ttl = ttl_seconds;
}

/*
 * Force rotation of client secret
 */
int
SocketDNSCookie_rotate_secret (T cache)
{
  if (cache == NULL)
    return -1;

  /* Save previous secret for rollover */
  memcpy (cache->prev_secret, cache->secret, SECRET_SIZE);
  cache->prev_secret_valid_until
      = time (NULL) + 150; /* 150 seconds per RFC 7873 */

  /* Generate new secret */
  if (get_entropy (cache->secret, SECRET_SIZE) != 0)
    return -1;

  cache->secret_created_at = time (NULL);
  cache->stats.secret_rotations++;

  return 0;
}

/*
 * Check and perform automatic secret rotation if needed
 */
static void
check_secret_rotation (T cache)
{
  time_t now = time (NULL);

  if (now - cache->secret_created_at >= cache->secret_lifetime)
    SocketDNSCookie_rotate_secret (cache);
}

/*
 * Generate a client cookie for a server
 */
int
SocketDNSCookie_generate (T cache, const struct sockaddr *server_addr,
                          socklen_t addr_len,
                          const struct sockaddr *client_addr,
                          socklen_t client_len, SocketDNSCookie_Cookie *cookie)
{
  if (cache == NULL || server_addr == NULL || cookie == NULL)
    return -1;

  check_secret_rotation (cache);

  memset (cookie, 0, sizeof (*cookie));

  /* Generate client cookie */
  if (generate_client_cookie (cache, server_addr, addr_len, client_addr,
                              client_len, cookie->client_cookie)
      != 0)
    return -1;

  cache->stats.client_cookies_generated++;

  /* Check for cached server cookie */
  SocketDNSCookie_Entry entry;
  if (SocketDNSCookie_cache_lookup (cache, server_addr, addr_len, &entry))
    {
      memcpy (cookie->server_cookie, entry.server_cookie,
              entry.server_cookie_len);
      cookie->server_cookie_len = entry.server_cookie_len;
    }

  return 0;
}

/*
 * Parse cookie from EDNS0 option data
 */
int
SocketDNSCookie_parse (const unsigned char *data, size_t len,
                       SocketDNSCookie_Cookie *cookie)
{
  if (data == NULL || cookie == NULL)
    return -1;

  /* Validate length per RFC 7873:
   * - 8 bytes: client cookie only
   * - 16-40 bytes: client + server cookie
   */
  if (len < DNS_COOKIE_OPTION_MIN_LEN)
    return -1;
  if (len > DNS_COOKIE_OPTION_MAX_LEN)
    return -1;
  if (len > DNS_CLIENT_COOKIE_SIZE
      && len < DNS_CLIENT_COOKIE_SIZE + DNS_SERVER_COOKIE_MIN_SIZE)
    return -1;

  memset (cookie, 0, sizeof (*cookie));

  /* Copy client cookie */
  memcpy (cookie->client_cookie, data, DNS_CLIENT_COOKIE_SIZE);

  /* Copy server cookie if present */
  if (len > DNS_CLIENT_COOKIE_SIZE)
    {
      cookie->server_cookie_len = len - DNS_CLIENT_COOKIE_SIZE;
      memcpy (cookie->server_cookie, data + DNS_CLIENT_COOKIE_SIZE,
              cookie->server_cookie_len);
    }

  return 0;
}

/*
 * Encode cookie to EDNS0 option format
 */
int
SocketDNSCookie_encode (const SocketDNSCookie_Cookie *cookie, unsigned char *buf,
                        size_t buflen)
{
  if (cookie == NULL || buf == NULL)
    return -1;

  size_t total = DNS_CLIENT_COOKIE_SIZE + cookie->server_cookie_len;
  if (buflen < total)
    return -1;

  /* Copy client cookie */
  memcpy (buf, cookie->client_cookie, DNS_CLIENT_COOKIE_SIZE);

  /* Copy server cookie if present */
  if (cookie->server_cookie_len > 0)
    memcpy (buf + DNS_CLIENT_COOKIE_SIZE, cookie->server_cookie,
            cookie->server_cookie_len);

  return (int)total;
}

/*
 * Store a server cookie in the cache
 */
int
SocketDNSCookie_cache_store (T cache, const struct sockaddr *server_addr,
                             socklen_t addr_len, const uint8_t *client_cookie,
                             const uint8_t *server_cookie, size_t server_len)
{
  if (cache == NULL || server_addr == NULL || client_cookie == NULL
      || server_cookie == NULL)
    return -1;

  /* Validate server cookie length */
  if (server_len < DNS_SERVER_COOKIE_MIN_SIZE
      || server_len > DNS_SERVER_COOKIE_MAX_SIZE)
    return -1;

  time_t now = time (NULL);

  /* Look for existing entry */
  CacheNode *node = find_node (cache, server_addr, addr_len);

  if (node)
    {
      /* Update existing entry */
      memcpy (node->entry.client_cookie, client_cookie, DNS_CLIENT_COOKIE_SIZE);
      memcpy (node->entry.server_cookie, server_cookie, server_len);
      node->entry.server_cookie_len = server_len;
      node->entry.received_at = now;
      node->entry.expires_at = now + cache->server_ttl;
      node->last_used = now;
      move_to_front (cache, node);
    }
  else
    {
      /* Evict if at capacity */
      if (cache->count >= cache->max_entries)
        evict_lru (cache);

      /* Create new entry */
      node = Arena_alloc (cache->arena, sizeof (*node), __FILE__, __LINE__);
      memset (node, 0, sizeof (*node));

      memcpy (&node->entry.server_addr, server_addr, addr_len);
      node->entry.addr_len = addr_len;
      memcpy (node->entry.client_cookie, client_cookie, DNS_CLIENT_COOKIE_SIZE);
      memcpy (node->entry.server_cookie, server_cookie, server_len);
      node->entry.server_cookie_len = server_len;
      node->entry.received_at = now;
      node->entry.expires_at = now + cache->server_ttl;
      node->last_used = now;

      /* Add to front of list */
      node->next = cache->head;
      node->prev = NULL;
      if (cache->head)
        cache->head->prev = node;
      cache->head = node;
      if (!cache->tail)
        cache->tail = node;

      cache->count++;
      cache->stats.server_cookies_cached++;
    }

  cache->stats.current_entries = cache->count;
  return 0;
}

/*
 * Look up a cached server cookie
 */
int
SocketDNSCookie_cache_lookup (T cache, const struct sockaddr *server_addr,
                              socklen_t addr_len, SocketDNSCookie_Entry *entry)
{
  if (cache == NULL || server_addr == NULL)
    return 0;

  CacheNode *node = find_node (cache, server_addr, addr_len);

  if (!node)
    {
      cache->stats.cache_misses++;
      return 0;
    }

  /* Check expiration */
  time_t now = time (NULL);
  if (now >= node->entry.expires_at)
    {
      /* Expired - remove from cache */
      SocketDNSCookie_cache_invalidate (cache, server_addr, addr_len);
      cache->stats.cache_misses++;
      return 0;
    }

  /* Update LRU */
  node->last_used = now;
  move_to_front (cache, node);
  cache->stats.cache_hits++;

  if (entry)
    memcpy (entry, &node->entry, sizeof (*entry));

  return 1;
}

/*
 * Invalidate cached cookie for a server
 */
int
SocketDNSCookie_cache_invalidate (T cache, const struct sockaddr *server_addr,
                                  socklen_t addr_len)
{
  if (cache == NULL || server_addr == NULL)
    return 0;

  CacheNode *node = find_node (cache, server_addr, addr_len);
  if (!node)
    return 0;

  /* Remove from list */
  if (node->prev)
    node->prev->next = node->next;
  else
    cache->head = node->next;

  if (node->next)
    node->next->prev = node->prev;
  else
    cache->tail = node->prev;

  /* Clear sensitive data */
  memset (&node->entry.server_cookie, 0, DNS_SERVER_COOKIE_MAX_SIZE);

  cache->count--;
  cache->stats.current_entries = cache->count;

  return 1;
}

/*
 * Clear all cached server cookies
 */
void
SocketDNSCookie_cache_clear (T cache)
{
  if (cache == NULL)
    return;

  CacheNode *node = cache->head;
  while (node)
    {
      CacheNode *next = node->next;
      memset (&node->entry.server_cookie, 0, DNS_SERVER_COOKIE_MAX_SIZE);
      node = next;
    }

  cache->head = NULL;
  cache->tail = NULL;
  cache->count = 0;
  cache->stats.current_entries = 0;
}

/*
 * Remove expired entries
 */
int
SocketDNSCookie_cache_expire (T cache)
{
  if (cache == NULL)
    return 0;

  time_t now = time (NULL);
  int removed = 0;

  CacheNode *node = cache->head;
  while (node)
    {
      CacheNode *next = node->next;
      if (now >= node->entry.expires_at)
        {
          if (SocketDNSCookie_cache_invalidate (
                  cache, (struct sockaddr *)&node->entry.server_addr,
                  node->entry.addr_len))
            removed++;
        }
      node = next;
    }

  return removed;
}

/*
 * Validate response cookie against request
 */
int
SocketDNSCookie_validate (const SocketDNSCookie_Cookie *sent_cookie,
                          const SocketDNSCookie_Cookie *response)
{
  if (sent_cookie == NULL || response == NULL)
    return 0;

  return constant_time_compare (sent_cookie->client_cookie,
                                response->client_cookie,
                                DNS_CLIENT_COOKIE_SIZE);
}

/*
 * Check if RCODE is BADCOOKIE
 */
int
SocketDNSCookie_is_badcookie (uint16_t rcode)
{
  return rcode == DNS_RCODE_BADCOOKIE;
}

/*
 * Get statistics
 */
void
SocketDNSCookie_stats (T cache, SocketDNSCookie_Stats *stats)
{
  if (cache == NULL || stats == NULL)
    return;

  memcpy (stats, &cache->stats, sizeof (*stats));
  stats->max_entries = cache->max_entries;
  stats->secret_expires_at = cache->secret_created_at + cache->secret_lifetime;
}

/*
 * Reset statistics
 */
void
SocketDNSCookie_stats_reset (T cache)
{
  if (cache == NULL)
    return;

  memset (&cache->stats, 0, sizeof (cache->stats));
  cache->stats.current_entries = cache->count;
}

/*
 * Compare two cookies for equality
 */
int
SocketDNSCookie_equal (const SocketDNSCookie_Cookie *a,
                       const SocketDNSCookie_Cookie *b)
{
  if (a == NULL || b == NULL)
    return 0;

  if (!constant_time_compare (a->client_cookie, b->client_cookie,
                              DNS_CLIENT_COOKIE_SIZE))
    return 0;

  if (a->server_cookie_len != b->server_cookie_len)
    return 0;

  if (a->server_cookie_len > 0)
    {
      if (!constant_time_compare (a->server_cookie, b->server_cookie,
                                  a->server_cookie_len))
        return 0;
    }

  return 1;
}

/*
 * Format cookie as hex string
 */
int
SocketDNSCookie_to_hex (const SocketDNSCookie_Cookie *cookie, char *buf,
                        size_t buflen)
{
  static const char hex[] = "0123456789abcdef";

  if (cookie == NULL || buf == NULL)
    return -1;

  /* Calculate required size: client(16) + ':' + server(max 64) + '\0' */
  size_t needed = DNS_CLIENT_COOKIE_SIZE * 2 + 1;
  if (cookie->server_cookie_len > 0)
    needed += 1 + cookie->server_cookie_len * 2;

  if (buflen < needed)
    return -1;

  char *p = buf;

  /* Format client cookie */
  for (int i = 0; i < DNS_CLIENT_COOKIE_SIZE; i++)
    {
      *p++ = hex[(cookie->client_cookie[i] >> 4) & 0xF];
      *p++ = hex[cookie->client_cookie[i] & 0xF];
    }

  /* Format server cookie if present */
  if (cookie->server_cookie_len > 0)
    {
      *p++ = ':';
      for (size_t i = 0; i < cookie->server_cookie_len; i++)
        {
          *p++ = hex[(cookie->server_cookie[i] >> 4) & 0xF];
          *p++ = hex[cookie->server_cookie[i] & 0xF];
        }
    }

  *p = '\0';
  return (int)(p - buf);
}

/* ========== Internal helper functions ========== */

/*
 * Generate entropy for secrets/cookies
 */
static int
get_entropy (uint8_t *buf, size_t len)
{
#ifdef SOCKET_HAS_TLS
  if (RAND_bytes (buf, (int)len) == 1)
    return 0;
#endif

  /* Fallback to getrandom() */
  ssize_t ret = getrandom (buf, len, 0);
  if (ret == (ssize_t)len)
    return 0;

  return -1;
}

/*
 * Constant-time comparison to prevent timing attacks
 */
static int
constant_time_compare (const uint8_t *a, const uint8_t *b, size_t len)
{
  uint8_t result = 0;
  for (size_t i = 0; i < len; i++)
    result |= a[i] ^ b[i];
  return result == 0;
}

/*
 * Generate client cookie using HMAC-SHA256
 */
static int
generate_client_cookie (T cache, const struct sockaddr *server_addr,
                        socklen_t addr_len __attribute__ ((unused)),
                        const struct sockaddr *client_addr,
                        socklen_t client_len, uint8_t *cookie)
{
#ifdef SOCKET_HAS_TLS
  unsigned char data[256];
  size_t data_len = 0;

  /* Build input: server IP + client IP */
  if (server_addr->sa_family == AF_INET)
    {
      const struct sockaddr_in *sin = (const struct sockaddr_in *)server_addr;
      /* Bounds check: IPv4 address is 4 bytes */
      if (data_len + sizeof (sin->sin_addr) > sizeof (data))
        return -1;
      memcpy (data + data_len, &sin->sin_addr, sizeof (sin->sin_addr));
      data_len += sizeof (sin->sin_addr);
    }
  else if (server_addr->sa_family == AF_INET6)
    {
      const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)server_addr;
      /* Bounds check: IPv6 address is 16 bytes */
      if (data_len + sizeof (sin6->sin6_addr) > sizeof (data))
        return -1;
      memcpy (data + data_len, &sin6->sin6_addr, sizeof (sin6->sin6_addr));
      data_len += sizeof (sin6->sin6_addr);
    }
  else
    {
      return -1;
    }

  if (client_addr && client_len > 0)
    {
      if (client_addr->sa_family == AF_INET)
        {
          const struct sockaddr_in *sin = (const struct sockaddr_in *)client_addr;
          /* Bounds check before copy */
          if (data_len + sizeof (sin->sin_addr) > sizeof (data))
            return -1;
          memcpy (data + data_len, &sin->sin_addr, sizeof (sin->sin_addr));
          data_len += sizeof (sin->sin_addr);
        }
      else if (client_addr->sa_family == AF_INET6)
        {
          const struct sockaddr_in6 *sin6
              = (const struct sockaddr_in6 *)client_addr;
          /* Bounds check before copy */
          if (data_len + sizeof (sin6->sin6_addr) > sizeof (data))
            return -1;
          memcpy (data + data_len, &sin6->sin6_addr, sizeof (sin6->sin6_addr));
          data_len += sizeof (sin6->sin6_addr);
        }
    }

  /* HMAC-SHA256 and truncate to 64 bits */
  unsigned char hmac_out[32];
  unsigned int hmac_len = 0;

  HMAC (EVP_sha256 (), cache->secret, SECRET_SIZE, data, data_len, hmac_out,
        &hmac_len);

  /* Verify HMAC succeeded and produced expected length */
  if (hmac_len < DNS_CLIENT_COOKIE_SIZE)
    return -1;

  memcpy (cookie, hmac_out, DNS_CLIENT_COOKIE_SIZE);
  return 0;

#else
  /* Fallback: FNV-1a 64-bit (RFC 7873 Appendix A.1) */
  uint64_t hash = 14695981039346656037ULL; /* FNV offset basis */
  const uint64_t prime = 1099511628211ULL; /* FNV prime */

  /* Hash server address */
  const uint8_t *p = (const uint8_t *)server_addr;
  for (socklen_t i = 0; i < addr_len; i++)
    {
      hash ^= p[i];
      hash *= prime;
    }

  /* Hash client address if provided */
  if (client_addr && client_len > 0)
    {
      p = (const uint8_t *)client_addr;
      for (socklen_t i = 0; i < client_len; i++)
        {
          hash ^= p[i];
          hash *= prime;
        }
    }

  /* Hash secret */
  for (int i = 0; i < SECRET_SIZE; i++)
    {
      hash ^= cache->secret[i];
      hash *= prime;
    }

  /* Store as big-endian */
  cookie[0] = (hash >> 56) & 0xFF;
  cookie[1] = (hash >> 48) & 0xFF;
  cookie[2] = (hash >> 40) & 0xFF;
  cookie[3] = (hash >> 32) & 0xFF;
  cookie[4] = (hash >> 24) & 0xFF;
  cookie[5] = (hash >> 16) & 0xFF;
  cookie[6] = (hash >> 8) & 0xFF;
  cookie[7] = hash & 0xFF;

  return 0;
#endif
}

/*
 * Find cache node by address
 */
static CacheNode *
find_node (T cache, const struct sockaddr *addr, socklen_t len)
{
  CacheNode *node = cache->head;
  while (node)
    {
      if (addr_equal ((struct sockaddr *)&node->entry.server_addr,
                      node->entry.addr_len, addr, len))
        return node;
      node = node->next;
    }
  return NULL;
}

/*
 * Move node to front of LRU list
 */
static void
move_to_front (T cache, CacheNode *node)
{
  if (node == cache->head)
    return; /* Already at front */

  /* Remove from current position */
  if (node->prev)
    node->prev->next = node->next;
  if (node->next)
    node->next->prev = node->prev;
  if (node == cache->tail)
    cache->tail = node->prev;

  /* Add to front */
  node->prev = NULL;
  node->next = cache->head;
  if (cache->head)
    cache->head->prev = node;
  cache->head = node;
}

/*
 * Evict least recently used entry
 */
static void
evict_lru (T cache)
{
  if (!cache->tail)
    return;

  CacheNode *node = cache->tail;

  /* Remove from list */
  if (node->prev)
    node->prev->next = NULL;
  cache->tail = node->prev;

  if (cache->head == node)
    cache->head = NULL;

  /* Clear sensitive data */
  memset (&node->entry.server_cookie, 0, DNS_SERVER_COOKIE_MAX_SIZE);

  cache->count--;
  cache->stats.cache_evictions++;
  cache->stats.current_entries = cache->count;
}

/*
 * Compare socket addresses
 */
static int
addr_equal (const struct sockaddr *a, socklen_t alen, const struct sockaddr *b,
            socklen_t blen)
{
  if (a->sa_family != b->sa_family)
    return 0;

  if (a->sa_family == AF_INET)
    {
      const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
      const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
      return a4->sin_addr.s_addr == b4->sin_addr.s_addr
             && a4->sin_port == b4->sin_port;
    }
  else if (a->sa_family == AF_INET6)
    {
      const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
      const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
      return memcmp (&a6->sin6_addr, &b6->sin6_addr, sizeof (a6->sin6_addr))
                 == 0
             && a6->sin6_port == b6->sin6_port;
    }

  /* Fallback: byte comparison */
  if (alen != blen)
    return 0;
  return memcmp (a, b, alen) == 0;
}

#undef T

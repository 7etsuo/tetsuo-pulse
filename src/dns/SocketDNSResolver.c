/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDNSResolver.c
 * @brief Async DNS resolver with query multiplexing (RFC 1035 Section 7).
 */

#include "dns/SocketDNSResolver.h"
#include "dns/SocketDNSConfig.h"
#include "dns/SocketDNSTransport.h"
#include "dns/SocketDNSWire.h"
#include "socket/SocketCommon.h"
#include "core/SocketUtil.h"

#include <arpa/inet.h>
#include <assert.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/random.h>
#include <time.h>

#define T SocketDNSResolver_T

/* Exception definition */
const Except_T SocketDNSResolver_Failed
    = { &SocketDNSResolver_Failed, "DNS resolver operation failed" };

/* Internal constants */

/**
 * Query hash table size (power of 2 for fast modulo via bitwise AND).
 * Sized to handle 256 concurrent queries without excessive collisions.
 * 16-bit query ID space (65536) / 256 buckets = ~256 IDs per bucket max.
 */
#define QUERY_HASH_SIZE 256

/**
 * Cache hash table size (prime number for uniform distribution).
 * Prime numbers reduce clustering in hash tables using modulo.
 * Sized slightly larger than RESOLVER_DEFAULT_CACHE_MAX (1000) to
 * maintain low load factor (~0.98) for fast lookups.
 */
#define CACHE_HASH_SIZE 1021

/**
 * Maximum DNS query message size (RFC 1035 Section 4.2.1).
 * Standard UDP DNS messages are limited to 512 bytes without EDNS0.
 * Queries sent via UDP use this limit; TCP queries have no size limit.
 *
 * Note: This is for query messages only. Response parsing handles
 * larger messages via TCP fallback on truncation (TC bit set).
 */
#define MAX_QUERY_MESSAGE_SIZE 512

/**
 * Timeout backoff multiplier for transport layer.
 * Allows for exponential backoff: initial, 2x, 4x timeout.
 * RFC 1035 Section 4.2.1 recommends retry with increasing timeouts.
 */
#define TIMEOUT_BACKOFF_MULTIPLIER 4

/* Query states */
typedef enum
{
  QUERY_STATE_INIT,
  QUERY_STATE_SENT,
  QUERY_STATE_WAITING,
  QUERY_STATE_TCP_FALLBACK,
  QUERY_STATE_CNAME,
  QUERY_STATE_COMPLETE,
  QUERY_STATE_FAILED,
  QUERY_STATE_CANCELLED
} QueryState;

/* Internal query structure */
struct SocketDNSResolver_Query
{
  uint16_t id;                        /* DNS message ID */
  char hostname[DNS_MAX_NAME_LEN];    /* Original query hostname */
  char current_name[DNS_MAX_NAME_LEN]; /* Current name (may be CNAME target) */
  int flags;                          /* Resolution flags */
  QueryState state;                   /* Current state */
  int cname_depth;                    /* CNAME chain depth */
  int query_type;                     /* Current query type (A or AAAA) */
  int is_tcp;                         /* Using TCP transport */

  /* Results accumulation */
  SocketDNSResolver_Address addresses[RESOLVER_MAX_ADDRESSES];
  size_t address_count;
  uint32_t min_ttl;

  /* User callback */
  SocketDNSResolver_Callback callback;
  void *userdata;

  /* Query message for retries */
  unsigned char query_msg[MAX_QUERY_MESSAGE_SIZE];
  size_t query_len;

  /* Back-pointer to resolver (for transport callback) */
  T resolver;

  /* List pointers */
  struct SocketDNSResolver_Query *hash_next;
  struct SocketDNSResolver_Query *list_next;
  struct SocketDNSResolver_Query *list_prev;
};

/* Cache entry structure */
struct CacheEntry
{
  char *hostname;                                      /* Cached hostname */
  SocketDNSResolver_Address addresses[RESOLVER_MAX_ADDRESSES];
  size_t address_count;
  uint32_t ttl;
  int64_t insert_time_ms;                              /* Monotonic timestamp */
  struct CacheEntry *hash_next;
  struct CacheEntry *lru_prev;
  struct CacheEntry *lru_next;
};

/* Resolver structure */
struct T
{
  Arena_T arena;
  SocketDNSTransport_T transport;

  /* Query management */
  struct SocketDNSResolver_Query *query_hash[QUERY_HASH_SIZE];
  struct SocketDNSResolver_Query *query_head;
  struct SocketDNSResolver_Query *query_tail;
  int pending_count;

  /* Cache */
  struct CacheEntry *cache_hash[CACHE_HASH_SIZE];
  struct CacheEntry *cache_lru_head;
  struct CacheEntry *cache_lru_tail;
  size_t cache_size;
  size_t cache_max_entries;
  int cache_ttl_seconds;
  uint64_t cache_hits;
  uint64_t cache_misses;
  uint64_t cache_evictions;
  uint64_t cache_insertions;

  /* Configuration */
  int timeout_ms;
  int max_retries;
};

/* Forward declarations */
static void transport_callback (SocketDNSQuery_T query,
                                const unsigned char *response, size_t len,
                                int error, void *userdata);
static int send_query (T resolver, struct SocketDNSResolver_Query *q);
static void complete_query (T resolver, struct SocketDNSResolver_Query *q,
                            int error);
static void cache_insert (T resolver, const char *hostname,
                          const SocketDNSResolver_Address *addresses,
                          size_t count, uint32_t ttl);
static struct CacheEntry *cache_lookup (T resolver, const char *hostname);
static struct SocketDNSResolver_Query *initialize_query (
    T resolver, const char *hostname, int flags,
    SocketDNSResolver_Callback callback, void *userdata);

/* Use centralized monotonic time utility from SocketUtil.h */
#define get_monotonic_ms() Socket_get_monotonic_ms()

/**
 * @brief Hash DNS hostname for cache lookup.
 *
 * Uses centralized case-insensitive DJB2 hash from SocketUtil.
 * DNS names are case-insensitive per RFC 1035 Section 2.3.3.
 *
 * @param hostname DNS hostname (ASCII, case-insensitive).
 * @return Hash bucket index (0 to CACHE_HASH_SIZE-1).
 */
static unsigned
hash_hostname (const char *hostname)
{
  return socket_util_hash_djb2_ci (hostname, CACHE_HASH_SIZE);
}

/* Utility: hash query ID */
static unsigned
hash_query_id (uint16_t id)
{
  return id % QUERY_HASH_SIZE;
}

/**
 * Check if hostname is a numeric IPv4 address.
 *
 * Uses strict dotted-decimal format per RFC 3986 Section 3.2.2.
 *
 * @param hostname  Address string to check.
 * @param addr      Optional output for parsed address.
 * @return 1 if valid IPv4, 0 otherwise.
 */
static int
is_ipv4_address (const char *hostname, struct in_addr *addr)
{
  struct in_addr temp;
  if (!addr)
    addr = &temp;

  return inet_pton (AF_INET, hostname, addr) == 1;
}

/**
 * Check if hostname is a numeric IPv6 address, with optional zone ID.
 *
 * Handles zone identifiers like "fe80::1%eth0" per RFC 6874.
 * The zone ID is stripped before validation since inet_pton(3) doesn't
 * handle zone IDs.
 *
 * @param hostname     Address string to check.
 * @param addr         Optional output for parsed address.
 * @param scope_id_out Optional output for scope ID (0 if no zone specified).
 * @return 1 if valid IPv6, 0 otherwise.
 */
static int
is_ipv6_address (const char *hostname, struct in6_addr *addr,
                 unsigned int *scope_id_out)
{
  struct in6_addr temp_addr;
  char addr_buf[INET6_ADDRSTRLEN];
  const char *zone_sep;
  size_t addr_len;

  if (!addr)
    addr = &temp_addr;

  if (scope_id_out)
    *scope_id_out = 0;

  /* Check for zone ID separator (RFC 6874) */
  zone_sep = strchr (hostname, '%');
  if (!zone_sep)
    {
      /* No zone ID - direct parse */
      return inet_pton (AF_INET6, hostname, addr) == 1;
    }

  /* Has zone ID - extract and parse address part only */
  addr_len = (size_t)(zone_sep - hostname);
  if (addr_len == 0 || addr_len >= sizeof (addr_buf))
    return 0;

  memcpy (addr_buf, hostname, addr_len);
  addr_buf[addr_len] = '\0';

  if (inet_pton (AF_INET6, addr_buf, addr) != 1)
    return 0;

  /* Convert zone ID to scope_id using if_nametoindex */
  if (scope_id_out)
    {
      const char *zone_id = zone_sep + 1;
      if (*zone_id != '\0')
        {
          /* Try to convert interface name to index */
          unsigned int idx = if_nametoindex (zone_id);
          if (idx > 0)
            *scope_id_out = idx;
          /* If if_nametoindex fails, leave scope_id as 0 */
        }
    }

  return 1;
}

/**
 * Check if hostname is a numeric IP address (IPv4 or IPv6).
 *
 * Handles:
 * - IPv4 dotted-decimal: "192.168.1.1"
 * - IPv6 colon-hex: "2001:db8::1"
 * - IPv6 with zone ID: "fe80::1%eth0" (RFC 6874)
 *
 * @param hostname Address string to check.
 * @return 1 if valid IP address, 0 otherwise.
 */
static int
is_ip_address (const char *hostname)
{
  return is_ipv4_address (hostname, NULL) || is_ipv6_address (hostname, NULL, NULL);
}

/* Check if hostname is "localhost" (case-insensitive) */
static int
is_localhost (const char *hostname)
{
  return strcasecmp (hostname, "localhost") == 0;
}

/**
 * Cap TTL to maximum allowed value per RFC 8767.
 *
 * Prevents cache poisoning via excessively long TTLs and ensures
 * reasonable cache refresh intervals.
 */
static inline uint32_t
cap_ttl (uint32_t ttl)
{
  return ttl > DNS_TTL_MAX ? DNS_TTL_MAX : ttl;
}

/*
 * Query ID Management
 */

/**
 * Generate a cryptographically random query ID per RFC 5452 Section 4.
 *
 * Uses getrandom() for full 16-bit entropy to prevent cache poisoning
 * attacks. Falls back to XOR of monotonic time bits if getrandom() fails.
 */
static uint16_t
generate_unique_id (T resolver)
{
  uint16_t id;
  int attempts = 0;
  const int max_attempts = 1000;

  do
    {
      /* Use getrandom() for cryptographic randomness (RFC 5452 Section 4) */
      ssize_t ret = getrandom (&id, sizeof (id), 0);
      if (ret != (ssize_t)sizeof (id))
        {
          /* Fallback: XOR monotonic time bits for some entropy */
          uint64_t t = (uint64_t)get_monotonic_ms ();
          id = (uint16_t)((t ^ (t >> 16) ^ (t >> 32)) & 0xFFFF);
        }

      /* Avoid ID 0 (reserved in some implementations) */
      if (id == 0)
        id = 1;

      /* Check if ID is already in use */
      unsigned h = hash_query_id (id);
      struct SocketDNSResolver_Query *q = resolver->query_hash[h];
      int found = 0;
      while (q)
        {
          if (q->id == id)
            {
              found = 1;
              break;
            }
          q = q->hash_next;
        }

      if (!found)
        return id;

      attempts++;
    }
  while (attempts < max_attempts);

  /* ID space exhausted - refuse to send query to prevent cache poisoning */
  RAISE (SocketDNSResolver_Failed);
}

static struct SocketDNSResolver_Query *
find_query_by_id (T resolver, uint16_t id)
{
  unsigned h = hash_query_id (id);
  struct SocketDNSResolver_Query *q = resolver->query_hash[h];

  while (q)
    {
      if (q->id == id && q->state != QUERY_STATE_COMPLETE
          && q->state != QUERY_STATE_FAILED
          && q->state != QUERY_STATE_CANCELLED)
        return q;
      q = q->hash_next;
    }
  return NULL;
}

/*
 * Query List Management
 */

static void
query_list_add (T resolver, struct SocketDNSResolver_Query *q)
{
  q->list_next = NULL;
  q->list_prev = resolver->query_tail;

  if (resolver->query_tail)
    resolver->query_tail->list_next = q;
  else
    resolver->query_head = q;

  resolver->query_tail = q;

  /* Add to hash */
  unsigned h = hash_query_id (q->id);
  q->hash_next = resolver->query_hash[h];
  resolver->query_hash[h] = q;

  resolver->pending_count++;
}

static void
query_list_remove (T resolver, struct SocketDNSResolver_Query *q)
{
  /* Remove from linked list */
  if (q->list_prev)
    q->list_prev->list_next = q->list_next;
  else
    resolver->query_head = q->list_next;

  if (q->list_next)
    q->list_next->list_prev = q->list_prev;
  else
    resolver->query_tail = q->list_prev;

  /* Remove from hash */
  unsigned h = hash_query_id (q->id);
  struct SocketDNSResolver_Query **pp = &resolver->query_hash[h];
  while (*pp)
    {
      if (*pp == q)
        {
          *pp = q->hash_next;
          break;
        }
      pp = &(*pp)->hash_next;
    }

  resolver->pending_count--;
}

/*
 * Cache Implementation
 */

static void
cache_entry_free (struct CacheEntry *entry)
{
  if (entry && entry->hostname)
    {
      free (entry->hostname);
      entry->hostname = NULL;
    }
}

static void
cache_lru_remove (T resolver, struct CacheEntry *entry)
{
  if (entry->lru_prev)
    entry->lru_prev->lru_next = entry->lru_next;
  else
    resolver->cache_lru_head = entry->lru_next;

  if (entry->lru_next)
    entry->lru_next->lru_prev = entry->lru_prev;
  else
    resolver->cache_lru_tail = entry->lru_prev;

  entry->lru_prev = NULL;
  entry->lru_next = NULL;
}

static void
cache_lru_insert_front (T resolver, struct CacheEntry *entry)
{
  entry->lru_prev = NULL;
  entry->lru_next = resolver->cache_lru_head;

  if (resolver->cache_lru_head)
    resolver->cache_lru_head->lru_prev = entry;
  else
    resolver->cache_lru_tail = entry;

  resolver->cache_lru_head = entry;
}

static void
cache_hash_remove (T resolver, struct CacheEntry *entry)
{
  unsigned h = hash_hostname (entry->hostname);
  struct CacheEntry **pp = &resolver->cache_hash[h];

  while (*pp)
    {
      if (*pp == entry)
        {
          *pp = entry->hash_next;
          return;
        }
      pp = &(*pp)->hash_next;
    }
}

static void
cache_remove_entry (T resolver, struct CacheEntry *entry)
{
  cache_lru_remove (resolver, entry);
  cache_hash_remove (resolver, entry);
  cache_entry_free (entry);
  resolver->cache_size--;
}

static void
cache_evict_oldest (T resolver)
{
  struct CacheEntry *oldest = resolver->cache_lru_tail;
  if (!oldest)
    return;

  cache_remove_entry (resolver, oldest);
  resolver->cache_evictions++;
}

static int
cache_entry_expired (T resolver, const struct CacheEntry *entry)
{
  int64_t now_ms = get_monotonic_ms ();
  int64_t age_ms = now_ms - entry->insert_time_ms;
  int ttl = resolver->cache_ttl_seconds > 0 ? resolver->cache_ttl_seconds
                                            : (int)entry->ttl;
  return age_ms >= (int64_t)ttl * 1000;
}

static struct CacheEntry *
cache_lookup (T resolver, const char *hostname)
{
  if (resolver->cache_max_entries == 0)
    return NULL;

  unsigned h = hash_hostname (hostname);
  struct CacheEntry *entry = resolver->cache_hash[h];

  while (entry)
    {
      if (strcasecmp (entry->hostname, hostname) == 0)
        {
          if (cache_entry_expired (resolver, entry))
            {
              cache_remove_entry (resolver, entry);
              resolver->cache_misses++;
              return NULL;
            }

          /* Move to front of LRU */
          cache_lru_remove (resolver, entry);
          cache_lru_insert_front (resolver, entry);
          resolver->cache_hits++;
          return entry;
        }
      entry = entry->hash_next;
    }

  resolver->cache_misses++;
  return NULL;
}

static void
cache_insert (T resolver, const char *hostname,
              const SocketDNSResolver_Address *addresses, size_t count,
              uint32_t ttl)
{
  if (resolver->cache_max_entries == 0 || count == 0)
    return;

  /* Evict if full */
  while (resolver->cache_size >= resolver->cache_max_entries)
    cache_evict_oldest (resolver);

  /* Allocate entry from arena */
  struct CacheEntry *entry = Arena_alloc (resolver->arena, sizeof (*entry),
                                          __FILE__, __LINE__);
  if (!entry)
    return;

  /* Allocate hostname from arena to prevent leak */
  size_t hostname_len = strlen (hostname) + 1;
  entry->hostname = Arena_alloc (resolver->arena, hostname_len, __FILE__,
                                 __LINE__);
  if (!entry->hostname)
    return;
  memcpy (entry->hostname, hostname, hostname_len);

  /* Copy addresses */
  size_t copy_count = count > RESOLVER_MAX_ADDRESSES ? RESOLVER_MAX_ADDRESSES
                                                     : count;
  memcpy (entry->addresses, addresses,
          copy_count * sizeof (SocketDNSResolver_Address));
  entry->address_count = copy_count;
  entry->ttl = ttl;
  entry->insert_time_ms = get_monotonic_ms ();
  entry->hash_next = NULL;
  entry->lru_prev = NULL;
  entry->lru_next = NULL;

  /* Insert into hash */
  unsigned h = hash_hostname (hostname);
  entry->hash_next = resolver->cache_hash[h];
  resolver->cache_hash[h] = entry;

  /* Insert into LRU */
  cache_lru_insert_front (resolver, entry);

  resolver->cache_size++;
  resolver->cache_insertions++;
}

static void
cache_clear (T resolver)
{
  for (size_t i = 0; i < CACHE_HASH_SIZE; i++)
    {
      struct CacheEntry *entry = resolver->cache_hash[i];
      while (entry)
        {
          struct CacheEntry *next = entry->hash_next;
          cache_entry_free (entry);
          entry = next;
        }
      resolver->cache_hash[i] = NULL;
    }

  resolver->cache_lru_head = NULL;
  resolver->cache_lru_tail = NULL;
  resolver->cache_size = 0;
}

/*
 * Query Message Building
 */

static int
build_query_message (struct SocketDNSResolver_Query *q, int query_type)
{
  SocketDNS_Header header;
  SocketDNS_Question question;
  size_t offset = 0;
  size_t written;

  /* Initialize header */
  SocketDNS_header_init_query (&header, q->id, 1);

  /* Encode header */
  if (SocketDNS_header_encode (&header, q->query_msg, MAX_QUERY_MESSAGE_SIZE)
      != 0)
    return -1;
  offset = DNS_HEADER_SIZE;

  /* Initialize and encode question */
  SocketDNS_question_init (&question, q->current_name, query_type);
  if (SocketDNS_question_encode (&question, q->query_msg + offset,
                                 MAX_QUERY_MESSAGE_SIZE - offset, &written)
      != 0)
    return -1;
  offset += written;

  q->query_len = offset;
  q->query_type = query_type;
  return 0;
}

/*
 * Response Validation (RFC 5452)
 */

/**
 * Validate response question section matches query per RFC 5452 Section 3.
 *
 * Prevents cache poisoning by verifying the response is for our query.
 */
static int
validate_response_question (const unsigned char *response, size_t len,
                            struct SocketDNSResolver_Query *q)
{
  SocketDNS_Question question;
  size_t consumed;

  /* Decode first question from response */
  if (SocketDNS_question_decode (response, len, DNS_HEADER_SIZE,
                                  &question, &consumed) != 0)
    return RESOLVER_ERROR_INVALID;

  /* QNAME must match (case-insensitive per RFC 1035 Section 2.3.3) */
  if (!SocketDNS_name_equal (question.qname, q->current_name))
    return RESOLVER_ERROR_VALIDATION_QNAME;

  /* QTYPE must match query type */
  if (question.qtype != (uint16_t)q->query_type)
    return RESOLVER_ERROR_VALIDATION_QTYPE;

  /* QCLASS must be IN (1) */
  if (question.qclass != DNS_CLASS_IN)
    return RESOLVER_ERROR_VALIDATION_QCLASS;

  return RESOLVER_OK;
}

/*
 * Response Parsing
 */

static int
parse_answer_rr (struct SocketDNSResolver_Query *q,
                 const unsigned char *response, size_t len,
                 const SocketDNS_RR *rr)
{
  char cname_target[DNS_MAX_NAME_LEN] = { 0 };

  /* Handle CNAME */
  if (rr->type == DNS_TYPE_CNAME)
    {
      if (SocketDNS_rdata_parse_cname (response, len, rr, cname_target,
                                       sizeof (cname_target))
          < 0)
        return RESOLVER_OK; /* Skip invalid CNAME */

      /* Check CNAME depth */
      if (q->cname_depth >= RESOLVER_MAX_CNAME_DEPTH)
        return RESOLVER_ERROR_CNAME_LOOP;

      /* Validate CNAME target length before copy */
      if (strlen (cname_target) >= DNS_MAX_NAME_LEN)
        return RESOLVER_ERROR_INVALID;

      /* Store CNAME target for re-query */
      snprintf (q->current_name, DNS_MAX_NAME_LEN, "%s", cname_target);
      q->cname_depth++;
      q->state = QUERY_STATE_CNAME;
      return RESOLVER_OK; /* Will trigger re-query */
    }

  /* Handle A record */
  if (rr->type == DNS_TYPE_A && q->address_count < RESOLVER_MAX_ADDRESSES)
    {
      /* Bailiwick check: skip out-of-zone records (RFC 5452) */
      if (!SocketDNS_name_in_bailiwick (rr->name, q->hostname))
        return RESOLVER_OK;

      struct in_addr addr;
      if (SocketDNS_rdata_parse_a (rr, &addr) == 0)
        {
          uint32_t capped_ttl = cap_ttl (rr->ttl);
          q->addresses[q->address_count].family = AF_INET;
          q->addresses[q->address_count].addr.v4 = addr;
          q->addresses[q->address_count].ttl = capped_ttl;
          if (q->min_ttl == 0 || capped_ttl < q->min_ttl)
            q->min_ttl = capped_ttl;
          q->address_count++;
        }
    }

  /* Handle AAAA record */
  if (rr->type == DNS_TYPE_AAAA && q->address_count < RESOLVER_MAX_ADDRESSES)
    {
      /* Bailiwick check: skip out-of-zone records (RFC 5452) */
      if (!SocketDNS_name_in_bailiwick (rr->name, q->hostname))
        return RESOLVER_OK;

      struct in6_addr addr;
      if (SocketDNS_rdata_parse_aaaa (rr, &addr) == 0)
        {
          uint32_t capped_ttl = cap_ttl (rr->ttl);
          q->addresses[q->address_count].family = AF_INET6;
          q->addresses[q->address_count].addr.v6 = addr;
          q->addresses[q->address_count].ttl = capped_ttl;
          if (q->min_ttl == 0 || capped_ttl < q->min_ttl)
            q->min_ttl = capped_ttl;
          q->address_count++;
        }
    }

  return RESOLVER_OK;
}

static int
parse_response (T resolver, struct SocketDNSResolver_Query *q,
                const unsigned char *response, size_t len)
{
  SocketDNS_Header header;
  SocketDNS_Question question;
  SocketDNS_RR rr;
  size_t offset;
  size_t consumed;

  (void)resolver; /* Currently unused - reserved for future caching extensions */

  /* Decode header */
  if (SocketDNS_header_decode (response, len, &header) != 0)
    return RESOLVER_ERROR_INVALID;

  /* Verify response */
  if (header.qr != 1)
    return RESOLVER_ERROR_INVALID;
  if (header.id != q->id)
    return RESOLVER_ERROR_INVALID;

  /* Validate question section matches query (RFC 5452 Section 3) */
  if (header.qdcount >= 1)
    {
      int vret = validate_response_question (response, len, q);
      if (vret != RESOLVER_OK)
        return vret;
    }

  /* Check RCODE */
  switch (header.rcode)
    {
    case DNS_RCODE_NOERROR:
      break;
    case DNS_RCODE_NXDOMAIN:
      return RESOLVER_ERROR_NXDOMAIN;
    case DNS_RCODE_SERVFAIL:
      return RESOLVER_ERROR_SERVFAIL;
    case DNS_RCODE_REFUSED:
      return RESOLVER_ERROR_REFUSED;
    case DNS_RCODE_FORMERR:
      return RESOLVER_ERROR_INVALID;
    default:
      return RESOLVER_ERROR_INVALID;
    }

  /* Skip question section */
  offset = DNS_HEADER_SIZE;
  for (int i = 0; i < header.qdcount; i++)
    {
      if (SocketDNS_question_decode (response, len, offset, &question,
                                     &consumed)
          != 0)
        return RESOLVER_ERROR_INVALID;
      offset += consumed;
    }

  /* Parse answer section */
  for (int i = 0; i < header.ancount; i++)
    {
      if (SocketDNS_rr_decode (response, len, offset, &rr, &consumed) != 0)
        return RESOLVER_ERROR_INVALID;
      offset += consumed;

      int result = parse_answer_rr (q, response, len, &rr);
      if (result != RESOLVER_OK)
        return result;
    }

  return RESOLVER_OK;
}

/*
 * Transport Callback
 */

static void
transport_callback (SocketDNSQuery_T query, const unsigned char *response,
                    size_t len, int error, void *userdata)
{
  struct SocketDNSResolver_Query *q = userdata;
  T resolver;
  int parse_result;

  (void)query;

  if (!q)
    return;

  resolver = q->resolver; /* Use back-pointer */

  /* Handle transport errors */
  if (error != DNS_ERROR_SUCCESS)
    {
      switch (error)
        {
        case DNS_ERROR_TRUNCATED:
          /* TCP fallback - resend via TCP */
          q->state = QUERY_STATE_TCP_FALLBACK;
          q->is_tcp = 1;
          return;
        default:
          /* All other errors cause failure */
          q->state = QUERY_STATE_FAILED;
          return;
        }
    }

  /* Parse response using shared parsing logic */
  if (response && len > 0)
    {
      parse_result = parse_response (resolver, q, response, len);

      if (parse_result == RESOLVER_OK && q->state == QUERY_STATE_CNAME)
        {
          /* CNAME re-query needed */
          return;
        }

      if (parse_result != RESOLVER_OK)
        {
          q->state = QUERY_STATE_FAILED;
          return;
        }
    }

  /* Check if we need to query for the other record type (A vs AAAA) */
  if ((q->flags & RESOLVER_FLAG_BOTH) == RESOLVER_FLAG_BOTH)
    {
      if (q->query_type == DNS_TYPE_A && (q->flags & RESOLVER_FLAG_IPV6))
        {
          /* We queried A, now query AAAA */
          q->query_type = DNS_TYPE_AAAA;
          q->state = QUERY_STATE_INIT; /* Will resend */
          return;
        }
    }

  /* Query complete */
  q->state = QUERY_STATE_COMPLETE;
}

/*
 * Send Query
 */

static int
send_query (T resolver, struct SocketDNSResolver_Query *q)
{
  int query_type;

  /* Determine query type */
  if (q->flags & RESOLVER_FLAG_IPV6)
    query_type = DNS_TYPE_AAAA;
  else
    query_type = DNS_TYPE_A;

  /* For RESOLVER_FLAG_BOTH, start with A then do AAAA */
  if ((q->flags & RESOLVER_FLAG_BOTH) == RESOLVER_FLAG_BOTH
      && q->query_type == 0)
    query_type = DNS_TYPE_A;
  else if (q->query_type != 0)
    query_type = q->query_type;

  /* Build query message */
  if (build_query_message (q, query_type) != 0)
    return -1;

  /* Send via transport */
  SocketDNSQuery_T tq;
  if (q->is_tcp || (q->flags & RESOLVER_FLAG_TCP))
    {
      tq = SocketDNSTransport_query_tcp (resolver->transport, q->query_msg,
                                         q->query_len, transport_callback, q);
    }
  else
    {
      tq = SocketDNSTransport_query_udp (resolver->transport, q->query_msg,
                                         q->query_len, transport_callback, q);
    }

  if (!tq)
    return -1;

  q->state = QUERY_STATE_SENT;
  return 0;
}

/*
 * Complete Query
 */

static void
complete_query (T resolver, struct SocketDNSResolver_Query *q, int error)
{
  SocketDNSResolver_Result result = { 0 };

  if (error == RESOLVER_OK && q->address_count > 0)
    {
      /* Build result - use reallocarray to prevent integer overflow */
      result.addresses = reallocarray (NULL, q->address_count,
                                       sizeof (SocketDNSResolver_Address));
      if (result.addresses)
        {
          memcpy (result.addresses, q->addresses,
                  q->address_count * sizeof (SocketDNSResolver_Address));
          result.count = q->address_count;
          result.min_ttl = q->min_ttl;

          /* Cache the result */
          cache_insert (resolver, q->hostname, q->addresses, q->address_count,
                        q->min_ttl);
        }
      else
        {
          error = RESOLVER_ERROR_NOMEM;
        }
    }
  else if (error == RESOLVER_OK && q->address_count == 0)
    {
      /* No addresses found - treat as NXDOMAIN */
      error = RESOLVER_ERROR_NXDOMAIN;
    }

  /* Remove from pending list */
  query_list_remove (resolver, q);

  /* Invoke callback */
  if (q->callback)
    {
      q->callback (q, error == RESOLVER_OK ? &result : NULL, error,
                   q->userdata);
    }

  /* Free result */
  if (result.addresses)
    free (result.addresses);
}

/*
 * Configuration Propagation
 */

/**
 * @brief Apply resolver configuration to transport layer.
 *
 * Propagates timeout, retry, and rotation settings to the underlying
 * transport. Called when configuration changes or when loading from
 * resolv.conf.
 *
 * @param resolver Resolver instance.
 */
static void
apply_config_to_transport (T resolver)
{
  SocketDNSTransport_Config config = { 0 };

  config.initial_timeout_ms = resolver->timeout_ms;
  config.max_timeout_ms = resolver->timeout_ms * TIMEOUT_BACKOFF_MULTIPLIER;
  config.max_retries = resolver->max_retries;
  config.rotate_nameservers = 1;

  SocketDNSTransport_configure (resolver->transport, &config);
}

/*
 * Public API Implementation
 */

T
SocketDNSResolver_new (Arena_T arena)
{
  T resolver;

  assert (arena);

  resolver = Arena_alloc (arena, sizeof (*resolver), __FILE__, __LINE__);
  if (!resolver)
    RAISE (SocketDNSResolver_Failed);

  memset (resolver, 0, sizeof (*resolver));
  resolver->arena = arena;

  /* Create transport */
  TRY
  {
    resolver->transport = SocketDNSTransport_new (arena, NULL);
  }
  EXCEPT (SocketDNSTransport_Failed)
  {
    RAISE (SocketDNSResolver_Failed);
  }
  END_TRY;

  /* Note: Query IDs are now generated cryptographically per RFC 5452 */

  /* Set defaults */
  resolver->timeout_ms = RESOLVER_DEFAULT_TIMEOUT_MS;
  resolver->max_retries = RESOLVER_DEFAULT_MAX_RETRIES;
  resolver->cache_max_entries = RESOLVER_DEFAULT_CACHE_MAX;
  resolver->cache_ttl_seconds = RESOLVER_DEFAULT_CACHE_TTL;

  return resolver;
}

void
SocketDNSResolver_free (T *resolver)
{
  if (!resolver || !*resolver)
    return;

  T r = *resolver;

  /* Cancel all pending queries */
  struct SocketDNSResolver_Query *q = r->query_head;
  while (q)
    {
      struct SocketDNSResolver_Query *next = q->list_next;
      if (q->callback)
        {
          q->callback (q, NULL, RESOLVER_ERROR_CANCELLED, q->userdata);
        }
      q = next;
    }

  /* Clear cache */
  cache_clear (r);

  /* Free transport */
  SocketDNSTransport_free (&r->transport);

  *resolver = NULL;
}

int
SocketDNSResolver_load_resolv_conf (T resolver)
{
  SocketDNSConfig_T config;
  int count = 0;

  assert (resolver);

  /* Initialize and load config */
  SocketDNSConfig_init (&config);
  if (SocketDNSConfig_load (&config) < 0)
    {
      /* Load failed, but defaults are applied */
    }

  /* Clear existing nameservers */
  SocketDNSTransport_clear_nameservers (resolver->transport);

  /* Add nameservers from config */
  for (int i = 0; i < config.nameserver_count; i++)
    {
      const char *ns = config.nameservers[i].address;
      if (ns[0] != '\0'
          && SocketDNSTransport_add_nameserver (resolver->transport, ns,
                                                DNS_PORT)
                 == 0)
        {
          count++;
        }
    }

  /* Apply timeout/retry/rotate options from resolv.conf (RFC 1035 §4.2.1) */
  resolver->timeout_ms = config.timeout_secs * 1000;
  resolver->max_retries = config.attempts;

  /* Propagate to transport layer */
  SocketDNSTransport_Config transport_config = { 0 };
  transport_config.initial_timeout_ms = resolver->timeout_ms;
  transport_config.max_timeout_ms = resolver->timeout_ms * 4;
  transport_config.max_retries = resolver->max_retries;
  transport_config.rotate_nameservers = SocketDNSConfig_has_rotate (&config);
  SocketDNSTransport_configure (resolver->transport, &transport_config);

  return count;
}

int
SocketDNSResolver_add_nameserver (T resolver, const char *address, int port)
{
  assert (resolver);
  assert (address);

  return SocketDNSTransport_add_nameserver (resolver->transport, address, port);
}

void
SocketDNSResolver_clear_nameservers (T resolver)
{
  assert (resolver);
  SocketDNSTransport_clear_nameservers (resolver->transport);
}

int
SocketDNSResolver_nameserver_count (T resolver)
{
  assert (resolver);
  return SocketDNSTransport_nameserver_count (resolver->transport);
}

void
SocketDNSResolver_set_timeout (T resolver, int timeout_ms)
{
  assert (resolver);
  resolver->timeout_ms = timeout_ms > 0 ? timeout_ms
                                        : RESOLVER_DEFAULT_TIMEOUT_MS;

  /* Propagate to transport (RFC 1035 §4.2.1) */
  apply_config_to_transport (resolver);
}

void
SocketDNSResolver_set_retries (T resolver, int max_retries)
{
  assert (resolver);
  resolver->max_retries = max_retries >= 0 ? max_retries
                                           : RESOLVER_DEFAULT_MAX_RETRIES;

  /* Propagate to transport (RFC 1035 §4.2.1) */
  apply_config_to_transport (resolver);
}

/**
 * Fast path: Check if hostname is an IP literal and handle immediately.
 *
 * @param hostname  Hostname to check.
 * @param flags     Resolution flags (unused for literals).
 * @param callback  User callback to invoke if literal.
 * @param userdata  User data for callback.
 * @return 1 if handled (IPv4 or IPv6 literal), 0 otherwise.
 */
static int
try_ip_literal (const char *hostname, int flags,
                SocketDNSResolver_Callback callback, void *userdata)
{
  SocketDNSResolver_Result result = { 0 };
  SocketDNSResolver_Address addr = { 0 };
  struct in_addr v4;
  struct in6_addr v6;
  unsigned int scope_id = 0;

  (void)flags; /* Unused - literals ignore family preference */

  /* Check for IPv4 literal */
  if (is_ipv4_address (hostname, &v4))
    {
      addr.family = AF_INET;
      addr.addr.v4 = v4;
      addr.ttl = 0; /* No TTL for literals */

      result.addresses = &addr;
      result.count = 1;
      result.min_ttl = 0;

      callback (NULL, &result, RESOLVER_OK, userdata);
      return 1;
    }

  /* Check for IPv6 literal */
  if (is_ipv6_address (hostname, &v6, &scope_id))
    {
      addr.family = AF_INET6;
      addr.addr.v6 = v6;
      addr.ttl = 0;
      /* Note: scope_id available but not stored in result */
      (void)scope_id;

      result.addresses = &addr;
      result.count = 1;
      result.min_ttl = 0;

      callback (NULL, &result, RESOLVER_OK, userdata);
      return 1;
    }

  return 0;
}

/**
 * Fast path: Check if hostname is "localhost" and handle immediately.
 *
 * Returns loopback addresses (127.0.0.1 and/or ::1) based on flags.
 *
 * @param hostname  Hostname to check.
 * @param flags     Resolution flags (determines IPv4/IPv6).
 * @param callback  User callback to invoke if localhost.
 * @param userdata  User data for callback.
 * @return 1 if handled, 0 otherwise.
 */
static int
try_localhost (const char *hostname, int flags,
               SocketDNSResolver_Callback callback, void *userdata)
{
  SocketDNSResolver_Result result = { 0 };
  SocketDNSResolver_Address addrs[2];
  size_t addr_count = 0;

  if (!is_localhost (hostname))
    return 0;

  /* Return both IPv4 and IPv6 loopback based on flags */
  if (flags & RESOLVER_FLAG_IPV4)
    {
      addrs[addr_count].family = AF_INET;
      addrs[addr_count].addr.v4.s_addr = htonl (INADDR_LOOPBACK);
      addrs[addr_count].ttl = 0;
      addr_count++;
    }

  if (flags & RESOLVER_FLAG_IPV6)
    {
      addrs[addr_count].family = AF_INET6;
      addrs[addr_count].addr.v6 = in6addr_loopback;
      addrs[addr_count].ttl = 0;
      addr_count++;
    }

  result.addresses = addrs;
  result.count = addr_count;
  result.min_ttl = 0;

  callback (NULL, &result, RESOLVER_OK, userdata);
  return 1;
}

/**
 * Fast path: Check cache for existing resolution.
 *
 * @param resolver  Resolver instance.
 * @param hostname  Hostname to look up.
 * @param flags     Resolution flags.
 * @param callback  User callback to invoke if cache hit.
 * @param userdata  User data for callback.
 * @return 1 if cache hit, 0 otherwise.
 */
static int
try_cache (T resolver, const char *hostname, int flags,
           SocketDNSResolver_Callback callback, void *userdata)
{
  struct CacheEntry *cached;
  SocketDNSResolver_Result result = { 0 };

  if (flags & RESOLVER_FLAG_NO_CACHE)
    return 0;

  cached = cache_lookup (resolver, hostname);
  if (!cached)
    return 0;

  /* Build result from cache - use reallocarray to prevent overflow */
  result.addresses = reallocarray (NULL, cached->address_count,
                                   sizeof (SocketDNSResolver_Address));
  if (!result.addresses)
    return 0; /* Allocation failed, proceed to query */

  memcpy (result.addresses, cached->addresses,
          cached->address_count * sizeof (SocketDNSResolver_Address));
  result.count = cached->address_count;
  result.min_ttl = cached->ttl;

  callback (NULL, &result, RESOLVER_OK, userdata);
  free (result.addresses);
  return 1;
}

/**
 * Initialize a new DNS query structure.
 *
 * Allocates and initializes a query for the given hostname and parameters.
 * The query is added to the resolver's pending list.
 *
 * @param resolver  Resolver instance.
 * @param hostname  Hostname to query (already validated).
 * @param flags     Resolution flags.
 * @param callback  User callback for results.
 * @param userdata  User data for callback.
 * @return Initialized query on success, NULL on allocation failure.
 */
static struct SocketDNSResolver_Query *
initialize_query (T resolver, const char *hostname, int flags,
                  SocketDNSResolver_Callback callback, void *userdata)
{
  struct SocketDNSResolver_Query *q;

  /* Allocate query */
  q = Arena_alloc (resolver->arena, sizeof (*q), __FILE__, __LINE__);
  if (!q)
    return NULL;

  /* Initialize query structure */
  memset (q, 0, sizeof (*q));
  q->id = generate_unique_id (resolver);
  snprintf (q->hostname, DNS_MAX_NAME_LEN, "%s", hostname);
  snprintf (q->current_name, DNS_MAX_NAME_LEN, "%s", hostname);
  q->flags = flags;
  q->state = QUERY_STATE_INIT;
  q->callback = callback;
  q->userdata = userdata;
  q->resolver = resolver; /* Set back-pointer for transport callback */

  /* Add to pending list */
  query_list_add (resolver, q);

  return q;
}

SocketDNSResolver_Query_T
SocketDNSResolver_resolve (T resolver, const char *hostname, int flags,
                           SocketDNSResolver_Callback callback, void *userdata)
{
  struct SocketDNSResolver_Query *q;

  assert (resolver);
  assert (hostname);
  assert (callback);

  /* Default flags */
  if ((flags & (RESOLVER_FLAG_IPV4 | RESOLVER_FLAG_IPV6)) == 0)
    flags |= RESOLVER_FLAG_BOTH;

  /* Fast paths: IP literals, localhost, cache */
  if (try_ip_literal (hostname, flags, callback, userdata))
    return NULL;

  if (try_localhost (hostname, flags, callback, userdata))
    return NULL;

  if (try_cache (resolver, hostname, flags, callback, userdata))
    return NULL;

  /* Check nameservers */
  if (SocketDNSTransport_nameserver_count (resolver->transport) == 0)
    {
      callback (NULL, NULL, RESOLVER_ERROR_NO_NS, userdata);
      return NULL;
    }

  /* Validate hostname length before allocation */
  if (strlen (hostname) >= DNS_MAX_NAME_LEN)
    {
      callback (NULL, NULL, RESOLVER_ERROR_INVALID, userdata);
      return NULL;
    }

  /* Initialize query */
  q = initialize_query (resolver, hostname, flags, callback, userdata);
  if (!q)
    {
      callback (NULL, NULL, RESOLVER_ERROR_NOMEM, userdata);
      return NULL;
    }

  /* Send initial query */
  if (send_query (resolver, q) != 0)
    {
      query_list_remove (resolver, q);
      callback (q, NULL, RESOLVER_ERROR_NETWORK, userdata);
      return NULL;
    }

  return q;
}

/*
 * Synchronous Resolution Context
 */

struct resolve_sync_context
{
  volatile int done;
  volatile int error;
  SocketDNSResolver_Result result;
};

/*
 * Timeout Tracker for Event Loops
 */

typedef struct
{
  int64_t start_ms;
  int64_t timeout_ms;
} TimeoutTracker;

/* Poll in small increments for responsiveness */
#define SYNC_POLL_INCREMENT_MS 100

static void
timeout_tracker_init (TimeoutTracker *tracker, int timeout_ms)
{
  tracker->start_ms = get_monotonic_ms ();
  tracker->timeout_ms = timeout_ms;
}

static int
timeout_tracker_remaining (const TimeoutTracker *tracker)
{
  int64_t elapsed = get_monotonic_ms () - tracker->start_ms;
  int64_t remaining = tracker->timeout_ms - elapsed;

  if (remaining <= 0)
    return 0; /* Timeout expired */

  if (remaining > INT_MAX)
    return INT_MAX;

  return (int)remaining;
}

static int
timeout_tracker_expired (const TimeoutTracker *tracker)
{
  return timeout_tracker_remaining (tracker) <= 0;
}

static void
resolve_sync_callback (SocketDNSResolver_Query_T query,
                       const SocketDNSResolver_Result *result, int error,
                       void *userdata)
{
  struct resolve_sync_context *ctx = userdata;

  (void)query;

  ctx->error = error;

  if (error == RESOLVER_OK && result && result->count > 0)
    {
      /* Copy result - caller must free */
      ctx->result.addresses
          = reallocarray (NULL, result->count, sizeof (SocketDNSResolver_Address));
      if (ctx->result.addresses)
        {
          memcpy (ctx->result.addresses, result->addresses,
                  result->count * sizeof (SocketDNSResolver_Address));
          ctx->result.count = result->count;
          ctx->result.min_ttl = result->min_ttl;
        }
      else
        {
          ctx->error = RESOLVER_ERROR_NOMEM;
        }
    }

  ctx->done = 1;
}

/**
 * @brief Run event loop until completion or timeout.
 *
 * @param resolver The DNS resolver instance.
 * @param query The query handle (may be NULL if immediate failure).
 * @param ctx The synchronous context.
 * @param tracker The timeout tracker.
 * @return RESOLVER_OK on completion, RESOLVER_ERROR_TIMEOUT on timeout.
 */
static int
run_sync_event_loop (T resolver, SocketDNSResolver_Query_T query,
                     struct resolve_sync_context *ctx,
                     TimeoutTracker *tracker)
{
  while (!ctx->done)
    {
      if (timeout_tracker_expired (tracker))
        {
          /* Cancel and process to fire callback */
          SocketDNSResolver_cancel (resolver, query);
          SocketDNSResolver_process (resolver, 0);
          return RESOLVER_ERROR_TIMEOUT;
        }

      /* Poll in small increments for responsiveness */
      int poll_timeout = timeout_tracker_remaining (tracker);
      if (poll_timeout > SYNC_POLL_INCREMENT_MS)
        poll_timeout = SYNC_POLL_INCREMENT_MS;

      SocketDNSResolver_process (resolver, poll_timeout);
    }

  return ctx->error;
}

int
SocketDNSResolver_resolve_sync (T resolver, const char *hostname, int flags,
                                int timeout_ms,
                                SocketDNSResolver_Result *result)
{
  struct resolve_sync_context ctx = { 0 };
  SocketDNSResolver_Query_T query;
  TimeoutTracker tracker;
  int loop_result;

  assert (resolver);
  assert (hostname);
  assert (result);

  /* Initialize result */
  memset (result, 0, sizeof (*result));

  /* Use default timeout if not specified */
  if (timeout_ms <= 0)
    timeout_ms = RESOLVER_DEFAULT_TIMEOUT_MS;

  timeout_tracker_init (&tracker, timeout_ms);

  /* Start async resolution */
  query = SocketDNSResolver_resolve (resolver, hostname, flags,
                                     resolve_sync_callback, &ctx);

  /* Fast path: immediate completion (cached, localhost, IP literal) */
  if (ctx.done)
    {
      if (ctx.error == RESOLVER_OK)
        *result = ctx.result;
      return ctx.error;
    }

  /* Query failed to start */
  if (!query)
    return ctx.error != 0 ? ctx.error : RESOLVER_ERROR_NETWORK;

  /* Run event loop until completion or timeout */
  loop_result = run_sync_event_loop (resolver, query, &ctx, &tracker);

  /* Copy result on success */
  if (loop_result == RESOLVER_OK && ctx.error == RESOLVER_OK)
    *result = ctx.result;

  return loop_result;
}

int
SocketDNSResolver_cancel (T resolver, SocketDNSResolver_Query_T query)
{
  assert (resolver);

  if (!query)
    return -1;

  /* Find query in list */
  struct SocketDNSResolver_Query *q = resolver->query_head;
  while (q)
    {
      if (q == query)
        {
          q->state = QUERY_STATE_CANCELLED;
          return 0;
        }
      q = q->list_next;
    }

  return -1; /* Not found */
}

const char *
SocketDNSResolver_query_hostname (SocketDNSResolver_Query_T query)
{
  return query ? query->hostname : NULL;
}

int
SocketDNSResolver_fd_v4 (T resolver)
{
  assert (resolver);
  return SocketDNSTransport_fd_v4 (resolver->transport);
}

int
SocketDNSResolver_fd_v6 (T resolver)
{
  assert (resolver);
  return SocketDNSTransport_fd_v6 (resolver->transport);
}

/*
 * State Transition Handlers
 */

/**
 * Handle CNAME state - re-query for CNAME target.
 *
 * @param resolver Resolver instance.
 * @param q        Query in CNAME state.
 * @return 1 if query completed, 0 otherwise.
 */
static int
handle_cname_state (T resolver, struct SocketDNSResolver_Query *q)
{
  q->id = generate_unique_id (resolver);
  if (send_query (resolver, q) != 0)
    {
      complete_query (resolver, q, RESOLVER_ERROR_NETWORK);
      return 1;
    }
  return 0;
}

/**
 * Handle TCP fallback state - retry via TCP after truncation.
 *
 * @param resolver Resolver instance.
 * @param q        Query in TCP_FALLBACK state.
 * @return 1 if query completed, 0 otherwise.
 */
static int
handle_tcp_fallback_state (T resolver, struct SocketDNSResolver_Query *q)
{
  q->id = generate_unique_id (resolver);
  if (send_query (resolver, q) != 0)
    {
      complete_query (resolver, q, RESOLVER_ERROR_NETWORK);
      return 1;
    }
  return 0;
}

/**
 * Handle init state - send query for second record type (AAAA after A).
 *
 * @param resolver Resolver instance.
 * @param q        Query in INIT state.
 * @return 1 if query completed, 0 otherwise.
 */
static int
handle_init_state (T resolver, struct SocketDNSResolver_Query *q)
{
  q->id = generate_unique_id (resolver);
  if (send_query (resolver, q) != 0)
    {
      complete_query (resolver, q, RESOLVER_ERROR_NETWORK);
      return 1;
    }
  return 0;
}

/**
 * Handle complete state - query succeeded.
 *
 * @param resolver Resolver instance.
 * @param q        Query in COMPLETE state.
 * @return Always 1 (query is complete).
 */
static int
handle_complete_state (T resolver, struct SocketDNSResolver_Query *q)
{
  complete_query (resolver, q, RESOLVER_OK);
  return 1;
}

/**
 * Handle failed state - query timed out or encountered error.
 *
 * @param resolver Resolver instance.
 * @param q        Query in FAILED state.
 * @return Always 1 (query is complete).
 */
static int
handle_failed_state (T resolver, struct SocketDNSResolver_Query *q)
{
  complete_query (resolver, q, RESOLVER_ERROR_TIMEOUT);
  return 1;
}

/**
 * Handle cancelled state - query was cancelled by user.
 *
 * @param resolver Resolver instance.
 * @param q        Query in CANCELLED state.
 * @return Always 1 (query is complete).
 */
static int
handle_cancelled_state (T resolver, struct SocketDNSResolver_Query *q)
{
  complete_query (resolver, q, RESOLVER_ERROR_CANCELLED);
  return 1;
}

/**
 * Dispatch state transition for a query.
 *
 * @param resolver Resolver instance.
 * @param q        Query to process.
 * @return Number of queries completed (0 or 1).
 */
static int
dispatch_state_transition (T resolver, struct SocketDNSResolver_Query *q)
{
  switch (q->state)
    {
    case QUERY_STATE_CNAME:
      return handle_cname_state (resolver, q);
    case QUERY_STATE_TCP_FALLBACK:
      return handle_tcp_fallback_state (resolver, q);
    case QUERY_STATE_INIT:
      return handle_init_state (resolver, q);
    case QUERY_STATE_COMPLETE:
      return handle_complete_state (resolver, q);
    case QUERY_STATE_FAILED:
      return handle_failed_state (resolver, q);
    case QUERY_STATE_CANCELLED:
      return handle_cancelled_state (resolver, q);
    default:
      /* SENT/WAITING - no action needed */
      return 0;
    }
}

int
SocketDNSResolver_process (T resolver, int timeout_ms)
{
  int completed = 0;

  assert (resolver);

  /* Process transport */
  SocketDNSTransport_process (resolver->transport, timeout_ms);

  /* Process queries that need state transitions */
  struct SocketDNSResolver_Query *q = resolver->query_head;
  while (q)
    {
      struct SocketDNSResolver_Query *next = q->list_next;

      completed += dispatch_state_transition (resolver, q);

      q = next;
    }

  return completed;
}

int
SocketDNSResolver_pending_count (T resolver)
{
  assert (resolver);
  return resolver->pending_count;
}

void
SocketDNSResolver_cache_clear (T resolver)
{
  assert (resolver);
  cache_clear (resolver);
}

void
SocketDNSResolver_cache_set_ttl (T resolver, int ttl_seconds)
{
  assert (resolver);
  resolver->cache_ttl_seconds = ttl_seconds >= 0 ? ttl_seconds : 0;
}

void
SocketDNSResolver_cache_set_max (T resolver, size_t max_entries)
{
  assert (resolver);
  resolver->cache_max_entries = max_entries;

  if (max_entries == 0)
    {
      cache_clear (resolver);
    }
  else
    {
      while (resolver->cache_size > max_entries)
        cache_evict_oldest (resolver);
    }
}

void
SocketDNSResolver_cache_stats (T resolver, SocketDNSResolver_CacheStats *stats)
{
  uint64_t total;

  assert (resolver);
  assert (stats);

  stats->hits = resolver->cache_hits;
  stats->misses = resolver->cache_misses;
  stats->evictions = resolver->cache_evictions;
  stats->insertions = resolver->cache_insertions;
  stats->current_size = resolver->cache_size;
  stats->max_entries = resolver->cache_max_entries;
  stats->ttl_seconds = resolver->cache_ttl_seconds;

  total = stats->hits + stats->misses;
  stats->hit_rate = (total > 0) ? (double)stats->hits / (double)total : 0.0;
}

int
SocketDNSResolver_cache_lookup (T resolver, const char *hostname,
                                SocketDNSResolver_Result *result)
{
  struct CacheEntry *cached;

  assert (resolver);
  assert (hostname);
  assert (result);

  /* Initialize result */
  memset (result, 0, sizeof (*result));

  /* Check cache */
  cached = cache_lookup (resolver, hostname);
  if (!cached)
    return RESOLVER_ERROR_NXDOMAIN; /* Not in cache */

  /* Build result from cache - use reallocarray to prevent integer overflow */
  result->addresses = reallocarray (NULL, cached->address_count,
                                    sizeof (SocketDNSResolver_Address));
  if (!result->addresses)
    return RESOLVER_ERROR_NOMEM;

  memcpy (result->addresses, cached->addresses,
          cached->address_count * sizeof (SocketDNSResolver_Address));
  result->count = cached->address_count;
  result->min_ttl = cached->ttl;

  return RESOLVER_OK;
}

void
SocketDNSResolver_result_free (SocketDNSResolver_Result *result)
{
  if (result && result->addresses)
    {
      free (result->addresses);
      result->addresses = NULL;
      result->count = 0;
    }
}

const char *
SocketDNSResolver_strerror (int error)
{
  switch (error)
    {
    case RESOLVER_OK:
      return "Success";
    case RESOLVER_ERROR_TIMEOUT:
      return "Query timeout";
    case RESOLVER_ERROR_CANCELLED:
      return "Query cancelled";
    case RESOLVER_ERROR_NXDOMAIN:
      return "Domain does not exist";
    case RESOLVER_ERROR_SERVFAIL:
      return "Server failure";
    case RESOLVER_ERROR_REFUSED:
      return "Query refused";
    case RESOLVER_ERROR_NO_NS:
      return "No nameservers configured";
    case RESOLVER_ERROR_NETWORK:
      return "Network error";
    case RESOLVER_ERROR_CNAME_LOOP:
      return "CNAME chain too deep";
    case RESOLVER_ERROR_INVALID:
      return "Invalid response";
    case RESOLVER_ERROR_NOMEM:
      return "Out of memory";
    case RESOLVER_ERROR_VALIDATION_QNAME:
      return "Response QNAME mismatch (RFC 5452)";
    case RESOLVER_ERROR_VALIDATION_QTYPE:
      return "Response QTYPE mismatch (RFC 5452)";
    case RESOLVER_ERROR_VALIDATION_QCLASS:
      return "Response QCLASS mismatch (RFC 5452)";
    case RESOLVER_ERROR_VALIDATION_BAILIWICK:
      return "Answer outside queried zone (RFC 5452)";
    default:
      return "Unknown error";
    }
}

#undef T

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

#include <arpa/inet.h>
#include <assert.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define T SocketDNSResolver_T

/* Exception definition */
const Except_T SocketDNSResolver_Failed
    = { &SocketDNSResolver_Failed, "DNS resolver operation failed" };

/* Internal constants */
#define QUERY_HASH_SIZE 256
#define CACHE_HASH_SIZE 1021
#define MAX_QUERY_MESSAGE_SIZE 512

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
  uint16_t next_query_id;
  uint16_t id_seed;

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

/* Utility: get monotonic time in milliseconds */
static int64_t
get_monotonic_ms (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Utility: DJB2 case-insensitive hash */
static unsigned
hash_hostname (const char *hostname)
{
  unsigned hash = 5381;
  int c;
  while ((c = (unsigned char)*hostname++) != 0)
    {
      if (c >= 'A' && c <= 'Z')
        c += 32; /* lowercase */
      hash = ((hash << 5) + hash) + c;
    }
  return hash % CACHE_HASH_SIZE;
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

/*
 * Query ID Management
 */

static uint16_t
generate_unique_id (T resolver)
{
  uint16_t id;
  int attempts = 0;
  const int max_attempts = 1000;

  do
    {
      id = resolver->next_query_id++;
      if (resolver->next_query_id == 0)
        resolver->next_query_id = 1;

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

  /* Fallback: just use the ID (collision will be handled) */
  return resolver->next_query_id++;
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

  entry->hostname = strdup (hostname);
  if (!entry->hostname)
    return;

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
 * Response Parsing
 */

static int
parse_response (T resolver, struct SocketDNSResolver_Query *q,
                const unsigned char *response, size_t len)
{
  SocketDNS_Header header;
  SocketDNS_Question question;
  SocketDNS_RR rr;
  size_t offset;
  size_t consumed;
  char cname_target[DNS_MAX_NAME_LEN] = { 0 };

  (void)resolver; /* unused - may be used for caching in future */

  /* Decode header */
  if (SocketDNS_header_decode (response, len, &header) != 0)
    return RESOLVER_ERROR_INVALID;

  /* Verify response */
  if (header.qr != 1)
    return RESOLVER_ERROR_INVALID;
  if (header.id != q->id)
    return RESOLVER_ERROR_INVALID;

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

      /* Handle CNAME */
      if (rr.type == DNS_TYPE_CNAME)
        {
          if (SocketDNS_rdata_parse_cname (response, len, &rr, cname_target,
                                           sizeof (cname_target))
              < 0)
            continue;

          /* Check CNAME depth */
          if (q->cname_depth >= RESOLVER_MAX_CNAME_DEPTH)
            return RESOLVER_ERROR_CNAME_LOOP;

          /* Store CNAME target for re-query */
          snprintf (q->current_name, DNS_MAX_NAME_LEN, "%s", cname_target);
          q->cname_depth++;
          q->state = QUERY_STATE_CNAME;
          return RESOLVER_OK; /* Will trigger re-query */
        }

      /* Handle A record */
      if (rr.type == DNS_TYPE_A && q->address_count < RESOLVER_MAX_ADDRESSES)
        {
          struct in_addr addr;
          if (SocketDNS_rdata_parse_a (&rr, &addr) == 0)
            {
              q->addresses[q->address_count].family = AF_INET;
              q->addresses[q->address_count].addr.v4 = addr;
              q->addresses[q->address_count].ttl = rr.ttl;
              if (q->min_ttl == 0 || rr.ttl < q->min_ttl)
                q->min_ttl = rr.ttl;
              q->address_count++;
            }
        }

      /* Handle AAAA record */
      if (rr.type == DNS_TYPE_AAAA && q->address_count < RESOLVER_MAX_ADDRESSES)
        {
          struct in6_addr addr;
          if (SocketDNS_rdata_parse_aaaa (&rr, &addr) == 0)
            {
              q->addresses[q->address_count].family = AF_INET6;
              q->addresses[q->address_count].addr.v6 = addr;
              q->addresses[q->address_count].ttl = rr.ttl;
              if (q->min_ttl == 0 || rr.ttl < q->min_ttl)
                q->min_ttl = rr.ttl;
              q->address_count++;
            }
        }
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
  T resolver = NULL;

  /* We need the resolver to find q in our list */
  /* The query struct contains a pointer back to us via the list */
  /* For now, store resolver in a way we can access it */
  /* This is a limitation - we'll use a global or embed resolver ptr in query */
  (void)query;

  if (!q)
    return;

  /* Handle transport errors */
  if (error != DNS_ERROR_SUCCESS)
    {
      switch (error)
        {
        case DNS_ERROR_TRUNCATED:
          /* TCP fallback - resend via TCP */
          q->state = QUERY_STATE_TCP_FALLBACK;
          q->is_tcp = 1;
          /* Will be handled in process() */
          return;
        default:
          /* All other errors cause failure */
          q->state = QUERY_STATE_FAILED;
          /* Callback will be fired in process() */
          return;
        }
    }

  /* Parse response */
  /* We need the resolver for cache - store it in query */
  /* For now, just parse without caching */
  int parse_result = RESOLVER_OK;
  if (response && len > 0)
    {
      /* Quick header check for RCODE */
      SocketDNS_Header header;
      if (SocketDNS_header_decode (response, len, &header) == 0)
        {
          if (header.tc)
            {
              /* Truncated - need TCP fallback */
              q->state = QUERY_STATE_TCP_FALLBACK;
              q->is_tcp = 1;
              return;
            }

          /* Check RCODE in header */
          switch (header.rcode)
            {
            case DNS_RCODE_NOERROR:
              break;
            case DNS_RCODE_NXDOMAIN:
              q->state = QUERY_STATE_FAILED;
              return;
            case DNS_RCODE_SERVFAIL:
              q->state = QUERY_STATE_FAILED;
              return;
            case DNS_RCODE_REFUSED:
              q->state = QUERY_STATE_FAILED;
              return;
            default:
              break;
            }
        }

      /* Full parse will be done in process() when we have resolver context */
      /* Store response temporarily - but we can't, so parse now */
      /* Actually, let's parse inline */
      SocketDNS_Question question;
      SocketDNS_RR rr;
      size_t offset;
      size_t consumed;
      char cname_target[DNS_MAX_NAME_LEN] = { 0 };

      if (SocketDNS_header_decode (response, len, &header) != 0)
        {
          q->state = QUERY_STATE_FAILED;
          return;
        }

      /* Skip question section */
      offset = DNS_HEADER_SIZE;
      for (int i = 0; i < header.qdcount; i++)
        {
          if (SocketDNS_question_decode (response, len, offset, &question,
                                         &consumed)
              != 0)
            {
              q->state = QUERY_STATE_FAILED;
              return;
            }
          offset += consumed;
        }

      /* Parse answer section */
      for (int i = 0; i < header.ancount; i++)
        {
          if (SocketDNS_rr_decode (response, len, offset, &rr, &consumed) != 0)
            break;
          offset += consumed;

          /* Handle CNAME */
          if (rr.type == DNS_TYPE_CNAME)
            {
              if (SocketDNS_rdata_parse_cname (response, len, &rr, cname_target,
                                               sizeof (cname_target))
                  >= 0)
                {
                  if (q->cname_depth >= RESOLVER_MAX_CNAME_DEPTH)
                    {
                      q->state = QUERY_STATE_FAILED;
                      return;
                    }
                  snprintf (q->current_name, DNS_MAX_NAME_LEN, "%s",
                            cname_target);
                  q->cname_depth++;
                  q->state = QUERY_STATE_CNAME;
                  return;
                }
            }

          /* Handle A record */
          if (rr.type == DNS_TYPE_A
              && q->address_count < RESOLVER_MAX_ADDRESSES)
            {
              struct in_addr addr;
              if (SocketDNS_rdata_parse_a (&rr, &addr) == 0)
                {
                  q->addresses[q->address_count].family = AF_INET;
                  q->addresses[q->address_count].addr.v4 = addr;
                  q->addresses[q->address_count].ttl = rr.ttl;
                  if (q->min_ttl == 0 || rr.ttl < q->min_ttl)
                    q->min_ttl = rr.ttl;
                  q->address_count++;
                }
            }

          /* Handle AAAA record */
          if (rr.type == DNS_TYPE_AAAA
              && q->address_count < RESOLVER_MAX_ADDRESSES)
            {
              struct in6_addr addr;
              if (SocketDNS_rdata_parse_aaaa (&rr, &addr) == 0)
                {
                  q->addresses[q->address_count].family = AF_INET6;
                  q->addresses[q->address_count].addr.v6 = addr;
                  q->addresses[q->address_count].ttl = rr.ttl;
                  if (q->min_ttl == 0 || rr.ttl < q->min_ttl)
                    q->min_ttl = rr.ttl;
                  q->address_count++;
                }
            }
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
      /* Build result */
      result.addresses = malloc (q->address_count
                                 * sizeof (SocketDNSResolver_Address));
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
  config.max_timeout_ms = resolver->timeout_ms * 4; /* 4x for backoff headroom */
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

  /* Initialize query ID generator with random seed */
  resolver->id_seed = (uint16_t)(get_monotonic_ms () & 0xFFFF);
  resolver->next_query_id = resolver->id_seed;
  if (resolver->next_query_id == 0)
    resolver->next_query_id = 1;

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

  /* Check if hostname is a numeric IP address - fast path skips DNS */
  {
    SocketDNSResolver_Result result = { 0 };
    SocketDNSResolver_Address addr = { 0 };
    struct in_addr v4;
    struct in6_addr v6;
    unsigned int scope_id = 0;

    if (is_ipv4_address (hostname, &v4))
      {
        /* IPv4 numeric address - no DNS needed */
        addr.family = AF_INET;
        addr.addr.v4 = v4;
        addr.ttl = 0; /* No TTL for literals */

        result.addresses = &addr;
        result.count = 1;
        result.min_ttl = 0;

        callback (NULL, &result, RESOLVER_OK, userdata);
        return NULL; /* No pending query */
      }

    if (is_ipv6_address (hostname, &v6, &scope_id))
      {
        /* IPv6 numeric address (with optional zone ID) - no DNS needed */
        addr.family = AF_INET6;
        addr.addr.v6 = v6;
        addr.ttl = 0;
        /* Note: scope_id is available for caller but not stored in result.
         * The caller can use if_nametoindex() to get it if needed. */
        (void)scope_id;

        result.addresses = &addr;
        result.count = 1;
        result.min_ttl = 0;

        callback (NULL, &result, RESOLVER_OK, userdata);
        return NULL; /* No pending query */
      }
  }

  /* Check if hostname is "localhost" - return loopback addresses */
  if (is_localhost (hostname))
    {
      SocketDNSResolver_Result result = { 0 };
      SocketDNSResolver_Address addrs[2];
      size_t addr_count = 0;

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
      return NULL; /* No pending query */
    }

  /* Check cache */
  if (!(flags & RESOLVER_FLAG_NO_CACHE))
    {
      struct CacheEntry *cached = cache_lookup (resolver, hostname);
      if (cached)
        {
          /* Build result from cache */
          SocketDNSResolver_Result result = { 0 };
          result.addresses = malloc (cached->address_count
                                     * sizeof (SocketDNSResolver_Address));
          if (result.addresses)
            {
              memcpy (result.addresses, cached->addresses,
                      cached->address_count
                          * sizeof (SocketDNSResolver_Address));
              result.count = cached->address_count;
              result.min_ttl = cached->ttl;

              callback (NULL, &result, RESOLVER_OK, userdata);
              free (result.addresses);
              return NULL; /* No pending query */
            }
        }
    }

  /* Check nameservers */
  if (SocketDNSTransport_nameserver_count (resolver->transport) == 0)
    {
      callback (NULL, NULL, RESOLVER_ERROR_NO_NS, userdata);
      return NULL;
    }

  /* Allocate query */
  q = Arena_alloc (resolver->arena, sizeof (*q), __FILE__, __LINE__);
  if (!q)
    {
      callback (NULL, NULL, RESOLVER_ERROR_NOMEM, userdata);
      return NULL;
    }

  memset (q, 0, sizeof (*q));
  q->id = generate_unique_id (resolver);
  snprintf (q->hostname, DNS_MAX_NAME_LEN, "%s", hostname);
  snprintf (q->current_name, DNS_MAX_NAME_LEN, "%s", hostname);
  q->flags = flags;
  q->state = QUERY_STATE_INIT;
  q->callback = callback;
  q->userdata = userdata;

  /* Add to pending list */
  query_list_add (resolver, q);

  /* Send initial query */
  if (send_query (resolver, q) != 0)
    {
      query_list_remove (resolver, q);
      callback (q, NULL, RESOLVER_ERROR_NETWORK, userdata);
      return NULL;
    }

  return q;
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

      switch (q->state)
        {
        case QUERY_STATE_CNAME:
          /* Re-query for CNAME target */
          q->id = generate_unique_id (resolver);
          if (send_query (resolver, q) != 0)
            {
              complete_query (resolver, q, RESOLVER_ERROR_NETWORK);
              completed++;
            }
          break;

        case QUERY_STATE_TCP_FALLBACK:
          /* Retry via TCP */
          q->id = generate_unique_id (resolver);
          if (send_query (resolver, q) != 0)
            {
              complete_query (resolver, q, RESOLVER_ERROR_NETWORK);
              completed++;
            }
          break;

        case QUERY_STATE_INIT:
          /* Need to send query for second record type (AAAA after A) */
          q->id = generate_unique_id (resolver);
          if (send_query (resolver, q) != 0)
            {
              complete_query (resolver, q, RESOLVER_ERROR_NETWORK);
              completed++;
            }
          break;

        case QUERY_STATE_COMPLETE:
          complete_query (resolver, q, RESOLVER_OK);
          completed++;
          break;

        case QUERY_STATE_FAILED:
          complete_query (resolver, q, RESOLVER_ERROR_TIMEOUT);
          completed++;
          break;

        case QUERY_STATE_CANCELLED:
          complete_query (resolver, q, RESOLVER_ERROR_CANCELLED);
          completed++;
          break;

        default:
          break;
        }

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
    default:
      return "Unknown error";
    }
}

#undef T

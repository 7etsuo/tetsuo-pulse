#ifndef SOCKETSYNPROTECT_PRIVATE_INCLUDED
#define SOCKETSYNPROTECT_PRIVATE_INCLUDED

/**
 * SocketSYNProtect-private.h - Internal structures for SYN protection
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This header contains internal implementation details not part of the
 * public API. Do not include directly - use SocketSYNProtect.h instead.
 */

#include "core/Arena.h"
#include "core/SocketRateLimit.h"
#include "core/SocketSYNProtect.h"
#include "core/SocketUtil.h"
#include <pthread.h>
#include <stdatomic.h>

/* ============================================================================
 * Internal Configuration Constants
 * ============================================================================ */

/* Hash table size for IP tracking - prime number for good distribution */
#ifndef SOCKET_SYN_IP_HASH_SIZE
#define SOCKET_SYN_IP_HASH_SIZE 4093
#endif

/* Hash table size for whitelist/blacklist - smaller prime */
#ifndef SOCKET_SYN_LIST_HASH_SIZE
#define SOCKET_SYN_LIST_HASH_SIZE 509
#endif

/* Initial score for new IPs */
#ifndef SOCKET_SYN_INITIAL_SCORE
#define SOCKET_SYN_INITIAL_SCORE 0.8f
#endif

/* Score for whitelisted IPs */
#ifndef SOCKET_SYN_TRUSTED_SCORE
#define SOCKET_SYN_TRUSTED_SCORE 1.0f
#endif

/* Maximum CIDR entries (converted to individual ranges) */
#ifndef SOCKET_SYN_MAX_CIDR_ENTRIES
#define SOCKET_SYN_MAX_CIDR_ENTRIES 256
#endif

/* ============================================================================
 * IP Entry Structure (for hash table with LRU)
 * ============================================================================ */

/**
 * SocketSYN_IPEntry - Internal IP tracking entry
 *
 * Stored in hash table with chaining for collision resolution.
 * Linked in LRU list for eviction when at capacity.
 */
typedef struct SocketSYN_IPEntry
{
  /* State data (public view) */
  SocketSYN_IPState state;

  /* Hash table chaining */
  struct SocketSYN_IPEntry *hash_next;

  /* LRU doubly-linked list */
  struct SocketSYN_IPEntry *lru_prev;
  struct SocketSYN_IPEntry *lru_next;
} SocketSYN_IPEntry;

/* ============================================================================
 * Whitelist Entry Structure
 * ============================================================================ */

/**
 * SocketSYN_WhitelistEntry - Whitelist entry
 *
 * Supports both individual IPs and CIDR ranges.
 */
typedef struct SocketSYN_WhitelistEntry
{
  char ip[SOCKET_IP_MAX_LEN]; /**< IP or network address */
  int is_cidr;                /**< 1 if CIDR range, 0 if single IP */
  uint8_t prefix_len;         /**< CIDR prefix length (0-128) */
  uint8_t addr_bytes[16];     /**< Parsed address bytes (IPv6 max) */
  int addr_family;            /**< AF_INET or AF_INET6 */
  struct SocketSYN_WhitelistEntry *next;
} SocketSYN_WhitelistEntry;

/* ============================================================================
 * Blacklist Entry Structure
 * ============================================================================ */

/**
 * SocketSYN_BlacklistEntry - Blacklist entry with expiry
 */
typedef struct SocketSYN_BlacklistEntry
{
  char ip[SOCKET_IP_MAX_LEN]; /**< IP address */
  int64_t expires_ms;         /**< Expiry timestamp (0 = permanent) */
  struct SocketSYN_BlacklistEntry *next;
} SocketSYN_BlacklistEntry;

/* ============================================================================
 * Main Structure Definition
 * ============================================================================ */

/**
 * struct SocketSYNProtect_T - Main SYN protection structure
 *
 * Contains all state for SYN flood protection including hash tables,
 * LRU lists, whitelist/blacklist, and statistics.
 */
struct SocketSYNProtect_T
{
  /* Memory management */
  Arena_T arena;       /**< Arena for allocations (NULL = malloc) */
  int use_malloc;      /**< 1 if using malloc, 0 if arena */
  int initialized;     /**< 1 if mutex initialized */
  pthread_mutex_t mutex; /**< Thread safety mutex */

  /* Configuration (copy of user config) */
  SocketSYNProtect_Config config;

  /* IP state tracking hash table */
  SocketSYN_IPEntry **ip_table;  /**< Hash table buckets */
  size_t ip_table_size;          /**< Number of buckets */
  size_t ip_entry_count;         /**< Current entries */

  /* LRU list for eviction */
  SocketSYN_IPEntry *lru_head;   /**< Most recently used */
  SocketSYN_IPEntry *lru_tail;   /**< Least recently used */

  /* Whitelist hash table */
  SocketSYN_WhitelistEntry **whitelist_table;
  size_t whitelist_count;

  /* Blacklist hash table */
  SocketSYN_BlacklistEntry **blacklist_table;
  size_t blacklist_count;

  /* Global rate limiter */
  SocketRateLimit_T global_limiter;

  /* Statistics (use atomics for lock-free reads) */
  _Atomic uint64_t stat_attempts;
  _Atomic uint64_t stat_allowed;
  _Atomic uint64_t stat_throttled;
  _Atomic uint64_t stat_challenged;
  _Atomic uint64_t stat_blocked;
  _Atomic uint64_t stat_whitelisted;
  _Atomic uint64_t stat_blacklisted;
  _Atomic uint64_t stat_lru_evictions;
  int64_t start_time_ms;
};

/* ============================================================================
 * Internal Helper Function Declarations
 * ============================================================================ */

/**
 * synprotect_hash_ip - Hash IP address string
 * @ip: IP address string
 * @table_size: Hash table size
 *
 * Returns: Hash bucket index
 * Thread-safe: Yes (pure function)
 */
static inline unsigned
synprotect_hash_ip (const char *ip, size_t table_size)
{
  return socket_util_hash_djb2 (ip, (unsigned)table_size);
}

/**
 * synprotect_clamp_score - Clamp score to [0.0, 1.0]
 * @score: Score to clamp
 *
 * Returns: Clamped score
 */
static inline float
synprotect_clamp_score (float score)
{
  if (score < 0.0f)
    return 0.0f;
  if (score > 1.0f)
    return 1.0f;
  return score;
}

/**
 * synprotect_min - Integer minimum
 */
static inline int64_t
synprotect_min (int64_t a, int64_t b)
{
  return (a < b) ? a : b;
}

/**
 * synprotect_max - Integer maximum
 */
static inline int64_t
synprotect_max (int64_t a, int64_t b)
{
  return (a > b) ? a : b;
}

#endif /* SOCKETSYNPROTECT_PRIVATE_INCLUDED */


/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSYNPROTECT_PRIVATE_INCLUDED
#define SOCKETSYNPROTECT_PRIVATE_INCLUDED

/**
 * @file SocketSYNProtect-private.h
 * @ingroup security
 * @internal
 * @brief Internal SYN flood protection implementation details for the @ref
 * security "Security Modules" group.
 *
 * Private header containing internal structures and functions for the
 * SocketSYNProtect module. Not part of the public API - do not include
 * directly from user code.
 *
 * Contains:
 * - IP reputation tracking hash tables
 * - Sliding window counters for rate measurement
 * - CIDR range parsing and prefix matching management
 * - Score calculation and decay algorithms
 * - Whitelist/blacklist data structures
 *
 * @note Do not include directly - use SocketSYNProtect.h instead.
 * @warning Internal implementation details subject to change.
 * @see SocketSYNProtect.h for public SYN protection API.
 */

#include "core/Arena.h"
#include "core/SocketRateLimit.h"
#include "core/SocketSYNProtect.h"
#include "core/SocketUtil.h"
#include <pthread.h>
#include <stdatomic.h>

/* ============================================================================
 * Internal Configuration Constants
 * ============================================================================
 */

/**
 * @brief Default hash table size for IP state tracking entries.
 *
 * Prime number (4093) chosen for optimal hash distribution, low collision
 * rate, and efficient memory usage.
 *
 * @ingroup security
 * @internal
 * @note Can be overridden via preprocessor definition before including this
 * header.
 * @see SocketSYNProtect_T::ip_table - The hash table using this size.
 * @see synprotect_hash_ip() - The hashing function that uses this table size.
 */
#ifndef SOCKET_SYN_IP_HASH_SIZE
#define SOCKET_SYN_IP_HASH_SIZE 4093
#endif

/**
 * @brief Default hash table size for whitelist and blacklist entries.
 *
 * Smaller prime number (509) suitable for lower-volume lists with fewer
 * entries compared to main IP tracking table.
 *
 * @ingroup security
 * @internal
 * @note Override via preprocessor if needed for custom sizing.
 * @see SocketSYNProtect_T::whitelist_table
 * @see SocketSYNProtect_T::blacklist_table
 */
#ifndef SOCKET_SYN_LIST_HASH_SIZE
#define SOCKET_SYN_LIST_HASH_SIZE 509
#endif

/**
 * @brief Initial reputation score for newly encountered IP addresses.
 *
 * Default value of 0.8f provides moderate trust ("benefit of the doubt")
 * to unknown IPs before any behavior is observed.
 *
 * @ingroup security
 * @internal
 * @note Value must be in [0.0f, 1.0f]; clamped if necessary.
 * @see synprotect_clamp_score() for validation.
 * @see SocketSYNProtect_T::ip_table entries initialization.
 */
#ifndef SOCKET_SYN_INITIAL_SCORE
#define SOCKET_SYN_INITIAL_SCORE 0.8f
#endif

/**
 * @brief Reputation score assigned to whitelisted or fully trusted IPs.
 *
 * Maximum trust level (1.0f) which typically bypasses rate limits and
 * challenges.
 *
 * @ingroup security
 * @internal
 * @note Clamped to [0.0f, 1.0f] range.
 * @see SocketSYNProtect_whitelist_add() and related functions.
 * @see synprotect_clamp_score() for clamping.
 */
#ifndef SOCKET_SYN_TRUSTED_SCORE
#define SOCKET_SYN_TRUSTED_SCORE 1.0f
#endif

/**
 * @brief Maximum number of whitelist entries (CIDR ranges or single IPs).
 *
 * Limits memory and hash table chain lengths for efficient lookups.
 *
 * @ingroup security
 * @internal
 * @note Each CIDR entry stores network prefix and length; no expansion to
 * individuals.
 * @see SocketSYN_WhitelistEntry for entry structure with prefix_len.
 * @see SocketSYNProtect_whitelist_add_cidr() for adding CIDR notations.
 * @see ip_matches_cidr() internal matching function.
 */
#ifndef SOCKET_SYN_MAX_CIDR_ENTRIES
#define SOCKET_SYN_MAX_CIDR_ENTRIES 256
#endif

/* ============================================================================
 * IP Entry Structure (for hash table with LRU)
 * ============================================================================
 */

/**
 * @brief Internal IP tracking entry for hash table and LRU management.
 * @ingroup security
 * @internal Not part of public API; used for efficient IP state storage.
 *
 * Combines public SocketSYN_IPState with private linking fields for
 * hash chaining and least-recently-used eviction policy.
 *
 * @see SocketSYN_IPState for the public-facing state fields.
 * @see SocketSYNProtect_T::ip_table for the containing hash table.
 * @see SocketSYNProtect_cleanup() for eviction during maintenance.
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
 * ============================================================================
 */

/**
 * @brief Structure for whitelist entries supporting single IPs and CIDR
 * ranges.
 * @ingroup security
 * @internal Chained list in hash table for fast lookups.
 *
 * Stores parsed address for efficient prefix matching on IPv4/IPv6 CIDR
 * ranges. CIDR entries are not expanded to individual IPs; uses prefix length
 * for matching.
 *
 * @see SocketSYNProtect_whitelist_add_cidr() for adding CIDR notations.
 * @see SocketSYNProtect_whitelist_add() for single IPs.
 * @see SocketSYNProtect_whitelist_contains() for query.
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
 * ============================================================================
 */

/**
 * @brief Internal structure for blacklisted IP addresses with expiry support.
 * @ingroup security
 * @internal Chained in hash table; entries auto-expire via cleanup().
 *
 * Stores IP string and absolute expiry timestamp; permanent if 0.
 *
 * @see SocketSYNProtect_blacklist_add() for adding with duration.
 * @see SocketSYNProtect_blacklist_contains() for checking active status.
 * @see SocketSYNProtect_cleanup() for removing expired entries.
 */
typedef struct SocketSYN_BlacklistEntry
{
  char ip[SOCKET_IP_MAX_LEN]; /**< IP address */
  int64_t expires_ms;         /**< Expiry timestamp (0 = permanent) */
  struct SocketSYN_BlacklistEntry *next;
} SocketSYN_BlacklistEntry;

/* ============================================================================
 * Main Structure Definition
 * ============================================================================
 */

#define T SocketSYNProtect_T

/**
 * @brief Core internal structure for the SYN protection module.
 * @ingroup security
 * @internal Opaque type exposed as SocketSYNProtect_T in public header.
 *
 * Aggregates configuration, tracking tables, lists, rate limiters, and atomic
 * stats. Thread-safe via pthread mutex for modifications; atomics for
 * concurrent stat reads.
 *
 * @see SocketSYNProtect_new() for creation and initialization.
 * @see SocketSYNProtect_Config for tunable parameters.
 * @see SocketSYNProtect_Stats for observable metrics.
 * @see SocketRateLimit_T for global rate limiting integration.
 * @threadsafe Conditional - mutex guards most fields; stats readable
 * lock-free.
 */
struct SocketSYNProtect_T
{
  /* Memory management */
  Arena_T arena;         /**< Arena for allocations (NULL = malloc) */
  int use_malloc;        /**< 1 if using malloc, 0 if arena */
  int initialized;       /**< 1 if mutex initialized */
  pthread_mutex_t mutex; /**< Thread safety mutex */

  /* Configuration (copy of user config) */
  SocketSYNProtect_Config config;
  unsigned
      hash_seed; /**< Random seed for hash functions (collision mitigation) */

  /* IP state tracking hash table */
  SocketSYN_IPEntry **ip_table; /**< Hash table buckets */
  size_t ip_table_size;         /**< Number of buckets */
  size_t ip_entry_count;        /**< Current entries */

  /* LRU list for eviction */
  SocketSYN_IPEntry *lru_head; /**< Most recently used */
  SocketSYN_IPEntry *lru_tail; /**< Least recently used */

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
 * ============================================================================
 */

/**
 * @brief Compute hash index for an IP address using instance-specific seed.
 * @ingroup security
 * @internal Internal hashing utility for distributing IP entries.
 *
 * Combines DJB2-style hash with per-instance seed and modulo for table
 * indexing. Designed to resist hash flooding attacks by randomizing per
 * deployment.
 *
 * @param protect The SYN protection instance providing hash_seed.
 * @param ip Null-terminated C string containing IPv4 or IPv6 address.
 * @param table_size Number of buckets in the target hash table (typically
 * prime).
 * @return Unsigned integer hash index in range [0, table_size).
 *
 * @threadsafe Yes - pure function with no observable side effects.
 * @note Relies on socket_util_hash_djb2_ci_len() internally for
 * case-insensitive hashing.
 * @see socket_util_hash_djb2_ci_len() base algorithm.
 * @see SocketSYNProtect_Config::hash_seed for seed configuration.
 */
unsigned synprotect_hash_ip (SocketSYNProtect_T protect, const char *ip,
                             unsigned table_size);

/**
 * @brief Clamp reputation score to valid range [0.0f, 1.0f].
 * @ingroup security
 * @internal Utility for ensuring scores stay bounded during calculations.
 *
 * Prevents invalid scores from propagating through reputation algorithms.
 *
 * @param score Input score value which may be out of bounds.
 * @return Clamped score value, guaranteed to be >= 0.0f and <= 1.0f.
 *
 * @note Used extensively in score adjustment logic.
 * @see SOCKET_SYN_INITIAL_SCORE, SOCKET_SYN_TRUSTED_SCORE constants.
 * @see SocketSYN_IPState::score field.
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
 * @brief Compute the minimum of two int64_t values.
 * @ingroup security
 * @internal Generic min utility for timing and counter calculations.
 *
 * Simple, branchless where possible, for use in internal algorithms.
 *
 * @param a First integer value.
 * @param b Second integer value.
 * @return The smaller (minimum) of the two input values.
 *
 * @note Used for clamping timeouts, windows, and limits.
 */
static inline int64_t
synprotect_min (int64_t a, int64_t b)
{
  return (a < b) ? a : b;
}

/**
 * @brief Compute the maximum of two int64_t values.
 * @ingroup security
 * @internal Generic max utility for internal bounds checking and timing.
 *
 * Complements synprotect_min() for symmetric operations in algorithms.
 *
 * @param a First integer value.
 * @param b Second integer value.
 * @return The larger (maximum) of the two input values.
 *
 * @note Used alongside synprotect_min() for range clamping.
 * @see synprotect_min()
 */
static inline int64_t
synprotect_max (int64_t a, int64_t b)
{
  return (a > b) ? a : b;
}

/* ============================================================================
 * List Management Declarations (implemented in SocketSYNProtect-list.c)
 * ============================================================================
 */
static void safe_copy_ip (char *dest, const char *src);
static int parse_ipv4_address (const char *ip, uint8_t *addr_bytes);
static int parse_ipv6_address (const char *ip, uint8_t *addr_bytes);
static int parse_ip_address (const char *ip, uint8_t *addr_bytes, size_t addr_size);
static int cidr_full_bytes_match (const uint8_t *ip_bytes, const uint8_t *entry_bytes, int bytes);
static int cidr_partial_byte_match (const uint8_t *ip_bytes, const uint8_t *entry_bytes, int byte_index, int remaining_bits);
static int ip_matches_cidr_bytes (int family, const uint8_t *ip_bytes, const SocketSYN_WhitelistEntry *entry);
static int ip_matches_cidr (const char *ip, const SocketSYN_WhitelistEntry *entry);
static int whitelist_check_bucket_bytes (const SocketSYN_WhitelistEntry *entry, const char *ip_str, int family, const uint8_t *ip_bytes);
static int whitelist_check_bucket (const SocketSYN_WhitelistEntry *entry, const char *ip);
static int whitelist_check_all_cidrs_bytes (T protect, int family, const uint8_t *ip_bytes, unsigned skip_bucket);
static int whitelist_check_all_cidrs (T protect, const char *ip, unsigned skip_bucket);
static int whitelist_check (T protect, const char *ip);
static int blacklist_check (T protect, const char *ip, int64_t now_ms);
static SocketSYN_WhitelistEntry * find_whitelist_entry_exact (SocketSYN_WhitelistEntry *bucket_head, const char *ip);
static SocketSYN_BlacklistEntry * find_blacklist_entry (SocketSYN_BlacklistEntry *bucket_head, const char *ip);
static void insert_whitelist_entry (T protect, SocketSYN_WhitelistEntry *entry, unsigned bucket);
static void insert_blacklist_entry (T protect, SocketSYN_BlacklistEntry *entry, unsigned bucket);
static SocketSYN_WhitelistEntry * create_whitelist_entry (T protect, const char *ip, int is_cidr);
static SocketSYN_BlacklistEntry * create_blacklist_entry (T protect, const char *ip, int64_t expires_ms);
static int setup_cidr_entry (SocketSYN_WhitelistEntry *entry, const char *ip_part, int prefix_len);
static int parse_cidr_notation (const char *cidr, char *ip_out, size_t ip_out_size, int *prefix_out);
static size_t cleanup_expired_blacklist (T protect, int64_t now_ms);
static size_t count_active_blacklists (T protect, int64_t now_ms);

/* ============================================================================
 * IP Management Declarations (implemented in SocketSYNProtect-ip.c)
 * ============================================================================
 */
static SocketSYN_IPEntry * find_ip_entry (T protect, const char *ip);
void remove_ip_entry_from_hash (T protect, SocketSYN_IPEntry *entry);
static void evict_lru_entry (T protect);
static void init_ip_state (SocketSYN_IPState *state, const char *ip, int64_t now_ms);
static SocketSYN_IPEntry * create_ip_entry (T protect, const char *ip, int64_t now_ms);
static SocketSYN_IPEntry * get_or_create_ip_entry (T protect, const char *ip, int64_t now_ms);
void lru_remove (T protect, SocketSYN_IPEntry *entry);
static void lru_push_front (T protect, SocketSYN_IPEntry *entry);
static void lru_touch (T protect, SocketSYN_IPEntry *entry);
static void rotate_window_if_needed (SocketSYN_IPState *state, int64_t now_ms, int window_ms);
static float calculate_window_progress (int64_t elapsed, int window_ms);
static uint32_t calculate_effective_attempts (const SocketSYN_IPState *state, int64_t now_ms, int window_ms);
static void apply_score_decay (SocketSYN_IPState *state, const SocketSYNProtect_Config *config, int64_t elapsed_ms);
static void update_reputation_from_score (SocketSYN_IPState *state, const SocketSYNProtect_Config *config);
static void penalize_attempt (SocketSYN_IPState *state, const SocketSYNProtect_Config *config);
static void penalize_failure (SocketSYN_IPState *state, const SocketSYNProtect_Config *config);
static void reward_success (SocketSYN_IPState *state, const SocketSYNProtect_Config *config);
static int is_currently_blocked (const SocketSYN_IPState *state, int64_t now_ms);
static SocketSYN_Action determine_action (const SocketSYN_IPState *state, const SocketSYNProtect_Config *config, uint32_t effective_attempts, int64_t now_ms);
static SocketSYN_Action process_ip_attempt (T protect, SocketSYN_IPEntry *entry, int64_t now_ms);
static SocketSYN_Action process_tracked_ip (T protect, const char *client_ip, int64_t now_ms, SocketSYN_IPState *state_out);
static void fill_ip_state_out (SocketSYN_IPState *state_out, const char *ip, SocketSYN_Reputation rep, float score);
static void handle_whitelisted_ip (T protect, const char *client_ip, SocketSYN_IPState *state_out);
static void handle_blacklisted_ip (T protect, const char *client_ip, SocketSYN_IPState *state_out);
static void update_action_stats (T protect, SocketSYN_Action action);
static int check_global_rate_limit (T protect);
static int check_whitelist_blacklist (T protect, const char *client_ip, int64_t now_ms, SocketSYN_IPState *state_out, SocketSYN_Action *action_out);
static void cleanup_expired_ip_blocks (T protect, int64_t now_ms);
static size_t count_currently_blocked (T protect, int64_t now_ms);
static void * alloc_zeroed (T protect, size_t count, size_t size);
void free_memory (T protect, void *ptr);

#endif /* SOCKETSYNPROTECT_PRIVATE_INCLUDED */

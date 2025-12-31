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
 * @brief Internal SYN flood protection implementation details.
 *
 * Contains IP reputation tracking, sliding window counters, CIDR range
 * matching, score decay algorithms, and whitelist/blacklist structures.
 */

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketRateLimit.h"
#include "core/SocketSYNProtect.h"
#include "core/SocketUtil.h"
#include <pthread.h>
#include <stdatomic.h>

/**
 * @brief Default hash table size for IP state tracking entries.
 * @internal
 */
#ifndef SOCKET_SYN_IP_HASH_SIZE
#define SOCKET_SYN_IP_HASH_SIZE 4093
#endif

/**
 * @brief Default hash table size for whitelist and blacklist entries.
 * @internal
 */
#ifndef SOCKET_SYN_LIST_HASH_SIZE
#define SOCKET_SYN_LIST_HASH_SIZE 509
#endif

/**
 * @brief Initial reputation score for newly encountered IP addresses.
 * @internal
 */
#ifndef SOCKET_SYN_INITIAL_SCORE
#define SOCKET_SYN_INITIAL_SCORE 0.8f
#endif

/**
 * @brief Reputation score assigned to whitelisted or fully trusted IPs.
 * @internal
 */
#ifndef SOCKET_SYN_TRUSTED_SCORE
#define SOCKET_SYN_TRUSTED_SCORE 1.0f
#endif

/**
 * @brief Maximum number of whitelist entries (CIDR ranges or single IPs).
 * @internal
 */
#ifndef SOCKET_SYN_MAX_CIDR_ENTRIES
#define SOCKET_SYN_MAX_CIDR_ENTRIES 256
#endif

/**
 * @brief Internal IP tracking entry for hash table and LRU management.
 * @internal
 */
typedef struct SocketSYN_IPEntry
{
  SocketSYN_IPState state;
  struct SocketSYN_IPEntry *hash_next;
  struct SocketSYN_IPEntry *lru_prev;
  struct SocketSYN_IPEntry *lru_next;
} SocketSYN_IPEntry;

/**
 * @brief Whitelist entry supporting single IPs and CIDR ranges.
 * @internal
 */
typedef struct SocketSYN_WhitelistEntry
{
  char ip[SOCKET_IP_MAX_LEN];
  int is_cidr;
  uint8_t prefix_len;
  uint8_t addr_bytes[16];
  int addr_family;
  struct SocketSYN_WhitelistEntry *next;
} SocketSYN_WhitelistEntry;

/**
 * @brief Blacklisted IP address with expiry support.
 * @internal
 */
typedef struct SocketSYN_BlacklistEntry
{
  char ip[SOCKET_IP_MAX_LEN];
  int64_t expires_ms;
  struct SocketSYN_BlacklistEntry *next;
} SocketSYN_BlacklistEntry;

#define T SocketSYNProtect_T

/**
 * @brief Core internal structure for the SYN protection module.
 * @internal
 *
 * @threadsafe Mutex guards most fields; stats readable lock-free via atomics.
 */
struct SocketSYNProtect_T
{
  Arena_T arena;
  int use_malloc;
  int initialized;
  pthread_mutex_t mutex;

  SocketSYNProtect_Config config;
  unsigned hash_seed;

  SocketSYN_IPEntry **ip_table;
  size_t ip_table_size;
  size_t ip_entry_count;

  SocketSYN_IPEntry *lru_head;
  SocketSYN_IPEntry *lru_tail;

  SocketSYN_WhitelistEntry **whitelist_table;
  size_t whitelist_count;

  SocketSYN_BlacklistEntry **blacklist_table;
  size_t blacklist_count;

  SocketRateLimit_T global_limiter;

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

/**
 * @brief Compute hash index for an IP address using instance-specific seed.
 * @internal
 *
 * @param protect  The SYN protection instance (must not be NULL)
 * @param ip       IP address string (must not be NULL)
 * @param table_size  Number of buckets in hash table
 * Returns: Hash index in range [0, table_size)
 *
 * @pre ip != NULL
 * @pre protect != NULL
 * @threadsafe Yes
 */
unsigned synprotect_hash_ip (SocketSYNProtect_T protect,
                             const char *ip,
                             unsigned table_size);

/**
 * @brief Clamp reputation score to valid range [0.0f, 1.0f].
 * @internal
 *
 * @param score  Input score value
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

/* IP parsing - implemented in SocketSYNProtect-ip.c */
int parse_ipv4_address (const char *ip, uint8_t *addr_bytes);
int parse_ipv6_address (const char *ip, uint8_t *addr_bytes);
int parse_ip_address (const char *ip, uint8_t *addr_bytes, size_t addr_size);
int ip_addresses_equal (const char *ip1, const char *ip2);

/* CIDR matching - implemented in SocketSYNProtect-ip.c */
int cidr_full_bytes_match (const uint8_t *ip_bytes,
                           const uint8_t *entry_bytes,
                           int bytes);
int cidr_partial_byte_match (const uint8_t *ip_bytes,
                             const uint8_t *entry_bytes,
                             int byte_index,
                             int remaining_bits);
int ip_matches_cidr_bytes (int family,
                           const uint8_t *ip_bytes,
                           const SocketSYN_WhitelistEntry *entry);
int ip_matches_cidr (const char *ip, const SocketSYN_WhitelistEntry *entry);

/* Whitelist/blacklist checks - implemented in SocketSYNProtect-ip.c */
int whitelist_check_bucket_bytes (const SocketSYN_WhitelistEntry *entry,
                                  const char *ip_str,
                                  int family,
                                  const uint8_t *ip_bytes);
int
whitelist_check_bucket (const SocketSYN_WhitelistEntry *entry, const char *ip);
int whitelist_check_all_cidrs_bytes (T protect,
                                     int family,
                                     const uint8_t *ip_bytes,
                                     unsigned skip_bucket);
int whitelist_check_all_cidrs (T protect, const char *ip, unsigned skip_bucket);
int whitelist_check (T protect, const char *ip);
int blacklist_check (T protect, const char *ip, int64_t now_ms);

/* LRU operations - implemented in SocketSYNProtect-list.c */
void lru_remove (T protect, SocketSYN_IPEntry *entry);
void lru_push_front (T protect, SocketSYN_IPEntry *entry);
void lru_touch (T protect, SocketSYN_IPEntry *entry);
void evict_lru_entry (T protect);
void free_memory (T protect, void *ptr);
void remove_ip_entry_from_hash (T protect, SocketSYN_IPEntry *entry);

/* Local to main file */
static SocketSYN_WhitelistEntry *
find_whitelist_entry_exact (SocketSYN_WhitelistEntry *bucket_head,
                            const char *ip);
static SocketSYN_BlacklistEntry *
find_blacklist_entry (SocketSYN_BlacklistEntry *bucket_head, const char *ip);
static void insert_whitelist_entry (T protect,
                                    SocketSYN_WhitelistEntry *entry,
                                    unsigned bucket);
static void insert_blacklist_entry (T protect,
                                    SocketSYN_BlacklistEntry *entry,
                                    unsigned bucket);
static SocketSYN_WhitelistEntry *
create_whitelist_entry (T protect, const char *ip, int is_cidr);
static SocketSYN_BlacklistEntry *
create_blacklist_entry (T protect, const char *ip, int64_t expires_ms);
static int setup_cidr_entry (SocketSYN_WhitelistEntry *entry,
                             const char *ip_part,
                             int prefix_len);
static int parse_cidr_notation (const char *cidr,
                                char *ip_out,
                                size_t ip_out_size,
                                int *prefix_out);
static size_t cleanup_expired_blacklist (T protect, int64_t now_ms);
static size_t count_active_blacklists (T protect, int64_t now_ms);
static SocketSYN_IPEntry *find_ip_entry (T protect, const char *ip);
static void
init_ip_state (SocketSYN_IPState *state, const char *ip, int64_t now_ms);
static SocketSYN_IPEntry *
create_ip_entry (T protect, const char *ip, int64_t now_ms);
static SocketSYN_IPEntry *
get_or_create_ip_entry (T protect, const char *ip, int64_t now_ms);
static void rotate_window_if_needed (SocketSYN_IPState *state,
                                     int64_t now_ms,
                                     int window_ms);
static float calculate_window_progress (int64_t elapsed, int window_ms);
static uint32_t calculate_effective_attempts (const SocketSYN_IPState *state,
                                              int64_t now_ms,
                                              int window_ms);
static void apply_score_decay (SocketSYN_IPState *state,
                               const SocketSYNProtect_Config *config,
                               int64_t elapsed_ms);
static void
update_reputation_from_score (SocketSYN_IPState *state,
                              const SocketSYNProtect_Config *config);
static void penalize_attempt (SocketSYN_IPState *state,
                              const SocketSYNProtect_Config *config);
static void penalize_failure (SocketSYN_IPState *state,
                              const SocketSYNProtect_Config *config);
static void reward_success (SocketSYN_IPState *state,
                            const SocketSYNProtect_Config *config);
static int
is_currently_blocked (const SocketSYN_IPState *state, int64_t now_ms);
static SocketSYN_Action determine_action (const SocketSYN_IPState *state,
                                          const SocketSYNProtect_Config *config,
                                          uint32_t effective_attempts,
                                          int64_t now_ms);
static SocketSYN_Action
process_ip_attempt (T protect, SocketSYN_IPEntry *entry, int64_t now_ms);
static SocketSYN_Action process_tracked_ip (T protect,
                                            const char *client_ip,
                                            int64_t now_ms,
                                            SocketSYN_IPState *state_out);
static void fill_ip_state_out (SocketSYN_IPState *state_out,
                               const char *ip,
                               SocketSYN_Reputation rep,
                               float score);
static void handle_whitelisted_ip (T protect,
                                   const char *client_ip,
                                   SocketSYN_IPState *state_out);
static void handle_blacklisted_ip (T protect,
                                   const char *client_ip,
                                   SocketSYN_IPState *state_out);
static void update_action_stats (T protect, SocketSYN_Action action);
static int check_global_rate_limit (T protect);
static int check_whitelist_blacklist (T protect,
                                      const char *client_ip,
                                      int64_t now_ms,
                                      SocketSYN_IPState *state_out,
                                      SocketSYN_Action *action_out);
static void cleanup_expired_ip_blocks (T protect, int64_t now_ms);
static size_t count_currently_blocked (T protect, int64_t now_ms);
static void *alloc_zeroed (T protect, size_t count, size_t size);

#endif /* SOCKETSYNPROTECT_PRIVATE_INCLUDED */

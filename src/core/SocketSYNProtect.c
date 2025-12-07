/**
 * SocketSYNProtect.c - SYN Flood Protection Implementation
 *
 * Part of the Socket Library
 *
 * Implements comprehensive SYN flood protection with:
 * - Sliding window connection attempt tracking
 * - Adaptive IP reputation scoring
 * - Hash table with LRU eviction for bounded memory
 * - Whitelist/blacklist with CIDR support
 * - Thread-safe operations
 */

#include "core/SocketSYNProtect.h"
#include "core/SocketSYNProtect-private.h"


#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include "core/SocketMetrics.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "core/SocketCrypto.h"

#define T SocketSYNProtect_T

/* ============================================================================
 * Exception Definitions
 * ============================================================================ */

const Except_T SocketSYNProtect_Failed
    = { &SocketSYNProtect_Failed, "SYN protection operation failed" };

/* Thread-local exception using centralized macro */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketSYNProtect);

/* ============================================================================
 * Static String Tables
 * ============================================================================ */

static const char *const action_names[] = { "ALLOW", "THROTTLE", "CHALLENGE",
                                            "BLOCK" };

static const char *const reputation_names[]
    = { "TRUSTED", "NEUTRAL", "SUSPECT", "HOSTILE" };

#define ACTION_NAMES_COUNT (sizeof (action_names) / sizeof (action_names[0]))
#define REPUTATION_NAMES_COUNT                                                 \
  (sizeof (reputation_names) / sizeof (reputation_names[0]))

/* ============================================================================
 * Internal Helper Functions - String Utilities
 * ============================================================================ */

/**
 * safe_copy_ip - Safely copy IP string with null termination
 * @dest: Destination buffer (must be at least SOCKET_IP_MAX_LEN bytes)
 * @src: Source IP string
 */
static void
safe_copy_ip (char *dest, const char *src)
{
  strncpy (dest, src, SOCKET_IP_MAX_LEN - 1);
  dest[SOCKET_IP_MAX_LEN - 1] = '\0';
}

/* ============================================================================
 * Internal Helper Functions - Memory Allocation
 * ============================================================================ */

/**
 * alloc_zeroed - Allocate zeroed memory from arena or heap
 * @protect: Protection instance
 * @count: Number of elements
 * @size: Size of each element
 *
 * Returns: Pointer to zeroed memory, or NULL on failure
 */
static void *
alloc_zeroed (T protect, size_t count, size_t size)
{
  if (protect->arena != NULL)
    return Arena_calloc (protect->arena, count, size, __FILE__, __LINE__);
  return calloc (count, size);
}

/**
 * free_memory - Free heap-allocated memory (no-op for arena)
 * @protect: Protection instance
 * @ptr: Pointer to free
 */
static void
free_memory (T protect, void *ptr)
{
  if (protect->use_malloc && ptr != NULL)
    free (ptr);
}

/* ============================================================================
 * Internal Helper Functions - LRU List Operations
 * ============================================================================ */

/**
 * lru_remove - Remove entry from LRU list
 * @protect: Protection instance (must hold mutex)
 * @entry: Entry to remove
 */
static void
lru_remove (T protect, SocketSYN_IPEntry *entry)
{
  if (entry->lru_prev != NULL)
    entry->lru_prev->lru_next = entry->lru_next;
  else
    protect->lru_head = entry->lru_next;

  if (entry->lru_next != NULL)
    entry->lru_next->lru_prev = entry->lru_prev;
  else
    protect->lru_tail = entry->lru_prev;

  entry->lru_prev = NULL;
  entry->lru_next = NULL;
}

/**
 * lru_push_front - Move entry to front of LRU list (most recently used)
 * @protect: Protection instance (must hold mutex)
 * @entry: Entry to move
 */
static void
lru_push_front (T protect, SocketSYN_IPEntry *entry)
{
  entry->lru_prev = NULL;
  entry->lru_next = protect->lru_head;

  if (protect->lru_head != NULL)
    protect->lru_head->lru_prev = entry;
  else
    protect->lru_tail = entry;

  protect->lru_head = entry;
}

/**
 * lru_touch - Mark entry as recently used
 * @protect: Protection instance (must hold mutex)
 * @entry: Entry to touch
 */
static void
lru_touch (T protect, SocketSYN_IPEntry *entry)
{
  if (entry != protect->lru_head)
    {
      lru_remove (protect, entry);
      lru_push_front (protect, entry);
    }
}

/* ============================================================================
 * Internal Helper Functions - IP Entry Management
 * ============================================================================ */

/**
 * find_ip_entry - Find IP entry in hash table
 * @protect: Protection instance (must hold mutex)
 * @ip: IP address string
 *
 * Returns: Entry pointer or NULL if not found
 */
static SocketSYN_IPEntry *
find_ip_entry (T protect, const char *ip)
{
  unsigned bucket = synprotect_hash_ip (protect, ip, protect->ip_table_size);
  SocketSYN_IPEntry *entry = protect->ip_table[bucket];

  while (entry != NULL)
    {
      if (strcmp (entry->state.ip, ip) == 0)
        return entry;
      entry = entry->hash_next;
    }

  return NULL;
}

/**
 * remove_ip_entry_from_hash - Remove entry from hash table
 * @protect: Protection instance (must hold mutex)
 * @entry: Entry to remove
 */
static void
remove_ip_entry_from_hash (T protect, SocketSYN_IPEntry *entry)
{
  unsigned bucket
      = synprotect_hash_ip (protect, entry->state.ip, protect->ip_table_size);
  SocketSYN_IPEntry **pp = &protect->ip_table[bucket];

  while (*pp != NULL)
    {
      if (*pp == entry)
        {
          *pp = entry->hash_next;
          break;
        }
      pp = &(*pp)->hash_next;
    }
}

/**
 * evict_lru_entry - Evict least recently used entry
 * @protect: Protection instance (must hold mutex)
 */
static void
evict_lru_entry (T protect)
{
  SocketSYN_IPEntry *victim = protect->lru_tail;
  if (victim == NULL)
    return;

  remove_ip_entry_from_hash (protect, victim);
  lru_remove (protect, victim);
  free_memory (protect, victim);

  protect->ip_entry_count--;
  SocketMetrics_gauge_set(SOCKET_GAU_SYNPROTECT_TRACKED_IPS, protect->ip_entry_count);
  atomic_fetch_add (&protect->stat_lru_evictions, 1);
  SocketMetrics_counter_inc(SOCKET_CTR_SYNPROTECT_LRU_EVICTIONS);
}

/**
 * init_ip_state - Initialize IP state with defaults
 * @state: State to initialize
 * @ip: IP address string
 * @now_ms: Current timestamp
 */
static void
init_ip_state (SocketSYN_IPState *state, const char *ip, int64_t now_ms)
{
  memset (state, 0, sizeof (*state));
  safe_copy_ip (state->ip, ip);
  state->window_start_ms = now_ms;
  state->last_attempt_ms = now_ms;
  state->rep = SYN_REP_NEUTRAL;
  state->score = SOCKET_SYN_INITIAL_SCORE;
}

/**
 * create_ip_entry - Create new IP entry
 * @protect: Protection instance (must hold mutex)
 * @ip: IP address string
 * @now_ms: Current timestamp
 *
 * Returns: New entry or NULL on allocation failure
 */
static SocketSYN_IPEntry *
create_ip_entry (T protect, const char *ip, int64_t now_ms)
{
  SocketSYN_IPEntry *entry;
  unsigned bucket;

  while (protect->use_malloc && protect->ip_entry_count >= protect->config.max_tracked_ips)
    evict_lru_entry (protect);

  if (protect->ip_entry_count >= protect->config.max_tracked_ips)
    return NULL;  // Still full, can't add more (arena mode or alloc would evict but limit reached)

  entry = alloc_zeroed (protect, 1, sizeof (*entry));
  if (entry == NULL)
    return NULL;

  init_ip_state (&entry->state, ip, now_ms);

  bucket = synprotect_hash_ip (protect, ip, protect->ip_table_size);
  entry->hash_next = protect->ip_table[bucket];
  protect->ip_table[bucket] = entry;

  lru_push_front (protect, entry);
  protect->ip_entry_count++;
  SocketMetrics_gauge_set(SOCKET_GAU_SYNPROTECT_TRACKED_IPS, protect->ip_entry_count);

  return entry;
}

/**
 * get_or_create_ip_entry - Get existing or create new IP entry
 * @protect: Protection instance (must hold mutex)
 * @ip: IP address string
 * @now_ms: Current timestamp
 *
 * Returns: Entry pointer or NULL on allocation failure
 */
static SocketSYN_IPEntry *
get_or_create_ip_entry (T protect, const char *ip, int64_t now_ms)
{
  SocketSYN_IPEntry *entry = find_ip_entry (protect, ip);
  if (entry != NULL)
    {
      lru_touch (protect, entry);
      return entry;
    }
  return create_ip_entry (protect, ip, now_ms);
}

/* ============================================================================
 * Internal Helper Functions - Sliding Window
 * ============================================================================ */

/**
 * rotate_window_if_needed - Rotate sliding window if expired
 * @state: IP state to update
 * @now_ms: Current timestamp
 * @window_ms: Window duration
 */
static void
rotate_window_if_needed (SocketSYN_IPState *state, int64_t now_ms,
                         int window_ms)
{
  int64_t elapsed = now_ms - state->window_start_ms;

  if (elapsed >= window_ms)
    {
      state->attempts_previous = state->attempts_current;
      state->attempts_current = 0;
      state->window_start_ms = now_ms;
    }
}

/**
 * calculate_window_progress - Calculate progress through current window
 * @elapsed: Time elapsed since window start
 * @window_ms: Window duration
 *
 * Returns: Progress as float (0.0 = start, 1.0 = end)
 */
static float
calculate_window_progress (int64_t elapsed, int window_ms)
{
  if (elapsed < 0)
    elapsed = 0;
  if (elapsed > window_ms)
    elapsed = window_ms;

  return (float)elapsed / (float)window_ms;
}

/**
 * synprotect_hash_ip - Hash IP address string with instance-specific seed
 * @protect: Protection instance (provides hash_seed)
 * @ip: IP address string
 * @table_size: Hash table size
 *
 * Returns: Bucket index, seeded for collision resistance
 */
unsigned
synprotect_hash_ip (T protect, const char *ip, unsigned table_size)
{
  unsigned h = socket_util_hash_djb2 (ip, table_size);
  h ^= protect->hash_seed;
  h = socket_util_hash_uint (h, table_size);
  return h % table_size;
}

/**
 * calculate_effective_attempts - Calculate weighted attempt count
 * @state: IP state
 * @now_ms: Current timestamp
 * @window_ms: Window duration
 *
 * Returns: Weighted attempt count using linear interpolation
 */
static uint32_t
calculate_effective_attempts (const SocketSYN_IPState *state, int64_t now_ms,
                              int window_ms)
{
  float progress, previous_weight;

  if (window_ms <= 0)
    return state->attempts_current;

  progress
      = calculate_window_progress (now_ms - state->window_start_ms, window_ms);
  previous_weight = 1.0f - progress;

  return state->attempts_current
         + (uint32_t) (state->attempts_previous * previous_weight);
}

/* ============================================================================
 * Internal Helper Functions - Reputation Scoring
 * ============================================================================ */

/**
 * apply_score_decay - Apply time-based score recovery
 * @state: IP state to update
 * @config: Configuration
 * @elapsed_ms: Time elapsed since last update
 */
static void
apply_score_decay (SocketSYN_IPState *state,
                   const SocketSYNProtect_Config *config, int64_t elapsed_ms)
{
  float decay;

  if (elapsed_ms <= 0 || config->score_decay_per_sec <= 0.0f)
    return;

  decay = ((float)elapsed_ms / (float)SOCKET_MS_PER_SECOND)
          * config->score_decay_per_sec;
  state->score = synprotect_clamp_score (state->score + decay);
}

/**
 * update_reputation_from_score - Update reputation enum based on score
 * @state: IP state to update
 * @config: Configuration with score thresholds
 */
static void
update_reputation_from_score (SocketSYN_IPState *state,
                              const SocketSYNProtect_Config *config)
{
  if (state->score >= SOCKET_SYN_TRUSTED_SCORE_THRESHOLD)
    state->rep = SYN_REP_TRUSTED;
  else if (state->score >= config->score_throttle)
    state->rep = SYN_REP_NEUTRAL;
  else if (state->score >= config->score_block)
    state->rep = SYN_REP_SUSPECT;
  else
    state->rep = SYN_REP_HOSTILE;
}

/**
 * penalize_attempt - Apply score penalty for new attempt
 * @state: IP state to update
 * @config: Configuration
 */
static void
penalize_attempt (SocketSYN_IPState *state,
                  const SocketSYNProtect_Config *config)
{
  state->score
      = synprotect_clamp_score (state->score - config->score_penalty_attempt);
  update_reputation_from_score (state, config);
}

/**
 * penalize_failure - Apply score penalty for failure
 * @state: IP state to update
 * @config: Configuration
 */
static void
penalize_failure (SocketSYN_IPState *state,
                  const SocketSYNProtect_Config *config)
{
  state->score
      = synprotect_clamp_score (state->score - config->score_penalty_failure);
  state->failures++;
  update_reputation_from_score (state, config);
}

/**
 * reward_success - Apply score reward for success
 * @state: IP state to update
 * @config: Configuration
 */
static void
reward_success (SocketSYN_IPState *state,
                const SocketSYNProtect_Config *config)
{
  state->score
      = synprotect_clamp_score (state->score + config->score_reward_success);
  state->successes++;
  update_reputation_from_score (state, config);
}

/* ============================================================================
 * Internal Helper Functions - Action Determination
 * ============================================================================ */

/**
 * is_currently_blocked - Check if IP is currently blocked
 * @state: IP state
 * @now_ms: Current timestamp
 *
 * Returns: 1 if blocked, 0 otherwise
 */
static int
is_currently_blocked (const SocketSYN_IPState *state, int64_t now_ms)
{
  return (state->block_until_ms > 0 && now_ms < state->block_until_ms);
}

/**
 * determine_action - Determine action based on IP state
 * @state: IP state
 * @config: Configuration
 * @effective_attempts: Weighted attempt count
 * @now_ms: Current timestamp
 *
 * Returns: Action to take
 */
static SocketSYN_Action
determine_action (const SocketSYN_IPState *state,
                  const SocketSYNProtect_Config *config,
                  uint32_t effective_attempts, int64_t now_ms)
{
  if (is_currently_blocked (state, now_ms))
    return SYN_ACTION_BLOCK;

  if ((int)effective_attempts > config->max_attempts_per_window)
    return SYN_ACTION_BLOCK;

  if (state->score < config->score_block)
    return SYN_ACTION_BLOCK;

  if (state->score < config->score_challenge)
    return SYN_ACTION_CHALLENGE;

  if (state->score < config->score_throttle)
    return SYN_ACTION_THROTTLE;

  return SYN_ACTION_ALLOW;
}

/* ============================================================================
 * Internal Helper Functions - IP Address Parsing
 * ============================================================================ */

/**
 * parse_ipv4_address - Parse IPv4 address to bytes
 * @ip: IP address string
 * @addr_bytes: Output buffer (at least SOCKET_IPV4_ADDR_BYTES)
 *
 * Returns: 1 on success, 0 on failure
 */
static int
parse_ipv4_address (const char *ip, uint8_t *addr_bytes)
{
  struct in_addr addr4;

  if (inet_pton (AF_INET, ip, &addr4) == 1)
    {
      memset (addr_bytes, 0, SOCKET_IPV6_ADDR_BYTES);
      memcpy (addr_bytes, &addr4.s_addr, SOCKET_IPV4_ADDR_BYTES);
      return 1;
    }
  return 0;
}

/**
 * parse_ipv6_address - Parse IPv6 address to bytes
 * @ip: IP address string
 * @addr_bytes: Output buffer (at least SOCKET_IPV6_ADDR_BYTES)
 *
 * Returns: 1 on success, 0 on failure
 */
static int
parse_ipv6_address (const char *ip, uint8_t *addr_bytes)
{
  struct in6_addr addr6;

  if (inet_pton (AF_INET6, ip, &addr6) == 1)
    {
      memcpy (addr_bytes, addr6.s6_addr, SOCKET_IPV6_ADDR_BYTES);
      return 1;
    }
  return 0;
}

/**
 * parse_ip_address - Parse IP address string to bytes
 * @ip: IP address string
 * @addr_bytes: Output buffer (at least SOCKET_IPV6_ADDR_BYTES)
 * @addr_size: Size of output buffer
 *
 * Returns: AF_INET, AF_INET6, or 0 on error
 */
static int
parse_ip_address (const char *ip, uint8_t *addr_bytes, size_t addr_size)
{
  if (addr_size < SOCKET_IPV6_ADDR_BYTES)
    return 0;

  if (parse_ipv4_address (ip, addr_bytes))
    return AF_INET;

  if (parse_ipv6_address (ip, addr_bytes))
    return AF_INET6;

  return 0;
}

/* ============================================================================
 * Internal Helper Functions - CIDR Matching
 * ============================================================================ */

/**
 * cidr_full_bytes_match - Compare full bytes of addresses
 * @ip_bytes: IP address bytes
 * @entry_bytes: CIDR entry bytes
 * @bytes: Number of bytes to compare
 *
 * Returns: 1 if match, 0 otherwise
 */
static int
cidr_full_bytes_match (const uint8_t *ip_bytes, const uint8_t *entry_bytes,
                       int bytes)
{
  return (memcmp (ip_bytes, entry_bytes, (size_t)bytes) == 0);
}

/**
 * cidr_partial_byte_match - Compare partial byte with mask
 * @ip_bytes: IP address bytes
 * @entry_bytes: CIDR entry bytes
 * @byte_index: Index of byte to compare
 * @remaining_bits: Number of bits to compare
 *
 * Returns: 1 if match, 0 otherwise
 */
static int
cidr_partial_byte_match (const uint8_t *ip_bytes, const uint8_t *entry_bytes,
                         int byte_index, int remaining_bits)
{
  uint8_t mask = (uint8_t) (0xFF << (SOCKET_BITS_PER_BYTE - remaining_bits));
  return ((ip_bytes[byte_index] & mask) == (entry_bytes[byte_index] & mask));
}

/**
 * ip_matches_cidr - Check if IP matches CIDR entry
 * @ip: IP address string
 * @entry: Whitelist entry with CIDR
 *
 * Returns: 1 if match, 0 otherwise
 */
static int
ip_matches_cidr_bytes (int family, const uint8_t *ip_bytes, const SocketSYN_WhitelistEntry *entry)
{
  int bits, bytes_to_match, remaining_bits;

  if (family != entry->addr_family)
    return 0;

  bits = entry->prefix_len;
  bytes_to_match = bits / SOCKET_BITS_PER_BYTE;
  remaining_bits = bits % SOCKET_BITS_PER_BYTE;

  if (!cidr_full_bytes_match (ip_bytes, entry->addr_bytes, bytes_to_match))
    return 0;

  if (remaining_bits != 0)
    return cidr_partial_byte_match (ip_bytes, entry->addr_bytes, bytes_to_match,
                                    remaining_bits);

  return 1;
}

/**
 * ip_matches_cidr - Check if IP matches CIDR entry
 * @ip: IP address string
 * @entry: Whitelist entry with CIDR
 *
 * Returns: 1 if match, 0 otherwise
 * Note: Avoid in loops; use ip_matches_cidr_bytes for efficiency
 */
static int
ip_matches_cidr (const char *ip, const SocketSYN_WhitelistEntry *entry)
{
  uint8_t ip_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family = parse_ip_address (ip, ip_bytes, sizeof (ip_bytes));
  if (family == 0)
    return 0;
  return ip_matches_cidr_bytes (family, ip_bytes, entry);
}

/* ============================================================================
 * Internal Helper Functions - Whitelist
 * ============================================================================ */

/**
 * whitelist_check_bucket - Check single bucket for IP match
 * @entry: First entry in bucket chain
 * @ip: IP address to check
 *
 * Returns: 1 if found, 0 otherwise
 */
static int
whitelist_check_bucket_bytes (const SocketSYN_WhitelistEntry *entry, const char *ip_str,
                              int family, const uint8_t *ip_bytes)
{
  while (entry != NULL)
    {
      if (entry->is_cidr)
        {
          if (entry->addr_family == family &&
              ip_matches_cidr_bytes (family, ip_bytes, entry))
            return 1;
        }
      else
        {
          if (strcmp (entry->ip, ip_str) == 0)
            return 1;
        }
      entry = entry->next;
    }
  return 0;
}

static int
whitelist_check_bucket (const SocketSYN_WhitelistEntry *entry, const char *ip)
{
  uint8_t ip_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family = parse_ip_address (ip, ip_bytes, sizeof (ip_bytes));
  return whitelist_check_bucket_bytes (entry, ip, family, ip_bytes);
}

/**
 * whitelist_check_all_cidrs - Check all buckets for CIDR match
 * @protect: Protection instance (must hold mutex)
 * @ip: IP address to check
 * @skip_bucket: Bucket to skip (already checked)
 *
 * Returns: 1 if found, 0 otherwise
 */
static int
whitelist_check_all_cidrs_bytes (T protect, int family, const uint8_t *ip_bytes, unsigned skip_bucket)
{
  for (size_t i = 0; i < SOCKET_SYN_LIST_HASH_SIZE; i++)
    {
      if (i == skip_bucket)
        continue;

      const SocketSYN_WhitelistEntry *entry = protect->whitelist_table[i];
      while (entry != NULL)
        {
          if (entry->is_cidr && entry->addr_family == family &&
              ip_matches_cidr_bytes (family, ip_bytes, entry))
            return 1;
          entry = entry->next;
        }
    }
  return 0;
}

static int
whitelist_check_all_cidrs (T protect, const char *ip, unsigned skip_bucket)
{
  uint8_t ip_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family = parse_ip_address (ip, ip_bytes, sizeof (ip_bytes));
  if (family == 0)
    return 0;
  return whitelist_check_all_cidrs_bytes (protect, family, ip_bytes, skip_bucket);
}

/**
 * whitelist_check - Check if IP is whitelisted
 * @protect: Protection instance (must hold mutex)
 * @ip: IP address to check
 *
 * Returns: 1 if whitelisted, 0 otherwise
 */
static int
whitelist_check (T protect, const char *ip)
{
  unsigned bucket;
  uint8_t ip_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  if (protect->whitelist_count == 0)
    return 0;

  family = parse_ip_address (ip, ip_bytes, sizeof (ip_bytes));
  // If invalid IP, can't be whitelisted
  if (family == 0)
    return 0;

  bucket = synprotect_hash_ip (protect, ip, SOCKET_SYN_LIST_HASH_SIZE);

  if (whitelist_check_bucket_bytes (protect->whitelist_table[bucket], ip, family, ip_bytes))
    return 1;

  return whitelist_check_all_cidrs_bytes (protect, family, ip_bytes, bucket);
}

/* ============================================================================
 * Internal Helper Functions - Blacklist
 * ============================================================================ */

/**
 * blacklist_check - Check if IP is blacklisted
 * @protect: Protection instance (must hold mutex)
 * @ip: IP address to check
 * @now_ms: Current timestamp
 *
 * Returns: 1 if blacklisted and not expired, 0 otherwise
 */
static int
blacklist_check (T protect, const char *ip, int64_t now_ms)
{
  unsigned bucket;
  const SocketSYN_BlacklistEntry *entry;

  if (protect->blacklist_count == 0)
    return 0;

  bucket = synprotect_hash_ip (protect, ip, SOCKET_SYN_LIST_HASH_SIZE);
  entry = protect->blacklist_table[bucket];

  while (entry != NULL)
    {
      if (strcmp (entry->ip, ip) == 0)
        {
          if (entry->expires_ms == 0 || entry->expires_ms > now_ms)
            return 1;
        }
      entry = entry->next;
    }

  return 0;
}

/* ============================================================================
 * Internal Helper Functions - Check Processing
 * ============================================================================ */

/**
 * fill_ip_state_out - Fill state_out with IP state
 * @state_out: Output state structure (may be NULL)
 * @ip: IP address string
 * @rep: Reputation to set
 * @score: Score to set
 */
static void
fill_ip_state_out (SocketSYN_IPState *state_out, const char *ip,
                   SocketSYN_Reputation rep, float score)
{
  if (state_out == NULL)
    return;

  memset (state_out, 0, sizeof (*state_out));
  safe_copy_ip (state_out->ip, ip);
  state_out->rep = rep;
  state_out->score = score;
}

/**
 * handle_whitelisted_ip - Handle whitelisted IP
 * @protect: Protection instance
 * @client_ip: Client IP address
 * @state_out: Output state (optional)
 */
static void
handle_whitelisted_ip (T protect, const char *client_ip,
                       SocketSYN_IPState *state_out)
{
  atomic_fetch_add (&protect->stat_whitelisted, 1);
  SocketMetrics_counter_inc(SOCKET_CTR_SYNPROTECT_WHITELISTED);
  atomic_fetch_add (&protect->stat_allowed, 1);
  SocketMetrics_counter_inc(SOCKET_CTR_SYNPROTECT_ALLOWED);
  fill_ip_state_out (state_out, client_ip, SYN_REP_TRUSTED,
                     SOCKET_SYN_TRUSTED_SCORE);
}

/**
 * handle_blacklisted_ip - Handle blacklisted IP
 * @protect: Protection instance
 * @client_ip: Client IP address
 * @state_out: Output state (optional)
 */
static void
handle_blacklisted_ip (T protect, const char *client_ip,
                       SocketSYN_IPState *state_out)
{
  atomic_fetch_add (&protect->stat_blacklisted, 1);
  SocketMetrics_counter_inc(SOCKET_CTR_SYNPROTECT_BLACKLISTED);
  atomic_fetch_add (&protect->stat_blocked, 1);
  SocketMetrics_counter_inc(SOCKET_CTR_SYNPROTECT_BLOCKED);
  fill_ip_state_out (state_out, client_ip, SYN_REP_HOSTILE, 0.0f);
}

/**
 * update_action_stats - Update statistics based on action
 * @protect: Protection instance
 * @action: Action taken
 */
static void
update_action_stats (T protect, SocketSYN_Action action)
{
  switch (action)
    {
    case SYN_ACTION_ALLOW:
      atomic_fetch_add (&protect->stat_allowed, 1);
      SocketMetrics_counter_inc(SOCKET_CTR_SYNPROTECT_ALLOWED);
      break;
    case SYN_ACTION_THROTTLE:
      atomic_fetch_add (&protect->stat_throttled, 1);
      SocketMetrics_counter_inc(SOCKET_CTR_SYNPROTECT_THROTTLED);
      break;
    case SYN_ACTION_CHALLENGE:
      atomic_fetch_add (&protect->stat_challenged, 1);
      SocketMetrics_counter_inc(SOCKET_CTR_SYNPROTECT_CHALLENGED);
      break;
    case SYN_ACTION_BLOCK:
      atomic_fetch_add (&protect->stat_blocked, 1);
      SocketMetrics_counter_inc(SOCKET_CTR_SYNPROTECT_BLOCKED);
      break;
    }
}

/**
 * process_ip_attempt - Process an attempt from an IP
 * @protect: Protection instance (must hold mutex)
 * @entry: IP entry
 * @now_ms: Current timestamp
 *
 * Returns: Action to take
 */
static SocketSYN_Action
process_ip_attempt (T protect, SocketSYN_IPEntry *entry, int64_t now_ms)
{
  SocketSYN_Action action;
  uint32_t effective_attempts;

  apply_score_decay (&entry->state, &protect->config,
                     now_ms - entry->state.last_attempt_ms);

  rotate_window_if_needed (&entry->state, now_ms,
                           protect->config.window_duration_ms);

  entry->state.attempts_current++;
  entry->state.last_attempt_ms = now_ms;

  penalize_attempt (&entry->state, &protect->config);

  effective_attempts = calculate_effective_attempts (
      &entry->state, now_ms, protect->config.window_duration_ms);

  action = determine_action (&entry->state, &protect->config,
                             effective_attempts, now_ms);

  if (action == SYN_ACTION_BLOCK && entry->state.block_until_ms == 0)
    {
      entry->state.block_until_ms = now_ms + protect->config.block_duration_ms;
      SocketMetrics_gauge_inc(SOCKET_GAU_SYNPROTECT_BLOCKED_IPS);
    }

  return action;
}

/**
 * check_whitelist_blacklist - Check whitelist and blacklist for IP
 * @protect: Protection instance (must hold mutex)
 * @client_ip: Client IP address
 * @now_ms: Current timestamp
 * @state_out: Output state (optional)
 * @action_out: Output action if IP is in whitelist/blacklist
 *
 * Returns: 1 if IP found in whitelist/blacklist, 0 otherwise
 */
static int
check_whitelist_blacklist (T protect, const char *client_ip, int64_t now_ms,
                           SocketSYN_IPState *state_out,
                           SocketSYN_Action *action_out)
{
  if (whitelist_check (protect, client_ip))
    {
      handle_whitelisted_ip (protect, client_ip, state_out);
      *action_out = SYN_ACTION_ALLOW;
      return 1;
    }

  if (blacklist_check (protect, client_ip, now_ms))
    {
      handle_blacklisted_ip (protect, client_ip, state_out);
      *action_out = SYN_ACTION_BLOCK;
      return 1;
    }

  return 0;
}

/* ============================================================================
 * Internal Helper Functions - Initialization Cleanup
 * ============================================================================ */

/**
 * Cleanup stages for SocketSYNProtect_new() error handling
 */
typedef enum
{
  SYN_CLEANUP_NONE = 0,
  SYN_CLEANUP_MUTEX,
  SYN_CLEANUP_IP_TABLE,
  SYN_CLEANUP_WHITELIST,
  SYN_CLEANUP_BLACKLIST,
  SYN_CLEANUP_LIMITER
} SYN_CleanupStage;

/**
 * cleanup_synprotect_init - Clean up partially initialized SYN protection
 * @protect: Protection instance to clean up
 * @stage: Stage reached before failure
 */
static void
cleanup_synprotect_init (T protect, SYN_CleanupStage stage)
{
  switch (stage)
    {
    case SYN_CLEANUP_LIMITER:
      if (protect->global_limiter != NULL)
        SocketRateLimit_free (&protect->global_limiter);
      /* FALLTHROUGH */
    case SYN_CLEANUP_BLACKLIST:
      free_memory (protect, protect->blacklist_table);
      /* FALLTHROUGH */
    case SYN_CLEANUP_WHITELIST:
      free_memory (protect, protect->whitelist_table);
      /* FALLTHROUGH */
    case SYN_CLEANUP_IP_TABLE:
      free_memory (protect, protect->ip_table);
      /* FALLTHROUGH */
    case SYN_CLEANUP_MUTEX:
      pthread_mutex_destroy (&protect->mutex);
      /* FALLTHROUGH */
    case SYN_CLEANUP_NONE:
      if (protect->use_malloc)
        free (protect);
      break;
    }
}

/* ============================================================================
 * Internal Helper Functions - Initialization
 * ============================================================================ */

/**
 * init_ip_hash_table - Initialize IP hash table
 * @protect: Protection instance
 *
 * Returns: 1 on success, 0 on failure
 */
static int
init_ip_hash_table (T protect)
{
  protect->ip_table_size = SOCKET_SYN_IP_HASH_SIZE;
  protect->ip_table = alloc_zeroed (protect, protect->ip_table_size,
                                    sizeof (SocketSYN_IPEntry *));
  return (protect->ip_table != NULL);
}

/**
 * init_whitelist_table - Initialize whitelist hash table
 * @protect: Protection instance
 *
 * Returns: 1 on success, 0 on failure
 */
static int
init_whitelist_table (T protect)
{
  protect->whitelist_table = alloc_zeroed (protect, SOCKET_SYN_LIST_HASH_SIZE,
                                           sizeof (SocketSYN_WhitelistEntry *));
  return (protect->whitelist_table != NULL);
}

/**
 * init_blacklist_table - Initialize blacklist hash table
 * @protect: Protection instance
 *
 * Returns: 1 on success, 0 on failure
 */
static int
init_blacklist_table (T protect)
{
  protect->blacklist_table = alloc_zeroed (protect, SOCKET_SYN_LIST_HASH_SIZE,
                                           sizeof (SocketSYN_BlacklistEntry *));
  return (protect->blacklist_table != NULL);
}

/**
 * init_global_limiter - Initialize global rate limiter
 * @protect: Protection instance
 * @config: Configuration
 *
 * Returns: 1 on success, 0 on failure
 */
static int
init_global_limiter (T protect, const SocketSYNProtect_Config *config)
{
  TRY
    protect->global_limiter
        = SocketRateLimit_new (protect->arena,
                               (size_t)config->max_global_per_second,
                               (size_t)config->max_global_per_second);
  EXCEPT (SocketRateLimit_Failed)
    return 0;
  END_TRY;
  return 1;
}

/**
 * init_atomic_stats - Initialize atomic statistics counters
 * @protect: Protection instance
 */
static void
init_atomic_stats (T protect)
{
  atomic_store (&protect->stat_attempts, 0);
  atomic_store (&protect->stat_allowed, 0);
  atomic_store (&protect->stat_throttled, 0);
  atomic_store (&protect->stat_challenged, 0);
  atomic_store (&protect->stat_blocked, 0);
  atomic_store (&protect->stat_whitelisted, 0);
  atomic_store (&protect->stat_blacklisted, 0);
  atomic_store (&protect->stat_lru_evictions, 0);
}

/* ============================================================================
 * Internal Helper Functions - Cleanup
 * ============================================================================ */

/**
 * free_ip_entries - Free all IP entries (malloc mode only)
 * @protect: Protection instance
 */
static void
free_ip_entries (T protect)
{
  for (size_t i = 0; i < protect->ip_table_size; i++)
    {
      SocketSYN_IPEntry *entry = protect->ip_table[i];
      while (entry != NULL)
        {
          SocketSYN_IPEntry *next = entry->hash_next;
          free (entry);
          entry = next;
        }
    }
}

/**
 * free_whitelist_entries - Free all whitelist entries (malloc mode only)
 * @protect: Protection instance
 */
static void
free_whitelist_entries (T protect)
{
  for (size_t i = 0; i < SOCKET_SYN_LIST_HASH_SIZE; i++)
    {
      SocketSYN_WhitelistEntry *entry = protect->whitelist_table[i];
      while (entry != NULL)
        {
          SocketSYN_WhitelistEntry *next = entry->next;
          free (entry);
          entry = next;
        }
    }
}

/**
 * free_blacklist_entries - Free all blacklist entries (malloc mode only)
 * @protect: Protection instance
 */
static void
free_blacklist_entries (T protect)
{
  for (size_t i = 0; i < SOCKET_SYN_LIST_HASH_SIZE; i++)
    {
      SocketSYN_BlacklistEntry *entry = protect->blacklist_table[i];
      while (entry != NULL)
        {
          SocketSYN_BlacklistEntry *next = entry->next;
          free (entry);
          entry = next;
        }
    }
}

/* ============================================================================
 * Internal Helper Functions - CIDR Parsing
 * ============================================================================ */

/**
 * parse_cidr_notation - Parse CIDR string into components
 * @cidr: CIDR notation string (e.g., "10.0.0.0/8")
 * @ip_out: Output buffer for IP part
 * @ip_out_size: Size of output buffer
 * @prefix_out: Output for prefix length
 *
 * Returns: 1 on success, 0 on failure
 */
static int
parse_cidr_notation (const char *cidr, char *ip_out, size_t ip_out_size,
                     int *prefix_out)
{
  const char *slash = strchr (cidr, '/');
  size_t ip_len;

  if (slash == NULL)
    return 0;

  ip_len = (size_t) (slash - cidr);
  if (ip_len >= ip_out_size)
    return 0;

  memcpy (ip_out, cidr, ip_len);
  ip_out[ip_len] = '\0';

  const char *prefix_str = slash + 1;
  char *endptr;
  long prefix_long = strtol(prefix_str, &endptr, 10);
  if (prefix_str == endptr || *endptr != '\0' || errno == ERANGE ||
      prefix_long < 0 || prefix_long > SOCKET_IPV6_MAX_PREFIX) {
    return 0;
  }
  *prefix_out = (int)prefix_long;

  return 1;
}

/* ============================================================================
 * Internal Helper Functions - Whitelist/Blacklist Common Operations
 * ============================================================================ */

/**
 * find_whitelist_entry_exact - Find exact IP match in whitelist bucket
 * @bucket_head: First entry in bucket
 * @ip: IP address to find
 *
 * Returns: Entry if found (exact, non-CIDR match), NULL otherwise
 */
static SocketSYN_WhitelistEntry *
find_whitelist_entry_exact (SocketSYN_WhitelistEntry *bucket_head,
                            const char *ip)
{
  SocketSYN_WhitelistEntry *entry = bucket_head;
  while (entry != NULL)
    {
      if (!entry->is_cidr && strcmp (entry->ip, ip) == 0)
        return entry;
      entry = entry->next;
    }
  return NULL;
}

/**
 * find_blacklist_entry - Find IP in blacklist bucket
 * @bucket_head: First entry in bucket
 * @ip: IP address to find
 *
 * Returns: Entry if found, NULL otherwise
 */
static SocketSYN_BlacklistEntry *
find_blacklist_entry (SocketSYN_BlacklistEntry *bucket_head, const char *ip)
{
  SocketSYN_BlacklistEntry *entry = bucket_head;
  while (entry != NULL)
    {
      if (strcmp (entry->ip, ip) == 0)
        return entry;
      entry = entry->next;
    }
  return NULL;
}

/**
 * insert_whitelist_entry - Insert entry at bucket head
 * @protect: Protection instance
 * @entry: Entry to insert
 * @bucket: Bucket index
 */
static void
insert_whitelist_entry (T protect, SocketSYN_WhitelistEntry *entry,
                        unsigned bucket)
{
  entry->next = protect->whitelist_table[bucket];
  protect->whitelist_table[bucket] = entry;
  protect->whitelist_count++;
}

/**
 * insert_blacklist_entry - Insert entry at bucket head
 * @protect: Protection instance
 * @entry: Entry to insert
 * @bucket: Bucket index
 */
static void
insert_blacklist_entry (T protect, SocketSYN_BlacklistEntry *entry,
                        unsigned bucket)
{
  entry->next = protect->blacklist_table[bucket];
  protect->blacklist_table[bucket] = entry;
  protect->blacklist_count++;
  SocketMetrics_gauge_inc(SOCKET_GAU_SYNPROTECT_BLOCKED_IPS);
}

/**
 * create_whitelist_entry - Create new whitelist entry
 * @protect: Protection instance
 * @ip: IP or CIDR string
 * @is_cidr: 1 if CIDR, 0 if single IP
 *
 * Returns: New entry or NULL on failure
 */
static SocketSYN_WhitelistEntry *
create_whitelist_entry (T protect, const char *ip, int is_cidr)
{
  SocketSYN_WhitelistEntry *entry;

  entry = alloc_zeroed (protect, 1, sizeof (*entry));
  if (entry == NULL)
    return NULL;

  safe_copy_ip (entry->ip, ip);
  entry->is_cidr = is_cidr;
  return entry;
}

/**
 * create_blacklist_entry - Create new blacklist entry
 * @protect: Protection instance
 * @ip: IP address string
 * @expires_ms: Expiry timestamp (0 = permanent)
 *
 * Returns: New entry or NULL on failure
 */
static SocketSYN_BlacklistEntry *
create_blacklist_entry (T protect, const char *ip, int64_t expires_ms)
{
  SocketSYN_BlacklistEntry *entry;

  entry = alloc_zeroed (protect, 1, sizeof (*entry));
  if (entry == NULL)
    return NULL;

  safe_copy_ip (entry->ip, ip);
  entry->expires_ms = expires_ms;
  return entry;
}

/* ============================================================================
 * Internal Helper Functions - Check Core Logic
 * ============================================================================ */

/**
 * check_global_rate_limit - Check global rate limit
 * @protect: Protection instance
 *
 * Returns: 1 if allowed, 0 if blocked
 */
static int
check_global_rate_limit (T protect)
{
  if (!SocketRateLimit_try_acquire (protect->global_limiter, 1))
    {
      atomic_fetch_add (&protect->stat_blocked, 1);
      return 0;
    }
  return 1;
}

/**
 * process_tracked_ip - Process check for a tracked/new IP
 * @protect: Protection instance (must hold mutex)
 * @client_ip: Client IP address
 * @now_ms: Current timestamp
 * @state_out: Output state (optional)
 *
 * Returns: Action to take
 */
static SocketSYN_Action
process_tracked_ip (T protect, const char *client_ip, int64_t now_ms,
                    SocketSYN_IPState *state_out)
{
  SocketSYN_IPEntry *entry;
  SocketSYN_Action action;

  entry = get_or_create_ip_entry (protect, client_ip, now_ms);
  if (entry == NULL)
    {
      atomic_fetch_add (&protect->stat_allowed, 1);
      return SYN_ACTION_ALLOW;
    }

  action = process_ip_attempt (protect, entry, now_ms);
  update_action_stats (protect, action);

  if (state_out != NULL)
    memcpy (state_out, &entry->state, sizeof (*state_out));

  return action;
}

/* ============================================================================
 * Public API Implementation - Lifecycle
 * ============================================================================ */

void
SocketSYNProtect_config_defaults (SocketSYNProtect_Config *config)
{
  assert (config != NULL);

  memset (config, 0, sizeof (*config));

  config->window_duration_ms = SOCKET_SYN_DEFAULT_WINDOW_MS;
  config->max_attempts_per_window = SOCKET_SYN_DEFAULT_MAX_PER_WINDOW;
  config->max_global_per_second = SOCKET_SYN_DEFAULT_GLOBAL_PER_SEC;
  config->min_success_ratio = SOCKET_SYN_DEFAULT_MIN_SUCCESS_RATIO;

  config->throttle_delay_ms = SOCKET_SYN_DEFAULT_THROTTLE_DELAY_MS;
  config->block_duration_ms = SOCKET_SYN_DEFAULT_BLOCK_DURATION_MS;
  config->challenge_defer_sec = SOCKET_SYN_DEFAULT_DEFER_SEC;

  config->score_throttle = SOCKET_SYN_DEFAULT_SCORE_THROTTLE;
  config->score_challenge = SOCKET_SYN_DEFAULT_SCORE_CHALLENGE;
  config->score_block = SOCKET_SYN_DEFAULT_SCORE_BLOCK;

  config->score_decay_per_sec = SOCKET_SYN_DEFAULT_SCORE_DECAY;
  config->score_penalty_attempt = SOCKET_SYN_DEFAULT_PENALTY_ATTEMPT;
  config->score_penalty_failure = SOCKET_SYN_DEFAULT_PENALTY_FAILURE;
  config->score_reward_success = SOCKET_SYN_DEFAULT_REWARD_SUCCESS;

  config->max_tracked_ips = SOCKET_SYN_DEFAULT_MAX_TRACKED_IPS;
  config->max_whitelist = SOCKET_SYN_DEFAULT_MAX_WHITELIST;
  config->max_blacklist = SOCKET_SYN_DEFAULT_MAX_BLACKLIST;
  config->hash_seed = 0;  /* Auto-generate random seed for hash collision resistance */
}

/**
 * synprotect_get_config - Get or create default config
 * @config: User-provided config (may be NULL)
 * @local_config: Storage for default config if needed
 *
 * Returns: Pointer to config to use
 */
static const SocketSYNProtect_Config *
synprotect_get_config (const SocketSYNProtect_Config *config,
                       SocketSYNProtect_Config *local_config)
{
  if (config == NULL)
    {
      SocketSYNProtect_config_defaults (local_config);
    }
  else
    {
      *local_config = *config;
    }

  // Harden config: Clamp invalid values to prevent misconfig DoS/OOM
  SocketSYNProtect_Config *cfg = local_config;
  if (cfg->window_duration_ms <= 0) cfg->window_duration_ms = SOCKET_SYN_DEFAULT_WINDOW_MS;
  if (cfg->window_duration_ms > 60000) cfg->window_duration_ms = 60000;  // Cap 1min

  if (cfg->max_attempts_per_window <= 0) cfg->max_attempts_per_window = SOCKET_SYN_DEFAULT_MAX_PER_WINDOW;
  if (cfg->max_attempts_per_window > 1000) cfg->max_attempts_per_window = 1000;

  if (cfg->max_global_per_second <= 0) cfg->max_global_per_second = SOCKET_SYN_DEFAULT_GLOBAL_PER_SEC;
  if (cfg->max_global_per_second > 10000) cfg->max_global_per_second = 10000;

  // Score thresholds: Ensure logical order 1.0 >= throttle >= challenge >= block >= 0.0
  cfg->score_throttle = synprotect_clamp_score (cfg->score_throttle);
  cfg->score_challenge = synprotect_clamp_score (cfg->score_challenge);
  cfg->score_block = synprotect_clamp_score (cfg->score_block);
  if (cfg->score_challenge > cfg->score_throttle) cfg->score_challenge = cfg->score_throttle * 0.8f;
  if (cfg->score_block > cfg->score_challenge) cfg->score_block = cfg->score_challenge * 0.5f;

  // Memory limits: Prevent OOM
  if (cfg->max_tracked_ips == 0) cfg->max_tracked_ips = SOCKET_SYN_DEFAULT_MAX_TRACKED_IPS;
  if (cfg->max_tracked_ips > 1000000) cfg->max_tracked_ips = 1000000;  // Reasonable cap

  if (cfg->max_whitelist == 0) cfg->max_whitelist = SOCKET_SYN_DEFAULT_MAX_WHITELIST;
  if (cfg->max_whitelist > 10000) cfg->max_whitelist = 10000;

  if (cfg->max_blacklist == 0) cfg->max_blacklist = SOCKET_SYN_DEFAULT_MAX_BLACKLIST;
  if (cfg->max_blacklist > 10000) cfg->max_blacklist = 10000;

  // Other rates positive
  if (cfg->score_decay_per_sec < 0.0f) cfg->score_decay_per_sec = SOCKET_SYN_DEFAULT_SCORE_DECAY;
  if (cfg->score_penalty_attempt < 0.0f) cfg->score_penalty_attempt = SOCKET_SYN_DEFAULT_PENALTY_ATTEMPT;
  // etc.

  return local_config;
}

/**
 * synprotect_alloc_structure - Allocate SYN protection structure
 * @arena: Arena for allocation (may be NULL for malloc)
 *
 * Returns: Allocated structure, or NULL on failure
 */
static T
synprotect_alloc_structure (Arena_T arena)
{
  if (arena != NULL)
    return Arena_alloc (arena, sizeof (struct SocketSYNProtect_T), __FILE__,
                        __LINE__);
  return malloc (sizeof (struct SocketSYNProtect_T));
}

/**
 * synprotect_init_base - Initialize base structure fields
 * @protect: Protection instance
 * @arena: Arena used for allocation
 * @config: Configuration to copy
 */
static void
synprotect_init_base (T protect, Arena_T arena,
                      const SocketSYNProtect_Config *config)
{
  memset (protect, 0, sizeof (*protect));
  protect->arena = arena;
  protect->use_malloc = (arena == NULL);
  memcpy (&protect->config, config, sizeof (protect->config));

  /* Auto-generate hash seed if not provided for collision resistance */
  if (protect->config.hash_seed == 0) {
    TRY {
      if (SocketCrypto_random_bytes (&protect->hash_seed, sizeof (protect->hash_seed)) != 0) {
        protect->hash_seed = (unsigned) Socket_get_monotonic_ms ();
      }
    } EXCEPT (SocketCrypto_Failed) {
      protect->hash_seed = SOCKET_UTIL_DJB2_SEED;  /* Fallback to standard DJB2 seed */
    } END_TRY;
  } else {
    protect->hash_seed = protect->config.hash_seed;
  }
}

/**
 * synprotect_init_mutex - Initialize mutex
 * @protect: Protection instance
 *
 * Returns: 1 on success, 0 on failure
 */
static int
synprotect_init_mutex (T protect)
{
  if (pthread_mutex_init (&protect->mutex, NULL) != 0)
    return 0;

  protect->initialized = 1;
  return 1;
}

/**
 * synprotect_finalize - Finalize successful initialization
 * @protect: Protection instance
 */
static void
synprotect_finalize (T protect)
{
  protect->start_time_ms = Socket_get_monotonic_ms ();
  init_atomic_stats (protect);
  SocketMetrics_gauge_set(SOCKET_GAU_SYNPROTECT_TRACKED_IPS, 0);
  SocketMetrics_gauge_set(SOCKET_GAU_SYNPROTECT_BLOCKED_IPS, 0);
}

/**
 * synprotect_init_tables - Initialize all hash tables
 * @protect: Protection instance
 * @config: Configuration
 *
 * Returns: Cleanup stage reached on failure, or -1 on success
 */
static int
synprotect_init_tables (T protect, const SocketSYNProtect_Config *config)
{
  if (!init_ip_hash_table (protect))
    return SYN_CLEANUP_MUTEX;

  if (!init_whitelist_table (protect))
    return SYN_CLEANUP_IP_TABLE;

  if (!init_blacklist_table (protect))
    return SYN_CLEANUP_WHITELIST;

  if (!init_global_limiter (protect, config))
    return SYN_CLEANUP_BLACKLIST;

  return -1; /* Success */
}

T
SocketSYNProtect_new (Arena_T arena, const SocketSYNProtect_Config *config)
{
  T protect;
  SocketSYNProtect_Config local_config;
  const SocketSYNProtect_Config *cfg;
  int init_result;

  cfg = synprotect_get_config (config, &local_config);

  protect = synprotect_alloc_structure (arena);
  if (protect == NULL)
    SOCKET_RAISE_MSG (SocketSYNProtect, SocketSYNProtect_Failed,
                      "Failed to allocate SYN protection structure");

  synprotect_init_base (protect, arena, cfg);

  if (!synprotect_init_mutex (protect))
    {
      cleanup_synprotect_init (protect, SYN_CLEANUP_NONE);
      SOCKET_RAISE_FMT (SocketSYNProtect, SocketSYNProtect_Failed,
                        "Failed to initialize mutex");
    }

  init_result = synprotect_init_tables (protect, cfg);
  if (init_result >= 0)
    {
      cleanup_synprotect_init (protect, (SYN_CleanupStage)init_result);
      SOCKET_RAISE_MSG (SocketSYNProtect, SocketSYNProtect_Failed,
                        "Failed to initialize hash tables");
    }

  synprotect_finalize (protect);
  return protect;
}

void
SocketSYNProtect_free (T *protect)
{
  T p;

  if (protect == NULL || *protect == NULL)
    return;

  p = *protect;

  if (p->initialized)
    pthread_mutex_destroy (&p->mutex);

  if (p->global_limiter != NULL)
    SocketRateLimit_free (&p->global_limiter);

  if (p->use_malloc)
    {
      free_ip_entries (p);
      free_whitelist_entries (p);
      free_blacklist_entries (p);
      SocketMetrics_gauge_set(SOCKET_GAU_SYNPROTECT_TRACKED_IPS, 0);
      SocketMetrics_gauge_set(SOCKET_GAU_SYNPROTECT_BLOCKED_IPS, 0);
      free (p->ip_table);
      free (p->whitelist_table);
      free (p->blacklist_table);
      free (p);
    }

  *protect = NULL;
}

void
SocketSYNProtect_configure (T protect, const SocketSYNProtect_Config *config)
{
  assert (protect != NULL);
  assert (config != NULL);

  pthread_mutex_lock (&protect->mutex);
  memcpy (&protect->config, config, sizeof (protect->config));

  if (protect->global_limiter != NULL)
    {
      SocketRateLimit_configure (protect->global_limiter,
                                 (size_t)config->max_global_per_second,
                                 (size_t)config->max_global_per_second);
    }

  pthread_mutex_unlock (&protect->mutex);
}

/* ============================================================================
 * Public API Implementation - Core Protection
 * ============================================================================ */

SocketSYN_Action
SocketSYNProtect_check (T protect, const char *client_ip,
                        SocketSYN_IPState *state_out)
{
  SocketSYN_Action action;
  int64_t now_ms;

  assert (protect != NULL);

  if (!SOCKET_VALID_IP_STRING (client_ip))
    return SYN_ACTION_ALLOW;

  now_ms = Socket_get_monotonic_ms ();

  pthread_mutex_lock (&protect->mutex);

  atomic_fetch_add (&protect->stat_attempts, 1);
  SocketMetrics_counter_inc(SOCKET_CTR_SYNPROTECT_ATTEMPTS_TOTAL);

  if (check_whitelist_blacklist (protect, client_ip, now_ms, state_out,
                                 &action))
    {
      pthread_mutex_unlock (&protect->mutex);
      return action;
    }

  if (!check_global_rate_limit (protect))
    {
      pthread_mutex_unlock (&protect->mutex);
      return SYN_ACTION_BLOCK;
    }

  action = process_tracked_ip (protect, client_ip, now_ms, state_out);

  pthread_mutex_unlock (&protect->mutex);

  return action;
}

void
SocketSYNProtect_report_success (T protect, const char *client_ip)
{
  SocketSYN_IPEntry *entry;

  assert (protect != NULL);

  if (!SOCKET_VALID_IP_STRING (client_ip))
    return;

  pthread_mutex_lock (&protect->mutex);

  entry = find_ip_entry (protect, client_ip);
  if (entry != NULL)
    {
      lru_touch (protect, entry);
      reward_success (&entry->state, &protect->config);

      if (entry->state.score >= protect->config.score_throttle)
        entry->state.block_until_ms = 0;
    }

  pthread_mutex_unlock (&protect->mutex);
}

void
SocketSYNProtect_report_failure (T protect, const char *client_ip,
                                 int error_code)
{
  SocketSYN_IPEntry *entry;
  int64_t now_ms;

  (void)error_code;

  assert (protect != NULL);

  if (!SOCKET_VALID_IP_STRING (client_ip))
    return;

  now_ms = Socket_get_monotonic_ms ();

  pthread_mutex_lock (&protect->mutex);

  entry = find_ip_entry (protect, client_ip);
  if (entry != NULL)
    {
      lru_touch (protect, entry);
      penalize_failure (&entry->state, &protect->config);

      if (entry->state.score < protect->config.score_block
          && entry->state.block_until_ms == 0)
        {
          entry->state.block_until_ms
              = now_ms + protect->config.block_duration_ms;
        }
    }

  pthread_mutex_unlock (&protect->mutex);
}

/* ============================================================================
 * Public API Implementation - Whitelist Management
 * ============================================================================ */

int
SocketSYNProtect_whitelist_add (T protect, const char *ip)
{
  SocketSYN_WhitelistEntry *entry;
  unsigned bucket;
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];

  assert (protect != NULL);

  if (!SOCKET_VALID_IP_STRING (ip))
    return 0;

  /* Validate IP address format before adding */
  if (parse_ip_address (ip, addr_bytes, sizeof (addr_bytes)) == 0)
    return 0;

  pthread_mutex_lock (&protect->mutex);

  if (protect->whitelist_count >= protect->config.max_whitelist)
    {
      pthread_mutex_unlock (&protect->mutex);
      return 0;
    }

  bucket = synprotect_hash_ip (protect, ip, SOCKET_SYN_LIST_HASH_SIZE);

  if (find_whitelist_entry_exact (protect->whitelist_table[bucket], ip) != NULL)
    {
      pthread_mutex_unlock (&protect->mutex);
      return 1;
    }

  entry = create_whitelist_entry (protect, ip, 0);
  if (entry == NULL)
    {
      pthread_mutex_unlock (&protect->mutex);
      return 0;
    }

  insert_whitelist_entry (protect, entry, bucket);

  pthread_mutex_unlock (&protect->mutex);
  return 1;
}

/**
 * setup_cidr_entry - Setup CIDR fields on whitelist entry
 * @entry: Whitelist entry to configure
 * @ip_part: IP address part of CIDR
 * @prefix_len: CIDR prefix length
 *
 * Returns: 1 on success, 0 on failure
 */
static int
setup_cidr_entry (SocketSYN_WhitelistEntry *entry, const char *ip_part,
                  int prefix_len)
{
  entry->prefix_len = (uint8_t)prefix_len;
  entry->addr_family
      = parse_ip_address (ip_part, entry->addr_bytes, sizeof (entry->addr_bytes));
  return (entry->addr_family != 0);
}

int
SocketSYNProtect_whitelist_add_cidr (T protect, const char *cidr)
{
  SocketSYN_WhitelistEntry *entry;
  char ip_part[SOCKET_IP_MAX_LEN];
  int prefix_len;
  unsigned bucket;

  assert (protect != NULL);

  if (!SOCKET_VALID_IP_STRING (cidr))
    return 0;

  if (!parse_cidr_notation (cidr, ip_part, sizeof (ip_part), &prefix_len))
    return SocketSYNProtect_whitelist_add (protect, cidr);

  pthread_mutex_lock (&protect->mutex);

  if (protect->whitelist_count >= protect->config.max_whitelist)
    {
      pthread_mutex_unlock (&protect->mutex);
      return 0;
    }

  entry = create_whitelist_entry (protect, cidr, 1);
  if (entry == NULL)
    {
      pthread_mutex_unlock (&protect->mutex);
      return 0;
    }

  if (!setup_cidr_entry (entry, ip_part, prefix_len))
    {
      free_memory (protect, entry);
      pthread_mutex_unlock (&protect->mutex);
      return 0;
    }

  // Warn on overly broad CIDR (/0 matches all in family)
  if (prefix_len == 0) {
    SOCKET_LOG_WARN_MSG ("Adding /0 CIDR - matches all IPs in family %d, potential security risk: %s",
                         entry->addr_family, cidr);
  }

  bucket = synprotect_hash_ip (protect, ip_part, SOCKET_SYN_LIST_HASH_SIZE);
  insert_whitelist_entry (protect, entry, bucket);

  pthread_mutex_unlock (&protect->mutex);
  return 1;
}

void
SocketSYNProtect_whitelist_remove (T protect, const char *ip)
{
  SocketSYN_WhitelistEntry **pp;
  unsigned bucket;

  assert (protect != NULL);

  if (!SOCKET_VALID_IP_STRING (ip))
    return;

  pthread_mutex_lock (&protect->mutex);

  bucket = synprotect_hash_ip (protect, ip, SOCKET_SYN_LIST_HASH_SIZE);
  pp = &protect->whitelist_table[bucket];

  while (*pp != NULL)
    {
      if (strcmp ((*pp)->ip, ip) == 0)
        {
          SocketSYN_WhitelistEntry *to_remove = *pp;
          *pp = to_remove->next;
          free_memory (protect, to_remove);
          protect->whitelist_count--;
          break;
        }
      pp = &(*pp)->next;
    }

  pthread_mutex_unlock (&protect->mutex);
}

int
SocketSYNProtect_whitelist_contains (T protect, const char *ip)
{
  int result;

  assert (protect != NULL);

  if (!SOCKET_VALID_IP_STRING (ip))
    return 0;

  pthread_mutex_lock (&protect->mutex);
  result = whitelist_check (protect, ip);
  pthread_mutex_unlock (&protect->mutex);

  return result;
}

void
SocketSYNProtect_whitelist_clear (T protect)
{
  assert (protect != NULL);

  pthread_mutex_lock (&protect->mutex);

  for (size_t i = 0; i < SOCKET_SYN_LIST_HASH_SIZE; i++)
    {
      SocketSYN_WhitelistEntry *entry = protect->whitelist_table[i];
      while (entry != NULL)
        {
          SocketSYN_WhitelistEntry *next = entry->next;
          free_memory (protect, entry);
          entry = next;
        }
      protect->whitelist_table[i] = NULL;
    }

  protect->whitelist_count = 0;

  pthread_mutex_unlock (&protect->mutex);
}

/* ============================================================================
 * Public API Implementation - Blacklist Management
 * ============================================================================ */



/**
 * calculate_expiry_time - Calculate blacklist expiry time
 * @now_ms: Current timestamp
 * @duration_ms: Duration in milliseconds (0 = permanent)
 *
 * Returns: Expiry timestamp (0 = permanent)
 */
static int64_t
calculate_expiry_time (int64_t now_ms, int duration_ms)
{
  return (duration_ms > 0) ? (now_ms + duration_ms) : 0;
}

int
SocketSYNProtect_blacklist_add (T protect, const char *ip, int duration_ms)
{
  SocketSYN_BlacklistEntry *entry;
  unsigned bucket;
  int64_t now_ms, expires_ms;

  assert (protect != NULL);

  if (!SOCKET_VALID_IP_STRING (ip))
    return 0;

  now_ms = Socket_get_monotonic_ms ();
  expires_ms = calculate_expiry_time (now_ms, duration_ms);

  pthread_mutex_lock (&protect->mutex);

  if (protect->blacklist_count >= protect->config.max_blacklist)
    {
      pthread_mutex_unlock (&protect->mutex);
      return 0;
    }

  bucket = synprotect_hash_ip (protect, ip, SOCKET_SYN_LIST_HASH_SIZE);

  entry = find_blacklist_entry (protect->blacklist_table[bucket], ip);
  if (entry != NULL)
    {
      entry->expires_ms = expires_ms;
      pthread_mutex_unlock (&protect->mutex);
      return 1;
    }

  entry = create_blacklist_entry (protect, ip, expires_ms);
  if (entry == NULL)
    {
      pthread_mutex_unlock (&protect->mutex);
      return 0;
    }

  insert_blacklist_entry (protect, entry, bucket);

  pthread_mutex_unlock (&protect->mutex);
  return 1;
}

void
SocketSYNProtect_blacklist_remove (T protect, const char *ip)
{
  SocketSYN_BlacklistEntry **pp;
  unsigned bucket;

  assert (protect != NULL);

  if (!SOCKET_VALID_IP_STRING (ip))
    return;

  pthread_mutex_lock (&protect->mutex);

  bucket = synprotect_hash_ip (protect, ip, SOCKET_SYN_LIST_HASH_SIZE);
  pp = &protect->blacklist_table[bucket];

  while (*pp != NULL)
    {
      if (strcmp ((*pp)->ip, ip) == 0)
        {
          SocketSYN_BlacklistEntry *to_remove = *pp;
          *pp = to_remove->next;
          free_memory (protect, to_remove);
          protect->blacklist_count--;
  SocketMetrics_gauge_dec(SOCKET_GAU_SYNPROTECT_BLOCKED_IPS);
          break;
        }
      pp = &(*pp)->next;
    }

  pthread_mutex_unlock (&protect->mutex);
}

int
SocketSYNProtect_blacklist_contains (T protect, const char *ip)
{
  int result;
  int64_t now_ms;

  assert (protect != NULL);

  if (!SOCKET_VALID_IP_STRING (ip))
    return 0;

  now_ms = Socket_get_monotonic_ms ();

  pthread_mutex_lock (&protect->mutex);
  result = blacklist_check (protect, ip, now_ms);
  pthread_mutex_unlock (&protect->mutex);

  return result;
}

/* count_currently_blocked moved earlier for forward reference */

void
SocketSYNProtect_blacklist_clear (T protect)
{
  assert (protect != NULL);

  pthread_mutex_lock (&protect->mutex);

  for (size_t i = 0; i < SOCKET_SYN_LIST_HASH_SIZE; i++)
    {
      SocketSYN_BlacklistEntry *entry = protect->blacklist_table[i];
      while (entry != NULL)
        {
          SocketSYN_BlacklistEntry *next = entry->next;
          free_memory (protect, entry);
          entry = next;
        }
      protect->blacklist_table[i] = NULL;
    }

  protect->blacklist_count = 0;

  size_t timed_blocked = 0;
  int64_t now_ms = Socket_get_monotonic_ms ();
  for (size_t i = 0; i < protect->ip_table_size; i++)
    {
      const SocketSYN_IPEntry *entry = protect->ip_table[i];
      while (entry != NULL)
        {
          if (entry->state.block_until_ms > now_ms)
            timed_blocked++;
          entry = entry->hash_next;
        }
    }
  SocketMetrics_gauge_set (SOCKET_GAU_SYNPROTECT_BLOCKED_IPS, timed_blocked);

  pthread_mutex_unlock (&protect->mutex);
}

/* ============================================================================
 * Public API Implementation - Query and Statistics
 * ============================================================================ */

/**
 * count_currently_blocked - Count IPs with active blocks
 * @protect: Protection instance (must hold mutex)
 * @now_ms: Current timestamp
 *
 * Returns: Number of blocked IPs
 * Thread-safe: No (caller must hold mutex)
 */
static size_t
count_currently_blocked (T protect, int64_t now_ms)
{
  size_t blocked_count = 0;

  for (size_t i = 0; i < protect->ip_table_size; i++)
    {
      const SocketSYN_IPEntry *entry = protect->ip_table[i];
      while (entry != NULL)
        {
          if (entry->state.block_until_ms > now_ms)
            blocked_count++;
          entry = entry->hash_next;
        }
    }

  return blocked_count;
}

/**
 * count_active_blacklists - Count active (non-expired) blacklist entries
 * @protect: Protection instance (must hold mutex)
 * @now_ms: Current timestamp
 *
 * Returns: Number of active blacklisted IPs
 * Thread-safe: No (caller must hold mutex)
 */
static size_t
count_active_blacklists (T protect, int64_t now_ms)
{
  size_t active_count = 0;

  for (size_t i = 0; i < SOCKET_SYN_LIST_HASH_SIZE; i++)
    {
      const SocketSYN_BlacklistEntry *entry = protect->blacklist_table[i];
      while (entry != NULL)
        {
          if (entry->expires_ms == 0 || entry->expires_ms > now_ms)
            active_count++;
          entry = entry->next;
        }
    }

  return active_count;
}

int
SocketSYNProtect_get_ip_state (T protect, const char *ip,
                               SocketSYN_IPState *state)
{
  SocketSYN_IPEntry *entry;

  assert (protect != NULL);
  assert (state != NULL);

  if (!SOCKET_VALID_IP_STRING (ip))
    return 0;

  pthread_mutex_lock (&protect->mutex);

  entry = find_ip_entry (protect, ip);
  if (entry != NULL)
    {
      memcpy (state, &entry->state, sizeof (*state));
      pthread_mutex_unlock (&protect->mutex);
      return 1;
    }

  pthread_mutex_unlock (&protect->mutex);
  return 0;
}

/**
 * count_currently_blocked - Count IPs with active blocks
 * @protect: Protection instance (must hold mutex)
 * @now_ms: Current timestamp
 *
 * Returns: Number of blocked IPs
 */
/* count_currently_blocked moved earlier for forward reference */

void
SocketSYNProtect_stats (T protect, SocketSYNProtect_Stats *stats)
{
  int64_t now_ms;
  size_t blocked_count;

  assert (protect != NULL);
  assert (stats != NULL);

  now_ms = Socket_get_monotonic_ms ();

  pthread_mutex_lock (&protect->mutex);

  size_t ip_blocked_count = count_currently_blocked (protect, now_ms);
  size_t bl_active_count = count_active_blacklists (protect, now_ms);

  stats->total_attempts = atomic_load (&protect->stat_attempts);
  stats->total_allowed = atomic_load (&protect->stat_allowed);
  stats->total_throttled = atomic_load (&protect->stat_throttled);
  stats->total_challenged = atomic_load (&protect->stat_challenged);
  stats->total_blocked = atomic_load (&protect->stat_blocked);
  stats->total_whitelisted = atomic_load (&protect->stat_whitelisted);
  stats->total_blacklisted = atomic_load (&protect->stat_blacklisted);
  stats->current_tracked_ips = protect->ip_entry_count;
  stats->current_blocked_ips = ip_blocked_count + bl_active_count;
  stats->lru_evictions = atomic_load (&protect->stat_lru_evictions);
  stats->uptime_ms = now_ms - protect->start_time_ms;

  pthread_mutex_unlock (&protect->mutex);
}

void
SocketSYNProtect_stats_reset (T protect)
{
  assert (protect != NULL);

  atomic_store (&protect->stat_attempts, 0);
  atomic_store (&protect->stat_allowed, 0);
  atomic_store (&protect->stat_throttled, 0);
  atomic_store (&protect->stat_challenged, 0);
  atomic_store (&protect->stat_blocked, 0);
  atomic_store (&protect->stat_whitelisted, 0);
  atomic_store (&protect->stat_blacklisted, 0);
}

const char *
SocketSYNProtect_action_name (SocketSYN_Action action)
{
  if (action >= 0 && (size_t)action < ACTION_NAMES_COUNT)
    return action_names[action];
  return "UNKNOWN";
}

const char *
SocketSYNProtect_reputation_name (SocketSYN_Reputation rep)
{
  if (rep >= 0 && (size_t)rep < REPUTATION_NAMES_COUNT)
    return reputation_names[rep];
  return "UNKNOWN";
}

/* ============================================================================
 * Public API Implementation - Maintenance
 * ============================================================================ */

/**
 * cleanup_expired_blacklist - Remove expired blacklist entries
 * @protect: Protection instance (must hold mutex)
 * @now_ms: Current timestamp
 *
 * Returns: Number of entries removed
 */
static size_t
cleanup_expired_blacklist (T protect, int64_t now_ms)
{
  size_t removed = 0;

  for (size_t i = 0; i < SOCKET_SYN_LIST_HASH_SIZE; i++)
    {
      SocketSYN_BlacklistEntry **pp = &protect->blacklist_table[i];
      while (*pp != NULL)
        {
          if ((*pp)->expires_ms > 0 && (*pp)->expires_ms <= now_ms)
            {
              SocketSYN_BlacklistEntry *expired = *pp;
              *pp = expired->next;
              free_memory (protect, expired);
              protect->blacklist_count--;
              SocketMetrics_gauge_dec(SOCKET_GAU_SYNPROTECT_BLOCKED_IPS);
              removed++;
            }
          else
            {
              pp = &(*pp)->next;
            }
        }
    }

  return removed;
}

/**
 * cleanup_expired_ip_blocks - Clear expired IP blocks
 * @protect: Protection instance (must hold mutex)
 * @now_ms: Current timestamp
 */
static void
cleanup_expired_ip_blocks (T protect, int64_t now_ms)
{
  for (size_t i = 0; i < protect->ip_table_size; i++)
    {
      SocketSYN_IPEntry *entry = protect->ip_table[i];
      while (entry != NULL)
        {
          if (entry->state.block_until_ms > 0
              && entry->state.block_until_ms <= now_ms)
            {
              entry->state.block_until_ms = 0;
              SocketMetrics_gauge_dec(SOCKET_GAU_SYNPROTECT_BLOCKED_IPS);
            }
          entry = entry->hash_next;
        }
    }
}

size_t
SocketSYNProtect_cleanup (T protect)
{
  size_t removed;
  int64_t now_ms;

  assert (protect != NULL);

  now_ms = Socket_get_monotonic_ms ();

  pthread_mutex_lock (&protect->mutex);

  removed = cleanup_expired_blacklist (protect, now_ms);
  cleanup_expired_ip_blocks (protect, now_ms);

  pthread_mutex_unlock (&protect->mutex);

  return removed;
}

void
SocketSYNProtect_clear_all (T protect)
{
  assert (protect != NULL);

  pthread_mutex_lock (&protect->mutex);

  for (size_t i = 0; i < protect->ip_table_size; i++)
    {
      SocketSYN_IPEntry *entry = protect->ip_table[i];
      while (entry != NULL)
        {
          SocketSYN_IPEntry *next = entry->hash_next;
          free_memory (protect, entry);
          entry = next;
        }
      protect->ip_table[i] = NULL;
    }

  protect->ip_entry_count = 0;
  SocketMetrics_gauge_set(SOCKET_GAU_SYNPROTECT_TRACKED_IPS, 0);
  protect->lru_head = NULL;
  protect->lru_tail = NULL;

  pthread_mutex_unlock (&protect->mutex);
}

void
SocketSYNProtect_reset (T protect)
{
  assert (protect != NULL);

  SocketSYNProtect_clear_all (protect);
  SocketSYNProtect_whitelist_clear (protect);
  SocketSYNProtect_blacklist_clear (protect);
  SocketSYNProtect_stats_reset (protect);

  pthread_mutex_lock (&protect->mutex);
  protect->start_time_ms = Socket_get_monotonic_ms ();
  pthread_mutex_unlock (&protect->mutex);
}

#undef T

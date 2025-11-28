/**
 * SocketSYNProtect.c - SYN Flood Protection Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
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
#include <arpa/inet.h>
#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define T SocketSYNProtect_T

/* ============================================================================
 * Exception Definitions
 * ============================================================================ */

const Except_T SocketSYNProtect_Failed
    = { &SocketSYNProtect_Failed, "SYN protection operation failed" };

/* Thread-local exception using centralized macro */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketSYNProtect);

#define RAISE_SYNPROTECT_ERROR(exception)                                      \
  SOCKET_RAISE_MODULE_ERROR (SocketSYNProtect, exception)

/* ============================================================================
 * Static String Tables
 * ============================================================================ */

static const char *const action_names[] = { "ALLOW", "THROTTLE", "CHALLENGE",
                                            "BLOCK" };

static const char *const reputation_names[]
    = { "TRUSTED", "NEUTRAL", "SUSPECT", "HOSTILE" };

/* ============================================================================
 * Internal Helper Functions - Memory Allocation
 * ============================================================================ */

/**
 * alloc_memory - Allocate memory from arena or heap
 */
static void *
alloc_memory (T protect, size_t size)
{
  if (protect->arena != NULL)
    return Arena_alloc (protect->arena, size, __FILE__, __LINE__);
  return malloc (size);
}

/**
 * alloc_zeroed - Allocate zeroed memory from arena or heap
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
 */
static void
free_memory (T protect, void *ptr)
{
  if (protect->use_malloc && ptr != NULL)
    free (ptr);
}

/* ============================================================================
 * Internal Helper Functions - IP Entry Management
 * ============================================================================ */

/**
 * find_ip_entry - Find IP entry in hash table
 * @protect: Protection instance (caller must hold mutex)
 * @ip: IP address string
 *
 * Returns: Entry pointer or NULL if not found
 */
static SocketSYN_IPEntry *
find_ip_entry (T protect, const char *ip)
{
  unsigned bucket = synprotect_hash_ip (ip, protect->ip_table_size);
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
 * lru_remove - Remove entry from LRU list
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

/**
 * remove_ip_entry_from_hash - Remove entry from hash table
 */
static void
remove_ip_entry_from_hash (T protect, SocketSYN_IPEntry *entry)
{
  unsigned bucket = synprotect_hash_ip (entry->state.ip, protect->ip_table_size);
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
 */
static void
evict_lru_entry (T protect)
{
  SocketSYN_IPEntry *victim = protect->lru_tail;
  if (victim == NULL)
    return;

  /* Remove from hash table */
  remove_ip_entry_from_hash (protect, victim);

  /* Remove from LRU list */
  lru_remove (protect, victim);

  /* Free memory */
  free_memory (protect, victim);

  protect->ip_entry_count--;
  atomic_fetch_add (&protect->stat_lru_evictions, 1);
}

/**
 * create_ip_entry - Create new IP entry
 */
static SocketSYN_IPEntry *
create_ip_entry (T protect, const char *ip, int64_t now_ms)
{
  SocketSYN_IPEntry *entry;
  unsigned bucket;

  /* Evict if at capacity */
  while (protect->ip_entry_count >= protect->config.max_tracked_ips)
    evict_lru_entry (protect);

  /* Allocate new entry */
  entry = alloc_zeroed (protect, 1, sizeof (*entry));
  if (entry == NULL)
    return NULL;

  /* Initialize state */
  strncpy (entry->state.ip, ip, SOCKET_IP_MAX_LEN - 1);
  entry->state.ip[SOCKET_IP_MAX_LEN - 1] = '\0';
  entry->state.window_start_ms = now_ms;
  entry->state.attempts_current = 0;
  entry->state.attempts_previous = 0;
  entry->state.successes = 0;
  entry->state.failures = 0;
  entry->state.last_attempt_ms = now_ms;
  entry->state.block_until_ms = 0;
  entry->state.rep = SYN_REP_NEUTRAL;
  entry->state.score = SOCKET_SYN_INITIAL_SCORE;

  /* Insert into hash table */
  bucket = synprotect_hash_ip (ip, protect->ip_table_size);
  entry->hash_next = protect->ip_table[bucket];
  protect->ip_table[bucket] = entry;

  /* Add to LRU list front */
  lru_push_front (protect, entry);

  protect->ip_entry_count++;

  return entry;
}

/**
 * get_or_create_ip_entry - Get existing or create new IP entry
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
 */
static void
rotate_window_if_needed (SocketSYN_IPState *state, int64_t now_ms,
                         int window_ms)
{
  int64_t elapsed = now_ms - state->window_start_ms;

  if (elapsed >= window_ms)
    {
      /* Rotate: current becomes previous, reset current */
      state->attempts_previous = state->attempts_current;
      state->attempts_current = 0;
      state->window_start_ms = now_ms;
    }
}

/**
 * calculate_effective_attempts - Calculate weighted attempt count
 *
 * Uses linear interpolation between current and previous window
 * for smooth rate estimation.
 */
static uint32_t
calculate_effective_attempts (const SocketSYN_IPState *state, int64_t now_ms,
                              int window_ms)
{
  int64_t elapsed;
  float progress;
  float previous_weight;

  if (window_ms <= 0)
    return state->attempts_current;

  elapsed = now_ms - state->window_start_ms;
  if (elapsed < 0)
    elapsed = 0;
  if (elapsed > window_ms)
    elapsed = window_ms;

  /* Progress through current window (0.0 = start, 1.0 = end) */
  progress = (float)elapsed / (float)window_ms;

  /* Weight previous window inversely to progress */
  previous_weight = 1.0f - progress;

  return state->attempts_current
         + (uint32_t) (state->attempts_previous * previous_weight);
}

/* ============================================================================
 * Internal Helper Functions - Reputation Scoring
 * ============================================================================ */

/**
 * apply_score_decay - Apply time-based score recovery
 */
static void
apply_score_decay (SocketSYN_IPState *state,
                   const SocketSYNProtect_Config *config, int64_t elapsed_ms)
{
  if (elapsed_ms <= 0 || config->score_decay_per_sec <= 0.0f)
    return;

  float decay = ((float)elapsed_ms / 1000.0f) * config->score_decay_per_sec;
  state->score = synprotect_clamp_score (state->score + decay);
}

/**
 * update_reputation_from_score - Update reputation enum based on score
 */
static void
update_reputation_from_score (SocketSYN_IPState *state,
                              const SocketSYNProtect_Config *config)
{
  if (state->score >= 0.9f)
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
 * determine_action - Determine action based on IP state
 */
static SocketSYN_Action
determine_action (const SocketSYN_IPState *state,
                  const SocketSYNProtect_Config *config, uint32_t effective_attempts)
{
  /* Check for active block */
  if (state->block_until_ms > 0)
    {
      int64_t now = Socket_get_monotonic_ms ();
      if (now < state->block_until_ms)
        return SYN_ACTION_BLOCK;
    }

  /* Check attempt rate threshold */
  if ((int)effective_attempts > config->max_attempts_per_window)
    return SYN_ACTION_BLOCK;

  /* Check score thresholds */
  if (state->score < config->score_block)
    return SYN_ACTION_BLOCK;

  if (state->score < config->score_challenge)
    return SYN_ACTION_CHALLENGE;

  if (state->score < config->score_throttle)
    return SYN_ACTION_THROTTLE;

  return SYN_ACTION_ALLOW;
}

/* ============================================================================
 * Internal Helper Functions - Whitelist
 * ============================================================================ */

/**
 * parse_ip_address - Parse IP address string to bytes
 * Returns: AF_INET, AF_INET6, or 0 on error
 */
static int
parse_ip_address (const char *ip, uint8_t *addr_bytes, size_t addr_size)
{
  struct in_addr addr4;
  struct in6_addr addr6;

  if (addr_size < 16)
    return 0;

  /* Try IPv4 first */
  if (inet_pton (AF_INET, ip, &addr4) == 1)
    {
      memset (addr_bytes, 0, 16);
      memcpy (addr_bytes, &addr4.s_addr, 4);
      return AF_INET;
    }

  /* Try IPv6 */
  if (inet_pton (AF_INET6, ip, &addr6) == 1)
    {
      memcpy (addr_bytes, addr6.s6_addr, 16);
      return AF_INET6;
    }

  return 0;
}

/**
 * ip_matches_cidr - Check if IP matches CIDR entry
 */
static int
ip_matches_cidr (const char *ip, const SocketSYN_WhitelistEntry *entry)
{
  uint8_t ip_bytes[16];
  int family;
  int bits;
  int bytes;
  int i;

  family = parse_ip_address (ip, ip_bytes, sizeof (ip_bytes));
  if (family == 0 || family != entry->addr_family)
    return 0;

  bits = entry->prefix_len;
  bytes = bits / 8;

  /* Compare full bytes */
  if (memcmp (ip_bytes, entry->addr_bytes, (size_t)bytes) != 0)
    return 0;

  /* Compare partial byte if needed */
  if (bits % 8 != 0)
    {
      int remaining_bits = bits % 8;
      uint8_t mask = (uint8_t) (0xFF << (8 - remaining_bits));
      if ((ip_bytes[bytes] & mask) != (entry->addr_bytes[bytes] & mask))
        return 0;
    }

  return 1;
}

/**
 * whitelist_check - Check if IP is whitelisted
 */
static int
whitelist_check (T protect, const char *ip)
{
  unsigned bucket;
  SocketSYN_WhitelistEntry *entry;

  if (protect->whitelist_count == 0)
    return 0;

  bucket = synprotect_hash_ip (ip, SOCKET_SYN_LIST_HASH_SIZE);
  entry = protect->whitelist_table[bucket];

  while (entry != NULL)
    {
      if (entry->is_cidr)
        {
          if (ip_matches_cidr (ip, entry))
            return 1;
        }
      else
        {
          if (strcmp (entry->ip, ip) == 0)
            return 1;
        }
      entry = entry->next;
    }

  /* Also check all CIDR entries in other buckets */
  for (size_t i = 0; i < SOCKET_SYN_LIST_HASH_SIZE; i++)
    {
      if (i == bucket)
        continue;
      entry = protect->whitelist_table[i];
      while (entry != NULL)
        {
          if (entry->is_cidr && ip_matches_cidr (ip, entry))
            return 1;
          entry = entry->next;
        }
    }

  return 0;
}

/* ============================================================================
 * Internal Helper Functions - Blacklist
 * ============================================================================ */

/**
 * blacklist_check - Check if IP is blacklisted
 */
static int
blacklist_check (T protect, const char *ip, int64_t now_ms)
{
  unsigned bucket;
  SocketSYN_BlacklistEntry *entry;

  if (protect->blacklist_count == 0)
    return 0;

  bucket = synprotect_hash_ip (ip, SOCKET_SYN_LIST_HASH_SIZE);
  entry = protect->blacklist_table[bucket];

  while (entry != NULL)
    {
      if (strcmp (entry->ip, ip) == 0)
        {
          /* Check expiry */
          if (entry->expires_ms == 0 || entry->expires_ms > now_ms)
            return 1;
          /* Entry expired - will be cleaned up later */
        }
      entry = entry->next;
    }

  return 0;
}

/* ============================================================================
 * Public API Implementation - Lifecycle
 * ============================================================================ */

void
SocketSYNProtect_config_defaults (SocketSYNProtect_Config *config)
{
  assert (config != NULL);

  memset (config, 0, sizeof (*config));

  /* Window settings */
  config->window_duration_ms = SOCKET_SYN_DEFAULT_WINDOW_MS;

  /* Rate thresholds */
  config->max_attempts_per_window = SOCKET_SYN_DEFAULT_MAX_PER_WINDOW;
  config->max_global_per_second = SOCKET_SYN_DEFAULT_GLOBAL_PER_SEC;
  config->min_success_ratio = SOCKET_SYN_DEFAULT_MIN_SUCCESS_RATIO;

  /* Response tuning */
  config->throttle_delay_ms = SOCKET_SYN_DEFAULT_THROTTLE_DELAY_MS;
  config->block_duration_ms = SOCKET_SYN_DEFAULT_BLOCK_DURATION_MS;
  config->challenge_defer_sec = SOCKET_SYN_DEFAULT_DEFER_SEC;

  /* Score thresholds */
  config->score_throttle = SOCKET_SYN_DEFAULT_SCORE_THROTTLE;
  config->score_challenge = SOCKET_SYN_DEFAULT_SCORE_CHALLENGE;
  config->score_block = SOCKET_SYN_DEFAULT_SCORE_BLOCK;

  /* Score adjustment rates */
  config->score_decay_per_sec = SOCKET_SYN_DEFAULT_SCORE_DECAY;
  config->score_penalty_attempt = SOCKET_SYN_DEFAULT_PENALTY_ATTEMPT;
  config->score_penalty_failure = SOCKET_SYN_DEFAULT_PENALTY_FAILURE;
  config->score_reward_success = SOCKET_SYN_DEFAULT_REWARD_SUCCESS;

  /* Memory management */
  config->max_tracked_ips = SOCKET_SYN_DEFAULT_MAX_TRACKED_IPS;
  config->max_whitelist = SOCKET_SYN_DEFAULT_MAX_WHITELIST;
  config->max_blacklist = SOCKET_SYN_DEFAULT_MAX_BLACKLIST;
}

T
SocketSYNProtect_new (Arena_T arena, const SocketSYNProtect_Config *config)
{
  T protect;
  SocketSYNProtect_Config local_config;
  const SocketSYNProtect_Config *cfg;

  /* Use defaults if no config provided - copy to local to avoid clobbering */
  if (config == NULL)
    {
      SocketSYNProtect_config_defaults (&local_config);
      cfg = &local_config;
    }
  else
    {
      local_config = *config;
      cfg = &local_config;
    }

  /* Allocate main structure */
  if (arena != NULL)
    protect = Arena_alloc (arena, sizeof (*protect), __FILE__, __LINE__);
  else
    protect = malloc (sizeof (*protect));

  if (protect == NULL)
    {
      SOCKET_ERROR_MSG ("Failed to allocate SYN protection structure");
      RAISE_SYNPROTECT_ERROR (SocketSYNProtect_Failed);
    }

  memset (protect, 0, sizeof (*protect));
  protect->arena = arena;
  protect->use_malloc = (arena == NULL);

  /* Copy configuration */
  memcpy (&protect->config, cfg, sizeof (protect->config));

  /* Initialize mutex */
  if (pthread_mutex_init (&protect->mutex, NULL) != 0)
    {
      if (protect->use_malloc)
        free (protect);
      SOCKET_ERROR_FMT ("Failed to initialize mutex");
      RAISE_SYNPROTECT_ERROR (SocketSYNProtect_Failed);
    }
  protect->initialized = 1;

  /* Allocate IP hash table */
  protect->ip_table_size = SOCKET_SYN_IP_HASH_SIZE;
  protect->ip_table = alloc_zeroed (protect, protect->ip_table_size,
                                    sizeof (SocketSYN_IPEntry *));
  if (protect->ip_table == NULL)
    {
      pthread_mutex_destroy (&protect->mutex);
      if (protect->use_malloc)
        free (protect);
      SOCKET_ERROR_MSG ("Failed to allocate IP hash table");
      RAISE_SYNPROTECT_ERROR (SocketSYNProtect_Failed);
    }

  /* Allocate whitelist hash table */
  protect->whitelist_table = alloc_zeroed (protect, SOCKET_SYN_LIST_HASH_SIZE,
                                           sizeof (SocketSYN_WhitelistEntry *));
  if (protect->whitelist_table == NULL)
    {
      free_memory (protect, protect->ip_table);
      pthread_mutex_destroy (&protect->mutex);
      if (protect->use_malloc)
        free (protect);
      SOCKET_ERROR_MSG ("Failed to allocate whitelist hash table");
      RAISE_SYNPROTECT_ERROR (SocketSYNProtect_Failed);
    }

  /* Allocate blacklist hash table */
  protect->blacklist_table = alloc_zeroed (protect, SOCKET_SYN_LIST_HASH_SIZE,
                                           sizeof (SocketSYN_BlacklistEntry *));
  if (protect->blacklist_table == NULL)
    {
      free_memory (protect, protect->whitelist_table);
      free_memory (protect, protect->ip_table);
      pthread_mutex_destroy (&protect->mutex);
      if (protect->use_malloc)
        free (protect);
      SOCKET_ERROR_MSG ("Failed to allocate blacklist hash table");
      RAISE_SYNPROTECT_ERROR (SocketSYNProtect_Failed);
    }

  /* Create global rate limiter */
  TRY
    protect->global_limiter
        = SocketRateLimit_new (arena, (size_t)cfg->max_global_per_second,
                               (size_t)cfg->max_global_per_second);
  EXCEPT (SocketRateLimit_Failed)
    free_memory (protect, protect->blacklist_table);
    free_memory (protect, protect->whitelist_table);
    free_memory (protect, protect->ip_table);
    pthread_mutex_destroy (&protect->mutex);
    if (protect->use_malloc)
      free (protect);
    SOCKET_ERROR_MSG ("Failed to create global rate limiter");
    RAISE_SYNPROTECT_ERROR (SocketSYNProtect_Failed);
  END_TRY;

  /* Initialize timestamps */
  protect->start_time_ms = Socket_get_monotonic_ms ();

  /* Initialize atomic stats */
  atomic_store (&protect->stat_attempts, 0);
  atomic_store (&protect->stat_allowed, 0);
  atomic_store (&protect->stat_throttled, 0);
  atomic_store (&protect->stat_challenged, 0);
  atomic_store (&protect->stat_blocked, 0);
  atomic_store (&protect->stat_whitelisted, 0);
  atomic_store (&protect->stat_blacklisted, 0);
  atomic_store (&protect->stat_lru_evictions, 0);

  return protect;
}

void
SocketSYNProtect_free (T *protect)
{
  T p;

  if (protect == NULL || *protect == NULL)
    return;

  p = *protect;

  /* Destroy mutex */
  if (p->initialized)
    pthread_mutex_destroy (&p->mutex);

  /* Free global limiter */
  if (p->global_limiter != NULL)
    SocketRateLimit_free (&p->global_limiter);

  /* Free hash table contents if using malloc */
  if (p->use_malloc)
    {
      /* Free IP entries */
      for (size_t i = 0; i < p->ip_table_size; i++)
        {
          SocketSYN_IPEntry *entry = p->ip_table[i];
          while (entry != NULL)
            {
              SocketSYN_IPEntry *next = entry->hash_next;
              free (entry);
              entry = next;
            }
        }

      /* Free whitelist entries */
      for (size_t i = 0; i < SOCKET_SYN_LIST_HASH_SIZE; i++)
        {
          SocketSYN_WhitelistEntry *entry = p->whitelist_table[i];
          while (entry != NULL)
            {
              SocketSYN_WhitelistEntry *next = entry->next;
              free (entry);
              entry = next;
            }
        }

      /* Free blacklist entries */
      for (size_t i = 0; i < SOCKET_SYN_LIST_HASH_SIZE; i++)
        {
          SocketSYN_BlacklistEntry *entry = p->blacklist_table[i];
          while (entry != NULL)
            {
              SocketSYN_BlacklistEntry *next = entry->next;
              free (entry);
              entry = next;
            }
        }

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

  /* Reconfigure global rate limiter */
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
  SocketSYN_IPEntry *entry;
  int64_t now_ms;
  uint32_t effective_attempts;

  assert (protect != NULL);

  /* Handle NULL/empty IP */
  if (client_ip == NULL || client_ip[0] == '\0')
    return SYN_ACTION_ALLOW;

  now_ms = Socket_get_monotonic_ms ();

  pthread_mutex_lock (&protect->mutex);

  /* Increment total attempts */
  atomic_fetch_add (&protect->stat_attempts, 1);

  /* Check whitelist first */
  if (whitelist_check (protect, client_ip))
    {
      atomic_fetch_add (&protect->stat_whitelisted, 1);
      atomic_fetch_add (&protect->stat_allowed, 1);
      if (state_out != NULL)
        {
          memset (state_out, 0, sizeof (*state_out));
          strncpy (state_out->ip, client_ip, SOCKET_IP_MAX_LEN - 1);
          state_out->rep = SYN_REP_TRUSTED;
          state_out->score = SOCKET_SYN_TRUSTED_SCORE;
        }
      pthread_mutex_unlock (&protect->mutex);
      return SYN_ACTION_ALLOW;
    }

  /* Check blacklist */
  if (blacklist_check (protect, client_ip, now_ms))
    {
      atomic_fetch_add (&protect->stat_blacklisted, 1);
      atomic_fetch_add (&protect->stat_blocked, 1);
      if (state_out != NULL)
        {
          memset (state_out, 0, sizeof (*state_out));
          strncpy (state_out->ip, client_ip, SOCKET_IP_MAX_LEN - 1);
          state_out->rep = SYN_REP_HOSTILE;
          state_out->score = 0.0f;
        }
      pthread_mutex_unlock (&protect->mutex);
      return SYN_ACTION_BLOCK;
    }

  /* Check global rate limit */
  if (!SocketRateLimit_try_acquire (protect->global_limiter, 1))
    {
      atomic_fetch_add (&protect->stat_blocked, 1);
      pthread_mutex_unlock (&protect->mutex);
      return SYN_ACTION_BLOCK;
    }

  /* Get or create IP entry */
  entry = get_or_create_ip_entry (protect, client_ip, now_ms);
  if (entry == NULL)
    {
      /* Memory allocation failed - allow but don't track */
      atomic_fetch_add (&protect->stat_allowed, 1);
      pthread_mutex_unlock (&protect->mutex);
      return SYN_ACTION_ALLOW;
    }

  /* Apply time-based score decay */
  apply_score_decay (&entry->state, &protect->config,
                     now_ms - entry->state.last_attempt_ms);

  /* Rotate sliding window if needed */
  rotate_window_if_needed (&entry->state, now_ms,
                           protect->config.window_duration_ms);

  /* Increment attempt counter */
  entry->state.attempts_current++;
  entry->state.last_attempt_ms = now_ms;

  /* Apply attempt penalty */
  penalize_attempt (&entry->state, &protect->config);

  /* Calculate effective attempt rate */
  effective_attempts = calculate_effective_attempts (
      &entry->state, now_ms, protect->config.window_duration_ms);

  /* Determine action */
  action = determine_action (&entry->state, &protect->config, effective_attempts);

  /* Auto-block if action is BLOCK and not already blocked */
  if (action == SYN_ACTION_BLOCK && entry->state.block_until_ms == 0)
    {
      entry->state.block_until_ms
          = now_ms + protect->config.block_duration_ms;
    }

  /* Update statistics */
  switch (action)
    {
    case SYN_ACTION_ALLOW:
      atomic_fetch_add (&protect->stat_allowed, 1);
      break;
    case SYN_ACTION_THROTTLE:
      atomic_fetch_add (&protect->stat_throttled, 1);
      break;
    case SYN_ACTION_CHALLENGE:
      atomic_fetch_add (&protect->stat_challenged, 1);
      break;
    case SYN_ACTION_BLOCK:
      atomic_fetch_add (&protect->stat_blocked, 1);
      break;
    }

  /* Copy state if requested */
  if (state_out != NULL)
    memcpy (state_out, &entry->state, sizeof (*state_out));

  pthread_mutex_unlock (&protect->mutex);

  return action;
}

void
SocketSYNProtect_report_success (T protect, const char *client_ip)
{
  SocketSYN_IPEntry *entry;

  assert (protect != NULL);

  if (client_ip == NULL || client_ip[0] == '\0')
    return;

  pthread_mutex_lock (&protect->mutex);

  entry = find_ip_entry (protect, client_ip);
  if (entry != NULL)
    {
      lru_touch (protect, entry);
      reward_success (&entry->state, &protect->config);

      /* Clear block if score recovered */
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
  int64_t now_ms = Socket_get_monotonic_ms ();

  (void)error_code; /* May be used for future enhancements */

  assert (protect != NULL);

  if (client_ip == NULL || client_ip[0] == '\0')
    return;

  pthread_mutex_lock (&protect->mutex);

  entry = find_ip_entry (protect, client_ip);
  if (entry != NULL)
    {
      lru_touch (protect, entry);
      penalize_failure (&entry->state, &protect->config);

      /* Auto-block on severe score drop */
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

  assert (protect != NULL);

  if (ip == NULL || ip[0] == '\0')
    return 0;

  pthread_mutex_lock (&protect->mutex);

  /* Check capacity */
  if (protect->whitelist_count >= protect->config.max_whitelist)
    {
      pthread_mutex_unlock (&protect->mutex);
      return 0;
    }

  /* Check if already exists */
  bucket = synprotect_hash_ip (ip, SOCKET_SYN_LIST_HASH_SIZE);
  entry = protect->whitelist_table[bucket];
  while (entry != NULL)
    {
      if (!entry->is_cidr && strcmp (entry->ip, ip) == 0)
        {
          pthread_mutex_unlock (&protect->mutex);
          return 1; /* Already exists */
        }
      entry = entry->next;
    }

  /* Create new entry */
  entry = alloc_zeroed (protect, 1, sizeof (*entry));
  if (entry == NULL)
    {
      pthread_mutex_unlock (&protect->mutex);
      return 0;
    }

  strncpy (entry->ip, ip, SOCKET_IP_MAX_LEN - 1);
  entry->ip[SOCKET_IP_MAX_LEN - 1] = '\0';
  entry->is_cidr = 0;

  /* Insert into hash table */
  entry->next = protect->whitelist_table[bucket];
  protect->whitelist_table[bucket] = entry;
  protect->whitelist_count++;

  pthread_mutex_unlock (&protect->mutex);
  return 1;
}

int
SocketSYNProtect_whitelist_add_cidr (T protect, const char *cidr)
{
  SocketSYN_WhitelistEntry *entry;
  char ip_part[SOCKET_IP_MAX_LEN];
  const char *slash;
  int prefix_len;
  unsigned bucket;

  assert (protect != NULL);

  if (cidr == NULL || cidr[0] == '\0')
    return 0;

  /* Parse CIDR notation */
  slash = strchr (cidr, '/');
  if (slash == NULL)
    {
      /* No prefix - treat as single IP */
      return SocketSYNProtect_whitelist_add (protect, cidr);
    }

  /* Extract IP part */
  size_t ip_len = (size_t) (slash - cidr);
  if (ip_len >= SOCKET_IP_MAX_LEN)
    return 0;

  memcpy (ip_part, cidr, ip_len);
  ip_part[ip_len] = '\0';

  /* Parse prefix length */
  prefix_len = atoi (slash + 1);
  if (prefix_len < 0 || prefix_len > 128)
    return 0;

  pthread_mutex_lock (&protect->mutex);

  /* Check capacity */
  if (protect->whitelist_count >= protect->config.max_whitelist)
    {
      pthread_mutex_unlock (&protect->mutex);
      return 0;
    }

  /* Create new entry */
  entry = alloc_zeroed (protect, 1, sizeof (*entry));
  if (entry == NULL)
    {
      pthread_mutex_unlock (&protect->mutex);
      return 0;
    }

  strncpy (entry->ip, cidr, SOCKET_IP_MAX_LEN - 1);
  entry->ip[SOCKET_IP_MAX_LEN - 1] = '\0';
  entry->is_cidr = 1;
  entry->prefix_len = (uint8_t)prefix_len;

  /* Parse IP address */
  entry->addr_family
      = parse_ip_address (ip_part, entry->addr_bytes, sizeof (entry->addr_bytes));
  if (entry->addr_family == 0)
    {
      free_memory (protect, entry);
      pthread_mutex_unlock (&protect->mutex);
      return 0;
    }

  /* Insert into hash table (use network address for bucket) */
  bucket = synprotect_hash_ip (ip_part, SOCKET_SYN_LIST_HASH_SIZE);
  entry->next = protect->whitelist_table[bucket];
  protect->whitelist_table[bucket] = entry;
  protect->whitelist_count++;

  pthread_mutex_unlock (&protect->mutex);
  return 1;
}

void
SocketSYNProtect_whitelist_remove (T protect, const char *ip)
{
  SocketSYN_WhitelistEntry **pp;
  unsigned bucket;

  assert (protect != NULL);

  if (ip == NULL || ip[0] == '\0')
    return;

  pthread_mutex_lock (&protect->mutex);

  bucket = synprotect_hash_ip (ip, SOCKET_SYN_LIST_HASH_SIZE);
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

  if (ip == NULL || ip[0] == '\0')
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

int
SocketSYNProtect_blacklist_add (T protect, const char *ip, int duration_ms)
{
  SocketSYN_BlacklistEntry *entry;
  unsigned bucket;
  int64_t now_ms;

  assert (protect != NULL);

  if (ip == NULL || ip[0] == '\0')
    return 0;

  now_ms = Socket_get_monotonic_ms ();

  pthread_mutex_lock (&protect->mutex);

  /* Check capacity */
  if (protect->blacklist_count >= protect->config.max_blacklist)
    {
      pthread_mutex_unlock (&protect->mutex);
      return 0;
    }

  /* Check if already exists and update expiry */
  bucket = synprotect_hash_ip (ip, SOCKET_SYN_LIST_HASH_SIZE);
  entry = protect->blacklist_table[bucket];
  while (entry != NULL)
    {
      if (strcmp (entry->ip, ip) == 0)
        {
          /* Update expiry */
          entry->expires_ms
              = (duration_ms > 0) ? (now_ms + duration_ms) : 0;
          pthread_mutex_unlock (&protect->mutex);
          return 1;
        }
      entry = entry->next;
    }

  /* Create new entry */
  entry = alloc_zeroed (protect, 1, sizeof (*entry));
  if (entry == NULL)
    {
      pthread_mutex_unlock (&protect->mutex);
      return 0;
    }

  strncpy (entry->ip, ip, SOCKET_IP_MAX_LEN - 1);
  entry->ip[SOCKET_IP_MAX_LEN - 1] = '\0';
  entry->expires_ms = (duration_ms > 0) ? (now_ms + duration_ms) : 0;

  /* Insert into hash table */
  entry->next = protect->blacklist_table[bucket];
  protect->blacklist_table[bucket] = entry;
  protect->blacklist_count++;

  pthread_mutex_unlock (&protect->mutex);
  return 1;
}

void
SocketSYNProtect_blacklist_remove (T protect, const char *ip)
{
  SocketSYN_BlacklistEntry **pp;
  unsigned bucket;

  assert (protect != NULL);

  if (ip == NULL || ip[0] == '\0')
    return;

  pthread_mutex_lock (&protect->mutex);

  bucket = synprotect_hash_ip (ip, SOCKET_SYN_LIST_HASH_SIZE);
  pp = &protect->blacklist_table[bucket];

  while (*pp != NULL)
    {
      if (strcmp ((*pp)->ip, ip) == 0)
        {
          SocketSYN_BlacklistEntry *to_remove = *pp;
          *pp = to_remove->next;
          free_memory (protect, to_remove);
          protect->blacklist_count--;
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

  if (ip == NULL || ip[0] == '\0')
    return 0;

  now_ms = Socket_get_monotonic_ms ();

  pthread_mutex_lock (&protect->mutex);
  result = blacklist_check (protect, ip, now_ms);
  pthread_mutex_unlock (&protect->mutex);

  return result;
}

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

  pthread_mutex_unlock (&protect->mutex);
}

/* ============================================================================
 * Public API Implementation - Query and Statistics
 * ============================================================================ */

int
SocketSYNProtect_get_ip_state (T protect, const char *ip,
                               SocketSYN_IPState *state)
{
  SocketSYN_IPEntry *entry;

  assert (protect != NULL);
  assert (state != NULL);

  if (ip == NULL || ip[0] == '\0')
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

void
SocketSYNProtect_stats (T protect, SocketSYNProtect_Stats *stats)
{
  int64_t now_ms;
  size_t blocked_count = 0;

  assert (protect != NULL);
  assert (stats != NULL);

  now_ms = Socket_get_monotonic_ms ();

  pthread_mutex_lock (&protect->mutex);

  /* Count currently blocked IPs */
  for (size_t i = 0; i < protect->ip_table_size; i++)
    {
      SocketSYN_IPEntry *entry = protect->ip_table[i];
      while (entry != NULL)
        {
          if (entry->state.block_until_ms > now_ms)
            blocked_count++;
          entry = entry->hash_next;
        }
    }

  stats->total_attempts = atomic_load (&protect->stat_attempts);
  stats->total_allowed = atomic_load (&protect->stat_allowed);
  stats->total_throttled = atomic_load (&protect->stat_throttled);
  stats->total_challenged = atomic_load (&protect->stat_challenged);
  stats->total_blocked = atomic_load (&protect->stat_blocked);
  stats->total_whitelisted = atomic_load (&protect->stat_whitelisted);
  stats->total_blacklisted = atomic_load (&protect->stat_blacklisted);
  stats->current_tracked_ips = protect->ip_entry_count;
  stats->current_blocked_ips = blocked_count + protect->blacklist_count;
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
  /* Don't reset lru_evictions as it's a lifetime counter */
}

const char *
SocketSYNProtect_action_name (SocketSYN_Action action)
{
  if (action >= 0 && action <= SYN_ACTION_BLOCK)
    return action_names[action];
  return "UNKNOWN";
}

const char *
SocketSYNProtect_reputation_name (SocketSYN_Reputation rep)
{
  if (rep >= 0 && rep <= SYN_REP_HOSTILE)
    return reputation_names[rep];
  return "UNKNOWN";
}

/* ============================================================================
 * Public API Implementation - Maintenance
 * ============================================================================ */

size_t
SocketSYNProtect_cleanup (T protect)
{
  size_t removed = 0;
  int64_t now_ms;

  assert (protect != NULL);

  now_ms = Socket_get_monotonic_ms ();

  pthread_mutex_lock (&protect->mutex);

  /* Clean up expired blacklist entries */
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
              removed++;
            }
          else
            {
              pp = &(*pp)->next;
            }
        }
    }

  /* Clean up expired IP blocks */
  for (size_t i = 0; i < protect->ip_table_size; i++)
    {
      SocketSYN_IPEntry *entry = protect->ip_table[i];
      while (entry != NULL)
        {
          if (entry->state.block_until_ms > 0
              && entry->state.block_until_ms <= now_ms)
            {
              entry->state.block_until_ms = 0;
            }
          entry = entry->hash_next;
        }
    }

  pthread_mutex_unlock (&protect->mutex);

  return removed;
}

void
SocketSYNProtect_clear_all (T protect)
{
  assert (protect != NULL);

  pthread_mutex_lock (&protect->mutex);

  /* Clear all IP entries */
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


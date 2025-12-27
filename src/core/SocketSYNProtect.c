/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include "core/SocketSYNProtect-private.h"
#include "core/SocketSYNProtect.h"

#include "core/SocketConfig.h"
#include "core/SocketCrypto.h"
#include "core/SocketMetrics.h"
#include "core/SocketUtil.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/auxv.h>
#endif

#define T SocketSYNProtect_T

const Except_T SocketSYNProtect_Failed
    = { &SocketSYNProtect_Failed, "SYN protection operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketSYNProtect);

static const char *const action_names[]
    = { "ALLOW", "THROTTLE", "CHALLENGE", "BLOCK" };

static const char *const reputation_names[]
    = { "TRUSTED", "NEUTRAL", "SUSPECT", "HOSTILE" };

#define ACTION_NAMES_COUNT (sizeof (action_names) / sizeof (action_names[0]))
#define REPUTATION_NAMES_COUNT                                                \
  (sizeof (reputation_names) / sizeof (reputation_names[0]))

/* Generate fallback seed from multiple entropy sources */
static unsigned
synprotect_get_fallback_seed (void)
{
  unsigned seed = 0;

#ifdef __linux__
  /* Use AT_RANDOM from aux vector (kernel-provided random at exec) */
  unsigned long at_random = getauxval (AT_RANDOM);
  if (at_random != 0)
    {
      const unsigned char *random_bytes = (const unsigned char *)at_random;
      seed ^= (unsigned)random_bytes[0];
      seed ^= (unsigned)random_bytes[1] << 8;
      seed ^= (unsigned)random_bytes[2] << 16;
      seed ^= (unsigned)random_bytes[3] << 24;
    }
#endif

  seed ^= (unsigned)getpid ();
  seed ^= (unsigned)(uintptr_t)&seed;
  seed ^= (unsigned)Socket_get_monotonic_ms ();
  seed = socket_util_hash_uint (seed, UINT_MAX);

  if (seed == 0)
    seed = SOCKET_SYN_FALLBACK_SEED;

  return seed;
}

static void *
alloc_zeroed (T protect, size_t count, size_t size)
{
  if (protect->arena != NULL)
    return Arena_calloc (protect->arena, count, size, __FILE__, __LINE__);
  return calloc (count, size);
}

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

static void
init_ip_state (SocketSYN_IPState *state, const char *ip, int64_t now_ms)
{
  memset (state, 0, sizeof (*state));
  socket_util_safe_copy_ip (state->ip, ip, SOCKET_IP_MAX_LEN);
  state->window_start_ms = now_ms;
  state->last_attempt_ms = now_ms;
  state->rep = SYN_REP_NEUTRAL;
  state->score = SOCKET_SYN_INITIAL_SCORE;
}

static SocketSYN_IPEntry *
create_ip_entry (T protect, const char *ip, int64_t now_ms)
{
  SocketSYN_IPEntry *entry;
  unsigned bucket;

  while (protect->use_malloc
         && protect->ip_entry_count >= protect->config.max_tracked_ips)
    evict_lru_entry (protect);

  if (protect->ip_entry_count >= protect->config.max_tracked_ips)
    return NULL;

  entry = alloc_zeroed (protect, 1, sizeof (*entry));
  if (entry == NULL)
    return NULL;

  init_ip_state (&entry->state, ip, now_ms);

  bucket = synprotect_hash_ip (protect, ip, protect->ip_table_size);
  entry->hash_next = protect->ip_table[bucket];
  protect->ip_table[bucket] = entry;

  lru_push_front (protect, entry);
  protect->ip_entry_count++;
  SocketMetrics_gauge_set (SOCKET_GAU_SYNPROTECT_TRACKED_IPS,
                           protect->ip_entry_count);

  return entry;
}

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

static float
calculate_window_progress (int64_t elapsed, int window_ms)
{
  if (elapsed < 0)
    elapsed = 0;
  if (elapsed > window_ms)
    elapsed = window_ms;

  return (float)elapsed / (float)window_ms;
}

/* Hash IP with instance-specific seed for collision resistance */
unsigned
synprotect_hash_ip (T protect, const char *ip, unsigned table_size)
{
  assert (ip != NULL);
  assert (protect != NULL);

  unsigned h = socket_util_hash_djb2 (ip, table_size);
  h ^= protect->hash_seed;
  h = socket_util_hash_uint (h, table_size);
  return h % table_size;
}

/* Calculate weighted attempt count using linear interpolation */
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
         + (uint32_t)(state->attempts_previous * previous_weight);
}

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

static void
penalize_attempt (SocketSYN_IPState *state,
                  const SocketSYNProtect_Config *config)
{
  state->score
      = synprotect_clamp_score (state->score - config->score_penalty_attempt);
  update_reputation_from_score (state, config);
}

static void
penalize_failure (SocketSYN_IPState *state,
                  const SocketSYNProtect_Config *config)
{
  state->score
      = synprotect_clamp_score (state->score - config->score_penalty_failure);
  state->failures++;
  update_reputation_from_score (state, config);
}

static void
reward_success (SocketSYN_IPState *state,
                const SocketSYNProtect_Config *config)
{
  state->score
      = synprotect_clamp_score (state->score + config->score_reward_success);
  state->successes++;
  update_reputation_from_score (state, config);
}

static int
is_currently_blocked (const SocketSYN_IPState *state, int64_t now_ms)
{
  return (state->block_until_ms > 0 && now_ms < state->block_until_ms);
}

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

static void
fill_ip_state_out (SocketSYN_IPState *state_out, const char *ip,
                   SocketSYN_Reputation rep, float score)
{
  if (state_out == NULL)
    return;

  memset (state_out, 0, sizeof (*state_out));
  socket_util_safe_copy_ip (state_out->ip, ip, SOCKET_IP_MAX_LEN);
  state_out->rep = rep;
  state_out->score = score;
}

static void
handle_whitelisted_ip (T protect, const char *client_ip,
                       SocketSYN_IPState *state_out)
{
  atomic_fetch_add (&protect->stat_whitelisted, 1);
  SocketMetrics_counter_inc (SOCKET_CTR_SYNPROTECT_WHITELISTED);
  atomic_fetch_add (&protect->stat_allowed, 1);
  SocketMetrics_counter_inc (SOCKET_CTR_SYNPROTECT_ALLOWED);
  fill_ip_state_out (state_out, client_ip, SYN_REP_TRUSTED,
                     SOCKET_SYN_TRUSTED_SCORE);
}

static void
handle_blacklisted_ip (T protect, const char *client_ip,
                       SocketSYN_IPState *state_out)
{
  atomic_fetch_add (&protect->stat_blacklisted, 1);
  SocketMetrics_counter_inc (SOCKET_CTR_SYNPROTECT_BLACKLISTED);
  atomic_fetch_add (&protect->stat_blocked, 1);
  SocketMetrics_counter_inc (SOCKET_CTR_SYNPROTECT_BLOCKED);
  fill_ip_state_out (state_out, client_ip, SYN_REP_HOSTILE, 0.0f);
}

static void
update_action_stats (T protect, SocketSYN_Action action)
{
  switch (action)
    {
    case SYN_ACTION_ALLOW:
      atomic_fetch_add (&protect->stat_allowed, 1);
      SocketMetrics_counter_inc (SOCKET_CTR_SYNPROTECT_ALLOWED);
      break;
    case SYN_ACTION_THROTTLE:
      atomic_fetch_add (&protect->stat_throttled, 1);
      SocketMetrics_counter_inc (SOCKET_CTR_SYNPROTECT_THROTTLED);
      break;
    case SYN_ACTION_CHALLENGE:
      atomic_fetch_add (&protect->stat_challenged, 1);
      SocketMetrics_counter_inc (SOCKET_CTR_SYNPROTECT_CHALLENGED);
      break;
    case SYN_ACTION_BLOCK:
      atomic_fetch_add (&protect->stat_blocked, 1);
      SocketMetrics_counter_inc (SOCKET_CTR_SYNPROTECT_BLOCKED);
      break;
    }
}

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
      SocketMetrics_gauge_inc (SOCKET_GAU_SYNPROTECT_BLOCKED_IPS);
    }

  return action;
}

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

typedef enum
{
  SYN_CLEANUP_NONE = 0,
  SYN_CLEANUP_MUTEX,
  SYN_CLEANUP_IP_TABLE,
  SYN_CLEANUP_WHITELIST,
  SYN_CLEANUP_BLACKLIST,
  SYN_CLEANUP_LIMITER
} SYN_CleanupStage;

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

static int
init_ip_hash_table (T protect)
{
  protect->ip_table_size = SOCKET_SYN_IP_HASH_SIZE;
  protect->ip_table = alloc_zeroed (protect, protect->ip_table_size,
                                    sizeof (SocketSYN_IPEntry *));
  return (protect->ip_table != NULL);
}

static int
init_whitelist_table (T protect)
{
  protect->whitelist_table = alloc_zeroed (
      protect, SOCKET_SYN_LIST_HASH_SIZE, sizeof (SocketSYN_WhitelistEntry *));
  return (protect->whitelist_table != NULL);
}

static int
init_blacklist_table (T protect)
{
  protect->blacklist_table = alloc_zeroed (
      protect, SOCKET_SYN_LIST_HASH_SIZE, sizeof (SocketSYN_BlacklistEntry *));
  return (protect->blacklist_table != NULL);
}

static int
init_global_limiter (T protect, const SocketSYNProtect_Config *config)
{
  TRY protect->global_limiter = SocketRateLimit_new (
      protect->arena, (size_t)config->max_global_per_second,
      (size_t)config->max_global_per_second);
  EXCEPT (SocketRateLimit_Failed)
  return 0;
  END_TRY;
  return 1;
}

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

static int
parse_cidr_notation (const char *cidr, char *ip_out, size_t ip_out_size,
                     int *prefix_out)
{
  const char *slash = strchr (cidr, '/');
  size_t ip_len;

  if (slash == NULL)
    return 0;

  ip_len = (size_t)(slash - cidr);
  if (ip_len >= ip_out_size)
    return 0;

  memcpy (ip_out, cidr, ip_len);
  ip_out[ip_len] = '\0';

  const char *prefix_str = slash + 1;
  char *endptr;
  errno = 0; /* Reset errno before strtol to detect ERANGE accurately */
  long prefix_long = strtol (prefix_str, &endptr, 10);
  if (prefix_str == endptr || *endptr != '\0' || errno == ERANGE
      || prefix_long < 0 || prefix_long > SOCKET_IPV6_MAX_PREFIX)
    {
      return 0;
    }
  *prefix_out = (int)prefix_long;

  return 1;
}

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

static void
insert_whitelist_entry (T protect, SocketSYN_WhitelistEntry *entry,
                        unsigned bucket)
{
  entry->next = protect->whitelist_table[bucket];
  protect->whitelist_table[bucket] = entry;
  protect->whitelist_count++;
}

static void
insert_blacklist_entry (T protect, SocketSYN_BlacklistEntry *entry,
                        unsigned bucket)
{
  entry->next = protect->blacklist_table[bucket];
  protect->blacklist_table[bucket] = entry;
  protect->blacklist_count++;
  SocketMetrics_gauge_inc (SOCKET_GAU_SYNPROTECT_BLOCKED_IPS);
}

static SocketSYN_WhitelistEntry *
create_whitelist_entry (T protect, const char *ip, int is_cidr)
{
  SocketSYN_WhitelistEntry *entry;

  entry = alloc_zeroed (protect, 1, sizeof (*entry));
  if (entry == NULL)
    return NULL;

  socket_util_safe_copy_ip (entry->ip, ip, SOCKET_IP_MAX_LEN);
  entry->is_cidr = is_cidr;
  return entry;
}

static SocketSYN_BlacklistEntry *
create_blacklist_entry (T protect, const char *ip, int64_t expires_ms)
{
  SocketSYN_BlacklistEntry *entry;

  entry = alloc_zeroed (protect, 1, sizeof (*entry));
  if (entry == NULL)
    return NULL;

  socket_util_safe_copy_ip (entry->ip, ip, SOCKET_IP_MAX_LEN);
  entry->expires_ms = expires_ms;
  return entry;
}

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
  config->hash_seed = 0;
}

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

  /* Harden config: Clamp invalid values to prevent misconfig DoS/OOM */
  SocketSYNProtect_Config *cfg = local_config;

  if (cfg->window_duration_ms <= 0)
    cfg->window_duration_ms = SOCKET_SYN_DEFAULT_WINDOW_MS;
  if (cfg->window_duration_ms > SOCKET_SYN_MAX_WINDOW_MS)
    cfg->window_duration_ms = SOCKET_SYN_MAX_WINDOW_MS;

  if (cfg->max_attempts_per_window <= 0)
    cfg->max_attempts_per_window = SOCKET_SYN_DEFAULT_MAX_PER_WINDOW;
  if (cfg->max_attempts_per_window > SOCKET_SYN_MAX_ATTEMPTS_CAP)
    cfg->max_attempts_per_window = SOCKET_SYN_MAX_ATTEMPTS_CAP;

  if (cfg->max_global_per_second <= 0)
    cfg->max_global_per_second = SOCKET_SYN_DEFAULT_GLOBAL_PER_SEC;
  if (cfg->max_global_per_second > SOCKET_SYN_MAX_GLOBAL_PER_SEC_CAP)
    cfg->max_global_per_second = SOCKET_SYN_MAX_GLOBAL_PER_SEC_CAP;

  /* Ensure logical order: 1.0 >= throttle >= challenge >= block >= 0.0 */
  cfg->score_throttle = synprotect_clamp_score (cfg->score_throttle);
  cfg->score_challenge = synprotect_clamp_score (cfg->score_challenge);
  cfg->score_block = synprotect_clamp_score (cfg->score_block);
  if (cfg->score_challenge > cfg->score_throttle)
    cfg->score_challenge
        = cfg->score_throttle * SOCKET_SYN_CHALLENGE_ADJUST_FACTOR;
  if (cfg->score_block > cfg->score_challenge)
    cfg->score_block = cfg->score_challenge * SOCKET_SYN_BLOCK_ADJUST_FACTOR;

  if (cfg->max_tracked_ips == 0)
    cfg->max_tracked_ips = SOCKET_SYN_DEFAULT_MAX_TRACKED_IPS;
  if (cfg->max_tracked_ips > SOCKET_SYN_MAX_TRACKED_IPS_CAP)
    cfg->max_tracked_ips = SOCKET_SYN_MAX_TRACKED_IPS_CAP;

  if (cfg->max_whitelist == 0)
    cfg->max_whitelist = SOCKET_SYN_DEFAULT_MAX_WHITELIST;
  if (cfg->max_whitelist > SOCKET_SYN_MAX_LIST_CAP)
    cfg->max_whitelist = SOCKET_SYN_MAX_LIST_CAP;

  if (cfg->max_blacklist == 0)
    cfg->max_blacklist = SOCKET_SYN_DEFAULT_MAX_BLACKLIST;
  if (cfg->max_blacklist > SOCKET_SYN_MAX_LIST_CAP)
    cfg->max_blacklist = SOCKET_SYN_MAX_LIST_CAP;

  if (cfg->score_decay_per_sec < 0.0f)
    cfg->score_decay_per_sec = SOCKET_SYN_DEFAULT_SCORE_DECAY;
  if (cfg->score_penalty_attempt < 0.0f)
    cfg->score_penalty_attempt = SOCKET_SYN_DEFAULT_PENALTY_ATTEMPT;
  if (cfg->score_penalty_failure < 0.0f)
    cfg->score_penalty_failure = SOCKET_SYN_DEFAULT_PENALTY_FAILURE;
  if (cfg->score_reward_success < 0.0f)
    cfg->score_reward_success = SOCKET_SYN_DEFAULT_REWARD_SUCCESS;

  return local_config;
}

static T
synprotect_alloc_structure (Arena_T arena)
{
  if (arena != NULL)
    return Arena_alloc (arena, sizeof (struct SocketSYNProtect_T), __FILE__,
                        __LINE__);
  return malloc (sizeof (struct SocketSYNProtect_T));
}

/* Hash seed uses crypto randomness when available, fallback to multiple
 * entropy sources */
static void
synprotect_init_base (T protect, Arena_T arena,
                      const SocketSYNProtect_Config *config)
{
  memset (protect, 0, sizeof (*protect));
  protect->arena = arena;
  protect->use_malloc = (arena == NULL);
  memcpy (&protect->config, config, sizeof (protect->config));

  if (protect->config.hash_seed == 0)
    {
      TRY
      {
        if (SocketCrypto_random_bytes (&protect->hash_seed,
                                       sizeof (protect->hash_seed))
            != 0)
          {
            protect->hash_seed = synprotect_get_fallback_seed ();
          }
      }
      EXCEPT (SocketCrypto_Failed)
      {
        protect->hash_seed = synprotect_get_fallback_seed ();
      }
      END_TRY;
    }
  else
    {
      protect->hash_seed = protect->config.hash_seed;
    }
}

static int
synprotect_init_mutex (T protect)
{
  if (pthread_mutex_init (&protect->mutex, NULL) != 0)
    return 0;

  protect->initialized = SOCKET_MUTEX_INITIALIZED;
  return 1;
}

static void
synprotect_finalize (T protect)
{
  protect->start_time_ms = Socket_get_monotonic_ms ();
  init_atomic_stats (protect);
  SocketMetrics_gauge_set (SOCKET_GAU_SYNPROTECT_TRACKED_IPS, 0);
  SocketMetrics_gauge_set (SOCKET_GAU_SYNPROTECT_BLOCKED_IPS, 0);
}

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

  return -1;
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

  if (p->initialized == SOCKET_MUTEX_INITIALIZED)
    pthread_mutex_destroy (&p->mutex);

  if (p->global_limiter != NULL)
    SocketRateLimit_free (&p->global_limiter);

  if (p->use_malloc)
    {
      free_ip_entries (p);
      free_whitelist_entries (p);
      free_blacklist_entries (p);
      SocketMetrics_gauge_set (SOCKET_GAU_SYNPROTECT_TRACKED_IPS, 0);
      SocketMetrics_gauge_set (SOCKET_GAU_SYNPROTECT_BLOCKED_IPS, 0);
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
  SocketMetrics_counter_inc (SOCKET_CTR_SYNPROTECT_ATTEMPTS_TOTAL);

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

int
SocketSYNProtect_whitelist_add (T protect, const char *ip)
{
  SocketSYN_WhitelistEntry *entry;
  unsigned bucket;
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];

  assert (protect != NULL);

  if (!SOCKET_VALID_IP_STRING (ip))
    return 0;

  if (parse_ip_address (ip, addr_bytes, sizeof (addr_bytes)) == 0)
    return 0;

  pthread_mutex_lock (&protect->mutex);

  if (protect->whitelist_count >= protect->config.max_whitelist)
    {
      pthread_mutex_unlock (&protect->mutex);
      return 0;
    }

  bucket = synprotect_hash_ip (protect, ip, SOCKET_SYN_LIST_HASH_SIZE);

  if (find_whitelist_entry_exact (protect->whitelist_table[bucket], ip)
      != NULL)
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

static int
setup_cidr_entry (SocketSYN_WhitelistEntry *entry, const char *ip_part,
                  int prefix_len)
{
  entry->prefix_len = (uint8_t)prefix_len;
  entry->addr_family = parse_ip_address (ip_part, entry->addr_bytes,
                                         sizeof (entry->addr_bytes));
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

  /* Warn on overly broad CIDR (/0 matches all in family) */
  if (prefix_len == 0)
    {
      SOCKET_LOG_WARN_MSG ("Adding /0 CIDR - matches all IPs in family %d, "
                           "potential security risk: %s",
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
          SocketMetrics_gauge_dec (SOCKET_GAU_SYNPROTECT_BLOCKED_IPS);
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

  int64_t now_ms = Socket_get_monotonic_ms ();
  size_t timed_blocked = count_currently_blocked (protect, now_ms);
  SocketMetrics_gauge_set (SOCKET_GAU_SYNPROTECT_BLOCKED_IPS, timed_blocked);

  pthread_mutex_unlock (&protect->mutex);
}

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
              SocketMetrics_gauge_dec (SOCKET_GAU_SYNPROTECT_BLOCKED_IPS);
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
              SocketMetrics_gauge_dec (SOCKET_GAU_SYNPROTECT_BLOCKED_IPS);
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
  SocketMetrics_gauge_set (SOCKET_GAU_SYNPROTECT_TRACKED_IPS, 0);
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

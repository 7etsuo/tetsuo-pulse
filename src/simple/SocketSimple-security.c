/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-security.c
 * @brief Security implementation for Simple API.
 *
 * Wraps SocketSYNProtect and SocketIPTracker modules with exception-safe
 * Simple API patterns.
 */

#include "SocketSimple-internal.h"
#include "simple/SocketSimple-security.h"

#include "core/SocketConfig.h"
#include "core/SocketIPTracker.h"
#include "core/SocketSYNProtect.h"

struct SocketSimple_SYNProtect
{
  SocketSYNProtect_T protect;
};

struct SocketSimple_IPTracker
{
  SocketIPTracker_T tracker;
};

/**
 * @brief Common pattern for wrapping core security objects in Simple API
 * handles.
 *
 * This macro extracts the duplicated pattern from Socket_simple_syn_new and
 * Socket_simple_ip_tracker_new, providing consistent error handling and
 * memory management.
 *
 * @param CORE_TYPE      Core module type (e.g., SocketSYNProtect_T)
 * @param CORE_VAR       Variable name for core object (e.g., protect)
 * @param HANDLE_TYPE    Simple API handle type (e.g., struct
 * SocketSimple_SYNProtect)
 * @param HANDLE_VAR     Variable name for handle (e.g., handle)
 * @param CORE_CREATE    Expression to create core object (e.g.,
 * SocketSYNProtect_new(...))
 * @param CORE_FREE      Function to free core object (e.g.,
 * SocketSYNProtect_free)
 * @param CORE_EXCEPTION Exception type to catch (e.g., SocketSYNProtect_Failed)
 * @param ERROR_MSG      Error message string literal
 * @param MEMBER_NAME    Name of member in handle struct (e.g., protect)
 */
#define SIMPLE_SECURITY_WRAP_NEW(CORE_TYPE,                         \
                                 CORE_VAR,                          \
                                 HANDLE_TYPE,                       \
                                 HANDLE_VAR,                        \
                                 CORE_CREATE,                       \
                                 CORE_FREE,                         \
                                 CORE_EXCEPTION,                    \
                                 ERROR_MSG,                         \
                                 MEMBER_NAME)                       \
  do                                                                \
    {                                                               \
      volatile CORE_TYPE CORE_VAR = NULL;                           \
      HANDLE_TYPE *HANDLE_VAR = NULL;                               \
                                                                    \
      Socket_simple_clear_error ();                                 \
                                                                    \
      TRY                                                           \
      {                                                             \
        CORE_VAR = CORE_CREATE;                                     \
      }                                                             \
      EXCEPT (CORE_EXCEPTION)                                       \
      {                                                             \
        simple_set_error (SOCKET_SIMPLE_ERR_SECURITY, ERROR_MSG);   \
        return NULL;                                                \
      }                                                             \
      END_TRY;                                                      \
                                                                    \
      if (!CORE_VAR)                                                \
        {                                                           \
          simple_set_error (SOCKET_SIMPLE_ERR_SECURITY, ERROR_MSG); \
          return NULL;                                              \
        }                                                           \
                                                                    \
      HANDLE_VAR = calloc (1, sizeof (*HANDLE_VAR));                \
      if (!HANDLE_VAR)                                              \
        {                                                           \
          simple_set_error (SOCKET_SIMPLE_ERR_MEMORY,               \
                            "Memory allocation failed");            \
          CORE_FREE ((CORE_TYPE *)&CORE_VAR);                       \
          return NULL;                                              \
        }                                                           \
                                                                    \
      HANDLE_VAR->MEMBER_NAME = CORE_VAR;                           \
      return HANDLE_VAR;                                            \
    }                                                               \
  while (0)

void
Socket_simple_syn_config_init (SocketSimple_SYNConfig *config)
{
  if (!config)
    return;
  memset (config, 0, sizeof (*config));
  config->window_duration_ms = SOCKET_SYN_DEFAULT_WINDOW_MS;
  config->max_attempts_per_window = SOCKET_SYN_DEFAULT_MAX_PER_WINDOW;
  config->max_global_per_second = SOCKET_SYN_DEFAULT_GLOBAL_PER_SEC;
  config->min_success_ratio = SOCKET_SYN_DEFAULT_MIN_SUCCESS_RATIO;
  config->throttle_delay_ms = SOCKET_SYN_DEFAULT_THROTTLE_DELAY_MS;
  config->block_duration_ms = SOCKET_SYN_DEFAULT_BLOCK_DURATION_MS;
  config->score_throttle = SOCKET_SYN_DEFAULT_SCORE_THROTTLE;
  config->score_challenge = SOCKET_SYN_DEFAULT_SCORE_CHALLENGE;
  config->score_block = SOCKET_SYN_DEFAULT_SCORE_BLOCK;
  config->max_tracked_ips = SOCKET_SYN_DEFAULT_MAX_TRACKED_IPS;
}

SocketSimple_SYNProtect_T
Socket_simple_syn_new (const SocketSimple_SYNConfig *config)
{
  SocketSYNProtect_Config core_config;

  /* Build core config */
  SocketSYNProtect_config_defaults (&core_config);

  if (config)
    {
      core_config.window_duration_ms = config->window_duration_ms;
      core_config.max_attempts_per_window = config->max_attempts_per_window;
      core_config.max_global_per_second = config->max_global_per_second;
      core_config.min_success_ratio = config->min_success_ratio;
      core_config.throttle_delay_ms = config->throttle_delay_ms;
      core_config.block_duration_ms = config->block_duration_ms;
      core_config.score_throttle = config->score_throttle;
      core_config.score_challenge = config->score_challenge;
      core_config.score_block = config->score_block;
      core_config.max_tracked_ips = config->max_tracked_ips;
    }

  SIMPLE_SECURITY_WRAP_NEW (SocketSYNProtect_T,
                            protect,
                            struct SocketSimple_SYNProtect,
                            handle,
                            SocketSYNProtect_new (NULL, &core_config),
                            SocketSYNProtect_free,
                            SocketSYNProtect_Failed,
                            "Failed to create SYN protection",
                            protect);
}

void
Socket_simple_syn_free (SocketSimple_SYNProtect_T *protect)
{
  if (!protect || !*protect)
    return;

  struct SocketSimple_SYNProtect *handle = *protect;

  if (handle->protect)
    {
      SocketSYNProtect_free (&handle->protect);
    }

  free (handle);
  *protect = NULL;
}

SocketSimple_SYNAction
Socket_simple_syn_check (SocketSimple_SYNProtect_T protect,
                         const char *client_ip)
{
  if (!protect || !protect->protect)
    return SOCKET_SIMPLE_SYN_ALLOW;

  SocketSYN_Action action
      = SocketSYNProtect_check (protect->protect, client_ip, NULL);

  switch (action)
    {
    case SYN_ACTION_ALLOW:
      return SOCKET_SIMPLE_SYN_ALLOW;
    case SYN_ACTION_THROTTLE:
      return SOCKET_SIMPLE_SYN_THROTTLE;
    case SYN_ACTION_CHALLENGE:
      return SOCKET_SIMPLE_SYN_CHALLENGE;
    case SYN_ACTION_BLOCK:
      return SOCKET_SIMPLE_SYN_BLOCK;
    default:
      return SOCKET_SIMPLE_SYN_ALLOW;
    }
}

void
Socket_simple_syn_report_success (SocketSimple_SYNProtect_T protect,
                                  const char *client_ip)
{
  if (!protect || !protect->protect || !client_ip)
    return;

  SocketSYNProtect_report_success (protect->protect, client_ip);
}

void
Socket_simple_syn_report_failure (SocketSimple_SYNProtect_T protect,
                                  const char *client_ip)
{
  if (!protect || !protect->protect || !client_ip)
    return;

  SocketSYNProtect_report_failure (protect->protect, client_ip, 0);
}

int
Socket_simple_syn_whitelist_add (SocketSimple_SYNProtect_T protect,
                                 const char *ip)
{
  if (!protect || !protect->protect || !ip)
    return 0;

  return SocketSYNProtect_whitelist_add (protect->protect, ip);
}

int
Socket_simple_syn_whitelist_add_cidr (SocketSimple_SYNProtect_T protect,
                                      const char *cidr)
{
  if (!protect || !protect->protect || !cidr)
    return 0;

  return SocketSYNProtect_whitelist_add_cidr (protect->protect, cidr);
}

void
Socket_simple_syn_whitelist_remove (SocketSimple_SYNProtect_T protect,
                                    const char *ip)
{
  if (!protect || !protect->protect || !ip)
    return;

  SocketSYNProtect_whitelist_remove (protect->protect, ip);
}

int
Socket_simple_syn_whitelist_contains (SocketSimple_SYNProtect_T protect,
                                      const char *ip)
{
  if (!protect || !protect->protect || !ip)
    return 0;

  return SocketSYNProtect_whitelist_contains (protect->protect, ip);
}

int
Socket_simple_syn_blacklist_add (SocketSimple_SYNProtect_T protect,
                                 const char *ip,
                                 int duration_ms)
{
  if (!protect || !protect->protect || !ip)
    return 0;

  return SocketSYNProtect_blacklist_add (protect->protect, ip, duration_ms);
}

void
Socket_simple_syn_blacklist_remove (SocketSimple_SYNProtect_T protect,
                                    const char *ip)
{
  if (!protect || !protect->protect || !ip)
    return;

  SocketSYNProtect_blacklist_remove (protect->protect, ip);
}

int
Socket_simple_syn_blacklist_contains (SocketSimple_SYNProtect_T protect,
                                      const char *ip)
{
  if (!protect || !protect->protect || !ip)
    return 0;

  return SocketSYNProtect_blacklist_contains (protect->protect, ip);
}

int
Socket_simple_syn_stats (SocketSimple_SYNProtect_T protect,
                         SocketSimple_SYNStats *stats)
{
  if (!protect || !protect->protect || !stats)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  SocketSYNProtect_Stats core_stats;
  SocketSYNProtect_stats (protect->protect, &core_stats);

  stats->total_attempts = core_stats.total_attempts;
  stats->total_allowed = core_stats.total_allowed;
  stats->total_throttled = core_stats.total_throttled;
  stats->total_challenged = core_stats.total_challenged;
  stats->total_blocked = core_stats.total_blocked;
  stats->total_whitelisted = core_stats.total_whitelisted;
  stats->total_blacklisted = core_stats.total_blacklisted;
  stats->current_tracked_ips = core_stats.current_tracked_ips;
  stats->current_blocked_ips = core_stats.current_blocked_ips;
  stats->uptime_ms = core_stats.uptime_ms;

  return 0;
}

int
Socket_simple_syn_get_ip_state (SocketSimple_SYNProtect_T protect,
                                const char *ip,
                                SocketSimple_IPState *state)
{
  if (!protect || !protect->protect || !ip || !state)
    return 0;

  SocketSYN_IPState core_state;
  if (!SocketSYNProtect_get_ip_state (protect->protect, ip, &core_state))
    return 0;

  memset (state, 0, sizeof (*state));
  /* Safe copy with explicit null termination */
  size_t ip_len = strlen (core_state.ip);
  if (ip_len >= sizeof (state->ip))
    ip_len = sizeof (state->ip) - 1;
  memcpy (state->ip, core_state.ip, ip_len);
  state->ip[ip_len] = '\0';
  state->attempts_current = core_state.attempts_current;
  state->successes = core_state.successes;
  state->failures = core_state.failures;
  state->score = core_state.score;
  state->is_blocked = (core_state.block_until_ms > 0) ? 1 : 0;

  switch (core_state.rep)
    {
    case SYN_REP_TRUSTED:
      state->rep = SOCKET_SIMPLE_REP_TRUSTED;
      break;
    case SYN_REP_NEUTRAL:
      state->rep = SOCKET_SIMPLE_REP_NEUTRAL;
      break;
    case SYN_REP_SUSPECT:
      state->rep = SOCKET_SIMPLE_REP_SUSPECT;
      break;
    case SYN_REP_HOSTILE:
      state->rep = SOCKET_SIMPLE_REP_HOSTILE;
      break;
    default:
      state->rep = SOCKET_SIMPLE_REP_NEUTRAL;
      break;
    }

  return 1;
}

size_t
Socket_simple_syn_cleanup (SocketSimple_SYNProtect_T protect)
{
  if (!protect || !protect->protect)
    return 0;

  return SocketSYNProtect_cleanup (protect->protect);
}

void
Socket_simple_syn_reset (SocketSimple_SYNProtect_T protect)
{
  if (!protect || !protect->protect)
    return;

  SocketSYNProtect_reset (protect->protect);
}

const char *
Socket_simple_syn_action_name (SocketSimple_SYNAction action)
{
  switch (action)
    {
    case SOCKET_SIMPLE_SYN_ALLOW:
      return "ALLOW";
    case SOCKET_SIMPLE_SYN_THROTTLE:
      return "THROTTLE";
    case SOCKET_SIMPLE_SYN_CHALLENGE:
      return "CHALLENGE";
    case SOCKET_SIMPLE_SYN_BLOCK:
      return "BLOCK";
    default:
      return "UNKNOWN";
    }
}

const char *
Socket_simple_syn_reputation_name (SocketSimple_Reputation rep)
{
  switch (rep)
    {
    case SOCKET_SIMPLE_REP_TRUSTED:
      return "TRUSTED";
    case SOCKET_SIMPLE_REP_NEUTRAL:
      return "NEUTRAL";
    case SOCKET_SIMPLE_REP_SUSPECT:
      return "SUSPECT";
    case SOCKET_SIMPLE_REP_HOSTILE:
      return "HOSTILE";
    default:
      return "UNKNOWN";
    }
}

SocketSimple_IPTracker_T
Socket_simple_ip_tracker_new (int max_per_ip)
{
  SIMPLE_SECURITY_WRAP_NEW (SocketIPTracker_T,
                            tracker,
                            struct SocketSimple_IPTracker,
                            handle,
                            SocketIPTracker_new (NULL, max_per_ip),
                            SocketIPTracker_free,
                            SocketIPTracker_Failed,
                            "Failed to create IP tracker",
                            tracker);
}

void
Socket_simple_ip_tracker_free (SocketSimple_IPTracker_T *tracker)
{
  if (!tracker || !*tracker)
    return;

  struct SocketSimple_IPTracker *handle = *tracker;

  if (handle->tracker)
    {
      SocketIPTracker_free (&handle->tracker);
    }

  free (handle);
  *tracker = NULL;
}

int
Socket_simple_ip_tracker_track (SocketSimple_IPTracker_T tracker,
                                const char *ip)
{
  if (!tracker || !tracker->tracker)
    return 1; /* Allow if no tracker */

  if (!ip || !*ip)
    return 1; /* Allow empty IP */

  return SocketIPTracker_track (tracker->tracker, ip);
}

void
Socket_simple_ip_tracker_release (SocketSimple_IPTracker_T tracker,
                                  const char *ip)
{
  if (!tracker || !tracker->tracker || !ip)
    return;

  SocketIPTracker_release (tracker->tracker, ip);
}

int
Socket_simple_ip_tracker_count (SocketSimple_IPTracker_T tracker,
                                const char *ip)
{
  if (!tracker || !tracker->tracker || !ip)
    return 0;

  return SocketIPTracker_count (tracker->tracker, ip);
}

void
Socket_simple_ip_tracker_set_max (SocketSimple_IPTracker_T tracker,
                                  int max_per_ip)
{
  if (!tracker || !tracker->tracker)
    return;

  SocketIPTracker_setmax (tracker->tracker, max_per_ip);
}

int
Socket_simple_ip_tracker_get_max (SocketSimple_IPTracker_T tracker)
{
  if (!tracker || !tracker->tracker)
    return 0;

  return SocketIPTracker_getmax (tracker->tracker);
}

size_t
Socket_simple_ip_tracker_total (SocketSimple_IPTracker_T tracker)
{
  if (!tracker || !tracker->tracker)
    return 0;

  return SocketIPTracker_total (tracker->tracker);
}

size_t
Socket_simple_ip_tracker_unique_ips (SocketSimple_IPTracker_T tracker)
{
  if (!tracker || !tracker->tracker)
    return 0;

  return SocketIPTracker_unique_ips (tracker->tracker);
}

void
Socket_simple_ip_tracker_clear (SocketSimple_IPTracker_T tracker)
{
  if (!tracker || !tracker->tracker)
    return;

  SocketIPTracker_clear (tracker->tracker);
}

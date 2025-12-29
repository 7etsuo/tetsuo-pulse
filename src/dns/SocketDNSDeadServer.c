/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDNSDeadServer.c
 * @brief Dead Server Tracking implementation (RFC 2308 Section 7.2).
 */

#include "dns/SocketDNSDeadServer.h"
#include "core/Arena.h"
#include "core/SocketUtil.h"

#include <pthread.h>
#include <string.h>

#define T SocketDNSDeadServer_T

/**
 * @brief Internal dead server entry structure.
 *
 * Tracks a single nameserver's failure state.
 */
struct DeadServerEntry
{
  char address[DNS_DEAD_SERVER_MAX_ADDR + 1]; /**< Nameserver address */
  int consecutive_failures;                    /**< Consecutive timeout count */
  int64_t marked_dead_ms;                      /**< When marked dead (0 if not dead) */
};

/**
 * @brief Dead server tracker structure.
 */
struct T
{
  Arena_T arena;           /**< Memory arena */
  pthread_mutex_t mutex;   /**< Thread safety */

  struct DeadServerEntry servers[DNS_DEAD_SERVER_MAX_TRACKED];
  int count;               /**< Current tracked server count */
  int threshold;           /**< Failures needed to mark dead */

  /* Statistics */
  uint64_t checks;
  uint64_t dead_hits;
  uint64_t alive_marks;
  uint64_t dead_marks;
  uint64_t expirations;
};

/**
 * @brief Find entry by address (case-insensitive for hostnames).
 */
static struct DeadServerEntry *
find_entry (T tracker, const char *address)
{
  for (int i = 0; i < tracker->count; i++)
    {
      if (strcmp (tracker->servers[i].address, address) == 0)
        return &tracker->servers[i];
    }
  return NULL;
}

/**
 * @brief Remove entry at index, compacting array.
 */
static void
remove_entry_at (T tracker, int index)
{
  if (index < 0 || index >= tracker->count)
    return;

  /* Shift remaining entries down */
  for (int i = index; i < tracker->count - 1; i++)
    tracker->servers[i] = tracker->servers[i + 1];

  tracker->count--;
}

/**
 * @brief Remove entry by pointer.
 */
static void
remove_entry (T tracker, struct DeadServerEntry *entry)
{
  int index = (int)(entry - tracker->servers);
  remove_entry_at (tracker, index);
}

/**
 * @brief Check if a dead marking has expired.
 */
static bool
entry_expired (const struct DeadServerEntry *entry, int64_t now_ms)
{
  if (entry->marked_dead_ms == 0)
    return false; /* Not marked dead */

  return socket_util_ttl_expired (entry->marked_dead_ms,
                                   DNS_DEAD_SERVER_MAX_TTL, now_ms);
}

/**
 * @brief Calculate remaining TTL in seconds.
 */
static uint32_t
entry_ttl_remaining (const struct DeadServerEntry *entry, int64_t now_ms)
{
  if (entry->marked_dead_ms == 0)
    return 0;

  return socket_util_ttl_remaining (entry->marked_dead_ms,
                                     DNS_DEAD_SERVER_MAX_TTL, now_ms);
}

/* Public API */

T
SocketDNSDeadServer_new (Arena_T arena)
{
  if (arena == NULL)
    return NULL;

  T tracker = Arena_alloc (arena, sizeof (*tracker), __FILE__, __LINE__);
  if (tracker == NULL)
    return NULL;

  memset (tracker, 0, sizeof (*tracker));
  tracker->arena = arena;
  tracker->threshold = DNS_DEAD_SERVER_DEFAULT_THRESHOLD;

  if (pthread_mutex_init (&tracker->mutex, NULL) != 0)
    return NULL;

  return tracker;
}

void
SocketDNSDeadServer_free (T *tracker)
{
  if (tracker == NULL || *tracker == NULL)
    return;

  pthread_mutex_destroy (&(*tracker)->mutex);

  /* Arena handles memory, just clear pointer */
  *tracker = NULL;
}

bool
SocketDNSDeadServer_is_dead (T tracker, const char *address,
                              SocketDNS_DeadServerEntry *entry)
{
  if (tracker == NULL || address == NULL)
    return false;

  int64_t now_ms = Socket_get_monotonic_ms ();
  bool is_dead = false;

  pthread_mutex_lock (&tracker->mutex);

  tracker->checks++;

  struct DeadServerEntry *found = find_entry (tracker, address);
  if (found)
    {
      /* Check if expired */
      if (entry_expired (found, now_ms))
        {
          /* Dead marking expired - server should be retried */
          tracker->expirations++;
          remove_entry (tracker, found);
          found = NULL;
        }
      else if (found->marked_dead_ms > 0)
        {
          /* Currently marked dead and not expired */
          is_dead = true;
          tracker->dead_hits++;

          /* Fill in entry details if requested */
          if (entry != NULL)
            {
              entry->ttl_remaining = entry_ttl_remaining (found, now_ms);
              entry->consecutive_failures = found->consecutive_failures;
              entry->marked_dead_ms = found->marked_dead_ms;
            }
        }
    }

  pthread_mutex_unlock (&tracker->mutex);

  return is_dead;
}

void
SocketDNSDeadServer_mark_failure (T tracker, const char *address)
{
  if (tracker == NULL || address == NULL)
    return;

  size_t addr_len = strlen (address);
  if (addr_len > DNS_DEAD_SERVER_MAX_ADDR)
    return;

  int64_t now_ms = Socket_get_monotonic_ms ();

  pthread_mutex_lock (&tracker->mutex);

  struct DeadServerEntry *entry = find_entry (tracker, address);

  if (entry)
    {
      /* Existing entry - increment failure count */
      entry->consecutive_failures++;

      /* Check if we should mark as dead */
      if (entry->consecutive_failures >= tracker->threshold
          && entry->marked_dead_ms == 0)
        {
          entry->marked_dead_ms = now_ms;
          tracker->dead_marks++;
        }
    }
  else
    {
      /* New entry - add if we have space */
      if (tracker->count < DNS_DEAD_SERVER_MAX_TRACKED)
        {
          entry = &tracker->servers[tracker->count];
          memset (entry, 0, sizeof (*entry));
          strncpy (entry->address, address, DNS_DEAD_SERVER_MAX_ADDR);
          entry->address[DNS_DEAD_SERVER_MAX_ADDR] = '\0';
          entry->consecutive_failures = 1;
          entry->marked_dead_ms = 0;
          tracker->count++;

          /* Check if single failure should mark dead (threshold=1) */
          if (entry->consecutive_failures >= tracker->threshold)
            {
              entry->marked_dead_ms = now_ms;
              tracker->dead_marks++;
            }
        }
      /* If at capacity, we silently drop - shouldn't happen often */
    }

  pthread_mutex_unlock (&tracker->mutex);
}

void
SocketDNSDeadServer_mark_alive (T tracker, const char *address)
{
  if (tracker == NULL || address == NULL)
    return;

  pthread_mutex_lock (&tracker->mutex);

  struct DeadServerEntry *entry = find_entry (tracker, address);
  if (entry)
    {
      /* Server responded - remove from tracking entirely */
      remove_entry (tracker, entry);
      tracker->alive_marks++;
    }

  pthread_mutex_unlock (&tracker->mutex);
}

int
SocketDNSDeadServer_prune (T tracker)
{
  if (tracker == NULL)
    return 0;

  int64_t now_ms = Socket_get_monotonic_ms ();
  int pruned = 0;

  pthread_mutex_lock (&tracker->mutex);

  /* Iterate backwards to safely remove while iterating */
  for (int i = tracker->count - 1; i >= 0; i--)
    {
      struct DeadServerEntry *entry = &tracker->servers[i];

      if (entry->marked_dead_ms > 0 && entry_expired (entry, now_ms))
        {
          remove_entry_at (tracker, i);
          tracker->expirations++;
          pruned++;
        }
    }

  pthread_mutex_unlock (&tracker->mutex);

  return pruned;
}

void
SocketDNSDeadServer_clear (T tracker)
{
  if (tracker == NULL)
    return;

  pthread_mutex_lock (&tracker->mutex);

  tracker->count = 0;

  pthread_mutex_unlock (&tracker->mutex);
}

void
SocketDNSDeadServer_set_threshold (T tracker, int threshold)
{
  if (tracker == NULL)
    return;

  if (threshold < 1)
    threshold = 1;

  pthread_mutex_lock (&tracker->mutex);
  tracker->threshold = threshold;
  pthread_mutex_unlock (&tracker->mutex);
}

int
SocketDNSDeadServer_get_threshold (T tracker)
{
  if (tracker == NULL)
    return DNS_DEAD_SERVER_DEFAULT_THRESHOLD;

  int threshold;

  pthread_mutex_lock (&tracker->mutex);
  threshold = tracker->threshold;
  pthread_mutex_unlock (&tracker->mutex);

  return threshold;
}

void
SocketDNSDeadServer_stats (T tracker, SocketDNS_DeadServerStats *stats)
{
  if (tracker == NULL || stats == NULL)
    return;

  pthread_mutex_lock (&tracker->mutex);

  stats->checks = tracker->checks;
  stats->dead_hits = tracker->dead_hits;
  stats->alive_marks = tracker->alive_marks;
  stats->dead_marks = tracker->dead_marks;
  stats->expirations = tracker->expirations;
  stats->current_dead = 0;

  /* Count currently dead servers */
  int64_t now_ms = Socket_get_monotonic_ms ();
  for (int i = 0; i < tracker->count; i++)
    {
      if (tracker->servers[i].marked_dead_ms > 0
          && !entry_expired (&tracker->servers[i], now_ms))
        {
          stats->current_dead++;
        }
    }

  stats->max_tracked = DNS_DEAD_SERVER_MAX_TRACKED;

  pthread_mutex_unlock (&tracker->mutex);
}

#undef T

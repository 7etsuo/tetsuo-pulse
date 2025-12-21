/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* LRU list operations for SYN protection IP entry management */

#include "core/SocketSYNProtect-private.h"
#include "core/SocketSYNProtect.h"

#include "core/SocketUtil.h"
#include "core/SocketMetrics.h"
#include <assert.h>
#include <stdlib.h>

/* ============================================================================
 * Internal Helper Functions - LRU List Operations
 * ============================================================================
 */

void
lru_remove (SocketSYNProtect_T protect, SocketSYN_IPEntry *entry)
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

void
lru_push_front (SocketSYNProtect_T protect, SocketSYN_IPEntry *entry)
{
  entry->lru_prev = NULL;
  entry->lru_next = protect->lru_head;

  if (protect->lru_head != NULL)
    protect->lru_head->lru_prev = entry;
  else
    protect->lru_tail = entry;

  protect->lru_head = entry;
}

void
lru_touch (SocketSYNProtect_T protect, SocketSYN_IPEntry *entry)
{
  if (entry != protect->lru_head)
    {
      lru_remove (protect, entry);
      lru_push_front (protect, entry);
    }
}

/* Free heap-allocated memory (no-op for arena) */
void
free_memory (SocketSYNProtect_T protect, void *ptr)
{
  if (protect->use_malloc && ptr != NULL)
    free (ptr);
}

void
evict_lru_entry (SocketSYNProtect_T protect)
{
  SocketSYN_IPEntry *victim = protect->lru_tail;
  if (victim == NULL)
    return;

  remove_ip_entry_from_hash (protect, victim);
  lru_remove (protect, victim);
  free_memory (protect, victim);

  protect->ip_entry_count--;
  SocketMetrics_gauge_set (SOCKET_GAU_SYNPROTECT_TRACKED_IPS,
                           protect->ip_entry_count);
  atomic_fetch_add (&protect->stat_lru_evictions, 1);
  SocketMetrics_counter_inc (SOCKET_CTR_SYNPROTECT_LRU_EVICTIONS);
}

#undef T
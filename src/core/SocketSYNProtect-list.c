/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSYNProtect-list.c
 * @ingroup security
 * @internal
 * @brief LRU list operations for SYN protection IP entry management.
 *
 * Implements doubly-linked list operations for managing IP entries in
 * least-recently-used (LRU) order. Used for eviction policy when the
 * hash table reaches capacity.
 */

#include "core/SocketSYNProtect-private.h"
#include "core/SocketSYNProtect.h"

#include "core/SocketMetrics.h"
#include "core/SocketUtil.h"
#include <assert.h>
#include <stdlib.h>

/**
 * @brief Remove an entry from the LRU doubly-linked list.
 * @internal
 *
 * Unlinks the entry from the doubly-linked LRU list by updating adjacent
 * entries' pointers and adjusting the head/tail pointers if necessary.
 * Does not free memory or modify hash table - only updates LRU list links.
 *
 * @param protect  SYN protection instance
 * @param entry    IP entry to remove from LRU list
 *
 * @note Caller must hold protect->mutex
 * @note Entry's lru_prev and lru_next are set to NULL after removal
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

/**
 * @brief Add an entry to the front of the LRU list (most recently used).
 * @internal
 *
 * Inserts the entry at the head of the doubly-linked LRU list, marking it
 * as the most recently used. Updates head/tail pointers and adjacent entry
 * links as needed.
 *
 * @param protect  SYN protection instance
 * @param entry    IP entry to insert at front of LRU list
 *
 * @note Caller must hold protect->mutex
 * @note Entry must not already be in the LRU list (caller should call
 * lru_remove first)
 */
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

/**
 * @brief Mark an entry as recently used by moving it to the front of LRU list.
 * @internal
 *
 * If the entry is not already at the front, removes it from its current
 * position and pushes it to the front of the LRU list. No-op if entry is
 * already the head. Used to update access time when an IP is accessed.
 *
 * @param protect  SYN protection instance
 * @param entry    IP entry to mark as recently used
 *
 * @note Caller must hold protect->mutex
 */
void
lru_touch (SocketSYNProtect_T protect, SocketSYN_IPEntry *entry)
{
  if (entry != protect->lru_head)
    {
      lru_remove (protect, entry);
      lru_push_front (protect, entry);
    }
}

/**
 * @brief Free heap-allocated memory if not using arena allocator.
 * @internal
 *
 * Conditionally frees memory allocated via malloc() when the SYN protection
 * instance was created without an arena. No-op if using arena-based allocation,
 * as arena cleanup handles all memory at once.
 *
 * @param protect  SYN protection instance
 * @param ptr      Memory to free (may be NULL)
 *
 * @note Caller must hold protect->mutex when freeing shared structures
 */
void
free_memory (SocketSYNProtect_T protect, void *ptr)
{
  if (protect->use_malloc && ptr != NULL)
    free (ptr);
}

/**
 * @brief Evict the least recently used IP entry from the hash table.
 * @internal
 *
 * Removes the tail entry (least recently used) from both the hash table and
 * LRU list, then frees its memory. Updates metrics counters to track evictions.
 * Used when the hash table reaches capacity and a new entry needs space.
 *
 * @param protect  SYN protection instance
 *
 * @note Caller must hold protect->mutex
 * @note No-op if LRU list is empty (no entries to evict)
 * @note Increments stat_lru_evictions counter and updates tracked IPs gauge
 */
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

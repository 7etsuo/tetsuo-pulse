/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICConnectionID-pool.c
 * @brief QUIC Connection ID Pool Management (RFC 9000 Section 5.1.1-5.1.2).
 *
 * Implements connection ID lifecycle operations including:
 *   - Hash table for O(1) CID lookup
 *   - Doubly-linked list for sequence-ordered iteration
 *   - Retire Prior To bulk retirement
 *   - active_connection_id_limit enforcement
 */

#include "quic/SocketQUICConnectionID-pool.h"
#include "quic/SocketQUICConstants.h"
#include "core/SocketUtil.h"
#include "core/SocketCrypto.h"

#include <inttypes.h>
#include <string.h>

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "QUIC-CID"

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *result_strings[] = {
    [QUIC_CONNID_POOL_OK] = "OK",
    [QUIC_CONNID_POOL_ERROR_NULL] = "NULL pointer argument",
    [QUIC_CONNID_POOL_ERROR_FULL] = "Pool at peer's active_connection_id_limit",
    [QUIC_CONNID_POOL_ERROR_DUP] = "Duplicate connection ID",
    [QUIC_CONNID_POOL_ERROR_SEQ] = "Invalid sequence number",
    [QUIC_CONNID_POOL_ERROR_LIMIT] = "Limit exceeded",
    [QUIC_CONNID_POOL_ERROR_CHAIN] = "Hash chain too long (potential DoS)",
    [QUIC_CONNID_POOL_NOT_FOUND] = "Connection ID not found",
};

DEFINE_RESULT_STRING_FUNC (SocketQUICConnectionIDPool, QUIC_CONNID_POOL_NOT_FOUND)

/* ============================================================================
 * Internal Hash Functions
 * ============================================================================
 */

static unsigned
hash_cid_bytes (const uint8_t *id, size_t len, uint32_t seed)
{
  if (len == 0)
    return 0;

  /* FNV-1a hash with seed mixing */
  uint32_t hash = QUIC_HASH_FNV1A_OFFSET_BASIS ^ seed;

  for (size_t i = 0; i < len; i++)
    hash = QUIC_HASH_FNV1A_STEP (hash, id[i]);

  return hash % QUIC_CONNID_POOL_HASH_SIZE;
}

/* ============================================================================
 * Pool Lifecycle Functions
 * ============================================================================
 */

SocketQUICConnectionIDPool_T
SocketQUICConnectionIDPool_new (Arena_T arena, size_t peer_limit)
{
  SocketQUICConnectionIDPool_T pool;

  if (arena == NULL)
    return NULL;

  /* Minimum peer limit per RFC 9000 Section 18.2 */
  if (peer_limit < QUIC_CONNID_DEFAULT_LIMIT)
    peer_limit = QUIC_CONNID_DEFAULT_LIMIT;

  pool = CALLOC (arena, 1, sizeof (*pool));
  if (pool == NULL)
    return NULL;

  pool->arena = arena;
  pool->peer_limit = peer_limit;
  pool->next_sequence = 0;
  pool->retire_prior_to = 0;
  pool->active_count = 0;
  pool->total_count = 0;

  /* Generate cryptographically secure random hash seed for collision resistance
   * Fail initialization rather than using a weak seed (defense against hash collision DoS) */
  if (SocketCrypto_random_bytes (&pool->hash_seed, sizeof (pool->hash_seed)) != 0)
    {
      SOCKET_LOG_ERROR_MSG ("Failed to generate secure hash seed");
      return NULL;
    }

  return pool;
}

size_t
SocketQUICConnectionIDPool_active_count (const SocketQUICConnectionIDPool_T pool)
{
  if (pool == NULL)
    return 0;
  return pool->active_count;
}

size_t
SocketQUICConnectionIDPool_total_count (const SocketQUICConnectionIDPool_T pool)
{
  if (pool == NULL)
    return 0;
  return pool->total_count;
}

int
SocketQUICConnectionIDPool_can_add (const SocketQUICConnectionIDPool_T pool)
{
  if (pool == NULL)
    return 0;
  return pool->active_count < pool->peer_limit;
}

/* ============================================================================
 * Internal List Operations
 * ============================================================================
 */

static void
list_append (SocketQUICConnectionIDPool_T pool,
             SocketQUICConnectionIDEntry_T *entry)
{
  entry->list_prev = pool->list_tail;
  entry->list_next = NULL;

  if (pool->list_tail)
    pool->list_tail->list_next = entry;
  else
    pool->list_head = entry;

  pool->list_tail = entry;
}

static void
list_remove (SocketQUICConnectionIDPool_T pool,
             SocketQUICConnectionIDEntry_T *entry)
{
  if (entry->list_prev)
    entry->list_prev->list_next = entry->list_next;
  else
    pool->list_head = entry->list_next;

  if (entry->list_next)
    entry->list_next->list_prev = entry->list_prev;
  else
    pool->list_tail = entry->list_prev;

  entry->list_prev = NULL;
  entry->list_next = NULL;
}

/* ============================================================================
 * Internal Hash Table Operations
 * ============================================================================
 */

static void
hash_insert (SocketQUICConnectionIDPool_T pool,
             SocketQUICConnectionIDEntry_T *entry)
{
  unsigned idx
      = hash_cid_bytes (entry->cid.data, entry->cid.len, pool->hash_seed);

  entry->hash_next = pool->hash_table[idx];
  pool->hash_table[idx] = entry;
}

static void
hash_remove (SocketQUICConnectionIDPool_T pool,
             SocketQUICConnectionIDEntry_T *entry)
{
  unsigned idx
      = hash_cid_bytes (entry->cid.data, entry->cid.len, pool->hash_seed);

  SocketQUICConnectionIDEntry_T **prev = &pool->hash_table[idx];

  while (*prev)
    {
      if (*prev == entry)
        {
          *prev = entry->hash_next;
          entry->hash_next = NULL;
          return;
        }
      prev = &(*prev)->hash_next;
    }
}

/* ============================================================================
 * Connection ID Management
 * ============================================================================
 */

/**
 * @brief Check for duplicate CID in hash chain.
 *
 * @param pool The connection ID pool.
 * @param cid The connection ID to check.
 * @param idx Hash table index.
 * @return QUIC_CONNID_POOL_OK if no duplicate, error code otherwise.
 */
static SocketQUICConnectionIDPool_Result
check_for_duplicate_cid (SocketQUICConnectionIDPool_T pool,
                         const SocketQUICConnectionID_T *cid,
                         unsigned idx)
{
  SocketQUICConnectionIDEntry_T *entry;
  int chain_len = 0;

  entry = pool->hash_table[idx];

  while (entry)
    {
      chain_len++;
      if (chain_len > QUIC_CONNID_POOL_MAX_CHAIN_LEN)
        {
          SOCKET_LOG_WARN_MSG (
              "SECURITY: Hash chain too long (%d) - potential DoS attack",
              chain_len);
          return QUIC_CONNID_POOL_ERROR_CHAIN;
        }

      if (SocketQUICConnectionID_equal (&entry->cid, cid))
        {
          SOCKET_LOG_DEBUG_MSG ("Duplicate CID detected at sequence %" PRIu64,
                                entry->cid.sequence);
          return QUIC_CONNID_POOL_ERROR_DUP;
        }

      entry = entry->hash_next;
    }

  return QUIC_CONNID_POOL_OK;
}

/**
 * @brief Create and initialize a new pool entry.
 *
 * @param pool The connection ID pool.
 * @param cid The connection ID to store.
 * @param sequence The sequence number for this CID.
 * @return Pointer to new entry, or NULL on allocation failure.
 */
static SocketQUICConnectionIDEntry_T *
create_pool_entry (SocketQUICConnectionIDPool_T pool,
                   const SocketQUICConnectionID_T *cid,
                   uint64_t sequence)
{
  SocketQUICConnectionIDEntry_T *entry;

  entry = CALLOC (pool->arena, 1, sizeof (*entry));
  if (entry == NULL)
    return NULL;

  SocketQUICConnectionID_copy (&entry->cid, cid);
  entry->cid.sequence = sequence;
  entry->is_retired = 0;
  entry->is_used = 0;
  entry->used_at = 0;

  return entry;
}

SocketQUICConnectionIDPool_Result
SocketQUICConnectionIDPool_add (SocketQUICConnectionIDPool_T pool,
                                 const SocketQUICConnectionID_T *cid)
{
  if (pool == NULL || cid == NULL)
    return QUIC_CONNID_POOL_ERROR_NULL;

  return SocketQUICConnectionIDPool_add_with_sequence (pool, cid,
                                                        pool->next_sequence);
}

SocketQUICConnectionIDPool_Result
SocketQUICConnectionIDPool_add_with_sequence (SocketQUICConnectionIDPool_T pool,
                                               const SocketQUICConnectionID_T *cid,
                                               uint64_t sequence)
{
  SocketQUICConnectionIDEntry_T *entry;
  SocketQUICConnectionIDPool_Result result;
  unsigned idx;

  if (pool == NULL || cid == NULL)
    return QUIC_CONNID_POOL_ERROR_NULL;

  /* Check active_connection_id_limit */
  if (pool->active_count >= pool->peer_limit)
    {
      SOCKET_LOG_WARN_MSG ("Cannot add CID: at peer limit (%zu)",
                           pool->peer_limit);
      return QUIC_CONNID_POOL_ERROR_FULL;
    }

  /* Check for duplicate by CID bytes */
  idx = hash_cid_bytes (cid->data, cid->len, pool->hash_seed);
  result = check_for_duplicate_cid (pool, cid, idx);
  if (result != QUIC_CONNID_POOL_OK)
    return result;

  /* Create new entry */
  entry = create_pool_entry (pool, cid, sequence);
  if (entry == NULL)
    return QUIC_CONNID_POOL_ERROR_NULL;

  /* Insert into hash table and list */
  hash_insert (pool, entry);
  list_append (pool, entry);

  pool->total_count++;
  pool->active_count++;

  /* Update next sequence if needed */
  if (sequence >= pool->next_sequence)
    pool->next_sequence = sequence + 1;

  SOCKET_LOG_DEBUG_MSG ("Added CID with sequence %" PRIu64 " (active: %zu/%zu)",
                        sequence, pool->active_count, pool->peer_limit);

  return QUIC_CONNID_POOL_OK;
}

SocketQUICConnectionIDEntry_T *
SocketQUICConnectionIDPool_lookup (const SocketQUICConnectionIDPool_T pool,
                                    const uint8_t *id, size_t len)
{
  SocketQUICConnectionIDEntry_T *entry;
  unsigned idx;
  int chain_len;

  if (pool == NULL || id == NULL)
    return NULL;

  idx = hash_cid_bytes (id, len, pool->hash_seed);
  entry = pool->hash_table[idx];
  chain_len = 0;

  while (entry)
    {
      chain_len++;
      if (chain_len > QUIC_CONNID_POOL_MAX_CHAIN_LEN)
        {
          SOCKET_LOG_WARN_MSG (
              "SECURITY: Hash chain too long in lookup (%d)", chain_len);
          return NULL;
        }

      if (SocketQUICConnectionID_equal_raw (&entry->cid, id, len))
        return entry;

      entry = entry->hash_next;
    }

  return NULL;
}

SocketQUICConnectionIDEntry_T *
SocketQUICConnectionIDPool_lookup_sequence (const SocketQUICConnectionIDPool_T pool,
                                             uint64_t sequence)
{
  SocketQUICConnectionIDEntry_T *entry;

  if (pool == NULL)
    return NULL;

  /* Linear search through list - could be optimized with sequence index */
  entry = pool->list_head;
  while (entry)
    {
      if (entry->cid.sequence == sequence)
        return entry;
      entry = entry->list_next;
    }

  return NULL;
}

SocketQUICConnectionIDPool_Result
SocketQUICConnectionIDPool_remove (SocketQUICConnectionIDPool_T pool,
                                    const uint8_t *id, size_t len)
{
  SocketQUICConnectionIDEntry_T *entry;

  if (pool == NULL || id == NULL)
    return QUIC_CONNID_POOL_ERROR_NULL;

  entry = SocketQUICConnectionIDPool_lookup (pool, id, len);
  if (entry == NULL)
    return QUIC_CONNID_POOL_NOT_FOUND;

  /* Remove from data structures */
  hash_remove (pool, entry);
  list_remove (pool, entry);

  pool->total_count--;
  if (!entry->is_retired)
    pool->active_count--;

  SOCKET_LOG_DEBUG_MSG ("Removed CID with sequence %" PRIu64,
                        entry->cid.sequence);

  /* Entry memory will be freed when arena is disposed */
  return QUIC_CONNID_POOL_OK;
}

/* ============================================================================
 * Retirement Functions (RFC 9000 Section 5.1.2)
 * ============================================================================
 */

SocketQUICConnectionIDPool_Result
SocketQUICConnectionIDPool_retire_prior_to (SocketQUICConnectionIDPool_T pool,
                                             uint64_t retire_prior_to,
                                             size_t *retired_count)
{
  SocketQUICConnectionIDEntry_T *entry;
  size_t count = 0;

  if (pool == NULL)
    return QUIC_CONNID_POOL_ERROR_NULL;

  /* RFC 9000 §5.1.2: retire_prior_to must not decrease */
  if (retire_prior_to < pool->retire_prior_to)
    {
      SOCKET_LOG_WARN_MSG ("Invalid retire_prior_to: %" PRIu64
                           " < current %" PRIu64,
                           retire_prior_to, pool->retire_prior_to);
      return QUIC_CONNID_POOL_ERROR_SEQ;
    }

  if (retire_prior_to == pool->retire_prior_to)
    {
      if (retired_count)
        *retired_count = 0;
      return QUIC_CONNID_POOL_OK;
    }

  pool->retire_prior_to = retire_prior_to;

  /* Mark all CIDs with sequence < retire_prior_to as retired */
  entry = pool->list_head;
  while (entry)
    {
      if (entry->cid.sequence < retire_prior_to && !entry->is_retired)
        {
          entry->is_retired = 1;
          pool->active_count--;
          count++;
        }
      entry = entry->list_next;
    }

  if (retired_count)
    *retired_count = count;

  SOCKET_LOG_DEBUG_MSG ("Retired %zu CIDs with sequence < %" PRIu64
                        " (active: %zu)",
                        count, retire_prior_to, pool->active_count);

  return QUIC_CONNID_POOL_OK;
}

SocketQUICConnectionIDPool_Result
SocketQUICConnectionIDPool_retire_sequence (SocketQUICConnectionIDPool_T pool,
                                             uint64_t sequence)
{
  SocketQUICConnectionIDEntry_T *entry;

  if (pool == NULL)
    return QUIC_CONNID_POOL_ERROR_NULL;

  entry = SocketQUICConnectionIDPool_lookup_sequence (pool, sequence);
  if (entry == NULL)
    return QUIC_CONNID_POOL_NOT_FOUND;

  if (!entry->is_retired)
    {
      entry->is_retired = 1;
      pool->active_count--;
      SOCKET_LOG_DEBUG_MSG ("Retired CID with sequence %" PRIu64, sequence);
    }

  return QUIC_CONNID_POOL_OK;
}

SocketQUICConnectionIDPool_Result
SocketQUICConnectionIDPool_purge_retired (SocketQUICConnectionIDPool_T pool,
                                           size_t *removed_count)
{
  SocketQUICConnectionIDEntry_T *entry;
  SocketQUICConnectionIDEntry_T *next;
  size_t count = 0;

  if (pool == NULL)
    return QUIC_CONNID_POOL_ERROR_NULL;

  entry = pool->list_head;
  while (entry)
    {
      next = entry->list_next;

      if (entry->is_retired)
        {
          hash_remove (pool, entry);
          list_remove (pool, entry);
          pool->total_count--;
          count++;
          /* Memory freed when arena is disposed */
        }

      entry = next;
    }

  if (removed_count)
    *removed_count = count;

  SOCKET_LOG_DEBUG_MSG ("Purged %zu retired CIDs (total: %zu)", count,
                        pool->total_count);

  return QUIC_CONNID_POOL_OK;
}

uint64_t
SocketQUICConnectionIDPool_get_retire_prior_to (const SocketQUICConnectionIDPool_T pool)
{
  if (pool == NULL)
    return 0;
  return pool->retire_prior_to;
}

/* ============================================================================
 * Iteration Functions
 * ============================================================================
 */

int
SocketQUICConnectionIDPool_foreach (SocketQUICConnectionIDPool_T pool,
                                     SocketQUICConnectionIDPool_Iterator callback,
                                     void *context)
{
  SocketQUICConnectionIDEntry_T *entry;
  int count = 0;

  if (pool == NULL || callback == NULL)
    return -1;

  entry = pool->list_head;
  while (entry)
    {
      if (!entry->is_retired)
        {
          if (callback (entry, context) != 0)
            break;
          count++;
        }
      entry = entry->list_next;
    }

  return count;
}

SocketQUICConnectionIDEntry_T *
SocketQUICConnectionIDPool_get_available (SocketQUICConnectionIDPool_T pool)
{
  SocketQUICConnectionIDEntry_T *entry;

  if (pool == NULL)
    return NULL;

  entry = pool->list_head;
  while (entry)
    {
      if (!entry->is_retired && !entry->is_used)
        {
          entry->is_used = 1;
          entry->used_at = (uint64_t)Socket_get_monotonic_ms ();
          return entry;
        }
      entry = entry->list_next;
    }

  return NULL;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

int
SocketQUICConnectionIDPool_needs_more (const SocketQUICConnectionIDPool_T pool,
                                        size_t min_for_migrate)
{
  if (pool == NULL)
    return 0;

  /* Need more if active count is below minimum for migration */
  return pool->active_count < min_for_migrate;
}

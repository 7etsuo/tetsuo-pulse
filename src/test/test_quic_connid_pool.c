/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_connid_pool.c
 * @brief Unit tests for QUIC Connection ID Pool (RFC 9000 §5.1.1-5.1.2).
 */

#include "core/Arena.h"
#include "quic/SocketQUICConnectionID-pool.h"
#include "quic/SocketQUICConnectionID.h"
#include "test/Test.h"

#include <string.h>

TEST (connid_pool_new_creates_pool)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICConnectionIDPool_T pool = SocketQUICConnectionIDPool_new (arena, 8);
  ASSERT_NOT_NULL (pool);
  ASSERT_EQ (SocketQUICConnectionIDPool_active_count (pool), 0);
  ASSERT_EQ (SocketQUICConnectionIDPool_total_count (pool), 0);

  Arena_dispose (&arena);
}

TEST (connid_pool_new_null_arena_returns_null)
{
  SocketQUICConnectionIDPool_T pool = SocketQUICConnectionIDPool_new (NULL, 8);
  ASSERT_NULL (pool);
}

TEST (connid_pool_new_enforces_minimum_peer_limit)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Request limit of 1, should be upgraded to minimum (2) */
  SocketQUICConnectionIDPool_T pool = SocketQUICConnectionIDPool_new (arena, 1);
  ASSERT_NOT_NULL (pool);

  /* Can add at least 2 CIDs */
  ASSERT (SocketQUICConnectionIDPool_can_add (pool));

  Arena_dispose (&arena);
}

TEST (connid_pool_add_basic)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnectionIDPool_T pool = SocketQUICConnectionIDPool_new (arena, 8);
  ASSERT_NOT_NULL (pool);

  SocketQUICConnectionID_T cid;
  ASSERT_EQ (SocketQUICConnectionID_generate (&cid, 8), QUIC_CONNID_OK);
  ASSERT_EQ (SocketQUICConnectionID_generate_reset_token (&cid),
             QUIC_CONNID_OK);

  SocketQUICConnectionIDPool_Result result
      = SocketQUICConnectionIDPool_add (pool, &cid);
  ASSERT_EQ (result, QUIC_CONNID_POOL_OK);
  ASSERT_EQ (SocketQUICConnectionIDPool_active_count (pool), 1);
  ASSERT_EQ (SocketQUICConnectionIDPool_total_count (pool), 1);

  Arena_dispose (&arena);
}

TEST (connid_pool_add_with_sequence)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnectionIDPool_T pool = SocketQUICConnectionIDPool_new (arena, 8);
  ASSERT_NOT_NULL (pool);

  SocketQUICConnectionID_T cid;
  ASSERT_EQ (SocketQUICConnectionID_generate (&cid, 8), QUIC_CONNID_OK);

  /* Add with sequence 0 (initial CID) */
  SocketQUICConnectionIDPool_Result result
      = SocketQUICConnectionIDPool_add_with_sequence (pool, &cid, 0);
  ASSERT_EQ (result, QUIC_CONNID_POOL_OK);

  /* Verify sequence was set */
  SocketQUICConnectionIDEntry_T *entry
      = SocketQUICConnectionIDPool_lookup_sequence (pool, 0);
  ASSERT_NOT_NULL (entry);
  ASSERT_EQ (entry->cid.sequence, 0);

  Arena_dispose (&arena);
}

TEST (connid_pool_add_multiple)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnectionIDPool_T pool = SocketQUICConnectionIDPool_new (arena, 8);
  ASSERT_NOT_NULL (pool);

  for (int i = 0; i < 5; i++)
    {
      SocketQUICConnectionID_T cid;
      ASSERT_EQ (SocketQUICConnectionID_generate (&cid, 8), QUIC_CONNID_OK);
      ASSERT_EQ (SocketQUICConnectionIDPool_add (pool, &cid),
                 QUIC_CONNID_POOL_OK);
    }

  ASSERT_EQ (SocketQUICConnectionIDPool_active_count (pool), 5);
  ASSERT_EQ (SocketQUICConnectionIDPool_total_count (pool), 5);

  Arena_dispose (&arena);
}

TEST (connid_pool_add_respects_peer_limit)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnectionIDPool_T pool = SocketQUICConnectionIDPool_new (arena, 3);
  ASSERT_NOT_NULL (pool);

  /* Add up to limit */
  for (int i = 0; i < 3; i++)
    {
      SocketQUICConnectionID_T cid;
      ASSERT_EQ (SocketQUICConnectionID_generate (&cid, 8), QUIC_CONNID_OK);
      ASSERT_EQ (SocketQUICConnectionIDPool_add (pool, &cid),
                 QUIC_CONNID_POOL_OK);
    }

  ASSERT (!SocketQUICConnectionIDPool_can_add (pool));

  /* Adding another should fail */
  SocketQUICConnectionID_T cid;
  ASSERT_EQ (SocketQUICConnectionID_generate (&cid, 8), QUIC_CONNID_OK);
  ASSERT_EQ (SocketQUICConnectionIDPool_add (pool, &cid),
             QUIC_CONNID_POOL_ERROR_FULL);

  Arena_dispose (&arena);
}

TEST (connid_pool_add_rejects_duplicate)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnectionIDPool_T pool = SocketQUICConnectionIDPool_new (arena, 8);
  ASSERT_NOT_NULL (pool);

  SocketQUICConnectionID_T cid;
  ASSERT_EQ (SocketQUICConnectionID_generate (&cid, 8), QUIC_CONNID_OK);

  ASSERT_EQ (SocketQUICConnectionIDPool_add (pool, &cid), QUIC_CONNID_POOL_OK);
  ASSERT_EQ (SocketQUICConnectionIDPool_add (pool, &cid),
             QUIC_CONNID_POOL_ERROR_DUP);

  Arena_dispose (&arena);
}

TEST (connid_pool_lookup_by_bytes)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnectionIDPool_T pool = SocketQUICConnectionIDPool_new (arena, 8);
  ASSERT_NOT_NULL (pool);

  SocketQUICConnectionID_T cid;
  uint8_t test_bytes[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  ASSERT_EQ (SocketQUICConnectionID_set (&cid, test_bytes, 8), QUIC_CONNID_OK);

  ASSERT_EQ (SocketQUICConnectionIDPool_add (pool, &cid), QUIC_CONNID_POOL_OK);

  /* Lookup should find it */
  SocketQUICConnectionIDEntry_T *entry
      = SocketQUICConnectionIDPool_lookup (pool, test_bytes, 8);
  ASSERT_NOT_NULL (entry);
  ASSERT (SocketQUICConnectionID_equal_raw (&entry->cid, test_bytes, 8));

  /* Lookup with different bytes should not find it */
  uint8_t other_bytes[8] = { 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8 };
  entry = SocketQUICConnectionIDPool_lookup (pool, other_bytes, 8);
  ASSERT_NULL (entry);

  Arena_dispose (&arena);
}

TEST (connid_pool_lookup_by_sequence)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnectionIDPool_T pool = SocketQUICConnectionIDPool_new (arena, 8);
  ASSERT_NOT_NULL (pool);

  for (int i = 0; i < 5; i++)
    {
      SocketQUICConnectionID_T cid;
      ASSERT_EQ (SocketQUICConnectionID_generate (&cid, 8), QUIC_CONNID_OK);
      ASSERT_EQ (SocketQUICConnectionIDPool_add (pool, &cid),
                 QUIC_CONNID_POOL_OK);
    }

  /* Should find sequences 0-4 */
  for (uint64_t i = 0; i < 5; i++)
    {
      SocketQUICConnectionIDEntry_T *entry
          = SocketQUICConnectionIDPool_lookup_sequence (pool, i);
      ASSERT_NOT_NULL (entry);
      ASSERT_EQ (entry->cid.sequence, i);
    }

  /* Sequence 5 should not exist */
  ASSERT_NULL (SocketQUICConnectionIDPool_lookup_sequence (pool, 5));

  Arena_dispose (&arena);
}

TEST (connid_pool_remove_basic)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnectionIDPool_T pool = SocketQUICConnectionIDPool_new (arena, 8);
  ASSERT_NOT_NULL (pool);

  uint8_t test_bytes[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  SocketQUICConnectionID_T cid;
  ASSERT_EQ (SocketQUICConnectionID_set (&cid, test_bytes, 8), QUIC_CONNID_OK);

  ASSERT_EQ (SocketQUICConnectionIDPool_add (pool, &cid), QUIC_CONNID_POOL_OK);
  ASSERT_EQ (SocketQUICConnectionIDPool_active_count (pool), 1);

  ASSERT_EQ (SocketQUICConnectionIDPool_remove (pool, test_bytes, 8),
             QUIC_CONNID_POOL_OK);
  ASSERT_EQ (SocketQUICConnectionIDPool_active_count (pool), 0);

  /* Lookup should not find it anymore */
  ASSERT_NULL (SocketQUICConnectionIDPool_lookup (pool, test_bytes, 8));

  Arena_dispose (&arena);
}

TEST (connid_pool_remove_not_found)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnectionIDPool_T pool = SocketQUICConnectionIDPool_new (arena, 8);
  ASSERT_NOT_NULL (pool);

  uint8_t test_bytes[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

  ASSERT_EQ (SocketQUICConnectionIDPool_remove (pool, test_bytes, 8),
             QUIC_CONNID_POOL_NOT_FOUND);

  Arena_dispose (&arena);
}

TEST (connid_pool_retire_prior_to_basic)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnectionIDPool_T pool
      = SocketQUICConnectionIDPool_new (arena, 10);
  ASSERT_NOT_NULL (pool);

  /* Add 5 CIDs with sequences 0-4 */
  for (int i = 0; i < 5; i++)
    {
      SocketQUICConnectionID_T cid;
      ASSERT_EQ (SocketQUICConnectionID_generate (&cid, 8), QUIC_CONNID_OK);
      ASSERT_EQ (SocketQUICConnectionIDPool_add (pool, &cid),
                 QUIC_CONNID_POOL_OK);
    }

  ASSERT_EQ (SocketQUICConnectionIDPool_active_count (pool), 5);

  /* Retire all with sequence < 3 */
  size_t retired_count = 0;
  ASSERT_EQ (
      SocketQUICConnectionIDPool_retire_prior_to (pool, 3, &retired_count),
      QUIC_CONNID_POOL_OK);
  ASSERT_EQ (retired_count, 3);
  ASSERT_EQ (SocketQUICConnectionIDPool_active_count (pool), 2);
  ASSERT_EQ (SocketQUICConnectionIDPool_total_count (pool), 5);

  /* Entries 0, 1, 2 should be retired */
  for (uint64_t i = 0; i < 3; i++)
    {
      SocketQUICConnectionIDEntry_T *entry
          = SocketQUICConnectionIDPool_lookup_sequence (pool, i);
      ASSERT_NOT_NULL (entry);
      ASSERT (entry->is_retired);
    }

  /* Entries 3, 4 should still be active */
  for (uint64_t i = 3; i < 5; i++)
    {
      SocketQUICConnectionIDEntry_T *entry
          = SocketQUICConnectionIDPool_lookup_sequence (pool, i);
      ASSERT_NOT_NULL (entry);
      ASSERT (!entry->is_retired);
    }

  Arena_dispose (&arena);
}

TEST (connid_pool_retire_prior_to_cannot_decrease)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnectionIDPool_T pool
      = SocketQUICConnectionIDPool_new (arena, 10);
  ASSERT_NOT_NULL (pool);

  /* Set retire_prior_to to 5 */
  ASSERT_EQ (SocketQUICConnectionIDPool_retire_prior_to (pool, 5, NULL),
             QUIC_CONNID_POOL_OK);
  ASSERT_EQ (SocketQUICConnectionIDPool_get_retire_prior_to (pool), 5);

  /* Trying to decrease should fail */
  ASSERT_EQ (SocketQUICConnectionIDPool_retire_prior_to (pool, 3, NULL),
             QUIC_CONNID_POOL_ERROR_SEQ);

  /* Value should remain unchanged */
  ASSERT_EQ (SocketQUICConnectionIDPool_get_retire_prior_to (pool), 5);

  Arena_dispose (&arena);
}

TEST (connid_pool_retire_sequence)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnectionIDPool_T pool
      = SocketQUICConnectionIDPool_new (arena, 10);
  ASSERT_NOT_NULL (pool);

  /* Add 3 CIDs */
  for (int i = 0; i < 3; i++)
    {
      SocketQUICConnectionID_T cid;
      ASSERT_EQ (SocketQUICConnectionID_generate (&cid, 8), QUIC_CONNID_OK);
      ASSERT_EQ (SocketQUICConnectionIDPool_add (pool, &cid),
                 QUIC_CONNID_POOL_OK);
    }

  ASSERT_EQ (SocketQUICConnectionIDPool_active_count (pool), 3);

  /* Retire sequence 1 */
  ASSERT_EQ (SocketQUICConnectionIDPool_retire_sequence (pool, 1),
             QUIC_CONNID_POOL_OK);
  ASSERT_EQ (SocketQUICConnectionIDPool_active_count (pool), 2);

  /* Verify it's retired */
  SocketQUICConnectionIDEntry_T *entry
      = SocketQUICConnectionIDPool_lookup_sequence (pool, 1);
  ASSERT_NOT_NULL (entry);
  ASSERT (entry->is_retired);

  Arena_dispose (&arena);
}

TEST (connid_pool_purge_retired)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnectionIDPool_T pool
      = SocketQUICConnectionIDPool_new (arena, 10);
  ASSERT_NOT_NULL (pool);

  /* Add 5 CIDs */
  for (int i = 0; i < 5; i++)
    {
      SocketQUICConnectionID_T cid;
      ASSERT_EQ (SocketQUICConnectionID_generate (&cid, 8), QUIC_CONNID_OK);
      ASSERT_EQ (SocketQUICConnectionIDPool_add (pool, &cid),
                 QUIC_CONNID_POOL_OK);
    }

  /* Retire first 3 */
  ASSERT_EQ (SocketQUICConnectionIDPool_retire_prior_to (pool, 3, NULL),
             QUIC_CONNID_POOL_OK);
  ASSERT_EQ (SocketQUICConnectionIDPool_total_count (pool), 5);

  /* Purge retired */
  size_t removed_count = 0;
  ASSERT_EQ (SocketQUICConnectionIDPool_purge_retired (pool, &removed_count),
             QUIC_CONNID_POOL_OK);
  ASSERT_EQ (removed_count, 3);
  ASSERT_EQ (SocketQUICConnectionIDPool_total_count (pool), 2);
  ASSERT_EQ (SocketQUICConnectionIDPool_active_count (pool), 2);

  /* Purged entries should not be found */
  for (uint64_t i = 0; i < 3; i++)
    {
      ASSERT_NULL (SocketQUICConnectionIDPool_lookup_sequence (pool, i));
    }

  Arena_dispose (&arena);
}

static int
count_iterator (SocketQUICConnectionIDEntry_T *entry, void *context)
{
  (void)entry;
  int *count = (int *)context;
  (*count)++;
  return 0;
}

TEST (connid_pool_foreach_skips_retired)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnectionIDPool_T pool
      = SocketQUICConnectionIDPool_new (arena, 10);
  ASSERT_NOT_NULL (pool);

  /* Add 5 CIDs, retire 2 */
  for (int i = 0; i < 5; i++)
    {
      SocketQUICConnectionID_T cid;
      ASSERT_EQ (SocketQUICConnectionID_generate (&cid, 8), QUIC_CONNID_OK);
      ASSERT_EQ (SocketQUICConnectionIDPool_add (pool, &cid),
                 QUIC_CONNID_POOL_OK);
    }

  ASSERT_EQ (SocketQUICConnectionIDPool_retire_prior_to (pool, 2, NULL),
             QUIC_CONNID_POOL_OK);

  /* Count via foreach - should only count non-retired */
  int count = 0;
  int visited
      = SocketQUICConnectionIDPool_foreach (pool, count_iterator, &count);
  ASSERT_EQ (visited, 3);
  ASSERT_EQ (count, 3);

  Arena_dispose (&arena);
}

TEST (connid_pool_get_available)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnectionIDPool_T pool
      = SocketQUICConnectionIDPool_new (arena, 10);
  ASSERT_NOT_NULL (pool);

  /* Add 3 CIDs */
  for (int i = 0; i < 3; i++)
    {
      SocketQUICConnectionID_T cid;
      ASSERT_EQ (SocketQUICConnectionID_generate (&cid, 8), QUIC_CONNID_OK);
      ASSERT_EQ (SocketQUICConnectionIDPool_add (pool, &cid),
                 QUIC_CONNID_POOL_OK);
    }

  /* Get available - should return first one */
  SocketQUICConnectionIDEntry_T *entry1
      = SocketQUICConnectionIDPool_get_available (pool);
  ASSERT_NOT_NULL (entry1);
  ASSERT (entry1->is_used);

  /* Get another - should return a different one */
  SocketQUICConnectionIDEntry_T *entry2
      = SocketQUICConnectionIDPool_get_available (pool);
  ASSERT_NOT_NULL (entry2);
  ASSERT (entry2->is_used);
  ASSERT_NE (entry1, entry2);

  /* Get third */
  SocketQUICConnectionIDEntry_T *entry3
      = SocketQUICConnectionIDPool_get_available (pool);
  ASSERT_NOT_NULL (entry3);

  /* No more available */
  SocketQUICConnectionIDEntry_T *entry4
      = SocketQUICConnectionIDPool_get_available (pool);
  ASSERT_NULL (entry4);

  Arena_dispose (&arena);
}

TEST (connid_pool_needs_more)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnectionIDPool_T pool
      = SocketQUICConnectionIDPool_new (arena, 10);
  ASSERT_NOT_NULL (pool);

  /* Empty pool needs more for migration (needs at least 2) */
  ASSERT (SocketQUICConnectionIDPool_needs_more (pool, 2));

  /* Add 1 CID - still needs more */
  SocketQUICConnectionID_T cid;
  ASSERT_EQ (SocketQUICConnectionID_generate (&cid, 8), QUIC_CONNID_OK);
  ASSERT_EQ (SocketQUICConnectionIDPool_add (pool, &cid), QUIC_CONNID_POOL_OK);
  ASSERT (SocketQUICConnectionIDPool_needs_more (pool, 2));

  /* Add second - now has enough */
  ASSERT_EQ (SocketQUICConnectionID_generate (&cid, 8), QUIC_CONNID_OK);
  ASSERT_EQ (SocketQUICConnectionIDPool_add (pool, &cid), QUIC_CONNID_POOL_OK);
  ASSERT (!SocketQUICConnectionIDPool_needs_more (pool, 2));

  Arena_dispose (&arena);
}

TEST (connid_pool_result_strings)
{
  ASSERT_NOT_NULL (
      SocketQUICConnectionIDPool_result_string (QUIC_CONNID_POOL_OK));
  ASSERT_NOT_NULL (
      SocketQUICConnectionIDPool_result_string (QUIC_CONNID_POOL_ERROR_NULL));
  ASSERT_NOT_NULL (
      SocketQUICConnectionIDPool_result_string (QUIC_CONNID_POOL_ERROR_FULL));
  ASSERT_NOT_NULL (
      SocketQUICConnectionIDPool_result_string (QUIC_CONNID_POOL_ERROR_DUP));
  ASSERT_NOT_NULL (
      SocketQUICConnectionIDPool_result_string (QUIC_CONNID_POOL_NOT_FOUND));
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

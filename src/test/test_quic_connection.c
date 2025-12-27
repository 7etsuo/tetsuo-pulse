/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_connection.c - QUIC Connection Table unit tests (RFC 9000 Section 5.2-5.3)
 *
 * Tests connection table operations, packet demultiplexing by DCID,
 * zero-length DCID (address-based) routing, and CID lifecycle management.
 */

#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "quic/SocketQUICConnection.h"
#include "quic/SocketQUICConnectionID.h"
#include "test/Test.h"

/* ============================================================================
 * Connection Creation Tests
 * ============================================================================
 */

TEST (quic_connection_new_client)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);

  ASSERT_NOT_NULL (conn);
  ASSERT_EQ (conn->role, QUIC_CONN_ROLE_CLIENT);
  ASSERT_EQ (conn->state, QUIC_CONN_STATE_IDLE);
  ASSERT_EQ (conn->local_cid_count, 0);

  Arena_dispose (&arena);
}

TEST (quic_connection_new_server)
{
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (NULL, QUIC_CONN_ROLE_SERVER);

  ASSERT_NOT_NULL (conn);
  ASSERT_EQ (conn->role, QUIC_CONN_ROLE_SERVER);

  free (conn);
}

TEST (quic_connection_add_local_cid)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICConnectionID_T cid;
  const uint8_t data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

  SocketQUICConnectionID_set (&cid, data, sizeof (data));
  SocketQUICConnection_Result result
      = SocketQUICConnection_add_local_cid (conn, &cid);

  ASSERT_EQ (result, QUIC_CONN_OK);
  ASSERT_EQ (conn->local_cid_count, 1);

  Arena_dispose (&arena);
}

TEST (quic_connection_add_peer_cid)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICConnectionID_T cid;
  uint8_t data[16];

  for (int i = 0; i < 16; i++)
    data[i] = (uint8_t)i;
  SocketQUICConnectionID_set (&cid, data, sizeof (data));

  SocketQUICConnection_Result result
      = SocketQUICConnection_add_peer_cid (conn, &cid);

  ASSERT_EQ (result, QUIC_CONN_OK);
  ASSERT_EQ (conn->peer_cid_count, 1);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Connection Table Tests
 * ============================================================================
 */

TEST (quic_conntable_new)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnTable_T table = SocketQUICConnTable_new (arena, 0);

  ASSERT_NOT_NULL (table);
  ASSERT_EQ (SocketQUICConnTable_count (table), 0);

  Arena_dispose (&arena);
}

TEST (quic_conntable_add_lookup)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnTable_T table = SocketQUICConnTable_new (arena, 0);
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
  SocketQUICConnectionID_T cid;
  const uint8_t data[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };

  SocketQUICConnectionID_set (&cid, data, sizeof (data));
  SocketQUICConnection_add_local_cid (conn, &cid);

  SocketQUICConnection_Result result = SocketQUICConnTable_add (table, conn);

  ASSERT_EQ (result, QUIC_CONN_OK);
  ASSERT_EQ (SocketQUICConnTable_count (table), 1);

  SocketQUICConnection_T found
      = SocketQUICConnTable_lookup (table, data, sizeof (data));
  ASSERT_EQ (found, conn);

  Arena_dispose (&arena);
}

TEST (quic_conntable_lookup_not_found)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnTable_T table = SocketQUICConnTable_new (arena, 0);
  const uint8_t data[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

  SocketQUICConnection_T found
      = SocketQUICConnTable_lookup (table, data, sizeof (data));
  ASSERT_NULL (found);

  Arena_dispose (&arena);
}

TEST (quic_conntable_remove)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnTable_T table = SocketQUICConnTable_new (arena, 0);
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICConnectionID_T cid;
  const uint8_t data[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 };

  SocketQUICConnectionID_set (&cid, data, sizeof (data));
  SocketQUICConnection_add_local_cid (conn, &cid);
  SocketQUICConnTable_add (table, conn);

  SocketQUICConnection_Result result = SocketQUICConnTable_remove (table, conn);

  ASSERT_EQ (result, QUIC_CONN_OK);
  ASSERT_EQ (SocketQUICConnTable_count (table), 0);

  SocketQUICConnection_T found
      = SocketQUICConnTable_lookup (table, data, sizeof (data));
  ASSERT_NULL (found);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Zero-Length DCID (Address-Based Routing) Tests
 * ============================================================================
 */

TEST (quic_connection_zero_length_dcid)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnTable_T table = SocketQUICConnTable_new (arena, 0);
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  const uint8_t local_addr[] = { 127, 0, 0, 1 };
  const uint8_t peer_addr[] = { 192, 168, 1, 1 };

  SocketQUICConnection_set_addresses (conn, local_addr, peer_addr, 12345, 443,
                                      0);

  ASSERT (SocketQUICConnection_uses_zero_dcid (conn));

  SocketQUICConnTable_add (table, conn);

  SocketQUICConnection_T found = SocketQUICConnTable_lookup_by_addr (
      table, local_addr, peer_addr, 12345, 443, 0);
  ASSERT_EQ (found, conn);

  Arena_dispose (&arena);
}

TEST (quic_connection_ipv6_addresses)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
  const uint8_t local_addr[]
      = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
  const uint8_t peer_addr[]
      = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

  SocketQUICConnection_Result result = SocketQUICConnection_set_addresses (
      conn, local_addr, peer_addr, 443, 54321, 1);

  ASSERT_EQ (result, QUIC_CONN_OK);
  ASSERT_EQ (conn->is_ipv6, 1);

  Arena_dispose (&arena);
}

/* ============================================================================
 * State and String Conversion Tests
 * ============================================================================
 */

TEST (quic_connection_state_transitions)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);

  ASSERT_EQ (conn->state, QUIC_CONN_STATE_IDLE);

  conn->state = QUIC_CONN_STATE_HANDSHAKE;
  ASSERT (strcmp (SocketQUICConnection_state_string (conn->state), "HANDSHAKE")
          == 0);

  conn->state = QUIC_CONN_STATE_ESTABLISHED;
  ASSERT (
      strcmp (SocketQUICConnection_state_string (conn->state), "ESTABLISHED")
      == 0);

  Arena_dispose (&arena);
}

TEST (quic_connection_result_strings)
{
  ASSERT (strcmp (SocketQUICConnection_result_string (QUIC_CONN_OK), "OK")
          == 0);
  ASSERT (strcmp (SocketQUICConnection_result_string (QUIC_CONN_ERROR_NULL),
                  "NULL pointer argument")
          == 0);
  ASSERT (
      strcmp (SocketQUICConnection_role_string (QUIC_CONN_ROLE_CLIENT), "CLIENT")
      == 0);
  ASSERT (
      strcmp (SocketQUICConnection_role_string (QUIC_CONN_ROLE_SERVER), "SERVER")
      == 0);
}

/* ============================================================================
 * Multiple CID Tests
 * ============================================================================
 */

TEST (quic_conntable_multiple_cids)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnTable_T table = SocketQUICConnTable_new (arena, 0);
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
  const uint8_t cid1_data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08 };
  const uint8_t cid2_data[] = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                0x18 };
  SocketQUICConnectionID_T cid1, cid2;

  SocketQUICConnectionID_set (&cid1, cid1_data, sizeof (cid1_data));
  SocketQUICConnectionID_set (&cid2, cid2_data, sizeof (cid2_data));

  SocketQUICConnection_add_local_cid (conn, &cid1);
  SocketQUICConnTable_add (table, conn);
  SocketQUICConnTable_add_cid (table, conn, &cid2);

  SocketQUICConnection_T found1
      = SocketQUICConnTable_lookup (table, cid1_data, sizeof (cid1_data));
  SocketQUICConnection_T found2
      = SocketQUICConnTable_lookup (table, cid2_data, sizeof (cid2_data));

  ASSERT_EQ (found1, conn);
  ASSERT_EQ (found2, conn);

  Arena_dispose (&arena);
}

TEST (quic_conntable_retire_cid)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnTable_T table = SocketQUICConnTable_new (arena, 0);
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  const uint8_t cid_data[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 };
  SocketQUICConnectionID_T cid;

  SocketQUICConnectionID_set (&cid, cid_data, sizeof (cid_data));
  cid.sequence = 42;

  SocketQUICConnection_add_local_cid (conn, &cid);
  SocketQUICConnTable_add (table, conn);

  SocketQUICConnection_Result result
      = SocketQUICConnTable_retire_cid (table, conn, 42);

  ASSERT_EQ (result, QUIC_CONN_OK);
  ASSERT_EQ (conn->local_cid_count, 0);

  SocketQUICConnection_T found
      = SocketQUICConnTable_lookup (table, cid_data, sizeof (cid_data));
  ASSERT_NULL (found);

  Arena_dispose (&arena);
}

TEST (quic_connection_cid_limit)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICConnection_Result result = QUIC_CONN_OK;

  for (int i = 0; i < QUIC_CONNECTION_MAX_CIDS + 1; i++)
    {
      SocketQUICConnectionID_T cid;
      uint8_t data[1] = { (uint8_t)i };
      SocketQUICConnectionID_set (&cid, data, 1);
      result = SocketQUICConnection_add_local_cid (conn, &cid);
      if (i >= QUIC_CONNECTION_MAX_CIDS)
        ASSERT_EQ (result, QUIC_CONN_ERROR_CID_LIMIT);
    }

  Arena_dispose (&arena);
}

TEST (quic_connection_update_dcid)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICConnectionID_T cid;
  const uint8_t data[] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

  SocketQUICConnectionID_set (&cid, data, sizeof (data));

  SocketQUICConnection_Result result
      = SocketQUICConnection_update_dcid (conn, &cid);

  ASSERT_EQ (result, QUIC_CONN_OK);
  ASSERT_EQ (conn->peer_cid_count, 1);

  const SocketQUICConnectionID_T *peer = SocketQUICConnection_get_peer_cid (conn);
  ASSERT_NOT_NULL (peer);
  ASSERT (SocketQUICConnectionID_equal_raw (peer, data, sizeof (data)));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Bounds Validation Tests for retire_cid (Issue #788)
 * ============================================================================
 */

TEST (quic_conntable_retire_cid_from_middle)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnTable_T table = SocketQUICConnTable_new (arena, 0);
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);

  /* Add multiple CIDs */
  for (int i = 0; i < 5; i++)
    {
      SocketQUICConnectionID_T cid;
      uint8_t data[8];
      for (int j = 0; j < 8; j++)
        data[j] = (uint8_t)(i * 10 + j);
      SocketQUICConnectionID_set (&cid, data, sizeof (data));
      cid.sequence = i + 1;
      SocketQUICConnection_add_local_cid (conn, &cid);
    }

  SocketQUICConnTable_add (table, conn);
  ASSERT_EQ (conn->local_cid_count, 5);

  /* Retire CID from middle (sequence 3) */
  SocketQUICConnection_Result result
      = SocketQUICConnTable_retire_cid (table, conn, 3);

  ASSERT_EQ (result, QUIC_CONN_OK);
  ASSERT_EQ (conn->local_cid_count, 4);

  /* Verify remaining CIDs are correct */
  ASSERT_EQ (conn->local_cids[0].sequence, (uint64_t)1);
  ASSERT_EQ (conn->local_cids[1].sequence, (uint64_t)2);
  ASSERT_EQ (conn->local_cids[2].sequence, (uint64_t)4);
  ASSERT_EQ (conn->local_cids[3].sequence, (uint64_t)5);

  Arena_dispose (&arena);
}

TEST (quic_conntable_retire_last_cid)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnTable_T table = SocketQUICConnTable_new (arena, 0);
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);

  /* Add 3 CIDs */
  for (int i = 0; i < 3; i++)
    {
      SocketQUICConnectionID_T cid;
      uint8_t data[4];
      for (int j = 0; j < 4; j++)
        data[j] = (uint8_t)(i + j);
      SocketQUICConnectionID_set (&cid, data, sizeof (data));
      cid.sequence = i + 10;
      SocketQUICConnection_add_local_cid (conn, &cid);
    }

  SocketQUICConnTable_add (table, conn);
  ASSERT_EQ (conn->local_cid_count, 3);

  /* Retire last CID (sequence 12) */
  SocketQUICConnection_Result result
      = SocketQUICConnTable_retire_cid (table, conn, 12);

  ASSERT_EQ (result, QUIC_CONN_OK);
  ASSERT_EQ (conn->local_cid_count, 2);

  /* Verify no memmove occurred for last element */
  ASSERT_EQ (conn->local_cids[0].sequence, (uint64_t)10);
  ASSERT_EQ (conn->local_cids[1].sequence, (uint64_t)11);

  Arena_dispose (&arena);
}

TEST (quic_conntable_retire_only_cid)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnTable_T table = SocketQUICConnTable_new (arena, 0);
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
  const uint8_t cid_data[] = { 0x01, 0x02, 0x03, 0x04 };
  SocketQUICConnectionID_T cid;

  SocketQUICConnectionID_set (&cid, cid_data, sizeof (cid_data));
  cid.sequence = 100;

  SocketQUICConnection_add_local_cid (conn, &cid);
  SocketQUICConnTable_add (table, conn);
  ASSERT_EQ (conn->local_cid_count, 1);

  /* Retire the only CID */
  SocketQUICConnection_Result result
      = SocketQUICConnTable_retire_cid (table, conn, 100);

  ASSERT_EQ (result, QUIC_CONN_OK);
  ASSERT_EQ (conn->local_cid_count, 0);

  Arena_dispose (&arena);
}

TEST (quic_conntable_retire_nonexistent_cid)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnTable_T table = SocketQUICConnTable_new (arena, 0);
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
  const uint8_t cid_data[] = { 0xAB, 0xCD, 0xEF };
  SocketQUICConnectionID_T cid;

  SocketQUICConnectionID_set (&cid, cid_data, sizeof (cid_data));
  cid.sequence = 5;

  SocketQUICConnection_add_local_cid (conn, &cid);
  SocketQUICConnTable_add (table, conn);

  /* Try to retire non-existent sequence */
  SocketQUICConnection_Result result
      = SocketQUICConnTable_retire_cid (table, conn, 999);

  ASSERT_EQ (result, QUIC_CONN_ERROR_NOT_FOUND);
  ASSERT_EQ (conn->local_cid_count, 1);

  Arena_dispose (&arena);
}

TEST (quic_conntable_retire_first_of_max_cids)
{
  Arena_T arena = Arena_new ();
  SocketQUICConnTable_T table = SocketQUICConnTable_new (arena, 0);
  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);

  /* Fill to maximum CIDs */
  for (int i = 0; i < QUIC_CONNECTION_MAX_CIDS; i++)
    {
      SocketQUICConnectionID_T cid;
      uint8_t data[8];
      for (int j = 0; j < 8; j++)
        data[j] = (uint8_t)(i * 8 + j);
      SocketQUICConnectionID_set (&cid, data, sizeof (data));
      cid.sequence = i + 1;
      SocketQUICConnection_add_local_cid (conn, &cid);
    }

  SocketQUICConnTable_add (table, conn);
  ASSERT_EQ (conn->local_cid_count, QUIC_CONNECTION_MAX_CIDS);

  /* Retire first CID - maximum memmove operation */
  SocketQUICConnection_Result result
      = SocketQUICConnTable_retire_cid (table, conn, 1);

  ASSERT_EQ (result, QUIC_CONN_OK);
  ASSERT_EQ (conn->local_cid_count, QUIC_CONNECTION_MAX_CIDS - 1);

  /* Verify all remaining CIDs shifted correctly */
  for (int i = 0; i < QUIC_CONNECTION_MAX_CIDS - 1; i++)
    {
      ASSERT_EQ (conn->local_cids[i].sequence, (uint64_t)(i + 2));
    }

  Arena_dispose (&arena);
}

/* ============================================================================
 * Default Size Test
 * ============================================================================
 */

TEST (quic_conntable_create_default)
{
  SocketQUICConnTable_T table = SocketQUICConnTable_new (NULL, 0);

  ASSERT_NOT_NULL (table);
  ASSERT_EQ (SocketQUICConnTable_count (table), 0);

  SocketQUICConnTable_free (&table);
  ASSERT_NULL (table);
}

/* ============================================================================
 * Arena Allocation Test
 * ============================================================================
 */

TEST (quic_connection_arena_allocation)
{
  Arena_T arena = Arena_new ();

  SocketQUICConnTable_T table = SocketQUICConnTable_new (arena, 128);
  ASSERT_NOT_NULL (table);

  SocketQUICConnection_T conn
      = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
  ASSERT_NOT_NULL (conn);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Main Entry Point
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

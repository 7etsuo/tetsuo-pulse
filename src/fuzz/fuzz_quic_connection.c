/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_connection.c - libFuzzer for QUIC Connection Table (RFC 9000 §5)
 *
 * Fuzzes connection management and packet demultiplexing:
 * - Connection table insert/lookup/remove
 * - Connection ID management
 * - Address-based lookup
 * - Idle timeout and closing states
 * - Stateless reset verification
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_quic_connection
 * ./fuzz_quic_connection corpus/quic_conn/ -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICConnection.h"
#include "quic/SocketQUICConnectionID.h"

/* Operation types */
enum
{
  OP_CONN_TABLE_OPS,
  OP_CONNECTION_LIFECYCLE,
  OP_CID_MANAGEMENT,
  OP_TIMEOUT_STATES,
  OP_STATELESS_RESET,
  OP_STRING_FUNCTIONS,
  OP_MAX
};

/* Helper to read uint64_t from buffer */
static uint64_t
read_u64 (const uint8_t *data)
{
  uint64_t val = 0;
  for (int i = 0; i < 8; i++)
    val = (val << 8) | data[i];
  return val;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 50)
    return 0;

  volatile Arena_T arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    uint8_t op = data[0] % OP_MAX;

    switch (op)
      {
      case OP_CONN_TABLE_OPS:
        {
          /* Test connection table operations */
          size_t bucket_count
              = (read_u64 (data + 1) % 1000) + 1; /* 1-1000 buckets */

          SocketQUICConnTable_T table
              = SocketQUICConnTable_new (arena, bucket_count);
          if (!table)
            break;

          /* Create and add connections */
          size_t offset = 9;
          SocketQUICConnection_T connections[20];
          int conn_count = 0;

          while (offset + 20 <= size && conn_count < 20)
            {
              SocketQUICConnection_Role role
                  = (data[offset] & 1) ? QUIC_CONN_ROLE_SERVER
                                       : QUIC_CONN_ROLE_CLIENT;

              SocketQUICConnection_T conn
                  = SocketQUICConnection_new (arena, role);
              if (!conn)
                break;

              /* Set up connection ID */
              uint8_t cid_len = (data[offset + 1] % 20) + 1;
              if (offset + 2 + cid_len > size)
                break;

              SocketQUICConnectionID_T cid;
              SocketQUICConnectionID_init (&cid);
              SocketQUICConnectionID_set (&cid, data + offset + 2, cid_len);

              SocketQUICConnection_add_local_cid (conn, &cid);

              /* Add to table */
              SocketQUICConnection_Result result
                  = SocketQUICConnTable_add (table, conn);
              (void)result;

              connections[conn_count++] = conn;
              offset += 2 + cid_len;
            }

          /* Lookup connections by CID */
          offset = 9;
          while (offset + 10 <= size)
            {
              uint8_t cid_len = (data[offset] % 20) + 1;
              if (offset + 1 + cid_len > size)
                break;

              SocketQUICConnection_T found
                  = SocketQUICConnTable_lookup (table, data + offset + 1,
                                                cid_len);
              (void)found;

              offset += 1 + cid_len;
            }

          /* Get table stats */
          uint64_t chain_hits_cid = 0, chain_hits_addr = 0, max_chain = 0;
          size_t count = 0;
          SocketQUICConnTable_get_stats (table, &chain_hits_cid,
                                         &chain_hits_addr, &max_chain, &count);
          (void)chain_hits_cid;
          (void)chain_hits_addr;
          (void)max_chain;
          (void)count;

          count = SocketQUICConnTable_count (table);
          (void)count;

          /* Remove connections */
          for (int i = 0; i < conn_count; i++)
            {
              SocketQUICConnTable_remove (table, connections[i]);
            }

          /* Test NULL inputs */
          SocketQUICConnTable_lookup (NULL, data, 8);
          SocketQUICConnTable_lookup (table, NULL, 0);
          SocketQUICConnTable_add (NULL, NULL);
          SocketQUICConnTable_remove (NULL, NULL);
          SocketQUICConnTable_count (NULL);

          /* Free table */
          SocketQUICConnTable_free (&table);
          break;
        }

      case OP_CONNECTION_LIFECYCLE:
        {
          /* Test connection creation and initialization */
          SocketQUICConnection_Role role
              = (data[1] & 1) ? QUIC_CONN_ROLE_SERVER : QUIC_CONN_ROLE_CLIENT;

          SocketQUICConnection_T conn
              = SocketQUICConnection_new (arena, role);
          if (!conn)
            break;

          /* Initialize */
          SocketQUICConnection_init (conn, role);

          /* Set addresses */
          uint8_t local_addr[16], peer_addr[16];
          memcpy (local_addr, data + 2, 16);
          memcpy (peer_addr, data + 18, 16);
          uint16_t local_port = (data[34] << 8) | data[35];
          uint16_t peer_port = (data[36] << 8) | data[37];
          int is_ipv6 = data[38] & 1;

          SocketQUICConnection_Result result
              = SocketQUICConnection_set_addresses (conn, local_addr, peer_addr,
                                                    local_port, peer_port,
                                                    is_ipv6);
          (void)result;

          /* Get CIDs */
          const SocketQUICConnectionID_T *local_cid
              = SocketQUICConnection_get_local_cid (conn);
          const SocketQUICConnectionID_T *peer_cid
              = SocketQUICConnection_get_peer_cid (conn);
          (void)local_cid;
          (void)peer_cid;

          /* Check zero DCID */
          int uses_zero = SocketQUICConnection_uses_zero_dcid (conn);
          (void)uses_zero;

          /* Test NULL inputs */
          SocketQUICConnection_init (NULL, role);
          SocketQUICConnection_set_addresses (NULL, NULL, NULL, 0, 0, 0);
          SocketQUICConnection_get_local_cid (NULL);
          SocketQUICConnection_get_peer_cid (NULL);
          SocketQUICConnection_uses_zero_dcid (NULL);

          /* Free */
          SocketQUICConnection_free (&conn);
          break;
        }

      case OP_CID_MANAGEMENT:
        {
          /* Test CID add/retire operations */
          SocketQUICConnTable_T table
              = SocketQUICConnTable_new (arena, QUIC_CONNTABLE_DEFAULT_SIZE);
          if (!table)
            break;

          SocketQUICConnection_T conn
              = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
          if (!conn)
            break;

          /* Add initial CID */
          SocketQUICConnectionID_T initial_cid;
          SocketQUICConnectionID_init (&initial_cid);
          SocketQUICConnectionID_set (&initial_cid, data + 1, 8);
          SocketQUICConnection_add_local_cid (conn, &initial_cid);

          SocketQUICConnTable_add (table, conn);

          /* Add more CIDs up to limit */
          size_t offset = 9;
          uint64_t seq = 1;
          while (offset + 20 <= size && seq < QUIC_CONNECTION_MAX_CIDS + 2)
            {
              SocketQUICConnectionID_T new_cid;
              SocketQUICConnectionID_init (&new_cid);

              uint8_t cid_len = (data[offset] % 20) + 1;
              if (offset + 1 + cid_len > size)
                break;

              SocketQUICConnectionID_set (&new_cid, data + offset + 1, cid_len);
              new_cid.sequence = seq++;

              SocketQUICConnection_Result result
                  = SocketQUICConnTable_add_cid (table, conn, &new_cid);
              (void)result;

              offset += 1 + cid_len;
            }

          /* Retire some CIDs */
          for (uint64_t i = 0; i < 5; i++)
            {
              uint64_t retire_seq = read_u64 (data + 1 + i * 8 % (size - 8));
              SocketQUICConnTable_retire_cid (table, conn, retire_seq);
            }

          /* Add peer CIDs */
          offset = 9;
          while (offset + 20 <= size)
            {
              SocketQUICConnectionID_T peer_cid;
              SocketQUICConnectionID_init (&peer_cid);

              uint8_t cid_len = (data[offset] % 20) + 1;
              if (offset + 1 + cid_len > size)
                break;

              SocketQUICConnectionID_set (&peer_cid, data + offset + 1,
                                          cid_len);

              SocketQUICConnection_add_peer_cid (conn, &peer_cid);
              offset += 1 + cid_len;
            }

          /* Update DCID */
          SocketQUICConnectionID_T new_dcid;
          SocketQUICConnectionID_init (&new_dcid);
          SocketQUICConnectionID_set (&new_dcid, data + 20, 8);
          SocketQUICConnection_update_dcid (conn, &new_dcid);

          /* Test NULL inputs */
          SocketQUICConnTable_add_cid (NULL, conn, &initial_cid);
          SocketQUICConnTable_add_cid (table, NULL, &initial_cid);
          SocketQUICConnTable_add_cid (table, conn, NULL);
          SocketQUICConnTable_retire_cid (NULL, conn, 0);
          SocketQUICConnection_add_local_cid (NULL, &initial_cid);
          SocketQUICConnection_add_peer_cid (NULL, &initial_cid);
          SocketQUICConnection_update_dcid (NULL, &new_dcid);

          SocketQUICConnTable_free (&table);
          break;
        }

      case OP_TIMEOUT_STATES:
        {
          /* Test idle timeout and closing/draining states */
          SocketQUICConnection_T conn
              = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
          if (!conn)
            break;

          uint64_t local_timeout = read_u64 (data + 1);
          uint64_t peer_timeout = read_u64 (data + 9);
          uint64_t now_ms = read_u64 (data + 17);
          uint64_t pto_ms = (read_u64 (data + 25) % 10000) + 100;

          /* Set idle timeout */
          SocketQUICConnection_set_idle_timeout (conn, local_timeout,
                                                 peer_timeout);

          /* Reset idle timer */
          SocketQUICConnection_reset_idle_timer (conn, now_ms);

          /* Check idle timeout */
          int timed_out = SocketQUICConnection_check_idle_timeout (conn, now_ms);
          (void)timed_out;

          timed_out = SocketQUICConnection_check_idle_timeout (
              conn, now_ms + local_timeout + 1000);
          (void)timed_out;

          /* Test closing state */
          SocketQUICConnection_initiate_close (conn, now_ms, pto_ms);

          int is_closing = SocketQUICConnection_is_closing_or_draining (conn);
          (void)is_closing;

          int deadline_reached
              = SocketQUICConnection_check_termination_deadline (conn, now_ms);
          (void)deadline_reached;

          /* Test draining state */
          SocketQUICConnection_T conn2
              = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_SERVER);
          if (conn2)
            {
              SocketQUICConnection_enter_draining (conn2, now_ms, pto_ms);
              is_closing = SocketQUICConnection_is_closing_or_draining (conn2);
              (void)is_closing;
            }

          /* Test NULL inputs */
          SocketQUICConnection_set_idle_timeout (NULL, 0, 0);
          SocketQUICConnection_reset_idle_timer (NULL, 0);
          SocketQUICConnection_check_idle_timeout (NULL, 0);
          SocketQUICConnection_initiate_close (NULL, 0, 0);
          SocketQUICConnection_enter_draining (NULL, 0, 0);
          SocketQUICConnection_is_closing_or_draining (NULL);
          SocketQUICConnection_check_termination_deadline (NULL, 0);
          break;
        }

      case OP_STATELESS_RESET:
        {
          /* Test stateless reset token handling */
          SocketQUICConnection_T conn
              = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
          if (!conn)
            break;

          /* Set stateless reset token */
          uint8_t token[QUIC_STATELESS_RESET_TOKEN_LEN];
          memcpy (token, data + 1, QUIC_STATELESS_RESET_TOKEN_LEN);

          SocketQUICConnection_set_stateless_reset_token (conn, token);

          /* Verify stateless reset with matching token */
          uint8_t packet[100];
          size_t packet_len = (size > 50) ? 50 : size;
          memcpy (packet, data + 17, packet_len - 17);
          /* Put token at end of packet */
          if (packet_len >= QUIC_STATELESS_RESET_TOKEN_LEN)
            {
              memcpy (packet + packet_len - QUIC_STATELESS_RESET_TOKEN_LEN,
                      token, QUIC_STATELESS_RESET_TOKEN_LEN);
            }

          int valid = SocketQUICConnection_verify_stateless_reset (
              packet, packet_len, token);
          (void)valid;

          /* Verify with wrong token */
          uint8_t wrong_token[QUIC_STATELESS_RESET_TOKEN_LEN];
          memset (wrong_token, 0xAB, QUIC_STATELESS_RESET_TOKEN_LEN);
          valid = SocketQUICConnection_verify_stateless_reset (
              packet, packet_len, wrong_token);
          (void)valid;

          /* Verify with fuzzed packet */
          valid = SocketQUICConnection_verify_stateless_reset (data, size,
                                                               token);
          (void)valid;

          /* Test edge cases */
          valid = SocketQUICConnection_verify_stateless_reset (
              packet, QUIC_STATELESS_RESET_TOKEN_LEN - 1, token);
          (void)valid;
          valid = SocketQUICConnection_verify_stateless_reset (
              packet, QUIC_STATELESS_RESET_TOKEN_LEN, token);
          (void)valid;

          /* Test NULL inputs */
          SocketQUICConnection_set_stateless_reset_token (NULL, token);
          SocketQUICConnection_verify_stateless_reset (NULL, 0, token);
          SocketQUICConnection_verify_stateless_reset (packet, packet_len,
                                                       NULL);
          break;
        }

      case OP_STRING_FUNCTIONS:
        {
          /* Test all string functions */

          /* Result codes */
          SocketQUICConnection_Result results[]
              = { QUIC_CONN_OK,           QUIC_CONN_ERROR_NULL,
                  QUIC_CONN_ERROR_FULL,   QUIC_CONN_ERROR_EXISTS,
                  QUIC_CONN_ERROR_NOT_FOUND, QUIC_CONN_ERROR_CID_LIMIT,
                  QUIC_CONN_ERROR_CHAIN_LIMIT, QUIC_CONN_ERROR_ZERO_DCID,
                  QUIC_CONN_ERROR_MEMORY };
          for (size_t i = 0; i < sizeof (results) / sizeof (results[0]); i++)
            {
              const char *str = SocketQUICConnection_result_string (results[i]);
              (void)str;
            }
          SocketQUICConnection_result_string (
              (SocketQUICConnection_Result)data[1]);

          /* States */
          SocketQUICConnection_State states[]
              = { QUIC_CONN_STATE_IDLE,      QUIC_CONN_STATE_HANDSHAKE,
                  QUIC_CONN_STATE_ESTABLISHED, QUIC_CONN_STATE_CLOSING,
                  QUIC_CONN_STATE_DRAINING,  QUIC_CONN_STATE_CLOSED };
          for (size_t i = 0; i < sizeof (states) / sizeof (states[0]); i++)
            {
              const char *str = SocketQUICConnection_state_string (states[i]);
              (void)str;
            }
          SocketQUICConnection_state_string (
              (SocketQUICConnection_State)data[2]);

          /* Roles */
          const char *client_str
              = SocketQUICConnection_role_string (QUIC_CONN_ROLE_CLIENT);
          const char *server_str
              = SocketQUICConnection_role_string (QUIC_CONN_ROLE_SERVER);
          (void)client_str;
          (void)server_str;
          SocketQUICConnection_role_string ((SocketQUICConnection_Role)data[3]);

          /* Test address lookup */
          SocketQUICConnTable_T table
              = SocketQUICConnTable_new (arena, QUIC_CONNTABLE_DEFAULT_SIZE);
          if (table)
            {
              uint8_t local_addr[16], peer_addr[16];
              memcpy (local_addr, data + 4, 16);
              memcpy (peer_addr, data + 20, 16);

              SocketQUICConnection_T found
                  = SocketQUICConnTable_lookup_by_addr (table, local_addr,
                                                        peer_addr, 443, 12345,
                                                        data[36] & 1);
              (void)found;

              SocketQUICConnTable_lookup_by_addr (NULL, local_addr, peer_addr,
                                                  0, 0, 0);
              SocketQUICConnTable_free (&table);
            }
          break;
        }
      }
  }
  EXCEPT (SocketQUICConnTable_Failed)
  {
    /* Expected on table errors */
  }
  EXCEPT (SocketQUICConnection_Failed)
  {
    /* Expected on connection errors */
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on allocation failure */
  }
  END_TRY;

  Arena_dispose ((Arena_T *)&arena);
  return 0;
}

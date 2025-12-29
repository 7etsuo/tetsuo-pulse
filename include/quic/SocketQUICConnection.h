/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICConnection.h
 * @brief QUIC Connection Table and Packet Demultiplexing (RFC 9000 Section 5.2-5.3).
 */

#ifndef SOCKETQUICCONNECTION_INCLUDED
#define SOCKETQUICCONNECTION_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICConnectionID.h"

#define QUIC_CONNTABLE_DEFAULT_SIZE 1021
#define QUIC_CONNTABLE_MAX_CHAIN_LEN 32
#define QUIC_CONNECTION_MAX_CIDS 8
#define QUIC_CONNECTION_MIN_CID_LIMIT 2
#define QUIC_STATELESS_RESET_TOKEN_LEN 16

/* RFC 9000 Section 10.2: Closing/draining timeout = 3 * PTO */
#define QUIC_TERMINATION_PTO_MULTIPLIER 3

typedef struct SocketQUICConnection *SocketQUICConnection_T;
typedef struct SocketQUICConnTable *SocketQUICConnTable_T;

extern const Except_T SocketQUICConnTable_Failed;
extern const Except_T SocketQUICConnection_Failed;

typedef enum {
  QUIC_CONN_OK = 0,
  QUIC_CONN_ERROR_NULL,
  QUIC_CONN_ERROR_FULL,
  QUIC_CONN_ERROR_EXISTS,
  QUIC_CONN_ERROR_NOT_FOUND,
  QUIC_CONN_ERROR_CID_LIMIT,
  QUIC_CONN_ERROR_CHAIN_LIMIT,
  QUIC_CONN_ERROR_ZERO_DCID,
  QUIC_CONN_ERROR_MEMORY
} SocketQUICConnection_Result;

typedef enum {
  QUIC_CONN_STATE_IDLE = 0,
  QUIC_CONN_STATE_HANDSHAKE,
  QUIC_CONN_STATE_ESTABLISHED,
  QUIC_CONN_STATE_CLOSING,
  QUIC_CONN_STATE_DRAINING,
  QUIC_CONN_STATE_CLOSED
} SocketQUICConnection_State;

typedef enum {
  QUIC_CONN_ROLE_CLIENT = 0,
  QUIC_CONN_ROLE_SERVER
} SocketQUICConnection_Role;

struct SocketQUICConnection {
  SocketQUICConnectionID_T local_cids[QUIC_CONNECTION_MAX_CIDS];
  size_t local_cid_count;
  SocketQUICConnectionID_T peer_cids[QUIC_CONNECTION_MAX_CIDS];
  size_t peer_cid_count;
  SocketQUICConnectionID_T initial_dcid;
  SocketQUICConnection_State state;
  SocketQUICConnection_Role role;
  uint8_t local_addr[16];
  uint8_t peer_addr[16];
  uint16_t local_port;
  uint16_t peer_port;
  int is_ipv6;
  struct SocketQUICConnection *hash_next;
  void *user_data;
  uint64_t local_max_idle_timeout_ms;
  uint64_t peer_max_idle_timeout_ms;
  uint64_t idle_timeout_deadline_ms;
  uint64_t last_packet_sent_ms;
  uint64_t last_packet_received_ms;
  uint64_t closing_deadline_ms;
  uint64_t draining_deadline_ms;
  uint8_t stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];
  int has_stateless_reset_token;
  void *handshake;  /* SocketQUICHandshake_T (opaque to avoid circular dependency) */
};

extern SocketQUICConnTable_T SocketQUICConnTable_new(Arena_T arena, size_t bucket_count);
extern void SocketQUICConnTable_free(SocketQUICConnTable_T *table);
extern SocketQUICConnection_T SocketQUICConnTable_lookup(SocketQUICConnTable_T table, const uint8_t *dcid, size_t dcid_len);
extern SocketQUICConnection_T SocketQUICConnTable_lookup_by_addr(SocketQUICConnTable_T table, const uint8_t *local_addr, const uint8_t *peer_addr, uint16_t local_port, uint16_t peer_port, int is_ipv6);
extern SocketQUICConnection_Result SocketQUICConnTable_add(SocketQUICConnTable_T table, SocketQUICConnection_T conn);
extern SocketQUICConnection_Result SocketQUICConnTable_remove(SocketQUICConnTable_T table, SocketQUICConnection_T conn);
extern size_t SocketQUICConnTable_count(SocketQUICConnTable_T table);
extern SocketQUICConnection_Result SocketQUICConnTable_add_cid(SocketQUICConnTable_T table, SocketQUICConnection_T conn, const SocketQUICConnectionID_T *new_cid);
extern SocketQUICConnection_Result SocketQUICConnTable_retire_cid(SocketQUICConnTable_T table, SocketQUICConnection_T conn, uint64_t sequence);
extern void SocketQUICConnTable_get_stats(SocketQUICConnTable_T table, uint64_t *chain_limit_hits_cid, uint64_t *chain_limit_hits_addr, uint64_t *max_chain_len_seen, size_t *conn_count);

extern SocketQUICConnection_T SocketQUICConnection_new(Arena_T arena, SocketQUICConnection_Role role);
extern void SocketQUICConnection_init(SocketQUICConnection_T conn, SocketQUICConnection_Role role);
extern void SocketQUICConnection_free(SocketQUICConnection_T *conn);
extern SocketQUICConnection_Result SocketQUICConnection_update_dcid(SocketQUICConnection_T conn, const SocketQUICConnectionID_T *new_dcid);
extern SocketQUICConnection_Result SocketQUICConnection_add_local_cid(SocketQUICConnection_T conn, const SocketQUICConnectionID_T *cid);
extern SocketQUICConnection_Result SocketQUICConnection_add_peer_cid(SocketQUICConnection_T conn, const SocketQUICConnectionID_T *cid);
extern const SocketQUICConnectionID_T *SocketQUICConnection_get_local_cid(SocketQUICConnection_T conn);
extern const SocketQUICConnectionID_T *SocketQUICConnection_get_peer_cid(SocketQUICConnection_T conn);
extern SocketQUICConnection_Result SocketQUICConnection_set_addresses(SocketQUICConnection_T conn, const uint8_t *local_addr, const uint8_t *peer_addr, uint16_t local_port, uint16_t peer_port, int is_ipv6);
extern int SocketQUICConnection_uses_zero_dcid(SocketQUICConnection_T conn);

extern const char *SocketQUICConnection_result_string(SocketQUICConnection_Result result);
extern const char *SocketQUICConnection_state_string(SocketQUICConnection_State state);
extern const char *SocketQUICConnection_role_string(SocketQUICConnection_Role role);

extern void SocketQUICConnection_set_idle_timeout(SocketQUICConnection_T conn, uint64_t local_timeout_ms, uint64_t peer_timeout_ms);
extern void SocketQUICConnection_reset_idle_timer(SocketQUICConnection_T conn, uint64_t now_ms);
extern int SocketQUICConnection_check_idle_timeout(SocketQUICConnection_T conn, uint64_t now_ms);
extern void SocketQUICConnection_initiate_close(SocketQUICConnection_T conn, uint64_t error_code, uint64_t now_ms, uint64_t pto_ms);
extern void SocketQUICConnection_enter_draining(SocketQUICConnection_T conn, uint64_t now_ms, uint64_t pto_ms);
extern int SocketQUICConnection_is_closing_or_draining(SocketQUICConnection_T conn);
extern int SocketQUICConnection_check_termination_deadline(SocketQUICConnection_T conn, uint64_t now_ms);
extern void SocketQUICConnection_set_stateless_reset_token(SocketQUICConnection_T conn, const uint8_t token[QUIC_STATELESS_RESET_TOKEN_LEN]);
extern int SocketQUICConnection_verify_stateless_reset(const uint8_t *packet, size_t packet_len, const uint8_t *expected_token);

#endif /* SOCKETQUICCONNECTION_INCLUDED */

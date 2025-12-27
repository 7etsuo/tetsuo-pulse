/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICConnection.h"
#include "quic/SocketQUICConnectionID.h"
#include "quic/SocketQUICConstants.h"

const Except_T SocketQUICConnTable_Failed = { &SocketQUICConnTable_Failed, "QUIC connection table operation failed" };
const Except_T SocketQUICConnection_Failed = { &SocketQUICConnection_Failed, "QUIC connection operation failed" };

struct SocketQUICConnTable {
  Arena_T arena;
  pthread_mutex_t mutex;
  int mutex_initialized;
  SocketQUICConnection_T *buckets;
  size_t bucket_count;
  size_t conn_count;
  uint32_t hash_seed;
  SocketQUICConnection_T *addr_buckets;
  size_t addr_bucket_count;
  uint64_t chain_limit_hits_cid;
  uint64_t chain_limit_hits_addr;
  uint64_t max_chain_len_seen;
};

#ifdef __linux__
#include <sys/random.h>
#define SECURE_RANDOM(buf, len) (getrandom((buf), (len), 0) == (ssize_t)(len))
#else
#define SECURE_RANDOM(buf, len) 0
#endif

static const char *result_strings[] = { "OK", "NULL pointer argument", "Connection table is full", "Connection ID already registered", "Connection not found", "Too many CIDs for connection", "Hash chain too long (DoS protection)", "Zero-length DCID conflict", "Memory allocation failed" };

DEFINE_RESULT_STRING_FUNC (SocketQUICConnection, QUIC_CONN_ERROR_MEMORY)

static const char *state_strings[] = { "IDLE", "HANDSHAKE", "ESTABLISHED", "CLOSING", "DRAINING", "CLOSED" };

const char *SocketQUICConnection_state_string(SocketQUICConnection_State state) {
  if (state > QUIC_CONN_STATE_CLOSED) return "UNKNOWN";
  return state_strings[state];
}

const char *SocketQUICConnection_role_string(SocketQUICConnection_Role role) {
  return (role == QUIC_CONN_ROLE_CLIENT) ? "CLIENT" : "SERVER";
}

static unsigned hash_cid(const uint8_t *data, size_t len, size_t bucket_count, uint32_t seed) {
  uint32_t hash = QUIC_HASH_FNV1A_OFFSET_BASIS ^ seed;
  for (size_t i = 0; i < len; i++) { hash = QUIC_HASH_FNV1A_STEP(hash, data[i]); }
  return hash % bucket_count;
}

static unsigned hash_addr_pair(const uint8_t *local_addr, const uint8_t *peer_addr, uint16_t local_port, uint16_t peer_port, int is_ipv6, size_t bucket_count, uint32_t seed) {
  uint32_t hash = QUIC_HASH_FNV1A_OFFSET_BASIS ^ seed;
  size_t addr_len = is_ipv6 ? 16 : 4;
  for (size_t i = 0; i < addr_len; i++) { hash = QUIC_HASH_FNV1A_STEP(hash, local_addr[i]); }
  for (size_t i = 0; i < addr_len; i++) { hash = QUIC_HASH_FNV1A_STEP(hash, peer_addr[i]); }
  hash = QUIC_HASH_FNV1A_STEP(hash, local_port & 0xFF); hash = QUIC_HASH_FNV1A_STEP(hash, (local_port >> 8) & 0xFF);
  hash = QUIC_HASH_FNV1A_STEP(hash, peer_port & 0xFF); hash = QUIC_HASH_FNV1A_STEP(hash, (peer_port >> 8) & 0xFF);
  return hash % bucket_count;
}

SocketQUICConnTable_T SocketQUICConnTable_new(Arena_T arena, size_t bucket_count) {
  SocketQUICConnTable_T table;
  int using_arena;

  if (bucket_count == 0) {
    bucket_count = QUIC_CONNTABLE_DEFAULT_SIZE;
  }

  using_arena = (arena != NULL);

  /* Allocate table structure */
  if (using_arena) {
    table = Arena_calloc(arena, 1, sizeof(*table), __FILE__, __LINE__);
  } else {
    table = calloc(1, sizeof(*table));
  }
  if (!table) {
    RAISE(SocketQUICConnTable_Failed);
  }

  table->arena = arena;
  table->bucket_count = bucket_count;
  table->addr_bucket_count = bucket_count;

  /* Allocate hash table buckets */
  if (using_arena) {
    table->buckets = Arena_calloc(arena, bucket_count, sizeof(SocketQUICConnection_T), __FILE__, __LINE__);
    table->addr_buckets = Arena_calloc(arena, bucket_count, sizeof(SocketQUICConnection_T), __FILE__, __LINE__);
  } else {
    table->buckets = calloc(bucket_count, sizeof(SocketQUICConnection_T));
    table->addr_buckets = calloc(bucket_count, sizeof(SocketQUICConnection_T));
  }

  if (!table->buckets || !table->addr_buckets) {
    if (!using_arena) {
      free(table->buckets);
      free(table->addr_buckets);
      free(table);
    }
    RAISE(SocketQUICConnTable_Failed);
  }

  /* Initialize mutex */
  if (pthread_mutex_init(&table->mutex, NULL) != 0) {
    if (!using_arena) {
      free(table->buckets);
      free(table->addr_buckets);
      free(table);
    }
    RAISE(SocketQUICConnTable_Failed);
  }
  table->mutex_initialized = 1;

  /* Initialize hash seed with secure random or fallback */
  if (!SECURE_RANDOM(&table->hash_seed, sizeof(table->hash_seed))) {
    table->hash_seed = (uint32_t)((size_t)table ^ (size_t)table->buckets);
  }

  return table;
}

void SocketQUICConnTable_free(SocketQUICConnTable_T *tablep) {
  if (!tablep || !*tablep) return;
  SocketQUICConnTable_T table = *tablep; *tablep = NULL;
  if (table->mutex_initialized) pthread_mutex_destroy(&table->mutex);
  if (!table->arena) { free(table->buckets); free(table->addr_buckets); free(table); }
}

SocketQUICConnection_T SocketQUICConnTable_lookup(SocketQUICConnTable_T table, const uint8_t *dcid, size_t dcid_len) {
  if (!table || dcid_len == 0 || !dcid) return NULL;
  pthread_mutex_lock(&table->mutex);
  unsigned idx = hash_cid(dcid, dcid_len, table->bucket_count, table->hash_seed);
  SocketQUICConnection_T conn = table->buckets[idx];
  int chain_len = 0;
  while (conn) {
    if (++chain_len > QUIC_CONNTABLE_MAX_CHAIN_LEN) {
      table->chain_limit_hits_cid++;
      if ((uint64_t)chain_len > table->max_chain_len_seen) { table->max_chain_len_seen = (uint64_t)chain_len; }
      pthread_mutex_unlock(&table->mutex);
      return NULL;
    }
    for (size_t i = 0; i < conn->local_cid_count; i++)
      if (SocketQUICConnectionID_equal_raw(&conn->local_cids[i], dcid, dcid_len)) { pthread_mutex_unlock(&table->mutex); return conn; }
    conn = conn->hash_next;
  }
  pthread_mutex_unlock(&table->mutex);
  return NULL;
}

SocketQUICConnection_T SocketQUICConnTable_lookup_by_addr(SocketQUICConnTable_T table, const uint8_t *local_addr, const uint8_t *peer_addr, uint16_t local_port, uint16_t peer_port, int is_ipv6) {
  if (!table || !local_addr || !peer_addr) return NULL;
  size_t addr_len = is_ipv6 ? 16 : 4;
  pthread_mutex_lock(&table->mutex);
  unsigned idx = hash_addr_pair(local_addr, peer_addr, local_port, peer_port, is_ipv6, table->addr_bucket_count, table->hash_seed);
  SocketQUICConnection_T conn = table->addr_buckets[idx];
  int chain_len = 0;
  while (conn) {
    if (++chain_len > QUIC_CONNTABLE_MAX_CHAIN_LEN) {
      table->chain_limit_hits_addr++;
      if ((uint64_t)chain_len > table->max_chain_len_seen) { table->max_chain_len_seen = (uint64_t)chain_len; }
      pthread_mutex_unlock(&table->mutex);
      return NULL;
    }
    if (conn->local_port == local_port && conn->peer_port == peer_port && conn->is_ipv6 == is_ipv6 && memcmp(conn->local_addr, local_addr, addr_len) == 0 && memcmp(conn->peer_addr, peer_addr, addr_len) == 0) { pthread_mutex_unlock(&table->mutex); return conn; }
    conn = conn->hash_next;
  }
  pthread_mutex_unlock(&table->mutex);
  return NULL;
}

static void insert_into_cid_bucket(SocketQUICConnTable_T table, SocketQUICConnection_T conn, const uint8_t *cid_data, size_t cid_len) {
  unsigned idx = hash_cid(cid_data, cid_len, table->bucket_count, table->hash_seed);
  conn->hash_next = table->buckets[idx]; table->buckets[idx] = conn;
}

static void insert_into_addr_bucket(SocketQUICConnTable_T table, SocketQUICConnection_T conn) {
  unsigned idx = hash_addr_pair(conn->local_addr, conn->peer_addr, conn->local_port, conn->peer_port, conn->is_ipv6, table->addr_bucket_count, table->hash_seed);
  conn->hash_next = table->addr_buckets[idx]; table->addr_buckets[idx] = conn;
}

SocketQUICConnection_Result SocketQUICConnTable_add(SocketQUICConnTable_T table, SocketQUICConnection_T conn) {
  if (!table || !conn) return QUIC_CONN_ERROR_NULL;
  pthread_mutex_lock(&table->mutex);
  if (conn->local_cid_count == 0 || (conn->local_cid_count == 1 && conn->local_cids[0].len == 0)) insert_into_addr_bucket(table, conn);
  else for (size_t i = 0; i < conn->local_cid_count; i++) if (conn->local_cids[i].len > 0) insert_into_cid_bucket(table, conn, conn->local_cids[i].data, conn->local_cids[i].len);
  table->conn_count++;
  pthread_mutex_unlock(&table->mutex);
  return QUIC_CONN_OK;
}

static int remove_from_cid_bucket(SocketQUICConnTable_T table, SocketQUICConnection_T conn, const uint8_t *cid_data, size_t cid_len) {
  unsigned idx = hash_cid(cid_data, cid_len, table->bucket_count, table->hash_seed);
  SocketQUICConnection_T *prev = &table->buckets[idx];
  while (*prev) { if (*prev == conn) { *prev = conn->hash_next; return 1; } prev = &(*prev)->hash_next; }
  return 0;
}

static int remove_from_addr_bucket(SocketQUICConnTable_T table, SocketQUICConnection_T conn) {
  unsigned idx = hash_addr_pair(conn->local_addr, conn->peer_addr, conn->local_port, conn->peer_port, conn->is_ipv6, table->addr_bucket_count, table->hash_seed);
  SocketQUICConnection_T *prev = &table->addr_buckets[idx];
  while (*prev) { if (*prev == conn) { *prev = conn->hash_next; return 1; } prev = &(*prev)->hash_next; }
  return 0;
}

SocketQUICConnection_Result SocketQUICConnTable_remove(SocketQUICConnTable_T table, SocketQUICConnection_T conn) {
  if (!table || !conn) return QUIC_CONN_ERROR_NULL;
  pthread_mutex_lock(&table->mutex);
  int removed = 0;
  for (size_t i = 0; i < conn->local_cid_count; i++) if (conn->local_cids[i].len > 0 && remove_from_cid_bucket(table, conn, conn->local_cids[i].data, conn->local_cids[i].len)) { removed = 1; break; }
  if (!removed) removed = remove_from_addr_bucket(table, conn);
  if (removed) { table->conn_count--; conn->hash_next = NULL; }
  pthread_mutex_unlock(&table->mutex);
  return removed ? QUIC_CONN_OK : QUIC_CONN_ERROR_NOT_FOUND;
}

size_t SocketQUICConnTable_count(SocketQUICConnTable_T table) {
  if (!table) return 0;
  pthread_mutex_lock(&table->mutex); size_t count = table->conn_count; pthread_mutex_unlock(&table->mutex);
  return count;
}

SocketQUICConnection_Result SocketQUICConnTable_add_cid(SocketQUICConnTable_T table, SocketQUICConnection_T conn, const SocketQUICConnectionID_T *new_cid) {
  if (!table || !conn || !new_cid) return QUIC_CONN_ERROR_NULL;
  SocketQUICConnection_Result result = SocketQUICConnection_add_local_cid(conn, new_cid);
  if (result != QUIC_CONN_OK) return result;
  if (new_cid->len > 0) { pthread_mutex_lock(&table->mutex); insert_into_cid_bucket(table, conn, new_cid->data, new_cid->len); pthread_mutex_unlock(&table->mutex); }
  return QUIC_CONN_OK;
}

SocketQUICConnection_Result SocketQUICConnTable_retire_cid(SocketQUICConnTable_T table, SocketQUICConnection_T conn, uint64_t sequence) {
  if (!table || !conn) return QUIC_CONN_ERROR_NULL;
  pthread_mutex_lock(&table->mutex);
  int found = 0;
  for (size_t i = 0; i < conn->local_cid_count; i++) {
    if (conn->local_cids[i].sequence == sequence) {
      if (conn->local_cids[i].len > 0) remove_from_cid_bucket(table, conn, conn->local_cids[i].data, conn->local_cids[i].len);
      /* Explicit bounds validation for defensive programming (issue #788) */
      if (i < conn->local_cid_count - 1) {
        /* Assert invariants to catch programming errors early */
        assert(conn->local_cid_count <= QUIC_CONNECTION_MAX_CIDS);
        assert(i + 1 < QUIC_CONNECTION_MAX_CIDS);
        assert(conn->local_cid_count > 0);  /* Prevent underflow */
        /* Safe to proceed with memmove */
        size_t move_count = conn->local_cid_count - i - 1;
        memmove(&conn->local_cids[i], &conn->local_cids[i + 1], move_count * sizeof(SocketQUICConnectionID_T));
      }
      conn->local_cid_count--; found = 1; break;
    }
  }
  pthread_mutex_unlock(&table->mutex);
  return found ? QUIC_CONN_OK : QUIC_CONN_ERROR_NOT_FOUND;
}

SocketQUICConnection_T SocketQUICConnection_new(Arena_T arena, SocketQUICConnection_Role role) {
  SocketQUICConnection_T conn;
  if (arena) conn = Arena_calloc(arena, 1, sizeof(*conn), __FILE__, __LINE__);
  else conn = calloc(1, sizeof(*conn));
  if (!conn) RAISE(SocketQUICConnection_Failed);
  SocketQUICConnection_init(conn, role);
  return conn;
}

void SocketQUICConnection_init(SocketQUICConnection_T conn, SocketQUICConnection_Role role) {
  if (!conn) return;
  memset(conn, 0, sizeof(*conn)); conn->role = role; conn->state = QUIC_CONN_STATE_IDLE;
}

void SocketQUICConnection_free(SocketQUICConnection_T *connp) { if (connp && *connp) *connp = NULL; }

SocketQUICConnection_Result SocketQUICConnection_update_dcid(SocketQUICConnection_T conn, const SocketQUICConnectionID_T *new_dcid) {
  if (!conn || !new_dcid) return QUIC_CONN_ERROR_NULL;
  if (conn->peer_cid_count == 0) conn->peer_cid_count = 1;
  return SocketQUICConnectionID_copy(&conn->peer_cids[0], new_dcid) == QUIC_CONNID_OK ? QUIC_CONN_OK : QUIC_CONN_ERROR_NULL;
}

SocketQUICConnection_Result SocketQUICConnection_add_local_cid(SocketQUICConnection_T conn, const SocketQUICConnectionID_T *cid) {
  if (!conn || !cid) return QUIC_CONN_ERROR_NULL;
  if (conn->local_cid_count >= QUIC_CONNECTION_MAX_CIDS) return QUIC_CONN_ERROR_CID_LIMIT;
  if (SocketQUICConnectionID_copy(&conn->local_cids[conn->local_cid_count], cid) != QUIC_CONNID_OK) return QUIC_CONN_ERROR_NULL;
  conn->local_cid_count++; return QUIC_CONN_OK;
}

SocketQUICConnection_Result SocketQUICConnection_add_peer_cid(SocketQUICConnection_T conn, const SocketQUICConnectionID_T *cid) {
  if (!conn || !cid) return QUIC_CONN_ERROR_NULL;
  if (conn->peer_cid_count >= QUIC_CONNECTION_MAX_CIDS) return QUIC_CONN_ERROR_CID_LIMIT;
  if (SocketQUICConnectionID_copy(&conn->peer_cids[conn->peer_cid_count], cid) != QUIC_CONNID_OK) return QUIC_CONN_ERROR_NULL;
  conn->peer_cid_count++; return QUIC_CONN_OK;
}

const SocketQUICConnectionID_T *SocketQUICConnection_get_local_cid(SocketQUICConnection_T conn) { return (!conn || conn->local_cid_count == 0) ? NULL : &conn->local_cids[0]; }
const SocketQUICConnectionID_T *SocketQUICConnection_get_peer_cid(SocketQUICConnection_T conn) { return (!conn || conn->peer_cid_count == 0) ? NULL : &conn->peer_cids[0]; }

SocketQUICConnection_Result SocketQUICConnection_set_addresses(SocketQUICConnection_T conn, const uint8_t *local_addr, const uint8_t *peer_addr, uint16_t local_port, uint16_t peer_port, int is_ipv6) {
  if (!conn || !local_addr || !peer_addr) return QUIC_CONN_ERROR_NULL;
  size_t addr_len = is_ipv6 ? 16 : 4;
  memcpy(conn->local_addr, local_addr, addr_len); memcpy(conn->peer_addr, peer_addr, addr_len);
  conn->local_port = local_port; conn->peer_port = peer_port; conn->is_ipv6 = is_ipv6;
  return QUIC_CONN_OK;
}

int SocketQUICConnection_uses_zero_dcid(SocketQUICConnection_T conn) {
  if (!conn) return 0;
  return (conn->local_cid_count == 0) || (conn->local_cid_count == 1 && conn->local_cids[0].len == 0);
}

void SocketQUICConnTable_get_stats(SocketQUICConnTable_T table, uint64_t *chain_limit_hits_cid, uint64_t *chain_limit_hits_addr, uint64_t *max_chain_len_seen, size_t *conn_count) {
  if (!table) return;
  pthread_mutex_lock(&table->mutex);
  if (chain_limit_hits_cid) *chain_limit_hits_cid = table->chain_limit_hits_cid;
  if (chain_limit_hits_addr) *chain_limit_hits_addr = table->chain_limit_hits_addr;
  if (max_chain_len_seen) *max_chain_len_seen = table->max_chain_len_seen;
  if (conn_count) *conn_count = table->conn_count;
  pthread_mutex_unlock(&table->mutex);
}

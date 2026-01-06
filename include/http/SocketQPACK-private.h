/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-private.h
 * @brief Internal QPACK header compression structures and constants.
 * @internal
 *
 * Private implementation for QPACK (RFC 9204). Use SocketQPACK.h for public
 * API.
 */

#ifndef SOCKETQPACK_PRIVATE_INCLUDED
#define SOCKETQPACK_PRIVATE_INCLUDED

#include "http/SocketQPACK.h"
#include <stdint.h>

#include "core/SocketSecurity.h"

/* Hash table size for stream reference lookup (must be power of 2) */
#define QPACK_STREAM_REF_HASH_SIZE 64
#define QPACK_STREAM_REF_HASH_MASK (QPACK_STREAM_REF_HASH_SIZE - 1)

/* Initial capacity for entry indices array per stream */
#define QPACK_INITIAL_ENTRY_CAPACITY 8

/* Average dynamic entry size estimate */
#define QPACK_AVERAGE_DYNAMIC_ENTRY_SIZE 50

/* Minimum dynamic table capacity */
#define QPACK_MIN_DYNAMIC_TABLE_CAPACITY 16

/* Integer encoding constants (same as HPACK RFC 7541 Section 5.1) */
#define QPACK_INT_CONTINUATION_MASK 0x80
#define QPACK_INT_PAYLOAD_MASK 0x7F
#define QPACK_INT_CONTINUATION_VALUE 128
#define QPACK_INT_BUF_SIZE 16
#define QPACK_MAX_INT_CONTINUATION_BYTES 10
#define QPACK_MAX_SAFE_SHIFT 56

/**
 * QPACK Decoder internal structure.
 */
struct SocketQPACK_Decoder
{
  SocketQPACK_Table_T table;
  size_t max_table_size;
  size_t max_blocked_streams;
  size_t max_header_size;
  size_t max_header_list_size;

  /* Stream reference tracking via hash table */
  SocketQPACK_StreamRef *stream_refs[QPACK_STREAM_REF_HASH_SIZE];

  Arena_T arena;
};

/**
 * Hash function for stream ID lookup.
 */
static inline size_t
qpack_stream_hash (uint64_t stream_id)
{
  /* Simple hash: use lower bits after mixing */
  uint64_t h = stream_id;
  h ^= h >> 33;
  h *= 0xff51afd7ed558ccdULL;
  h ^= h >> 33;
  return (size_t)(h & QPACK_STREAM_REF_HASH_MASK);
}

/**
 * Calculate entry size (name + value + overhead).
 */
static inline size_t
qpack_entry_size (size_t name_len, size_t value_len)
{
  size_t temp;
  if (SocketSecurity_check_add (name_len, value_len, &temp)
      && SocketSecurity_check_add (temp, SOCKETQPACK_ENTRY_OVERHEAD, &temp))
    {
      return temp;
    }
  return SIZE_MAX;
}

/**
 * Validate prefix bits for integer encoding.
 */
static inline int
qpack_valid_prefix_bits (int prefix_bits)
{
  return prefix_bits >= 1 && prefix_bits <= 8;
}

#endif /* SOCKETQPACK_PRIVATE_INCLUDED */

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

#include "quic/SocketQPACK.h"
#include <stdint.h>

#include "core/SocketSecurity.h"

/* ============================================================================
 * Decoder Stream Instruction Bit Patterns (RFC 9204 Section 4.4)
 * ============================================================================
 */

/* Section Acknowledgment (4.4.1): 1xxxxxxx */
#define QPACK_SECTION_ACK_MASK 0x80
#define QPACK_SECTION_ACK_PREFIX 7

/* Stream Cancellation (4.4.2): 01xxxxxx */
#define QPACK_STREAM_CANCEL_MASK 0xC0
#define QPACK_STREAM_CANCEL_PATTERN 0x40
#define QPACK_STREAM_CANCEL_PREFIX 6

/* Insert Count Increment (4.4.3): 00xxxxxx */
#define QPACK_INSERT_COUNT_INC_MASK 0xC0
#define QPACK_INSERT_COUNT_INC_PATTERN 0x00
#define QPACK_INSERT_COUNT_INC_PREFIX 6

/* ============================================================================
 * Integer Encoding Constants (RFC 9204 Section 4.1.1)
 * ============================================================================
 */

#define QPACK_INT_CONTINUATION_MASK 0x80
#define QPACK_INT_PAYLOAD_MASK 0x7F
#define QPACK_INT_CONTINUATION_VALUE 128

/* Max continuation bytes: 10 bytes * 7 bits = 70 bits (> 64 bits needed) */
#define QPACK_MAX_INT_CONTINUATION_BYTES 10

/* Max safe shift: 64 bits - 8 bits for last continuation byte payload */
#define QPACK_MAX_SAFE_SHIFT 56

/* Buffer size for integer encoding (prefix + 10 continuation + safety) */
#define QPACK_INT_BUF_SIZE 16

/* ============================================================================
 * Stream Tracking Constants
 * ============================================================================
 */

/* Initial capacity for pending stream tracking hash table */
#define QPACK_INITIAL_STREAM_CAPACITY 64

/* Load factor threshold for resizing (75%) */
#define QPACK_LOAD_FACTOR_THRESHOLD 75

/* ============================================================================
 * Internal Types
 * ============================================================================
 */

/**
 * @brief Entry in the pending streams hash table.
 *
 * Tracks streams that have sent header sections with non-zero Required
 * Insert Count (RIC) and are awaiting acknowledgment.
 */
typedef struct SocketQPACKPendingStream_T
{
  uint64_t stream_id;                      /**< Stream ID (key) */
  uint64_t required_insert_count;          /**< RIC of pending section */
  int in_use;                              /**< 1 if slot is occupied */
  struct SocketQPACKPendingStream_T *next; /**< Chain for hash collisions */
} SocketQPACKPendingStream_T;

/**
 * @brief QPACK decoder acknowledgment state.
 *
 * Tracks the Known Received Count and pending stream acknowledgments.
 * This state is maintained by the encoder to track what the decoder
 * has acknowledged.
 */
struct SocketQPACK_DecoderState
{
  uint64_t known_received_count; /**< Max acknowledged RIC (RFC 9204 3.3) */
  uint64_t insert_count;         /**< Current dynamic table insert count */

  /* Hash table for pending streams */
  SocketQPACKPendingStream_T *streams; /**< Hash table buckets */
  size_t stream_capacity;              /**< Number of buckets */
  size_t stream_count;                 /**< Number of occupied entries */

  Arena_T arena; /**< Memory arena */
};

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * @brief Check if prefix bits value is valid.
 *
 * @param prefix_bits Number of prefix bits.
 *
 * @return 1 if valid (1-8), 0 otherwise.
 */
static inline int
qpack_valid_prefix_bits (int prefix_bits)
{
  return prefix_bits >= 1 && prefix_bits <= 8;
}

/**
 * @brief Calculate entry size including overhead.
 *
 * @param name_len  Name length in bytes.
 * @param value_len Value length in bytes.
 *
 * @return Entry size, or SIZE_MAX on overflow.
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
 * @brief Hash function for stream IDs.
 *
 * Uses FNV-1a variant for good distribution.
 *
 * @param stream_id Stream ID to hash.
 * @param capacity  Table capacity (must be power of 2).
 *
 * @return Bucket index.
 */
static inline size_t
qpack_stream_hash (uint64_t stream_id, size_t capacity)
{
  /* FNV-1a inspired mixing */
  uint64_t hash = stream_id;
  hash ^= hash >> 33;
  hash *= 0xff51afd7ed558ccdULL;
  hash ^= hash >> 33;
  hash *= 0xc4ceb9fe1a85ec53ULL;
  hash ^= hash >> 33;
  return (size_t)(hash & (capacity - 1));
}

#endif /* SOCKETQPACK_PRIVATE_INCLUDED */

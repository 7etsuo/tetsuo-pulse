/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK.h
 * @brief QPACK header compression/decompression for HTTP/3 (RFC 9204).
 *
 * Implements QPACK algorithm with static table (99 entries), dynamic table
 * with out-of-order delivery support, and Required Insert Count encoding.
 *
 * Thread Safety: Encoder/decoder instances are NOT thread-safe. One instance
 * per connection/thread recommended.
 *
 * @defgroup qpack QPACK Header Compression Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9204
 */

#ifndef SOCKETQPACK_INCLUDED
#define SOCKETQPACK_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/Except.h"

#ifndef SOCKETQPACK_DEFAULT_TABLE_SIZE
#define SOCKETQPACK_DEFAULT_TABLE_SIZE 4096
#endif

#ifndef SOCKETQPACK_MAX_TABLE_SIZE
#define SOCKETQPACK_MAX_TABLE_SIZE (64 * 1024)
#endif

/* RFC 9204 Section 4.5.1.1: MaxEntries = floor(MaxTableCapacity / 32) */
#define SOCKETQPACK_ENTRY_OVERHEAD 32

extern const Except_T SocketQPACK_Error;

typedef enum
{
  QPACK_OK = 0,
  QPACK_INCOMPLETE,
  QPACK_ERROR,
  QPACK_ERROR_INVALID_INDEX,
  QPACK_ERROR_INSERT_COUNT,
  QPACK_ERROR_INTEGER,
  QPACK_ERROR_TABLE_SIZE,
  QPACK_ERROR_HEADER_SIZE,
  QPACK_ERROR_LIST_SIZE
} SocketQPACK_Result;

/**
 * @brief State for Required Insert Count encoding/decoding.
 *
 * RFC 9204 Section 4.5.1.1: Tracks the total number of insertions and
 * the maximum table capacity for proper wrap-around handling.
 */
typedef struct
{
  uint64_t total_inserts;      /**< Total insertions in encoder/decoder */
  uint32_t max_table_capacity; /**< Max table size in bytes */
} SocketQPACK_InsertCountState;

/**
 * @brief Calculate MaxEntries from MaxTableCapacity.
 *
 * RFC 9204 Section 4.5.1.1: MaxEntries = floor(MaxTableCapacity / 32)
 *
 * @param max_table_capacity Maximum dynamic table capacity in bytes
 * @return MaxEntries value
 */
extern uint32_t SocketQPACK_max_entries (uint32_t max_table_capacity);

/**
 * @brief Encode Required Insert Count for field section prefix.
 *
 * RFC 9204 Section 4.5.1.1: Encodes Required Insert Count with wrap-around.
 *
 * Algorithm:
 * - If RIC == 0: encoded = 0
 * - Otherwise: encoded = (RIC mod (2 * MaxEntries)) + 1
 *
 * @param required_insert_count Required Insert Count to encode
 * @param max_table_capacity    Maximum table capacity in bytes
 * @return Encoded Required Insert Count value
 */
extern uint64_t
SocketQPACK_encode_required_insert_count (uint64_t required_insert_count,
                                          uint32_t max_table_capacity);

/**
 * @brief Decode Required Insert Count from field section prefix.
 *
 * RFC 9204 Section 4.5.1.1: Decodes with wrap-around and validation.
 *
 * Validation checks:
 * - EncodedRIC must not exceed FullRange (2 * MaxEntries)
 * - Decoded value must not be 0 (except when EncodedRIC is 0)
 * - Handles wrap-around when ReqInsertCount > MaxValue
 *
 * @param encoded_insert_count Encoded value from wire format
 * @param max_table_capacity   Maximum table capacity in bytes
 * @param total_inserts        Total number of insertions so far
 * @param decoded_out          Output: decoded Required Insert Count
 * @return QPACK_OK on success, QPACK_ERROR_INSERT_COUNT on validation failure
 */
extern SocketQPACK_Result
SocketQPACK_decode_required_insert_count (uint64_t encoded_insert_count,
                                          uint32_t max_table_capacity,
                                          uint64_t total_inserts,
                                          uint64_t *decoded_out);

extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/** @} */

#endif /* SOCKETQPACK_INCLUDED */

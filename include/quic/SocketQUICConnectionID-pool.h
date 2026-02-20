/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICConnectionID-pool.h
 * @brief QUIC Connection ID Pool Management (RFC 9000 Section 5.1.1-5.1.2).
 *
 * Implements connection ID lifecycle operations including:
 *   - Pool of active connection IDs with sequence number tracking
 *   - Hash table lookup by connection ID bytes
 *   - Retire Prior To bulk retirement (RFC 9000 §5.1.2)
 *   - active_connection_id_limit enforcement
 *
 * RFC 9000 §5.1.1 - Connection ID Issuance:
 *   - Initial CID has sequence 0
 *   - preferred_address CID has sequence 1
 *   - Endpoints must not exceed peer's active_connection_id_limit
 *
 * RFC 9000 §5.1.2 - Consuming and Retiring CIDs:
 *   - Retire Prior To indicates all CIDs with lower sequence should be retired
 *   - Endpoints should ensure sufficient CIDs for migration
 *
 * Thread Safety: Pool operations are NOT thread-safe. Use external
 * synchronization when accessing from multiple threads.
 *
 * @defgroup quic_connid_pool QUIC Connection ID Pool
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9000#section-5.1
 */

#ifndef SOCKETQUICCONNECTIONID_POOL_INCLUDED
#define SOCKETQUICCONNECTIONID_POOL_INCLUDED

#include "core/Arena.h"
#include "quic/SocketQUICConnectionID.h"

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Default hash table size for connection ID lookup.
 *
 * Should be a power of 2 for efficient modulo via bitmask.
 */
#define QUIC_CONNID_POOL_HASH_SIZE 32

/**
 * @brief Maximum hash chain length before considering it suspicious.
 *
 * Protects against hash collision DoS attacks.
 */
#define QUIC_CONNID_POOL_MAX_CHAIN_LEN 16

/**
 * @brief Entry in the connection ID pool.
 *
 * Wraps a connection ID with pool management metadata.
 */
typedef struct SocketQUICConnectionIDEntry
{
  SocketQUICConnectionID_T cid; /**< The connection ID data */

  int is_retired;   /**< Non-zero if retired but not yet removed */
  int is_used;      /**< Non-zero if currently in use for a path */
  uint64_t used_at; /**< Monotonic timestamp when last used (ms) */

  struct SocketQUICConnectionIDEntry *hash_next; /**< CID hash chain pointer */
  struct SocketQUICConnectionIDEntry
      *seq_hash_next;                            /**< Sequence hash chain ptr */
  struct SocketQUICConnectionIDEntry *list_next; /**< Sequence list pointer */
  struct SocketQUICConnectionIDEntry *list_prev; /**< Sequence list pointer */

} SocketQUICConnectionIDEntry_T;

/**
 * @brief Connection ID pool for managing active connection IDs.
 *
 * Maintains a hash table for O(1) lookup by CID bytes and a doubly-linked
 * list for sequence-ordered operations like Retire Prior To.
 */
typedef struct SocketQUICConnectionIDPool
{
  Arena_T arena; /**< Memory arena for allocations */

  SocketQUICConnectionIDEntry_T *hash_table[QUIC_CONNID_POOL_HASH_SIZE];
  /**< Hash table for O(1) CID byte lookup */

  SocketQUICConnectionIDEntry_T *sequence_table[QUIC_CONNID_POOL_HASH_SIZE];
  /**< Hash table for O(1) sequence number lookup */

  SocketQUICConnectionIDEntry_T *list_head; /**< First entry by sequence */
  SocketQUICConnectionIDEntry_T *list_tail; /**< Last entry by sequence */

  uint64_t next_sequence;   /**< Next sequence number to assign */
  uint64_t retire_prior_to; /**< Current retire prior to value */
  size_t active_count;      /**< Number of non-retired entries */
  size_t total_count;       /**< Total entries including retired */
  size_t peer_limit;        /**< Peer's active_connection_id_limit */
  uint32_t hash_seed;       /**< Random seed for hash function */

} *SocketQUICConnectionIDPool_T;

/**
 * @brief Result codes for pool operations.
 */
typedef enum
{
  QUIC_CONNID_POOL_OK = 0,      /**< Operation succeeded */
  QUIC_CONNID_POOL_ERROR_NULL,  /**< NULL pointer argument */
  QUIC_CONNID_POOL_ERROR_FULL,  /**< Pool at peer's limit */
  QUIC_CONNID_POOL_ERROR_DUP,   /**< Duplicate connection ID */
  QUIC_CONNID_POOL_ERROR_SEQ,   /**< Invalid sequence number */
  QUIC_CONNID_POOL_ERROR_LIMIT, /**< Limit exceeded */
  QUIC_CONNID_POOL_ERROR_CHAIN, /**< Hash chain too long (DoS) */
  QUIC_CONNID_POOL_NOT_FOUND    /**< Connection ID not in pool */
} SocketQUICConnectionIDPool_Result;

/**
 * @brief Create a new connection ID pool.
 *
 * @param arena      Memory arena for allocations.
 * @param peer_limit Peer's active_connection_id_limit (minimum 2).
 *
 * @return New pool instance, or NULL on failure.
 */
extern SocketQUICConnectionIDPool_T
SocketQUICConnectionIDPool_new (Arena_T arena, size_t peer_limit);

/**
 * @brief Get the number of active (non-retired) connection IDs.
 *
 * @param pool Pool to query.
 *
 * @return Number of active connection IDs.
 */
extern size_t SocketQUICConnectionIDPool_active_count (
    const SocketQUICConnectionIDPool_T pool);

/**
 * @brief Get the total number of connection IDs including retired.
 *
 * @param pool Pool to query.
 *
 * @return Total connection ID count.
 */
extern size_t SocketQUICConnectionIDPool_total_count (
    const SocketQUICConnectionIDPool_T pool);

/**
 * @brief Check if more connection IDs can be added.
 *
 * @param pool Pool to check.
 *
 * @return 1 if space available, 0 if at peer limit.
 */
extern int
SocketQUICConnectionIDPool_can_add (const SocketQUICConnectionIDPool_T pool);

/**
 * @brief Add a new connection ID to the pool.
 *
 * The connection ID is assigned the next sequence number automatically.
 * The sequence number is stored in cid->sequence.
 *
 * @param pool Pool to add to.
 * @param cid  Connection ID to add (sequence will be set).
 *
 * @return QUIC_CONNID_POOL_OK on success, error code otherwise.
 *
 * @note Caller should generate CID and reset token before calling.
 * @note The CID is copied; caller retains ownership of input.
 */
extern SocketQUICConnectionIDPool_Result
SocketQUICConnectionIDPool_add (SocketQUICConnectionIDPool_T pool,
                                const SocketQUICConnectionID_T *cid);

/**
 * @brief Add a connection ID with explicit sequence number.
 *
 * Used for the initial connection ID (sequence 0) and preferred_address
 * connection ID (sequence 1) which have predetermined sequence numbers.
 *
 * @param pool     Pool to add to.
 * @param cid      Connection ID to add.
 * @param sequence Explicit sequence number to assign.
 *
 * @return QUIC_CONNID_POOL_OK on success, error code otherwise.
 */
extern SocketQUICConnectionIDPool_Result
SocketQUICConnectionIDPool_add_with_sequence (
    SocketQUICConnectionIDPool_T pool,
    const SocketQUICConnectionID_T *cid,
    uint64_t sequence);

/**
 * @brief Look up a connection ID by its bytes.
 *
 * @param pool Pool to search.
 * @param id   Raw connection ID bytes.
 * @param len  Length of connection ID.
 *
 * @return Matching entry, or NULL if not found.
 */
extern SocketQUICConnectionIDEntry_T *
SocketQUICConnectionIDPool_lookup (const SocketQUICConnectionIDPool_T pool,
                                   const uint8_t *id,
                                   size_t len);

/**
 * @brief Look up a connection ID by sequence number.
 *
 * @param pool     Pool to search.
 * @param sequence Sequence number to find.
 *
 * @return Matching entry, or NULL if not found.
 */
extern SocketQUICConnectionIDEntry_T *
SocketQUICConnectionIDPool_lookup_sequence (
    const SocketQUICConnectionIDPool_T pool, uint64_t sequence);

/**
 * @brief Remove a specific connection ID from the pool.
 *
 * @param pool Pool to remove from.
 * @param id   Raw connection ID bytes.
 * @param len  Length of connection ID.
 *
 * @return QUIC_CONNID_POOL_OK on success, QUIC_CONNID_POOL_NOT_FOUND if
 *         the connection ID was not in the pool.
 */
extern SocketQUICConnectionIDPool_Result
SocketQUICConnectionIDPool_remove (SocketQUICConnectionIDPool_T pool,
                                   const uint8_t *id,
                                   size_t len);

/**
 * @brief Process Retire Prior To value from NEW_CONNECTION_ID frame.
 *
 * Marks all connection IDs with sequence < retire_prior_to as retired.
 * Does not remove them from the pool immediately to allow graceful
 * transition.
 *
 * @param pool            Pool to update.
 * @param retire_prior_to New retire prior to value.
 * @param retired_count   Output: number of CIDs newly retired (optional).
 *
 * @return QUIC_CONNID_POOL_OK on success, error code otherwise.
 *
 * @note retire_prior_to must not decrease (RFC 9000 §5.1.2).
 */
extern SocketQUICConnectionIDPool_Result
SocketQUICConnectionIDPool_retire_prior_to (SocketQUICConnectionIDPool_T pool,
                                            uint64_t retire_prior_to,
                                            size_t *retired_count);

/**
 * @brief Retire a specific connection ID by sequence number.
 *
 * Called when sending RETIRE_CONNECTION_ID frame.
 *
 * @param pool     Pool to update.
 * @param sequence Sequence number of CID to retire.
 *
 * @return QUIC_CONNID_POOL_OK on success, QUIC_CONNID_POOL_NOT_FOUND if
 *         the sequence number was not in the pool.
 */
extern SocketQUICConnectionIDPool_Result
SocketQUICConnectionIDPool_retire_sequence (SocketQUICConnectionIDPool_T pool,
                                            uint64_t sequence);

/**
 * @brief Remove all retired connection IDs from the pool.
 *
 * Should be called after confirming retirement with peer.
 *
 * @param pool          Pool to clean up.
 * @param removed_count Output: number of CIDs removed (optional).
 *
 * @return QUIC_CONNID_POOL_OK on success.
 */
extern SocketQUICConnectionIDPool_Result
SocketQUICConnectionIDPool_purge_retired (SocketQUICConnectionIDPool_T pool,
                                          size_t *removed_count);

/**
 * @brief Get the current Retire Prior To value.
 *
 * @param pool Pool to query.
 *
 * @return Current retire prior to value.
 */
extern uint64_t SocketQUICConnectionIDPool_get_retire_prior_to (
    const SocketQUICConnectionIDPool_T pool);

/**
 * @brief Callback type for iterating over connection IDs.
 *
 * @param entry   Current entry.
 * @param context User-provided context.
 *
 * @return 0 to continue iteration, non-zero to stop.
 */
typedef int (*SocketQUICConnectionIDPool_Iterator) (
    SocketQUICConnectionIDEntry_T *entry, void *context);

/**
 * @brief Iterate over all non-retired connection IDs.
 *
 * @param pool     Pool to iterate.
 * @param callback Function to call for each entry.
 * @param context  User context passed to callback.
 *
 * @return Number of entries visited, or -1 on error.
 */
extern int SocketQUICConnectionIDPool_foreach (
    SocketQUICConnectionIDPool_T pool,
    SocketQUICConnectionIDPool_Iterator callback,
    void *context);

/**
 * @brief Get the next available connection ID for use.
 *
 * Returns a non-retired, currently unused connection ID.
 * Marks it as in-use.
 *
 * @param pool Pool to search.
 *
 * @return Available entry, or NULL if none available.
 */
extern SocketQUICConnectionIDEntry_T *
SocketQUICConnectionIDPool_get_available (SocketQUICConnectionIDPool_T pool);

/**
 * @brief Get string representation of pool result code.
 *
 * @param result Result code to convert.
 *
 * @return Human-readable string.
 */
extern const char *SocketQUICConnectionIDPool_result_string (
    SocketQUICConnectionIDPool_Result result);

/**
 * @brief Check if the pool needs more connection IDs.
 *
 * Returns true if active count is below a threshold that would
 * impair migration capability.
 *
 * @param pool           Pool to check.
 * @param min_for_migrate Minimum CIDs needed for migration (typically 2).
 *
 * @return 1 if more CIDs needed, 0 otherwise.
 */
extern int
SocketQUICConnectionIDPool_needs_more (const SocketQUICConnectionIDPool_T pool,
                                       size_t min_for_migrate);

/** @} */

#endif /* SOCKETQUICCONNECTIONID_POOL_INCLUDED */

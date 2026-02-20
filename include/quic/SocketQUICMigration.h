/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICMigration.h
 * @brief QUIC Connection Migration (RFC 9000 Section 9).
 *
 * Implements seamless connection migration across network paths:
 * - Path validation using PATH_CHALLENGE/PATH_RESPONSE frames
 * - Anti-spoofing address validation
 * - Congestion control reset for new paths
 * - NAT rebinding detection
 * - Connection ID rotation on migration
 *
 * Key Requirements:
 * - Clients initiate voluntary migration
 * - Servers may migrate only to preferred_address
 * - New connection ID MUST be used when migrating (linkability prevention)
 * - PATH_CHALLENGE required before sending on new path
 * - Congestion state reset for new paths
 *
 * Thread Safety: Path structures are NOT thread-safe.
 * Use external synchronization when sharing across threads.
 *
 * @defgroup quic_migration QUIC Connection Migration Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9000#section-9
 */

#ifndef SOCKETQUICMIGRATION_INCLUDED
#define SOCKETQUICMIGRATION_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICConnection.h"
#include "quic/SocketQUICConnectionID.h"

/**
 * @brief Size of PATH_CHALLENGE/PATH_RESPONSE data in bytes.
 *
 * Challenge data is 8 bytes of unpredictable bits (RFC 9000 Section 8.2.1).
 */
#define QUIC_PATH_CHALLENGE_SIZE 8

/**
 * @brief Maximum number of paths to track per connection.
 *
 * Includes current path, probed paths, and failed paths.
 */
#define QUIC_MIGRATION_MAX_PATHS 4

/**
 * @brief Path validation timeout in milliseconds.
 *
 * If no PATH_RESPONSE received within 3 * PTO, path is considered failed.
 * Using conservative 3 seconds as default.
 */
#define QUIC_PATH_VALIDATION_TIMEOUT_MS 3000

/**
 * @brief Maximum PATH_CHALLENGE retransmissions.
 *
 * RFC 9000 recommends 3 retries before abandoning path validation.
 */
#define QUIC_PATH_MAX_CHALLENGES 3

/**
 * @brief NAT rebinding detection window in milliseconds.
 *
 * If peer address changes within this window without migration,
 * it's likely NAT rebinding rather than true migration.
 */
#define QUIC_NAT_REBIND_WINDOW_MS 500

/**
 * @brief Path validation state.
 *
 * Tracks the lifecycle of path validation per RFC 9000 Section 8.2.
 */
typedef enum
{
  QUIC_PATH_UNKNOWN = 0, /**< Path not yet validated */
  QUIC_PATH_VALIDATING,  /**< PATH_CHALLENGE sent, awaiting response */
  QUIC_PATH_VALIDATED,   /**< PATH_RESPONSE received, path usable */
  QUIC_PATH_FAILED,      /**< Validation failed or timeout */
  QUIC_PATH_ABANDONED    /**< Path explicitly abandoned */
} SocketQUICPath_State;

/**
 * @brief Migration role (client vs server).
 *
 * RFC 9000 Section 9.3: Only clients can initiate voluntary migration.
 * Servers can only migrate to preferred_address.
 */
typedef enum
{
  QUIC_MIGRATION_ROLE_INITIATOR = 0, /**< Initiating migration (client) */
  QUIC_MIGRATION_ROLE_RESPONDER      /**< Responding to migration (server) */
} SocketQUICMigration_Role;

/**
 * @brief QUIC network path structure.
 *
 * Represents a single network path with its validation state and
 * associated connection ID.
 */
typedef struct SocketQUICPath
{
  /** Network addresses */
  struct sockaddr_storage peer_addr;  /**< Peer IP address and port */
  struct sockaddr_storage local_addr; /**< Local IP address and port */

  /** Connection ID for this path */
  SocketQUICConnectionID_T cid; /**< Connection ID used on this path */

  /** Path validation state */
  SocketQUICPath_State state;                  /**< Current validation state */
  uint8_t challenge[QUIC_PATH_CHALLENGE_SIZE]; /**< Challenge data sent */
  uint64_t challenge_sent_time; /**< Timestamp when challenge was sent (ms) */
  int challenge_count;          /**< Number of challenges sent */

  /** Congestion control state (simplified) */
  uint64_t cwnd;            /**< Congestion window in bytes */
  uint64_t bytes_in_flight; /**< Bytes sent but not acked */
  uint64_t ssthresh;        /**< Slow-start threshold */

  /** Statistics */
  uint64_t packets_sent;     /**< Total packets sent on this path */
  uint64_t packets_received; /**< Total packets received on this path */
  uint64_t bytes_sent;       /**< Total bytes sent on this path */
  uint64_t bytes_received;   /**< Total bytes received on this path */
  uint64_t rtt_us;           /**< Smoothed RTT in microseconds */

} SocketQUICPath_T;

/**
 * @brief Connection migration manager.
 *
 * Manages multiple paths per connection and handles migration.
 */
typedef struct SocketQUICMigration
{
  Arena_T arena; /**< Memory arena for allocations */

  /** Active paths */
  SocketQUICPath_T paths[QUIC_MIGRATION_MAX_PATHS]; /**< Tracked paths */
  size_t path_count;                                /**< Number of paths */
  size_t active_path_index; /**< Index of current active path */

  /** Migration state */
  SocketQUICMigration_Role role; /**< Client or server role */
  int migration_in_progress;     /**< Non-zero if migration active */
  size_t target_path_index;      /**< Index of path being validated */

  /** NAT rebinding detection */
  uint64_t last_peer_addr_change_time; /**< Timestamp of last address change */
  int nat_rebinding_detected;          /**< Non-zero if NAT rebind detected */

  /** Connection reference */
  SocketQUICConnection_T connection; /**< Associated connection */

} SocketQUICMigration_T;

/**
 * @brief Result codes for migration operations.
 */
typedef enum
{
  QUIC_MIGRATION_OK = 0,              /**< Operation succeeded */
  QUIC_MIGRATION_ERROR_NULL,          /**< NULL pointer argument */
  QUIC_MIGRATION_ERROR_INVALID_STATE, /**< Invalid operation for current state
                                       */
  QUIC_MIGRATION_ERROR_NO_CID,        /**< No available connection IDs */
  QUIC_MIGRATION_ERROR_PATH_LIMIT,    /**< Maximum paths exceeded */
  QUIC_MIGRATION_ERROR_TIMEOUT,       /**< Path validation timeout */
  QUIC_MIGRATION_ERROR_NOT_ALLOWED,   /**< Migration not allowed (server) */
  QUIC_MIGRATION_ERROR_RANDOM,        /**< Random generation failed */
  QUIC_MIGRATION_ERROR_MEMORY         /**< Memory allocation failed */
} SocketQUICMigration_Result;

/** @brief Exception raised on migration failures. */
extern const Except_T SocketQUICMigration_Failed;

/**
 * @brief Create a new migration manager.
 *
 * Initializes migration tracking for a connection.
 *
 * @param arena      Memory arena for allocations.
 * @param connection Associated QUIC connection.
 * @param role       Migration role (client or server).
 *
 * @return Pointer to new migration manager, or NULL on failure.
 */
extern SocketQUICMigration_T *
SocketQUICMigration_new (Arena_T arena,
                         SocketQUICConnection_T connection,
                         SocketQUICMigration_Role role);

/**
 * @brief Initialize a migration manager structure.
 *
 * Zeros all fields. Call before using a migration manager.
 *
 * @param migration Migration manager to initialize.
 * @param connection Associated QUIC connection.
 * @param role       Migration role (client or server).
 */
extern void SocketQUICMigration_init (SocketQUICMigration_T *migration,
                                      SocketQUICConnection_T connection,
                                      SocketQUICMigration_Role role);

/**
 * @brief Free a migration manager.
 *
 * Releases resources. The structure itself is arena-allocated and
 * will be freed when the arena is disposed.
 *
 * @param migration Migration manager to free (pointer-to-pointer).
 */
extern void SocketQUICMigration_free (SocketQUICMigration_T **migration);

/**
 * @brief Initialize the initial path.
 *
 * Sets up the first path with the given addresses and CID.
 * This is the path established during handshake.
 *
 * @param migration  Migration manager.
 * @param local_addr Local address.
 * @param peer_addr  Peer address.
 * @param cid        Initial connection ID.
 *
 * @return QUIC_MIGRATION_OK on success, error code otherwise.
 */
extern SocketQUICMigration_Result
SocketQUICMigration_init_path (SocketQUICMigration_T *migration,
                               const struct sockaddr_storage *local_addr,
                               const struct sockaddr_storage *peer_addr,
                               const SocketQUICConnectionID_T *cid);

/**
 * @brief Get the current active path.
 *
 * Returns the path currently used for sending packets.
 *
 * @param migration Migration manager.
 *
 * @return Pointer to active path, or NULL if no active path.
 */
extern const SocketQUICPath_T *
SocketQUICMigration_get_active_path (const SocketQUICMigration_T *migration);

/**
 * @brief Find a path by peer address.
 *
 * Searches for an existing path matching the given peer address.
 *
 * @param migration Migration manager.
 * @param peer_addr Peer address to search for.
 *
 * @return Pointer to matching path, or NULL if not found.
 */
extern SocketQUICPath_T *
SocketQUICMigration_find_path (SocketQUICMigration_T *migration,
                               const struct sockaddr_storage *peer_addr);

/**
 * @brief Initiate path validation.
 *
 * Generates random challenge data and prepares path for validation.
 * This function sets up the path state but does NOT send the PATH_CHALLENGE
 * frame itself - the caller is responsible for frame transmission.
 *
 * Required Sequence for Connection Migration (RFC 9000 §9.1):
 * 1. Call SocketQUICMigration_probe_path() to generate challenge data
 * 2. Extract path->challenge data (8 bytes)
 * 3. Construct and send PATH_CHALLENGE frame containing path->challenge
 * 4. Ensure datagram is padded to at least 1200 bytes (RFC 9000 §8.2.1)
 * 5. Wait for PATH_RESPONSE from peer
 * 6. Call SocketQUICMigration_handle_path_response() when response arrives
 * 7. Once path is VALIDATED, call SocketQUICMigration_initiate() to complete
 * migration
 *
 * Frame Transmission Requirements:
 * - PATH_CHALLENGE MUST be sent in a packet that is padded to 1200+ bytes
 * - PATH_CHALLENGE can be sent multiple times if no response (see
 * check_timeouts)
 * - Path MUST be validated before sending any other application data on it
 * - Do not send PATH_CHALLENGE for initial path (pre-validated during
 * handshake)
 *
 * The function allocates or reuses a path slot, generates cryptographically
 * secure random challenge data, and sets the path state to
 * QUIC_PATH_VALIDATING.
 *
 * @param migration Migration manager.
 * @param peer_addr Peer address to probe.
 *
 * @return QUIC_MIGRATION_OK on success, error code otherwise.
 *
 * @note Caller MUST send PATH_CHALLENGE frame with path->challenge data.
 * @see RFC 9000 §9.1 (Connection Migration)
 * @see RFC 9000 §8.2 (Path Validation)
 */
extern SocketQUICMigration_Result
SocketQUICMigration_probe_path (SocketQUICMigration_T *migration,
                                const struct sockaddr_storage *peer_addr);

/**
 * @brief Handle PATH_RESPONSE frame.
 *
 * Validates that the response data matches a pending challenge.
 * If matched, marks path as validated.
 *
 * RFC 9000 Section 8.2.2: "PATH_RESPONSE contains the data from the
 * PATH_CHALLENGE that elicited it."
 *
 * @param migration     Migration manager.
 * @param response_data Response data (8 bytes).
 *
 * @return QUIC_MIGRATION_OK on success, error code otherwise.
 */
extern SocketQUICMigration_Result
SocketQUICMigration_handle_path_response (SocketQUICMigration_T *migration,
                                          const uint8_t response_data[8]);

/**
 * @brief Handle PATH_CHALLENGE frame.
 *
 * Generates a PATH_RESPONSE with the same data.
 * Called when receiving a challenge from peer.
 *
 * RFC 9000 Section 8.2.2: "An endpoint MUST respond to a PATH_CHALLENGE
 * with a PATH_RESPONSE containing the same data."
 *
 * @param migration      Migration manager.
 * @param challenge_data Challenge data received (8 bytes).
 * @param response_out   Output buffer for response data (8 bytes).
 *
 * @return QUIC_MIGRATION_OK on success, error code otherwise.
 */
extern SocketQUICMigration_Result
SocketQUICMigration_handle_path_challenge (SocketQUICMigration_T *migration,
                                           const uint8_t challenge_data[8],
                                           uint8_t response_out[8]);

/**
 * @brief Check for path validation timeouts.
 *
 * Checks if any validating paths have exceeded timeout.
 * Marks timed-out paths as FAILED and may retry challenge.
 *
 * @param migration  Migration manager.
 * @param current_time_ms Current time in milliseconds.
 *
 * @return Number of paths that timed out.
 */
extern int SocketQUICMigration_check_timeouts (SocketQUICMigration_T *migration,
                                               uint64_t current_time_ms);

/**
 * @brief Initiate connection migration to a new path.
 *
 * Begins migration to a validated path:
 * 1. Selects a new unused connection ID
 * 2. Switches active path
 * 3. Resets congestion control for new path
 * 4. Updates connection routing
 *
 * RFC 9000 Section 9.5: "An endpoint MUST use a new connection ID when
 * initiating connection migration."
 *
 * Precondition: Target path must be in QUIC_PATH_VALIDATED state.
 *
 * @param migration Migration manager.
 * @param new_path  Validated path to migrate to.
 *
 * @return QUIC_MIGRATION_OK on success, error code otherwise.
 */
extern SocketQUICMigration_Result
SocketQUICMigration_initiate (SocketQUICMigration_T *migration,
                              SocketQUICPath_T *new_path);

/**
 * @brief Detect and handle NAT rebinding.
 *
 * Differentiates between NAT rebinding and true migration.
 * NAT rebinding = same peer, different observed address.
 *
 * RFC 9000 Section 9.3.3: "An endpoint that receives a packet on a new
 * local address validates that address before using it."
 *
 * @param migration  Migration manager.
 * @param peer_addr  New peer address observed.
 * @param current_time_ms Current time in milliseconds.
 *
 * @return QUIC_MIGRATION_OK on success, error code otherwise.
 */
extern SocketQUICMigration_Result
SocketQUICMigration_handle_peer_address_change (
    SocketQUICMigration_T *migration,
    const struct sockaddr_storage *peer_addr,
    uint64_t current_time_ms);

/**
 * @brief Reset congestion control for new path.
 *
 * RFC 9000 Section 9.4: "When an endpoint validates a new path, it MUST reset
 * its congestion controller and round-trip time estimator for the new path."
 *
 * Resets:
 * - Congestion window to initial window
 * - Slow-start threshold to max
 * - RTT to initial value
 * - Bytes in flight to zero
 *
 * Optionally copies some state from old path:
 * - May reuse RTT if paths share router infrastructure
 * - May use 0-RTT data limits
 *
 * @param new_path Newly validated path to reset.
 * @param old_path Previous path (may be NULL).
 */
extern void
SocketQUICMigration_reset_congestion (SocketQUICPath_T *new_path,
                                      const SocketQUICPath_T *old_path);

/**
 * @brief Update path RTT estimate.
 *
 * Updates smoothed RTT for a path based on new measurement.
 *
 * @param path    Path to update.
 * @param rtt_us  RTT sample in microseconds.
 */
extern void
SocketQUICMigration_update_rtt (SocketQUICPath_T *path, uint64_t rtt_us);

/**
 * @brief Check if migration is allowed.
 *
 * Validates whether migration can be initiated based on:
 * - Role (clients can initiate, servers cannot unless preferred_address)
 * - Connection state
 * - Available connection IDs
 *
 * @param migration Migration manager.
 *
 * @return 1 if migration allowed, 0 otherwise.
 */
extern int
SocketQUICMigration_can_migrate (const SocketQUICMigration_T *migration);

/**
 * @brief Get path state as string.
 *
 * @param state Path state to convert.
 *
 * @return Human-readable string describing the state.
 */
extern const char *
SocketQUICMigration_state_string (SocketQUICPath_State state);

/**
 * @brief Get result code as string.
 *
 * @param result Result code to convert.
 *
 * @return Human-readable string describing the result.
 */
extern const char *
SocketQUICMigration_result_string (SocketQUICMigration_Result result);

/**
 * @brief Format path as string for debugging.
 *
 * Writes path information (addresses, state, CID) to buffer.
 *
 * @param path Path to format.
 * @param buf  Output buffer.
 * @param size Size of output buffer.
 *
 * @return Number of characters written (excluding null), or -1 on error.
 */
extern int SocketQUICMigration_path_to_string (const SocketQUICPath_T *path,
                                               char *buf,
                                               size_t size);

/** @} */

#endif /* SOCKETQUICMIGRATION_INCLUDED */

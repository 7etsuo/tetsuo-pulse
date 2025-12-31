/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICAddrValidation.h
 * @brief QUIC Address Validation (RFC 9000 Section 8).
 *
 * Implements token-based address validation during handshake and
 * path validation for connection migration using PATH_CHALLENGE/PATH_RESPONSE.
 */

#ifndef SOCKETQUICADDRVALIDATION_INCLUDED
#define SOCKETQUICADDRVALIDATION_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICConnection.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/** @brief Maximum token size in bytes (RFC 9000 allows variable) */
#define QUIC_ADDR_VALIDATION_MAX_TOKEN_SIZE 256

/** @brief Token component sizes */
#define QUIC_TOKEN_TIMESTAMP_SIZE 8  /**< Timestamp field size */
#define QUIC_TOKEN_ADDR_HASH_SIZE 16 /**< Address hash field size */
#define QUIC_TOKEN_HMAC_SIZE 32      /**< HMAC-SHA256 field size */

/** @brief Token field offsets */
#define QUIC_TOKEN_HMAC_OFFSET \
  (QUIC_TOKEN_TIMESTAMP_SIZE   \
   + QUIC_TOKEN_ADDR_HASH_SIZE) /**< HMAC field offset */

/** @brief Actual token size: 8 (timestamp) + 16 (addr hash) + 32 (HMAC) */
#define QUIC_ADDR_VALIDATION_TOKEN_SIZE \
  (QUIC_TOKEN_TIMESTAMP_SIZE + QUIC_TOKEN_ADDR_HASH_SIZE + QUIC_TOKEN_HMAC_SIZE)

/** @brief Token lifetime in seconds */
#define QUIC_ADDR_VALIDATION_TOKEN_LIFETIME 86400 /* 24 hours */

/** @brief 3x amplification limit before address validation */
#define QUIC_ADDR_VALIDATION_AMPLIFICATION_LIMIT 3

/** @brief Path challenge data size (RFC 9000 §8.2) */
#define QUIC_PATH_CHALLENGE_SIZE 8

/** @brief HMAC input size: 8 bytes timestamp + 16 bytes address hash */
#define QUIC_TOKEN_HMAC_INPUT_SIZE 24

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @brief Exception for address validation failures.
 */
extern const Except_T SocketQUICAddrValidation_Failed;

/* ============================================================================
 * Type Definitions
 * ============================================================================
 */

/**
 * @brief Result codes for address validation operations.
 */
typedef enum
{
  QUIC_ADDR_VALIDATION_OK = 0,
  QUIC_ADDR_VALIDATION_ERROR_NULL,
  QUIC_ADDR_VALIDATION_ERROR_INVALID,
  QUIC_ADDR_VALIDATION_ERROR_EXPIRED,
  QUIC_ADDR_VALIDATION_ERROR_BUFFER_SIZE,
  QUIC_ADDR_VALIDATION_ERROR_CRYPTO,
  QUIC_ADDR_VALIDATION_ERROR_AMPLIFICATION
} SocketQUICAddrValidation_Result;

/**
 * @brief Token validation state tracker.
 */
typedef struct SocketQUICAddrValidation_State
{
  uint64_t bytes_received;  /**< Bytes validated as received from peer */
  uint64_t bytes_sent;      /**< Bytes sent to peer */
  int address_validated;    /**< 1 if address validated, 0 otherwise */
  uint64_t validation_time; /**< Timestamp when validated */
} SocketQUICAddrValidation_State_T;

/**
 * @brief Path challenge tracker for migration validation.
 */
typedef struct SocketQUICPathChallenge
{
  uint8_t data[QUIC_PATH_CHALLENGE_SIZE]; /**< Challenge data */
  uint64_t sent_time;                     /**< When challenge was sent */
  int pending;                            /**< 1 if waiting for response */
  uint8_t peer_addr[16];                  /**< Address where sent */
  uint16_t peer_port;                     /**< Port where sent */
  int is_ipv6;                            /**< 1 if IPv6, 0 if IPv4 */
} SocketQUICPathChallenge_T;

/* ============================================================================
 * Amplification Limit Functions
 * ============================================================================
 */

/**
 * @brief Check if sending would violate amplification limit.
 *
 * RFC 9000 §8.1: Before address validation, endpoints MUST limit data
 * to 3x received bytes to prevent amplification attacks.
 *
 * @param[in] state Address validation state.
 * @param[in] bytes_to_send Number of bytes to send.
 *
 * @return 1 if allowed, 0 if would violate limit.
 *
 * @threadsafe Yes - reads immutable state.
 * @complexity O(1)
 */
extern int SocketQUICAddrValidation_check_amplification_limit (
    const SocketQUICAddrValidation_State_T *state, size_t bytes_to_send);

/**
 * @brief Update bytes sent/received counters.
 *
 * @param[in,out] state Address validation state.
 * @param[in] bytes_sent Bytes sent in this operation.
 * @param[in] bytes_received Bytes received in this operation.
 *
 * @threadsafe No - modifies state.
 * @complexity O(1)
 */
extern void SocketQUICAddrValidation_update_counters (
    SocketQUICAddrValidation_State_T *state,
    size_t bytes_sent,
    size_t bytes_received);

/**
 * @brief Mark address as validated.
 *
 * @param[in,out] state Address validation state.
 * @param[in] timestamp Current timestamp (monotonic).
 *
 * @threadsafe No - modifies state.
 * @complexity O(1)
 */
extern void SocketQUICAddrValidation_mark_validated (
    SocketQUICAddrValidation_State_T *state, uint64_t timestamp);

/* ============================================================================
 * Token Functions (Retry/NEW_TOKEN)
 * ============================================================================
 */

/**
 * @brief Generate address validation token.
 *
 * RFC 9000 §8.1.2: Tokens bind client address and prevent reuse.
 * Uses HMAC-SHA256 with server secret for stateless validation.
 *
 * Token format:
 *   - 8 bytes: timestamp
 *   - 16 bytes: address hash
 *   - 32 bytes: HMAC-SHA256(secret, timestamp || address)
 *
 * @param[in] addr Peer address to validate.
 * @param[in] secret Server secret key for HMAC (32 bytes).
 * @param[out] token Output buffer for token.
 * @param[in,out] token_len Input: buffer size, Output: token length.
 *
 * @return QUIC_ADDR_VALIDATION_OK on success, error code otherwise.
 *
 * @throws SocketQUICAddrValidation_Failed on crypto errors.
 * @threadsafe Yes if secret is read-only.
 * @complexity O(1) - crypto operations.
 */
extern SocketQUICAddrValidation_Result
SocketQUICAddrValidation_generate_token (const struct sockaddr *addr,
                                         const uint8_t *secret,
                                         uint8_t *token,
                                         size_t *token_len);

/**
 * @brief Validate address token.
 *
 * Verifies token HMAC, checks expiration, and validates address match.
 *
 * @param[in] token Token to validate.
 * @param[in] token_len Token length.
 * @param[in] addr Peer address to check against.
 * @param[in] secret Server secret key for HMAC (32 bytes).
 *
 * @return QUIC_ADDR_VALIDATION_OK if valid, error code otherwise.
 *
 * @throws SocketQUICAddrValidation_Failed on crypto errors.
 * @threadsafe Yes if secret is read-only.
 * @complexity O(1) - crypto operations.
 */
extern SocketQUICAddrValidation_Result
SocketQUICAddrValidation_validate_token (const uint8_t *token,
                                         size_t token_len,
                                         const struct sockaddr *addr,
                                         const uint8_t *secret);

/* ============================================================================
 * Path Validation Functions (PATH_CHALLENGE/PATH_RESPONSE)
 * ============================================================================
 */

/**
 * @brief Initialize path challenge structure.
 *
 * @param[out] challenge Path challenge structure to initialize.
 *
 * @threadsafe Yes.
 * @complexity O(1)
 */
extern void SocketQUICPathChallenge_init (SocketQUICPathChallenge_T *challenge);

/**
 * @brief Generate and send PATH_CHALLENGE frame.
 *
 * RFC 9000 §8.2: Path validation uses unpredictable data to prove
 * peer can receive packets at the claimed address.
 *
 * @param[in,out] challenge Path challenge tracker.
 * @param[in] path Destination address for validation.
 * @param[in] timestamp Current timestamp (monotonic).
 *
 * @return QUIC_ADDR_VALIDATION_OK on success, error code otherwise.
 *
 * @throws SocketQUICAddrValidation_Failed on RNG failure.
 * @threadsafe No - modifies challenge state.
 * @complexity O(1) - RNG operation.
 */
extern SocketQUICAddrValidation_Result
SocketQUICPathChallenge_generate (SocketQUICPathChallenge_T *challenge,
                                  const struct sockaddr *path,
                                  uint64_t timestamp);

/**
 * @brief Verify PATH_RESPONSE matches challenge.
 *
 * @param[in] challenge Path challenge tracker.
 * @param[in] response_data Response data from PATH_RESPONSE frame.
 * @param[in] response_len Response data length (must be 8 bytes).
 *
 * @return 1 if valid response, 0 otherwise.
 *
 * @threadsafe Yes - reads immutable challenge data.
 * @complexity O(1) - constant-time comparison.
 */
extern int SocketQUICPathChallenge_verify_response (
    const SocketQUICPathChallenge_T *challenge,
    const uint8_t *response_data,
    size_t response_len);

/**
 * @brief Mark path challenge as complete.
 *
 * @param[in,out] challenge Path challenge tracker.
 *
 * @threadsafe No - modifies state.
 * @complexity O(1)
 */
extern void
SocketQUICPathChallenge_complete (SocketQUICPathChallenge_T *challenge);

/**
 * @brief Check if path challenge is pending.
 *
 * @param[in] challenge Path challenge tracker.
 *
 * @return 1 if pending, 0 otherwise.
 *
 * @threadsafe Yes - reads immutable state.
 * @complexity O(1)
 */
extern int
SocketQUICPathChallenge_is_pending (const SocketQUICPathChallenge_T *challenge);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Get string representation of result code.
 *
 * @param[in] result Result code.
 *
 * @return Human-readable string.
 *
 * @threadsafe Yes.
 * @complexity O(1)
 */
extern const char *
SocketQUICAddrValidation_result_string (SocketQUICAddrValidation_Result result);

#endif /* SOCKETQUICADDRVALIDATION_INCLUDED */

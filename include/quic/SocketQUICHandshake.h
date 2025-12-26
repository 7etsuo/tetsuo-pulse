/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICHandshake.h
 * @brief QUIC Cryptographic and Transport Handshake (RFC 9000 Section 7).
 *
 * Integrates TLS 1.3 with QUIC for connection establishment:
 * - CRYPTO frames carry TLS handshake messages
 * - Transport parameters exchanged via TLS extension
 * - Key derivation for Initial/Handshake/1-RTT protection levels
 * - Optional 0-RTT early data support
 *
 * The handshake progresses through encryption levels:
 * 1. Initial: Derived from client's Destination Connection ID
 * 2. Handshake: Derived after TLS key exchange
 * 3. 1-RTT: Application data keys after handshake completion
 * 4. 0-RTT: Optional early data keys (client only)
 *
 * @see https://www.rfc-editor.org/rfc/rfc9000#section-7
 * @see https://www.rfc-editor.org/rfc/rfc9001 (QUIC-TLS)
 */

#ifndef SOCKETQUICHANDSHAKE_INCLUDED
#define SOCKETQUICHANDSHAKE_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICConnection.h"
#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICTransportParams.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/**
 * @brief Maximum CRYPTO frame data buffer size.
 *
 * Limits memory for buffering out-of-order CRYPTO frames.
 */
#define QUIC_HANDSHAKE_CRYPTO_BUFFER_SIZE 16384

/**
 * @brief Maximum number of buffered CRYPTO frame segments.
 */
#define QUIC_HANDSHAKE_MAX_CRYPTO_SEGMENTS 64

/* ============================================================================
 * Types
 * ============================================================================
 */

/**
 * @brief QUIC encryption levels (RFC 9000 Section 4.1.4).
 *
 * Each level has independent packet protection keys.
 */
typedef enum {
  QUIC_CRYPTO_LEVEL_INITIAL = 0,    /**< Initial packets (known secret) */
  QUIC_CRYPTO_LEVEL_0RTT,            /**< 0-RTT early data (client only) */
  QUIC_CRYPTO_LEVEL_HANDSHAKE,       /**< Handshake packets */
  QUIC_CRYPTO_LEVEL_APPLICATION,     /**< 1-RTT application data */
  QUIC_CRYPTO_LEVEL_COUNT
} SocketQUICCryptoLevel;

/**
 * @brief Handshake state machine states.
 */
typedef enum {
  QUIC_HANDSHAKE_STATE_IDLE = 0,       /**< Not started */
  QUIC_HANDSHAKE_STATE_INITIAL,        /**< Sending/receiving Initial */
  QUIC_HANDSHAKE_STATE_HANDSHAKE,      /**< TLS handshake in progress */
  QUIC_HANDSHAKE_STATE_COMPLETE,       /**< Handshake complete */
  QUIC_HANDSHAKE_STATE_CONFIRMED,      /**< Handshake confirmed */
  QUIC_HANDSHAKE_STATE_FAILED          /**< Handshake failed */
} SocketQUICHandshakeState;

/**
 * @brief Result codes for handshake operations.
 */
typedef enum {
  QUIC_HANDSHAKE_OK = 0,              /**< Success */
  QUIC_HANDSHAKE_ERROR_NULL,          /**< NULL argument */
  QUIC_HANDSHAKE_ERROR_STATE,         /**< Invalid state */
  QUIC_HANDSHAKE_ERROR_CRYPTO,        /**< Cryptographic error */
  QUIC_HANDSHAKE_ERROR_TLS,           /**< TLS error */
  QUIC_HANDSHAKE_ERROR_BUFFER,        /**< Buffer overflow */
  QUIC_HANDSHAKE_ERROR_OFFSET,        /**< Invalid offset */
  QUIC_HANDSHAKE_ERROR_DUPLICATE,     /**< Duplicate data */
  QUIC_HANDSHAKE_ERROR_TRANSPORT,     /**< Transport parameter error */
  QUIC_HANDSHAKE_ERROR_MEMORY         /**< Memory allocation failure */
} SocketQUICHandshake_Result;

/**
 * @brief Buffered CRYPTO frame segment.
 *
 * Used for reassembling out-of-order CRYPTO data.
 */
typedef struct SocketQUICCryptoSegment {
  uint64_t offset;                    /**< Offset in CRYPTO stream */
  uint64_t length;                    /**< Data length */
  uint8_t *data;                      /**< Data buffer */
  struct SocketQUICCryptoSegment *next; /**< Next segment in list */
} SocketQUICCryptoSegment_T;

/**
 * @brief CRYPTO stream state for one encryption level.
 *
 * Tracks sent and received CRYPTO data.
 */
typedef struct {
  uint64_t send_offset;               /**< Next byte to send */
  uint64_t recv_offset;               /**< Next expected byte */
  uint8_t *recv_buffer;               /**< Reassembly buffer */
  size_t recv_buffer_size;            /**< Buffer allocation size */
  SocketQUICCryptoSegment_T *segments; /**< Out-of-order segments */
  int segment_count;                  /**< Number of buffered segments */
} SocketQUICCryptoStream_T;

/**
 * @brief Opaque handshake context.
 */
typedef struct SocketQUICHandshake *SocketQUICHandshake_T;

/**
 * @brief Handshake structure.
 */
struct SocketQUICHandshake {
  Arena_T arena;                      /**< Memory arena */
  SocketQUICConnection_T conn;         /**< Associated connection */
  SocketQUICConnection_Role role;      /**< Client or server */
  SocketQUICHandshakeState state;      /**< Current state */

  /* TLS integration (opaque pointer to avoid OpenSSL dependency in header) */
  void *tls_ctx;                      /**< TLS context (SSL_CTX*) */
  void *tls_ssl;                      /**< TLS connection (SSL*) */

  /* Transport parameters */
  SocketQUICTransportParams_T local_params;  /**< Our parameters */
  SocketQUICTransportParams_T peer_params;   /**< Peer's parameters */
  int params_received;                /**< Peer params received flag */

  /* CRYPTO streams per encryption level */
  SocketQUICCryptoStream_T crypto_streams[QUIC_CRYPTO_LEVEL_COUNT];

  /* Key material (opaque to allow different crypto backends) */
  void *keys[QUIC_CRYPTO_LEVEL_COUNT]; /**< Packet protection keys */
  int keys_available[QUIC_CRYPTO_LEVEL_COUNT]; /**< Key availability flags */

  /* Error tracking */
  uint64_t error_code;                /**< TLS alert or crypto error */
  char error_reason[256];             /**< Human-readable error */
};

/* ============================================================================
 * Exceptions
 * ============================================================================
 */

extern const Except_T SocketQUICHandshake_Failed;

/* ============================================================================
 * Lifecycle Functions
 * ============================================================================
 */

/**
 * @brief Create a new handshake context.
 *
 * @param arena Memory arena for allocations.
 * @param conn  Associated QUIC connection.
 * @param role  Client or server role.
 *
 * @return Handshake context, or NULL on allocation failure.
 */
extern SocketQUICHandshake_T
SocketQUICHandshake_new(Arena_T arena, SocketQUICConnection_T conn,
                        SocketQUICConnection_Role role);

/**
 * @brief Free handshake context and associated resources.
 *
 * @param handshake Pointer to handshake context (set to NULL after).
 */
extern void
SocketQUICHandshake_free(SocketQUICHandshake_T *handshake);

/* ============================================================================
 * Initialization Functions
 * ============================================================================
 */

/**
 * @brief Initialize handshake for a connection.
 *
 * Sets up TLS context and initial crypto state.
 *
 * @param conn QUIC connection.
 * @param role Client or server role.
 *
 * @return QUIC_HANDSHAKE_OK on success, error code otherwise.
 */
extern SocketQUICHandshake_Result
SocketQUICHandshake_init(SocketQUICConnection_T conn,
                         SocketQUICConnection_Role role);

/**
 * @brief Configure handshake with transport parameters.
 *
 * Must be called before sending Initial packet.
 *
 * @param handshake Handshake context.
 * @param params    Local transport parameters to advertise.
 *
 * @return QUIC_HANDSHAKE_OK on success, error code otherwise.
 */
extern SocketQUICHandshake_Result
SocketQUICHandshake_set_transport_params(SocketQUICHandshake_T handshake,
                                         const SocketQUICTransportParams_T *params);

/* ============================================================================
 * Handshake Operations
 * ============================================================================
 */

/**
 * @brief Send Initial packet to start handshake.
 *
 * Client: Sends ClientHello in CRYPTO frame.
 * Server: Not applicable (server responds to client Initial).
 *
 * @param conn QUIC connection.
 *
 * @return QUIC_HANDSHAKE_OK on success, error code otherwise.
 */
extern SocketQUICHandshake_Result
SocketQUICHandshake_send_initial(SocketQUICConnection_T conn);

/**
 * @brief Process received CRYPTO frame.
 *
 * Handles CRYPTO frame data, buffering if out-of-order, and feeds
 * to TLS when contiguous data is available.
 *
 * @param conn  QUIC connection.
 * @param frame CRYPTO frame to process.
 *
 * @return QUIC_HANDSHAKE_OK on success, error code otherwise.
 */
extern SocketQUICHandshake_Result
SocketQUICHandshake_process_crypto(SocketQUICConnection_T conn,
                                   const SocketQUICFrameCrypto_T *frame);

/**
 * @brief Derive packet protection keys for encryption level.
 *
 * Called when TLS provides new key material.
 *
 * @param conn  QUIC connection.
 * @param level Encryption level for key derivation.
 *
 * @return QUIC_HANDSHAKE_OK on success, error code otherwise.
 */
extern SocketQUICHandshake_Result
SocketQUICHandshake_derive_keys(SocketQUICConnection_T conn,
                                SocketQUICCryptoLevel level);

/**
 * @brief Process TLS messages and generate outgoing CRYPTO frames.
 *
 * Advances TLS state machine and extracts data to send in CRYPTO frames.
 *
 * @param handshake Handshake context.
 *
 * @return QUIC_HANDSHAKE_OK on success, error code otherwise.
 */
extern SocketQUICHandshake_Result
SocketQUICHandshake_process(SocketQUICHandshake_T handshake);

/* ============================================================================
 * Key Management Functions
 * ============================================================================
 */

/**
 * @brief Check if keys are available for encryption level.
 *
 * @param handshake Handshake context.
 * @param level     Encryption level to check.
 *
 * @return Non-zero if keys are available, 0 otherwise.
 */
extern int
SocketQUICHandshake_has_keys(SocketQUICHandshake_T handshake,
                             SocketQUICCryptoLevel level);

/**
 * @brief Get packet protection keys for encryption level.
 *
 * @param handshake Handshake context.
 * @param level     Encryption level.
 *
 * @return Opaque key structure, or NULL if not available.
 */
extern void *
SocketQUICHandshake_get_keys(SocketQUICHandshake_T handshake,
                             SocketQUICCryptoLevel level);

/**
 * @brief Discard keys for encryption level.
 *
 * Called when transitioning to higher encryption level.
 *
 * @param handshake Handshake context.
 * @param level     Encryption level to discard.
 */
extern void
SocketQUICHandshake_discard_keys(SocketQUICHandshake_T handshake,
                                 SocketQUICCryptoLevel level);

/* ============================================================================
 * State Query Functions
 * ============================================================================
 */

/**
 * @brief Get current handshake state.
 *
 * @param handshake Handshake context.
 *
 * @return Current handshake state.
 */
extern SocketQUICHandshakeState
SocketQUICHandshake_get_state(SocketQUICHandshake_T handshake);

/**
 * @brief Check if handshake is complete.
 *
 * @param handshake Handshake context.
 *
 * @return Non-zero if complete, 0 otherwise.
 */
extern int
SocketQUICHandshake_is_complete(SocketQUICHandshake_T handshake);

/**
 * @brief Check if handshake is confirmed.
 *
 * Confirmation means both endpoints have completed handshake.
 *
 * @param handshake Handshake context.
 *
 * @return Non-zero if confirmed, 0 otherwise.
 */
extern int
SocketQUICHandshake_is_confirmed(SocketQUICHandshake_T handshake);

/**
 * @brief Get peer transport parameters.
 *
 * Only valid after parameters have been received.
 *
 * @param handshake Handshake context.
 *
 * @return Pointer to peer parameters, or NULL if not yet received.
 */
extern const SocketQUICTransportParams_T *
SocketQUICHandshake_get_peer_params(SocketQUICHandshake_T handshake);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Get string representation of crypto level.
 *
 * @param level Crypto level.
 *
 * @return Human-readable string.
 */
extern const char *
SocketQUICHandshake_crypto_level_string(SocketQUICCryptoLevel level);

/**
 * @brief Get string representation of handshake state.
 *
 * @param state Handshake state.
 *
 * @return Human-readable string.
 */
extern const char *
SocketQUICHandshake_state_string(SocketQUICHandshakeState state);

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code.
 *
 * @return Human-readable string.
 */
extern const char *
SocketQUICHandshake_result_string(SocketQUICHandshake_Result result);

#endif /* SOCKETQUICHANDSHAKE_INCLUDED */

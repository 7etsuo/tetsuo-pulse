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
#include "core/SocketConfig.h"
#include "quic/SocketQUICConnection.h"
#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICTransportParams.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/**
 * @brief CRYPTO stream receive buffer size per encryption level.
 *
 * Must accommodate largest possible TLS message (16KB + overhead).
 */
#ifndef QUIC_HANDSHAKE_CRYPTO_BUFFER_SIZE
#define QUIC_HANDSHAKE_CRYPTO_BUFFER_SIZE 16384
#endif

/* ============================================================================
 * Types
 * ============================================================================
 */

/**
 * @brief QUIC encryption levels (RFC 9000 Section 4.1.4).
 *
 * Each level has independent packet protection keys.
 */
typedef enum
{
  QUIC_CRYPTO_LEVEL_INITIAL = 0, /**< Initial packets (known secret) */
  QUIC_CRYPTO_LEVEL_0RTT,        /**< 0-RTT early data (client only) */
  QUIC_CRYPTO_LEVEL_HANDSHAKE,   /**< Handshake packets */
  QUIC_CRYPTO_LEVEL_APPLICATION, /**< 1-RTT application data */
  QUIC_CRYPTO_LEVEL_COUNT
} SocketQUICCryptoLevel;

/**
 * @brief Handshake state machine states.
 */
typedef enum
{
  QUIC_HANDSHAKE_STATE_IDLE = 0,  /**< Not started */
  QUIC_HANDSHAKE_STATE_INITIAL,   /**< Sending/receiving Initial */
  QUIC_HANDSHAKE_STATE_HANDSHAKE, /**< TLS handshake in progress */
  QUIC_HANDSHAKE_STATE_COMPLETE,  /**< Handshake complete */
  QUIC_HANDSHAKE_STATE_CONFIRMED, /**< Handshake confirmed */
  QUIC_HANDSHAKE_STATE_FAILED     /**< Handshake failed */
} SocketQUICHandshakeState;

/**
 * @brief Result codes for handshake operations.
 */
typedef enum
{
  QUIC_HANDSHAKE_OK = 0,          /**< Success */
  QUIC_HANDSHAKE_ERROR_NULL,      /**< NULL argument */
  QUIC_HANDSHAKE_ERROR_STATE,     /**< Invalid state */
  QUIC_HANDSHAKE_ERROR_CRYPTO,    /**< Cryptographic error */
  QUIC_HANDSHAKE_ERROR_TLS,       /**< TLS error */
  QUIC_HANDSHAKE_ERROR_BUFFER,    /**< Buffer overflow */
  QUIC_HANDSHAKE_ERROR_OFFSET,    /**< Invalid offset */
  QUIC_HANDSHAKE_ERROR_DUPLICATE, /**< Duplicate data */
  QUIC_HANDSHAKE_ERROR_TRANSPORT, /**< Transport parameter error */
  QUIC_HANDSHAKE_ERROR_MEMORY     /**< Memory allocation failure */
} SocketQUICHandshake_Result;

/**
 * @brief Buffered CRYPTO frame segment.
 *
 * Used for reassembling out-of-order CRYPTO data.
 */
typedef struct SocketQUICCryptoSegment
{
  uint64_t offset;                      /**< Offset in CRYPTO stream */
  uint64_t length;                      /**< Data length */
  uint8_t *data;                        /**< Data buffer */
  struct SocketQUICCryptoSegment *next; /**< Next segment in list */
} SocketQUICCryptoSegment_T;

/**
 * @brief CRYPTO stream state for one encryption level.
 *
 * Tracks sent and received CRYPTO data.
 */
typedef struct
{
  uint64_t send_offset;                /**< Next byte to send */
  uint64_t recv_offset;                /**< Next expected byte */
  uint8_t *recv_buffer;                /**< Reassembly buffer */
  size_t recv_buffer_size;             /**< Buffer allocation size */
  SocketQUICCryptoSegment_T *segments; /**< Out-of-order segments */
  int segment_count;                   /**< Number of buffered segments */
} SocketQUICCryptoStream_T;

/**
 * @brief 0-RTT state machine states (RFC 9001 Section 4.6).
 *
 * Tracks the lifecycle of 0-RTT early data from offer through
 * acceptance or rejection.
 */
typedef enum
{
  QUIC_0RTT_STATE_NONE = 0, /**< No 0-RTT attempted */
  QUIC_0RTT_STATE_OFFERED,  /**< Client: session ticket set, will offer */
  QUIC_0RTT_STATE_PENDING,  /**< Waiting for server response */
  QUIC_0RTT_STATE_ACCEPTED, /**< Server accepted early data */
  QUIC_0RTT_STATE_REJECTED  /**< Server rejected early data */
} SocketQUIC0RTT_State;

/**
 * @brief 0-RTT early data context (RFC 9001 Section 4.6).
 *
 * Manages session resumption state including:
 * - Session ticket storage and metadata
 * - Saved transport parameters for validation
 * - Early data buffer for replay on rejection
 *
 * Thread Safety: Not thread-safe; one context per connection.
 */
typedef struct SocketQUIC0RTT
{
  SocketQUIC0RTT_State state; /**< Current 0-RTT state */

  /* Session ticket (from previous connection) */
  uint8_t *ticket_data;          /**< Serialized session ticket */
  size_t ticket_len;             /**< Ticket length in bytes */
  uint64_t ticket_age_add;       /**< Obfuscation for ticket age */
  uint64_t ticket_issued_ms;     /**< When ticket was issued (ms) */
  uint32_t ticket_max_early_data; /**< max_early_data_size from ticket */

  /* Saved parameters from original connection (for validation) */
  SocketQUICTransportParams_T saved_params; /**< Original transport params */
  int saved_params_valid;                   /**< Params were saved */
  char saved_alpn[256];                     /**< Original ALPN protocol */
  size_t saved_alpn_len;                    /**< ALPN string length */

  /* Early data tracking */
  uint8_t *early_data_buffer;  /**< Buffer for replay on rejection */
  size_t early_data_len;       /**< Bytes in early_data_buffer */
  size_t early_data_capacity;  /**< Allocated buffer size */

  int keys_derived; /**< 0-RTT keys have been derived */
} SocketQUIC0RTT_T;

/**
 * @brief Opaque handshake context.
 */
typedef struct SocketQUICHandshake *SocketQUICHandshake_T;

/**
 * @brief Handshake structure.
 */
struct SocketQUICHandshake
{
  Arena_T arena;                  /**< Memory arena */
  SocketQUICConnection_T conn;    /**< Associated connection */
  SocketQUICConnection_Role role; /**< Client or server */
  SocketQUICHandshakeState state; /**< Current state */

  /* TLS integration (opaque pointer to avoid OpenSSL dependency in header) */
  void *tls_ctx; /**< TLS context (SSL_CTX*) */
  void *tls_ssl; /**< TLS connection (SSL*) */

  /* Transport parameters */
  SocketQUICTransportParams_T local_params; /**< Our parameters */
  SocketQUICTransportParams_T peer_params;  /**< Peer's parameters */
  int params_received;                      /**< Peer params received flag */

  /* CRYPTO streams per encryption level */
  SocketQUICCryptoStream_T crypto_streams[QUIC_CRYPTO_LEVEL_COUNT];

  /* Key material (opaque to allow different crypto backends) */
  void *keys[QUIC_CRYPTO_LEVEL_COUNT];         /**< Packet protection keys */
  int keys_available[QUIC_CRYPTO_LEVEL_COUNT]; /**< Key availability flags */

  /* Key discard state tracking (RFC 9001 §4.9) */
  int initial_keys_discarded;   /**< Initial keys discarded (§4.9.1) */
  int handshake_keys_discarded; /**< Handshake keys discarded (§4.9.2) */
  int zero_rtt_keys_discarded;  /**< 0-RTT keys discarded (§4.9.3) */
  int first_handshake_sent;     /**< Client: first Handshake packet sent */
  int first_handshake_received; /**< Server: first Handshake packet processed */

  /* Error tracking */
  uint64_t error_code;    /**< TLS alert or crypto error */
  char error_reason[256]; /**< Human-readable error */

  /* 0-RTT early data support (RFC 9001 §4.6) */
  SocketQUIC0RTT_T zero_rtt;   /**< 0-RTT state and data */
  int hello_retry_received;    /**< HRR received (forces 0-RTT rejection) */
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
SocketQUICHandshake_new (Arena_T arena,
                         SocketQUICConnection_T conn,
                         SocketQUICConnection_Role role);

/**
 * @brief Free handshake context and associated resources.
 *
 * @param handshake Pointer to handshake context (set to NULL after).
 */
extern void SocketQUICHandshake_free (SocketQUICHandshake_T *handshake);

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
SocketQUICHandshake_init (SocketQUICConnection_T conn,
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
extern SocketQUICHandshake_Result SocketQUICHandshake_set_transport_params (
    SocketQUICHandshake_T handshake, const SocketQUICTransportParams_T *params);

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
SocketQUICHandshake_send_initial (SocketQUICConnection_T conn);

/**
 * @brief Process received CRYPTO frame.
 *
 * Handles CRYPTO frame data, buffering if out-of-order, and feeds
 * to TLS when contiguous data is available.
 *
 * @param conn  QUIC connection.
 * @param frame CRYPTO frame to process.
 * @param level Encryption level from packet context.
 *
 * @return QUIC_HANDSHAKE_OK on success, error code otherwise.
 */
extern SocketQUICHandshake_Result
SocketQUICHandshake_process_crypto (SocketQUICConnection_T conn,
                                    const SocketQUICFrameCrypto_T *frame,
                                    SocketQUICCryptoLevel level);

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
SocketQUICHandshake_derive_keys (SocketQUICConnection_T conn,
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
SocketQUICHandshake_process (SocketQUICHandshake_T handshake);

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
extern int SocketQUICHandshake_has_keys (SocketQUICHandshake_T handshake,
                                         SocketQUICCryptoLevel level);

/**
 * @brief Get packet protection keys for encryption level.
 *
 * @param handshake Handshake context.
 * @param level     Encryption level.
 *
 * @return Opaque key structure, or NULL if not available.
 */
extern void *SocketQUICHandshake_get_keys (SocketQUICHandshake_T handshake,
                                           SocketQUICCryptoLevel level);

/**
 * @brief Discard keys for encryption level.
 *
 * Called when transitioning to higher encryption level.
 *
 * @param handshake Handshake context.
 * @param level     Encryption level to discard.
 */
extern void SocketQUICHandshake_discard_keys (SocketQUICHandshake_T handshake,
                                              SocketQUICCryptoLevel level);

/* ============================================================================
 * Key Discard Triggers (RFC 9001 Section 4.9)
 * ============================================================================
 */

/**
 * @brief Notify that client sent first Handshake packet (RFC 9001 §4.9.1).
 *
 * Client MUST discard Initial keys when it first sends a Handshake packet.
 * This function is idempotent; subsequent calls have no effect.
 *
 * @param handshake Handshake context.
 */
extern void
SocketQUICHandshake_on_handshake_packet_sent (SocketQUICHandshake_T handshake);

/**
 * @brief Notify that server processed first Handshake packet (RFC 9001 §4.9.1).
 *
 * Server MUST discard Initial keys when it first successfully processes
 * a Handshake packet. This function is idempotent.
 *
 * @param handshake Handshake context.
 */
extern void SocketQUICHandshake_on_handshake_packet_received (
    SocketQUICHandshake_T handshake);

/**
 * @brief Notify that handshake is confirmed (RFC 9001 §4.9.2).
 *
 * Both endpoints MUST discard Handshake keys when the TLS handshake
 * is confirmed. This function is idempotent.
 *
 * @param handshake Handshake context.
 */
extern void SocketQUICHandshake_on_confirmed (SocketQUICHandshake_T handshake);

/**
 * @brief Notify that 1-RTT keys are installed (RFC 9001 §4.9.3).
 *
 * Client SHOULD discard 0-RTT keys as soon as 1-RTT keys are installed.
 * This function is idempotent.
 *
 * @param handshake Handshake context.
 */
extern void
SocketQUICHandshake_on_1rtt_keys_installed (SocketQUICHandshake_T handshake);

/**
 * @brief Notify that server received 1-RTT packet (RFC 9001 §4.9.3).
 *
 * Server MAY discard 0-RTT keys when it receives a 1-RTT packet.
 * Server MUST discard 0-RTT keys within 3×PTO after first 1-RTT packet.
 * This function is idempotent.
 *
 * @param handshake Handshake context.
 */
extern void
SocketQUICHandshake_on_1rtt_packet_received (SocketQUICHandshake_T handshake);

/* ============================================================================
 * Key Availability Checks (RFC 9001 Section 4.9)
 * ============================================================================
 */

/**
 * @brief Check if Initial packets can be sent.
 *
 * Returns false after Initial keys are discarded per RFC 9001 §4.9.1.
 *
 * @param handshake Handshake context.
 *
 * @return Non-zero if Initial packets can be sent, 0 otherwise.
 */
extern int
SocketQUICHandshake_can_send_initial (SocketQUICHandshake_T handshake);

/**
 * @brief Check if Initial packets can be received and processed.
 *
 * Returns false after Initial keys are discarded per RFC 9001 §4.9.1.
 *
 * @param handshake Handshake context.
 *
 * @return Non-zero if Initial packets can be received, 0 otherwise.
 */
extern int
SocketQUICHandshake_can_receive_initial (SocketQUICHandshake_T handshake);

/**
 * @brief Check if Handshake packets can be sent.
 *
 * Returns false after Handshake keys are discarded per RFC 9001 §4.9.2.
 *
 * @param handshake Handshake context.
 *
 * @return Non-zero if Handshake packets can be sent, 0 otherwise.
 */
extern int
SocketQUICHandshake_can_send_handshake (SocketQUICHandshake_T handshake);

/**
 * @brief Check if Handshake packets can be received and processed.
 *
 * Returns false after Handshake keys are discarded per RFC 9001 §4.9.2.
 *
 * @param handshake Handshake context.
 *
 * @return Non-zero if Handshake packets can be received, 0 otherwise.
 */
extern int
SocketQUICHandshake_can_receive_handshake (SocketQUICHandshake_T handshake);

/**
 * @brief Check if 0-RTT packets can be sent (client only).
 *
 * Returns false after 0-RTT keys are discarded per RFC 9001 §4.9.3.
 *
 * @param handshake Handshake context.
 *
 * @return Non-zero if 0-RTT packets can be sent, 0 otherwise.
 */
extern int SocketQUICHandshake_can_send_0rtt (SocketQUICHandshake_T handshake);

/**
 * @brief Check if 0-RTT packets can be received (server only).
 *
 * Returns false after 0-RTT keys are discarded per RFC 9001 §4.9.3.
 *
 * @param handshake Handshake context.
 *
 * @return Non-zero if 0-RTT packets can be received, 0 otherwise.
 */
extern int
SocketQUICHandshake_can_receive_0rtt (SocketQUICHandshake_T handshake);

/* ============================================================================
 * 0-RTT Early Data Functions (RFC 9001 Section 4.6)
 * ============================================================================
 */

/**
 * @brief Initialize 0-RTT state to default values.
 *
 * Sets state to NONE and zeros all fields. Called automatically
 * by SocketQUICHandshake_new() but can be called to reset state.
 *
 * @param handshake Handshake context.
 */
extern void SocketQUICHandshake_0rtt_init (SocketQUICHandshake_T handshake);

/**
 * @brief Check if 0-RTT early data is available for this connection.
 *
 * Returns true if:
 * - A valid session ticket is stored
 * - No HelloRetryRequest was received
 * - State is OFFERED or PENDING
 *
 * Client should check this before sending 0-RTT data.
 *
 * @param handshake Handshake context.
 *
 * @return Non-zero if 0-RTT is available, 0 otherwise.
 */
extern int SocketQUICHandshake_0rtt_available (SocketQUICHandshake_T handshake);

/**
 * @brief Store session ticket for 0-RTT resumption (RFC 9001 §4.6).
 *
 * Copies session ticket data and associated parameters for use in
 * subsequent connection. Client should call this after receiving
 * NewSessionTicket from a previous connection.
 *
 * Per RFC 9001 §4.6.1: Only tickets with max_early_data_size=0xffffffff
 * are valid for QUIC 0-RTT. Tickets with other values MUST be rejected.
 *
 * @param handshake   Handshake context.
 * @param ticket      Serialized session ticket.
 * @param ticket_len  Ticket length in bytes.
 * @param params      Transport parameters from original connection.
 * @param alpn        ALPN protocol from original connection.
 * @param alpn_len    ALPN string length.
 *
 * @return QUIC_HANDSHAKE_OK on success, error code otherwise.
 */
extern SocketQUICHandshake_Result
SocketQUICHandshake_0rtt_set_ticket (SocketQUICHandshake_T handshake,
                                     const uint8_t *ticket,
                                     size_t ticket_len,
                                     const SocketQUICTransportParams_T *params,
                                     const char *alpn,
                                     size_t alpn_len);

/**
 * @brief Get current 0-RTT state.
 *
 * @param handshake Handshake context.
 *
 * @return Current 0-RTT state.
 */
extern SocketQUIC0RTT_State
SocketQUICHandshake_0rtt_get_state (SocketQUICHandshake_T handshake);

/**
 * @brief Check if 0-RTT was accepted by server.
 *
 * Valid only after handshake completes. Returns true if server
 * included early_data extension in EncryptedExtensions.
 *
 * @param handshake Handshake context.
 *
 * @return Non-zero if 0-RTT was accepted, 0 otherwise.
 */
extern int SocketQUICHandshake_0rtt_accepted (SocketQUICHandshake_T handshake);

/**
 * @brief Handle 0-RTT rejection by server (RFC 9001 §4.6.2).
 *
 * Called when server does not accept early data. Per RFC 9001:
 * - Discards 0-RTT keys
 * - Resets stream state for 0-RTT data
 * - Transitions state to REJECTED
 *
 * Client MUST resend all 0-RTT data as 1-RTT data after this.
 *
 * @param handshake Handshake context.
 *
 * @return QUIC_HANDSHAKE_OK on success.
 */
extern SocketQUICHandshake_Result
SocketQUICHandshake_0rtt_handle_rejection (SocketQUICHandshake_T handshake);

/**
 * @brief Notify that HelloRetryRequest was received (RFC 9001 §4.6.2).
 *
 * Per RFC 9001 §4.6.2: A HelloRetryRequest always rejects 0-RTT.
 * This function sets the HRR flag which forces 0-RTT rejection.
 *
 * @param handshake Handshake context.
 */
extern void
SocketQUICHandshake_on_hello_retry_request (SocketQUICHandshake_T handshake);

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
SocketQUICHandshake_get_state (SocketQUICHandshake_T handshake);

/**
 * @brief Check if handshake is complete.
 *
 * @param handshake Handshake context.
 *
 * @return Non-zero if complete, 0 otherwise.
 */
extern int SocketQUICHandshake_is_complete (SocketQUICHandshake_T handshake);

/**
 * @brief Check if handshake is confirmed.
 *
 * Confirmation means both endpoints have completed handshake.
 *
 * @param handshake Handshake context.
 *
 * @return Non-zero if confirmed, 0 otherwise.
 */
extern int SocketQUICHandshake_is_confirmed (SocketQUICHandshake_T handshake);

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
SocketQUICHandshake_get_peer_params (SocketQUICHandshake_T handshake);

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
SocketQUICHandshake_crypto_level_string (SocketQUICCryptoLevel level);

/**
 * @brief Get string representation of handshake state.
 *
 * @param state Handshake state.
 *
 * @return Human-readable string.
 */
extern const char *
SocketQUICHandshake_state_string (SocketQUICHandshakeState state);

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code.
 *
 * @return Human-readable string.
 */
extern const char *
SocketQUICHandshake_result_string (SocketQUICHandshake_Result result);

#endif /* SOCKETQUICHANDSHAKE_INCLUDED */

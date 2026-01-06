/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICSession.h
 * @brief QUIC Session Resumption and HelloRetryRequest (RFC 9001 §4.5, §4.7).
 *
 * Session Resumption (§4.5):
 * - NewSessionTicket messages carried in CRYPTO frames after handshake
 * - Clients store tickets for subsequent 0-RTT connections
 * - Servers use tickets to restore session state
 *
 * HelloRetryRequest (§4.7):
 * - Server requests different key share or validates client
 * - Client responds with new ClientHello
 * - Initial keys updated after HRR with new transcript hash
 *
 * Thread Safety: Functions are not thread-safe per session context.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9001#section-4.5
 * @see https://www.rfc-editor.org/rfc/rfc9001#section-4.7
 */

#ifndef SOCKETQUICSESSION_INCLUDED
#define SOCKETQUICSESSION_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICHandshake.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/**
 * @brief Maximum session ticket size (RFC 8446 §4.6.1).
 *
 * TLS 1.3 recommends tickets be compact for QUIC due to ClientHello size.
 */
#define QUIC_SESSION_MAX_TICKET_SIZE 2048

/**
 * @brief Maximum HRR cookie size (RFC 8446 §4.2.2).
 *
 * Servers may include a cookie in HelloRetryRequest for stateless retry.
 */
#define QUIC_SESSION_MAX_COOKIE_SIZE 256

/**
 * @brief Maximum age for session resumption (RFC 8446 §4.6.1).
 *
 * TLS 1.3 limits resumption to 7 days (604800 seconds).
 */
#define QUIC_SESSION_MAX_AGE_SECONDS 604800

/**
 * @brief QUIC 0-RTT sentinel value (RFC 9001 §4.6.1).
 *
 * NewSessionTicket max_early_data_size must be 0xffffffff to enable 0-RTT.
 */
#define QUIC_SESSION_0RTT_SENTINEL 0xffffffffUL

/* ============================================================================
 * Types
 * ============================================================================
 */

/**
 * @brief Result codes for session operations.
 */
typedef enum
{
  QUIC_SESSION_OK = 0,             /**< Success */
  QUIC_SESSION_ERROR_NULL,         /**< NULL argument */
  QUIC_SESSION_ERROR_STATE,        /**< Invalid state for operation */
  QUIC_SESSION_ERROR_TICKET,       /**< Invalid or expired ticket */
  QUIC_SESSION_ERROR_HRR,          /**< HelloRetryRequest error */
  QUIC_SESSION_ERROR_COOKIE,       /**< Cookie validation failed */
  QUIC_SESSION_ERROR_MEMORY,       /**< Memory allocation failed */
  QUIC_SESSION_ERROR_TRANSPORT,    /**< Transport parameter mismatch */
  QUIC_SESSION_ERROR_ALPN,         /**< ALPN mismatch on resumption */
  QUIC_SESSION_ERROR_EXPIRED,      /**< Session ticket expired */
  QUIC_SESSION_ERROR_NOT_RESUMABLE /**< Session cannot be resumed */
} SocketQUICSession_Result;

/**
 * @brief Session resumption state.
 */
typedef enum
{
  QUIC_SESSION_STATE_NONE = 0,   /**< No session/resumption */
  QUIC_SESSION_STATE_STORED,     /**< Ticket stored, can attempt resumption */
  QUIC_SESSION_STATE_ATTEMPTING, /**< Currently attempting resumption */
  QUIC_SESSION_STATE_RESUMED,    /**< Successfully resumed */
  QUIC_SESSION_STATE_NEW         /**< New session (no resumption) */
} SocketQUICSessionState;

/**
 * @brief HelloRetryRequest state tracking.
 */
typedef struct
{
  int hrr_received;               /**< HRR received from server */
  int hrr_sent;                   /**< HRR sent by server */
  uint8_t cookie[QUIC_SESSION_MAX_COOKIE_SIZE]; /**< HRR cookie data */
  size_t cookie_len;              /**< Cookie length in bytes */
  uint8_t transcript_hash[32];    /**< CH1 transcript hash after HRR */
  int transcript_hash_valid;      /**< Transcript hash computed */
} SocketQUICHRR_T;

/**
 * @brief Session ticket storage for resumption.
 */
typedef struct
{
  uint8_t ticket[QUIC_SESSION_MAX_TICKET_SIZE]; /**< Ticket data */
  size_t ticket_len;                /**< Ticket length in bytes */
  uint32_t lifetime;                /**< Ticket lifetime in seconds */
  uint32_t age_add;                 /**< Ticket age obfuscator (RFC 8446) */
  uint64_t issue_time;              /**< Timestamp when ticket was issued */
  uint32_t max_early_data;          /**< max_early_data_size (0xffffffff for 0-RTT) */
  int valid;                        /**< Ticket is valid */
} SocketQUICTicket_T;

/**
 * @brief Transport parameters saved for 0-RTT validation.
 *
 * Per RFC 9001 §4.6.3, these parameters from the original connection
 * must be validated when attempting 0-RTT.
 */
typedef struct
{
  uint64_t initial_max_data;          /**< initial_max_data from server */
  uint64_t initial_max_stream_data_bidi_local;
  uint64_t initial_max_stream_data_bidi_remote;
  uint64_t initial_max_stream_data_uni;
  uint64_t initial_max_streams_bidi;
  uint64_t initial_max_streams_uni;
  uint64_t active_connection_id_limit;
  int params_valid;                   /**< Parameters are valid */
} SocketQUICSessionParams_T;

/**
 * @brief Complete session context for resumption and HRR.
 */
typedef struct SocketQUICSession *SocketQUICSession_T;

struct SocketQUICSession
{
  Arena_T arena;                      /**< Memory arena */
  SocketQUICSessionState state;       /**< Current session state */
  SocketQUICHRR_T hrr;                /**< HelloRetryRequest tracking */
  SocketQUICTicket_T ticket;          /**< Stored session ticket */
  SocketQUICSessionParams_T params;   /**< Transport params for 0-RTT */
  char alpn[32];                      /**< ALPN protocol from original conn */
  size_t alpn_len;                    /**< ALPN length */
  int enable_0rtt;                    /**< 0-RTT enabled for this session */
  void *ssl_session;                  /**< OpenSSL SSL_SESSION* (opaque) */
};

/* ============================================================================
 * Exceptions
 * ============================================================================
 */

extern const Except_T SocketQUICSession_Failed;

/* ============================================================================
 * Lifecycle Functions
 * ============================================================================
 */

/**
 * @brief Create a new session context.
 *
 * @param arena Memory arena for allocations.
 *
 * @return Session context, or NULL on allocation failure.
 */
extern SocketQUICSession_T SocketQUICSession_new (Arena_T arena);

/**
 * @brief Free session context and securely clear sensitive data.
 *
 * @param session Pointer to session context (set to NULL after).
 */
extern void SocketQUICSession_free (SocketQUICSession_T *session);

/* ============================================================================
 * Session Ticket Functions (RFC 9001 §4.5)
 * ============================================================================
 */

/**
 * @brief Store a session ticket for future resumption.
 *
 * Called after handshake when NewSessionTicket is received.
 * Validates max_early_data_size sentinel for 0-RTT capability.
 *
 * @param session      Session context.
 * @param ticket_data  Raw ticket data from NewSessionTicket.
 * @param ticket_len   Ticket data length.
 * @param lifetime     Ticket lifetime in seconds.
 * @param age_add      Ticket age obfuscator value.
 * @param max_early_data max_early_data_size from NewSessionTicket.
 *
 * @return QUIC_SESSION_OK on success, error code otherwise.
 */
extern SocketQUICSession_Result
SocketQUICSession_store_ticket (SocketQUICSession_T session,
                                const uint8_t *ticket_data,
                                size_t ticket_len,
                                uint32_t lifetime,
                                uint32_t age_add,
                                uint32_t max_early_data);

/**
 * @brief Check if session can be resumed with 0-RTT.
 *
 * Verifies ticket validity, expiration, and 0-RTT capability.
 *
 * @param session Session context.
 *
 * @return Non-zero if 0-RTT resumption is possible, 0 otherwise.
 */
extern int SocketQUICSession_can_attempt_0rtt (SocketQUICSession_T session);

/**
 * @brief Check if session can be resumed (with or without 0-RTT).
 *
 * Verifies ticket validity and expiration only.
 *
 * @param session Session context.
 *
 * @return Non-zero if resumption is possible, 0 otherwise.
 */
extern int SocketQUICSession_can_resume (SocketQUICSession_T session);

/**
 * @brief Get obfuscated ticket age for ClientHello.
 *
 * Per RFC 8446 §4.2.11.1, obfuscated_ticket_age =
 * (current_time - issue_time + age_add) mod 2^32
 *
 * @param session Session context.
 *
 * @return Obfuscated ticket age, or 0 if no valid ticket.
 */
extern uint32_t
SocketQUICSession_get_obfuscated_age (SocketQUICSession_T session);

/**
 * @brief Save transport parameters for 0-RTT validation.
 *
 * Per RFC 9001 §4.6.3, these must be saved with the ticket.
 *
 * @param session Session context.
 * @param params  Transport parameters from server.
 *
 * @return QUIC_SESSION_OK on success.
 */
extern SocketQUICSession_Result SocketQUICSession_save_transport_params (
    SocketQUICSession_T session, const SocketQUICTransportParams_T *params);

/**
 * @brief Validate transport parameters for 0-RTT.
 *
 * Per RFC 9001 §4.6.3, server's new parameters must be at least
 * as permissive as the remembered parameters.
 *
 * @param session    Session context.
 * @param new_params Server's new transport parameters.
 *
 * @return QUIC_SESSION_OK if valid, QUIC_SESSION_ERROR_TRANSPORT if not.
 */
extern SocketQUICSession_Result SocketQUICSession_validate_transport_params (
    SocketQUICSession_T session, const SocketQUICTransportParams_T *new_params);

/**
 * @brief Clear stored session ticket.
 *
 * Securely erases ticket data.
 *
 * @param session Session context.
 */
extern void SocketQUICSession_clear_ticket (SocketQUICSession_T session);

/* ============================================================================
 * HelloRetryRequest Functions (RFC 9001 §4.7)
 * ============================================================================
 */

/**
 * @brief Notify that HelloRetryRequest was received (client).
 *
 * Updates session state and stores any cookie from HRR.
 *
 * @param session    Session context.
 * @param cookie     Cookie data from HRR (may be NULL).
 * @param cookie_len Cookie length (0 if no cookie).
 *
 * @return QUIC_SESSION_OK on success.
 */
extern SocketQUICSession_Result
SocketQUICSession_on_hrr_received (SocketQUICSession_T session,
                                   const uint8_t *cookie,
                                   size_t cookie_len);

/**
 * @brief Notify that HelloRetryRequest was sent (server).
 *
 * Updates session state for server-side HRR tracking.
 *
 * @param session Session context.
 *
 * @return QUIC_SESSION_OK on success.
 */
extern SocketQUICSession_Result
SocketQUICSession_on_hrr_sent (SocketQUICSession_T session);

/**
 * @brief Check if HelloRetryRequest was received.
 *
 * @param session Session context.
 *
 * @return Non-zero if HRR was received, 0 otherwise.
 */
extern int SocketQUICSession_is_hrr (SocketQUICSession_T session);

/**
 * @brief Get HRR cookie for second ClientHello.
 *
 * @param session    Session context.
 * @param cookie     Output: cookie data pointer.
 * @param cookie_len Output: cookie length.
 *
 * @return QUIC_SESSION_OK if cookie available, error otherwise.
 */
extern SocketQUICSession_Result
SocketQUICSession_get_hrr_cookie (SocketQUICSession_T session,
                                  const uint8_t **cookie,
                                  size_t *cookie_len);

/**
 * @brief Store transcript hash for post-HRR operations.
 *
 * After HRR, the transcript hash includes a synthetic message.
 * This hash is needed for key derivation.
 *
 * @param session Session context.
 * @param hash    32-byte transcript hash.
 *
 * @return QUIC_SESSION_OK on success.
 */
extern SocketQUICSession_Result
SocketQUICSession_set_hrr_transcript (SocketQUICSession_T session,
                                      const uint8_t hash[32]);

/**
 * @brief Check if HRR causes 0-RTT rejection.
 *
 * Per RFC 9001 §4.6.2, server always rejects 0-RTT if HRR is sent.
 *
 * @param session Session context.
 *
 * @return Non-zero if 0-RTT is rejected due to HRR, 0 otherwise.
 */
extern int SocketQUICSession_hrr_rejects_0rtt (SocketQUICSession_T session);

/* ============================================================================
 * State Query Functions
 * ============================================================================
 */

/**
 * @brief Get current session state.
 *
 * @param session Session context.
 *
 * @return Current session state.
 */
extern SocketQUICSessionState
SocketQUICSession_get_state (SocketQUICSession_T session);

/**
 * @brief Check if session was resumed.
 *
 * @param session Session context.
 *
 * @return Non-zero if session was resumed, 0 otherwise.
 */
extern int SocketQUICSession_is_resumed (SocketQUICSession_T session);

/**
 * @brief Mark session as successfully resumed.
 *
 * Called when server accepts resumption.
 *
 * @param session Session context.
 */
extern void SocketQUICSession_mark_resumed (SocketQUICSession_T session);

/**
 * @brief Mark session as new (resumption failed or not attempted).
 *
 * @param session Session context.
 */
extern void SocketQUICSession_mark_new (SocketQUICSession_T session);

/* ============================================================================
 * ALPN Functions (RFC 9001 §4.6.3)
 * ============================================================================
 */

/**
 * @brief Save ALPN protocol for 0-RTT validation.
 *
 * Per RFC 9001 §4.6.3, ALPN from original connection must match.
 *
 * @param session  Session context.
 * @param alpn     ALPN protocol string.
 * @param alpn_len ALPN length.
 *
 * @return QUIC_SESSION_OK on success.
 */
extern SocketQUICSession_Result
SocketQUICSession_save_alpn (SocketQUICSession_T session,
                             const char *alpn,
                             size_t alpn_len);

/**
 * @brief Validate ALPN for 0-RTT.
 *
 * ALPN from new connection must match the remembered ALPN.
 *
 * @param session  Session context.
 * @param alpn     ALPN from new connection.
 * @param alpn_len ALPN length.
 *
 * @return QUIC_SESSION_OK if match, QUIC_SESSION_ERROR_ALPN if not.
 */
extern SocketQUICSession_Result
SocketQUICSession_validate_alpn (SocketQUICSession_T session,
                                 const char *alpn,
                                 size_t alpn_len);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Get string representation of session state.
 *
 * @param state Session state.
 *
 * @return Human-readable string.
 */
extern const char *
SocketQUICSession_state_string (SocketQUICSessionState state);

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code.
 *
 * @return Human-readable string.
 */
extern const char *
SocketQUICSession_result_string (SocketQUICSession_Result result);

#endif /* SOCKETQUICSESSION_INCLUDED */

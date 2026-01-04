/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICTLS.h
 * @brief TLS 1.3 Interface for QUIC (RFC 9001 Section 4.1).
 *
 * Provides the QUIC-TLS interface using OpenSSL 3.0+ SSL_QUIC_METHOD:
 * - TLS context creation and configuration for QUIC
 * - Encryption secrets management at each crypto level
 * - CRYPTO data extraction for handshake frames
 * - Alert to QUIC error code conversion
 *
 * Key behaviors per RFC 9001:
 * - CRYPTO frames carry TLS handshake at encryption levels
 * - Encryption level changes trigger key derivation
 * - Handshake complete when both Finished messages exchanged
 * - Handshake confirmed when 1-RTT ACK received
 *
 * Thread Safety: Functions are not thread-safe per handshake context.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9001#section-4.1
 */

#ifndef SOCKETQUICTLS_INCLUDED
#define SOCKETQUICTLS_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/SocketCrypto.h"
#include "quic/SocketQUICHandshake.h"

/* ============================================================================
 * Result Codes
 * ============================================================================
 */

/**
 * @brief Result codes for QUIC-TLS operations.
 */
typedef enum
{
  QUIC_TLS_OK = 0,           /**< Success */
  QUIC_TLS_ERROR_NULL,       /**< NULL argument */
  QUIC_TLS_ERROR_INIT,       /**< TLS initialization failed */
  QUIC_TLS_ERROR_CERT,       /**< Certificate error */
  QUIC_TLS_ERROR_KEY,        /**< Private key error */
  QUIC_TLS_ERROR_ALPN,       /**< ALPN configuration error */
  QUIC_TLS_ERROR_TRANSPORT,  /**< Transport params error */
  QUIC_TLS_ERROR_HANDSHAKE,  /**< Handshake failed */
  QUIC_TLS_ERROR_SECRETS,    /**< Secret derivation failed */
  QUIC_TLS_ERROR_ALERT,      /**< TLS alert received */
  QUIC_TLS_ERROR_NO_TLS,     /**< TLS support not available */
  QUIC_TLS_ERROR_WANT_READ,  /**< Need more data */
  QUIC_TLS_ERROR_WANT_WRITE, /**< Need to send data */
  QUIC_TLS_ERROR_LEVEL       /**< Invalid encryption level */
} SocketQUICTLS_Result;

/* ============================================================================
 * TLS Configuration
 * ============================================================================
 */

/**
 * @brief Configuration for QUIC-TLS context.
 *
 * Used to initialize TLS context with certificates, ALPN, and options.
 */
typedef struct SocketQUICTLSConfig
{
  const char *cert_file;  /**< Server certificate file (PEM) */
  const char *key_file;   /**< Server private key file (PEM) */
  const char *ca_file;    /**< CA certificates file (PEM) */
  const char *alpn;       /**< ALPN protocol (e.g., "h3") */
  int verify_peer;        /**< Verify peer certificate (1=yes) */
  int enable_0rtt;        /**< Enable 0-RTT early data (1=yes) */
} SocketQUICTLSConfig_T;

/* ============================================================================
 * Lifecycle Functions
 * ============================================================================
 */

/**
 * @brief Initialize TLS context for QUIC.
 *
 * Creates SSL_CTX with TLS 1.3 only, QUIC transport params extension,
 * and SSL_QUIC_METHOD callbacks.
 *
 * @param handshake Handshake context.
 * @param config    TLS configuration (NULL for defaults).
 *
 * @return QUIC_TLS_OK on success, error code otherwise.
 */
extern SocketQUICTLS_Result
SocketQUICTLS_init_context (SocketQUICHandshake_T handshake,
                            const SocketQUICTLSConfig_T *config);

/**
 * @brief Create SSL object for connection.
 *
 * Sets up SSL object from context with QUIC method and connect/accept state.
 *
 * @param handshake Handshake context (must have tls_ctx set).
 *
 * @return QUIC_TLS_OK on success, error code otherwise.
 */
extern SocketQUICTLS_Result
SocketQUICTLS_create_ssl (SocketQUICHandshake_T handshake);

/**
 * @brief Free TLS resources.
 *
 * Securely clears and frees SSL and SSL_CTX objects.
 *
 * @param handshake Handshake context.
 */
extern void SocketQUICTLS_free (SocketQUICHandshake_T handshake);

/* ============================================================================
 * Handshake Operations
 * ============================================================================
 */

/**
 * @brief Advance TLS handshake state machine.
 *
 * Calls SSL_do_handshake() and processes results. May generate CRYPTO
 * data or derive new keys.
 *
 * @param handshake Handshake context.
 *
 * @return QUIC_TLS_OK on success/progress, error code otherwise.
 */
extern SocketQUICTLS_Result
SocketQUICTLS_do_handshake (SocketQUICHandshake_T handshake);

/**
 * @brief Provide CRYPTO frame data to TLS stack.
 *
 * Feeds received handshake data via SSL_provide_quic_data().
 *
 * @param handshake Handshake context.
 * @param level     Encryption level the data was received at.
 * @param data      CRYPTO frame data.
 * @param len       Data length.
 *
 * @return QUIC_TLS_OK on success, error code otherwise.
 */
extern SocketQUICTLS_Result
SocketQUICTLS_provide_data (SocketQUICHandshake_T handshake,
                            SocketQUICCryptoLevel level,
                            const uint8_t *data,
                            size_t len);

/**
 * @brief Get pending CRYPTO data to send.
 *
 * Retrieves handshake data buffered by TLS for the current level.
 * Call after do_handshake() or provide_data() to get data to send.
 *
 * @param handshake Handshake context.
 * @param level     Output: encryption level for data.
 * @param data      Output: pointer to data (valid until next call).
 * @param len       Output: data length.
 *
 * @return QUIC_TLS_OK if data available, QUIC_TLS_ERROR_WANT_READ if none.
 */
extern SocketQUICTLS_Result
SocketQUICTLS_get_data (SocketQUICHandshake_T handshake,
                        SocketQUICCryptoLevel *level,
                        const uint8_t **data,
                        size_t *len);

/**
 * @brief Mark CRYPTO data as consumed.
 *
 * Call after sending data returned by get_data().
 *
 * @param handshake Handshake context.
 * @param level     Encryption level.
 * @param len       Number of bytes consumed.
 *
 * @return QUIC_TLS_OK on success.
 */
extern SocketQUICTLS_Result
SocketQUICTLS_consume_data (SocketQUICHandshake_T handshake,
                            SocketQUICCryptoLevel level,
                            size_t len);

/**
 * @brief Check if handshake is complete.
 *
 * Handshake is complete when TLS Finished messages exchanged.
 *
 * @param handshake Handshake context.
 *
 * @return Non-zero if complete, 0 otherwise.
 */
extern int SocketQUICTLS_is_complete (SocketQUICHandshake_T handshake);

/* ============================================================================
 * Key Management
 * ============================================================================
 */

/**
 * @brief Check if keys are available for encryption level.
 *
 * @param handshake Handshake context.
 * @param level     Encryption level to check.
 *
 * @return Non-zero if keys available, 0 otherwise.
 */
extern int SocketQUICTLS_has_keys (SocketQUICHandshake_T handshake,
                                   SocketQUICCryptoLevel level);

/**
 * @brief Derive packet protection keys from TLS secrets.
 *
 * Called internally when TLS provides secrets. Derives AEAD key,
 * IV, and header protection key using HKDF-Expand-Label.
 *
 * @param handshake Handshake context.
 * @param level     Encryption level to derive keys for.
 *
 * @return QUIC_TLS_OK on success, error code otherwise.
 */
extern SocketQUICTLS_Result
SocketQUICTLS_derive_keys (SocketQUICHandshake_T handshake,
                           SocketQUICCryptoLevel level);

/* ============================================================================
 * Alert Handling
 * ============================================================================
 */

/**
 * @brief Convert TLS alert to QUIC CRYPTO_ERROR code.
 *
 * Per RFC 9001 Section 4.8: QUIC error = 0x0100 + TLS alert.
 *
 * @param alert TLS alert description value.
 *
 * @return QUIC error code in CRYPTO_ERROR range.
 */
extern uint64_t SocketQUICTLS_alert_to_error (uint8_t alert);

/**
 * @brief Get QUIC error code from last TLS error.
 *
 * @param handshake Handshake context.
 *
 * @return QUIC error code, or 0 if no error.
 */
extern uint64_t SocketQUICTLS_get_error_code (SocketQUICHandshake_T handshake);

/**
 * @brief Get human-readable error string from last TLS error.
 *
 * @param handshake Handshake context.
 *
 * @return Error string (may be empty if no error).
 */
extern const char *
SocketQUICTLS_get_error_string (SocketQUICHandshake_T handshake);

/* ============================================================================
 * Transport Parameters
 * ============================================================================
 */

/**
 * @brief Set local transport parameters for TLS extension.
 *
 * Must be called before handshake starts. Uses SSL_set_quic_transport_params().
 *
 * @param handshake Handshake context.
 * @param params    Encoded transport parameters.
 * @param len       Parameters length.
 *
 * @return QUIC_TLS_OK on success, error code otherwise.
 */
extern SocketQUICTLS_Result
SocketQUICTLS_set_transport_params (SocketQUICHandshake_T handshake,
                                    const uint8_t *params,
                                    size_t len);

/**
 * @brief Get peer transport parameters from TLS extension.
 *
 * Only valid after handshake is complete. Uses
 * SSL_get_peer_quic_transport_params().
 *
 * @param handshake Handshake context.
 * @param params    Output: pointer to parameters (valid until SSL freed).
 * @param len       Output: parameters length.
 *
 * @return QUIC_TLS_OK on success, error code otherwise.
 */
extern SocketQUICTLS_Result
SocketQUICTLS_get_peer_transport_params (SocketQUICHandshake_T handshake,
                                         const uint8_t **params,
                                         size_t *len);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code.
 *
 * @return Human-readable string.
 */
extern const char *SocketQUICTLS_result_string (SocketQUICTLS_Result result);

#endif /* SOCKETQUICTLS_INCLUDED */

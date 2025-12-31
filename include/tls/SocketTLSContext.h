/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketTLSContext.h
 * @ingroup security
 * @brief TLS context management with secure defaults and certificate handling.
 *
 * Features:
 * - TLS 1.3 preferred, modern cipher suites
 * - Certificate/CA loading with verification
 * - ALPN protocol negotiation
 * - Session caching and tickets
 * - OCSP stapling (client and server)
 * - Certificate pinning (SPKI SHA256)
 * - Certificate Transparency (RFC 6962)
 * - CRL with auto-refresh
 *
 * Thread safety: Contexts NOT thread-safe during modification. Share read-only
 * after setup. SSL objects created from context are per-connection.
 *
 * @see SocketTLS.h for socket integration
 * @see docs/SECURITY.md for TLS hardening
 */

#ifndef SOCKETTLSCONTEXT_INCLUDED
#define SOCKETTLSCONTEXT_INCLUDED

#include "core/Arena.h"
#include "core/Except.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"

#if SOCKET_HAS_TLS

#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#define T SocketTLSContext_T
typedef struct T *T;

/* ============================================================================
 * Context Creation
 * ============================================================================
 */

/**
 * @brief Create server TLS context with cert/key.
 * @param cert_file Server certificate (PEM)
 * @param key_file Private key (PEM)
 * @param ca_file Optional CA file for client auth (NULL to disable)
 * @return New context
 * @throws SocketTLS_Failed on error
 */
extern T SocketTLSContext_new_server (const char *cert_file,
                                      const char *key_file,
                                      const char *ca_file);

/**
 * @brief Create client TLS context.
 * @param ca_file Optional CA file for server verification
 * @return New context
 * @throws SocketTLS_Failed on error
 */
extern T SocketTLSContext_new_client (const char *ca_file);

/**
 * @brief Create TLS context with custom config.
 * @param config Configuration (NULL for defaults)
 * @return New context
 * @throws SocketTLS_Failed on error
 */
extern T SocketTLSContext_new (const SocketTLSConfig_T *config);

/**
 * @brief Dispose of TLS context.
 * @param ctx_p Pointer to context (set to NULL)
 */
extern void SocketTLSContext_free (T *ctx_p);

/* ============================================================================
 * Certificate Management
 * ============================================================================
 */

/**
 * @brief Load server certificate and key.
 * @param ctx TLS context
 * @param cert_file Certificate (PEM)
 * @param key_file Private key (PEM)
 * @throws SocketTLS_Failed on error
 */
extern void SocketTLSContext_load_certificate (T ctx,
                                               const char *cert_file,
                                               const char *key_file);

/**
 * @brief Add certificate for SNI virtual hosting.
 * @param ctx TLS context
 * @param hostname Hostname (NULL for default)
 * @param cert_file Certificate (PEM)
 * @param key_file Private key (PEM)
 * @throws SocketTLS_Failed on error
 */
extern void SocketTLSContext_add_certificate (T ctx,
                                              const char *hostname,
                                              const char *cert_file,
                                              const char *key_file);

/**
 * @brief Load trusted CA certificates.
 * @param ctx TLS context
 * @param ca_file CA file or directory
 * @throws SocketTLS_Failed on error
 */
extern void SocketTLSContext_load_ca (T ctx, const char *ca_file);

/**
 * @brief Set certificate verification mode.
 * @param ctx TLS context
 * @param mode TLS_VERIFY_NONE, TLS_VERIFY_PEER, etc.
 * @throws SocketTLS_Failed on invalid mode
 */
extern void SocketTLSContext_set_verify_mode (T ctx, TLSVerifyMode mode);

/* ============================================================================
 * Custom Verification
 * ============================================================================
 */

/**
 * @brief User-defined verification callback.
 * @param preverify_ok OpenSSL result (1=OK, 0=fail)
 * @param x509_ctx Certificate store context
 * @param tls_ctx TLS context
 * @param socket Socket being verified
 * @param user_data User data
 * @return 1 to accept, 0 to reject
 * @note Callback MUST be thread-safe if context is shared across threads.
 */
typedef int (*SocketTLSVerifyCallback) (int preverify_ok,
                                        X509_STORE_CTX *x509_ctx,
                                        T tls_ctx,
                                        Socket_T socket,
                                        void *user_data);

/**
 * @brief Register custom verification callback.
 * @param ctx TLS context
 * @param callback Verify function (NULL to disable)
 * @param user_data User data for callback
 * @throws SocketTLS_Failed on error
 */
extern void
SocketTLSContext_set_verify_callback (T ctx,
                                      SocketTLSVerifyCallback callback,
                                      void *user_data);

/* ============================================================================
 * CRL Support
 * ============================================================================
 */

/**
 * @brief Load CRL file or directory.
 * @param ctx TLS context
 * @param crl_path CRL file or directory
 * @throws SocketTLS_Failed on error
 */
extern void SocketTLSContext_load_crl (T ctx, const char *crl_path);

/** @brief Re-load CRL from path. */
extern void SocketTLSContext_refresh_crl (T ctx, const char *crl_path);

/** @brief Alias for refresh_crl. */
extern void SocketTLSContext_reload_crl (T ctx, const char *crl_path);

/** @brief CRL refresh callback. */
typedef void (*SocketTLSCrlCallback) (T ctx,
                                      const char *path,
                                      int success,
                                      void *user_data);

/**
 * @brief Enable automatic CRL refresh.
 * @param ctx TLS context
 * @param crl_path CRL file path
 * @param interval_seconds Refresh interval (min 60, 0 to disable)
 * @param callback Optional notification callback
 * @param user_data User data for callback
 */
extern void
SocketTLSContext_set_crl_auto_refresh (T ctx,
                                       const char *crl_path,
                                       long interval_seconds,
                                       SocketTLSCrlCallback callback,
                                       void *user_data);

/** @brief Disable automatic CRL refresh. */
extern void SocketTLSContext_cancel_crl_auto_refresh (T ctx);

/** @brief Check and perform CRL refresh if due. Returns 1 if refreshed. */
extern int SocketTLSContext_crl_check_refresh (T ctx);

/** @brief Get ms until next CRL refresh. Returns -1 if disabled. */
extern long SocketTLSContext_crl_next_refresh_ms (T ctx);

/* ============================================================================
 * OCSP Support
 * ============================================================================
 */

/**
 * @brief Set static OCSP response for stapling (server).
 * @param ctx TLS context
 * @param response DER-encoded OCSP response
 * @param len Response length
 */
extern void SocketTLSContext_set_ocsp_response (T ctx,
                                                const unsigned char *response,
                                                size_t len);

/**
 * @brief OCSP response generator callback.
 * @param ssl SSL connection
 * @param arg User data
 * @return Freshly allocated OCSP_RESPONSE (OpenSSL takes ownership), or NULL
 * @note Callback MUST be thread-safe if context is shared.
 */
typedef OCSP_RESPONSE *(*SocketTLSOcspGenCallback) (SSL *ssl, void *arg);

/**
 * @brief Register dynamic OCSP response generator (server).
 * @param ctx TLS context
 * @param cb Generator callback
 * @param arg User data
 */
extern void SocketTLSContext_set_ocsp_gen_callback (T ctx,
                                                    SocketTLSOcspGenCallback cb,
                                                    void *arg);

/**
 * @brief Get OCSP status after handshake (client).
 * @param socket TLS socket
 * @return OCSP status (GOOD=1, REVOKED=2, UNKNOWN=3, NONE=0)
 */
extern int SocketTLS_get_ocsp_status (Socket_T socket);

/** @brief Enable OCSP stapling request (client). */
extern void SocketTLSContext_enable_ocsp_stapling (T ctx);

/** @brief Check if OCSP stapling enabled. */
extern int SocketTLSContext_ocsp_stapling_enabled (T ctx);

/** @brief OCSP Must-Staple mode (RFC 7633). */
typedef enum
{
  OCSP_MUST_STAPLE_DISABLED = 0, /**< Ignore must-staple */
  OCSP_MUST_STAPLE_AUTO = 1,     /**< Check cert for extension */
  OCSP_MUST_STAPLE_ALWAYS = 2    /**< Always require OCSP response */
} OCSPMustStapleMode;

/** @brief Set OCSP Must-Staple mode (client). */
extern void
SocketTLSContext_set_ocsp_must_staple (T ctx, OCSPMustStapleMode mode);

/** @brief Get OCSP Must-Staple mode. */
extern OCSPMustStapleMode SocketTLSContext_get_ocsp_must_staple (T ctx);

/** @brief Check if certificate has must-staple extension. */
extern int SocketTLSContext_cert_has_must_staple (const X509 *cert);

/* ============================================================================
 * Custom Certificate Lookup
 * ============================================================================
 */

/**
 * @brief Certificate lookup callback for HSM/database sources.
 * @param store_ctx OpenSSL store context
 * @param name Subject name to look up
 * @param user_data User data
 * @return X509 certificate (caller takes ownership), or NULL
 * @note Callback MUST be thread-safe if context is shared.
 */
typedef X509 *(*SocketTLSCertLookupCallback) (X509_STORE_CTX *store_ctx,
                                              const X509_NAME *name,
                                              void *user_data);

/**
 * @brief Register certificate lookup callback.
 * @param ctx TLS context
 * @param callback Lookup function (NULL to disable)
 * @param user_data User data
 * @note OpenSSL 3.0+ uses this automatically; <3.0 requires manual invocation.
 */
extern void
SocketTLSContext_set_cert_lookup_callback (T ctx,
                                           SocketTLSCertLookupCallback callback,
                                           void *user_data);

/* ============================================================================
 * Protocol Configuration
 * ============================================================================
 */

/** @brief Set minimum TLS version. */
extern void SocketTLSContext_set_min_protocol (T ctx, int version);

/** @brief Set maximum TLS version. */
extern void SocketTLSContext_set_max_protocol (T ctx, int version);

/** @brief Set cipher list (OpenSSL format). */
extern void SocketTLSContext_set_cipher_list (T ctx, const char *ciphers);

/** @brief Validate cipher list. Returns 1 if valid. */
extern int SocketTLSContext_validate_cipher_list (const char *ciphers);

/** @brief Set TLS 1.3 ciphersuites. */
extern void SocketTLSContext_set_ciphersuites (T ctx, const char *ciphersuites);

/** @brief Validate TLS 1.3 ciphersuites. Returns 1 if valid. */
extern int SocketTLSContext_validate_ciphersuites (const char *ciphersuites);

/* ============================================================================
 * ALPN Support
 * ============================================================================
 */

/**
 * @brief Set ALPN protocols.
 * @param ctx TLS context
 * @param protos Protocol strings (e.g., "h2", "http/1.1")
 * @param count Number of protocols
 */
extern void
SocketTLSContext_set_alpn_protos (T ctx, const char **protos, size_t count);

/** @brief ALPN selection callback. */
typedef const char *(*SocketTLSAlpnCallback) (const char **client_protos,
                                              size_t client_count,
                                              void *user_data);

/** @brief Set custom ALPN selection callback. */
extern void SocketTLSContext_set_alpn_callback (T ctx,
                                                SocketTLSAlpnCallback callback,
                                                void *user_data);

/* ============================================================================
 * Session Management
 * ============================================================================
 */

/**
 * @brief Set session ID context (server).
 * @param ctx TLS context
 * @param context Context bytes
 * @param context_len Length (1-32 bytes)
 */
extern void
SocketTLSContext_set_session_id_context (T ctx,
                                         const unsigned char *context,
                                         size_t context_len);

/**
 * @brief Enable session caching.
 * @param ctx TLS context
 * @param max_sessions Max sessions (0 for default)
 * @param timeout_seconds Timeout (0 for default 300s)
 */
extern void SocketTLSContext_enable_session_cache (T ctx,
                                                   size_t max_sessions,
                                                   long timeout_seconds);

/** @brief Set session cache size. */
extern void SocketTLSContext_set_session_cache_size (T ctx, size_t size);

/** @brief Get session cache statistics. */
extern void SocketTLSContext_get_cache_stats (T ctx,
                                              size_t *hits,
                                              size_t *misses,
                                              size_t *stores);

/**
 * @brief Enable session tickets.
 * @param ctx TLS context
 * @param key Ticket key (SOCKET_TLS_TICKET_KEY_LEN = 80 bytes)
 * @param key_len Key length
 */
extern void SocketTLSContext_enable_session_tickets (T ctx,
                                                     const unsigned char *key,
                                                     size_t key_len);

/** @brief Rotate session ticket key. */
extern void
SocketTLSContext_rotate_session_ticket_key (T ctx,
                                            const unsigned char *new_key,
                                            size_t new_key_len);

/** @brief Check if session tickets enabled. */
extern int SocketTLSContext_session_tickets_enabled (T ctx);

/** @brief Disable session tickets. */
extern void SocketTLSContext_disable_session_tickets (T ctx);

/* ============================================================================
 * Certificate Pinning (SPKI SHA256)
 * ============================================================================
 */

/** @brief Add pin (32-byte SHA256 hash). */
extern void SocketTLSContext_add_pin (T ctx, const unsigned char *sha256_hash);

/** @brief Add pin (64-char hex string, optionally "sha256//" prefixed). */
extern void SocketTLSContext_add_pin_hex (T ctx, const char *hex_hash);

/** @brief Add pin from certificate file. */
extern void SocketTLSContext_add_pin_from_cert (T ctx, const char *cert_file);

/** @brief Add pin from X509 object. */
extern void SocketTLSContext_add_pin_from_x509 (T ctx, const X509 *cert);

/** @brief Remove all pins. */
extern void SocketTLSContext_clear_pins (T ctx);

/** @brief Set pin enforcement (1=strict, 0=warn only). */
extern void SocketTLSContext_set_pin_enforcement (T ctx, int enforce);

/** @brief Get pin enforcement mode. */
extern int SocketTLSContext_get_pin_enforcement (T ctx);

/** @brief Get number of configured pins. */
extern size_t SocketTLSContext_get_pin_count (T ctx);

/** @brief Check if any pins configured. */
extern int SocketTLSContext_has_pins (T ctx);

/** @brief Verify hash against pins. Returns 1 if match. */
extern int
SocketTLSContext_verify_pin (T ctx, const unsigned char *sha256_hash);

/** @brief Verify certificate against pins. Returns 1 if match. */
extern int SocketTLSContext_verify_cert_pin (T ctx, const X509 *cert);

/** @brief Exception for pin verification failure. */
extern const Except_T SocketTLS_PinVerifyFailed;

/* ============================================================================
 * Certificate Transparency (RFC 6962)
 * ============================================================================
 */

/** @brief CT validation mode. */
typedef enum
{
  CT_VALIDATION_PERMISSIVE = 0, /**< Log missing SCTs, don't fail */
  CT_VALIDATION_STRICT = 1      /**< Require valid SCTs */
} CTValidationMode;

/** @brief Enable CT verification (client). */
extern void SocketTLSContext_enable_ct (T ctx, CTValidationMode mode);

/** @brief Check if CT enabled. */
extern int SocketTLSContext_ct_enabled (T ctx);

/** @brief Get CT validation mode. */
extern CTValidationMode SocketTLSContext_get_ct_mode (T ctx);

/** @brief Load custom CT log list. */
extern void SocketTLSContext_set_ctlog_list_file (T ctx, const char *log_file);

/* ============================================================================
 * 0-RTT Early Data Replay Protection
 * ============================================================================
 */

/**
 * @brief Early data replay detection callback.
 * @param ctx TLS context
 * @param session_id Session identifier
 * @param session_id_len Length
 * @param user_data User data
 * @return 1 to accept, 0 to reject (replay detected)
 * @note Callback MUST be thread-safe if context is shared.
 */
typedef int (*SocketTLSEarlyDataReplayCallback) (
    T ctx,
    const unsigned char *session_id,
    size_t session_id_len,
    void *user_data);

/** @brief Register replay protection callback (server). */
extern void SocketTLSContext_set_early_data_replay_callback (
    T ctx, SocketTLSEarlyDataReplayCallback callback, void *user_data);

/** @brief Require replay protection for early data (server). */
extern void SocketTLSContext_require_early_data_replay (T ctx, int require);

/** @brief Check if replay callback registered. */
extern int SocketTLSContext_has_early_data_replay_callback (T ctx);

/** @brief Invoke replay callback. Returns 1 if accepted. */
extern int
SocketTLSContext_check_early_data_replay (T ctx,
                                          const unsigned char *session_id,
                                          size_t session_id_len);

/* ============================================================================
 * Internal Functions
 * ============================================================================
 */

/** @brief Get underlying SSL_CTX*. */
extern void *SocketTLSContext_get_ssl_ctx (T ctx);

/** @brief Check if context is server-mode. */
extern int SocketTLSContext_is_server (T ctx);

/** @} */

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLSCONTEXT_INCLUDED */

/**
 * @defgroup security Security Modules
 * @brief TLS encryption and security protection mechanisms.
 *
 * The Security group provides comprehensive security features including
 * TLS encryption, certificate validation, SYN flood protection, and
 * IP filtering. Key components include:
 * - SocketTLS (tls): TLS/SSL socket integration with TLS 1.3 support
 * - SocketTLSContext (tls-context): TLS context management and certificates
 * - SocketSYNProtect (syn-protect): SYN flood protection
 * - SocketDTLS (dtls): DTLS for UDP sockets with cookie protection
 * - SocketIPTracker (ip-tracker): IP-based rate limiting and filtering
 *
 * @see @ref core_io for socket primitives that can be secured.
 * @see @ref http for TLS integration in HTTP clients/servers.
 * @see SocketTLS_enable() for enabling TLS on sockets.
 * @see SocketDTLS_enable() for DTLS on UDP sockets.
 * @see SocketSYNProtect_T for SYN flood protection.
 * @{
 */

/**
 * @file SocketTLS.h
 * @ingroup security
 * @brief TLS/SSL socket integration with TLS 1.3 support.
 *
 * Features:
 * - TLS1.3-only (strict PFS, no legacy vulns)
 * - Transparent I/O integration
 * - Non-blocking handshake with poll
 * - SNI + hostname verification
 * - ALPN support
 *
 * @see SocketTLS_enable() for enabling TLS on existing sockets.
 * @see @ref SocketTLSContext_T for TLS context management.
 * @see @ref SocketDTLS_T for DTLS support on UDP sockets.
 */

#ifndef SOCKETTLS_INCLUDED
#define SOCKETTLS_INCLUDED

#include "core/Except.h"
#include "socket/Socket.h"

#if SOCKET_HAS_TLS

/**
 * @brief Thread-local error buffer for detailed TLS error messages.
 * @ingroup security
 * @var tls_error_buf
 *
 * Thread-local storage for formatting detailed error messages with OpenSSL
 * error codes and context information. Shared across all TLS implementation
 * files to provide consistent error reporting. Uses thread-local storage
 * to prevent race conditions between threads. Size: SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE.
 *
 * Access via macros like TLS_ERROR_MSG() or directly for custom formatting.
 * Automatically populated by error handling macros (RAISE_TLS_ERROR*).
 *
 * @see RAISE_TLS_ERROR() for raising exceptions with error details
 * @see SocketTLS-private.h for internal TLS error macros
 * @note Thread-local: Each thread has independent buffer; no locking needed.
 */
#ifdef _WIN32
extern __declspec (thread) char tls_error_buf[];
#else
extern __thread char tls_error_buf[];
#endif

#define T SocketTLS_T
typedef struct T *T;

/* ============================================================================
 * Exception Types
 * ============================================================================
 *
 * RETRYABILITY: TLS errors are generally NOT retryable as they indicate
 * configuration issues, certificate problems, or protocol mismatches.
 */

/**
 * @brief General TLS operation failure.
 * @ingroup security
 *
 * Category: PROTOCOL
 * Retryable: NO - Usually indicates configuration or setup error.
 *
 * Used for generic TLS errors not covered by more specific exceptions like handshake or verification failures.
 *
 * @see tls_error_buf for detailed OpenSSL error information.
 * @see Socket_GetLastError() for formatted error string.
 * @see SocketError_categorize_errno() for system error classification.
 */
extern const Except_T SocketTLS_Failed;

/**
 * @brief TLS handshake could not complete.
 * @ingroup security
 *
 * Category: PROTOCOL
 * Retryable: NO - Protocol/version mismatch or server rejection.
 *
 * Raised when the TLS handshake fails due to:
 * - Protocol version mismatch
 * - Cipher suite negotiation failure
 * - Server rejection of connection parameters
 *
 * @see SocketTLS_handshake(), SocketTLS_handshake_loop(), SocketTLS_handshake_auto() for handshake APIs.
 * @see SocketTLS_VerifyFailed for certificate issues during handshake.
 * @see tls_error_buf for OpenSSL-specific error details.
 */
extern const Except_T SocketTLS_HandshakeFailed;

/**
 * @brief Peer certificate verification failure.
 * @ingroup security
 *
 * Category: PROTOCOL
 * Retryable: NO - Certificate validation failure persists on retry.
 *
 * Raised during handshake when peer certificate or chain fails validation:
 * - Expired or not-yet-valid certificate
 * - Invalid signature or malformed chain
 * - Hostname or SNI mismatch
 * - Unknown or untrusted CA
 * - Revocation detected (CRL/OCSP)
 *
 * @see SocketTLS_get_verify_result() for X509 verification error code.
 * @see SocketTLS_get_verify_error_string() for human-readable description.
 * @see SocketTLSContext_set_verify_mode() to configure verification policy.
 * @see SocketTLSContext_load_ca() for CA trust store management.
 */
extern const Except_T SocketTLS_VerifyFailed;

/**
 * @brief TLS protocol violation or internal state error.
 * @ingroup security
 *
 * Category: PROTOCOL
 * Retryable: NO - Indicates malformed messages or desynchronization.
 *
 * Raised for errors in TLS record layer, handshake messages, or application data,
 * such as invalid records, decryption failures, or unexpected alerts.
 *
 * @see SocketTLS_send(), SocketTLS_recv() for I/O functions that can trigger this.
 * @see tls_error_buf for specific protocol alert codes and details.
 * @see SocketTLS_HandshakeFailed for handshake-specific protocol issues.
 */
extern const Except_T SocketTLS_ProtocolError;

/**
 * @brief TLS graceful shutdown failure.
 * @ingroup security
 *
 * Category: PROTOCOL
 * Retryable: NO - Shutdown alert exchange failed; connection may be compromised.
 *
 * Raised when the bidirectional close_notify alert cannot be completed,
 * typically due to peer abrupt disconnect, network errors, or prior protocol issues.
 *
 * @see SocketTLS_shutdown() for performing the shutdown sequence.
 * @see Socket_close() for underlying socket cleanup after shutdown attempt.
 * @see tls_error_buf for low-level error details.
 */
extern const Except_T SocketTLS_ShutdownFailed;

/**
 * @brief TLS handshake state enumeration for non-blocking operations.
 * @ingroup security
 *
 * Returned by SocketTLS_handshake() and related functions to indicate current status
 * and required next action (e.g., poll for READ or WRITE events).
 * Use in event loops: if WANT_READ, add socket to poll for POLL_READ; similarly for WRITE.
 *
 * Values map to OpenSSL's SSL_ERROR_WANT_READ/WRITE and handshake phases.
 *
 * @see SocketTLS_handshake()
 * @see SocketTLS_handshake_loop()
 * @see SocketTLS_handshake_auto()
 * @see @ref event_system for SocketPoll integration.
 * @see SocketPoll_add() to monitor socket during handshake.
 */
typedef enum
{
  TLS_HANDSHAKE_NOT_STARTED = 0,   /**< Handshake not yet initiated */
  TLS_HANDSHAKE_IN_PROGRESS = 1,   /**< Handshake in progress */
  TLS_HANDSHAKE_WANT_READ = 2,     /**< Need to read from socket (data available) */
  TLS_HANDSHAKE_WANT_WRITE = 3,    /**< Need to write to socket (buffer space available) */
  TLS_HANDSHAKE_COMPLETE = 4,      /**< Handshake completed successfully */
  TLS_HANDSHAKE_ERROR = 5          /**< Handshake failed */
} TLSHandshakeState;

/**
 * @brief TLS peer certificate verification mode enumeration.
 * @ingroup security
 *
 * Configures the policy for verifying peer certificates during the TLS handshake.
 * Defaults to TLS_VERIFY_PEER in secure configurations.
 * Values correspond to OpenSSL's SSL_VERIFY_* flags.
 *
 * - TLS_VERIFY_NONE: Disable verification (insecure, use only for testing)
 * - TLS_VERIFY_PEER: Require and verify peer certificate against trust store
 * - TLS_VERIFY_FAIL_IF_NO_PEER_CERT: Fail if no certificate provided by peer
 * - TLS_VERIFY_CLIENT_ONCE: Verify client cert only once per session (server-side optimization)
 *
 * @see SocketTLSContext_set_verify_mode() to set this mode in the context.
 * @see SocketTLS_VerifyFailed raised on verification errors.
 * @see SocketTLSContext_load_ca() for managing trusted CAs.
 * @see docs/SECURITY_GUIDE.md for verification best practices.
 */
typedef enum
{
  TLS_VERIFY_NONE = 0,                    /**< No peer verification (insecure) */
  TLS_VERIFY_PEER = 1,                    /**< Verify peer certificate */
  TLS_VERIFY_FAIL_IF_NO_PEER_CERT = 2,    /**< Fail if no peer cert provided */
  TLS_VERIFY_CLIENT_ONCE = 4              /**< Verify client once per session */
} TLSVerifyMode;

/**
 * @brief Opaque TLS context type for managing certificates, keys, and configuration.
 * @ingroup security
 *
 * Handles OpenSSL SSL_CTX lifecycle, security policies, ALPN protocols,
 * session caching, certificate pinning, CT validation, and more.
 * Created via dedicated functions in SocketTLSContext.h and passed to
 * SocketTLS_enable() to secure sockets.
 *
 * @see SocketTLSContext.h for complete API and creation functions like SocketTLSContext_new_client().
 * @see SocketTLSContext_new_server() for server contexts.
 * @see SocketTLS_enable() to apply context to a socket.
 * @see @ref security "Security Modules" for related protection features.
 */
typedef struct SocketTLSContext_T *SocketTLSContext_T;

/* TLS socket operations */
/**
 * @brief Enable TLS on a socket using the provided context
 * @ingroup security
 * @param socket The socket instance to enable TLS on
 * @param ctx The TLS context to use for this connection
 *
 * Enables TLS/SSL encryption on the specified socket. The socket must be
 * connected before calling this function. Creates an SSL object from the
 * context, associates it with the socket's file descriptor, sets client/server
 * mode, and initializes TLS buffers and state.
 *
 * @return void
 * @throws SocketTLS_Failed if TLS cannot be enabled (e.g., already enabled,
 * invalid socket, context error)
 * @threadsafe No - modifies socket state directly
 *
 * @see Socket_connect() for establishing connections before enabling TLS
 * @see Socket_accept() for accepting connections before enabling TLS
 * @see SocketTLS_handshake() for performing the TLS handshake
 * @see SocketTLSContext_new_client() for creating client contexts
 */
extern void SocketTLS_enable (Socket_T socket, SocketTLSContext_T ctx);

/**
 * @brief Set SNI hostname for client TLS connections
 * @ingroup security
 * @param socket The socket instance
 * @param hostname Null-terminated hostname string for SNI and verification
 *
 * Sets the Server Name Indication (SNI) hostname for the TLS connection. This
 * is required for virtual hosting on servers and enables hostname verification
 * for clients. The hostname is validated and allocated in the socket's arena.
 * Should be called after SocketTLS_enable() but before SocketTLS_handshake().
 *
 * @return void
 * @throws SocketTLS_Failed if TLS not enabled, invalid hostname, or OpenSSL
 * @threadsafe No - modifies socket and SSL state
 */
extern void SocketTLS_set_hostname (Socket_T socket, const char *hostname);

/**
 * @brief Perform non-blocking TLS handshake
 * @ingroup security
 * @param socket The socket instance with TLS enabled
 *
 * Performs one step of the TLS handshake. For non-blocking sockets, this may
 * return WANT_READ or WANT_WRITE indicating more data or writability is
 * needed. Call repeatedly in a poll loop until TLS_HANDSHAKE_COMPLETE is
 * returned.
 *
 * @return TLSHandshakeState indicating progress (COMPLETE, WANT_READ,
 * WANT_WRITE, ERROR)
 * @throws SocketTLS_HandshakeFailed on fatal handshake errors (e.g., protocol
 * mismatch, cert verify fail)
 * @threadsafe No - modifies socket TLS state and SSL object
 *
 * @see SocketPoll_T for event-driven handshake completion
 * @see SocketTLS_handshake_loop() for timeout-based completion
 * @see SocketTLS_handshake_auto() for automatic timeout handling
 */
extern TLSHandshakeState SocketTLS_handshake (Socket_T socket);

/**
 * @brief Complete handshake with timeout (non-blocking)
 * @ingroup security
 * @param socket The socket instance with TLS enabled
 * @param timeout_ms Maximum time to wait for handshake completion (0 for
 * non-blocking)
 *
 * Convenience function to run the handshake loop until complete or timeout.
 * Uses SocketPoll internally for non-blocking operation if timeout > 0.
 *
 * @return TLSHandshakeState (COMPLETE on success, ERROR on failure/timeout)
 * @throws SocketTLS_HandshakeFailed on error or timeout
 * @threadsafe No
 *
 * Note: This is a higher-level helper; low-level code should use
 * SocketTLS_handshake() directly.
 */
extern TLSHandshakeState SocketTLS_handshake_loop (Socket_T socket,
                                                   int timeout_ms);

/**
 * @brief Complete handshake using socket's timeout config
 * @ingroup security
 * @param socket The socket instance with TLS enabled
 *
 * Convenience function that performs a TLS handshake using the socket's
 * configured operation_timeout_ms. If operation_timeout_ms is 0 or not set,
 * uses SOCKET_DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS (30 seconds).
 *
 * This is the recommended function for production code as it automatically
 * uses the socket's timeout configuration, ensuring consistent timeout
 * behavior across the application.
 *
 * @return TLSHandshakeState (COMPLETE on success, ERROR on failure/timeout)
 * @throws SocketTLS_HandshakeFailed on error or timeout
 * @threadsafe No
 */
extern TLSHandshakeState SocketTLS_handshake_auto (Socket_T socket);

/**
 * @brief Perform graceful TLS connection shutdown
 * @ingroup security
 * @param socket The socket instance with TLS enabled
 *
 * Initiates a bidirectional TLS shutdown (close_notify alert). May need
 * multiple calls for full shutdown in non-blocking mode. Call before
 * Socket_close() to ensure proper TLS termination.
 *
 * @return void
 * @throws SocketTLS_ShutdownFailed on error
 * @threadsafe No - modifies SSL object state
 */
extern void SocketTLS_shutdown (Socket_T socket);

/* TLS I/O operations */
/**
 * @brief Send data over TLS-encrypted connection
 * @ingroup security
 * @param socket The socket instance with completed TLS handshake
 * @param buf Buffer containing data to send
 * @param len Number of bytes to send from buf
 *
 * Sends data using SSL_write(). For non-blocking sockets, returns 0 and sets
 * errno=EAGAIN if the operation would block. Handshake must be complete before
 * calling.
 *
 * @return Number of bytes sent, or 0 if would block
 * @throws SocketTLS_Failed on TLS errors, Socket_Closed if connection closed
 * @threadsafe No - modifies SSL buffers and state
 *
 * Note: Does not perform partial sends; application must loop if needed.
 */
extern ssize_t SocketTLS_send (Socket_T socket, const void *buf, size_t len);

/**
 * @brief Receive data from TLS-encrypted connection
 * @ingroup security
 * @param socket The socket instance with completed TLS handshake
 * @param buf Buffer to receive data into
 * @param len Maximum number of bytes to receive
 *
 * Receives data using SSL_read(). For non-blocking sockets, returns 0 and sets
 * errno=EAGAIN if would block. Returns 0 and raises Socket_Closed on clean
 * peer shutdown.
 *
 * @return Number of bytes received, or 0 if would block or EOF
 * @throws SocketTLS_Failed on TLS errors, Socket_Closed on clean shutdown
 * @threadsafe No - modifies SSL buffers and state
 *
 * Note: Application must handle partial reads by looping until desired amount
 * received.
 */
extern ssize_t SocketTLS_recv (Socket_T socket, void *buf, size_t len);

/* TLS information */
/**
 * @brief Get negotiated cipher suite name
 * @ingroup security
 * @param socket The socket instance with completed handshake
 *
 * Returns the name of the cipher suite negotiated during handshake (e.g.,
 * "TLS_AES_256_GCM_SHA384").
 *
 * @return Const string with cipher name, or NULL if unavailable
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake state - reads immutable post-handshake state
 *
 * @see SocketTLS_get_version() for protocol version.
 * @see SocketTLSContext_set_cipher_list() for configuring ciphers.
 * @see docs/SECURITY_GUIDE.md for cipher security recommendations.
 */
extern const char *SocketTLS_get_cipher (Socket_T socket);

/**
 * @brief Get negotiated TLS protocol version
 * @ingroup security
 * @param socket The socket instance with completed handshake
 *
 * Returns the TLS protocol version string (e.g., "TLSv1.3").
 *
 * @return Const string with version, or NULL if unavailable
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake state
 *
 * @see SocketTLS_get_cipher() for negotiated cipher suite.
 * @see SocketTLSContext_set_min_protocol() for minimum version.
 * @see SocketTLSContext_set_max_protocol() for maximum version.
 */
extern const char *SocketTLS_get_version (Socket_T socket);

/**
 * @brief Get peer certificate verification result
 * @ingroup security
 * @param socket The socket instance with completed handshake
 *
 * Returns OpenSSL's X509 verify result code. 0 (X509_V_OK) indicates
 * successful verification. Non-zero codes detail failures (e.g., untrusted
 * CA).
 *
 * @return long verify result code (X509_V_OK = 0 on success)
 * @throws None (caller checks and may raise SocketTLS_VerifyFailed)
 * @threadsafe Yes - reads immutable post-handshake state (read-only post-handshake)
 *
 * @see SocketTLS_VerifyFailed exception for handling verification failures.
 * @see SocketTLS_get_verify_error_string() for detailed error description.
 * @see SocketTLSContext_set_verify_mode() to configure verification policy.
 * @see X509_verify_cert_error_string() for OpenSSL error code meanings.
 *
 * Requires: tls_enabled and tls_handshake_done
 */
extern long SocketTLS_get_verify_result (Socket_T socket);

/**
 * @brief Get detailed verification error string
 * @ingroup security
 * @param socket TLS socket
 * @param buf Output buffer for error description
 * @param size Buffer size (including null terminator)
 *
 * Provides human-readable string for the last verification error (from
 * CRL/OCSP/custom verify). Uses X509_verify_cert_error_string or OpenSSL ERR
 * queue.
 *
 * @return buf if error found, NULL if no error or invalid args
 * @throws None
 * @threadsafe No (ERR queue shared)
 *
 * @see SocketTLS_get_verify_result() for the numeric error code.
 * @see SocketTLS_VerifyFailed for when verification fails.
 * @see ERR_get_error() for accessing OpenSSL error queue directly.
 *
 * Requires: tls_handshake_done
 */
extern const char *SocketTLS_get_verify_error_string (Socket_T socket,
                                                      char *buf, size_t size);

/**
 * @brief Check if TLS session was resumed
 * @ingroup security
 * @param socket The socket instance with completed handshake
 *
 * Determines if the connection used a resumed session (faster handshake via
 * session tickets/cache).
 *
 * @return 1 if reused, 0 if full handshake, -1 if unavailable
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake state
 *
 * @see SocketTLSContext_enable_session_cache() for enabling session caching.
 * @see SocketTLSContext_enable_session_tickets() for ticket-based resumption.
 * @see SocketTLSContext_get_cache_stats() for monitoring cache performance.
 * @see docs/SECURITY_GUIDE.md for session resumption security considerations.
 */
extern int SocketTLS_is_session_reused (Socket_T socket);

/**
 * @brief Get the negotiated ALPN protocol
 * @ingroup security
 * @param socket Socket instance with completed handshake
 *
 * Returns the ALPN protocol that was negotiated during the TLS handshake.
 * This is useful for determining which application protocol to use (e.g.,
 * "h2", "http/1.1").
 *
 * @return Negotiated protocol string, or NULL if none negotiated or
 * unavailable
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake state - reads immutable post-handshake state
 *
 * @see SocketTLSContext_set_alpn_protos() for advertising supported protocols.
 * @see SocketTLSContext_set_alpn_callback() for custom protocol selection.
 * @see @ref http for examples like "h2" (HTTP/2) and "http/1.1".
 */
extern const char *SocketTLS_get_alpn_selected (Socket_T socket);

#undef T

/** @} */ /* end of security group */

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLS_INCLUDED */

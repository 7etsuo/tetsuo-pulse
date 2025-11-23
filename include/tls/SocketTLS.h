/**
 * SocketTLS.h - TLS/SSL Socket Integration (TLS1.3-Only by Default)
 *
 * Features:
 * - TLS1.3-only (strict PFS, no legacy vulns)
 * - Transparent I/O integration
 * - Non-blocking handshake with poll
 * - SNI + hostname verification
 * - ALPN support
 */

#ifndef SOCKETTLS_INCLUDED
#define SOCKETTLS_INCLUDED

#include "core/Except.h"
#include "socket/Socket.h"

#ifdef SOCKET_HAS_TLS

/* TLS error buffer for cross-module error reporting */
#ifdef _WIN32
extern __declspec (thread) char tls_error_buf[];
#else
extern __thread char tls_error_buf[];
#endif

#define T SocketTLS_T
typedef struct T *T;

/* TLS-specific exception types */
extern const Except_T SocketTLS_Failed;          /* General TLS operation failure */
extern const Except_T SocketTLS_HandshakeFailed; /* TLS handshake failure */
extern const Except_T SocketTLS_VerifyFailed;  /* Certificate verification failure */
extern const Except_T SocketTLS_ProtocolError; /* TLS protocol error */
extern const Except_T SocketTLS_ShutdownFailed; /* TLS shutdown failure */

/* TLS handshake state (for polling/integration) */
typedef enum
{
  TLS_HANDSHAKE_NOT_STARTED = 0,
  TLS_HANDSHAKE_IN_PROGRESS = 1,
  TLS_HANDSHAKE_WANT_READ = 2,
  TLS_HANDSHAKE_WANT_WRITE = 3,
  TLS_HANDSHAKE_COMPLETE = 4,
  TLS_HANDSHAKE_ERROR = 5
} TLSHandshakeState;

/* TLS verification mode */
typedef enum
{
  TLS_VERIFY_NONE = 0,
  TLS_VERIFY_PEER = 1,
  TLS_VERIFY_FAIL_IF_NO_PEER_CERT = 2,
  TLS_VERIFY_CLIENT_ONCE = 4
} TLSVerifyMode;

/* Forward declaration to avoid circular dependency */
typedef struct SocketTLSContext_T *SocketTLSContext_T;

/* TLS socket operations */
/**
 * SocketTLS_enable - Enable TLS on a socket using the provided context
 * @socket: The socket instance to enable TLS on
 * @ctx: The TLS context to use for this connection
 *
 * Enables TLS/SSL encryption on the specified socket. The socket must be
 * connected before calling this function. Creates an SSL object from the
 * context, associates it with the socket's file descriptor, sets client/server
 * mode, and initializes TLS buffers and state.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if TLS cannot be enabled (e.g., already enabled,
 * invalid socket, context error) Thread-safe: No - modifies socket state
 * directly
 *
 * Usage note: Call after Socket_connect() or Socket_accept() but before any
 * TLS I/O. The handshake must be performed separately using
 * SocketTLS_handshake().
 */
extern void SocketTLS_enable (Socket_T socket, SocketTLSContext_T ctx);

/**
 * SocketTLS_set_hostname - Set SNI hostname for client TLS connections
 * @socket: The socket instance
 * @hostname: Null-terminated hostname string for SNI and verification
 *
 * Sets the Server Name Indication (SNI) hostname for the TLS connection. This
 * is required for virtual hosting on servers and enables hostname verification
 * for clients. The hostname is validated and allocated in the socket's arena.
 * Should be called after SocketTLS_enable() but before SocketTLS_handshake().
 *
 * Returns: void
 * Raises: SocketTLS_Failed if TLS not enabled, invalid hostname, or OpenSSL
 * error Thread-safe: No - modifies socket and SSL state
 */
extern void SocketTLS_set_hostname (Socket_T socket, const char *hostname);

/**
 * SocketTLS_handshake - Perform non-blocking TLS handshake
 * @socket: The socket instance with TLS enabled
 *
 * Performs one step of the TLS handshake. For non-blocking sockets, this may
 * return WANT_READ or WANT_WRITE indicating more data or writability is
 * needed. Call repeatedly in a poll loop until TLS_HANDSHAKE_COMPLETE is
 * returned.
 *
 * Returns: TLSHandshakeState indicating progress (COMPLETE, WANT_READ,
 * WANT_WRITE, ERROR) Raises: SocketTLS_HandshakeFailed on fatal handshake
 * errors (e.g., protocol mismatch, cert verify fail) Thread-safe: No -
 * modifies socket TLS state and SSL object
 *
 * Note: Integrates with SocketPoll by checking tls_last_handshake_state for
 * pending I/O.
 */
extern TLSHandshakeState SocketTLS_handshake (Socket_T socket);

/**
 * SocketTLS_handshake_loop - Complete handshake with timeout (non-blocking)
 * @socket: The socket instance with TLS enabled
 * @timeout_ms: Maximum time to wait for handshake completion (0 for
 * non-blocking)
 *
 * Convenience function to run the handshake loop until complete or timeout.
 * Uses SocketPoll internally for non-blocking operation if timeout > 0.
 *
 * Returns: TLSHandshakeState (COMPLETE on success, ERROR on failure/timeout)
 * Raises: SocketTLS_HandshakeFailed on error or timeout
 * Thread-safe: No
 *
 * Note: This is a higher-level helper; low-level code should use
 * SocketTLS_handshake() directly.
 */
extern TLSHandshakeState SocketTLS_handshake_loop (Socket_T socket,
                                                   int timeout_ms);

/**
 * SocketTLS_shutdown - Perform graceful TLS connection shutdown
 * @socket: The socket instance with TLS enabled
 *
 * Initiates a bidirectional TLS shutdown (close_notify alert). May need
 * multiple calls for full shutdown in non-blocking mode. Call before
 * Socket_close() to ensure proper TLS termination.
 *
 * Returns: void
 * Raises: SocketTLS_ShutdownFailed on error
 * Thread-safe: No - modifies SSL object state
 */
extern void SocketTLS_shutdown (Socket_T socket);

/* TLS I/O operations */
/**
 * SocketTLS_send - Send data over TLS-encrypted connection
 * @socket: The socket instance with completed TLS handshake
 * @buf: Buffer containing data to send
 * @len: Number of bytes to send from buf
 *
 * Sends data using SSL_write(). For non-blocking sockets, returns 0 and sets
 * errno=EAGAIN if the operation would block. Handshake must be complete before
 * calling.
 *
 * Returns: Number of bytes sent, or 0 if would block
 * Raises: SocketTLS_Failed on TLS errors, Socket_Closed if connection closed
 * Thread-safe: No - modifies SSL buffers and state
 *
 * Note: Does not perform partial sends; application must loop if needed.
 */
extern ssize_t SocketTLS_send (Socket_T socket, const void *buf, size_t len);

/**
 * SocketTLS_recv - Receive data from TLS-encrypted connection
 * @socket: The socket instance with completed TLS handshake
 * @buf: Buffer to receive data into
 * @len: Maximum number of bytes to receive
 *
 * Receives data using SSL_read(). For non-blocking sockets, returns 0 and sets
 * errno=EAGAIN if would block. Returns 0 and raises Socket_Closed on clean
 * peer shutdown.
 *
 * Returns: Number of bytes received, or 0 if would block or EOF
 * Raises: SocketTLS_Failed on TLS errors, Socket_Closed on clean shutdown
 * Thread-safe: No - modifies SSL buffers and state
 *
 * Note: Application must handle partial reads by looping until desired amount
 * received.
 */
extern ssize_t SocketTLS_recv (Socket_T socket, void *buf, size_t len);

/* TLS information */
/**
 * SocketTLS_get_cipher - Get negotiated cipher suite name
 * @socket: The socket instance with completed handshake
 *
 * Returns the name of the cipher suite negotiated during handshake (e.g.,
 * "TLS_AES_256_GCM_SHA384").
 *
 * Returns: Const string with cipher name, or NULL if unavailable
 * Raises: None
 * Thread-safe: Yes - reads immutable post-handshake state
 */
extern const char *SocketTLS_get_cipher (Socket_T socket);

/**
 * SocketTLS_get_version - Get negotiated TLS protocol version
 * @socket: The socket instance with completed handshake
 *
 * Returns the TLS protocol version string (e.g., "TLSv1.3").
 *
 * Returns: Const string with version, or NULL if unavailable
 * Raises: None
 * Thread-safe: Yes
 */
extern const char *SocketTLS_get_version (Socket_T socket);

/**
 * SocketTLS_get_verify_result - Get peer certificate verification result
 * @socket: The socket instance with completed handshake
 *
 * Returns OpenSSL's X509 verify result code. 0 (X509_V_OK) indicates
 * successful verification. Non-zero codes detail failures (e.g., untrusted CA).
 *
 * Returns: long verify result code (X509_V_OK = 0 on success)
 * Raises: None (caller checks and may raise SocketTLS_VerifyFailed)
 * Thread-safe: Yes (read-only post-handshake)
 * Requires: tls_enabled and tls_handshake_done
 */
extern long SocketTLS_get_verify_result (Socket_T socket);

/**
 * SocketTLS_is_session_reused - Check if TLS session was resumed
 * @socket: The socket instance with completed handshake
 *
 * Determines if the connection used a resumed session (faster handshake via
 * session tickets/cache).
 *
 * Returns: 1 if reused, 0 if full handshake, -1 if unavailable
 * Raises: None
 * Thread-safe: Yes
 */
extern int SocketTLS_is_session_reused (Socket_T socket);

/**
 * SocketTLS_get_alpn_selected - Get the negotiated ALPN protocol
 * @socket: Socket instance with completed handshake
 *
 * Returns the ALPN protocol that was negotiated during the TLS handshake.
 * This is useful for determining which application protocol to use (e.g.,
 * "h2", "http/1.1").
 *
 * Returns: Negotiated protocol string, or NULL if none negotiated or
 * unavailable Raises: None Thread-safe: Yes - reads immutable post-handshake
 * state
 */
extern const char *SocketTLS_get_alpn_selected (Socket_T socket);

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLS_INCLUDED */

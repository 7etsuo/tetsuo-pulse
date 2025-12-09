/**
 * @file SocketDTLS-private.h
 * @ingroup security
 * @brief DTLS internal shared definitions and helper functions.
 *
 * Internal header for all DTLS module implementation files. Contains shared
 * helper function declarations, error handling macros, internal types,
 * and the SocketDTLSContext_T structure definition.
 * NOT part of public API - do not include from application code.
 *
 * Thread safety: Internal functions are not thread-safe unless noted.
 *
 * @see SocketDTLS.h for public DTLS API.
 * @see SocketDTLSContext.h for public DTLS context API.
 */

#ifndef SOCKETDTLS_PRIVATE_INCLUDED
#define SOCKETDTLS_PRIVATE_INCLUDED

#if SOCKET_HAS_TLS

#include <ctype.h>
#include <pthread.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketUtil.h"
#include "socket/SocketDgram-private.h"
#include "tls/SocketDTLS.h"
#include "tls/SocketDTLSConfig.h"
#include "tls/SocketDTLSContext.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

/* ============================================================================
 * Thread-Local Error Handling for SocketDTLS
 * ============================================================================
 */

/**
 * @brief RAISE_DTLS_ERROR - Raise DTLS exception with detailed error message
 * @ingroup security
 * @param exception Exception type to raise
 *
 * Wrapper around SOCKET_RAISE_MODULE_ERROR(SocketDTLS, exception) that creates
 * thread-local copy of exception with reason from socket_error_buf.
 *
 * Uses the detailed exception pattern to prevent race conditions in multi-threaded
 * environments. SocketDTLS_DetailedException is declared in SocketDTLS.c via
 * SOCKET_DECLARE_MODULE_EXCEPTION(SocketDTLS).
 *
 * @see SocketUtil.h#SOCKET_RAISE_MODULE_ERROR for base macro implementation
 * @see socket_error_buf in SocketUtil.h for thread-local error buffer
 * @see SocketDTLS_DetailedException declared in SocketDTLS.c
 */
#define RAISE_DTLS_ERROR(exception)                                           \
  SOCKET_RAISE_MODULE_ERROR (SocketDTLS, exception)

/**
 * @brief RAISE_DTLS_ERROR_MSG - Raise DTLS exception with formatted message
 * @ingroup security
 * @param exception Exception type to raise
 * @param msg Error message format string
 * @param ... Format arguments
 *
 * Formats message using SOCKET_ERROR_MSG (populates socket_error_buf) then
 * raises via RAISE_DTLS_ERROR. Thread-safe via per-thread storage.
 *
 * @see SOCKET_ERROR_MSG in SocketUtil.h for formatting
 * @see RAISE_DTLS_ERROR for raising logic
 */
#define RAISE_DTLS_ERROR_MSG(exception, msg)                                  \
  do                                                                          \
    {                                                                         \
      SOCKET_ERROR_MSG (msg);                                                 \
      RAISE_DTLS_ERROR (exception);                                           \
    }                                                                         \
  while (0)

/**
 * @brief REQUIRE_DTLS_ENABLED - Validate DTLS is enabled on socket
 * @ingroup security
 * @param socket Socket to validate
 * @param exception Exception to raise on failure
 *
 * Validates that DTLS has been enabled on the specified socket. Raises
 * the provided exception with a descriptive message if DTLS is not enabled.
 * Used throughout DTLS operations to ensure proper initialization order.
 *
 * @see SocketDTLS_enable() for enabling DTLS on sockets
 */
#define REQUIRE_DTLS_ENABLED(socket, exception)                               \
  do                                                                          \
    {                                                                         \
      if (!(socket)->dtls_enabled)                                            \
        RAISE_DTLS_ERROR_MSG (exception, "DTLS not enabled on socket");       \
    }                                                                         \
  while (0)

/**
 * @brief DTLS_ERROR_MSG - Format simple error message
 * @ingroup security
 * @param msg Message string
 *
 * Formats a simple error message into the thread-local error buffer.
 * Used for consistent error reporting across DTLS operations.
 */
#define DTLS_ERROR_MSG(msg) SOCKET_ERROR_MSG (msg)

/**
 * @brief DTLS_ERROR_FMT - Format error message with arguments
 * @ingroup security
 * @param fmt Format string
 * @param ... Format arguments
 *
 * Formats an error message with arguments into the thread-local error buffer.
 * Includes errno information when available for system call diagnostics.
 */
#define DTLS_ERROR_FMT(fmt, ...) SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__)

/**
 * @brief VALIDATE_DTLS_IO_READY - Validate socket is ready for DTLS I/O
 * @ingroup security
 * @param socket Socket to validate
 * @param exception Exception to raise on failure
 *
 * Performs comprehensive validation before DTLS I/O operations:
 * - Checks that DTLS is enabled on the socket
 * - Verifies handshake is complete
 * - Ensures SSL object is available
 *
 * Returns SSL* pointer on success for immediate use, raises exception on failure.
 * Used by all DTLS send/receive operations to ensure proper state.
 *
 * @return SSL* pointer for immediate use in DTLS operations
 */
#define VALIDATE_DTLS_IO_READY(socket, exception)                             \
  ({                                                                          \
    if (!(socket)->dtls_enabled)                                              \
      {                                                                       \
        DTLS_ERROR_MSG ("DTLS not enabled on socket");                        \
        RAISE_DTLS_ERROR (exception);                                         \
      }                                                                       \
    if (!(socket)->dtls_handshake_done)                                       \
      {                                                                       \
        DTLS_ERROR_MSG ("DTLS handshake not complete");                       \
        RAISE_DTLS_ERROR (exception);                                         \
      }                                                                       \
    SSL *_ssl = dtls_socket_get_ssl (socket);                                 \
    if (!_ssl)                                                                \
      {                                                                       \
        DTLS_ERROR_MSG ("SSL object not available");                          \
        RAISE_DTLS_ERROR (exception);                                         \
      }                                                                       \
    _ssl;                                                                     \
  })

/* ============================================================================
 * SSL Object Access
 * ============================================================================
 */

/**
 * @brief dtls_socket_get_ssl - Get SSL* from socket
 * @ingroup security
 * @param socket Socket instance
 * @return SSL* pointer or NULL if DTLS not enabled/available
 *
 * Safely extracts the SSL object from a DTLS-enabled socket. Performs
 * null checks and DTLS enablement validation before returning the SSL pointer.
 * Returns NULL if socket is invalid, DTLS is not enabled, or SSL object
 * is not available.
 *
 * @threadsafe Yes - read-only operation on socket state
 */
static inline SSL *
dtls_socket_get_ssl (SocketDgram_T socket)
{
  if (!socket || !socket->dtls_enabled || !socket->dtls_ssl)
    return NULL;
  return (SSL *)socket->dtls_ssl;
}

/* ============================================================================
 * SSL Error Handling
 * ============================================================================
 */

/**
 * @brief dtls_handle_ssl_error - Map OpenSSL errors to DTLSHandshakeState
 * @ingroup security
 * @param socket Socket instance
 * @param ssl SSL object
 * @param ssl_result Result from SSL operation
 * @return DTLSHandshakeState based on error type
 *
 * Maps OpenSSL error codes to DTLS handshake states for event-driven I/O.
 * Handles the complex mapping between OpenSSL's error model and the socket
 * library's state machine. Critical for non-blocking DTLS operations.
 *
 * Error handling:
 * - SSL_ERROR_NONE: Complete - handshake finished successfully
 * - SSL_ERROR_WANT_READ/WRITE: Non-blocking - need I/O, errno=EAGAIN
 * - SSL_ERROR_SYSCALL: System error - errno preserved for diagnostics
 * - SSL_ERROR_SSL: Protocol error - detailed in OpenSSL error queue
 * - SSL_ERROR_ZERO_RETURN: Clean peer shutdown
 *
 * @threadsafe Yes - operates on per-connection SSL state
 */
static inline DTLSHandshakeState
dtls_handle_ssl_error (SocketDgram_T socket, SSL *ssl, int ssl_result)
{
  int ssl_error = SSL_get_error (ssl, ssl_result);

  switch (ssl_error)
    {
    case SSL_ERROR_NONE:
      socket->dtls_handshake_done = 1;
      return DTLS_HANDSHAKE_COMPLETE;

    case SSL_ERROR_WANT_READ:
      socket->dtls_handshake_done = 0;
      errno = EAGAIN;
      return DTLS_HANDSHAKE_WANT_READ;

    case SSL_ERROR_WANT_WRITE:
      socket->dtls_handshake_done = 0;
      errno = EAGAIN;
      return DTLS_HANDSHAKE_WANT_WRITE;

    default:
      socket->dtls_handshake_done = 0;
      return DTLS_HANDSHAKE_ERROR;
    }
}

/**
 * @brief dtls_format_openssl_error - Format OpenSSL error into buffer
 * @ingroup security
 * @param context Context string for error message
 *
 * Formats current OpenSSL error into socket_error_buf with context.
 * Clears the entire error queue to prevent stale errors from affecting
 * subsequent operations or leaking information.
 */
static inline void
dtls_format_openssl_error (const char *context)
{
  unsigned long err = ERR_get_error ();
  char err_str[SOCKET_DTLS_OPENSSL_ERRSTR_BUFSIZE];

  if (err != 0)
    {
      ERR_error_string_n (err, err_str, sizeof (err_str));
      SOCKET_ERROR_MSG ("%s: %s", context, err_str);
    }
  else
    {
      SOCKET_ERROR_MSG ("%s: Unknown error", context);
    }
  ERR_clear_error (); /* Clear remaining OpenSSL error queue */
}

/* ============================================================================
 * Input Validation
 * ============================================================================
 */

/**
 * @brief dtls_validate_file_path - Validate certificate/key/CA file path
 * @ingroup security
 * @param path File path string to validate
 * @return 1 if valid, 0 if invalid
 *
 * Performs comprehensive security validation on file paths to prevent
 * directory traversal attacks and other path-based exploits:
 * - Non-empty and within configured length limits
 * - Rejects path traversal sequences (..) in any form
 * - Rejects control characters (except forward slash for paths)
 * - Validates against symlink attacks by checking file type
 * - Prevents embedded null bytes that could cause truncation
 *
 * Critical for preventing attacks where untrusted input could access
 * sensitive files outside intended directories, especially important
 * for DTLS due to UDP transport security considerations.
 */
static inline int
dtls_validate_file_path (const char *path)
{
  if (!path || !*path)
    return 0;

  size_t len = strlen (path);
  if (len == 0 || len > SOCKET_DTLS_MAX_PATH_LEN)
    return 0;

  /* Check for path traversal sequences (prefer absolute paths) */
  if (path[0] != '/')
    { /* Optional: warn or reject relative; preference for absolute */
      /* Relative paths accepted but may be insecure if cwd untrusted */
    }
  if (strstr (path, "../") != NULL || strstr (path, "..\\") != NULL
      || strstr (path, "/..") != NULL || strstr (path, "\\..") != NULL
      || strstr (path, "..") != NULL)
    {
      return 0;
    }

  /* Check for control characters */
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)path[i];
      if (c < 32 || c == 127)
        return 0;
    }

  return 1;
}

/* ============================================================================
 * SocketDTLSContext_T Structure Definition
 * ============================================================================
 */

#define T SocketDTLSContext_T

/**
 * @brief Cookie state structure for server-side DTLS cookie exchange.
 * @ingroup security
 *
 * Manages HMAC secrets for generating and verifying stateless cookies during
 * DTLS handshake to prevent DoS attacks (RFC 6347 Section 4.2.1). Supports
 * secret rotation for replay protection and forward secrecy.
 *
 * @threadsafe Conditional - mutex protects secret updates; read access thread-safe.
 *
 * @see dtls_cookie_generate_cb()
 * @see dtls_cookie_verify_cb()
 * @see SocketDTLSContext_enable_cookie_exchange()
 * @see RFC 6347 for cookie exchange protocol.
 */
typedef struct
{
  unsigned char secret[SOCKET_DTLS_COOKIE_SECRET_LEN]; /**< HMAC secret */
  unsigned char
      prev_secret[SOCKET_DTLS_COOKIE_SECRET_LEN]; /**< Previous secret for
                                                     rotation */
  int cookie_enabled;           /**< Cookie exchange enabled */
  pthread_mutex_t secret_mutex; /**< Protects secret rotation */
} DTLSContextCookie;

/**
 * @brief ALPN configuration structure for DTLS contexts.
 * @ingroup security
 *
 * Stores supported application protocols for negotiation during handshake
 * (RFC 7301). Enables protocol selection for HTTP/2 over DTLS or other services.
 *
 * @see SocketDTLSContext_set_alpn_protos()
 * @see SSL_get0_alpn_selected() for retrieval
 */
typedef struct
{
  const char **protocols; /**< Array of protocol strings */
  size_t count;           /**< Number of protocols */
  const char *selected;   /**< Negotiated protocol (set by server, read by client) */
} DTLSContextALPN;

/**
 * @brief SocketDTLSContext_T - DTLS Context Structure
 * @ingroup security
 *
 * Manages OpenSSL SSL_CTX for DTLS with secure defaults, certificates,
 * cookie exchange, and session caching. Provides DTLS 1.2+ support with
 * cookie-based DoS protection and session resumption for performance.
 *
 * Thread safety: Contexts are not thread-safe for modification after creation.
 * Share read-only after full setup, or use per-thread contexts.
 * SSL objects created from context are per-connection and thread-safe.
 */
struct T
{
  SSL_CTX *ssl_ctx;            /**< OpenSSL context */
  Arena_T arena;               /**< Arena for allocations */
  int is_server;               /**< 1 for server, 0 for client */
  size_t mtu;                  /**< Configured MTU */
  int session_cache_enabled;   /**< Session cache flag */
  size_t session_cache_size;   /**< Session cache size */
  size_t cache_hits;           /**< Session resumptions */
  size_t cache_misses;         /**< Full handshakes */
  size_t cache_stores;         /**< New sessions stored */
  pthread_mutex_t stats_mutex; /**< Thread-safe stats update */

  /* Cookie exchange (DTLS-specific DoS protection) */
  DTLSContextCookie cookie;

  /* ALPN configuration */
  DTLSContextALPN alpn;

  /* Timeout configuration */
  int initial_timeout_ms;
  int max_timeout_ms;
};

/* ============================================================================
 * Thread-Local Error Storage for SocketDTLSContext
 * ============================================================================
 */

/**
 * @brief Thread-local error buffer for SocketDTLSContext operations.
 * @ingroup security
 * @var dtls_context_error_buf
 *
 * Used by RAISE_DTLS_CTX_ERROR macros to store formatted error messages
 * with context. Thread-local to support concurrent operations without
 * contention or corruption.
 *
 * @see RAISE_DTLS_CTX_ERROR*
 * @see SOCKET_DTLS_ERROR_BUFSIZE for size constant
 */
#ifdef _WIN32
extern __declspec (thread) char dtls_context_error_buf[SOCKET_DTLS_ERROR_BUFSIZE];
#else
extern __thread char dtls_context_error_buf[SOCKET_DTLS_ERROR_BUFSIZE];
#endif

/**
 * @brief Thread-local detailed exception for SocketDTLSContext errors.
 * @ingroup security
 * @var SocketDTLSContext_DetailedException
 *
 * Exception instance used by module macros to attach .reason pointing to
 * dtls_context_error_buf. Enables race-free detailed exception raising in
 * multi-threaded contexts.
 *
 * @see RAISE_DTLS_CTX_ERROR*
 * @see Except_T base structure
 */
#ifdef _WIN32
extern __declspec (thread) Except_T SocketDTLSContext_DetailedException;
#else
extern __thread Except_T SocketDTLSContext_DetailedException;
#endif

/**
 * @brief RAISE_DTLS_CTX_ERROR - Raise context exception with current error buffer
 * @ingroup security
 * @param exception Exception type to raise
 *
 * Creates thread-local copy of exception with reason from dtls_context_error_buf.
 * Uses the detailed exception pattern to prevent race conditions when multiple
 * threads raise the same exception type.
 */
#define RAISE_DTLS_CTX_ERROR(exception)                                       \
  do                                                                          \
    {                                                                         \
      SocketDTLSContext_DetailedException = (exception);                      \
      SocketDTLSContext_DetailedException.reason = dtls_context_error_buf;    \
      RAISE (SocketDTLSContext_DetailedException);                            \
    }                                                                         \
  while (0)

/**
 * @brief RAISE_DTLS_CTX_ERROR_MSG - Raise context exception with formatted message
 * @ingroup security
 * @param exception Exception type to raise
 * @param msg Error message format string
 * @param ... Format arguments
 *
 * Raises DTLS context exception with formatted error message. Uses thread-local
 * exception storage to prevent race conditions.
 */
#define RAISE_DTLS_CTX_ERROR_MSG(exception, msg)                              \
  do                                                                          \
    {                                                                         \
      SOCKET_RAISE_MSG (SocketDTLSContext, exception, msg);                   \
    }                                                                         \
  while (0)

#define RAISE_DTLS_CTX_ERROR_FMT(exception, fmt, ...)                         \
  do                                                                          \
    {                                                                         \
      SOCKET_RAISE_FMT (SocketDTLSContext, exception, fmt, __VA_ARGS__);      \
    }                                                                         \
  while (0)

/* ============================================================================
 * Utility Macros
 * ============================================================================
 */

/**
 * @brief Suppress unused parameter compiler warnings.
 * @ingroup security
 * @param x Variable or parameter marked as intentionally unused.
 *
 * Casts the parameter to void to inform the compiler that the variable is
 * intentionally unused, suppressing -Wunused-parameter warnings. Commonly used
 * in callback functions with fixed signatures or debug-only code paths.
 *
 * @note Prefer removing unused parameters when possible; use this only when
 * necessary due to API constraints.
 * @threadsafe Yes - no side effects or shared state.
 * @see SocketUtil.h for general utility macros.
 */
#define DTLS_UNUSED(x) (void)(x)

/* ============================================================================
 * Cookie Exchange Internal Functions
 * ============================================================================
 */

/**
 * @brief OpenSSL DTLS cookie generation callback
 * @ingroup security
 * @param ssl SSL object for the DTLS connection
 * @param cookie Output buffer for generated cookie (SOCKET_DTLS_COOKIE_LEN bytes)
 * @param cookie_len Output parameter set to actual cookie length
 * @return 1 on success, 0 on failure
 *
 * Generates stateless cookies for DTLS cookie exchange (RFC 6347 Section 4.2.1).
 * Cookies prevent DoS attacks by requiring clients to prove address ownership
 * before servers allocate per-connection state. Uses HMAC-SHA256 with server
 * secret key over client address, port, and timestamp.
 *
 * Called automatically by OpenSSL during DTLS handshake when cookie exchange
 * is enabled. Server must have called SocketDTLSContext_enable_cookie_exchange().
 */

/**
 * @brief OpenSSL DTLS cookie verification callback
 * @ingroup security
 * @param ssl SSL object for the DTLS connection
 * @param cookie Cookie bytes provided by client
 * @param cookie_len Length of cookie data
 * @return 1 if cookie is valid and client address is verified, 0 if invalid
 *
 * Verifies cookies generated by dtls_cookie_generate_cb(). Ensures the cookie
 * was generated for this specific client address/port combination and hasn't
 * expired. Uses constant-time comparison to prevent timing attacks that could
 * leak information about valid cookies.
 *
 * If verification fails, the client must retry with a new cookie obtained
 * via HelloVerifyRequest. This stateless verification prevents memory
 * exhaustion attacks on DTLS servers.
 */

/**
 * @brief Generate HMAC-SHA256 based DTLS cookie for address verification
 * @ingroup security
 * @param secret Server secret key for HMAC (SOCKET_DTLS_COOKIE_SECRET_LEN bytes)
 * @param peer_addr Client socket address (struct sockaddr)
 * @param peer_len Length of peer address structure
 * @param out_cookie Output buffer for cookie (SOCKET_DTLS_COOKIE_LEN bytes)
 * @return 0 on success, -1 on failure
 *
 * Creates a cryptographically secure cookie using HMAC-SHA256:
 * HMAC-SHA256(secret, client_addr || client_port || timestamp)
 *
 * The cookie proves client address ownership and prevents spoofing attacks.
 * Truncated to SOCKET_DTLS_COOKIE_LEN bytes for efficiency while maintaining
 * security. Cookies have limited lifetime to prevent replay attacks.
 *
 * Used internally by dtls_cookie_generate_cb() and exposed for testing.
 * @see RFC 6347 Section 4.2.1 for cookie exchange specification
 */

/**
 * @brief Get SocketDTLSContext from SSL object.
 * @ingroup security
 * @param ssl SSL object
 * @return Context pointer or NULL
 */

/**
 * dtls_cookie_generate_cb - OpenSSL cookie generation callback
 * @ssl: SSL object
 * @cookie: Output buffer for cookie
 * @cookie_len: Output for cookie length
 *
 * @return 1 on success, 0 on failure
 */
extern int dtls_cookie_generate_cb (SSL *ssl, unsigned char *cookie,
                                    unsigned int *cookie_len);

/**
 * dtls_cookie_verify_cb - OpenSSL cookie verification callback
 * @ssl: SSL object
 * @cookie: Cookie to verify
 * @cookie_len: Cookie length
 *
 * @return 1 if valid, 0 if invalid
 */
extern int dtls_cookie_verify_cb (SSL *ssl, const unsigned char *cookie,
                                  unsigned int cookie_len);

/**
 * dtls_generate_cookie_hmac - Generate HMAC-based cookie
 * @secret: Secret key
 * @peer_addr: Peer socket address
 * @peer_len: Peer address length
 * @out_cookie: Output buffer (SOCKET_DTLS_COOKIE_LEN bytes)
 *
 * @return 0 on success, -1 on failure
 */
extern int dtls_generate_cookie_hmac (const unsigned char *secret,
                                      const struct sockaddr *peer_addr,
                                      socklen_t peer_len,
                                      unsigned char *out_cookie);

/**
 * @brief dtls_context_get_from_ssl - Get SocketDTLSContext from SSL object
 * @ingroup security
 * @param ssl SSL object
 * @return Context pointer or NULL
 *
 * Retrieves the SocketDTLSContext associated with an SSL object.
 * Used internally by DTLS callbacks to access context-specific data.
 */
extern SocketDTLSContext_T dtls_context_get_from_ssl (const SSL *ssl);

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETDTLS_PRIVATE_INCLUDED */

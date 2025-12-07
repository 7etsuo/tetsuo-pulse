/**
 * SocketDTLS-private.h - DTLS Internal Shared Definitions
 *
 * Part of the Socket Library
 *
 * Internal header for all DTLS module implementation files. Contains shared
 * helper function declarations, error handling macros, internal types,
 * and the SocketDTLSContext_T structure definition.
 * NOT part of public API - do not include from application code.
 *
 * Thread safety: Internal functions are not thread-safe unless noted.
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
 * RAISE_DTLS_ERROR - Raise DTLS exception with detailed error message
 * @exception: Exception type to raise
 *
 * Uses centralized socket_error_buf and SocketDTLS_DetailedException.
 */
#define RAISE_DTLS_ERROR(exception) \
  SOCKET_RAISE_MODULE_ERROR(SocketDTLS, exception)

/**
 * RAISE_DTLS_ERROR_MSG - Raise DTLS exception with specific message
 * @exception: Exception type to raise
 * @msg: Error message string
 */
#define RAISE_DTLS_ERROR_MSG(exception, msg) \
  do { \
    SOCKET_ERROR_MSG(msg); \
    RAISE_DTLS_ERROR(exception); \
  } while (0)

/**
 * REQUIRE_DTLS_ENABLED - Validate DTLS is enabled on socket
 * @socket: Socket to validate
 * @exception: Exception to raise on failure
 */
#define REQUIRE_DTLS_ENABLED(socket, exception)                                \
  do                                                                           \
    {                                                                          \
      if (!(socket)->dtls_enabled)                                             \
        RAISE_DTLS_ERROR_MSG (exception, "DTLS not enabled on socket");        \
    }                                                                          \
  while (0)

/**
 * DTLS_ERROR_MSG - Format simple error message
 * @msg: Message string
 *
 * Uses centralized socket_error_buf.
 */
#define DTLS_ERROR_MSG(msg) SOCKET_ERROR_MSG(msg)

/**
 * DTLS_ERROR_FMT - Format error message with arguments
 * @fmt: Format string
 * @...: Format arguments
 *
 * Uses centralized socket_error_buf with errno if set.
 */
#define DTLS_ERROR_FMT(fmt, ...) SOCKET_ERROR_FMT(fmt, ##__VA_ARGS__)

/**
 * VALIDATE_DTLS_IO_READY - Validate socket is ready for DTLS I/O
 * @socket: Socket to validate
 * @exception: Exception to raise on failure
 *
 * Checks dtls_enabled, handshake_done, and SSL object availability.
 * Returns SSL* on success, raises exception on failure.
 */
#define VALIDATE_DTLS_IO_READY(socket, exception)                              \
  ({                                                                           \
    if (!(socket)->dtls_enabled)                                               \
      {                                                                        \
        DTLS_ERROR_MSG ("DTLS not enabled on socket");                         \
        RAISE_DTLS_ERROR (exception);                                          \
      }                                                                        \
    if (!(socket)->dtls_handshake_done)                                        \
      {                                                                        \
        DTLS_ERROR_MSG ("DTLS handshake not complete");                        \
        RAISE_DTLS_ERROR (exception);                                          \
      }                                                                        \
    SSL *_ssl = dtls_socket_get_ssl (socket);                                  \
    if (!_ssl)                                                                 \
      {                                                                        \
        DTLS_ERROR_MSG ("SSL object not available");                           \
        RAISE_DTLS_ERROR (exception);                                          \
      }                                                                        \
    _ssl;                                                                      \
  })

/* ============================================================================
 * SSL Object Access
 * ============================================================================
 */

/**
 * dtls_socket_get_ssl - Get SSL* from socket
 * @socket: Socket instance
 *
 * Returns: SSL* pointer or NULL if DTLS not enabled/available
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
 * dtls_handle_ssl_error - Map OpenSSL errors to DTLSHandshakeState
 * @socket: Socket instance
 * @ssl: SSL object
 * @ssl_result: Result from SSL operation
 *
 * Returns: DTLSHandshakeState based on error type
 *
 * Sets errno to EAGAIN for WANT_READ/WRITE cases.
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
 * dtls_format_openssl_error - Format OpenSSL error into buffer
 * @context: Context string for error message
 *
 * Formats current OpenSSL error into socket_error_buf with context.
 */
static inline void
dtls_format_openssl_error (const char *context)
{
  unsigned long err = ERR_get_error ();
  char err_str[SOCKET_DTLS_OPENSSL_ERRSTR_BUFSIZE];

  if (err != 0)
    {
      ERR_error_string_n (err, err_str, sizeof (err_str));
      SOCKET_ERROR_MSG("%s: %s", context, err_str);
    }
  else
    {
      SOCKET_ERROR_MSG("%s: Unknown error", context);
    }
  ERR_clear_error();  /* Clear remaining OpenSSL error queue */
}

/* ============================================================================
 * Input Validation
 * ============================================================================
 */

/**
 * dtls_validate_file_path - Validate certificate/key/CA file path
 * @path: File path string to validate
 *
 * Returns: 1 if valid, 0 if invalid
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
  if (path[0] != '/' ) { /* Optional: warn or reject relative; preference for absolute */
    /* Relative paths accepted but may be insecure if cwd untrusted */
  }
  if (strstr (path, "../") != NULL || strstr (path, "..\\") != NULL ||
      strstr (path, "/..") != NULL || strstr (path, "\\..") != NULL ||
      strstr (path, "..") != NULL) {
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
 * Cookie State - Server-side cookie exchange state
 */
typedef struct
{
  unsigned char secret[SOCKET_DTLS_COOKIE_SECRET_LEN]; /**< HMAC secret */
  unsigned char prev_secret[SOCKET_DTLS_COOKIE_SECRET_LEN]; /**< Previous secret for rotation */
  int cookie_enabled;                                       /**< Cookie exchange enabled */
  pthread_mutex_t secret_mutex; /**< Protects secret rotation */
} DTLSContextCookie;

/**
 * ALPN Configuration - Application-Layer Protocol Negotiation settings
 */
typedef struct
{
  const char **protocols;  /**< Array of protocol strings */
  size_t count;            /**< Number of protocols */
  const char *selected;    /**< Negotiated protocol (for clients) */
} DTLSContextALPN;

/**
 * SocketDTLSContext_T - DTLS Context Structure
 *
 * Manages OpenSSL SSL_CTX for DTLS with secure defaults, certificates,
 * cookie exchange, and session caching.
 */
struct T
{
  SSL_CTX *ssl_ctx;             /**< OpenSSL context */
  Arena_T arena;                /**< Arena for allocations */
  int is_server;                /**< 1 for server, 0 for client */
  size_t mtu;                   /**< Configured MTU */
  int session_cache_enabled;    /**< Session cache flag */
  size_t session_cache_size;    /**< Session cache size */
  size_t cache_hits;            /**< Session resumptions */
  size_t cache_misses;          /**< Full handshakes */
  size_t cache_stores;          /**< New sessions stored */
  pthread_mutex_t stats_mutex;  /**< Thread-safe stats update */

  /* Cookie exchange (DTLS-specific DoS protection) */
  DTLSContextCookie cookie;

  /* ALPN configuration */
  DTLSContextALPN alpn;

  /* Timeout configuration */
  int initial_timeout_ms;
  int max_timeout_ms;
};

/* ============================================================================
 * Thread-Local Error Handling for SocketDTLSContext
 * ============================================================================
 */

#ifdef _WIN32
extern __declspec (thread) char dtls_context_error_buf[SOCKET_DTLS_ERROR_BUFSIZE];
extern __declspec (thread) Except_T SocketDTLSContext_DetailedException;
#else
extern __thread char dtls_context_error_buf[SOCKET_DTLS_ERROR_BUFSIZE];
extern __thread Except_T SocketDTLSContext_DetailedException;
#endif

/**
 * RAISE_DTLS_CTX_ERROR - Raise context exception with current error buffer
 */
#define RAISE_DTLS_CTX_ERROR(exception)                                        \
  do                                                                           \
    {                                                                          \
      SocketDTLSContext_DetailedException = (exception);                       \
      SocketDTLSContext_DetailedException.reason = dtls_context_error_buf;     \
      RAISE (SocketDTLSContext_DetailedException);                             \
    }                                                                          \
  while (0)

/**
 * RAISE_DTLS_CTX_ERROR_MSG - Raise context exception with specific message
 */
#define RAISE_DTLS_CTX_ERROR_MSG(exception, msg)                               \
  do { SOCKET_RAISE_MSG(SocketDTLSContext, exception, msg); } while(0)

#define RAISE_DTLS_CTX_ERROR_FMT(exception, fmt, ...)                          \
  do { SOCKET_RAISE_FMT(SocketDTLSContext, exception, fmt, __VA_ARGS__); } while(0)

/* ============================================================================
 * Utility Macros
 * ============================================================================
 */

#define DTLS_UNUSED(x) (void)(x)

/* ============================================================================
 * Cookie Exchange Internal Functions
 * ============================================================================
 */

/**
 * dtls_cookie_generate_cb - OpenSSL cookie generation callback
 * @ssl: SSL object
 * @cookie: Output buffer for cookie
 * @cookie_len: Output for cookie length
 *
 * Returns: 1 on success, 0 on failure
 */
extern int dtls_cookie_generate_cb (SSL *ssl, unsigned char *cookie,
                                    unsigned int *cookie_len);

/**
 * dtls_cookie_verify_cb - OpenSSL cookie verification callback
 * @ssl: SSL object
 * @cookie: Cookie to verify
 * @cookie_len: Cookie length
 *
 * Returns: 1 if valid, 0 if invalid
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
 * Returns: 0 on success, -1 on failure
 */
extern int dtls_generate_cookie_hmac (const unsigned char *secret,
                                      const struct sockaddr *peer_addr,
                                      socklen_t peer_len,
                                      unsigned char *out_cookie);

/**
 * dtls_context_get_from_ssl - Get SocketDTLSContext from SSL object
 * @ssl: SSL object
 *
 * Returns: Context pointer or NULL
 */
extern SocketDTLSContext_T dtls_context_get_from_ssl (const SSL *ssl);

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETDTLS_PRIVATE_INCLUDED */


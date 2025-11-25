/**
 * SocketTLS-private.h - TLS Internal Shared Definitions
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Internal header for TLS module implementation files. Contains shared
 * helper function declarations, error handling macros, and internal types.
 * NOT part of public API - do not include from application code.
 *
 * Thread safety: Internal functions are not thread-safe unless noted.
 */

#ifndef SOCKETTLS_PRIVATE_INCLUDED
#define SOCKETTLS_PRIVATE_INCLUDED

#ifdef SOCKET_HAS_TLS

#include <ctype.h>

#include "core/Except.h"
#include "socket/Socket-private.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include <openssl/ssl.h>

/* ============================================================================
 * Thread-Local Error Handling
 * ============================================================================
 */

/**
 * Thread-local error buffer for detailed TLS error messages.
 * Shared across all TLS implementation files.
 */
#ifdef _WIN32
extern __declspec (thread) char tls_error_buf[];
#else
extern __thread char tls_error_buf[];
#endif

/**
 * Thread-local exception copy for detailed TLS error messages.
 * Prevents race conditions when multiple threads raise same exception.
 */
#ifdef _WIN32
extern __declspec (thread) Except_T SocketTLS_DetailedException;
#else
extern __thread Except_T SocketTLS_DetailedException;
#endif

/**
 * RAISE_TLS_ERROR - Raise TLS exception with detailed error message
 * @exception: Exception type to raise
 *
 * Creates thread-local copy of exception with reason from tls_error_buf.
 */
#define RAISE_TLS_ERROR(exception)                                            \
  do                                                                          \
    {                                                                         \
      SocketTLS_DetailedException = (exception);                              \
      SocketTLS_DetailedException.reason = tls_error_buf;                     \
      RAISE (SocketTLS_DetailedException);                                    \
    }                                                                         \
  while (0)

/**
 * TLS_ERROR_MSG - Format simple error message
 * @msg: Message string
 */
#define TLS_ERROR_MSG(msg)                                                    \
  snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "%s", (msg))

/**
 * TLS_ERROR_FMT - Format error message with arguments
 * @fmt: Format string
 * @...: Format arguments
 */
#define TLS_ERROR_FMT(fmt, ...)                                               \
  snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, fmt, __VA_ARGS__)

/* ============================================================================
 * SSL Object Access
 * ============================================================================
 */

/**
 * tls_socket_get_ssl - Get SSL* from socket
 * @socket: Socket instance
 *
 * Returns: SSL* pointer or NULL if TLS not enabled/available
 */
static inline SSL *
tls_socket_get_ssl (Socket_T socket)
{
  if (!socket || !socket->tls_enabled || !socket->tls_ssl)
    return NULL;
  return (SSL *)socket->tls_ssl;
}

/* ============================================================================
 * SSL Error Handling
 * ============================================================================
 */

/**
 * tls_handle_ssl_error - Map OpenSSL errors to TLSHandshakeState
 * @socket: Socket instance
 * @ssl: SSL object
 * @ssl_result: Result from SSL operation
 *
 * Returns: TLSHandshakeState based on error type
 *
 * Sets errno to EAGAIN for WANT_READ/WRITE cases.
 */
static inline TLSHandshakeState
tls_handle_ssl_error (Socket_T socket, SSL *ssl, int ssl_result)
{
  int ssl_error = SSL_get_error (ssl, ssl_result);

  switch (ssl_error)
    {
    case SSL_ERROR_NONE:
      socket->tls_handshake_done = 1;
      return TLS_HANDSHAKE_COMPLETE;

    case SSL_ERROR_WANT_READ:
      socket->tls_handshake_done = 0;
      errno = EAGAIN;
      return TLS_HANDSHAKE_WANT_READ;

    case SSL_ERROR_WANT_WRITE:
      socket->tls_handshake_done = 0;
      errno = EAGAIN;
      return TLS_HANDSHAKE_WANT_WRITE;

    default:
      socket->tls_handshake_done = 0;
      return TLS_HANDSHAKE_ERROR;
    }
}

/**
 * tls_format_openssl_error - Format OpenSSL error into buffer
 * @context: Context string for error message
 *
 * Formats current OpenSSL error into tls_error_buf with context.
 */
static inline void
tls_format_openssl_error (const char *context)
{
  unsigned long err = ERR_get_error ();
  char err_str[SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE];

  if (err != 0)
    {
      ERR_error_string_n (err, err_str, sizeof (err_str));
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "%s: %s", context,
                err_str);
    }
  else
    {
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "%s: Unknown error",
                context);
    }
}

/* ============================================================================
 * Input Validation
 * ============================================================================
 */

/**
 * tls_validate_file_path - Validate certificate/key/CA file path
 * @path: File path string to validate
 *
 * Performs security checks: non-empty, reasonable length, no path traversal.
 *
 * Returns: 1 if valid, 0 if invalid
 */
static inline int
tls_validate_file_path (const char *path)
{
  if (!path || !*path)
    return 0;

  size_t len = strlen (path);
  if (len == 0 || len > 4096)
    return 0;

  if (strstr (path, "..") != NULL)
    return 0;

  return 1;
}

/**
 * tls_validate_hostname - Validate SNI hostname format
 * @hostname: Hostname string to validate
 *
 * Validates hostname according to DNS rules: labels with alphanum/-,
 * length limits per RFC 6066.
 *
 * Returns: 1 if valid, 0 if invalid
 */
static inline int
tls_validate_hostname (const char *hostname)
{
  if (!hostname)
    return 0;

  size_t len = strlen (hostname);
  if (len == 0 || len > SOCKET_TLS_MAX_SNI_LEN)
    return 0;

  const char *p = hostname;
  int label_len = 0;

  while (*p)
    {
      if (*p == '.')
        {
          if (label_len == 0 || label_len > 63)
            return 0;
          label_len = 0;
        }
      else
        {
          if (!(isalnum ((unsigned char)*p) || *p == '-'))
            return 0;
          if (*p == '-' && label_len == 0)
            return 0;
          label_len++;
          if (label_len > 63)
            return 0;
        }
      p++;
    }

  return (label_len > 0 && label_len <= 63);
}

/* ============================================================================
 * Context Internal Functions (implemented in SocketTLSContext-*.c)
 * ============================================================================
 */

/* Forward declaration for SocketTLSContext_T */
typedef struct SocketTLSContext_T *SocketTLSContext_T;

/**
 * tls_context_get_from_ssl - Get SocketTLSContext from SSL object
 * @ssl: SSL object
 *
 * Returns: Context pointer or NULL
 */
extern SocketTLSContext_T tls_context_get_from_ssl (const SSL *ssl);

/**
 * tls_context_get_from_ssl_ctx - Get SocketTLSContext from SSL_CTX
 * @ssl_ctx: OpenSSL context
 *
 * Returns: Context pointer or NULL
 */
extern SocketTLSContext_T tls_context_get_from_ssl_ctx (SSL_CTX *ssl_ctx);

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLS_PRIVATE_INCLUDED */


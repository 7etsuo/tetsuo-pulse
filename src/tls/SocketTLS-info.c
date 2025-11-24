/**
 * SocketTLS-info.c - TLS Connection Information Functions
 *


 *
 * Provides query functions for TLS connection details post-handshake:
 * cipher suite, protocol version, verification result, session reuse status.
 * Reads from SSL object in socket state.
 *
 * Thread-safe: Yes - read-only access to immutable state
 */

#ifdef SOCKET_HAS_TLS

#include "core/Arena.h"
#include "socket/Socket-private.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include <assert.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509_vfy.h> /* For X509_V_ERR_* constants */
#include <string.h>

#define T SocketTLS_T

static SSL *
socket_get_ssl (Socket_T socket)
{
  if (!socket || !socket->tls_enabled || !socket->tls_ssl)
    return NULL;
  return (SSL *)socket->tls_ssl;
}

/**
 * SocketTLS_get_cipher - Get the cipher suite used for the TLS connection
 * @socket: Socket instance
 *
 * Returns the name of the cipher suite negotiated for this TLS connection.
 * The handshake must be complete for this information to be available.
 *
 * Returns: Cipher suite name string, or NULL if not available
 * Thread-safe: No (reads socket state)
 */
const char *
SocketTLS_get_cipher (Socket_T socket)
{
  SSL *ssl;
  const SSL_CIPHER *cipher;

  assert (socket);

  /* Check if TLS is enabled */
  if (!socket->tls_enabled)
    {
      return NULL;
    }

  /* Get SSL object */
  ssl = socket_get_ssl (socket);
  if (!ssl)
    {
      return NULL;
    }

  /* Get cipher information */
  cipher = SSL_get_current_cipher (ssl);
  if (!cipher)
    {
      return NULL;
    }

  return SSL_CIPHER_get_name (cipher);
}

/**
 * SocketTLS_get_version - Get the TLS protocol version used for the connection
 * @socket: Socket instance
 *
 * Returns the TLS protocol version string (e.g., "TLSv1.2", "TLSv1.3").
 * The handshake must be complete for this information to be available.
 *
 * Returns: TLS version string, or NULL if not available
 * Thread-safe: No (reads socket state)
 */
const char *
SocketTLS_get_version (Socket_T socket)
{
  SSL *ssl;

  assert (socket);

  /* Check if TLS is enabled */
  if (!socket->tls_enabled)
    {
      return NULL;
    }

  /* Get SSL object */
  ssl = socket_get_ssl (socket);
  if (!ssl)
    {
      return NULL;
    }

  /* Get version information */
  return SSL_get_version (ssl);
}

/**
 * SocketTLS_get_verify_result - Get peer certificate verification result
 * @socket: The socket instance with completed handshake
 *
 * Returns OpenSSL's X509 verify result code. X509_V_OK (0) indicates
 * successful verification. Non-zero codes detail failures (e.g., untrusted
 * CA).
 *
 * Returns: long verify result code (X509_V_OK = 0 on success)
 * Raises: None (caller checks != X509_V_OK and may raise
 * SocketTLS_VerifyFailed) Thread-safe: Yes (read-only post-handshake)
 * Requires: tls_enabled and tls_handshake_done
 */
long
SocketTLS_get_verify_result (Socket_T socket)
{
  SSL *ssl;

  if (!socket || !socket->tls_enabled || !socket->tls_ssl
      || !socket->tls_handshake_done)
    {
      return X509_V_ERR_INVALID_CALL;
    }

  ssl = (SSL *)socket->tls_ssl; /* Direct access for perf */
  return SSL_get_verify_result (ssl);
}

/**
 * SocketTLS_get_verify_error_string - Get human-readable verification error
 * @socket: TLS socket
 * @buf: Buffer for error string
 * @size: Buffer size
 *
 * Fills buf with string for last verify error from get_verify_result or
 * OpenSSL ERR queue. Enhances reporting for CRL/OCSP/verify fails.
 *
 * Returns: buf or NULL on no error/buf too small
 * Raises: None
 * Thread-safe: No (ERR queue not thread-safe)
 */
const char *
SocketTLS_get_verify_error_string (Socket_T socket, char *buf, size_t size)
{
  if (!socket || !buf || size == 0)
    return NULL;

  long code = SocketTLS_get_verify_result (socket);
  if (code == X509_V_OK)
    return NULL; /* No error */

  /* Get string for code */
  const char *code_str = X509_verify_cert_error_string (code);
  if (code_str)
    {
      strncpy (buf, code_str, size - 1);
      buf[size - 1] = '\0';
      return buf;
    }

  /* Fallback to OpenSSL ERR */
  unsigned long err = ERR_get_error ();
  if (err)
    {
      ERR_error_string_n (err, buf, size);
      return buf;
    }

  /* Generic */
  strncpy (buf, "TLS verification failed (unknown error)", size - 1);
  buf[size - 1] = '\0';
  return buf;
}

/**
 * SocketTLS_is_session_reused - Check if the TLS session was reused
 * @socket: Socket instance
 *
 * Returns 1 if the current TLS session was resumed from a previous session
 * (session reuse), 0 if it's a new session. Session reuse improves performance
 * by avoiding full handshakes. The handshake must be complete for this
 * information to be available.
 *
 * Returns: 1 if session was reused, 0 if new session, -1 if not available
 * Thread-safe: No (reads socket state)
 */
int
SocketTLS_is_session_reused (Socket_T socket)
{
  SSL *ssl;

  assert (socket);

  /* Check if TLS is enabled */
  if (!socket->tls_enabled)
    {
      return -1; /* Not applicable */
    }

  /* Get SSL object directly from private field */
  ssl = (SSL *)socket->tls_ssl;
  if (!ssl)
    {
      return X509_V_ERR_INVALID_CALL;
    }

  /* Check if session was reused */
  return SSL_session_reused (ssl) ? 1 : 0;
}

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
const char *
SocketTLS_get_alpn_selected (Socket_T socket)
{
  SSL *ssl;
  const unsigned char *alpn_data;
  unsigned int alpn_len;

  assert (socket);

  /* Check if TLS is enabled */
  if (!socket->tls_enabled)
    {
      return NULL;
    }

  /* Get SSL object */
  ssl = socket_get_ssl (socket);
  if (!ssl)
    {
      return NULL;
    }

  /* Get negotiated ALPN protocol */
  SSL_get0_alpn_selected (ssl, &alpn_data, &alpn_len);
  if (!alpn_data || alpn_len == 0)
    {
      return NULL;
    }

  if (alpn_len > SOCKET_TLS_MAX_ALPN_LEN)
    {
      return NULL; /* Invalid length */
    }

  /* Allocate null-terminated copy in socket arena for safe string usage */
  char *proto_copy = Arena_alloc (SocketBase_arena (socket->base),
                                  alpn_len + 1, __FILE__, __LINE__);
  if (!proto_copy)
    {
      return NULL; /* Allocation failed */
    }

  memcpy (proto_copy, alpn_data, alpn_len);
  proto_copy[alpn_len] = '\0';

  return proto_copy;
}

#undef T

#endif /* SOCKET_HAS_TLS */
#include <openssl/ocsp.h>

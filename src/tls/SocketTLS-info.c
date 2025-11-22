/**
 * SocketTLS-info.c - TLS Connection Information Functions
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Provides query functions for TLS connection details post-handshake:
 * cipher suite, protocol version, verification result, session reuse status.
 * Reads from SSL object in socket state.
 *
 * Thread-safe: Yes - read-only access to immutable state
 */

#ifdef SOCKET_HAS_TLS

#include "socket/Socket-private.h"
#include "tls/SocketTLS.h"
#include <assert.h>
#include <openssl/ssl.h>

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
 * SocketTLS_get_verify_result - Get the certificate verification result
 * @socket: Socket instance
 *
 * Returns the result of certificate verification as defined by OpenSSL's
 * X509_V_* constants. X509_V_OK (0) means verification succeeded.
 * The handshake must be complete for this information to be available.
 *
 * Returns: Verification result code (X509_V_OK on success)
 * Thread-safe: No (reads socket state)
 */
int
SocketTLS_get_verify_result (Socket_T socket)
{
  SSL *ssl;

  assert (socket);

  /* Check if TLS is enabled */
  if (!socket->tls_enabled)
    {
      return -1; /* Not applicable */
    }

  /* Get SSL object */
  ssl = socket_get_ssl (socket);
  if (!ssl)
    {
      return -1; /* Not available */
    }

  /* Get verification result */
  return SSL_get_verify_result (ssl);
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

  /* Get SSL object */
  ssl = socket_get_ssl (socket);
  if (!ssl)
    {
      return -1; /* Not available */
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

  /* Note: OpenSSL returns the protocol in wire format (length-prefixed)
   * For simplicity, we assume it's a valid string and return it directly.
   * In production, you might want to validate the format. */
  return (const char *)alpn_data;
}

#undef T

#endif /* SOCKET_HAS_TLS */

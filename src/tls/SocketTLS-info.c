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

#include "tls/SocketTLS-private.h"
#include <assert.h>
#include <openssl/x509_vfy.h>
#include <string.h>

#define T SocketTLS_T

const char *
SocketTLS_get_cipher (Socket_T socket)
{
  SSL *ssl;
  const SSL_CIPHER *cipher;

  assert (socket);

  if (!socket->tls_enabled)
    return NULL;

  ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return NULL;

  cipher = SSL_get_current_cipher (ssl);
  if (!cipher)
    return NULL;

  return SSL_CIPHER_get_name (cipher);
}

const char *
SocketTLS_get_version (Socket_T socket)
{
  SSL *ssl;

  assert (socket);

  if (!socket->tls_enabled)
    return NULL;

  ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return NULL;

  return SSL_get_version (ssl);
}

long
SocketTLS_get_verify_result (Socket_T socket)
{
  SSL *ssl;

  if (!socket || !socket->tls_enabled || !socket->tls_ssl
      || !socket->tls_handshake_done)
    {
      return X509_V_ERR_INVALID_CALL;
    }

  ssl = (SSL *)socket->tls_ssl;
  return SSL_get_verify_result (ssl);
}

const char *
SocketTLS_get_verify_error_string (Socket_T socket, char *buf, size_t size)
{
  if (!socket || !buf || size == 0)
    return NULL;

  long code = SocketTLS_get_verify_result (socket);
  if (code == X509_V_OK)
    return NULL;

  const char *code_str = X509_verify_cert_error_string (code);
  if (code_str)
    {
      strncpy (buf, code_str, size - 1);
      buf[size - 1] = '\0';
      return buf;
    }

  unsigned long err = ERR_get_error ();
  if (err)
    {
      ERR_error_string_n (err, buf, size);
      return buf;
    }

  strncpy (buf, "TLS verification failed (unknown error)", size - 1);
  buf[size - 1] = '\0';
  return buf;
}

int
SocketTLS_is_session_reused (Socket_T socket)
{
  SSL *ssl;

  assert (socket);

  if (!socket->tls_enabled)
    return -1;

  ssl = (SSL *)socket->tls_ssl;
  if (!ssl)
    return X509_V_ERR_INVALID_CALL;

  return SSL_session_reused (ssl) ? 1 : 0;
}

const char *
SocketTLS_get_alpn_selected (Socket_T socket)
{
  SSL *ssl;
  const unsigned char *alpn_data;
  unsigned int alpn_len;

  assert (socket);

  if (!socket->tls_enabled)
    return NULL;

  ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return NULL;

  SSL_get0_alpn_selected (ssl, &alpn_data, &alpn_len);
  if (!alpn_data || alpn_len == 0)
    return NULL;

  if (alpn_len > SOCKET_TLS_MAX_ALPN_LEN)
    return NULL;

  char *proto_copy = Arena_alloc (SocketBase_arena (socket->base),
                                  alpn_len + 1, __FILE__, __LINE__);
  if (!proto_copy)
    return NULL;

  memcpy (proto_copy, alpn_data, alpn_len);
  proto_copy[alpn_len] = '\0';

  return proto_copy;
}

#undef T

#endif /* SOCKET_HAS_TLS */

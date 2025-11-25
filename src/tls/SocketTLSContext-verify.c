/**
 * SocketTLSContext-verify.c - TLS Verification Configuration
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Handles certificate verification mode, custom verification callbacks,
 * CRL loading, and protocol version configuration.
 *
 * Thread safety: Not thread-safe (modifies shared context).
 */

#ifdef SOCKET_HAS_TLS

#include "socket/Socket-private.h"
#include "tls/SocketTLSContext-private.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#define T SocketTLSContext_T

/**
 * verify_mode_to_openssl - Convert TLSVerifyMode to OpenSSL flags
 * @mode: Our verification mode enum
 *
 * Returns: OpenSSL SSL_VERIFY_* flags
 */
static int
verify_mode_to_openssl (TLSVerifyMode mode)
{
  switch (mode)
    {
    case TLS_VERIFY_NONE:
      return SSL_VERIFY_NONE;
    case TLS_VERIFY_PEER:
      return SSL_VERIFY_PEER;
    case TLS_VERIFY_FAIL_IF_NO_PEER_CERT:
      return SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    case TLS_VERIFY_CLIENT_ONCE:
      return SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
    default:
      return SSL_VERIFY_NONE;
    }
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclobbered"

/**
 * internal_verify_callback - OpenSSL verification wrapper
 * @pre_ok: OpenSSL pre-verification result
 * @x509_ctx: Certificate store context
 *
 * Returns: 1 to continue verification, 0 to fail
 */
static int
internal_verify_callback (int pre_ok, X509_STORE_CTX *x509_ctx)
{
  SSL *ssl = X509_STORE_CTX_get_ex_data (
      x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx ());
  if (!ssl)
    return pre_ok;

  Socket_T sock = (Socket_T)SSL_get_app_data (ssl);
  if (!sock)
    return pre_ok;

  T ctx = (T)sock->tls_ctx;
  if (!ctx || !ctx->verify_callback)
    return pre_ok;

  volatile int result;
  TRY
  {
    result
        = ctx->verify_callback (pre_ok, x509_ctx, ctx, sock, ctx->verify_user_data);
  }
  EXCEPT (SocketTLS_Failed)
  {
    result = 0;
    X509_STORE_CTX_set_error (x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
  }
  END_TRY;

  if (!result)
    {
      X509_STORE_CTX_set_error (x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
    }

  return result;
}

#pragma GCC diagnostic pop

void
SocketTLSContext_set_verify_mode (T ctx, TLSVerifyMode mode)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  ctx->verify_mode = mode;

  int openssl_mode = verify_mode_to_openssl (mode);
  SSL_verify_cb cb
      = ctx->verify_callback ? (SSL_verify_cb)internal_verify_callback : NULL;

  ERR_clear_error ();
  SSL_CTX_set_verify (ctx->ssl_ctx, openssl_mode, cb);
}

void
SocketTLSContext_set_verify_callback (T ctx, SocketTLSVerifyCallback callback,
                                      void *user_data)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  ctx->verify_callback = callback;
  ctx->verify_user_data = user_data;

  int openssl_mode = verify_mode_to_openssl (ctx->verify_mode);
  SSL_verify_cb cb = callback ? (SSL_verify_cb)internal_verify_callback : NULL;

  SSL_CTX_set_verify (ctx->ssl_ctx, openssl_mode, cb);

  if (ERR_get_error () != 0)
    {
      unsigned long err = ERR_get_error ();
      char err_buf[SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE];
      ERR_error_string_n (err, err_buf, sizeof (err_buf));
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                           "Failed to set verify callback: %s", err_buf);
    }
}

void
SocketTLSContext_load_crl (T ctx, const char *crl_path)
{
  if (!ctx)
    RAISE_CTX_ERROR (SocketTLS_Failed);
  if (!ctx->ssl_ctx)
    RAISE_CTX_ERROR (SocketTLS_Failed);
  if (!crl_path || !*crl_path)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "CRL path cannot be NULL or empty");

  X509_STORE *store = SSL_CTX_get_cert_store (ctx->ssl_ctx);
  if (!store)
    RAISE_CTX_ERROR (SocketTLS_Failed);

  struct stat st;
  if (stat (crl_path, &st) != 0)
    RAISE_CTX_ERROR_FMT (SocketTLS_Failed, "Invalid CRL path '%s': %s",
                         crl_path, strerror (errno));

  int ret;
  if (S_ISDIR (st.st_mode))
    {
      ret = X509_STORE_load_locations (store, NULL, crl_path);
    }
  else
    {
      ret = X509_STORE_load_locations (store, crl_path, NULL);
    }

  if (ret != 1)
    {
      unsigned long err = ERR_get_error ();
      char err_buf[SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE];
      ERR_error_string_n (err, err_buf, sizeof (err_buf));
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed, "Failed to load CRL '%s': %s",
                           crl_path, err_buf);
    }

  long current = X509_STORE_set_flags (store, 0);
  X509_STORE_set_flags (store,
                        current | X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
}

void
SocketTLSContext_refresh_crl (T ctx, const char *crl_path)
{
  SocketTLSContext_load_crl (ctx, crl_path);
}

void
SocketTLSContext_set_min_protocol (T ctx, int version)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (SSL_CTX_set_min_proto_version (ctx->ssl_ctx, version) != 1)
    {
#if defined(SSL_OP_NO_SSLv2) && defined(SSL_OP_NO_SSLv3)
      long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;

      if (version > TLS1_VERSION)
        options |= SSL_OP_NO_TLSv1;
      if (version > TLS1_1_VERSION)
        options |= SSL_OP_NO_TLSv1_1;
      if (version > TLS1_2_VERSION)
        options |= SSL_OP_NO_TLSv1_2;

      long current = SSL_CTX_set_options (ctx->ssl_ctx, options);
      if (!(current & options))
        {
          ctx_raise_openssl_error ("Failed to set minimum TLS protocol version");
        }
#else
      ctx_raise_openssl_error (
          "Failed to set minimum TLS protocol version (fallback unavailable)");
#endif
    }
}

void
SocketTLSContext_set_max_protocol (T ctx, int version)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (SSL_CTX_set_max_proto_version (ctx->ssl_ctx, version) != 1)
    {
      ctx_raise_openssl_error ("Failed to set maximum TLS protocol version");
    }
}

void
SocketTLSContext_set_cipher_list (T ctx, const char *ciphers)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  const char *list = ciphers
      ? ciphers
      : "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA";

  if (SSL_CTX_set_cipher_list (ctx->ssl_ctx, list) != 1)
    {
      ctx_raise_openssl_error ("Failed to set cipher list");
    }
}

#undef T

#endif /* SOCKET_HAS_TLS */


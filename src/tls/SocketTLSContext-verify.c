/**
 * SocketTLSContext-verify.c - TLS Verification and Revocation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Certificate verification mode, custom callbacks, CRL loading,
 * OCSP stapling, and protocol version/cipher configuration.
 *
 * Thread safety: Configuration is NOT thread-safe - perform before sharing.
 * Custom verification callbacks must be thread-safe if context is shared.
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include <assert.h>
#include <errno.h>
#include <openssl/ocsp.h>
#include <string.h>
#include <sys/stat.h>

#define T SocketTLSContext_T

/* ============================================================================
 * Verification Mode Configuration
 * ============================================================================
 */

/* Forward declaration for OpenSSL callback */
static int internal_verify_callback (int pre_ok, X509_STORE_CTX *x509_ctx);

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

/**
 * apply_verify_settings - Apply verification mode and callback to context
 * @ctx: TLS context
 *
 * Consolidates the SSL_CTX_set_verify call used by both set_verify_mode
 * and set_verify_callback.
 */
static void
apply_verify_settings (T ctx)
{
  int openssl_mode = verify_mode_to_openssl (ctx->verify_mode);
  SSL_verify_cb cb
      = ctx->verify_callback ? (SSL_verify_cb)internal_verify_callback : NULL;
  SSL_CTX_set_verify (ctx->ssl_ctx, openssl_mode, cb);
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
    result = ctx->verify_callback (pre_ok, x509_ctx, ctx, sock,
                                   ctx->verify_user_data);
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
  ERR_clear_error ();
  apply_verify_settings (ctx);
}

void
SocketTLSContext_set_verify_callback (T ctx, SocketTLSVerifyCallback callback,
                                      void *user_data)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  ctx->verify_callback = callback;
  ctx->verify_user_data = user_data;
  apply_verify_settings (ctx);
}

/* ============================================================================
 * CRL Management
 * ============================================================================
 */

void
SocketTLSContext_load_crl (T ctx, const char *crl_path)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (!crl_path || !*crl_path)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "CRL path cannot be NULL or empty");

  X509_STORE *store = SSL_CTX_get_cert_store (ctx->ssl_ctx);
  if (!store)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Failed to get certificate store");

  struct stat st;
  if (stat (crl_path, &st) != 0)
    RAISE_CTX_ERROR_FMT (SocketTLS_Failed, "Invalid CRL path '%s': %s",
                         crl_path, strerror (errno));

  int ret = S_ISDIR (st.st_mode)
                ? X509_STORE_load_locations (store, NULL, crl_path)
                : X509_STORE_load_locations (store, crl_path, NULL);

  if (ret != 1)
    ctx_raise_openssl_error ("Failed to load CRL");

  X509_STORE_set_flags (store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
}

void
SocketTLSContext_refresh_crl (T ctx, const char *crl_path)
{
  SocketTLSContext_load_crl (ctx, crl_path);
}

/* ============================================================================
 * Protocol Configuration
 * ============================================================================
 */

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

/* ============================================================================
 * OCSP Stapling
 * ============================================================================
 */

/**
 * status_cb_wrapper - OpenSSL OCSP status callback wrapper
 * @ssl: SSL connection
 * @arg: User argument (unused, we get context from SSL)
 *
 * Returns: SSL_TLSEXT_ERR_OK or SSL_TLSEXT_ERR_NOACK
 */
static int
status_cb_wrapper (SSL *ssl, void *arg)
{
  (void)arg;
  T ctx = tls_context_get_from_ssl (ssl);
  if (!ctx || !ctx->ocsp_gen_cb)
    return SSL_TLSEXT_ERR_NOACK;

  OCSP_RESPONSE *resp = ctx->ocsp_gen_cb (ssl, ctx->ocsp_gen_arg);
  if (!resp)
    return SSL_TLSEXT_ERR_NOACK;

  unsigned char *der = NULL;
  int len = i2d_OCSP_RESPONSE (resp, &der);
  if (len > 0 && der)
    {
      SSL_set_tlsext_status_ocsp_resp (ssl, der, len);
    }

  OCSP_RESPONSE_free (resp);
  if (der)
    OPENSSL_free (der);

  return len > 0 ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_NOACK;
}

void
SocketTLSContext_set_ocsp_response (T ctx, const unsigned char *response,
                                    size_t len)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (!response || len == 0)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "Invalid OCSP response (null or zero length)");

  OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE (NULL, &response, len);
  if (!resp)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Invalid OCSP response format");
    }
  OCSP_RESPONSE_free (resp);

  unsigned char *copy = Arena_alloc (ctx->arena, len, __FILE__, __LINE__);
  if (!copy)
    {
      RAISE_CTX_ERROR (SocketTLS_Failed);
    }
  memcpy (copy, response, len);
  ctx->ocsp_response = copy;
  ctx->ocsp_len = len;
}

void
SocketTLSContext_set_ocsp_gen_callback (T ctx, SocketTLSOcspGenCallback cb,
                                        void *arg)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  ctx->ocsp_gen_cb = cb;
  ctx->ocsp_gen_arg = arg;

  SSL_CTX_set_tlsext_status_cb (ctx->ssl_ctx, status_cb_wrapper);

  /* Check for OpenSSL errors - ERR_get_error consumes the error */
  unsigned long err = ERR_get_error ();
  if (err != 0)
    {
      char err_buf[SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE];
      ERR_error_string_n (err, err_buf, sizeof (err_buf));
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed, "Failed to set OCSP status cb: %s",
                           err_buf);
    }
}

/* ============================================================================
 * OCSP Status Query (Socket-side)
 * ============================================================================
 */

/**
 * validate_socket_for_ocsp - Check socket is ready for OCSP status query
 * @socket: Socket to validate
 *
 * Returns: 1 if valid, 0 if not ready for OCSP
 */
static int
validate_socket_for_ocsp (Socket_T socket)
{
  return socket && socket->tls_enabled && socket->tls_ssl
         && socket->tls_handshake_done;
}

/**
 * get_ocsp_response_bytes - Get raw OCSP response from SSL
 * @ssl: SSL connection
 * @resp_bytes: Output pointer to response bytes
 *
 * Returns: Length of response, or 0 if no response
 */
static int
get_ocsp_response_bytes (SSL *ssl, const unsigned char **resp_bytes)
{
  int len = SSL_get_tlsext_status_ocsp_resp (ssl, resp_bytes);
  return (len > 0 && *resp_bytes) ? len : 0;
}

/**
 * validate_ocsp_basic_response - Validate OCSP basic response structure
 * @resp: OCSP response to validate
 *
 * Returns: 1 if valid, error status code otherwise
 */
static int
validate_ocsp_basic_response (OCSP_RESPONSE *resp)
{
  OCSP_BASICRESP *basic = OCSP_response_get1_basic (resp);
  if (!basic)
    return OCSP_RESPONSE_STATUS_INTERNALERROR;
  OCSP_BASICRESP_free (basic);
  return 1;
}

int
SocketTLS_get_ocsp_status (Socket_T socket)
{
  if (!validate_socket_for_ocsp (socket))
    return 0;

  SSL *ssl = (SSL *)socket->tls_ssl;
  const unsigned char *resp_bytes;
  int resp_len = get_ocsp_response_bytes (ssl, &resp_bytes);
  if (resp_len == 0)
    return 0;

  const unsigned char *p = resp_bytes;
  OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE (NULL, &p, resp_len);
  if (!resp)
    return OCSP_RESPONSE_STATUS_MALFORMEDREQUEST;

  int status = OCSP_response_status (resp);
  if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    {
      OCSP_RESPONSE_free (resp);
      return status;
    }

  int result = validate_ocsp_basic_response (resp);
  OCSP_RESPONSE_free (resp);
  return result;
}

#undef T

#endif /* SOCKET_HAS_TLS */


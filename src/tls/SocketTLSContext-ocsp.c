/**
 * SocketTLSContext-ocsp.c - OCSP Stapling Support
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Handles OCSP (Online Certificate Status Protocol) stapling for certificate
 * revocation status. Supports both static responses and dynamic generation
 * via callback.
 *
 * Thread safety: Callbacks must be thread-safe if context is shared.
 */

#ifdef SOCKET_HAS_TLS

#include "socket/Socket-private.h"
#include "tls/SocketTLSContext-private.h"
#include <assert.h>
#include <openssl/ocsp.h>
#include <string.h>

#define T SocketTLSContext_T

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

  if (ERR_get_error ())
    {
      unsigned long err = ERR_get_error ();
      char err_buf[256];
      ERR_error_string_n (err, err_buf, sizeof (err_buf));
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed, "Failed to set OCSP status cb: %s",
                           err_buf);
    }
}

int
SocketTLS_get_ocsp_status (Socket_T socket)
{
  if (!socket || !socket->tls_enabled || !socket->tls_ssl
      || !socket->tls_handshake_done)
    return 0;

  SSL *ssl = (SSL *)socket->tls_ssl;

  const unsigned char *resp_bytes;
  int resp_len = SSL_get_tlsext_status_ocsp_resp (ssl, &resp_bytes);
  if (resp_len <= 0 || !resp_bytes)
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

  OCSP_BASICRESP *basic = OCSP_response_get1_basic (resp);
  OCSP_RESPONSE_free (resp);
  if (!basic)
    return OCSP_RESPONSE_STATUS_INTERNALERROR;

  OCSP_BASICRESP_free (basic);
  return 1;
}

#undef T

#endif /* SOCKET_HAS_TLS */


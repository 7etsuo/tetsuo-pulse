/**
 * SocketTLSContext-verify.c - TLS Verification and Revocation
 *
 * Part of the Socket Library
 *
 * Certificate verification mode, custom callbacks, CRL loading,
 * OCSP stapling, and protocol version/cipher configuration.
 *
 * Thread safety: Configuration is NOT thread-safe - perform before sharing.
 * Custom verification callbacks must be thread-safe if context is shared.
 */

#if SOCKET_HAS_TLS

#include "core/SocketSecurity.h"
#include "tls/SocketTLS-private.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <openssl/ocsp.h>
#include <string.h>
#include <sys/stat.h>

#define T SocketTLSContext_T

SOCKET_DECLARE_MODULE_EXCEPTION (SocketTLSContext);

/* ============================================================================
 * Configuration Constants
 * ============================================================================
 */

/**
 * Default cipher list for legacy TLS (< 1.3) when user doesn't specify.
 * Excludes weak ciphers while maintaining compatibility.
 * For TLS 1.3+, use SOCKET_TLS13_CIPHERSUITES from SocketTLSConfig.h.
 */
#ifndef SOCKET_TLS_LEGACY_CIPHER_LIST
#define SOCKET_TLS_LEGACY_CIPHER_LIST                                         \
  "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA"
#endif

/* ============================================================================
 * Forward Declarations
 * ============================================================================
 */

static int internal_verify_callback (int pre_ok, X509_STORE_CTX *x509_ctx);

/* ============================================================================
 * Verification Mode Helpers
 * ============================================================================
 */

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
 * needs_internal_callback - Check if internal callback should be installed
 * @ctx: TLS context
 *
 * Returns: 1 if callback needed, 0 otherwise
 */
static int
needs_internal_callback (T ctx)
{
  return ctx->verify_callback != NULL || ctx->pinning.count > 0;
}

/**
 * apply_verify_settings - Apply verification mode and callback to context
 * @ctx: TLS context
 *
 * Consolidates SSL_CTX_set_verify call.
 */
static void
apply_verify_settings (T ctx)
{
  int openssl_mode = verify_mode_to_openssl (ctx->verify_mode);
  SSL_verify_cb cb = needs_internal_callback (ctx)
                         ? (SSL_verify_cb)internal_verify_callback
                         : NULL;

  SSL_CTX_set_verify (ctx->ssl_ctx, openssl_mode, cb);
}

/* ============================================================================
 * Certificate Pinning Helpers
 * ============================================================================
 */

/* Suppress -Wclobbered warning for setjmp/longjmp usage (GCC only) */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/**
 * check_single_cert_pin - Check if a single certificate matches any pin
 * @ctx: TLS context with pins
 * @cert: Certificate to check
 *
 * Returns: 1 if match found, 0 if no match
 */
static int
check_single_cert_pin (T ctx, X509 *cert)
{
  unsigned char hash[SOCKET_TLS_PIN_HASH_LEN];

  if (tls_pinning_extract_spki_hash (cert, hash) != 0)
    return 0;

  pthread_mutex_lock (&ctx->pinning.lock);
  int res = tls_pinning_find (ctx->pinning.pins, ctx->pinning.count, hash);
  pthread_mutex_unlock (&ctx->pinning.lock);
  return res;
}

/**
 * handle_pin_mismatch - Handle pin verification failure
 * @ctx: TLS context
 * @x509_ctx: Certificate store context
 *
 * Returns: 0 if enforce mode (fail), 1 if warn-only mode (continue)
 */
static int
handle_pin_mismatch (T ctx, X509_STORE_CTX *x509_ctx)
{
  pthread_mutex_lock (&ctx->pinning.lock);
  int enforce = ctx->pinning.enforce;
  pthread_mutex_unlock (&ctx->pinning.lock);
  if (enforce)
    {
      X509_STORE_CTX_set_error (x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
      return 0;
    }
  return 1; /* Warn only - verification continues */
}

/**
 * check_current_cert_pin - Fallback when chain unavailable
 * @ctx: TLS context with pins
 * @x509_ctx: Certificate store context
 *
 * Returns: 1 if match or warn-only, 0 if enforce and no match
 */
static int
check_current_cert_pin (T ctx, X509_STORE_CTX *x509_ctx)
{
  X509 *cert = X509_STORE_CTX_get_current_cert (x509_ctx);

  if (cert && check_single_cert_pin (ctx, cert))
    return 1;

  return handle_pin_mismatch (ctx, x509_ctx);
}

/**
 * check_certificate_pins - Verify certificate chain against pins
 * @ctx: TLS context with pins configured
 * @x509_ctx: Certificate store context
 *
 * Returns: 1 if match found or no pins configured, 0 if no match
 */
static int
check_certificate_pins (T ctx, X509_STORE_CTX *x509_ctx)
{
  STACK_OF (X509) * chain;

  assert (ctx);

  pthread_mutex_lock (&ctx->pinning.lock);
  if (ctx->pinning.count == 0)
    {
      pthread_mutex_unlock (&ctx->pinning.lock);
      return 1; /* No pins configured - pass */
    }
  pthread_mutex_unlock (&ctx->pinning.lock);

  chain = X509_STORE_CTX_get0_chain (x509_ctx);
  int allocated = 0;
  if (!chain)
    {
      chain = X509_STORE_CTX_get1_chain (x509_ctx);
      if (!chain)
        return check_current_cert_pin (ctx, x509_ctx);
      allocated = 1;
    }

  int match = tls_pinning_check_chain (ctx, chain);
  if (allocated)
    {
      sk_X509_pop_free (chain, X509_free);
    }

  if (match)
    return 1;

  return handle_pin_mismatch (ctx, x509_ctx);
}

/* ============================================================================
 * User Callback Invocation
 * ============================================================================
 */

/**
 * invoke_user_callback - Call user verification callback with exception safety
 * @ctx: TLS context
 * @pre_ok: OpenSSL pre-verification result
 * @x509_ctx: Certificate store context
 * @sock: Socket being verified
 *
 * Returns: User callback result, or 0 on any exception
 *
 * Catches ALL exceptions to prevent undefined behavior from uncaught
 * exceptions propagating through OpenSSL's callback mechanism.
 */
static int
invoke_user_callback (T ctx, int pre_ok, X509_STORE_CTX *x509_ctx,
                      Socket_T sock)
{
  volatile int result = pre_ok;

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
  ELSE
  {
    /* Catch all to prevent undefined behavior */
    result = 0;
    X509_STORE_CTX_set_error (x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
  }
  END_TRY;

  return result;
}

/* ============================================================================
 * Internal Verification Callback
 * ============================================================================
 */

/**
 * get_verify_context - Extract verification context from OpenSSL callback
 * @x509_ctx: Certificate store context
 * @out_sock: Output socket pointer
 * @out_ctx: Output TLS context pointer
 *
 * Returns: 1 if context valid, 0 if missing (use pre_ok result)
 */
static int
get_verify_context (X509_STORE_CTX *x509_ctx, Socket_T *out_sock, T *out_ctx)
{
  SSL *ssl = X509_STORE_CTX_get_ex_data (
      x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx ());

  if (!ssl)
    return 0;

  *out_sock = (Socket_T)SSL_get_app_data (ssl);
  if (!*out_sock)
    return 0;

  *out_ctx = (T)(*out_sock)->tls_ctx;
  return *out_ctx != NULL;
}

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
  Socket_T sock;
  T ctx;

  if (!get_verify_context (x509_ctx, &sock, &ctx))
    return pre_ok;

  /* Step 1: Call user callback if set */
  if (ctx->verify_callback)
    {
      int result = invoke_user_callback (ctx, pre_ok, x509_ctx, sock);
      if (!result)
        return 0;
      pre_ok = result;
    }

  /* Step 2: Check certificate pins at chain end (depth 0) */
  if (ctx->pinning.count > 0)
    {
      int depth = X509_STORE_CTX_get_error_depth (x509_ctx);
      if (depth == 0 && !check_certificate_pins (ctx, x509_ctx))
        return 0;
    }

  return pre_ok;
}

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

/* ============================================================================
 * Public Verification API
 * ============================================================================
 */

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
  X509_STORE *store;
  struct stat st;
  int ret;

  assert (ctx);
  assert (ctx->ssl_ctx);

  if (!crl_path || !*crl_path)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "CRL path cannot be NULL or empty");

  store = SSL_CTX_get_cert_store (ctx->ssl_ctx);
  if (!store)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Failed to get certificate store");

  TRY
  {
    CRL_LOCK (ctx);

    if (stat (crl_path, &st) != 0)
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed, "Invalid CRL path '%s': %s",
                           crl_path, Socket_safe_strerror (errno));

    /* Security check: prevent DoS from oversized CRL files or directories */
    if (!S_ISDIR (st.st_mode))
      {
        size_t file_size = (size_t)st.st_size;
        if (st.st_size < 0 || file_size > SOCKET_TLS_MAX_CRL_SIZE
            || !SocketSecurity_check_size (file_size))
          RAISE_CTX_ERROR_FMT (
              SocketTLS_Failed,
              "CRL file '%s' too large or invalid size: %ld bytes (max %u)",
              crl_path, (long)st.st_size, SOCKET_TLS_MAX_CRL_SIZE);
      }
    else /* Directory CRL load */
      {
        DIR *dirp = opendir (crl_path);
        if (!dirp)
          RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                               "Cannot open CRL directory '%s': %s", crl_path,
                               Socket_safe_strerror (errno));

        struct dirent *de;
        int file_count = 0;
        while ((de = readdir (dirp)) != NULL)
          {
            if (de->d_type
                == DT_REG) /* Count regular files (potential CRLs) */
              {
                file_count++;
                if (file_count > SOCKET_TLS_MAX_CRL_FILES_IN_DIR)
                  {
                    closedir (dirp);
                    RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                                         "CRL directory '%s' has too many "
                                         "files (%d > max %d): potential DoS",
                                         crl_path, file_count,
                                         SOCKET_TLS_MAX_CRL_FILES_IN_DIR);
                  }
              }
          }
        closedir (dirp);
        if (file_count == 0)
          SOCKET_LOG_WARN_MSG ("CRL directory '%s' contains no regular files",
                               crl_path);
      }

    ret = S_ISDIR (st.st_mode)
              ? X509_STORE_load_locations (store, NULL, crl_path)
              : X509_STORE_load_locations (store, crl_path, NULL);

    if (ret != 1)
      ctx_raise_openssl_error ("Failed to load CRL");

    X509_STORE_set_flags (store,
                          X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
  }
  FINALLY { CRL_UNLOCK (ctx); }
  END_TRY;
}

void
SocketTLSContext_refresh_crl (T ctx, const char *crl_path)
{
  /* Note: CRLs accumulate in store on refresh (no OpenSSL clear API).
   * For memory management in long-running apps, recreate context periodically
   * or implement custom CRL store management. Load/refresh appends only. */
  SOCKET_LOG_INFO_MSG ("Refreshing CRL from path '%s' (accumulates in store)",
                       crl_path);

  SocketTLSContext_load_crl (ctx, crl_path);
}

/* ============================================================================
 * Protocol Configuration
 * ============================================================================
 */

/**
 * apply_min_proto_fallback - Fallback for older OpenSSL versions
 * @ctx: TLS context
 * @version: Target minimum version
 */
static void
apply_min_proto_fallback (T ctx, int version)
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
    ctx_raise_openssl_error ("Failed to set minimum TLS protocol version");
#else
  TLS_UNUSED (ctx);
  TLS_UNUSED (version);
  ctx_raise_openssl_error (
      "Failed to set minimum TLS protocol version (fallback unavailable)");
#endif
}

void
SocketTLSContext_set_min_protocol (T ctx, int version)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (SSL_CTX_set_min_proto_version (ctx->ssl_ctx, version) != 1)
    apply_min_proto_fallback (ctx, version);
}

void
SocketTLSContext_set_max_protocol (T ctx, int version)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (SSL_CTX_set_max_proto_version (ctx->ssl_ctx, version) != 1)
    ctx_raise_openssl_error ("Failed to set maximum TLS protocol version");
}

void
SocketTLSContext_set_cipher_list (T ctx, const char *ciphers)
{
  const char *list;

  assert (ctx);
  assert (ctx->ssl_ctx);

  list = ciphers ? ciphers : SOCKET_TLS_LEGACY_CIPHER_LIST;

  if (SSL_CTX_set_cipher_list (ctx->ssl_ctx, list) != 1)
    ctx_raise_openssl_error ("Failed to set cipher list");
}

/* ============================================================================
 * OCSP Stapling Server-Side
 * ============================================================================
 */

/**
 * encode_ocsp_response - Encode OCSP response to DER format
 * @resp: OCSP response to encode
 * @out_der: Output DER buffer (OPENSSL_malloc'd)
 *
 * Returns: DER length on success, 0 on failure (out_der set to NULL)
 */
static int
encode_ocsp_response (OCSP_RESPONSE *resp, unsigned char **out_der)
{
  *out_der = NULL;
  int len = i2d_OCSP_RESPONSE (resp, out_der);
  return (len > 0 && *out_der) ? len : 0;
}

/**
 * status_cb_wrapper - OpenSSL OCSP status callback wrapper
 * @ssl: SSL connection
 * @arg: User argument (unused)
 *
 * Returns: SSL_TLSEXT_ERR_OK or SSL_TLSEXT_ERR_NOACK
 *
 * Note: SSL_set_tlsext_status_ocsp_resp takes ownership of DER buffer.
 */
static int
status_cb_wrapper (SSL *ssl, void *arg)
{
  unsigned char *der = NULL;
  OCSP_RESPONSE *resp;
  int len;

  TLS_UNUSED (arg);

  T ctx = tls_context_get_from_ssl (ssl);
  if (!ctx || !ctx->ocsp_gen_cb)
    return SSL_TLSEXT_ERR_NOACK;

  resp = ctx->ocsp_gen_cb (ssl, ctx->ocsp_gen_arg);
  if (!resp)
    return SSL_TLSEXT_ERR_NOACK;

  len = encode_ocsp_response (resp, &der);
  OCSP_RESPONSE_free (resp);

  if (len == 0)
    {
      if (der)
        OPENSSL_free (der);
      return SSL_TLSEXT_ERR_NOACK;
    }
  else if (len > SOCKET_TLS_MAX_OCSP_RESPONSE_LEN)
    {
      if (der)
        OPENSSL_free (der);
      return SSL_TLSEXT_ERR_NOACK;
    }

  /* OpenSSL takes ownership of der buffer */
  SSL_set_tlsext_status_ocsp_resp (ssl, der, len);
  return SSL_TLSEXT_ERR_OK;
}

/**
 * validate_ocsp_response_size - Check response doesn't exceed limits
 * @len: Response length
 */
static void
validate_ocsp_response_size (size_t len)
{
  if (len > SOCKET_TLS_MAX_OCSP_RESPONSE_LEN)
    RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                         "OCSP response too large (%zu bytes, max %d)", len,
                         SOCKET_TLS_MAX_OCSP_RESPONSE_LEN);
}

/**
 * validate_ocsp_response_format - Validate response DER format
 * @response: Response bytes
 * @len: Response length
 */
static void
validate_ocsp_response_format (const unsigned char *response, size_t len)
{
  const unsigned char *p = response;
  OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE (NULL, &p, len);

  if (!resp)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Invalid OCSP response format");

  OCSP_RESPONSE_free (resp);
}

void
SocketTLSContext_set_ocsp_response (T ctx, const unsigned char *response,
                                    size_t len)
{
  unsigned char *copy;

  assert (ctx);
  assert (ctx->ssl_ctx);

  if (!response || len == 0)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "Invalid OCSP response (null or zero length)");

  validate_ocsp_response_size (len);
  validate_ocsp_response_format (response, len);

  copy = ctx_arena_alloc (ctx, len, "Failed to allocate OCSP response buffer");
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

  ERR_clear_error ();
  SSL_CTX_set_tlsext_status_cb (ctx->ssl_ctx, status_cb_wrapper);
}

/* ============================================================================
 * OCSP Status Query (Socket-side)
 * ============================================================================
 */

/**
 * validate_socket_for_ocsp - Check socket is ready for OCSP query
 * @socket: Socket to validate
 *
 * Returns: 1 if valid, 0 otherwise
 */
static int
validate_socket_for_ocsp (const Socket_T socket)
{
  return socket && socket->tls_enabled && socket->tls_ssl
         && socket->tls_handshake_done;
}

/**
 * get_ocsp_response_bytes - Get raw OCSP response from SSL
 * @ssl: SSL connection
 * @resp_bytes: Output pointer (OpenSSL-owned, do not free)
 *
 * Returns: Length of response, or 0 if none
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
 * Returns: 1 if valid, OCSP error status otherwise
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
  const unsigned char *resp_bytes;
  const unsigned char *p;
  OCSP_RESPONSE *resp;
  int resp_len, status, result;
  SSL *ssl;

  if (!validate_socket_for_ocsp (socket))
    return 0;

  ssl = (SSL *)socket->tls_ssl;
  resp_len = get_ocsp_response_bytes (ssl, &resp_bytes);
  if (resp_len <= 0 || resp_len > SOCKET_TLS_MAX_OCSP_RESPONSE_LEN)
    return 0;

  p = resp_bytes;
  resp = d2i_OCSP_RESPONSE (NULL, &p, resp_len);
  if (!resp)
    return OCSP_RESPONSE_STATUS_MALFORMEDREQUEST;

  status = OCSP_response_status (resp);
  if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    {
      OCSP_RESPONSE_free (resp);
      return status;
    }

  result = validate_ocsp_basic_response (resp);
  OCSP_RESPONSE_free (resp);
  return result;
}

/* ============================================================================
 * OCSP Stapling Client Enable
 * ============================================================================
 */

void
SocketTLSContext_enable_ocsp_stapling (T ctx)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (ctx->is_server)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "OCSP stapling request is for client contexts only");

  if (SSL_CTX_set_tlsext_status_type (ctx->ssl_ctx, TLSEXT_STATUSTYPE_ocsp)
      != 1)
    ctx_raise_openssl_error ("Failed to enable OCSP stapling request");

  ctx->ocsp_stapling_enabled = 1;
}

int
SocketTLSContext_ocsp_stapling_enabled (T ctx)
{
  assert (ctx);
  return ctx->ocsp_stapling_enabled;
}

/* ============================================================================
 * Custom Certificate Store Callback
 * ============================================================================
 */

void
SocketTLSContext_set_cert_lookup_callback (
    T ctx, SocketTLSCertLookupCallback callback, void *user_data)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  ctx->cert_lookup_callback = (void *)callback;
  ctx->cert_lookup_user_data = user_data;

  /* Note: Callback available for use in custom verify callbacks.
   * OpenSSL doesn't have built-in hook for certificate lookup.
   * See header documentation for usage pattern. */
}

#undef T

#endif /* SOCKET_HAS_TLS */

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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
#include "core/SocketUtil.h"
#include "tls/SocketTLS-private.h"
#include "tls/SocketSSL-internal.h"
#include <assert.h>

/* Thread-local exception for SocketTLSContext module */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketTLSContext);
#include <dirent.h>
#include <errno.h>
#include <openssl/ocsp.h>
#include <string.h>
#include <sys/stat.h>

#define T SocketTLSContext_T


/**
 * Default cipher list for legacy TLS (< 1.3) when user doesn't specify.
 * Excludes weak ciphers while maintaining compatibility.
 * For TLS 1.3+, use SOCKET_TLS13_CIPHERSUITES from SocketTLSConfig.h.
 */
#ifndef SOCKET_TLS_LEGACY_CIPHER_LIST
#define SOCKET_TLS_LEGACY_CIPHER_LIST \
  "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA"
#endif

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
 * needs_internal_callback - Check if internal callback should be installed
 * @ctx: TLS context
 *
 * Returns: 1 if callback needed, 0 otherwise
 */
static int
needs_internal_callback (T ctx)
{
  return ctx->verify_callback != NULL || ctx->pinning.count > 0
         || ctx->ocsp_must_staple_mode != OCSP_MUST_STAPLE_DISABLED;
}

/**
 * apply_verify_settings - Apply verification mode and callback to context
 * @ctx: TLS context
 *
 * Consolidates SSL_CTX_set_verify call. Clears OpenSSL error queue first
 * for clean error state.
 */
static void
apply_verify_settings (T ctx)
{
  int openssl_mode = verify_mode_to_openssl (ctx->verify_mode);
  SSL_verify_cb cb = needs_internal_callback (ctx)
                         ? (SSL_verify_cb)internal_verify_callback
                         : NULL;

  ERR_clear_error ();
  SSL_CTX_set_verify (ctx->ssl_ctx, openssl_mode, cb);
}

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
  int result;

  if (tls_pinning_extract_spki_hash (cert, hash) != 0)
    return 0;

  pthread_mutex_lock (&ctx->pinning.lock);
  result = tls_pinning_find (ctx->pinning.pins, ctx->pinning.count, hash);
  pthread_mutex_unlock (&ctx->pinning.lock);

  return result;
}

/**
 * get_pin_enforcement - Thread-safe read of enforcement mode
 * @ctx: TLS context
 *
 * Returns: 1 if enforce mode, 0 if warn-only
 */
static int
get_pin_enforcement (T ctx)
{
  int enforce;

  pthread_mutex_lock (&ctx->pinning.lock);
  enforce = ctx->pinning.enforce;
  pthread_mutex_unlock (&ctx->pinning.lock);

  return enforce;
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
  if (get_pin_enforcement (ctx))
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
 * get_pin_count_locked - Thread-safe read of pin count
 * @ctx: TLS context
 *
 * Returns: Number of configured pins
 */
static size_t
get_pin_count_locked (T ctx)
{
  size_t count;

  pthread_mutex_lock (&ctx->pinning.lock);
  count = ctx->pinning.count;
  pthread_mutex_unlock (&ctx->pinning.lock);

  return count;
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
  int match;
  int allocated = 0;

  assert (ctx);

  /* Early exit if no pins configured - avoid unnecessary locking */
  if (get_pin_count_locked (ctx) == 0)
    return 1;

  chain = X509_STORE_CTX_get0_chain (x509_ctx);
  if (!chain)
    {
      chain = X509_STORE_CTX_get1_chain (x509_ctx);
      if (!chain)
        return check_current_cert_pin (ctx, x509_ctx);
      allocated = 1;
    }

  match = tls_pinning_check_chain (ctx, chain);

  if (allocated)
    sk_X509_pop_free (chain, X509_free);

  if (match)
    return 1;

  return handle_pin_mismatch (ctx, x509_ctx);
}

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
invoke_user_callback (T ctx,
                      int pre_ok,
                      X509_STORE_CTX *x509_ctx,
                      Socket_T sock)
{
  volatile int result = pre_ok;

  TRY
  {
    result = ctx->verify_callback (
        pre_ok, x509_ctx, ctx, sock, ctx->verify_user_data);
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
  SSL *ssl = X509_STORE_CTX_get_ex_data (x509_ctx,
                                         SSL_get_ex_data_X509_STORE_CTX_idx ());

  if (!ssl)
    return 0;

  *out_sock = (Socket_T)SSL_get_app_data (ssl);
  if (!*out_sock)
    return 0;

  *out_ctx = (T)(*out_sock)->tls_ctx;
  return *out_ctx != NULL;
}

/**
 * OcspValidateMode - Error handling mode for OCSP validation
 */
typedef enum
{
  OCSP_VALIDATE_RETURN_CODE, /* Return 0/1 with logging */
  OCSP_VALIDATE_RAISE,       /* Raise exception on failure */
} OcspValidateMode;

/**
 * validate_ocsp_response - Unified OCSP response validation
 * @response: DER-encoded OCSP response
 * @len: Length of response
 * @check_basic: If true, also validate OCSP_BASICRESP structure
 * @mode: Error handling mode (return code vs exception)
 * @context: Context string for error messages
 *
 * Validates OCSP response format, status, and optionally basic response
 * structure in a single parse pass to avoid redundant parsing operations.
 *
 * Returns: 1 if valid, 0 if invalid (RETURN_CODE mode only)
 * Raises: SocketTLS_Failed (RAISE mode only)
 */
static int
validate_ocsp_response (const unsigned char *response,
                        size_t len,
                        int check_basic,
                        OcspValidateMode mode,
                        const char *context)
{
  const unsigned char *p = response;
  OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE (NULL, &p, len);
  OCSP_BASICRESP *basic = NULL;
  int status;

  if (!resp)
    {
      if (mode == OCSP_VALIDATE_RAISE)
        RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Invalid OCSP response format");
      SOCKET_LOG_ERROR_MSG ("%s: Invalid OCSP response format", context);
      return 0;
    }

  status = OCSP_response_status (resp);
  if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    {
      OCSP_RESPONSE_free (resp);
      if (mode == OCSP_VALIDATE_RAISE)
        RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                             "OCSP response status not successful: %d",
                             status);
      SOCKET_LOG_ERROR_MSG (
          "%s: OCSP response status not successful: %d", context, status);
      return 0;
    }

  if (check_basic)
    {
      basic = OCSP_response_get1_basic (resp);
      if (!basic)
        {
          OCSP_RESPONSE_free (resp);
          if (mode == OCSP_VALIDATE_RAISE)
            RAISE_CTX_ERROR_MSG (
                SocketTLS_Failed,
                "OCSP response missing basic response structure");
          SOCKET_LOG_ERROR_MSG ("%s: OCSP response missing basic response",
                                context);
          return 0;
        }
      OCSP_BASICRESP_free (basic);
    }

  OCSP_RESPONSE_free (resp);
  return 1;
}

/**
 * check_ocsp_must_staple - Verify OCSP stapling requirements
 * @ctx: TLS context with must-staple config
 * @sock: Socket being verified
 * @cert: Peer certificate (depth 0)
 *
 * Checks if OCSP Must-Staple requirements are satisfied:
 * - If mode is DISABLED, always returns 1 (pass)
 * - If mode is AUTO, checks cert for must-staple extension
 * - If mode is ALWAYS or cert has must-staple, requires valid OCSP response
 *
 * Returns: 1 if requirements satisfied, 0 if failed
 */
static int
check_ocsp_must_staple (T ctx, Socket_T sock, X509 *cert)
{
  int must_require_ocsp = 0;
  SSL *ssl;
  const unsigned char *ocsp_resp = NULL;
  long ocsp_len;

  /* Check if must-staple enforcement is enabled */
  if (ctx->ocsp_must_staple_mode == OCSP_MUST_STAPLE_DISABLED)
    return 1; /* Disabled - pass */

  if (ctx->ocsp_must_staple_mode == OCSP_MUST_STAPLE_ALWAYS)
    {
      must_require_ocsp = 1;
    }
  else if (ctx->ocsp_must_staple_mode == OCSP_MUST_STAPLE_AUTO)
    {
      /* Check if certificate has must-staple extension */
      must_require_ocsp = SocketTLSContext_cert_has_must_staple (cert);
    }

  if (!must_require_ocsp)
    return 1; /* No OCSP requirement - pass */

  /* OCSP stapling is required - check for valid response */
  ssl = (SSL *)sock->tls_ssl;
  if (!ssl)
    {
      SOCKET_LOG_ERROR_MSG ("OCSP Must-Staple: SSL object not available");
      return 0;
    }

  ocsp_len = SSL_get_tlsext_status_ocsp_resp (ssl, &ocsp_resp);

  if (ocsp_len <= 0 || !ocsp_resp)
    {
      SOCKET_LOG_ERROR_MSG (
          "OCSP Must-Staple: Certificate requires OCSP stapling but no "
          "response was provided by the server");
      return 0; /* No OCSP response - fail */
    }

  /* Validate the OCSP response */
  if (!validate_ocsp_response (ocsp_resp,
                               ocsp_len,
                               0,
                               OCSP_VALIDATE_RETURN_CODE,
                               "OCSP Must-Staple"))
    return 0;

  SOCKET_LOG_DEBUG_MSG ("OCSP Must-Staple: Valid OCSP response present");
  return 1; /* OCSP requirement satisfied */
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
  int result;
  int depth;

  if (!get_verify_context (x509_ctx, &sock, &ctx))
    return pre_ok;

  /* Step 1: Call user callback if set */
  if (ctx->verify_callback)
    {
      result = invoke_user_callback (ctx, pre_ok, x509_ctx, sock);
      if (!result)
        return 0;
      pre_ok = result;
    }

  depth = X509_STORE_CTX_get_error_depth (x509_ctx);

  /* Step 2: Check certificate pins at chain end (depth 0) */
  if (ctx->pinning.count > 0)
    {
      if (depth == 0 && !check_certificate_pins (ctx, x509_ctx))
        return 0;
    }

  /* Step 3: Check OCSP Must-Staple at chain end (depth 0) */
  if (depth == 0 && ctx->ocsp_must_staple_mode != OCSP_MUST_STAPLE_DISABLED)
    {
      X509 *cert = X509_STORE_CTX_get_current_cert (x509_ctx);
      if (!check_ocsp_must_staple (ctx, sock, cert))
        {
          X509_STORE_CTX_set_error (x509_ctx,
                                    X509_V_ERR_APPLICATION_VERIFICATION);
          return 0;
        }
    }

  return pre_ok;
}

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

void
SocketTLSContext_set_verify_mode (T ctx, TLSVerifyMode mode)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  ctx->verify_mode = mode;
  apply_verify_settings (ctx);
}

void
SocketTLSContext_set_verify_callback (T ctx,
                                      SocketTLSVerifyCallback callback,
                                      void *user_data)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  ctx->verify_callback = callback;
  ctx->verify_user_data = user_data;
  apply_verify_settings (ctx);
}

/**
 * validate_crl_file_size - Check CRL file size against limits
 * @path: CRL file path
 * @st: stat structure for the file
 *
 * Raises: SocketTLS_Failed if file too large or invalid
 */
static void
validate_crl_file_size (const char *path, const struct stat *st)
{
  size_t file_size;

  if (st->st_size < 0)
    RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                         "CRL file '%s' has invalid size: %ld bytes",
                         path,
                         (long)st->st_size);

  file_size = (size_t)st->st_size;
  if (file_size > SOCKET_TLS_MAX_CRL_SIZE
      || !SocketSecurity_check_size (file_size))
    RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                         "CRL file '%s' too large: %ld bytes (max %u)",
                         path,
                         (long)st->st_size,
                         SOCKET_TLS_MAX_CRL_SIZE);
}

/**
 * validate_crl_directory - Check CRL directory for DoS limits
 * @path: CRL directory path
 *
 * Raises: SocketTLS_Failed if too many files or cannot open
 */
static void
validate_crl_directory (const char *path)
{
  DIR *dirp;
  struct dirent *de;
  int file_count = 0;

  dirp = opendir (path);
  if (!dirp)
    RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                         "Cannot open CRL directory '%s': %s",
                         path,
                         Socket_safe_strerror (errno));

  while ((de = readdir (dirp)) != NULL)
    {
      if (de->d_type == DT_REG)
        {
          file_count++;
          if (file_count > SOCKET_TLS_MAX_CRL_FILES_IN_DIR)
            {
              closedir (dirp);
              RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                                   "CRL directory '%s' has too many "
                                   "files (%d > max %d): potential DoS",
                                   path,
                                   file_count,
                                   SOCKET_TLS_MAX_CRL_FILES_IN_DIR);
            }
        }
    }
  closedir (dirp);

  if (file_count == 0)
    SOCKET_LOG_WARN_MSG ("CRL directory '%s' contains no regular files", path);
}

/**
 * load_and_validate_crl - Load CRL with validation
 * @store: X509_STORE to load into
 * @crl_path: Path to CRL file or directory
 * @is_directory: Output - set to 1 if path is directory, 0 otherwise
 *
 * Validates path, checks size limits, and loads CRL into the store.
 * Raises SocketTLS_Failed on error.
 */
static void
load_and_validate_crl (X509_STORE *store,
                       const char *crl_path,
                       int *is_directory)
{
  struct stat st;
  int ret;

  if (stat (crl_path, &st) != 0)
    RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                         "Invalid CRL path '%s': %s",
                         crl_path,
                         Socket_safe_strerror (errno));

  *is_directory = S_ISDIR (st.st_mode);

  /* Security check: prevent DoS from oversized CRL files or directories */
  if (*is_directory)
    validate_crl_directory (crl_path);
  else
    validate_crl_file_size (crl_path, &st);

  ret = *is_directory ? X509_STORE_load_locations (store, NULL, crl_path)
                      : X509_STORE_load_locations (store, crl_path, NULL);

  if (ret != 1)
    ctx_raise_openssl_error ("Failed to load CRL");
}

void
SocketTLSContext_load_crl (T ctx, const char *crl_path)
{
  X509_STORE *store;
  int is_directory;

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
    load_and_validate_crl (store, crl_path, &is_directory);
    X509_STORE_set_flags (store,
                          X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
  }
  FINALLY
  {
    CRL_UNLOCK (ctx);
  }
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

void
SocketTLSContext_reload_crl (T ctx, const char *crl_path)
{
  /* Alias for refresh_crl() - provided for semantic clarity.
   * Use when you have downloaded an updated CRL and want to reload it. */
  SocketTLSContext_refresh_crl (ctx, crl_path);
}

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
  long current;

  if (version > TLS1_VERSION)
    options |= SSL_OP_NO_TLSv1;
  if (version > TLS1_1_VERSION)
    options |= SSL_OP_NO_TLSv1_1;
  if (version > TLS1_2_VERSION)
    options |= SSL_OP_NO_TLSv1_2;

  current = SSL_CTX_set_options (ctx->ssl_ctx, options);
  if (!(current & options))
    ctx_raise_openssl_error ("Failed to set minimum TLS protocol version");
#else
  TLS_UNUSED (ctx);
  TLS_UNUSED (version);
  ctx_raise_openssl_error (
      "Failed to set minimum TLS protocol version (fallback unavailable)");
#endif
}

/**
 * version_name - Get human-readable TLS version name
 * @version: OpenSSL protocol version constant
 *
 * Returns: Static string with version name for logging
 */
static const char *
version_name (int version)
{
  switch (version)
    {
    case TLS1_VERSION:
      return "TLS 1.0";
    case TLS1_1_VERSION:
      return "TLS 1.1";
    case TLS1_2_VERSION:
      return "TLS 1.2";
    case TLS1_3_VERSION:
      return "TLS 1.3";
    default:
      return "Unknown";
    }
}

void
SocketTLSContext_set_min_protocol (T ctx, int version)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  /* Security warning: TLS versions below 1.3 have known weaknesses */
  if (version < TLS1_3_VERSION)
    {
      SOCKET_LOG_WARN_MSG (
          "SECURITY WARNING: Setting minimum TLS version to %s "
          "(0x%04X) - versions below TLS 1.3 have known vulnerabilities "
          "(POODLE, BEAST, Lucky13). Consider using TLS 1.3 (0x%04X) for "
          "production environments.",
          version_name (version),
          version,
          TLS1_3_VERSION);
    }

  if (SSL_CTX_set_min_proto_version (ctx->ssl_ctx, version) != 1)
    apply_min_proto_fallback (ctx, version);
}

void
SocketTLSContext_set_max_protocol (T ctx, int version)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  /* Validate version is a known TLS version */
  if (version != TLS1_VERSION && version != TLS1_1_VERSION
      && version != TLS1_2_VERSION && version != TLS1_3_VERSION && version != 0)
    {
      SOCKET_LOG_WARN_MSG (
          "Unknown TLS version constant 0x%04X passed to "
          "SocketTLSContext_set_max_protocol - this may not work as expected",
          version);
    }

  /* Security info: log max version for debugging */
  if (version < TLS1_3_VERSION && version != 0)
    {
      SOCKET_LOG_WARN_MSG (
          "SECURITY WARNING: Setting maximum TLS version to %s "
          "(0x%04X) - this limits connections to older protocols with known "
          "vulnerabilities. Ensure this is intentional.",
          version_name (version),
          version);
    }

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

int
SocketTLSContext_validate_cipher_list (const char *ciphers)
{
  SSL_CTX *tmp_ctx;
  int result;

  if (!ciphers || !*ciphers)
    return 0;

  /* Create temporary context for validation */
  tmp_ctx = SSL_CTX_new (TLS_method ());
  if (!tmp_ctx)
    {
      ERR_clear_error ();
      return 0;
    }

  /* Try to set the cipher list - returns 1 on success, 0 on failure */
  result = SSL_CTX_set_cipher_list (tmp_ctx, ciphers);

  /* Clean up temporary context */
  SSL_CTX_free (tmp_ctx);
  ERR_clear_error ();

  return result == 1 ? 1 : 0;
}

void
SocketTLSContext_set_ciphersuites (T ctx, const char *ciphersuites)
{
  const char *list;

  assert (ctx);
  assert (ctx->ssl_ctx);

  list = ciphersuites ? ciphersuites : SOCKET_TLS13_CIPHERSUITES;

  if (SSL_CTX_set_ciphersuites (ctx->ssl_ctx, list) != 1)
    ctx_raise_openssl_error ("Failed to set TLS 1.3 ciphersuites");
}

int
SocketTLSContext_validate_ciphersuites (const char *ciphersuites)
{
  SSL_CTX *tmp_ctx;
  int result;

  if (!ciphersuites || !*ciphersuites)
    return 0;

  /* Create temporary context for validation */
  tmp_ctx = SSL_CTX_new (TLS_method ());
  if (!tmp_ctx)
    {
      ERR_clear_error ();
      return 0;
    }

  /* Set TLS 1.3 as minimum to ensure ciphersuites are validated */
  SSL_CTX_set_min_proto_version (tmp_ctx, TLS1_3_VERSION);

  /* Try to set the ciphersuites - returns 1 on success, 0 on failure */
  result = SSL_CTX_set_ciphersuites (tmp_ctx, ciphersuites);

  /* Clean up temporary context */
  SSL_CTX_free (tmp_ctx);
  ERR_clear_error ();

  return result == 1 ? 1 : 0;
}

/**
 * encode_ocsp_response - Encode OCSP response to DER format
 * @resp: OCSP response to encode
 * @out_der: Output DER buffer (OPENSSL_malloc'd)
 *
 * Security: Pre-checks encoded size before allocation to prevent
 * memory exhaustion from maliciously large OCSP responses.
 *
 * Returns: DER length on success, 0 on failure (out_der set to NULL)
 */
static int
encode_ocsp_response (OCSP_RESPONSE *resp, unsigned char **out_der)
{
  int len;

  *out_der = NULL;

  /* Security: Pre-check encoded size before allocating memory.
   * Passing NULL to i2d_OCSP_RESPONSE returns the required size
   * without allocating, preventing DoS via memory exhaustion. */
  len = i2d_OCSP_RESPONSE (resp, NULL);
  if (len <= 0 || len > SOCKET_TLS_MAX_OCSP_RESPONSE_LEN)
    return 0;

  /* Now allocate and encode - size is known to be safe */
  len = i2d_OCSP_RESPONSE (resp, out_der);

  /* i2d returns negative on error; positive on success with allocation */
  return (len > 0) ? len : 0;
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
  T ctx;

  TLS_UNUSED (arg);

  ctx = tls_context_get_from_ssl (ssl);
  if (!ctx || !ctx->ocsp_gen_cb)
    return SSL_TLSEXT_ERR_NOACK;

  resp = ctx->ocsp_gen_cb (ssl, ctx->ocsp_gen_arg);
  if (!resp)
    return SSL_TLSEXT_ERR_NOACK;

  len = encode_ocsp_response (resp, &der);
  OCSP_RESPONSE_free (resp);

  /* Check encoding result (encode_ocsp_response validates size internally) */
  if (len == 0)
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
                         "OCSP response too large (%zu bytes, max %d)",
                         len,
                         SOCKET_TLS_MAX_OCSP_RESPONSE_LEN);
}

void
SocketTLSContext_set_ocsp_response (T ctx,
                                    const unsigned char *response,
                                    size_t len)
{
  unsigned char *copy;

  assert (ctx);
  assert (ctx->ssl_ctx);

  if (!response || len == 0)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "Invalid OCSP response (null or zero length)");

  validate_ocsp_response_size (len);
  validate_ocsp_response (
      response, len, 1, OCSP_VALIDATE_RAISE, "OCSP response validation");

  copy = ctx_arena_alloc (ctx, len, "Failed to allocate OCSP response buffer");
  memcpy (copy, response, len);
  ctx->ocsp_response = copy;
  ctx->ocsp_len = len;
}

void
SocketTLSContext_set_ocsp_gen_callback (T ctx,
                                        SocketTLSOcspGenCallback cb,
                                        void *arg)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  ctx->ocsp_gen_cb = cb;
  ctx->ocsp_gen_arg = arg;

  ERR_clear_error ();
  SSL_CTX_set_tlsext_status_cb (ctx->ssl_ctx, status_cb_wrapper);
}

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
  int resp_len;
  int status;
  SSL *ssl;

  if (!validate_socket_for_ocsp (socket))
    return 0;

  ssl = (SSL *)socket->tls_ssl;
  resp_len = get_ocsp_response_bytes (ssl, &resp_bytes);

  /* No response or response exceeds limit */
  if (resp_len == 0 || resp_len > SOCKET_TLS_MAX_OCSP_RESPONSE_LEN)
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

  status = validate_ocsp_basic_response (resp);
  OCSP_RESPONSE_free (resp);

  return status;
}

/* OID for id-pe-tlsfeature: 1.3.6.1.5.5.7.1.24
 * status_request value per RFC 6066 / RFC 7633 */
#define OCSP_MUST_STAPLE_STATUS_REQUEST 5

/* Maximum number of TLS Feature extension entries to parse (DoS mitigation).
 * RFC 7633 defines only one feature value (status_request = 5).
 * Even with future extensions, 100 entries is extremely generous. */
#define MAX_TLSFEATURE_ENTRIES 100

/**
 * find_tlsfeature_extension - Find TLS Feature extension by OID
 * @cert: X509 certificate to search
 *
 * Returns: Extension index, or -1 if not found
 */
static int
find_tlsfeature_extension (const X509 *cert)
{
  int idx = -1;

  /* Try by NID first (OpenSSL 1.1.0+ defines NID_tlsfeature) */
#ifdef NID_tlsfeature
  idx = X509_get_ext_by_NID ((X509 *)cert, NID_tlsfeature, -1);
  if (idx >= 0)
    return idx;
#endif

  /* Fallback: search by OID string for older OpenSSL or if NID lookup failed */
  {
    ASN1_OBJECT *obj = OBJ_txt2obj ("1.3.6.1.5.5.7.1.24", 1);
    if (obj)
      {
        idx = X509_get_ext_by_OBJ ((X509 *)cert, obj, -1);
        ASN1_OBJECT_free (obj);
      }
  }

  return idx;
}

/**
 * parse_tlsfeature_extension_for_status_request - Parse TLS Feature extension
 * for status_request
 * @p: Pointer to extension data
 * @ext_len: Length of extension data
 *
 * Parses the ASN.1 SEQUENCE OF INTEGER looking for status_request (5) value.
 *
 * Returns: 1 if status_request found, 0 otherwise
 */
static int
parse_tlsfeature_extension_for_status_request (const unsigned char *p,
                                               long ext_len)
{
  const unsigned char *end = p + ext_len;
  long seq_len;
  int tag, xclass;

  /* Expect SEQUENCE */
  if (ASN1_get_object (&p, &seq_len, &tag, &xclass, ext_len) != 0)
    return 0;

  if (tag != V_ASN1_SEQUENCE)
    return 0;

  end = p + seq_len;

  /* Iterate through integers in sequence */
  int iteration = 0;
  while (p < end)
    {
      ASN1_INTEGER *aint = NULL;
      long value;

      /* Prevent DoS from excessive entries */
      if (++iteration > MAX_TLSFEATURE_ENTRIES)
        break;

      aint = d2i_ASN1_INTEGER (NULL, &p, end - p);
      if (!aint)
        break;

      value = ASN1_INTEGER_get (aint);
      ASN1_INTEGER_free (aint);

      /* ASN1_INTEGER_get returns -1 on error or overflow */
      if (value < 0)
        continue; /* Skip invalid value and continue parsing */

      /* status_request = 5 per RFC 6066 / RFC 7633 */
      if (value == OCSP_MUST_STAPLE_STATUS_REQUEST)
        return 1; /* Must-staple found */
    }

  return 0; /* status_request (5) not found */
}

/**
 * SocketTLSContext_cert_has_must_staple - Check certificate for OCSP
 * Must-Staple extension
 * @cert: X509 certificate to examine
 *
 * Checks for id-pe-tlsfeature extension containing status_request (5).
 *
 * Returns: 1 if must-staple is present, 0 otherwise
 */
int
SocketTLSContext_cert_has_must_staple (const X509 *cert)
{
  int idx = -1;
  ASN1_OCTET_STRING *ext_data;
  const unsigned char *p;
  long ext_len;

  if (!cert)
    return 0;

  /* Find the TLS Feature extension (id-pe-tlsfeature) */
  idx = find_tlsfeature_extension (cert);

  if (idx < 0)
    return 0; /* Extension not present */

  X509_EXTENSION *ext = X509_get_ext ((X509 *)cert, idx);
  if (!ext)
    return 0;

  /* Get extension data */
  ext_data = X509_EXTENSION_get_data (ext);
  if (!ext_data)
    return 0;

  p = ASN1_STRING_get0_data (ext_data);
  ext_len = ASN1_STRING_length (ext_data);

  if (!p || ext_len <= 0)
    return 0;

  return parse_tlsfeature_extension_for_status_request (p, ext_len);
}

void
SocketTLSContext_set_ocsp_must_staple (T ctx, OCSPMustStapleMode mode)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (ctx->is_server)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "OCSP Must-Staple is for client contexts only");

  if (mode < OCSP_MUST_STAPLE_DISABLED || mode > OCSP_MUST_STAPLE_ALWAYS)
    RAISE_CTX_ERROR_MSG (
        SocketTLS_Failed, "Invalid OCSP Must-Staple mode: %d", mode);

  ctx->ocsp_must_staple_mode = mode;

  /* Auto-enable OCSP stapling request when must-staple is enabled */
  if (mode != OCSP_MUST_STAPLE_DISABLED && !ctx->ocsp_stapling_enabled)
    {
      SOCKET_LOG_INFO_MSG ("Enabling OCSP stapling request (required for "
                           "Must-Staple enforcement)");
      SocketTLSContext_enable_ocsp_stapling (ctx);
    }

  /* Update verify settings to install/remove internal callback */
  apply_verify_settings (ctx);
}

OCSPMustStapleMode
SocketTLSContext_get_ocsp_must_staple (T ctx)
{
  assert (ctx);
  return (OCSPMustStapleMode)ctx->ocsp_must_staple_mode;
}

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

/* X509_STORE_set_lookup_certs_cb is only available in OpenSSL 3.0.0+
 * Check for OPENSSL_VERSION_NUMBER >= SOCKET_OPENSSL_VERSION_3_0 */
#if OPENSSL_VERSION_NUMBER >= SOCKET_OPENSSL_VERSION_3_0

/* Security: Dynamically allocated ex_data index to avoid conflicts with
 * other libraries using X509_STORE ex_data. Using hardcoded index 0
 * could cause resource conflicts and potential security issues. */
static int x509_store_exdata_idx = -1;
static pthread_once_t x509_store_exdata_once = PTHREAD_ONCE_INIT;

/**
 * init_x509_store_exdata_index - Initialize X509_STORE ex_data index
 *
 * Called once via pthread_once to allocate a unique ex_data index.
 */
static void
init_x509_store_exdata_index (void)
{
  x509_store_exdata_idx
      = X509_STORE_get_ex_new_index (0, NULL, NULL, NULL, NULL);
}

/**
 * get_x509_store_exdata_index - Get the allocated ex_data index
 *
 * Returns: Allocated index, or -1 if allocation failed
 */
static int
get_x509_store_exdata_index (void)
{
  pthread_once (&x509_store_exdata_once, init_x509_store_exdata_index);
  return x509_store_exdata_idx;
}

/**
 * cert_lookup_wrapper - Internal wrapper for X509_STORE lookup callback
 * @store_ctx: OpenSSL X509_STORE_CTX (from which we get our context)
 * @name: X509_NAME being looked up (issuer subject name)
 *
 * This callback is invoked by OpenSSL during certificate chain building
 * when it needs to find certificates matching a given subject name.
 * We retrieve our stored user callback and invoke it.
 *
 * Returns: STACK_OF(X509) containing matching certificates (caller takes
 *          ownership of stack and certs), or NULL if none found.
 *
 * Thread-safe: Yes, if user callback is thread-safe
 */
static STACK_OF (X509)
    * cert_lookup_wrapper (X509_STORE_CTX *store_ctx, const X509_NAME *name)
{
  STACK_OF (X509) *result = NULL;

  /* Get the SSL_CTX from the X509_STORE_CTX */
  X509_STORE *store = X509_STORE_CTX_get0_store (store_ctx);
  if (!store)
    return NULL;

  /* Retrieve our SocketTLSContext_T from the X509_STORE ex_data.
   * Uses dynamically allocated index to avoid conflicts with other libraries.
   */
  int idx = get_x509_store_exdata_index ();
  if (idx < 0)
    return NULL;

  T ctx = (T)X509_STORE_get_ex_data (store, idx);
  if (!ctx)
    return NULL;

  SocketTLSCertLookupCallback user_cb
      = (SocketTLSCertLookupCallback)ctx->cert_lookup_callback;
  if (!user_cb)
    return NULL;

  /* Call user's lookup callback
   * User returns a single X509* which they allocate - we take ownership */
  X509 *cert = user_cb (store_ctx, name, ctx->cert_lookup_user_data);
  if (!cert)
    return NULL;

  /* Wrap single certificate in a STACK_OF(X509) as OpenSSL expects */
  result = sk_X509_new_null ();
  if (!result)
    {
      X509_free (cert);
      return NULL;
    }

  if (!sk_X509_push (result, cert))
    {
      X509_free (cert);
      sk_X509_free (result);
      return NULL;
    }

  return result;
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

void
SocketTLSContext_set_cert_lookup_callback (T ctx,
                                           SocketTLSCertLookupCallback callback,
                                           void *user_data)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  ctx->cert_lookup_callback = (void *)callback;
  ctx->cert_lookup_user_data = user_data;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  /* OpenSSL 3.0+: Use X509_STORE_set_lookup_certs_cb for automatic integration
   */
  X509_STORE *store = SSL_CTX_get_cert_store (ctx->ssl_ctx);
  if (!store)
    {
      RAISE_CTX_ERROR_MSG (
          SocketTLS_Failed,
          "Failed to get certificate store for lookup callback");
    }

  /* Get dynamically allocated ex_data index */
  int exdata_idx = get_x509_store_exdata_index ();
  if (exdata_idx < 0)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Failed to allocate X509_STORE ex_data index");
    }

  if (callback)
    {
      /* Store our context in the X509_STORE ex_data for retrieval in callback.
       * Uses dynamically allocated index to avoid conflicts with other libs. */
      if (X509_STORE_set_ex_data (store, exdata_idx, ctx) != 1)
        {
          RAISE_CTX_ERROR_MSG (
              SocketTLS_Failed,
              "Failed to set ex_data on X509_STORE for callback context");
        }

      /* Set the lookup callback.
       * X509_STORE_set_lookup_certs registers a function that OpenSSL
       * calls when building certificate chains and needing to find
       * issuer certificates by subject name. */
      X509_STORE_set_lookup_certs (store, cert_lookup_wrapper);
    }
  else
    {
      /* Disable custom lookup by clearing the callback */
      X509_STORE_set_lookup_certs (store, NULL);
      X509_STORE_set_ex_data (store, exdata_idx, NULL);
    }
#else
  /* OpenSSL < 3.0.0: X509_STORE_set_lookup_certs_cb not available.
   * Callback is stored and can be used in custom verify callbacks.
   * Users can invoke the callback manually from SocketTLSVerifyCallback. */
  if (callback)
    {
      SOCKET_LOG_INFO_MSG (
          "Certificate lookup callback registered. On OpenSSL < 3.0, "
          "callback must be invoked from custom verify callbacks.");
    }
#endif
}

#undef T

#endif /* SOCKET_HAS_TLS */

/**
 * SocketTLSContext-ct.c - Certificate Transparency Support
 *
 * Part of the Socket Library
 *
 * Implements Certificate Transparency (RFC 6962) verification for TLS clients.
 * CT helps detect mis-issued certificates by requiring them to be logged in
 * publicly auditable CT logs.
 *
 * Requires OpenSSL 1.1.0+ with CT support compiled in.
 *
 * Thread safety: Configuration is NOT thread-safe - perform before sharing.
 */

#if SOCKET_HAS_TLS

#include "core/SocketMetrics.h"
#include "tls/SocketTLS-private.h"
#include <assert.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h> /* For SSL_CT_VALIDATION_* constants and SSL_CTX_enable_ct */

#define T SocketTLSContext_T

SOCKET_DECLARE_MODULE_EXCEPTION (SocketTLSContext);

/* ============================================================================
 * CT Support Detection
 * ============================================================================
 */

/* CT support requires OpenSSL 1.1.0+ and CT being compiled in */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(OPENSSL_NO_CT)
#define SOCKET_HAS_CT_SUPPORT 1
#else
#define SOCKET_HAS_CT_SUPPORT 0
#endif

/* ============================================================================
 * Certificate Transparency Implementation
 * ============================================================================
 */

#if SOCKET_HAS_CT_SUPPORT

/* Custom CT validation callback removed: using OpenSSL built-in policy for
 * proper SCT validation. This ensures correct handling of SCT verification,
 * log consistency, and timestamps.
 */

void
SocketTLSContext_enable_ct (T ctx, CTValidationMode mode)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (ctx->is_server)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "CT verification is for clients only");

  int openssl_mode = (mode == CT_VALIDATION_STRICT)
                         ? SSL_CT_VALIDATION_STRICT
                         : SSL_CT_VALIDATION_PERMISSIVE;

  /* Enable CT verification with OpenSSL built-in policy matching the requested
   * mode */
  if (SSL_CTX_enable_ct (ctx->ssl_ctx, openssl_mode) != 1)
    {
      ctx_raise_openssl_error ("Failed to enable Certificate Transparency");
    }

  /* Store mode for query functions */
  ctx->ct_enabled = 1;
  ctx->ct_mode = mode;
}

int
SocketTLSContext_ct_enabled (T ctx)
{
  assert (ctx);
  return ctx->ct_enabled;
}

CTValidationMode
SocketTLSContext_get_ct_mode (T ctx)
{
  assert (ctx);
  return ctx->ct_enabled ? ctx->ct_mode : CT_VALIDATION_PERMISSIVE;
}

#if SOCKET_HAS_CT_SUPPORT

void
SocketTLSContext_set_ctlog_list_file (T ctx, const char *log_file)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (ctx->is_server)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "Custom CT log list is for clients only");

  if (!log_file || !*log_file)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "CT log file path cannot be empty");

  if (!tls_validate_file_path (log_file))
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Invalid CT log file path: %s",
                         log_file);

  /* Load custom CT log list file, overriding OpenSSL defaults */
  if (SSL_CTX_set_ctlog_list_file (ctx->ssl_ctx, log_file) != 1)
    {
      ctx_raise_openssl_error ("Failed to load custom CT log list file");
    }

  /* Optional: Log success */
  SOCKET_LOG_INFO_MSG ("Loaded custom CT log list from %s", log_file);
}

#else /* !SOCKET_HAS_CT_SUPPORT */

void
SocketTLSContext_set_ctlog_list_file (T ctx, const char *log_file)
{
  (void)ctx;
  (void)log_file;
  assert (ctx);
  RAISE_CTX_ERROR_MSG (
      SocketTLS_Failed,
      "Custom CT log list not supported (requires OpenSSL 1.1.0+ with CT)");
}

#endif /* SOCKET_HAS_CT_SUPPORT */

#else /* !SOCKET_HAS_CT_SUPPORT */

void
SocketTLSContext_enable_ct (T ctx, CTValidationMode mode)
{
  (void)mode;
  assert (ctx);
  RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                       "Certificate Transparency not supported (requires "
                       "OpenSSL 1.1.0+ with CT)");
}

int
SocketTLSContext_ct_enabled (T ctx)
{
  assert (ctx);
  return 0;
}

#endif /* SOCKET_HAS_CT_SUPPORT */

#undef T

#endif /* SOCKET_HAS_TLS */

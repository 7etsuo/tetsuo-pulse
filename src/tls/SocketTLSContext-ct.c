/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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
 * CT support is detected via SOCKET_HAS_CT_SUPPORT in SocketTLSConfig.h.
 *
 * Thread safety: Configuration is NOT thread-safe - perform before sharing.
 */

#if SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include <assert.h>
#include <openssl/ssl.h>

#define T SocketTLSContext_T

SOCKET_DECLARE_MODULE_EXCEPTION (SocketTLSContext);

/* CT support detection is now in SocketTLSConfig.h (included via private.h) */

/* ============================================================================
 * Certificate Transparency Implementation
 * ============================================================================
 */

#if SOCKET_HAS_CT_SUPPORT

/**
 * SocketTLSContext_enable_ct - Enable Certificate Transparency verification
 * @ctx: TLS context instance (client only)
 * @mode: Validation mode (strict or permissive)
 *
 * Enables CT verification for client connections using OpenSSL's built-in
 * CT policy. In strict mode, connections fail if no valid SCTs are present.
 * In permissive mode, missing SCTs are logged but don't cause failure.
 *
 * Raises: SocketTLS_Failed if called on server context
 * Thread-safe: No - configure before sharing context
 */
void
SocketTLSContext_enable_ct (T ctx, CTValidationMode mode)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (ctx->is_server)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "CT verification is for clients only");

  int openssl_mode = (mode == CT_VALIDATION_STRICT) ? SSL_CT_VALIDATION_STRICT
                                                    : SSL_CT_VALIDATION_PERMISSIVE;

  if (SSL_CTX_enable_ct (ctx->ssl_ctx, openssl_mode) != 1)
    ctx_raise_openssl_error ("Failed to enable Certificate Transparency");

  ctx->ct_enabled = 1;
  ctx->ct_mode = mode;
}

/**
 * SocketTLSContext_ct_enabled - Check if CT verification is enabled
 * @ctx: TLS context instance
 *
 * Returns: 1 if CT enabled, 0 if disabled
 * Thread-safe: Yes (read-only)
 */
int
SocketTLSContext_ct_enabled (T ctx)
{
  assert (ctx);
  return ctx->ct_enabled;
}

/**
 * SocketTLSContext_get_ct_mode - Get current CT validation mode
 * @ctx: TLS context instance
 *
 * Returns: CT validation mode if enabled, CT_VALIDATION_PERMISSIVE if disabled
 * Thread-safe: Yes (read-only)
 */
CTValidationMode
SocketTLSContext_get_ct_mode (T ctx)
{
  assert (ctx);
  return ctx->ct_enabled ? ctx->ct_mode : CT_VALIDATION_PERMISSIVE;
}

/**
 * SocketTLSContext_set_ctlog_list_file - Load custom CT log list
 * @ctx: TLS context instance (client only)
 * @log_file: Path to CT log list file (OpenSSL format)
 *
 * Loads a custom list of trusted CT logs from file, overriding OpenSSL
 * defaults. The file should be in OpenSSL CT log list format.
 *
 * Raises: SocketTLS_Failed if file invalid, load fails, or server context
 * Thread-safe: No - configure before sharing context
 */
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

  if (SSL_CTX_set_ctlog_list_file (ctx->ssl_ctx, log_file) != 1)
    ctx_raise_openssl_error ("Failed to load custom CT log list file");

  SOCKET_LOG_INFO_MSG ("Loaded custom CT log list from %s", log_file);
}

#else /* !SOCKET_HAS_CT_SUPPORT */

/**
 * SocketTLSContext_enable_ct - Stub when CT not supported
 * @ctx: TLS context instance
 * @mode: Validation mode (ignored)
 *
 * Raises: SocketTLS_Failed always (CT not available)
 */
void
SocketTLSContext_enable_ct (T ctx, CTValidationMode mode)
{
  (void)mode;
  assert (ctx);
  RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                       "Certificate Transparency not supported (requires "
                       "OpenSSL 1.1.0+ with CT)");
}

/**
 * SocketTLSContext_ct_enabled - Stub when CT not supported
 * @ctx: TLS context instance
 *
 * Returns: 0 always (CT not available)
 */
int
SocketTLSContext_ct_enabled (T ctx)
{
  assert (ctx);
  return 0;
}

/**
 * SocketTLSContext_get_ct_mode - Stub when CT not supported
 * @ctx: TLS context instance
 *
 * Returns: CT_VALIDATION_PERMISSIVE (default, CT not available)
 */
CTValidationMode
SocketTLSContext_get_ct_mode (T ctx)
{
  assert (ctx);
  return CT_VALIDATION_PERMISSIVE;
}

/**
 * SocketTLSContext_set_ctlog_list_file - Stub when CT not supported
 * @ctx: TLS context instance
 * @log_file: Path to CT log file (ignored)
 *
 * Raises: SocketTLS_Failed always (CT not available)
 */
void
SocketTLSContext_set_ctlog_list_file (T ctx, const char *log_file)
{
  (void)log_file;
  assert (ctx);
  RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                       "Custom CT log list not supported (requires "
                       "OpenSSL 1.1.0+ with CT)");
}

#endif /* SOCKET_HAS_CT_SUPPORT */

#undef T

#endif /* SOCKET_HAS_TLS */

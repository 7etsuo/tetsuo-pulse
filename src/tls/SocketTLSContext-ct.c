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



/* CT support detection is now in SocketTLSConfig.h (included via private.h) */

SOCKET_DECLARE_MODULE_EXCEPTION (SocketTLSContext);

#if SOCKET_HAS_CT_SUPPORT

/**
 * @note Implementation of SocketTLSContext_enable_ct(). See header for details.
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
 * @note Implementation of SocketTLSContext_ct_enabled(). See header for details.
 */
int
SocketTLSContext_ct_enabled (T ctx)
{
  assert (ctx);
  return ctx->ct_enabled;
}

/**
 * @note Implementation of SocketTLSContext_get_ct_mode(). See header for details.
 */
CTValidationMode
SocketTLSContext_get_ct_mode (T ctx)
{
  assert (ctx);
  return ctx->ct_enabled ? ctx->ct_mode : CT_VALIDATION_PERMISSIVE;
}

/**
 * @note Implementation of SocketTLSContext_set_ctlog_list_file(). See header for details.
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

static void
raise_ct_not_supported(T ctx, const char *feature) {
  assert(ctx);
  RAISE_CTX_ERROR_MSG(SocketTLS_Failed, "%s not supported (requires OpenSSL 1.1.0+ with CT)", feature);
}

/**
 * @note Stub implementation when CT not supported. See header for details.
 */
void
SocketTLSContext_enable_ct (T ctx, CTValidationMode mode)
{
  TLS_UNUSED(mode);
  raise_ct_not_supported(ctx, "Certificate Transparency");
}

/**
 * @note Stub implementation when CT not supported. See header for details.
 */
int
SocketTLSContext_ct_enabled (T ctx)
{
  assert (ctx);
  return 0;
}

/**
 * @note Stub implementation when CT not supported. See header for details.
 */
CTValidationMode
SocketTLSContext_get_ct_mode (T ctx)
{
  assert (ctx);
  return CT_VALIDATION_PERMISSIVE;
}

/**
 * @note Stub implementation when CT not supported. See header for details.
 */
void
SocketTLSContext_set_ctlog_list_file (T ctx, const char *log_file)
{
  TLS_UNUSED(log_file);
  raise_ct_not_supported(ctx, "Custom CT log list");
}

#endif /* SOCKET_HAS_CT_SUPPORT */

#undef T

#endif /* SOCKET_HAS_TLS */

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

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include <assert.h>
#include <openssl/ct.h>
#include <openssl/opensslv.h>

#define T SocketTLSContext_T

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

/**
 * ct_validation_callback - OpenSSL CT validation callback
 * @ctx: CT policy context
 * @scts: List of SCTs
 * @arg: User argument (our TLS context)
 *
 * Returns: 1 to accept, 0 to reject
 */
static int
ct_validation_callback (const CT_POLICY_EVAL_CTX *policy_ctx,
                        const STACK_OF (SCT) *scts, void *arg)
{
  (void)policy_ctx; /* Unused - we get context from arg */
  T tls_ctx = (T)arg;
  if (!tls_ctx)
    return 1;

  int sct_count = scts ? sk_SCT_num (scts) : 0;

  /* In permissive mode, always accept */
  if (tls_ctx->ct_mode == CT_VALIDATION_PERMISSIVE)
    return 1;

  /* Strict mode: require at least one valid SCT */
  if (sct_count == 0)
    return 0;

  /* Check for at least one valid SCT */
  for (int i = 0; i < sct_count; i++)
    {
      SCT *sct = sk_SCT_value (scts, i);
      if (sct && SCT_get_validation_status (sct) == SCT_VALIDATION_STATUS_VALID)
        return 1;
    }

  /* No valid SCTs found in strict mode - reject */
  return 0;
}

void
SocketTLSContext_enable_ct (T ctx, CTValidationMode mode)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (ctx->is_server)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "CT verification is for clients only");

  /* Enable CT verification with OpenSSL's strict mode as baseline */
  if (SSL_CTX_enable_ct (ctx->ssl_ctx, SSL_CT_VALIDATION_STRICT) != 1)
    {
      ctx_raise_openssl_error ("Failed to enable Certificate Transparency");
    }

  /* Store mode before registering callback (callback reads it) */
  ctx->ct_enabled = 1;
  ctx->ct_mode = mode;

  /* Always register custom validation callback for consistent behavior.
   * The callback handles both strict and permissive modes internally:
   * - Strict: Requires at least one valid SCT, rejects otherwise
   * - Permissive: Always accepts (for logging/monitoring without enforcement)
   */
  SSL_CTX_set_ct_validation_callback (ctx->ssl_ctx, ct_validation_callback, ctx);
}

int
SocketTLSContext_ct_enabled (T ctx)
{
  assert (ctx);
  return ctx->ct_enabled;
}

#else /* !SOCKET_HAS_CT_SUPPORT */

void
SocketTLSContext_enable_ct (T ctx, CTValidationMode mode)
{
  (void)mode;
  assert (ctx);
  RAISE_CTX_ERROR_MSG (
      SocketTLS_Failed,
      "Certificate Transparency not supported (requires OpenSSL 1.1.0+ with CT)");
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


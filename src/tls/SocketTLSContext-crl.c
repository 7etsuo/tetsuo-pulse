/**
 * SocketTLSContext-crl.c - CRL Auto-Refresh Support
 *
 * Part of the Socket Library
 *
 * Implements automatic CRL (Certificate Revocation List) refresh for
 * long-running applications. Refresh is cooperative - the application
 * must call SocketTLSContext_crl_check_refresh() periodically.
 *
 * Thread safety: Configuration is NOT thread-safe - perform before sharing.
 * Refresh check is NOT thread-safe - call from single thread.
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include <assert.h>
#include <string.h>
#include <time.h>

#define T SocketTLSContext_T

/* ============================================================================
 * CRL Auto-Refresh Implementation
 * ============================================================================
 */

void
SocketTLSContext_set_crl_auto_refresh (T ctx, const char *crl_path,
                                       long interval_seconds,
                                       SocketTLSCrlCallback callback,
                                       void *user_data)
{
  assert (ctx);

  if (!crl_path || !*crl_path)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "CRL path cannot be NULL or empty");

  size_t path_len = strlen (crl_path);
  if (path_len >= SOCKET_TLS_CRL_MAX_PATH_LEN)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "CRL path too long");

  /* Validate interval */
  if (interval_seconds < 0)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "CRL refresh interval cannot be negative");

  if (interval_seconds > 0
      && interval_seconds < SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL)
    RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                         "CRL refresh interval must be at least %d seconds",
                         SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL);

  /* Free existing path if any */
  /* Note: path is arena-allocated, will be freed with context */

  /* Copy path to arena */
  ctx->crl_refresh_path
      = ctx_arena_strdup (ctx, crl_path, "Failed to allocate CRL path");

  ctx->crl_refresh_interval = interval_seconds;
  ctx->crl_callback = (void *)callback;
  ctx->crl_user_data = user_data;

  /* Schedule first refresh */
  if (interval_seconds > 0)
    {
      ctx->crl_next_refresh = time (NULL) + interval_seconds;
    }
  else
    {
      ctx->crl_next_refresh = 0;
    }

  /* Do initial load if interval is set */
  if (interval_seconds > 0)
    {
      TRY
      SocketTLSContext_load_crl (ctx, crl_path);
      EXCEPT (SocketTLS_Failed)
      /* Initial load failed - callback will be notified on next check */
      if (callback)
        {
          callback (ctx, crl_path, 0, user_data);
        }
      END_TRY;
    }
}

void
SocketTLSContext_cancel_crl_auto_refresh (T ctx)
{
  assert (ctx);

  ctx->crl_refresh_interval = 0;
  ctx->crl_next_refresh = 0;
  ctx->crl_callback = NULL;
  ctx->crl_user_data = NULL;
  /* Keep crl_refresh_path - arena will clean it up */
}

int
SocketTLSContext_crl_check_refresh (T ctx)
{
  assert (ctx);

  /* Not configured or disabled */
  if (ctx->crl_refresh_interval <= 0 || !ctx->crl_refresh_path)
    return 0;

  time_t now = time (NULL);

  /* Not due yet */
  if (now < ctx->crl_next_refresh)
    return 0;

  /* Attempt refresh */
  volatile int success = 1;
  TRY
  SocketTLSContext_load_crl (ctx, ctx->crl_refresh_path);
  EXCEPT (SocketTLS_Failed)
  success = 0;
  END_TRY;

  /* Schedule next refresh */
  ctx->crl_next_refresh = now + ctx->crl_refresh_interval;

  /* Notify callback */
  if (ctx->crl_callback)
    {
      SocketTLSCrlCallback cb = (SocketTLSCrlCallback)ctx->crl_callback;
      cb (ctx, ctx->crl_refresh_path, success, ctx->crl_user_data);
    }

  return 1;
}

long
SocketTLSContext_crl_next_refresh_ms (T ctx)
{
  assert (ctx);

  /* Not configured */
  if (ctx->crl_refresh_interval <= 0)
    return -1;

  time_t now = time (NULL);

  if (ctx->crl_next_refresh <= now)
    return 0; /* Due now */

  long diff = (long)(ctx->crl_next_refresh - now);

  /* Convert to milliseconds, checking for overflow */
  if (diff > LONG_MAX / 1000)
    return LONG_MAX;

  return diff * 1000;
}

#undef T

#endif /* SOCKET_HAS_TLS */

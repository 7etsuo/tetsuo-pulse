/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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

#if SOCKET_HAS_TLS

#include "core/SocketUtil.h"
#include "tls/SocketTLS-private.h"

/* Thread-local exception for SocketTLSContext module */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketTLSContext);

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define T SocketTLSContext_T

static void
validate_crl_interval (long interval_seconds)
{
  if (interval_seconds < 0)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "CRL refresh interval cannot be negative");

  if (interval_seconds > SOCKET_TLS_CRL_MAX_REFRESH_INTERVAL)
    RAISE_CTX_ERROR_FMT (
        SocketTLS_Failed,
        "CRL refresh interval must be at most %lld seconds (1 year max)",
        (long long)SOCKET_TLS_CRL_MAX_REFRESH_INTERVAL);

  if (interval_seconds > 0
      && interval_seconds < SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL)
    RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                         "CRL refresh interval must be at least %d seconds",
                         SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL);
}

static void
validate_crl_path_security (const char *crl_path)
{
  if (!crl_path || !*crl_path)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "CRL path cannot be NULL or empty");

  if (!tls_validate_file_path (crl_path))
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "CRL path failed security validation (length, characters, traversal, or symlink)");

  /* realpath() performs canonicalization that resolves:
   * - Path traversal (. and .. components)
   * - Symlinks (expands to actual target)
   * - Relative to absolute path conversion
   * Success indicates a valid, resolvable path. */
  char *resolved_path = realpath (crl_path, NULL);
  if (!resolved_path)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Invalid or unresolvable CRL path");

  free (resolved_path);
}

static int
try_load_crl (T ctx, const char *path)
{
  volatile int success = 1;
  TRY
  SocketTLSContext_load_crl (ctx, path);
  EXCEPT (SocketTLS_Failed)
  success = 0;
  END_TRY;
  return success;
}

static void
notify_crl_callback (T ctx, const char *path, int success)
{
  if (!ctx->crl_callback)
    return;
  SocketTLSCrlCallback cb = (SocketTLSCrlCallback)ctx->crl_callback;
  cb (ctx, path, success, ctx->crl_user_data);
}

static void
schedule_crl_refresh (T ctx, long interval_seconds)
{
  if (interval_seconds > 0)
    {
      int64_t now_ms = Socket_get_monotonic_ms ();
      int64_t interval_ms = interval_seconds * SOCKET_MS_PER_SECOND;
      uint64_t result;

      /* Overflow protection: INT64_MAX ~= 292M years uptime */
      if (!socket_util_safe_add_u64 ((uint64_t)now_ms, (uint64_t)interval_ms,
                                      &result)
          || result > (uint64_t)INT64_MAX)
        {
          /* Clamp to INT64_MAX on overflow */
          ctx->crl_next_refresh_ms = INT64_MAX;
        }
      else
        {
          ctx->crl_next_refresh_ms = (int64_t)result;
        }
    }
  else
    {
      ctx->crl_next_refresh_ms = 0;
    }
}

void
SocketTLSContext_set_crl_auto_refresh (T ctx, const char *crl_path,
                                       long interval_seconds,
                                       SocketTLSCrlCallback callback,
                                       void *user_data)
{
  assert (ctx);

  validate_crl_path_security (crl_path);
  validate_crl_interval (interval_seconds);

  TRY
  {
    CRL_LOCK (ctx);

    ctx->crl_refresh_path
        = ctx_arena_strdup (ctx, crl_path, "Failed to allocate CRL path");
    ctx->crl_refresh_interval = interval_seconds;
    ctx->crl_callback = (void *)callback;
    ctx->crl_user_data = user_data;

    schedule_crl_refresh (ctx, interval_seconds);

    if (interval_seconds > 0)
      {
        int success = try_load_crl (ctx, crl_path);
        if (!success)
          notify_crl_callback (ctx, crl_path, 0);
      }
  }
  FINALLY { CRL_UNLOCK (ctx); }
  END_TRY;
}

void
SocketTLSContext_cancel_crl_auto_refresh (T ctx)
{
  assert (ctx);

  TRY
  {
    CRL_LOCK (ctx);

    ctx->crl_refresh_interval = 0;
    ctx->crl_next_refresh_ms = 0;
    ctx->crl_callback = NULL;
    ctx->crl_user_data = NULL;
  }
  FINALLY { CRL_UNLOCK (ctx); }
  END_TRY;
}

int
SocketTLSContext_crl_check_refresh (T ctx)
{
  assert (ctx);

  volatile int result = 0;

  TRY
  {
    CRL_LOCK (ctx);

    if (ctx->crl_refresh_interval <= 0 || !ctx->crl_refresh_path)
      {
        result = 0;
      }
    else
      {
        int64_t now_ms = Socket_get_monotonic_ms ();

        if (now_ms < ctx->crl_next_refresh_ms)
          {
            result = 0;
          }
        else
          {
            int success = try_load_crl (ctx, ctx->crl_refresh_path);
            int64_t interval_ms = ctx->crl_refresh_interval * SOCKET_MS_PER_SECOND;
            uint64_t next_refresh;

            /* Overflow protection: INT64_MAX ~= 292M years uptime */
            if (!socket_util_safe_add_u64 ((uint64_t)now_ms,
                                            (uint64_t)interval_ms,
                                            &next_refresh)
                || next_refresh > (uint64_t)INT64_MAX)
              {
                /* Clamp to INT64_MAX on overflow */
                ctx->crl_next_refresh_ms = INT64_MAX;
              }
            else
              {
                ctx->crl_next_refresh_ms = (int64_t)next_refresh;
              }

            notify_crl_callback (ctx, ctx->crl_refresh_path, success);
            result = 1;
          }
      }
  }
  EXCEPT (SocketTLS_Failed)
  {
    result = 0;
  }
  FINALLY { CRL_UNLOCK (ctx); }
  END_TRY;

  return result;
}

long
SocketTLSContext_crl_next_refresh_ms (T ctx)
{
  assert (ctx);

  volatile long result = -1;

  TRY
  {
    CRL_LOCK (ctx);

    if (ctx->crl_refresh_interval <= 0)
      {
        result = -1;
      }
    else
      {
        int64_t now_ms = Socket_get_monotonic_ms ();
        int64_t remaining_ms = ctx->crl_next_refresh_ms - now_ms;

        if (remaining_ms <= 0)
          result = 0;
        else if (remaining_ms > LONG_MAX)
          result = LONG_MAX;
        else
          result = (long)remaining_ms;
      }
  }
  EXCEPT (SocketTLS_Failed)
  {
    result = -1;
  }
  FINALLY { CRL_UNLOCK (ctx); }
  END_TRY;

  return result;
}

#undef T

#endif /* SOCKET_HAS_TLS */

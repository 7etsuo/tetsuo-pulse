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

/**
 * validate_path_chars - Validate path contains no control characters
 * @path: Path to validate
 * @path_len: Length of path
 * @context: Description for error message (e.g., "CRL" or "Resolved CRL")
 *
 * Returns: void
 * Raises: SocketTLS_Failed if control characters found
 * Thread-safe: No
 */
/**
 * validate_path_length - Validate path does not exceed maximum length
 * @path_len: Length of path
 * @context: Description for error message
 *
 * Returns: void
 * Raises: SocketTLS_Failed if path too long
 * Thread-safe: No
 */
/**
 * validate_crl_interval - Validate CRL refresh interval
 * @interval_seconds: Refresh interval in seconds
 *
 * Returns: void
 * Raises: SocketTLS_Failed if interval invalid
 * Thread-safe: No
 */
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

/**
 * validate_crl_path_security - Validate CRL path for security issues
 * @crl_path: Path to validate
 *
 * Checks for all security issues using tls_validate_file_path() on both the
 * original path and its resolved canonical path (via realpath). Ensures path
 * is resolvable, exists, and passes all checks: length limits, no control
 * characters, no traversal sequences, not a symlink (before and after resolution).
 *
 * Returns: void
 * Raises: SocketTLS_Failed on validation failure
 * Thread-safe: No
 */
static void
validate_crl_path_security (const char *crl_path)
{
  if (!crl_path || !*crl_path)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "CRL path cannot be NULL or empty");

  if (!tls_validate_file_path (crl_path))
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "CRL path failed security validation (length, characters, traversal, or symlink)");

  /* Resolve path and validate canonical form - ensures safe resolution */
  char *resolved_path = realpath (crl_path, NULL);
  if (!resolved_path)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Invalid or unresolvable CRL path");

  if (!tls_validate_file_path (resolved_path))
    {
      free (resolved_path);
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Resolved CRL path failed security validation");
    }

  free (resolved_path);
}

/**
 * try_load_crl - Attempt to load CRL file, catching errors
 * @ctx: TLS context instance
 * @path: Path to the CRL file or directory
 *
 * Returns: 1 on successful load, 0 on failure
 * Raises: None - internally catches SocketTLS_Failed
 * Thread-safe: Depends on SocketTLSContext_load_crl implementation
 */
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

/**
 * notify_crl_callback - Notify application of CRL refresh result if callback
 * set
 * @ctx: TLS context instance
 * @path: Path that was attempted to load
 * @success: 1 if load succeeded, 0 if failed
 *
 * Returns: void
 * Raises: None
 * Thread-safe: No - assumes single-threaded access to ctx->crl_callback
 */
static void
notify_crl_callback (T ctx, const char *path, int success)
{
  if (!ctx->crl_callback)
    return;
  SocketTLSCrlCallback cb = (SocketTLSCrlCallback)ctx->crl_callback;
  cb (ctx, path, success, ctx->crl_user_data);
}

/**
 * schedule_crl_refresh - Schedule the next CRL refresh time
 * @ctx: TLS context instance
 * @interval_seconds: Refresh interval (>0 to schedule, 0 to disable)
 *
 * Returns: void
 * Raises: None
 * Thread-safe: No
 */
static void
schedule_crl_refresh (T ctx, long interval_seconds)
{
  if (interval_seconds > 0)
    {
      int64_t now_ms = Socket_get_monotonic_ms ();
      int64_t interval_ms = interval_seconds * 1000LL;
      ctx->crl_next_refresh_ms = now_ms + interval_ms;
    }
  else
    {
      ctx->crl_next_refresh_ms = 0;
    }
}

/**
 * SocketTLSContext_set_crl_auto_refresh - Configure automatic CRL refresh
 * @ctx: TLS context instance
 * @crl_path: Path to CRL file (PEM/DER) or directory (hashed CRLs)
 * @interval_seconds: Refresh interval in seconds; 0 disables auto-refresh
 * @callback: Optional callback notified after each refresh attempt
 * @user_data: User data passed to callback
 *
 * Configures periodic CRL refresh. Initial load attempted immediately if
 * interval > 0. Application must call SocketTLSContext_crl_check_refresh()
 * periodically (e.g. every second).
 *
 * Returns: void
 * Raises: SocketTLS_Failed on invalid path, interval, or allocation failure
 * Thread-safe: Yes (internal mutex protects state changes)
 */
void
SocketTLSContext_set_crl_auto_refresh (T ctx, const char *crl_path,
                                       long interval_seconds,
                                       SocketTLSCrlCallback callback,
                                       void *user_data)
{
  assert (ctx);

  /* Validate before locking */
  validate_crl_path_security (crl_path);
  validate_crl_interval (interval_seconds);

  TRY
  {
    CRL_LOCK (ctx);

    /* Copy path to arena (previous path freed with arena on dispose) */
    ctx->crl_refresh_path
        = ctx_arena_strdup (ctx, crl_path, "Failed to allocate CRL path");

    ctx->crl_refresh_interval = interval_seconds;
    ctx->crl_callback = (void *)callback;
    ctx->crl_user_data = user_data;

    schedule_crl_refresh (ctx, interval_seconds);

    /* Initial load if interval is set */
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

/**
 * SocketTLSContext_cancel_crl_auto_refresh - Disable CRL auto-refresh
 * @ctx: TLS context instance
 *
 * Stops future refreshes. Previously loaded CRLs remain active.
 * Allocated path remains in arena until context free.
 *
 * Returns: void
 * Raises: None
 * Thread-safe: Yes (internal mutex)
 */
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

/**
 * SocketTLSContext_crl_check_refresh - Check if CRL refresh is due
 * @ctx: TLS context instance
 *
 * Call periodically from event loop. Performs refresh if due.
 *
 * Returns: 1 if refresh was attempted, 0 if not due or not configured
 * Raises: None - catches load errors internally
 * Thread-safe: Yes (mutex serialized)
 */
int
SocketTLSContext_crl_check_refresh (T ctx)
{
  assert (ctx);

  volatile int result = 0;

  TRY
  {
    CRL_LOCK (ctx);

    /* Not configured or disabled */
    if (ctx->crl_refresh_interval <= 0 || !ctx->crl_refresh_path)
      {
        result = 0;
      }
    else
      {
        int64_t now_ms = Socket_get_monotonic_ms ();

        /* Not due yet */
        if (now_ms < ctx->crl_next_refresh_ms)
          {
            result = 0;
          }
        else
          {
            /* Attempt refresh */
            int success = try_load_crl (ctx, ctx->crl_refresh_path);

            /* Schedule next refresh */
            ctx->crl_next_refresh_ms
                = now_ms + (ctx->crl_refresh_interval * 1000LL);

            /* Notify callback */
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

/**
 * SocketTLSContext_crl_next_refresh_ms - Get ms until next CRL refresh
 * @ctx: TLS context instance
 *
 * Returns: -1 if disabled, 0 if due, positive ms until next, LONG_MAX overflow
 * Raises: None
 * Thread-safe: Yes
 */
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

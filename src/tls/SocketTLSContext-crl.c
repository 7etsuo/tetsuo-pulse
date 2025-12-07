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

#include "tls/SocketTLS-private.h"

SOCKET_DECLARE_MODULE_EXCEPTION(SocketTLSContext);
#include <assert.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>



#define T SocketTLSContext_T

/* ============================================================================
 * CRL Auto-Refresh Implementation
 * ============================================================================
 */

/**
 * try_load_crl - Attempt to load CRL file, catching errors
 *
 * @ctx: TLS context instance
 * @path: Path to the CRL file or directory
 *
 * Returns: 1 on successful load, 0 on failure (e.g. file not found, invalid format)
 * Raises: None - internally catches SocketTLS_Failed
 * Thread-safe: Depends on SocketTLSContext_load_crl implementation
 */
static int
try_load_crl(T ctx, const char *path)
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
 * notify_crl_callback - Notify application of CRL refresh result if callback set
 *
 * @ctx: TLS context instance
 * @path: Path that was attempted to load (for callback parameter)
 * @success: 1 if load succeeded, 0 if failed
 *
 * Returns: void
 * Raises: None
 * Thread-safe: No - assumes single-threaded access to ctx->crl_callback
 */
static void
notify_crl_callback(T ctx, const char *path, int success)
{
  if (!ctx->crl_callback)
    return;
  SocketTLSCrlCallback cb = (SocketTLSCrlCallback)ctx->crl_callback;
  cb (ctx, path, success, ctx->crl_user_data);
}

/**
 * validate_crl_config - Validate parameters for CRL auto-refresh configuration
 *
 * @crl_path: Path to CRL file or directory
 * @interval_seconds: Refresh interval in seconds
 *
 * Returns: void
 * Raises: SocketTLS_Failed on invalid parameters (empty path, too long path, negative or too small interval)
 * Thread-safe: No
 */
static void
validate_crl_config(const char *crl_path, long interval_seconds)
{
  if (!crl_path || !*crl_path)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "CRL path cannot be NULL or empty");
  size_t path_len = strlen (crl_path);
  if (path_len >= SOCKET_TLS_CRL_MAX_PATH_LEN)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "CRL path too long");

  /* Check for embedded null bytes */
  if (memchr (crl_path, '\0', path_len) != NULL)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "CRL path contains embedded null byte");

  /* Check for control characters */
  for (size_t i = 0; i < path_len; i++)
    {
      unsigned char c = (unsigned char)crl_path[i];
      if (c < 32 || c == 127)
        RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "CRL path contains invalid control character");
    }

  /* Enhanced traversal checks */
  const char *traversal_patterns[] = {
    "/../", "\\..\\", "/..\\", "\\../", "/...", "\\...", NULL
  };
  for (const char **pat = traversal_patterns; *pat != NULL; ++pat)
    {
      if (strstr (crl_path, *pat) != NULL)
        RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "CRL path contains traversal pattern '%s'", *pat);
    }
  if (strncmp (crl_path, "../", 3) == 0 || strncmp (crl_path, "..\\", 3) == 0)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "CRL path starts with relative traversal");

  /* Basic path security: prevent traversal and validate resolvability */
  if (strstr (crl_path, "..") != NULL)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "CRL path contains '..' traversal not allowed");

  char *resolved_path = realpath (crl_path, NULL);
  if (!resolved_path)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Invalid or unresolvable CRL path");
  if (strlen (resolved_path) >= SOCKET_TLS_CRL_MAX_PATH_LEN)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Resolved CRL path too long");

  /* Additional checks on resolved path */
  size_t res_len = strlen (resolved_path);
  if (memchr (resolved_path, '\0', res_len) != NULL)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Resolved CRL path contains embedded null byte");
  for (size_t i = 0; i < res_len; i++)
    {
      unsigned char c = (unsigned char)resolved_path[i];
      if (c < 32 || c == 127)
        RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Resolved CRL path contains invalid control character");
    }
  free (resolved_path);
  /* Validate interval */
  if (interval_seconds < 0)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "CRL refresh interval cannot be negative");
  if (interval_seconds > SOCKET_TLS_CRL_MAX_REFRESH_INTERVAL)
    RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                         "CRL refresh interval must be at most %lld seconds (1 year max)",
                         SOCKET_TLS_CRL_MAX_REFRESH_INTERVAL);
  if (interval_seconds > 0
      && interval_seconds < SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL)
    RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                         "CRL refresh interval must be at least %d seconds",
                         SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL);
}

/**
 * schedule_crl_refresh - Schedule the next CRL refresh time
 *
 * @ctx: TLS context instance
 * @interval_seconds: Refresh interval ( >0 to schedule, 0 to disable)
 *
 * Returns: void
 * Raises: None
 * Thread-safe: No
 */
static void
schedule_crl_refresh(T ctx, long interval_seconds)
{
  int64_t now_ms = Socket_get_monotonic_ms ();
  int64_t interval_ms = interval_seconds * 1000LL;
  ctx->crl_next_refresh_ms = (interval_seconds > 0) ?
    now_ms + interval_ms : 0;
}

/**
 * SocketTLSContext_set_crl_auto_refresh - Configure automatic CRL refresh
 *
 * @ctx: TLS context instance
 * @crl_path: Path to CRL file (PEM/DER) or directory (hashed CRLs) for periodic loading
 * @interval_seconds: Refresh interval in seconds; 0 disables auto-refresh
 * @callback: Optional callback notified after each refresh attempt (success/failure)
 * @user_data: User data passed to callback
 *
 * Configures periodic CRL refresh. Initial load attempted immediately if interval > 0.
 * Application must call SocketTLSContext_crl_check_refresh() periodically (e.g. every second).
 * Returns: void
 * Raises: SocketTLS_Failed on invalid path (empty, too long), invalid interval, or allocation failure
 * Thread-safe: Yes (internal mutex protects state changes)
 */
void
SocketTLSContext_set_crl_auto_refresh (T ctx, const char *crl_path,
                                       long interval_seconds,
                                       SocketTLSCrlCallback callback,
                                       void *user_data)
{
  assert (ctx);

  validate_crl_config(crl_path, interval_seconds);

  TRY
    {
      CRL_LOCK(ctx);

      /* Note: previous path freed with arena on context dispose */

      /* Copy path to arena */
      ctx->crl_refresh_path
          = ctx_arena_strdup (ctx, crl_path, "Failed to allocate CRL path");

      ctx->crl_refresh_interval = interval_seconds;
      ctx->crl_callback = (void *)callback;
      ctx->crl_user_data = user_data;

      schedule_crl_refresh(ctx, interval_seconds);

      /* Do initial load if interval is set */
      if (interval_seconds > 0)
        {
          int success = try_load_crl(ctx, crl_path);
          if (!success)
            notify_crl_callback(ctx, crl_path, 0);  /* under lock, recursive safe */
        }
    }
  FINALLY
    {
      CRL_UNLOCK(ctx);
    }
  END_TRY;
  /* Exceptions propagate; no return needed for void function */
}

/**
 * SocketTLSContext_cancel_crl_auto_refresh - Disable and reset CRL auto-refresh configuration
 *
 * @ctx: TLS context instance
 *
 * Stops future refreshes. Previously allocated CRL path remains in arena until context free.
 * Does not unload currently loaded CRLs.
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
      CRL_LOCK(ctx);

      ctx->crl_refresh_interval = 0;
      ctx->crl_next_refresh_ms = 0;
      ctx->crl_callback = NULL;
      ctx->crl_user_data = NULL;
      /* Keep crl_refresh_path - arena will clean it up */
    }
  FINALLY
    {
      CRL_UNLOCK(ctx);
    }
  END_TRY;
  /* Exceptions propagate; no return needed for void function */
}

/**
 * SocketTLSContext_crl_check_refresh - Check if CRL refresh is due and perform it
 *
 * @ctx: TLS context instance
 *
 * Call periodically (e.g. in event loop) to check and perform CRL refresh if due.
 * Schedules next refresh and notifies callback on result.
 * Returns: 1 if refresh was attempted (was due), 0 if not configured or not due yet
 * Raises: None - catches load errors internally
 * Thread-safe: Yes (mutex serialized access)
 */
int
SocketTLSContext_crl_check_refresh (T ctx)
{
  assert (ctx);

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

  TRY
    {
      CRL_LOCK(ctx);

      /* Not configured or disabled */
      if (ctx->crl_refresh_interval <= 0 || !ctx->crl_refresh_path)
        return 0;

      int64_t now_ms = Socket_get_monotonic_ms ();

      /* Not due yet */
      if (now_ms < ctx->crl_next_refresh_ms)
        return 0;

      /* Attempt refresh */
      int success = try_load_crl(ctx, ctx->crl_refresh_path);

      /* Schedule next refresh */
      ctx->crl_next_refresh_ms = now_ms + (ctx->crl_refresh_interval * 1000LL);

      /* Notify callback (recursive mutex allows reentry, but minimizes hold time) */
      notify_crl_callback(ctx, ctx->crl_refresh_path, success);

      return 1;
    }
  EXCEPT (SocketTLS_Failed)
    {
      /* Catch and ignore load errors as per doc: catches internally */
      return 0;
    }
  FINALLY
    {
      CRL_UNLOCK(ctx);
    }
  END_TRY;

  return 0;
}

/**
 * SocketTLSContext_crl_next_refresh_ms - Get milliseconds until next scheduled CRL refresh
 *
 * @ctx: TLS context instance
 *
 * Returns: -1 if auto-refresh disabled, 0 if due now or past, positive ms until next,
 *          LONG_MAX if very far future (overflow protection)
 * Raises: None
 * Thread-safe: Yes (read-only)
 */
long
SocketTLSContext_crl_next_refresh_ms (T ctx)
{
  assert (ctx);

  TRY
    {
      CRL_LOCK(ctx);

      if (ctx->crl_refresh_interval <= 0)
        return -1;

      int64_t now_ms = Socket_get_monotonic_ms ();
      int64_t remaining_ms = ctx->crl_next_refresh_ms - now_ms;
      if (remaining_ms <= 0)
        return 0; /* Due now or past */

      /* Overflow protection */
      if (remaining_ms > LONG_MAX)
        return LONG_MAX;
      return (long)remaining_ms;
    }
  EXCEPT (SocketTLS_Failed)
    {
      /* Catch any errors and return safe default */
      return -1;
    }
  FINALLY
    {
      CRL_UNLOCK(ctx);
    }
  END_TRY;

  return -1;
}

#undef T

#endif /* SOCKET_HAS_TLS */

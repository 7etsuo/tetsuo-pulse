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

SOCKET_DECLARE_MODULE_EXCEPTION (SocketTLSContext);
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define T SocketTLSContext_T

/* ============================================================================
 * CRL Path Validation Helpers
 * ============================================================================
 */

/**
 * contains_control_chars - Check if string contains ASCII control characters
 * @data: String to validate
 * @len: Length of string
 *
 * Control characters are bytes 0x00-0x1F and 0x7F (DEL).
 *
 * Returns: 1 if control characters found, 0 otherwise
 * Thread-safe: Yes (pure function)
 */
static int
contains_control_chars (const char *data, size_t len)
{
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)data[i];
      /* ASCII control: 0x00-0x1F (space-1) and 0x7F (DEL) */
      if (c < 0x20 || c == 0x7F)
        return 1;
    }
  return 0;
}

/**
 * contains_path_traversal - Check if path contains traversal sequences
 * @path: Path string to validate
 *
 * Detects ".." in any form that could escape the intended directory.
 * Covers /../, \..\ (Windows), mixed separators, and path start.
 *
 * Returns: 1 if traversal detected, 0 otherwise
 * Thread-safe: Yes (pure function)
 */
static int
contains_path_traversal (const char *path)
{
  /* Reject any ".." - realpath will resolve but we want defense-in-depth */
  if (strstr (path, "..") != NULL)
    return 1;
  return 0;
}

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
static void
validate_path_chars (const char *path, size_t path_len, const char *context)
{
  if (contains_control_chars (path, path_len))
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "%s path contains invalid control character", context);
}

/**
 * validate_path_length - Validate path does not exceed maximum length
 * @path_len: Length of path
 * @context: Description for error message
 *
 * Returns: void
 * Raises: SocketTLS_Failed if path too long
 * Thread-safe: No
 */
static void
validate_path_length (size_t path_len, const char *context)
{
  if (path_len >= SOCKET_TLS_CRL_MAX_PATH_LEN)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "%s path too long", context);
}

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
 * Checks for:
 * - Path traversal sequences (..)
 * - Control characters
 * - Excessive length
 * - Resolvability (must exist and be accessible)
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

  size_t path_len = strlen (crl_path);
  validate_path_length (path_len, "CRL");
  validate_path_chars (crl_path, path_len, "CRL");

  if (contains_path_traversal (crl_path))
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "CRL path contains '..' traversal (not allowed)");

  /* Resolve path and validate result */
  char *resolved_path = realpath (crl_path, NULL);
  if (!resolved_path)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Invalid or unresolvable CRL path");

  /* Validate resolved path - must free on any error */
  size_t res_len = strlen (resolved_path);

  if (res_len >= SOCKET_TLS_CRL_MAX_PATH_LEN)
    {
      free (resolved_path);
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Resolved CRL path too long");
    }

  if (contains_control_chars (resolved_path, res_len))
    {
      free (resolved_path);
      RAISE_CTX_ERROR_MSG (
          SocketTLS_Failed,
          "Resolved CRL path contains invalid control character");
    }

  free (resolved_path);
}

/* ============================================================================
 * CRL Auto-Refresh Implementation
 * ============================================================================
 */

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

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

  TRY
  {
    CRL_LOCK (ctx);

    /* Not configured or disabled */
    if (ctx->crl_refresh_interval <= 0 || !ctx->crl_refresh_path)
      return 0;

    int64_t now_ms = Socket_get_monotonic_ms ();

    /* Not due yet */
    if (now_ms < ctx->crl_next_refresh_ms)
      return 0;

    /* Attempt refresh */
    int success = try_load_crl (ctx, ctx->crl_refresh_path);

    /* Schedule next refresh */
    ctx->crl_next_refresh_ms = now_ms + (ctx->crl_refresh_interval * 1000LL);

    /* Notify callback */
    notify_crl_callback (ctx, ctx->crl_refresh_path, success);

    return 1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    return 0;
  }
  FINALLY { CRL_UNLOCK (ctx); }
  END_TRY;

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

  return 0; /* Unreachable - needed for compiler */
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

  TRY
  {
    CRL_LOCK (ctx);

    if (ctx->crl_refresh_interval <= 0)
      return -1;

    int64_t now_ms = Socket_get_monotonic_ms ();
    int64_t remaining_ms = ctx->crl_next_refresh_ms - now_ms;

    if (remaining_ms <= 0)
      return 0;

    if (remaining_ms > LONG_MAX)
      return LONG_MAX;

    return (long)remaining_ms;
  }
  EXCEPT (SocketTLS_Failed)
  {
    return -1;
  }
  FINALLY { CRL_UNLOCK (ctx); }
  END_TRY;

  return -1; /* Unreachable - needed for compiler */
}

#undef T

#endif /* SOCKET_HAS_TLS */

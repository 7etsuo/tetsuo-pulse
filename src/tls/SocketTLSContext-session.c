/**
 * SocketTLSContext-session.c - TLS Session Management
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * TLS session caching and session ticket support. Enables faster subsequent
 * connections via session resumption. Tracks cache statistics for monitoring.
 *
 * Thread safety: Session cache operations are thread-safe via internal mutex.
 * Statistics access is protected.
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include <assert.h>
#include <string.h>

#define T SocketTLSContext_T

/* ============================================================================
 * Session Cache Callbacks
 * ============================================================================
 */

/**
 * new_session_cb - Called when new session is created
 * @ssl: SSL connection
 * @sess: New session (unused)
 *
 * Returns: 1 to indicate we took ownership (we didn't, but OpenSSL expects 1)
 */
static int
new_session_cb (SSL *ssl, SSL_SESSION *sess)
{
  (void)sess;
  T ctx = tls_context_get_from_ssl (ssl);
  if (ctx)
    {
      pthread_mutex_lock (&ctx->stats_mutex);
      ctx->cache_stores++;
      pthread_mutex_unlock (&ctx->stats_mutex);
    }
  return 1;
}

/**
 * info_callback - Called on TLS state changes
 * @ssl: SSL connection
 * @where: Event type flags
 * @ret: Return code (unused unless error)
 *
 * Tracks session reuse on handshake completion.
 */
static void
info_callback (const SSL *ssl, int where, int ret)
{
  if (ret == 0)
    return;

  if (where & SSL_CB_HANDSHAKE_DONE)
    {
      T ctx = tls_context_get_from_ssl (ssl);
      if (ctx)
        {
          pthread_mutex_lock (&ctx->stats_mutex);
          if (SSL_session_reused ((SSL *)ssl))
            {
              ctx->cache_hits++;
            }
          else
            {
              ctx->cache_misses++;
            }
          pthread_mutex_unlock (&ctx->stats_mutex);
        }
    }
}

/* ============================================================================
 * Cache Size Management
 * ============================================================================
 */

/**
 * set_cache_size - Set session cache size with validation
 * @ctx: TLS context
 * @size: Cache size (must be > 0)
 *
 * Raises: SocketTLS_Failed on invalid size or OpenSSL error
 */
static void
set_cache_size (T ctx, size_t size)
{
  if (size == 0)
    ctx_raise_openssl_error ("Session cache size cannot be zero");

  if (SSL_CTX_sess_set_cache_size (ctx->ssl_ctx, (long)size) == 0)
    ctx_raise_openssl_error ("Failed to set session cache size");

  ctx->session_cache_size = size;
}

/* ============================================================================
 * Public Session Cache API
 * ============================================================================
 */

void
SocketTLSContext_enable_session_cache (T ctx, size_t max_sessions,
                                       long timeout_seconds)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  long mode = ctx->is_server ? SSL_SESS_CACHE_SERVER : SSL_SESS_CACHE_CLIENT;
  if (SSL_CTX_set_session_cache_mode (ctx->ssl_ctx, mode) == 0)
    ctx_raise_openssl_error ("Failed to enable session cache mode");

  SSL_CTX_sess_set_new_cb (ctx->ssl_ctx, new_session_cb);
  SSL_CTX_set_info_callback (ctx->ssl_ctx, info_callback);

  if (max_sessions > 0)
    set_cache_size (ctx, max_sessions);

  SSL_CTX_set_timeout (ctx->ssl_ctx, timeout_seconds > 0
                                         ? timeout_seconds
                                         : SOCKET_TLS_SESSION_TIMEOUT_DEFAULT);
  ctx->session_cache_enabled = 1;
}

void
SocketTLSContext_set_session_cache_size (T ctx, size_t size)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  set_cache_size (ctx, size);
}

void
SocketTLSContext_get_cache_stats (T ctx, size_t *hits, size_t *misses,
                                  size_t *stores)
{
  if (!ctx || !ctx->session_cache_enabled)
    {
      if (hits)
        *hits = 0;
      if (misses)
        *misses = 0;
      if (stores)
        *stores = 0;
      return;
    }

  pthread_mutex_lock (&ctx->stats_mutex);
  if (hits)
    *hits = ctx->cache_hits;
  if (misses)
    *misses = ctx->cache_misses;
  if (stores)
    *stores = ctx->cache_stores;
  pthread_mutex_unlock (&ctx->stats_mutex);
}

/* ============================================================================
 * Session Tickets
 * ============================================================================
 */

void
SocketTLSContext_enable_session_tickets (T ctx, const unsigned char *key,
                                         size_t key_len)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (key_len != SOCKET_TLS_TICKET_KEY_LEN)
    {
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                           "Session ticket key length must be exactly %d bytes",
                           SOCKET_TLS_TICKET_KEY_LEN);
    }

  /* Copy key into structure's ticket_key field for secure clearing on free */
  memcpy (ctx->ticket_key, key, key_len);
  ctx->tickets_enabled = 1;

  if (SSL_CTX_ctrl (ctx->ssl_ctx, SSL_CTRL_SET_TLSEXT_TICKET_KEYS,
                    (int)key_len, ctx->ticket_key)
      != 1)
    {
      /* Clear key material on failure before raising exception */
      OPENSSL_cleanse (ctx->ticket_key, SOCKET_TLS_TICKET_KEY_LEN);
      ctx->tickets_enabled = 0;
      ctx_raise_openssl_error ("Failed to set session ticket keys");
    }
}

#undef T

#endif /* SOCKET_HAS_TLS */


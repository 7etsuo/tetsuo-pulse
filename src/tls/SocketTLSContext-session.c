/**
 * SocketTLSContext-session.c - TLS Session Management
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * TLS session caching and session ticket support. Enables faster subsequent
 * connections via session resumption. Tracks cache statistics for monitoring.
 *
 * Features:
 * - Session cache enable/disable with configurable size
 * - Session cache statistics (hits, misses, stores)
 * - Session ticket support with 80-byte key rotation
 * - Thread-safe statistics access via mutex
 *
 * Thread safety: Session cache operations are thread-safe via internal mutex.
 * Statistics access is protected. Configuration should be done before sharing
 * context across threads.
 */

#if SOCKET_HAS_TLS

#include "core/SocketSecurity.h"
#include "tls/SocketTLS-private.h"
#include <assert.h>
#include <limits.h> /* for LONG_MAX */
#include <string.h>

#define T SocketTLSContext_T

SOCKET_DECLARE_MODULE_EXCEPTION (SocketTLSContext);

/* ============================================================================
 * Session Cache Callbacks (Internal)
 * ============================================================================
 */

/**
 * new_session_cb - Called by OpenSSL when new session is created
 * @ssl: SSL connection
 * @sess: New session (ownership depends on return value)
 *
 * Returns: 0 to let OpenSSL handle session storage and cleanup.
 *
 * This callback is invoked after a successful TLS handshake creates a new
 * session that can be reused. We only use it for statistics tracking, not
 * custom storage, so we return 0 to let OpenSSL manage the session.
 *
 * Note: Return value semantics:
 *   - 0: OpenSSL owns session (handles storage/free)
 *   - 1: Callback takes ownership (must free session manually)
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
  return 0;
}

/**
 * info_callback - Called by OpenSSL on TLS state changes
 * @ssl: SSL connection (const per OpenSSL signature)
 * @where: Event type bitmask (SSL_CB_* flags)
 * @ret: Event-specific value; for errors indicates failure, otherwise unused
 *
 * Tracks session reuse statistics on handshake completion. Called multiple
 * times during handshake at various state transitions.
 *
 * Note on 'ret' parameter: In SSL_CB_HANDSHAKE_DONE context, ret is always 1
 * (success) since the callback is only invoked on successful completion.
 * We check ret != 0 defensively for any error callbacks that might sneak in.
 */
static void
info_callback (const SSL *ssl, int where, int ret)
{
  /* Skip callbacks with error indication (ret == 0 for some callback types) */
  if (ret == 0)
    return;

  if (where & SSL_CB_HANDSHAKE_DONE)
    {
      T ctx = tls_context_get_from_ssl (ssl);
      if (ctx)
        {
          pthread_mutex_lock (&ctx->stats_mutex);
          /* Note: SSL_session_reused() expects non-const SSL*, but the info
           * callback signature provides const SSL*. This is an OpenSSL API
           * inconsistency - the function doesn't modify the SSL object. */
          if (SSL_session_reused ((SSL *)ssl))
            ctx->cache_hits++;
          else
            ctx->cache_misses++;
          pthread_mutex_unlock (&ctx->stats_mutex);
        }
    }
}

/* ============================================================================
 * Cache Size Management (Internal)
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

  SocketSecurityLimits limits;
  SocketSecurity_get_limits (&limits);
  if (size > limits.tls_session_cache_size)
    {
      RAISE_CTX_ERROR_FMT (
          SocketTLS_Failed,
          "Session cache size %zu exceeds security limit of %zu", size,
          limits.tls_session_cache_size);
    }

  if (size > (size_t)LONG_MAX)
    {
      RAISE_CTX_ERROR_FMT (
          SocketTLS_Failed,
          "Session cache size %zu exceeds maximum supported value %ld", size,
          LONG_MAX);
    }

  if (SSL_CTX_sess_set_cache_size (ctx->ssl_ctx, (long)size) == 0)
    ctx_raise_openssl_error ("Failed to set session cache size");

  ctx->session_cache_size = size;
}

/* ============================================================================
 * Session ID Context
 * ============================================================================
 */

/**
 * SocketTLSContext_set_session_id_context - Set session ID context for servers
 * @ctx: TLS context (must not be NULL)
 * @context: Session ID context bytes (must not be NULL)
 * @context_len: Length of context (1-32 bytes, per OpenSSL limit)
 *
 * Raises: SocketTLS_Failed on invalid parameters or OpenSSL error
 *
 * Sets the session ID context used to differentiate sessions between different
 * server applications or virtual hosts. Sessions created with one context will
 * not be reused when a client connects to a server with a different context.
 *
 * This is critical for:
 * - Multi-tenant servers with different security requirements per tenant
 * - Virtual hosting with separate session caches per hostname
 * - Load-balanced clusters that need consistent session behavior
 * - Applications sharing an SSL_CTX but needing session isolation
 *
 * For simple single-application servers, a fixed string like "myapp" works.
 * For virtual hosting, use the hostname or a hash of server configuration.
 * For enhanced security, include a unique server identifier.
 *
 * Thread-safe: No - call before sharing context across threads.
 */
void
SocketTLSContext_set_session_id_context (T ctx, const unsigned char *context,
                                         size_t context_len)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (context == NULL)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Session ID context cannot be NULL");
    }

  /* OpenSSL enforces maximum 32 bytes (SSL_MAX_SID_CTX_LENGTH) */
  if (context_len == 0 || context_len > SSL_MAX_SID_CTX_LENGTH)
    {
      RAISE_CTX_ERROR_FMT (
          SocketTLS_Failed,
          "Session ID context length must be 1-%d bytes, got %zu",
          SSL_MAX_SID_CTX_LENGTH, context_len);
    }

  if (SSL_CTX_set_session_id_context (ctx->ssl_ctx, context,
                                      (unsigned int)context_len)
      != 1)
    {
      ctx_raise_openssl_error ("Failed to set session ID context");
    }
}

/* ============================================================================
 * Public Session Cache API
 * ============================================================================
 */

/**
 * SocketTLSContext_enable_session_cache - Enable TLS session caching
 * @ctx: TLS context (must not be NULL)
 * @max_sessions: Maximum cached sessions (0 = use OpenSSL default)
 * @timeout_seconds: Session timeout (<=0 = use
 * SOCKET_TLS_SESSION_TIMEOUT_DEFAULT)
 *
 * Raises: SocketTLS_Failed on configuration error
 *
 * Enables session caching for faster subsequent connections via TLS session
 * resumption. For servers, stores sessions in internal cache. For clients,
 * stores sessions for reuse when reconnecting to the same server.
 *
 * Installs callbacks to track cache statistics (hits, misses, stores).
 * Statistics can be retrieved via SocketTLSContext_get_cache_stats().
 *
 * Thread-safe: No - call before sharing context across threads.
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

  long sess_timeout = timeout_seconds > 0 ? timeout_seconds
                                          : SOCKET_TLS_SESSION_TIMEOUT_DEFAULT;
  if (sess_timeout > SOCKET_TLS_SESSION_MAX_TIMEOUT)
    {
      RAISE_CTX_ERROR_FMT (
          SocketTLS_Failed,
          "Session timeout %ld seconds exceeds maximum allowed %ld",
          sess_timeout, SOCKET_TLS_SESSION_MAX_TIMEOUT);
    }
  SSL_CTX_set_timeout (ctx->ssl_ctx, sess_timeout);
  ctx->session_cache_enabled = 1;
}

/**
 * SocketTLSContext_set_session_cache_size - Update session cache size
 * @ctx: TLS context (must not be NULL)
 * @size: New cache size (must be > 0)
 *
 * Raises: SocketTLS_Failed on invalid size or OpenSSL error
 *
 * Updates the maximum number of sessions stored in the cache. Existing
 * sessions beyond the new limit may be evicted by OpenSSL.
 *
 * Thread-safe: No - call before sharing context across threads.
 */
void
SocketTLSContext_set_session_cache_size (T ctx, size_t size)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  set_cache_size (ctx, size);
}

/**
 * SocketTLSContext_get_cache_stats - Retrieve session cache statistics
 * @ctx: TLS context (may be NULL)
 * @hits: Output for cache hits (session reused) - may be NULL
 * @misses: Output for cache misses (full handshake) - may be NULL
 * @stores: Output for new sessions stored - may be NULL
 *
 * Returns statistics via output parameters. If ctx is NULL or session cache
 * is not enabled, all outputs are set to 0.
 *
 * Thread-safe: Yes - protected by stats_mutex.
 */
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

/**
 * SocketTLSContext_enable_session_tickets - Enable TLS session tickets
 * @ctx: TLS context (must not be NULL)
 * @key: Session ticket encryption key (must be SOCKET_TLS_TICKET_KEY_LEN
 * bytes)
 * @key_len: Key length (must equal SOCKET_TLS_TICKET_KEY_LEN = 80)
 *
 * Raises: SocketTLS_Failed on invalid key length or OpenSSL error
 *
 * Enables stateless session resumption via encrypted session tickets.
 * The key should be cryptographically random and rotated periodically.
 * Key format (80 bytes total):
 *   - 16 bytes: ticket name (identifies which key encrypted the ticket)
 *   - 32 bytes: AES-256 key (encrypts ticket contents)
 *   - 32 bytes: HMAC-SHA256 key (authenticates ticket)
 *
 * Security: The key is copied into the context structure and will be
 * securely cleared when the context is freed.
 *
 * Thread-safe: No - call before sharing context across threads.
 */
void
SocketTLSContext_enable_session_tickets (T ctx, const unsigned char *key,
                                         size_t key_len)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (key_len != SOCKET_TLS_TICKET_KEY_LEN)
    {
      RAISE_CTX_ERROR_FMT (
          SocketTLS_Failed,
          "Session ticket key length must be exactly %d bytes",
          SOCKET_TLS_TICKET_KEY_LEN);
    }

  if (key == NULL)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Session ticket key pointer cannot be NULL");
    }

  /* Copy key into structure for secure clearing on context free */
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

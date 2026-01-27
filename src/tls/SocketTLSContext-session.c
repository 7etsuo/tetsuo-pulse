/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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

/* Return 0: OpenSSL owns session. Return 1: callback takes ownership. */
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
          /* Cast: OpenSSL API inconsistency - SSL_session_reused needs
           * non-const */
          if (SSL_session_reused ((SSL *)ssl))
            ctx->cache_hits++;
          else
            ctx->cache_misses++;
          pthread_mutex_unlock (&ctx->stats_mutex);
        }
    }
}

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
          "Session cache size %zu exceeds security limit of %zu",
          size,
          limits.tls_session_cache_size);
    }

  if (size > (size_t)LONG_MAX)
    {
      RAISE_CTX_ERROR_FMT (
          SocketTLS_Failed,
          "Session cache size %zu exceeds maximum supported value %ld",
          size,
          LONG_MAX);
    }

  if (SSL_CTX_sess_set_cache_size (ctx->ssl_ctx, (long)size) == 0)
    ctx_raise_openssl_error ("Failed to set session cache size");

  ctx->session_cache_size = size;
}

void
SocketTLSContext_set_session_id_context (T ctx,
                                         const unsigned char *context,
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
          SSL_MAX_SID_CTX_LENGTH,
          context_len);
    }

  if (SSL_CTX_set_session_id_context (
          ctx->ssl_ctx, context, (unsigned int)context_len)
      != 1)
    {
      ctx_raise_openssl_error ("Failed to set session ID context");
    }
}

void
SocketTLSContext_enable_session_cache (T ctx,
                                       size_t max_sessions,
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
          sess_timeout,
          SOCKET_TLS_SESSION_MAX_TIMEOUT);
    }
  SSL_CTX_set_timeout (ctx->ssl_ctx, sess_timeout);
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
SocketTLSContext_get_cache_stats (T ctx,
                                  size_t *hits,
                                  size_t *misses,
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

static int
configure_ticket_keys (T ctx, const unsigned char *key, size_t key_len)
{
  assert (ctx != NULL);
  assert (key != NULL);
  assert (key_len == SOCKET_TLS_TICKET_KEY_LEN);

  memcpy (ctx->ticket_key, key, key_len);

  if (SSL_CTX_ctrl (ctx->ssl_ctx,
                    SSL_CTRL_SET_TLSEXT_TICKET_KEYS,
                    (int)key_len,
                    ctx->ticket_key)
      != 1)
    {
      OPENSSL_cleanse (ctx->ticket_key, SOCKET_TLS_TICKET_KEY_LEN);
      return 0;
    }

  return 1;
}

void
SocketTLSContext_enable_session_tickets (T ctx,
                                         const unsigned char *key,
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

  if (key == NULL)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Session ticket key pointer cannot be NULL");
    }

  /* Reject all-zeros key - matches DTLS cookie secret validation */
  static const unsigned char zeros[SOCKET_TLS_TICKET_KEY_LEN] = { 0 };
  if (SocketCrypto_secure_compare (key, zeros, SOCKET_TLS_TICKET_KEY_LEN) == 0)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Session ticket key cannot be all zeros");
    }

  if (!configure_ticket_keys (ctx, key, key_len))
    {
      ctx_raise_openssl_error ("Failed to set session ticket keys");
    }

  ctx->tickets_enabled = 1;
}

void
SocketTLSContext_rotate_session_ticket_key (T ctx,
                                            const unsigned char *new_key,
                                            size_t new_key_len)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (!ctx->tickets_enabled)
    {
      RAISE_CTX_ERROR_MSG (
          SocketTLS_Failed,
          "Cannot rotate session ticket key: tickets not enabled");
    }

  if (new_key_len != SOCKET_TLS_TICKET_KEY_LEN)
    {
      RAISE_CTX_ERROR_FMT (
          SocketTLS_Failed,
          "Session ticket key length must be exactly %d bytes, got %zu",
          SOCKET_TLS_TICKET_KEY_LEN,
          new_key_len);
    }

  if (new_key == NULL)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "New session ticket key pointer cannot be NULL");
    }

  pthread_mutex_lock (&ctx->stats_mutex);
  OPENSSL_cleanse (ctx->ticket_key, SOCKET_TLS_TICKET_KEY_LEN);

  if (!configure_ticket_keys (ctx, new_key, new_key_len))
    {
      ctx->tickets_enabled = 0;
      pthread_mutex_unlock (&ctx->stats_mutex);
      ctx_raise_openssl_error ("Failed to rotate session ticket keys");
    }

  pthread_mutex_unlock (&ctx->stats_mutex);
}

int
SocketTLSContext_session_tickets_enabled (T ctx)
{
  if (!ctx)
    return 0;
  return ctx->tickets_enabled;
}

void
SocketTLSContext_disable_session_tickets (T ctx)
{
  assert (ctx);

  if (!ctx->tickets_enabled)
    return;

  pthread_mutex_lock (&ctx->stats_mutex);
  OPENSSL_cleanse (ctx->ticket_key, SOCKET_TLS_TICKET_KEY_LEN);
  ctx->tickets_enabled = 0;
  SSL_CTX_set_options (ctx->ssl_ctx, SSL_OP_NO_TICKET);
  pthread_mutex_unlock (&ctx->stats_mutex);
}

#undef T

#endif /* SOCKET_HAS_TLS */

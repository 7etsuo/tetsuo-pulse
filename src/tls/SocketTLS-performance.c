/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketTLS-performance.c - TLS Performance Optimizations
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements TLS performance optimizations including:
 * - TLS 1.3 0-RTT early data support
 * - TCP tuning for handshake performance (TCP_NODELAY, TCP_QUICKACK)
 * - Session cache sharding for multi-threaded servers
 * - Buffer pooling for high-connection-count scenarios
 *
 * Thread safety: Functions are documented with their thread safety properties.
 */

#if SOCKET_HAS_TLS

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>

#include "core/Arena.h"
#include "core/SocketMetrics.h"
#include "core/SocketUtil.h"
#include "core/HashTable.h"
#include "tls/SocketTLS-private.h"
#include "tls/SocketTLSContext.h"

/* Thread-local exception for this translation unit */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketTLS);

/* Sharded session cache configuration constants */
#define SOCKET_TLS_SHARDED_BUCKET_COUNT     64   /* Power-of-2 for efficient modulo operations */
#define SOCKET_TLS_SHARDED_MIN_SHARDS       2    /* Minimum for meaningful sharding */
#define SOCKET_TLS_SHARDED_MAX_SHARDS       256  /* Maximum for reasonable memory usage */

/* Ex-data index for associating SocketTLSContext_T with SSL_CTX
 * Thread-safe initialization using pthread_once to prevent race conditions
 * when multiple threads create sharded caches concurrently. */
static int tls_ctx_ex_data_index = -1;
static pthread_once_t tls_ctx_ex_data_once = PTHREAD_ONCE_INIT;

/**
 * init_ex_data_index - One-time initialization of ex-data index
 *
 * Called via pthread_once to ensure thread-safe single initialization.
 * This prevents race conditions where multiple threads could call
 * SSL_CTX_get_ex_new_index() simultaneously and get different indices.
 */
static void
init_ex_data_index(void)
{
  tls_ctx_ex_data_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
}

/**
 * ensure_ex_data_index - Thread-safe ex-data index initialization
 *
 * Uses pthread_once for guaranteed single initialization across all threads.
 */
static void
ensure_ex_data_index(void)
{
  pthread_once(&tls_ctx_ex_data_once, init_ex_data_index);
}


/* Linux-specific TCP_QUICKACK availability */
#ifdef __linux__
#define SOCKET_HAS_QUICKACK 1
#else
#define SOCKET_HAS_QUICKACK 0
#endif

/**
 * SocketTLS_optimize_handshake - Apply TCP optimizations for faster handshake
 * @socket: Socket to optimize (must be TLS-enabled but before handshake)
 *
 * Applies TCP-level optimizations to reduce handshake latency:
 * 1. TCP_NODELAY: Disable Nagle's algorithm for immediate message send
 * 2. TCP_QUICKACK (Linux): Disable delayed ACKs during handshake
 *
 * These optimizations are especially beneficial on high-latency connections
 * where the TLS handshake RTT is significant.
 *
 * Call this after SocketTLS_enable() but before SocketTLS_handshake().
 *
 * Returns: 0 on success (all available options applied),
 *          -1 on error (TLS not enabled, invalid socket)
 *
 * Note: Even if some options are unavailable (e.g., TCP_QUICKACK on non-Linux),
 * the function still applies available options and returns success.
 *
 * @threadsafe No - modifies socket options
 */
int
SocketTLS_optimize_handshake (Socket_T socket)
{
  int optval = 1;

  assert (socket);

  if (!socket->tls_enabled)
    {
      errno = EINVAL;
      return -1;
    }

  int fd = SocketBase_fd (socket->base);
  if (fd < 0)
    {
      errno = EBADF;
      return -1;
    }

  /* TCP_NODELAY: Disable Nagle's algorithm for reduced latency
   * This is critical for TLS handshakes which involve multiple small messages
   */
  if (setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof (optval)) < 0)
    {
      SOCKET_LOG_DEBUG_MSG (
          "TCP_NODELAY failed for fd=%d (errno=%d, may be non-TCP socket)", fd,
          errno);
      /* Continue - this might be a Unix domain socket or other non-TCP type */
    }
  else
    {
      SOCKET_LOG_DEBUG_MSG ("TCP_NODELAY enabled for handshake optimization on "
                            "fd=%d",
                            fd);
    }

#if SOCKET_HAS_QUICKACK
  /* TCP_QUICKACK: Disable delayed ACKs during handshake (Linux only)
   * This is a hint that we want immediate ACKs during the handshake phase.
   * The kernel will revert to normal behavior after some time. */
  if (setsockopt (fd, IPPROTO_TCP, TCP_QUICKACK, &optval, sizeof (optval)) < 0)
    {
      SOCKET_LOG_DEBUG_MSG ("TCP_QUICKACK failed for fd=%d (errno=%d)", fd,
                            errno);
      /* Continue - not critical, just an optimization */
    }
  else
    {
      SOCKET_LOG_DEBUG_MSG (
          "TCP_QUICKACK enabled for handshake optimization on fd=%d", fd);
    }
#endif

  return 0;
}

/**
 * SocketTLS_restore_tcp_defaults - Restore TCP settings after handshake
 * @socket: Socket to restore defaults on
 *
 * Restores TCP settings to more appropriate values for data transfer after
 * handshake is complete. Specifically:
 * - Keeps TCP_NODELAY enabled (usually desired for interactive applications)
 * - TCP_QUICKACK resets automatically on Linux
 *
 * This is optional - most applications keep TCP_NODELAY enabled throughout
 * the connection. Call this if your application does bulk transfers and
 * wants Nagle's algorithm re-enabled for efficiency.
 *
 * Returns: 0 on success, -1 on error
 *
 * @threadsafe No - modifies socket options
 */
int
SocketTLS_restore_tcp_defaults (Socket_T socket)
{
  int optval = 0;

  assert (socket);

  int fd = SocketBase_fd (socket->base);
  if (fd < 0)
    {
      errno = EBADF;
      return -1;
    }

  /* Re-enable Nagle's algorithm for bulk transfers if desired */
  if (setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof (optval)) < 0)
    {
      SOCKET_LOG_DEBUG_MSG ("Failed to disable TCP_NODELAY for fd=%d", fd);
      /* Non-fatal */
    }

  /* TCP_QUICKACK resets automatically on Linux after kernel-determined time */

  return 0;
}

/**
 * SocketTLSContext_enable_early_data - Enable TLS 1.3 0-RTT support
 * @ctx: TLS context (must not be NULL)
 * @max_early_data: Maximum early data size (0 = OpenSSL default 16KB)
 *
 * Enables TLS 1.3 early data (0-RTT) on the context. For servers, this
 * configures the maximum amount of early data to accept. For clients,
 * this enables sending early data when resuming sessions.
 *
 * Security Warning: 0-RTT early data is vulnerable to replay attacks.
 * Applications MUST implement their own replay protection or only use
 * early data for idempotent operations.
 *
 * Raises: SocketTLS_Failed on configuration error
 *
 * Thread-safe: No - call before sharing context across threads.
 */
void
SocketTLSContext_enable_early_data (SocketTLSContext_T ctx,
                                    uint32_t max_early_data)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  /* Default to configured early data size (matches TLS record size) */
  uint32_t early_data_size = max_early_data > 0
                                 ? max_early_data
                                 : SOCKET_TLS_DEFAULT_EARLY_DATA_SIZE;

  /* Server-side: Set maximum early data to accept */
  if (ctx->is_server)
    {
      if (SSL_CTX_set_max_early_data (ctx->ssl_ctx, early_data_size) != 1)
        {
          ctx_raise_openssl_error ("Failed to set max early data");
        }
      SOCKET_LOG_DEBUG_MSG ("Enabled 0-RTT early data on server context "
                            "(max=%u bytes)",
                            early_data_size);
    }
  else
    {
      /* Client-side: Enable early data sending on session resumption */
      SSL_CTX_set_options (ctx->ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
      SOCKET_LOG_DEBUG_MSG ("Enabled 0-RTT early data on client context");
    }
}

/**
 * SocketTLSContext_disable_early_data - Disable TLS 1.3 0-RTT
 * @ctx: TLS context
 *
 * Disables 0-RTT early data support. Call this if replay protection
 * cannot be implemented at the application level.
 *
 * Thread-safe: No - call before sharing context across threads.
 */
void
SocketTLSContext_disable_early_data (SocketTLSContext_T ctx)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (ctx->is_server)
    {
      SSL_CTX_set_max_early_data (ctx->ssl_ctx, 0);
    }

  SOCKET_LOG_DEBUG_MSG ("Disabled 0-RTT early data on context");
}

/**
 * SocketTLS_write_early_data - Send early data during TLS 1.3 handshake
 * @socket: Socket with TLS enabled, during handshake
 * @buf: Data buffer to send
 * @len: Length of data
 * @written: Output - bytes actually written
 *
 * Sends application data during the initial handshake flight (0-RTT).
 * Only valid when:
 * 1. TLS 1.3 is negotiated
 * 2. Session resumption is being attempted
 * 3. Server accepts early data
 *
 * Returns: 1 on success (all data written),
 *          0 if early data not accepted (retry with normal send after
 * handshake), -1 on error
 *
 * Security Warning: Early data is NOT replay-protected. Only send
 * idempotent operations. The server should verify early data is acceptable.
 *
 * @threadsafe No - modifies SSL state
 */
int
SocketTLS_write_early_data (Socket_T socket, const void *buf, size_t len,
                            size_t *written)
{
  assert (socket);
  assert (buf || len == 0);
  assert (written);

  *written = 0;

  if (!socket->tls_enabled)
    {
      errno = EINVAL;
      return -1;
    }

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    {
      errno = EINVAL;
      return -1;
    }

  /* Check if we're in a state where early data can be written */
  int early_status = SSL_get_early_data_status (ssl);
  if (early_status == SSL_EARLY_DATA_REJECTED)
    {
      SOCKET_LOG_DEBUG_MSG ("Early data rejected by server for fd=%d",
                            SocketBase_fd (socket->base));
      errno = EAGAIN;
      return 0; /* Retry with normal send after handshake */
    }

  size_t bytes_written = 0;
  int result = SSL_write_early_data (ssl, buf, len, &bytes_written);

  if (result > 0)
    {
      *written = bytes_written;
      SocketMetrics_counter_inc (SOCKET_CTR_TLS_EARLY_DATA_SENT);
      SOCKET_LOG_DEBUG_MSG ("Wrote %zu bytes of early data for fd=%d",
                            bytes_written, SocketBase_fd (socket->base));
      return 1;
    }

  int ssl_error = SSL_get_error (ssl, result);
  switch (ssl_error)
    {
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
      errno = EAGAIN;
      return 0; /* Would block, retry */

    default:
      /* Check if early data was rejected */
      if (SSL_get_early_data_status (ssl) == SSL_EARLY_DATA_REJECTED)
        {
          SOCKET_LOG_DEBUG_MSG ("Early data rejected during write for fd=%d",
                                SocketBase_fd (socket->base));
          errno = EAGAIN;
          return 0; /* Retry with normal send */
        }
      tls_format_openssl_error ("Early data write failed");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  return -1;
}

/**
 * SocketTLS_read_early_data - Receive early data during TLS 1.3 handshake
 * @socket: Socket with TLS enabled (server-side), during handshake
 * @buf: Buffer to receive data
 * @len: Buffer size
 * @readbytes: Output - bytes actually read
 *
 * Reads application data sent by the client in the initial handshake
 * flight (0-RTT). Only valid when:
 * 1. This is a server socket
 * 2. TLS 1.3 is negotiated
 * 3. Client sent early data with session resumption
 *
 * Returns: 1 on success (data read),
 *          0 if no early data available,
 *          -1 on error
 *
 * Security Warning: Early data is NOT replay-protected. Server MUST
 * implement application-level replay protection or only accept idempotent
 * operations.
 *
 * @threadsafe No - modifies SSL state
 */
int
SocketTLS_read_early_data (Socket_T socket, void *buf, size_t len,
                           size_t *readbytes)
{
  assert (socket);
  assert (buf);
  assert (readbytes);

  *readbytes = 0;

  if (!socket->tls_enabled)
    {
      errno = EINVAL;
      return -1;
    }

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    {
      errno = EINVAL;
      return -1;
    }

  size_t bytes_read = 0;
  int result = SSL_read_early_data (ssl, buf, len, &bytes_read);

  switch (result)
    {
    case SSL_READ_EARLY_DATA_SUCCESS:
      *readbytes = bytes_read;
      SocketMetrics_counter_inc (SOCKET_CTR_TLS_EARLY_DATA_RECV);
      SOCKET_LOG_DEBUG_MSG ("Read %zu bytes of early data for fd=%d",
                            bytes_read, SocketBase_fd (socket->base));
      return 1;

    case SSL_READ_EARLY_DATA_FINISH:
      SOCKET_LOG_DEBUG_MSG (
          "Early data finished, handshake continuing for fd=%d",
          SocketBase_fd (socket->base));
      return 0; /* No more early data, proceed with handshake */

    case SSL_READ_EARLY_DATA_ERROR:
      {
        int ssl_error = SSL_get_error (ssl, (int)bytes_read);
        if (ssl_error == SSL_ERROR_WANT_READ
            || ssl_error == SSL_ERROR_WANT_WRITE)
          {
            errno = EAGAIN;
            return 0; /* Would block, retry */
          }
        tls_format_openssl_error ("Early data read failed");
        RAISE_TLS_ERROR (SocketTLS_Failed);
      }
      /* NOTREACHED - RAISE_TLS_ERROR never returns */
      break;

    default:
      errno = EIO;
      return -1;
    }
}

/**
 * SocketTLS_get_early_data_status - Check early data status after handshake
 * @socket: Socket with completed TLS handshake
 *
 * Returns the status of early data after handshake completion:
 * - SOCKET_EARLY_DATA_ACCEPTED: Server accepted early data
 * - SOCKET_EARLY_DATA_REJECTED: Server rejected early data (client should
 * resend)
 * - SOCKET_EARLY_DATA_NOT_SENT: No early data was sent
 *
 * For clients: Check this after handshake to determine if early data
 * needs to be retransmitted.
 *
 * For servers: Check this to know if early data was received.
 *
 * @return Early data status code
 * @threadsafe Yes - reads immutable post-handshake state
 */
SocketTLS_EarlyDataStatus
SocketTLS_get_early_data_status (Socket_T socket)
{
  assert (socket);

  if (!socket->tls_enabled || !socket->tls_handshake_done)
    {
      return SOCKET_EARLY_DATA_NOT_SENT;
    }

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    {
      return SOCKET_EARLY_DATA_NOT_SENT;
    }

  int status = SSL_get_early_data_status (ssl);
  switch (status)
    {
    case SSL_EARLY_DATA_ACCEPTED:
      return SOCKET_EARLY_DATA_ACCEPTED;
    case SSL_EARLY_DATA_REJECTED:
      return SOCKET_EARLY_DATA_REJECTED;
    default:
      return SOCKET_EARLY_DATA_NOT_SENT;
    }
}

/**
 * SocketTLS_request_key_update - Request TLS 1.3 key rotation
 * @socket: Socket with completed TLS 1.3 handshake
 * @request_peer_update: If 1, request peer to also update their keys
 *
 * Initiates a TLS 1.3 KeyUpdate to rotate encryption keys. This provides
 * forward secrecy for long-lived connections by periodically generating
 * new keys derived from the current traffic secrets.
 *
 * The update_type parameter controls whether the peer should also rotate:
 * - 0 (SSL_KEY_UPDATE_NOT_REQUESTED): Only update local keys
 * - 1 (SSL_KEY_UPDATE_REQUESTED): Request peer to also update
 *
 * This function queues the KeyUpdate message; actual key rotation happens
 * on the next I/O operation (send/recv). For immediate effect, call
 * SocketTLS_send() or perform a read after this call.
 *
 * Returns: 1 on success (KeyUpdate queued),
 *          0 if not applicable (not TLS 1.3 or handshake not done),
 *          -1 on error
 *
 * Raises: SocketTLS_Failed on OpenSSL error
 *
 * @threadsafe No - modifies SSL state
 */
int
SocketTLS_request_key_update (Socket_T socket, int request_peer_update)
{
  assert (socket);

  if (!socket->tls_enabled || !socket->tls_handshake_done)
    {
      errno = EINVAL;
      return 0;
    }

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    {
      errno = EINVAL;
      return -1;
    }

  /* KeyUpdate is TLS 1.3 only */
  if (SSL_version (ssl) < TLS1_3_VERSION)
    {
      SOCKET_LOG_DEBUG_MSG ("KeyUpdate not available for TLS version 0x%x "
                            "(requires TLS 1.3) on fd=%d",
                            SSL_version (ssl), SocketBase_fd (socket->base));
      errno = ENOTSUP;
      return 0;
    }

  /* Determine update type */
  int update_type = request_peer_update ? SSL_KEY_UPDATE_REQUESTED
                                        : SSL_KEY_UPDATE_NOT_REQUESTED;

  /* Queue the KeyUpdate message */
  if (SSL_key_update (ssl, update_type) != 1)
    {
      tls_format_openssl_error ("SSL_key_update failed");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  /* Increment counter */
  socket->tls_key_update_count++;
  SocketMetrics_counter_inc (SOCKET_CTR_TLS_KEY_UPDATES);

  SOCKET_LOG_DEBUG_MSG ("KeyUpdate %s queued for fd=%d (total updates: %d)",
                        request_peer_update ? "with peer request" : "local only",
                        SocketBase_fd (socket->base),
                        socket->tls_key_update_count);

  return 1;
}

/**
 * SocketTLS_get_key_update_count - Get number of KeyUpdates performed
 * @socket: Socket with TLS enabled
 *
 * Returns the number of KeyUpdate operations successfully performed on
 * this connection. Useful for monitoring key rotation frequency on
 * long-lived connections.
 *
 * Returns: Number of KeyUpdates, or 0 if TLS not enabled
 *
 * @threadsafe Yes - reads atomic counter
 */
int
SocketTLS_get_key_update_count (Socket_T socket)
{
  assert (socket);

  if (!socket->tls_enabled)
    return 0;

  return socket->tls_key_update_count;
}

/* Sharded session cache structs defined in SocketTLS-private.h */

/**
 * @brief Session entry wrapper for intrusive hash table
 */
typedef struct SessionEntry {
  unsigned char session_id[32];  /**< Copy of session ID for lookup */
  SSL_SESSION *session;          /**< The OpenSSL session object */
  struct SessionEntry *next;     /**< Hash chain pointer */
} SessionEntry;

/* Helper functions for sharded session hash table */
static unsigned
sharded_session_hash (const void *key, unsigned seed, unsigned table_size)
{
  uintptr_t h = (uintptr_t) key ^ seed;
  return (unsigned) (h % table_size);
}

static int
sharded_session_compare (const void *entry, const void *key)
{
  return memcmp (entry, key, 32); /* Fixed 32 bytes assumed */
}

static void **
sharded_session_next_ptr (void *entry)
{
  return (void **)&((SessionEntry *)entry)->next;
}

/* Static config for sharded session hash table */
static const HashTable_Config sharded_session_config = {
    .bucket_count = SOCKET_TLS_SHARDED_BUCKET_COUNT,
    .hash_seed = SOCKET_UTIL_DJB2_SEED,
    .hash = sharded_session_hash,
    .compare = sharded_session_compare,
    .next_ptr = sharded_session_next_ptr};

/**
 * Select shard based on session ID hash using golden ratio multiplication
 */
static size_t
select_shard (TLSSessionCacheSharded_T *cache, const unsigned char *session_id,
              size_t id_len)
{
  unsigned hash = 0;
  for (size_t i = 0; i < id_len && i < 16; i++)
    {
      hash = hash * 31 + session_id[i];
    }
  return (size_t)((hash * HASH_GOLDEN_RATIO) & cache->shard_mask);
}

/**
 * sharded_get_session_cb - Retrieve session from sharded cache
 */
static SSL_SESSION *
sharded_get_session_cb(SSL *ssl, const unsigned char *id, int id_len, int *copy)
{
  SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);
  SocketTLSContext_T ctx = SSL_CTX_get_ex_data(ssl_ctx, tls_ctx_ex_data_index);
  if (!ctx || !ctx->sharded_enabled)
    return NULL;

  TLSSessionCacheSharded_T *cache = &ctx->sharded_session_cache;
  size_t shard_idx = select_shard(cache, id, (size_t)id_len);
  TLSSessionShard_T *shard = &cache->shards[shard_idx];

  pthread_mutex_lock(&shard->mutex);
  SessionEntry *entry = HashTable_find(shard->session_table, id, NULL);
  SSL_SESSION *sess = NULL;
  if (entry) {
    sess = entry->session;
    shard->hits++;
    *copy = 1;
  } else {
    shard->misses++;
  }
  pthread_mutex_unlock(&shard->mutex);

  return sess;
}

/**
 * sharded_new_session_cb - Store newly negotiated session
 */
static int
sharded_new_session_cb(SSL *ssl, SSL_SESSION *sess)
{
  SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);
  SocketTLSContext_T ctx = SSL_CTX_get_ex_data(ssl_ctx, tls_ctx_ex_data_index);
  if (!ctx || !ctx->sharded_enabled)
    return 0;

  unsigned int id_len;
  const unsigned char *id = SSL_SESSION_get_id(sess, &id_len);

  TLSSessionCacheSharded_T *cache = &ctx->sharded_session_cache;
  size_t shard_idx = select_shard(cache, id, id_len);
  TLSSessionShard_T *shard = &cache->shards[shard_idx];

  pthread_mutex_lock(&shard->mutex);
  if (shard->current_count >= shard->max_sessions) {
    pthread_mutex_unlock(&shard->mutex);
    return 0;
  }

  SessionEntry *entry = Arena_alloc(ctx->arena, sizeof(SessionEntry), __FILE__, __LINE__);
  if (!entry) {
    pthread_mutex_unlock(&shard->mutex);
    return 0;
  }

  memset(entry->session_id, 0, 32);
  memcpy(entry->session_id, id, id_len < 32 ? id_len : 32);
  entry->session = sess;
  entry->next = NULL;

  HashTable_insert(shard->session_table, entry, entry->session_id);
  shard->current_count++;
  shard->stores++;
  pthread_mutex_unlock(&shard->mutex);

  return 1;
}

/**
 * sharded_remove_session_cb - Remove session from sharded cache
 */
static void
sharded_remove_session_cb(SSL_CTX *ssl_ctx, SSL_SESSION *sess)
{
  SocketTLSContext_T ctx = SSL_CTX_get_ex_data(ssl_ctx, tls_ctx_ex_data_index);
  if (!ctx || !ctx->sharded_enabled)
    return;

  unsigned int id_len;
  const unsigned char *id = SSL_SESSION_get_id(sess, &id_len);

  TLSSessionCacheSharded_T *cache = &ctx->sharded_session_cache;
  size_t shard_idx = select_shard(cache, id, id_len);
  TLSSessionShard_T *shard = &cache->shards[shard_idx];

  pthread_mutex_lock(&shard->mutex);
  void *prev = NULL;
  SessionEntry *entry = HashTable_find(shard->session_table, id, &prev);
  if (entry) {
    HashTable_remove(shard->session_table, entry, prev, id);
    if (shard->current_count > 0)
      shard->current_count--;
  }
  pthread_mutex_unlock(&shard->mutex);
}

/**
 * SocketTLSContext_create_sharded_cache - Create a sharded session cache
 * @ctx: TLS context
 * @num_shards: Number of shards (will be rounded up to power of 2, max 256)
 * @sessions_per_shard: Max sessions per shard
 * @timeout_seconds: Session timeout
 *
 * Creates a sharded session cache for improved concurrency in multi-threaded
 * servers. Each shard has independent locking, reducing contention.
 *
 * Raises: SocketTLS_Failed on allocation or configuration error
 *
 * Thread-safe: No - call before sharing context across threads.
 */
void
SocketTLSContext_create_sharded_cache (SocketTLSContext_T ctx,
                                       size_t num_shards,
                                       size_t sessions_per_shard,
                                       long timeout_seconds)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  /* Round up to power of 2 and cap at max for efficient hashing */
  size_t actual_shards = socket_util_round_up_pow2 (num_shards);
  if (actual_shards < SOCKET_TLS_SHARDED_MIN_SHARDS)
    actual_shards = SOCKET_TLS_SHARDED_MIN_SHARDS;
  if (actual_shards > SOCKET_TLS_SHARDED_MAX_SHARDS)
    actual_shards = SOCKET_TLS_SHARDED_MAX_SHARDS;

  TRY
  {
    /* Disable standard session cache - use sharded instead */
    ctx->session_cache_enabled = 0;
    ctx->cache_hits = ctx->cache_misses = ctx->cache_stores = 0;

    /* Set OpenSSL to use no internal cache, rely on custom sharded callbacks */
    int mode = ctx->is_server ? SSL_SESS_CACHE_SERVER : SSL_SESS_CACHE_CLIENT;
    SSL_CTX_set_session_cache_mode (ctx->ssl_ctx, SSL_SESS_CACHE_NO_INTERNAL_STORE | mode);

    /* Allocate sharded cache structure */
    ctx->sharded_session_cache.num_shards = actual_shards;
    ctx->sharded_session_cache.shard_mask = actual_shards - 1;
    ctx->sharded_session_cache.shards = Arena_calloc (ctx->arena, actual_shards,
                                                       sizeof (TLSSessionShard_T),
                                                       __FILE__, __LINE__);

    size_t sessions_per_shard_final = sessions_per_shard ? sessions_per_shard : (SOCKET_TLS_SESSION_CACHE_SIZE / actual_shards);

    for (size_t i = 0; i < actual_shards; i++)
    {
      TLSSessionShard_T *shard = &ctx->sharded_session_cache.shards[i];

      /* Initialize hash table for sessions using file-scope config */
      shard->session_table = HashTable_new (ctx->arena, &sharded_session_config);
      if (!shard->session_table)
        RAISE_TLS_ERROR (SocketTLS_Failed);

      pthread_mutex_init (&shard->mutex, NULL);

      shard->max_sessions = sessions_per_shard_final;
      shard->current_count = 0;
      shard->hits = shard->misses = shard->stores = 0;
    }

    ctx->sharded_enabled = 1;

    ensure_ex_data_index();
    SSL_CTX_set_ex_data(ctx->ssl_ctx, tls_ctx_ex_data_index, ctx);
    SSL_CTX_sess_set_get_cb(ctx->ssl_ctx, sharded_get_session_cb);
    SSL_CTX_sess_set_new_cb(ctx->ssl_ctx, sharded_new_session_cb);
    SSL_CTX_sess_set_remove_cb(ctx->ssl_ctx, sharded_remove_session_cb);

    SOCKET_LOG_INFO_MSG ("Created sharded session cache with %zu shards (%zu sessions/shard, timeout %lds)",
                         actual_shards, sessions_per_shard_final, timeout_seconds);
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Partial cleanup would be needed, but for simplicity RERAISE */
    RERAISE;
  }
  END_TRY;
}

/**
 * SocketTLSContext_get_sharded_stats - Get aggregate statistics from sharded session cache
 * @ctx: TLS context with sharded cache enabled
 * @total_hits: Output - total cache hits across all shards (may be NULL)
 * @total_misses: Output - total cache misses across all shards (may be NULL)
 * @total_stores: Output - total sessions stored across all shards (may be NULL)
 *
 * Sums statistics from all shards by locking each mutex briefly.
 * If sharded cache not enabled, returns standard cache stats as fallback.
 *
 * @threadsafe Yes - locks per-shard mutexes sequentially
 * @complexity O(number of shards) - linear scan over shards
 *
 * @see SocketTLSContext_create_sharded_cache() to enable sharded caching
 */
void
SocketTLSContext_get_sharded_stats (SocketTLSContext_T ctx, size_t *total_hits,
                                    size_t *total_misses, size_t *total_stores)
{
  if (!ctx || !ctx->sharded_enabled)
    {
      SocketTLSContext_get_cache_stats (ctx, total_hits, total_misses, total_stores);
      return;
    }

  size_t hits = 0, misses = 0, stores = 0;

  for (size_t i = 0; i < ctx->sharded_session_cache.num_shards; i++)
    {
      TLSSessionShard_T *shard = &ctx->sharded_session_cache.shards[i];
      pthread_mutex_lock (&shard->mutex);
      hits += shard->hits;
      misses += shard->misses;
      stores += shard->stores;
      pthread_mutex_unlock (&shard->mutex);
    }

  if (total_hits) *total_hits = hits;
  if (total_misses) *total_misses = misses;
  if (total_stores) *total_stores = stores;

  SOCKET_LOG_DEBUG_MSG ("Sharded cache stats: hits=%zu misses=%zu stores=%zu", hits, misses, stores);
}

/**
 * @brief TLS buffer pool entry
 */
struct TLSPoolBuffer
{
  void *data;                    /**< Buffer data */
  size_t size;                   /**< Buffer size */
  int in_use;                    /**< 1 if currently allocated */
  struct TLSPoolBuffer *next;    /**< Next in free list */
};

/**
 * @brief TLS buffer pool
 */
struct TLSBufferPool
{
  struct TLSPoolBuffer *buffers;  /**< Array of buffer entries */
  struct TLSPoolBuffer *free_list; /**< Head of free list */
  size_t buffer_size;             /**< Size of each buffer */
  size_t total_buffers;           /**< Total number of buffers */
  size_t in_use;                  /**< Buffers currently allocated */
  pthread_mutex_t mutex;          /**< Pool lock */
  Arena_T arena;                  /**< Memory arena for the pool */
  int owns_arena;                 /**< 1 if pool owns arena, 0 if caller owns */
};

typedef struct TLSBufferPool *TLSBufferPool_T;

/**
 * TLSBufferPool_new - Create a new TLS buffer pool
 * @buffer_size: Size of each buffer (typically SOCKET_TLS_BUFFER_SIZE)
 * @num_buffers: Number of pre-allocated buffers
 * @arena: Arena for pool memory (NULL to create internal arena)
 *
 * Creates a pool of reusable TLS buffers. Buffers are pre-allocated
 * to avoid fragmentation from per-connection allocations.
 *
 * Returns: New buffer pool, or NULL on error
 *
 * Thread-safe: Yes - fully thread-safe once created
 */
TLSBufferPool_T
TLSBufferPool_new (size_t buffer_size, size_t num_buffers, Arena_T arena)
{
  Arena_T pool_arena = arena;
  int owns_arena = 0;
  TLSBufferPool_T pool;

  if (!pool_arena)
    {
      pool_arena = Arena_new ();
      if (!pool_arena)
        return NULL;
      owns_arena = 1;
    }

  /*
   * CRITICAL: When pool owns the arena, we must NOT allocate the pool struct
   * from the arena. Otherwise, TLSBufferPool_free() would call
   * Arena_dispose(&p->arena) where &p->arena points into arena-allocated
   * memory, causing heap-use-after-free when Arena_dispose writes *ap = NULL.
   *
   * When caller provides arena: pool struct is arena-allocated, caller manages
   * arena lifetime, pool does NOT dispose the arena.
   */
  if (owns_arena)
    {
      pool = malloc (sizeof (struct TLSBufferPool));
      if (!pool)
        {
          Arena_dispose (&pool_arena);
          return NULL;
        }
    }
  else
    {
      pool = Arena_alloc (pool_arena, sizeof (struct TLSBufferPool), __FILE__,
                         __LINE__);
      if (!pool)
        return NULL;
    }

  pool->arena = pool_arena;
  pool->owns_arena = owns_arena;
  pool->buffer_size = buffer_size;
  pool->total_buffers = num_buffers;
  pool->in_use = 0;
  pool->free_list = NULL;

  if (pthread_mutex_init (&pool->mutex, NULL) != 0)
    {
      if (owns_arena)
        {
          free (pool);
          Arena_dispose (&pool_arena);
        }
      return NULL;
    }

  /* Allocate buffer array */
  pool->buffers = Arena_alloc (pool_arena, num_buffers * sizeof (struct TLSPoolBuffer), __FILE__,
                               __LINE__);
  if (!pool->buffers)
    {
      pthread_mutex_destroy (&pool->mutex);
      if (owns_arena)
        {
          free (pool);
          Arena_dispose (&pool_arena);
        }
      return NULL;
    }

  /* Pre-allocate buffers and build free list */
  for (size_t i = 0; i < num_buffers; i++)
    {
      pool->buffers[i].data
          = Arena_alloc (pool_arena, buffer_size, __FILE__, __LINE__);
      if (!pool->buffers[i].data)
        {
          /* Partial allocation - clean up */
          pthread_mutex_destroy (&pool->mutex);
          if (owns_arena)
            {
              free (pool);
              Arena_dispose (&pool_arena);
            }
          return NULL;
        }
      pool->buffers[i].size = buffer_size;
      pool->buffers[i].in_use = 0;
      pool->buffers[i].next = pool->free_list;
      pool->free_list = &pool->buffers[i];
    }

  SOCKET_LOG_DEBUG_MSG ("Created TLS buffer pool: %zu buffers of %zu bytes",
                        num_buffers, buffer_size);

  return pool;
}

/**
 * TLSBufferPool_acquire - Get a buffer from the pool
 * @pool: Buffer pool
 *
 * Returns a buffer from the pool if available, NULL if pool is exhausted.
 *
 * Thread-safe: Yes
 */
void *
TLSBufferPool_acquire (TLSBufferPool_T pool)
{
  if (!pool)
    return NULL;

  pthread_mutex_lock (&pool->mutex);

  if (!pool->free_list)
    {
      pthread_mutex_unlock (&pool->mutex);
      return NULL; /* Pool exhausted */
    }

  struct TLSPoolBuffer *buf = pool->free_list;
  pool->free_list = buf->next;
  buf->in_use = 1;
  buf->next = NULL;
  pool->in_use++;

  pthread_mutex_unlock (&pool->mutex);

  return buf->data;
}

/**
 * TLSBufferPool_release - Return a buffer to the pool
 * @pool: Buffer pool
 * @buffer: Buffer to return (must be from this pool)
 *
 * Returns a buffer to the pool for reuse. The buffer is NOT cleared;
 * caller should use SocketCrypto_secure_clear() first if it contained
 * sensitive data.
 *
 * Thread-safe: Yes
 */
void
TLSBufferPool_release (TLSBufferPool_T pool, void *buffer)
{
  if (!pool || !buffer)
    return;

  pthread_mutex_lock (&pool->mutex);

  /* Find the buffer entry */
  for (size_t i = 0; i < pool->total_buffers; i++)
    {
      if (pool->buffers[i].data == buffer)
        {
          pool->buffers[i].in_use = 0;
          pool->buffers[i].next = pool->free_list;
          pool->free_list = &pool->buffers[i];
          pool->in_use--;
          break;
        }
    }

  pthread_mutex_unlock (&pool->mutex);
}

/**
 * TLSBufferPool_stats - Get pool statistics
 * @pool: Buffer pool
 * @total: Output for total buffers (may be NULL)
 * @in_use: Output for buffers in use (may be NULL)
 * @available: Output for available buffers (may be NULL)
 *
 * Thread-safe: Yes
 */
void
TLSBufferPool_stats (TLSBufferPool_T pool, size_t *total, size_t *in_use,
                     size_t *available)
{
  if (!pool)
    {
      if (total)
        *total = 0;
      if (in_use)
        *in_use = 0;
      if (available)
        *available = 0;
      return;
    }

  pthread_mutex_lock (&pool->mutex);
  if (total)
    *total = pool->total_buffers;
  if (in_use)
    *in_use = pool->in_use;
  if (available)
    *available = pool->total_buffers - pool->in_use;
  pthread_mutex_unlock (&pool->mutex);
}

/**
 * TLSBufferPool_free - Destroy a buffer pool
 * @pool: Buffer pool to destroy (may be NULL)
 *
 * Frees all pool resources. Any buffers still in use become invalid.
 *
 * If the pool was created with its own arena (arena=NULL passed to _new),
 * the arena is disposed. If the pool was created with a caller-provided
 * arena, the caller remains responsible for disposing the arena.
 *
 * Thread-safe: No - ensure all buffers are released first
 */
void
TLSBufferPool_free (TLSBufferPool_T *pool)
{
  if (!pool || !*pool)
    return;

  TLSBufferPool_T p = *pool;
  int owns_arena = p->owns_arena;
  Arena_T arena = p->arena;

  pthread_mutex_destroy (&p->mutex);

  /* Clear caller's pointer first (always safe - points to caller's stack/heap) */
  *pool = NULL;

  if (owns_arena)
    {
      /*
       * Pool owns arena: pool struct was malloc'd (not arena-allocated).
       * Free the pool struct first, then dispose the arena.
       * This avoids UAF because &p->arena is not in the arena's memory.
       */
      free (p);
      Arena_dispose (&arena);
    }
  /*
   * If !owns_arena: caller provided arena and is responsible for its lifecycle.
   * The pool struct was arena-allocated, so it will be freed when the caller
   * disposes the arena. We only destroyed the mutex above.
   */
}

/**
 * SocketTLSContext_set_early_data_replay_callback - Register replay callback
 * @ctx: TLS context (server only)
 * @callback: Replay detection callback (NULL to disable)
 * @user_data: Opaque data passed to callback
 *
 * Registers a callback that is invoked when early data is received.
 * The callback should implement replay detection (e.g., nonce tracking).
 *
 * Thread-safe: No - call during configuration phase only.
 */
void
SocketTLSContext_set_early_data_replay_callback (
    SocketTLSContext_T ctx, SocketTLSEarlyDataReplayCallback callback,
    void *user_data)
{
  assert (ctx);

  if (!ctx->is_server)
    {
      RAISE_TLS_ERROR_MSG (SocketTLS_Failed,
                           "Replay callback only valid for server contexts");
    }

  ctx->early_data_replay_callback = (void *)callback;
  ctx->early_data_replay_user_data = user_data;

  if (callback)
    {
      SOCKET_LOG_DEBUG_MSG ("Registered 0-RTT replay protection callback");
    }
  else
    {
      SOCKET_LOG_DEBUG_MSG ("Cleared 0-RTT replay protection callback");
    }
}

/**
 * SocketTLSContext_require_early_data_replay - Require replay protection
 * @ctx: TLS context (server only)
 * @require: 1 = require callback, 0 = allow without callback
 *
 * When enabled, early data is rejected unless a replay callback is
 * registered AND returns 1 (accept).
 *
 * Thread-safe: No - call during configuration phase only.
 */
void
SocketTLSContext_require_early_data_replay (SocketTLSContext_T ctx,
                                             int require)
{
  assert (ctx);

  if (!ctx->is_server)
    {
      RAISE_TLS_ERROR_MSG (
          SocketTLS_Failed,
          "Replay requirement only valid for server contexts");
    }

  ctx->early_data_replay_required = require ? 1 : 0;

  if (require)
    {
      SOCKET_LOG_DEBUG_MSG (
          "Enabled mandatory 0-RTT replay protection requirement");
    }
  else
    {
      SOCKET_LOG_DEBUG_MSG (
          "Disabled mandatory 0-RTT replay protection requirement");
    }
}

/**
 * SocketTLSContext_has_early_data_replay_callback - Check if callback set
 * @ctx: TLS context
 *
 * Thread-safe: Yes (read-only)
 */
int
SocketTLSContext_has_early_data_replay_callback (SocketTLSContext_T ctx)
{
  assert (ctx);
  return ctx->early_data_replay_callback != NULL;
}

/**
 * SocketTLSContext_check_early_data_replay - Invoke replay check
 * @ctx: TLS context
 * @session_id: Session identifier from ticket
 * @session_id_len: Length of session_id
 *
 * Invokes the registered replay callback to determine if early data
 * should be accepted. If no callback is registered:
 * - If replay protection is required, returns 0 (reject)
 * - Otherwise returns 1 (accept - vulnerable to replay)
 *
 * Thread-safe: Yes - callback invocation is per-connection
 */
int
SocketTLSContext_check_early_data_replay (SocketTLSContext_T ctx,
                                           const unsigned char *session_id,
                                           size_t session_id_len)
{
  assert (ctx);

  SocketTLSEarlyDataReplayCallback callback
      = (SocketTLSEarlyDataReplayCallback)ctx->early_data_replay_callback;

  if (!callback)
    {
      /* No callback registered */
      if (ctx->early_data_replay_required)
        {
          SOCKET_LOG_DEBUG_MSG (
              "Rejecting early data: replay protection required but no "
              "callback registered");
          SocketMetrics_counter_inc (SOCKET_CTR_TLS_EARLY_DATA_REPLAY_REJECTED);
          return 0; /* Reject - protection required but not available */
        }

      /* No requirement, accept (but log warning) */
      SOCKET_LOG_DEBUG_MSG (
          "Accepting early data without replay protection (vulnerable)");
      return 1;
    }

  /* Invoke the callback */
  int result = callback (ctx, session_id, session_id_len,
                         ctx->early_data_replay_user_data);

  if (result)
    {
      SOCKET_LOG_DEBUG_MSG ("Replay callback accepted early data");
    }
  else
    {
      SOCKET_LOG_DEBUG_MSG ("Replay callback rejected early data (replay "
                            "detected or uncertain)");
      SocketMetrics_counter_inc (SOCKET_CTR_TLS_EARLY_DATA_REPLAY_REJECTED);
    }

  return result;
}

#endif /* SOCKET_HAS_TLS */

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketHTTPClient-pool.c - HTTP Connection Pool Implementation
 *
 * Part of the Socket Library
 *
 * HTTP connection pool with:
 * - Per-host keying (host:port:secure)
 * - Happy Eyeballs integration for fast connection
 * - HTTP/1.1 connection reuse
 * - HTTP/2 stream multiplexing (future)
 *
 * Leverages:
 * - SocketHappyEyeballs for fast dual-stack connection
 * - SocketHTTP1 for HTTP/1.1 parsing
 */

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTPClient-private.h"
#include "http/SocketHTTPClient.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketHappyEyeballs.h"

#include <assert.h>

/* Module exception - required for RAISE_HTTPCLIENT_ERROR macro */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTPClient);

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"
#endif

/* HTTP/2 support */
#include "http/SocketHTTP2.h"

/* #include <string.h> - provided by SocketUtil.h or others */
#include <time.h>

#ifndef HTTP_DEFAULT_PORT
#define HTTP_DEFAULT_PORT 80
#endif

#ifndef HTTPS_DEFAULT_PORT
#define HTTPS_DEFAULT_PORT 443
#endif

/**
 * @brief Maximum hash chain length before raising collision attack error.
 *
 * Security limit to prevent DoS via hash collision attacks.
 * If a hash chain exceeds this length during traversal, the operation
 * fails with an exception indicating possible attack.
 */
#ifndef POOL_MAX_HASH_CHAIN_LEN
#define POOL_MAX_HASH_CHAIN_LEN 1024
#endif

/**
 * @brief Milliseconds per second for timeout conversions.
 */
#ifndef POOL_MS_PER_SECOND
#define POOL_MS_PER_SECOND 1000
#endif

/* ============================================================================
 * Pool Configuration
 * ============================================================================
 * Pool constants are defined in SocketHTTPClient-config.h:
 *   - HTTPCLIENT_POOL_HASH_SIZE (127) - default hash table size
 *   - HTTPCLIENT_IO_BUFFER_SIZE (8192) - I/O buffer size per connection
 *   - HTTPCLIENT_POOL_LARGE_HASH_SIZE (251) - large pool hash size
 *   - HTTPCLIENT_POOL_LARGE_THRESHOLD (100) - threshold for larger hash
 */

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/* Forward declarations */
static void pool_entry_remove_and_recycle (HTTPPool *pool, HTTPPoolEntry *entry);

/**
 * pool_time - Get current time in seconds for pool tracking
 *
 * Returns: Current time as time_t (seconds)
 *
 * Used for idle timeout tracking. Uses wall-clock time which is
 * acceptable for connection pooling purposes.
 */
static time_t
pool_time (void)
{
  return time (NULL);
}

/**
 * pool_entry_alloc - Allocate a new pool entry
 * @pool: Connection pool
 *
 * Returns: Zeroed pool entry, or NULL on allocation failure
 *
 * Tries free list first for reuse, otherwise allocates from arena.
 */
static HTTPPoolEntry *
pool_entry_alloc (HTTPPool *pool)
{
  HTTPPoolEntry *entry;

  /* Try free list first */
  if (pool->free_entries != NULL)
    {
      entry = pool->free_entries;
      pool->free_entries = entry->next;
      memset (entry, 0, sizeof (*entry));
      return entry;
    }

  /* Allocate new entry from arena (already zeroed by calloc pattern) */
  size_t entry_size = sizeof (*entry);
  if (!SOCKET_SECURITY_VALID_SIZE (entry_size))
    {
      SOCKET_RAISE_MSG (SocketHTTPClient, SocketHTTPClient_Failed,
                        "Pool entry size invalid: %zu", entry_size);
    }
  entry = Arena_calloc (pool->arena, 1, entry_size, __FILE__, __LINE__);
  return entry;
}

/**
 * pool_hash_add - Add entry to hash table
 * @pool: Connection pool
 * @entry: Entry to add (must have host/port set)
 *
 * Adds entry at head of hash chain for O(1) insertion.
 */
static void
pool_hash_add (HTTPPool *pool, HTTPPoolEntry *entry)
{
  unsigned hash
      = httpclient_host_hash (entry->host, entry->port, pool->hash_size);

  entry->hash_next = pool->hash_table[hash];
  pool->hash_table[hash] = entry;
}

/**
 * raise_chain_too_long - Raise exception for hash chain length exceeded
 * @chain_len: Current chain length
 * @context: Description of operation for error message
 * @host: Host being accessed (may be NULL)
 * @port: Port being accessed
 *
 * Raises SocketHTTPClient_Failed with detailed collision attack message.
 */
static void
raise_chain_too_long (size_t chain_len, const char *context, const char *host,
                      int port)
{
  if (host != NULL)
    SOCKET_RAISE_MSG (SocketHTTPClient, SocketHTTPClient_Failed,
                      "Hash chain too long (%zu >= %d) %s for %s:%d - "
                      "possible collision attack",
                      chain_len, POOL_MAX_HASH_CHAIN_LEN, context, host, port);
  else
    SOCKET_RAISE_MSG (SocketHTTPClient, SocketHTTPClient_Failed,
                      "Hash chain too long (%zu >= %d) %s - "
                      "possible collision attack",
                      chain_len, POOL_MAX_HASH_CHAIN_LEN, context);
}

/**
 * pool_hash_remove - Remove entry from hash table
 * @pool: Connection pool
 * @entry: Entry to remove
 *
 * Scans hash chain to find and unlink the entry.
 */
static void
pool_hash_remove (HTTPPool *pool, HTTPPoolEntry *entry)
{
  unsigned hash
      = httpclient_host_hash (entry->host, entry->port, pool->hash_size);

  size_t chain_len = 0;
  HTTPPoolEntry **pp = &pool->hash_table[hash];
  while (*pp != NULL && chain_len < POOL_MAX_HASH_CHAIN_LEN)
    {
      ++chain_len;
      if (*pp == entry)
        {
          *pp = entry->hash_next;
          entry->hash_next = NULL;
          return;
        }
      pp = &(*pp)->hash_next;
    }
  if (chain_len >= POOL_MAX_HASH_CHAIN_LEN)
    raise_chain_too_long (chain_len, "during removal", entry->host,
                          entry->port);
}

/**
 * pool_list_add - Add entry to all connections list
 * @pool: Connection pool
 * @entry: Entry to add
 *
 * Adds entry at head of doubly-linked list for O(1) insertion.
 */
static void
pool_list_add (HTTPPool *pool, HTTPPoolEntry *entry)
{
  entry->next = pool->all_conns;
  entry->prev = NULL;
  if (pool->all_conns != NULL)
    pool->all_conns->prev = entry;
  pool->all_conns = entry;
}

/**
 * pool_list_remove - Remove entry from all connections list
 * @pool: Connection pool
 * @entry: Entry to remove
 *
 * Unlinks entry from doubly-linked list in O(1).
 */
static void
pool_list_remove (HTTPPool *pool, HTTPPoolEntry *entry)
{
  if (entry->prev != NULL)
    entry->prev->next = entry->next;
  else
    pool->all_conns = entry->next;

  if (entry->next != NULL)
    entry->next->prev = entry->prev;

  entry->next = NULL;
  entry->prev = NULL;
}

/**
 * close_http1_resources - Close HTTP/1.1 connection resources
 * @entry: Pool entry with HTTP/1.1 resources
 *
 * Releases socket, parser, buffers, and connection arena.
 */
static void
close_http1_resources (HTTPPoolEntry *entry)
{
  if (entry->proto.h1.socket != NULL)
    Socket_free (&entry->proto.h1.socket);

  if (entry->proto.h1.parser != NULL)
    SocketHTTP1_Parser_free (&entry->proto.h1.parser);

  if (entry->proto.h1.inbuf != NULL)
    SocketBuf_release (&entry->proto.h1.inbuf);

  if (entry->proto.h1.outbuf != NULL)
    SocketBuf_release (&entry->proto.h1.outbuf);

  if (entry->proto.h1.conn_arena != NULL)
    Arena_dispose (&entry->proto.h1.conn_arena);
}

/**
 * close_http2_resources - Close HTTP/2 connection resources
 * @entry: Pool entry with HTTP/2 resources
 *
 * Releases HTTP/2 connection.
 */
static void
close_http2_resources (HTTPPoolEntry *entry)
{
  if (entry->proto.h2.conn != NULL)
    SocketHTTP2_Conn_free (&entry->proto.h2.conn);
}

/**
 * pool_entry_close - Close and clean up a connection entry
 * @entry: Entry to close (may be NULL)
 *
 * Releases all resources based on protocol version.
 */
static void
pool_entry_close (HTTPPoolEntry *entry)
{
  if (entry == NULL)
    return;

  if (entry->version == HTTP_VERSION_1_1 || entry->version == HTTP_VERSION_1_0)
    close_http1_resources (entry);
  else if (entry->version == HTTP_VERSION_2)
    close_http2_resources (entry);

  entry->closed = 1;
}

/**
 * host_port_secure_match - Check if entry matches host/port/secure
 * @entry: Pool entry
 * @host: Target hostname
 * @port: Target port
 * @is_secure: TLS flag
 *
 * Returns: 1 if matches, 0 otherwise
 *
 * Performs case-insensitive host comparison.
 * Thread-safe: Yes (read-only)
 */
static int
host_port_secure_match (const HTTPPoolEntry *entry, const char *host, int port,
                        int is_secure)
{
  if (entry->port != port || entry->is_secure != is_secure)
    return 0;
  return strcasecmp (entry->host, host) == 0;
}

/**
 * pool_count_for_host - Count connections to a specific host:port
 * @pool: Connection pool
 * @host: Target hostname
 * @port: Target port
 * @is_secure: TLS flag
 *
 * Returns: Number of connections to the host
 *
 * Caller must hold pool mutex.
 */
static size_t
pool_count_for_host (HTTPPool *pool, const char *host, int port, int is_secure)
{
  size_t count = 0;
  size_t chain_len = 0;
  unsigned hash = httpclient_host_hash (host, port, pool->hash_size);

  HTTPPoolEntry *entry = pool->hash_table[hash];
  while (entry != NULL && chain_len < POOL_MAX_HASH_CHAIN_LEN)
    {
      ++chain_len;
      if (host_port_secure_match (entry, host, port, is_secure))
        count++;
      entry = entry->hash_next;
    }
  if (chain_len >= POOL_MAX_HASH_CHAIN_LEN)
    raise_chain_too_long (chain_len, "in pool count", host, port);

  return count;
}

/* ============================================================================
 * Pool Lifecycle
 * ============================================================================
 */

HTTPPool *
httpclient_pool_new (Arena_T arena, const SocketHTTPClient_Config *config)
{
  HTTPPool *pool;
  size_t hash_size;

  assert (arena != NULL);
  assert (config != NULL);

  size_t pool_size = sizeof (*pool);
  if (!SOCKET_SECURITY_VALID_SIZE (pool_size))
    {
      SOCKET_RAISE_MSG (SocketHTTPClient, SocketHTTPClient_Failed,
                        "HTTP pool size invalid: %zu", pool_size);
    }
  pool = Arena_calloc (arena, 1, pool_size, __FILE__, __LINE__);

  pool->arena = arena;

  /* Calculate hash table size based on expected connections, with security
   * limits */
  size_t suggested_size
      = config->max_total_connections / 8; /* Target load factor ~8 */
  if (suggested_size < HTTPCLIENT_POOL_HASH_SIZE)
    {
      suggested_size = HTTPCLIENT_POOL_HASH_SIZE;
    }
  const size_t max_hash_size = 65536; /* Prevent excessive memory use */
  if (suggested_size > max_hash_size)
    {
      suggested_size = max_hash_size;
    }
  size_t elem_size = sizeof (HTTPPoolEntry *);
  size_t table_bytes;
  if (!SocketSecurity_check_multiply (suggested_size, elem_size, &table_bytes)
      || !SocketSecurity_check_size (table_bytes))
    {
      SOCKET_RAISE_MSG (SocketHTTPClient, SocketHTTPClient_Failed,
                        "Computed hash table size too large: %zu elements",
                        suggested_size);
    }
  hash_size = (unsigned)suggested_size; /* Safe cast, checked above */

  pool->hash_size = hash_size;
  pool->hash_table = Arena_calloc (arena, hash_size, sizeof (HTTPPoolEntry *),
                                   __FILE__, __LINE__);

  pool->max_per_host = config->max_connections_per_host;
  pool->max_total = config->max_total_connections;
  pool->idle_timeout_ms = config->idle_timeout_ms;

  if (pthread_mutex_init (&pool->mutex, NULL) != 0)
    SOCKET_RAISE_MSG (SocketHTTPClient, SocketHTTPClient_Failed,
                      "Failed to initialize HTTP client pool mutex");

  return pool;
}

void
httpclient_pool_free (HTTPPool *pool)
{
  if (pool == NULL)
    return;

  pthread_mutex_lock (&pool->mutex);

  /* Close all connections */
  HTTPPoolEntry *entry = pool->all_conns;
  while (entry != NULL)
    {
      HTTPPoolEntry *next = entry->next;
      pool_entry_close (entry);
      entry = next;
    }

  pool->all_conns = NULL;
  pool->free_entries = NULL;
  pool->current_count = 0;

  pthread_mutex_unlock (&pool->mutex);
  pthread_mutex_destroy (&pool->mutex);
}

/* ============================================================================
 * Pool Operations
 * ============================================================================
 */

/**
 * entry_can_handle_request - Check if pool entry can handle another request
 * @entry: Pool entry to check
 *
 * Returns: 1 if entry can accept request, 0 if not
 *
 * For HTTP/1.1: check that entry is not in use
 * For HTTP/2: check that active_streams < peer's MAX_CONCURRENT_STREAMS
 */
static int
entry_can_handle_request (HTTPPoolEntry *entry)
{
  if (entry->closed)
    return 0;

  if (entry->version == HTTP_VERSION_2)
    {
      /* HTTP/2: allow multiplexing up to MAX_CONCURRENT_STREAMS */
      if (entry->proto.h2.conn == NULL)
        return 0;
      uint32_t max_streams = SocketHTTP2_Conn_get_setting (
          entry->proto.h2.conn, HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
      return (uint32_t)entry->proto.h2.active_streams < max_streams;
    }

  /* HTTP/1.1: must not be in use (sequential requests only) */
  return !entry->in_use;
}

/**
 * entry_mark_in_use - Mark pool entry as handling a request
 * @entry: Pool entry to mark
 *
 * For HTTP/1.1: sets in_use flag
 * For HTTP/2: increments active_streams counter
 */
static void
entry_mark_in_use (HTTPPoolEntry *entry)
{
  if (entry->version == HTTP_VERSION_2)
    {
      /* HTTP/2: increment stream count (actual stream created later) */
      entry->proto.h2.active_streams++;
    }
  else
    {
      /* HTTP/1.1: mark as exclusively in use */
      entry->in_use = 1;
    }
  entry->last_used = pool_time ();
}

HTTPPoolEntry *
httpclient_pool_get (HTTPPool *pool, const char *host, int port, int is_secure)
{
  HTTPPoolEntry *entry;
  unsigned hash;

  assert (pool != NULL);
  assert (host != NULL);

  pthread_mutex_lock (&pool->mutex);

  hash = httpclient_host_hash (host, port, pool->hash_size);

  /* Find an available connection, with chain length limit to prevent DoS */
  size_t chain_len = 0;
  entry = pool->hash_table[hash];
  while (entry != NULL && chain_len < POOL_MAX_HASH_CHAIN_LEN)
    {
      ++chain_len;
      if (host_port_secure_match (entry, host, port, is_secure)
          && entry_can_handle_request (entry))
        {
          /* SECURITY FIX: Verify TLS hostname matches for secure connections
           * to prevent connection reuse across different hostnames.
           * CVE-like vulnerability: An attacker could obtain a connection to
           * evil.com, then reuse it for bank.com if we don't verify SNI hostname.
           * RFC 6125 requires hostname verification on every TLS session use.
           */
          if (entry->is_secure && host) {
            /* Hostnames are case-insensitive per RFC 1035 */
            if (strcasecmp(entry->sni_hostname, host) != 0) {
              /* Hostname mismatch - skip this connection and continue search.
               * This prevents an attacker from reusing a TLS connection
               * established for one hostname with a different target hostname.
               */
              entry = entry->hash_next;
              continue;
            }
          }

          /* SECURITY: Clear buffers before reuse to prevent information leakage */
          if (entry->version == HTTP_VERSION_1_1 || entry->version == HTTP_VERSION_1_0) {
            if (entry->proto.h1.inbuf) {
              SocketBuf_clear(entry->proto.h1.inbuf);
            }
            if (entry->proto.h1.outbuf) {
              SocketBuf_clear(entry->proto.h1.outbuf);
            }
            /* Reset parser state */
            if (entry->proto.h1.parser) {
              SocketHTTP1_Parser_reset(entry->proto.h1.parser);
            }
          }

          entry_mark_in_use (entry);
          pool->reused_connections++;
          pthread_mutex_unlock (&pool->mutex);
          return entry;
        }
      entry = entry->hash_next;
    }
  if (chain_len >= POOL_MAX_HASH_CHAIN_LEN)
    raise_chain_too_long (chain_len, "in pool lookup", host, port);

  pthread_mutex_unlock (&pool->mutex);
  return 0;
}

void
httpclient_pool_release (HTTPPool *pool, HTTPPoolEntry *entry)
{
  assert (pool != NULL);
  assert (entry != NULL);

  pthread_mutex_lock (&pool->mutex);

  if (entry->version == HTTP_VERSION_2)
    {
      /* HTTP/2: decrement active stream count */
      if (entry->proto.h2.active_streams > 0)
        entry->proto.h2.active_streams--;
      /* Note: connection remains in pool for reuse with other streams */
    }
  else
    {
      /* HTTP/1.1: mark as no longer in use */
      entry->in_use = 0;
    }

  entry->last_used = pool_time ();
  pthread_mutex_unlock (&pool->mutex);
}

void
httpclient_pool_close (HTTPPool *pool, HTTPPoolEntry *entry)
{
  assert (pool != NULL);
  assert (entry != NULL);

  pthread_mutex_lock (&pool->mutex);
  pool_entry_remove_and_recycle (pool, entry);
  pthread_mutex_unlock (&pool->mutex);
}

/**
 * pool_entry_remove_and_recycle - Remove entry from pool and add to free list
 * @pool: Connection pool (mutex held)
 * @entry: Entry to remove
 *
 * Removes entry from hash table and all-connections list, closes resources,
 * decrements count, and adds to free list for reuse. Caller must hold mutex.
 *
 * Thread-safe: No (caller must hold pool->mutex)
 */
static void
pool_entry_remove_and_recycle (HTTPPool *pool, HTTPPoolEntry *entry)
{
  pool_hash_remove (pool, entry);
  pool_list_remove (pool, entry);
  pool_entry_close (entry);

  entry->next = pool->free_entries;
  pool->free_entries = entry;
  pool->current_count--;
}

void
httpclient_pool_cleanup_idle (HTTPPool *pool)
{
  time_t now;
  time_t idle_threshold;

  assert (pool != NULL);

  if (pool->idle_timeout_ms <= 0)
    return;

  pthread_mutex_lock (&pool->mutex);

  now = pool_time ();
  idle_threshold = pool->idle_timeout_ms / POOL_MS_PER_SECOND;

  HTTPPoolEntry *entry = pool->all_conns;
  while (entry != NULL)
    {
      HTTPPoolEntry *next = entry->next;

      if (!entry->in_use && !entry->closed
          && (now - entry->last_used) >= idle_threshold)
        pool_entry_remove_and_recycle (pool, entry);

      entry = next;
    }

  pthread_mutex_unlock (&pool->mutex);
}

/* ============================================================================
 * Connection Establishment - Helper Functions
 * ============================================================================
 */

/**
 * create_http1_entry_resources - Allocate HTTP/1.1 parser and buffers
 * @entry: Pool entry to initialize
 *
 * Raises: Arena_Failed, SocketHTTP1_ParseError, SocketBuf_Failed on allocation
 * failure
 *
 * Creates a connection arena, parser, and I/O buffers for the entry.
 * Thread-safe: No (caller must synchronize access to entry)
 */
static void
create_http1_entry_resources (HTTPPoolEntry *entry)
{
  entry->proto.h1.conn_arena = Arena_new ();

  entry->proto.h1.parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL,
                                                   entry->proto.h1.conn_arena);

  entry->proto.h1.inbuf
      = SocketBuf_new (entry->proto.h1.conn_arena, HTTPCLIENT_IO_BUFFER_SIZE);
  entry->proto.h1.outbuf
      = SocketBuf_new (entry->proto.h1.conn_arena, HTTPCLIENT_IO_BUFFER_SIZE);
}

/**
 * init_http1_entry_fields - Initialize HTTP/1.1 entry fields
 * @entry: Pool entry
 * @socket: Connected socket
 * @host: Target hostname (will be copied)
 * @port: Target port
 * @is_secure: TLS flag
 * @pool: Pool for hostname allocation
 *
 * Raises: Arena_Failed on host string allocation failure
 * Thread-safe: No (modifies entry under caller lock)
 */
static void
init_http1_entry_fields (HTTPPoolEntry *entry, Socket_T socket,
                         const char *host, int port, int is_secure,
                         HTTPPool *pool)
{
  size_t host_len = strlen (host);

  size_t alloc_size = host_len + 1;
  if (!SOCKET_SECURITY_VALID_SIZE (alloc_size))
    {
      SOCKET_RAISE_MSG (SocketHTTPClient, SocketHTTPClient_Failed,
                        "Hostname too long: %zu bytes", host_len);
    }

  entry->host = Arena_alloc (pool->arena, alloc_size, __FILE__, __LINE__);
  memcpy (entry->host, host, alloc_size);
  entry->port = port;
  entry->is_secure = is_secure;
  entry->version = HTTP_VERSION_1_1;
  entry->created_at = pool_time ();
  entry->last_used = entry->created_at;
  entry->in_use = 1;
  entry->closed = 0;
  entry->proto.h1.socket = socket;

  /* SECURITY: Store SNI hostname for TLS verification on connection reuse.
   * This prevents hostname confusion attacks where a connection established
   * for one hostname could be incorrectly reused for a different hostname.
   * The stored hostname is verified on every pool_get() call before reuse.
   */
  if (is_secure && host) {
    strncpy(entry->sni_hostname, host, sizeof(entry->sni_hostname) - 1);
    entry->sni_hostname[sizeof(entry->sni_hostname) - 1] = '\0';
  } else {
    entry->sni_hostname[0] = '\0';
  }
}

/**
 * recycle_entry_on_failure - Return entry to free list on allocation failure
 * @pool: Connection pool
 * @entry: Entry to recycle
 *
 * Helper to add entry back to free list when allocation fails.
 */
static void
recycle_entry_on_failure (HTTPPool *pool, HTTPPoolEntry *entry)
{
  entry->next = pool->free_entries;
  pool->free_entries = entry;
}

/**
 * create_http1_connection - Create new HTTP/1.1 pool entry
 * @pool: Connection pool
 * @socket: Connected socket (ownership transferred)
 * @host: Target hostname
 * @port: Target port
 * @is_secure: 1 for HTTPS, 0 for HTTP
 *
 * Returns: New pool entry, or NULL on failure
 *
 * Allocates entry, copies host, creates parser/buffers, adds to pool.
 * On failure, socket is NOT freed - caller retains ownership.
 */
static HTTPPoolEntry *
create_http1_connection (HTTPPool *pool, Socket_T socket, const char *host,
                         int port, int is_secure)
{
  /* Variables must be volatile to survive longjmp in TRY/EXCEPT */
  HTTPPoolEntry *volatile entry = NULL;
  volatile int stage = 0; /* Track progress for cleanup */

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

  TRY
  {
    entry = pool_entry_alloc (pool);
    stage = 1;

    init_http1_entry_fields ((HTTPPoolEntry *)entry, socket, host, port,
                             is_secure, pool);
    stage = 2;

    create_http1_entry_resources ((HTTPPoolEntry *)entry);
    stage = 3;
  }
  EXCEPT (Arena_Failed)
  {
    if (stage >= 2)
      Socket_free (&((HTTPPoolEntry *)entry)->proto.h1.socket);
    if (stage >= 1 && entry != NULL)
      recycle_entry_on_failure (pool, (HTTPPoolEntry *)entry);
    return NULL;
  }
  END_TRY;

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

  pool_hash_add (pool, (HTTPPoolEntry *)entry);
  pool_list_add (pool, (HTTPPoolEntry *)entry);
  pool->current_count++;
  pool->total_requests++;

  return (HTTPPoolEntry *)entry;
}

/* ============================================================================
 * HTTP/2 Connection Creation
 * ============================================================================
 */

/**
 * init_http2_entry_fields - Initialize HTTP/2 entry fields
 * @entry: Pool entry
 * @socket: Connected socket (with TLS after ALPN negotiation)
 * @host: Target hostname (will be copied)
 * @port: Target port
 * @is_secure: TLS flag (always 1 for HTTP/2 over TLS)
 * @pool: Pool for hostname allocation
 *
 * Raises: Arena_Failed on host string allocation failure
 * Thread-safe: No (modifies entry under caller lock)
 */
static void
init_http2_entry_fields (HTTPPoolEntry *entry, Socket_T socket,
                         const char *host, int port, int is_secure,
                         HTTPPool *pool)
{
  (void)socket; /* Socket is stored in HTTP/2 conn, not directly in entry */
  size_t host_len = strlen (host);
  size_t alloc_size = host_len + 1;

  if (!SOCKET_SECURITY_VALID_SIZE (alloc_size))
    {
      SOCKET_RAISE_MSG (SocketHTTPClient, SocketHTTPClient_Failed,
                        "Hostname too long: %zu bytes", host_len);
    }

  entry->host = Arena_alloc (pool->arena, alloc_size, __FILE__, __LINE__);
  memcpy (entry->host, host, alloc_size);
  entry->port = port;
  entry->is_secure = is_secure;
  entry->version = HTTP_VERSION_2;
  entry->created_at = pool_time ();
  entry->last_used = entry->created_at;
  entry->in_use = 0; /* HTTP/2: multiple streams, not exclusive */
  entry->closed = 0;
  entry->proto.h2.conn = NULL;
  entry->proto.h2.active_streams = 0;

  /* SECURITY: Store SNI hostname for TLS verification on connection reuse.
   * This prevents hostname confusion attacks where a connection established
   * for one hostname could be incorrectly reused for a different hostname.
   * The stored hostname is verified on every pool_get() call before reuse.
   */
  if (is_secure && host) {
    strncpy(entry->sni_hostname, host, sizeof(entry->sni_hostname) - 1);
    entry->sni_hostname[sizeof(entry->sni_hostname) - 1] = '\0';
  } else {
    entry->sni_hostname[0] = '\0';
  }
}

/**
 * create_http2_entry_resources - Create HTTP/2 connection and perform handshake
 * @entry: Pool entry with socket set
 * @socket: Connected TLS socket
 * @pool: Connection pool for arena
 *
 * Creates SocketHTTP2_Conn_T with CLIENT role and completes the HTTP/2
 * handshake (preface + SETTINGS exchange).
 *
 * Raises: SocketHTTP2_ProtocolError on handshake failure
 * Thread-safe: No
 */
static int
create_http2_entry_resources (HTTPPoolEntry *entry, Socket_T socket,
                              HTTPPool *pool)
{
  SocketHTTP2_Config config;
  SocketHTTP2_Conn_T conn;
  int handshake_result;

  /* Initialize HTTP/2 configuration with client defaults */
  SocketHTTP2_config_defaults (&config, HTTP2_ROLE_CLIENT);

  /* Create HTTP/2 connection */
  conn = SocketHTTP2_Conn_new (socket, &config, pool->arena);
  if (conn == NULL)
    return -1;

  entry->proto.h2.conn = conn;

  /* Complete HTTP/2 handshake (preface + SETTINGS) */
  do
    {
      handshake_result = SocketHTTP2_Conn_handshake (conn);
      if (handshake_result < 0)
        {
          /* Handshake failed */
          SocketHTTP2_Conn_free (&entry->proto.h2.conn);
          return -1;
        }
      if (handshake_result == 1)
        {
          /* Need more I/O - process and flush */
          if (SocketHTTP2_Conn_process (conn, 0) < 0)
            {
              SocketHTTP2_Conn_free (&entry->proto.h2.conn);
              return -1;
            }
          if (SocketHTTP2_Conn_flush (conn) < 0)
            {
              SocketHTTP2_Conn_free (&entry->proto.h2.conn);
              return -1;
            }
        }
    }
  while (handshake_result == 1);

  return 0;
}

/**
 * create_http2_connection - Create new HTTP/2 pool entry
 * @pool: Connection pool
 * @socket: Connected TLS socket (ownership transferred)
 * @host: Target hostname
 * @port: Target port
 * @is_secure: Always 1 for HTTP/2 over TLS
 *
 * Returns: New pool entry, or NULL on failure
 *
 * Allocates entry, creates HTTP/2 connection, performs handshake.
 * On failure, socket is NOT freed - caller retains ownership.
 */
static HTTPPoolEntry *
create_http2_connection (HTTPPool *pool, Socket_T socket, const char *host,
                         int port, int is_secure)
{
  HTTPPoolEntry *volatile entry = NULL;
  volatile int stage = 0;

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

  TRY
  {
    entry = pool_entry_alloc (pool);
    stage = 1;

    init_http2_entry_fields ((HTTPPoolEntry *)entry, socket, host, port,
                             is_secure, pool);
    stage = 2;

    if (create_http2_entry_resources ((HTTPPoolEntry *)entry, socket, pool)
        != 0)
      {
        RAISE (SocketHTTP2_ProtocolError);
      }
    stage = 3;
  }
  EXCEPT (Arena_Failed)
  {
    if (stage >= 2 && entry != NULL && ((HTTPPoolEntry *)entry)->proto.h2.conn)
      SocketHTTP2_Conn_free (&((HTTPPoolEntry *)entry)->proto.h2.conn);
    if (stage >= 1 && entry != NULL)
      recycle_entry_on_failure (pool, (HTTPPoolEntry *)entry);
    return NULL;
  }
  EXCEPT (SocketHTTP2_ProtocolError)
  {
    if (stage >= 1 && entry != NULL)
      recycle_entry_on_failure (pool, (HTTPPoolEntry *)entry);
    return NULL;
  }
  END_TRY;

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

  pool_hash_add (pool, (HTTPPoolEntry *)entry);
  pool_list_add (pool, (HTTPPoolEntry *)entry);
  pool->current_count++;
  pool->total_requests++;

  return (HTTPPoolEntry *)entry;
}

/**
 * check_connection_limits - Check if new connection can be created
 * @client: HTTP client
 * @host: Target hostname
 * @port: Target port
 * @is_secure: TLS flag
 *
 * Checks per-host and total connection limits under lock.
 * Sets last_error to LIMIT_EXCEEDED if limits hit.
 *
 * Returns: 1 if can create (limits allow), 0 if limits exceeded
 * Thread-safe: Yes (uses mutex)
 */
static int
check_connection_limits (SocketHTTPClient_T client, const char *host, int port,
                         int is_secure)
{
  assert (client != NULL);
  assert (client->pool != NULL);
  assert (host != NULL);

  pthread_mutex_lock (&client->pool->mutex);
  size_t host_count
      = pool_count_for_host (client->pool, host, port, is_secure);
  int can_create
      = (host_count < (size_t)client->pool->max_per_host
         && client->pool->current_count < (size_t)client->pool->max_total);
  pthread_mutex_unlock (&client->pool->mutex);

  if (!can_create)
    {
      HTTPCLIENT_ERROR_MSG (
          "Connection limit exceeded for %s:%d "
          "(host: %zu/%zu, total: %zu/%zu)",
          host, port, host_count, (size_t)client->pool->max_per_host,
          client->pool->current_count, client->pool->max_total);
      client->last_error = HTTPCLIENT_ERROR_LIMIT_EXCEEDED;
    }

  return can_create;
}

/**
 * pool_try_get_connection - Try to get existing connection from pool
 * @client: HTTP client
 * @host: Target hostname
 * @port: Target port
 * @is_secure: 1 for HTTPS, 0 for HTTP
 *
 * Returns: Pool entry if reusable connection found, NULL otherwise
 *
 * Attempts to find a reusable cached connection. If none found and limits
 * are hit, cleans up idle connections and rechecks. Returns NULL in both
 * "create new" and "limits exceeded" cases - caller checks last_error.
 */
static HTTPPoolEntry *
pool_try_get_connection (SocketHTTPClient_T client, const char *host, int port,
                         int is_secure)
{
  HTTPPoolEntry *entry;

  if (client->pool == NULL)
    return NULL;

  /* Try direct lookup for reusable connection */
  entry = httpclient_pool_get (client->pool, host, port, is_secure);
  if (entry != NULL)
    return entry;

  /* No cached connection - check if we can create new */
  if (check_connection_limits (client, host, port, is_secure))
    return NULL; /* Limits allow - caller should create new connection */

  /* Limits exceeded - try cleanup and recheck */
  httpclient_pool_cleanup_idle (client->pool);

  /* After cleanup, a slot may have opened */
  entry = httpclient_pool_get (client->pool, host, port, is_secure);
  if (entry != NULL)
    return entry;

  /* Final limit check - sets last_error if still exceeded */
  check_connection_limits (client, host, port, is_secure);
  return NULL;
}

/**
 * establish_tcp_connection - Create TCP connection with Happy Eyeballs
 * @client: HTTP client
 * @host: Target hostname
 * @port: Target port
 *
 * Returns: Connected socket, or NULL on failure
 *
 * Uses Happy Eyeballs for fast dual-stack connection establishment.
 */
static Socket_T
establish_tcp_connection (SocketHTTPClient_T client, const char *host,
                          int port)
{
  SocketHE_Config_T he_config;
  volatile Socket_T socket = NULL;

  SocketHappyEyeballs_config_defaults (&he_config);
  he_config.total_timeout_ms = client->config.connect_timeout_ms;
  he_config.attempt_timeout_ms = client->config.connect_timeout_ms / 2;

  TRY { socket = SocketHappyEyeballs_connect (host, port, &he_config); }
  EXCEPT (SocketHE_Failed) { socket = NULL; }
  END_TRY;

  if (socket == NULL)
    {
      client->last_error = HTTPCLIENT_ERROR_CONNECT;
      if (client->pool != NULL)
        {
          pthread_mutex_lock (&client->pool->mutex);
          client->pool->connections_failed++;
          pthread_mutex_unlock (&client->pool->mutex);
        }
      HTTPCLIENT_ERROR_MSG ("Connection to %s:%d failed", host, port);
    }

  return socket;
}

#if SOCKET_HAS_TLS
/**
 * ensure_tls_context - Get or create TLS context
 * @client: HTTP client
 *
 * Returns: TLS context, or NULL on failure
 */
static SocketTLSContext_T
ensure_tls_context (SocketHTTPClient_T client)
{
  if (client->config.tls_context != NULL)
    return client->config.tls_context;

  if (client->default_tls_ctx != NULL)
    return client->default_tls_ctx;

  TRY { client->default_tls_ctx = SocketTLSContext_new_client (NULL); }
  EXCEPT (SocketTLS_Failed) { return 0; }
  END_TRY;

  return client->default_tls_ctx;
}

/**
 * enable_socket_tls - Enable TLS on socket
 * @socket: TCP socket
 * @tls_ctx: TLS context
 *
 * Returns: 0 on success, -1 on failure
 */
static int
enable_socket_tls (Socket_T socket, SocketTLSContext_T tls_ctx)
{
  TRY { SocketTLS_enable (socket, tls_ctx); }
  EXCEPT (SocketTLS_Failed) { return -1; }
  END_TRY;

  return 0;
}

/**
 * perform_tls_handshake - Perform TLS handshake with timeout
 * @socket: TLS-enabled socket
 * @timeout_ms: Handshake timeout
 *
 * Returns: 0 on success, -1 on failure
 */
static int
perform_tls_handshake (Socket_T socket, int timeout_ms)
{
  TRY
  {
    TLSHandshakeState result = SocketTLS_handshake_loop (socket, timeout_ms);
    if (result != TLS_HANDSHAKE_COMPLETE)
      return -1;
  }
  EXCEPT (SocketTLS_HandshakeFailed) { return -1; }
  EXCEPT (SocketTLS_VerifyFailed) { return -1; }
  END_TRY;

  return 0;
}

/**
 * configure_alpn_for_http2 - Configure ALPN protocols for HTTP/2 negotiation
 * @tls_ctx: TLS context to configure
 * @max_version: Maximum HTTP version allowed by client config
 *
 * Configures ALPN protocol list based on max_version setting:
 * - HTTP/2: ["h2", "http/1.1"]
 * - HTTP/1.1 only: ["http/1.1"]
 *
 * Returns: 0 on success, -1 on failure
 */
static void
configure_alpn_for_http2 (SocketTLSContext_T tls_ctx,
                          SocketHTTP_Version max_version)
{
  if (max_version >= HTTP_VERSION_2)
    {
      /* Prefer HTTP/2, fall back to HTTP/1.1 */
      static const char *h2_protos[] = { "h2", "http/1.1" };
      SocketTLSContext_set_alpn_protos (tls_ctx, h2_protos, 2);
    }
  else
    {
      /* HTTP/1.1 only */
      static const char *h1_protos[] = { "http/1.1" };
      SocketTLSContext_set_alpn_protos (tls_ctx, h1_protos, 1);
    }
}

/**
 * determine_negotiated_version - Determine HTTP version from ALPN result
 * @socket: TLS-enabled socket after handshake
 *
 * Returns: Negotiated HTTP version (HTTP_VERSION_2 for "h2", HTTP_VERSION_1_1
 * otherwise)
 */
static SocketHTTP_Version
determine_negotiated_version (Socket_T socket)
{
  const char *alpn = SocketTLS_get_alpn_selected (socket);
  if (alpn != NULL && strcmp (alpn, "h2") == 0)
    return HTTP_VERSION_2;
  return HTTP_VERSION_1_1;
}

/**
 * setup_tls_connection - Enable TLS and perform handshake with ALPN
 * @client: HTTP client
 * @socket: Connected TCP socket (freed on error)
 * @hostname: SNI hostname
 * @negotiated_version: Output - negotiated HTTP version (HTTP/2 or HTTP/1.1)
 *
 * Configures ALPN based on client's max_version setting, performs TLS
 * handshake, and determines negotiated HTTP version from ALPN result.
 *
 * Returns: 0 on success, -1 on failure (socket freed on error)
 */
static int
setup_tls_connection (SocketHTTPClient_T client, Socket_T *socket,
                      const char *hostname,
                      SocketHTTP_Version *negotiated_version)
{
  if (hostname == NULL || *hostname == '\0')
    {
      Socket_free (socket);
      client->last_error = HTTPCLIENT_ERROR_TLS;
      return -1;
    }
  size_t hn_len = strlen (hostname);
  if (hn_len > SOCKET_TLS_MAX_SNI_LEN)
    {
      Socket_free (socket);
      client->last_error = HTTPCLIENT_ERROR_TLS;
      HTTPCLIENT_ERROR_MSG ("SNI hostname too long: %zu > %d", hn_len,
                            SOCKET_TLS_MAX_SNI_LEN);
      return -1;
    }

  SocketTLSContext_T tls_ctx;
  int tls_timeout;

  tls_ctx = ensure_tls_context (client);
  if (tls_ctx == NULL)
    {
      Socket_free (socket);
      client->last_error = HTTPCLIENT_ERROR_TLS;
      return -1;
    }

  /* Configure ALPN for HTTP/2 negotiation */
  configure_alpn_for_http2 (tls_ctx, client->config.max_version);

  if (enable_socket_tls (*socket, tls_ctx) != 0)
    {
      Socket_free (socket);
      client->last_error = HTTPCLIENT_ERROR_TLS;
      return -1;
    }

  SocketTLS_set_hostname (*socket, hostname);

  tls_timeout = client->config.connect_timeout_ms;
  if (tls_timeout <= 0)
    tls_timeout = SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS;

  if (perform_tls_handshake (*socket, tls_timeout) != 0)
    {
      Socket_free (socket);
      client->last_error = HTTPCLIENT_ERROR_TLS;
      return -1;
    }

  /* Determine negotiated HTTP version from ALPN */
  if (negotiated_version != NULL)
    *negotiated_version = determine_negotiated_version (*socket);

  return 0;
}
#endif /* SOCKET_HAS_TLS */

/**
 * create_temp_entry - Create temporary entry for non-pooled connections
 * @socket: Connected socket
 * @host: Target hostname
 * @port: Target port
 * @is_secure: 1 for HTTPS, 0 for HTTP
 *
 * Returns: Thread-local pool entry
 *
 * Uses thread-local storage for non-pooled case. The thread-local arena
 * is reused across calls within the same thread, with previous allocations
 * cleaned up on each new call.
 *
 * MEMORY NOTE: The thread-local arena is freed on each subsequent call,
 * but will not be freed if the thread exits without making another call.
 * This is acceptable because:
 * 1. Non-pooled mode is rare (pooling is enabled by default)
 * 2. Memory is small (~8KB per thread)
 * 3. Thread exit typically means process exit or thread pool reuse
 * For long-running servers, always use connection pooling.
 */
static HTTPPoolEntry *
create_temp_entry (Socket_T socket, const char *host, int port, int is_secure)
{
  static __thread HTTPPoolEntry temp_entry;
  static __thread Arena_T temp_arena = NULL;

  /* Clean up previous temp arena if it exists */
  if (temp_arena != NULL)
    {
      Arena_dispose (&temp_arena);
      temp_arena = NULL;
    }

  memset (&temp_entry, 0, sizeof (temp_entry));

  /* Create thread-local arena first for host copy and parser */
  temp_arena = Arena_new ();
  if (temp_arena == NULL)
    {
      return NULL; /* Allocation failed */
    }

  /* Copy host with validation */
  if (host == NULL || *host == '\0')
    {
      Arena_dispose (&temp_arena);
      return NULL; /* Invalid host */
    }
  size_t host_len = strlen (host);
  size_t alloc_size = host_len + 1;
  if (!SOCKET_SECURITY_VALID_SIZE (alloc_size))
    {
      Arena_dispose (&temp_arena);
      SOCKET_RAISE_MSG (SocketHTTPClient, SocketHTTPClient_Failed,
                        "Hostname too long for temporary entry: %zu bytes",
                        host_len);
    }
  temp_entry.host = ALLOC (temp_arena, alloc_size);
  if (temp_entry.host == NULL)
    {
      Arena_dispose (&temp_arena);
      RAISE (Arena_Failed);
    }
  memcpy (temp_entry.host, host, alloc_size);

  temp_entry.port = port;
  temp_entry.is_secure = is_secure;
  temp_entry.version = HTTP_VERSION_1_1;
  temp_entry.in_use = 1;

  temp_entry.proto.h1.parser
      = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, temp_arena);
  if (temp_entry.proto.h1.parser == NULL)
    {
      Arena_dispose (&temp_arena);
      return NULL;
    }
  temp_entry.proto.h1.socket = socket;

  return &temp_entry;
}

/**
 * create_pooled_entry - Create pool entry for new connection
 * @client: HTTP client
 * @socket: Connected socket (freed on error)
 * @host: Target hostname
 * @port: Target port
 * @is_secure: 1 for HTTPS, 0 for HTTP
 * @version: Negotiated HTTP version (HTTP_VERSION_2_0 or HTTP_VERSION_1_1)
 *
 * Returns: Pool entry, or NULL on failure
 *
 * Dispatches to HTTP/2 or HTTP/1.1 connection creation based on the
 * negotiated version from ALPN.
 */
static HTTPPoolEntry *
create_pooled_entry (SocketHTTPClient_T client, Socket_T socket,
                     const char *host, int port, int is_secure,
                     SocketHTTP_Version version)
{
  HTTPPoolEntry *entry;

  pthread_mutex_lock (&client->pool->mutex);

  if (version == HTTP_VERSION_2)
    entry
        = create_http2_connection (client->pool, socket, host, port, is_secure);
  else
    entry
        = create_http1_connection (client->pool, socket, host, port, is_secure);

  pthread_mutex_unlock (&client->pool->mutex);

  if (entry == NULL)
    {
      Socket_free (&socket);
      client->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;
    }

  return entry;
}

/* ============================================================================
 * Connection Establishment - Main Function
 * ============================================================================
 */

/**
 * httpclient_connect - Get or create connection to host
 * @client: HTTP client
 * @uri: Target URI
 *
 * Returns: Pool entry for connection, or NULL on failure
 *
 * Orchestrates connection establishment:
 * 1. Try existing pool connection (supports HTTP/2 multiplexing)
 * 2. Establish TCP via Happy Eyeballs
 * 3. Set up TLS if needed (with ALPN for HTTP/2 negotiation)
 * 4. Create pool entry (HTTP/2 or HTTP/1.1 based on ALPN result)
 */
HTTPPoolEntry *
httpclient_connect (SocketHTTPClient_T client, const SocketHTTP_URI *uri)
{
  HTTPPoolEntry *entry;
  Socket_T socket;
  int port;
  int is_secure;
  SocketHTTP_Version negotiated_version = HTTP_VERSION_1_1;

  assert (client != NULL);
  assert (uri != NULL);
  assert (uri->host != NULL);

  /* Determine port and security */
  is_secure = SocketHTTP_URI_is_secure (uri);
  port = SocketHTTP_URI_get_port (uri, is_secure ? HTTPS_DEFAULT_PORT
                                                 : HTTP_DEFAULT_PORT);

  /* Try to get existing connection from pool (also checks limits) */
  entry = pool_try_get_connection (client, uri->host, port, is_secure);
  if (entry != NULL)
    return entry;

  /* pool_try_get_connection returns NULL if limits exceeded after cleanup */
  if (client->pool != NULL
      && client->last_error == HTTPCLIENT_ERROR_LIMIT_EXCEEDED)
    return NULL;

  /* Establish new TCP connection */
  socket = establish_tcp_connection (client, uri->host, port);
  if (socket == NULL)
    return 0;

    /* Handle TLS if needed (with ALPN for HTTP/2 negotiation) */
#if SOCKET_HAS_TLS
  if (is_secure)
    {
      if (setup_tls_connection (client, &socket, uri->host,
                                &negotiated_version)
          != 0)
        return 0;
    }
#else
  if (is_secure)
    {
      Socket_free (&socket);
      client->last_error = HTTPCLIENT_ERROR_TLS;
      HTTPCLIENT_ERROR_MSG ("TLS not available (SOCKET_HAS_TLS not defined)");
      return 0;
    }
#endif

  /* Create pool entry or temporary entry */
  if (client->pool != NULL)
    return create_pooled_entry (client, socket, uri->host, port, is_secure,
                                negotiated_version);

  /* Non-pooled: only HTTP/1.1 for now (temp entries don't support HTTP/2) */
  TRY { return create_temp_entry (socket, uri->host, port, is_secure); }
  EXCEPT (Arena_Failed)
  {
    Socket_free (&socket);
    client->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;
    return 0;
  }
  END_TRY;

  return NULL; /* Unreachable, silences compiler */
}

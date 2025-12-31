/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketHTTPClient-pool.c - HTTP Connection Pooling with Happy Eyeballs */

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

/* SECURITY: Limit to prevent DoS via hash collision attacks */
#ifndef POOL_MAX_HASH_CHAIN_LEN
#define POOL_MAX_HASH_CHAIN_LEN 1024
#endif

/* Hash table load factor for sizing the hash table based on max connections.
 * A load factor of 8 means we size the hash table to ~1/8 the number of
 * max connections, providing a good balance between memory usage and
 * hash lookup performance. */
#ifndef POOL_TARGET_LOAD_FACTOR
#define POOL_TARGET_LOAD_FACTOR 8
#endif

/* Forward declarations */
static void
pool_entry_remove_and_recycle (HTTPPool *pool, HTTPPoolEntry *entry);

static time_t
pool_time (void)
{
  return time (NULL);
}

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
  if (!SocketSecurity_check_size (entry_size))
    {
      SOCKET_RAISE_MSG (SocketHTTPClient,
                        SocketHTTPClient_Failed,
                        "Pool entry size invalid: %zu",
                        entry_size);
    }
  entry = Arena_calloc (pool->arena, 1, entry_size, __FILE__, __LINE__);
  return entry;
}

static void
pool_hash_add (HTTPPool *pool, HTTPPoolEntry *entry)
{
  unsigned hash
      = httpclient_host_hash (entry->host, entry->port, pool->hash_size);

  entry->hash_next = pool->hash_table[hash];
  pool->hash_table[hash] = entry;
}

static void
raise_chain_too_long (size_t chain_len,
                      const char *context,
                      const char *host,
                      int port)
{
  if (host != NULL)
    SOCKET_RAISE_MSG (SocketHTTPClient,
                      SocketHTTPClient_Failed,
                      "Hash chain too long (%zu >= %d) %s for %s:%d - "
                      "possible collision attack",
                      chain_len,
                      POOL_MAX_HASH_CHAIN_LEN,
                      context,
                      host,
                      port);
  else
    SOCKET_RAISE_MSG (SocketHTTPClient,
                      SocketHTTPClient_Failed,
                      "Hash chain too long (%zu >= %d) %s - "
                      "possible collision attack",
                      chain_len,
                      POOL_MAX_HASH_CHAIN_LEN,
                      context);
}

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
    raise_chain_too_long (
        chain_len, "during removal", entry->host, entry->port);
}

static void
pool_list_add (HTTPPool *pool, HTTPPoolEntry *entry)
{
  entry->next = pool->all_conns;
  entry->prev = NULL;
  if (pool->all_conns != NULL)
    pool->all_conns->prev = entry;
  pool->all_conns = entry;
}

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

static void
clear_http1_buffers (HTTPPoolEntry *entry)
{
  if (entry->version != HTTP_VERSION_1_1 && entry->version != HTTP_VERSION_1_0)
    return;

  /* SECURITY: Clear buffers before reuse to prevent information leakage */
  if (entry->proto.h1.inbuf)
    SocketBuf_clear (entry->proto.h1.inbuf);
  if (entry->proto.h1.outbuf)
    SocketBuf_clear (entry->proto.h1.outbuf);

  /* Reset parser state */
  if (entry->proto.h1.parser)
    SocketHTTP1_Parser_reset (entry->proto.h1.parser);
}

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

static void
close_http2_resources (HTTPPoolEntry *entry)
{
  if (entry->proto.h2.conn != NULL)
    SocketHTTP2_Conn_free (&entry->proto.h2.conn);
}

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

static int
host_port_secure_match (const HTTPPoolEntry *entry,
                        const char *host,
                        int port,
                        int is_secure)
{
  if (entry->port != port || entry->is_secure != is_secure)
    return 0;
  return strcasecmp (entry->host, host) == 0;
}

/**
 * Verify SNI hostname match for secure connections.
 *
 * SECURITY: Ensures TLS hostname matches to prevent connection reuse
 * across different hostnames (RFC 6125 requirement).
 *
 * @param entry Pool entry to verify
 * @param host Hostname to match against (may be NULL)
 * @return 1 if match (or not secure), 0 if mismatch
 */
static int
verify_sni_hostname_match (const HTTPPoolEntry *entry, const char *host)
{
  /* Not secure or no host - no SNI verification needed */
  if (!entry->is_secure || host == NULL)
    return 1;

  /* Hostnames are case-insensitive per RFC 1035 */
  return strcasecmp (entry->sni_hostname, host) == 0;
}

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

HTTPPool *
httpclient_pool_new (Arena_T arena, const SocketHTTPClient_Config *config)
{
  HTTPPool *pool;
  size_t hash_size;

  assert (arena != NULL);
  assert (config != NULL);

  size_t pool_size = sizeof (*pool);
  if (!SocketSecurity_check_size (pool_size))
    {
      SOCKET_RAISE_MSG (SocketHTTPClient,
                        SocketHTTPClient_Failed,
                        "HTTP pool size invalid: %zu",
                        pool_size);
    }
  pool = Arena_calloc (arena, 1, pool_size, __FILE__, __LINE__);

  pool->arena = arena;

  /* Calculate hash table size based on expected connections, with security
   * limits */
  size_t suggested_size
      = config->max_total_connections / POOL_TARGET_LOAD_FACTOR;
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
      SOCKET_RAISE_MSG (SocketHTTPClient,
                        SocketHTTPClient_Failed,
                        "Computed hash table size too large: %zu elements",
                        suggested_size);
    }
  hash_size = (unsigned)suggested_size; /* Safe cast, checked above */

  pool->hash_size = hash_size;
  pool->hash_table = Arena_calloc (
      arena, hash_size, sizeof (HTTPPoolEntry *), __FILE__, __LINE__);

  pool->max_per_host = config->max_connections_per_host;
  pool->max_total = config->max_total_connections;
  pool->idle_timeout_ms = config->idle_timeout_ms;

  if (pthread_mutex_init (&pool->mutex, NULL) != 0)
    SOCKET_RAISE_MSG (SocketHTTPClient,
                      SocketHTTPClient_Failed,
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
          /* SECURITY: Verify TLS hostname matches for secure connections
           * to prevent connection reuse across different hostnames.
           * CVE-like vulnerability: An attacker could obtain a connection to
           * evil.com, then reuse it for bank.com if we don't verify SNI
           * hostname. RFC 6125 requires hostname verification on every TLS
           * session use.
           */
          if (!verify_sni_hostname_match (entry, host))
            {
              /* Hostname mismatch - skip this connection and continue search */
              entry = entry->hash_next;
              continue;
            }

          clear_http1_buffers (entry);
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

HTTPPoolEntry *
httpclient_pool_get_prepared (HTTPPool *pool,
                              const char *host,
                              size_t host_len,
                              int port,
                              int is_secure,
                              unsigned precomputed_hash)
{
  HTTPPoolEntry *entry;

  assert (pool != NULL);
  assert (host != NULL);

  (void)host_len; /* Used for consistency; comparison uses strcasecmp */

  pthread_mutex_lock (&pool->mutex);

  /* Use pre-computed hash directly - avoids strlen + hash computation */
  size_t chain_len = 0;
  entry = pool->hash_table[precomputed_hash];
  while (entry != NULL && chain_len < POOL_MAX_HASH_CHAIN_LEN)
    {
      ++chain_len;
      if (host_port_secure_match (entry, host, port, is_secure)
          && entry_can_handle_request (entry))
        {
          /* SECURITY: Verify TLS hostname matches for secure connections */
          if (!verify_sni_hostname_match (entry, host))
            {
              entry = entry->hash_next;
              continue;
            }

          clear_http1_buffers (entry);
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
  return NULL;
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
  idle_threshold = pool->idle_timeout_ms / SOCKET_MS_PER_SECOND;

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

/* SECURITY: Store SNI hostname for TLS verification on connection reuse.
 * This prevents hostname confusion attacks where a connection established
 * for one hostname could be incorrectly reused for a different hostname.
 * The stored hostname is verified on every pool_get() call before reuse.
 */
static void
store_sni_hostname (HTTPPoolEntry *entry, const char *host, int is_secure)
{
  if (is_secure && host)
    {
      strncpy (entry->sni_hostname, host, sizeof (entry->sni_hostname) - 1);
      entry->sni_hostname[sizeof (entry->sni_hostname) - 1] = '\0';
    }
  else
    {
      entry->sni_hostname[0] = '\0';
    }
}

static void
create_http1_entry_resources (HTTPPoolEntry *entry)
{
  /* Use unlocked arena for single-threaded per-connection use */
  entry->proto.h1.conn_arena = Arena_new_unlocked ();

  entry->proto.h1.parser = SocketHTTP1_Parser_new (
      HTTP1_PARSE_RESPONSE, NULL, entry->proto.h1.conn_arena);

  entry->proto.h1.inbuf
      = SocketBuf_new (entry->proto.h1.conn_arena, HTTPCLIENT_IO_BUFFER_SIZE);
  entry->proto.h1.outbuf
      = SocketBuf_new (entry->proto.h1.conn_arena, HTTPCLIENT_IO_BUFFER_SIZE);
}

static void
init_http1_entry_fields (HTTPPoolEntry *entry,
                         Socket_T socket,
                         const char *host,
                         int port,
                         int is_secure,
                         HTTPPool *pool)
{
  size_t host_len = strlen (host);

  size_t alloc_size = host_len + 1;
  if (!SocketSecurity_check_size (alloc_size))
    {
      SOCKET_RAISE_MSG (SocketHTTPClient,
                        SocketHTTPClient_Failed,
                        "Hostname too long: %zu bytes",
                        host_len);
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

  store_sni_hostname (entry, host, is_secure);
}

static void
recycle_entry_on_failure (HTTPPool *pool, HTTPPoolEntry *entry)
{
  entry->next = pool->free_entries;
  pool->free_entries = entry;
}

static HTTPPoolEntry *
create_http1_connection (
    HTTPPool *pool, Socket_T socket, const char *host, int port, int is_secure)
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

    init_http1_entry_fields (
        (HTTPPoolEntry *)entry, socket, host, port, is_secure, pool);
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

static void
init_http2_entry_fields (HTTPPoolEntry *entry,
                         Socket_T socket,
                         const char *host,
                         int port,
                         int is_secure,
                         HTTPPool *pool)
{
  (void)socket; /* Socket is stored in HTTP/2 conn, not directly in entry */
  size_t host_len = strlen (host);
  size_t alloc_size = host_len + 1;

  if (!SocketSecurity_check_size (alloc_size))
    {
      SOCKET_RAISE_MSG (SocketHTTPClient,
                        SocketHTTPClient_Failed,
                        "Hostname too long: %zu bytes",
                        host_len);
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

  store_sni_hostname (entry, host, is_secure);
}

static int
create_http2_entry_resources (HTTPPoolEntry *entry,
                              Socket_T socket,
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

static HTTPPoolEntry *
create_http2_connection (
    HTTPPool *pool, Socket_T socket, const char *host, int port, int is_secure)
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

    init_http2_entry_fields (
        (HTTPPoolEntry *)entry, socket, host, port, is_secure, pool);
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

static int
check_connection_limits (SocketHTTPClient_T client,
                         const char *host,
                         int port,
                         int is_secure)
{
  assert (client != NULL);
  assert (client->pool != NULL);
  assert (host != NULL);

  pthread_mutex_lock (&client->pool->mutex);
  size_t host_count = pool_count_for_host (client->pool, host, port, is_secure);
  int can_create
      = (host_count < (size_t)client->pool->max_per_host
         && client->pool->current_count < (size_t)client->pool->max_total);
  pthread_mutex_unlock (&client->pool->mutex);

  if (!can_create)
    {
      HTTPCLIENT_ERROR_MSG ("Connection limit exceeded for %s:%d "
                            "(host: %zu/%zu, total: %zu/%zu)",
                            host,
                            port,
                            host_count,
                            (size_t)client->pool->max_per_host,
                            client->pool->current_count,
                            client->pool->max_total);
      client->last_error = HTTPCLIENT_ERROR_LIMIT_EXCEEDED;
    }

  return can_create;
}

static HTTPPoolEntry *
pool_try_get_connection (SocketHTTPClient_T client,
                         const char *host,
                         int port,
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

static Socket_T
establish_tcp_connection (SocketHTTPClient_T client, const char *host, int port)
{
  SocketHE_Config_T he_config;
  volatile Socket_T socket = NULL;

  SocketHappyEyeballs_config_defaults (&he_config);
  he_config.total_timeout_ms = client->config.connect_timeout_ms;
  he_config.attempt_timeout_ms = client->config.connect_timeout_ms / 2;

  TRY
  {
    socket = SocketHappyEyeballs_connect (host, port, &he_config);
  }
  EXCEPT (SocketHE_Failed)
  {
    socket = NULL;
  }
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
static SocketTLSContext_T
ensure_tls_context (SocketHTTPClient_T client)
{
  if (client->config.tls_context != NULL)
    return client->config.tls_context;

  if (client->default_tls_ctx != NULL)
    return client->default_tls_ctx;

  TRY
  {
    client->default_tls_ctx = SocketTLSContext_new_client (NULL);
  }
  EXCEPT (SocketTLS_Failed)
  {
    return 0;
  }
  END_TRY;

  return client->default_tls_ctx;
}

static int
enable_socket_tls (Socket_T socket, SocketTLSContext_T tls_ctx)
{
  TRY
  {
    SocketTLS_enable (socket, tls_ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    return -1;
  }
  END_TRY;

  return 0;
}

static int
perform_tls_handshake (Socket_T socket, int timeout_ms)
{
  TRY
  {
    TLSHandshakeState result = SocketTLS_handshake_loop (socket, timeout_ms);
    if (result != TLS_HANDSHAKE_COMPLETE)
      return -1;
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    return -1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    return -1;
  }
  END_TRY;

  return 0;
}

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

static SocketHTTP_Version
determine_negotiated_version (Socket_T socket)
{
  const char *alpn = SocketTLS_get_alpn_selected (socket);
  if (alpn != NULL && strcmp (alpn, "h2") == 0)
    return HTTP_VERSION_2;
  return HTTP_VERSION_1_1;
}

static int
setup_tls_connection (SocketHTTPClient_T client,
                      Socket_T *socket,
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
      HTTPCLIENT_ERROR_MSG (
          "SNI hostname too long: %zu > %d", hn_len, SOCKET_TLS_MAX_SNI_LEN);
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

  /* Configure ALPN for HTTP/2 negotiation.
   * Non-pooled mode (pool == NULL) only supports HTTP/1.1, so limit ALPN
   * to prevent negotiating h2 that we can't handle. */
  SocketHTTP_Version effective_max_version = client->config.max_version;
  if (client->pool == NULL && effective_max_version > HTTP_VERSION_1_1)
    effective_max_version = HTTP_VERSION_1_1;
  configure_alpn_for_http2 (tls_ctx, effective_max_version);

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

/* Create temporary thread-local entry for non-pooled connections */
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

  /* Create thread-local arena first for host copy and parser.
   * Use unlocked arena since temp entries are thread-local. */
  temp_arena = Arena_new_unlocked ();
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
  if (!SocketSecurity_check_size (alloc_size))
    {
      Arena_dispose (&temp_arena);
      SOCKET_RAISE_MSG (SocketHTTPClient,
                        SocketHTTPClient_Failed,
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

static HTTPPoolEntry *
create_pooled_entry (SocketHTTPClient_T client,
                     Socket_T socket,
                     const char *host,
                     int port,
                     int is_secure,
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

static void
determine_connection_params (const SocketHTTP_URI *uri,
                             int *port,
                             int *is_secure)
{
  assert (uri != NULL);
  assert (port != NULL);
  assert (is_secure != NULL);

  *is_secure = SocketHTTP_URI_is_secure (uri);
  *port = SocketHTTP_URI_get_port (
      uri, *is_secure ? HTTPS_DEFAULT_PORT : HTTP_DEFAULT_PORT);
}

static HTTPPoolEntry *
handle_non_pooled_entry (SocketHTTPClient_T client,
                         Socket_T socket,
                         const char *host,
                         int port,
                         int is_secure,
                         SocketHTTP_Version negotiated_version)
{
  /* Non-pooled: only HTTP/1.1 supported (temp entries don't do HTTP/2).
   * If ALPN negotiated h2, we must fail since we can't handle HTTP/2 framing.
   * This can happen when the server only supports h2 (rare) or prefers it. */
  if (negotiated_version == HTTP_VERSION_2)
    {
      HTTPCLIENT_ERROR_MSG ("HTTP/2 negotiated but non-pooled mode only "
                            "supports HTTP/1.1");
      Socket_free (&socket);
      client->last_error = HTTPCLIENT_ERROR_PROTOCOL;
      return NULL;
    }

  TRY
  {
    return create_temp_entry (socket, host, port, is_secure);
  }
  EXCEPT (Arena_Failed)
  {
    Socket_free (&socket);
    client->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;
    return 0;
  }
  END_TRY;

  return NULL; /* Unreachable, silences compiler */
}

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

  determine_connection_params (uri, &port, &is_secure);

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
      if (setup_tls_connection (client, &socket, uri->host, &negotiated_version)
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
    return create_pooled_entry (
        client, socket, uri->host, port, is_secure, negotiated_version);

  return handle_non_pooled_entry (
      client, socket, uri->host, port, is_secure, negotiated_version);
}

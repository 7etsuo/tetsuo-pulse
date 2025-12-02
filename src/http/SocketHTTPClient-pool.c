/**
 * SocketHTTPClient-pool.c - HTTP Connection Pool Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
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

#include "http/SocketHTTPClient.h"
#include "http/SocketHTTPClient-private.h"
#include "http/SocketHTTP1.h"
#include "socket/Socket.h"
#include "socket/SocketHappyEyeballs.h"
#include "socket/SocketBuf.h"
#include "core/Arena.h"

#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"
#endif

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * Pool Configuration
 * ============================================================================ */

#define POOL_DEFAULT_HASH_SIZE 127
#define POOL_IO_BUFFER_SIZE 8192

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * Get monotonic time in seconds
 */
static time_t
pool_time (void)
{
  struct timespec ts;
  if (clock_gettime (CLOCK_MONOTONIC, &ts) == 0)
    return ts.tv_sec;
  return time (NULL);
}

/**
 * Allocate a new pool entry
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

  /* Allocate new entry */
  entry = Arena_alloc (pool->arena, sizeof (*entry), __FILE__, __LINE__);
  if (entry != NULL)
    {
      memset (entry, 0, sizeof (*entry));
    }

  return entry;
}

/**
 * Add entry to hash table
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
 * Remove entry from hash table
 */
static void
pool_hash_remove (HTTPPool *pool, HTTPPoolEntry *entry)
{
  unsigned hash
      = httpclient_host_hash (entry->host, entry->port, pool->hash_size);

  HTTPPoolEntry **pp = &pool->hash_table[hash];
  while (*pp != NULL)
    {
      if (*pp == entry)
        {
          *pp = entry->hash_next;
          entry->hash_next = NULL;
          return;
        }
      pp = &(*pp)->hash_next;
    }
}

/**
 * Add entry to all connections list
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
 * Remove entry from all connections list
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
 * Close and clean up a connection entry
 */
static void
pool_entry_close (HTTPPoolEntry *entry)
{
  if (entry == NULL)
    return;

  if (entry->version == HTTP_VERSION_1_1 || entry->version == HTTP_VERSION_1_0)
    {
      if (entry->proto.h1.socket != NULL)
        {
          Socket_free (&entry->proto.h1.socket);
        }
      if (entry->proto.h1.parser != NULL)
        {
          SocketHTTP1_Parser_free (&entry->proto.h1.parser);
        }
      if (entry->proto.h1.inbuf != NULL)
        {
          SocketBuf_release (&entry->proto.h1.inbuf);
        }
      if (entry->proto.h1.outbuf != NULL)
        {
          SocketBuf_release (&entry->proto.h1.outbuf);
        }
    }
  else if (entry->version == HTTP_VERSION_2)
    {
      if (entry->proto.h2.conn != NULL)
        {
          SocketHTTP2_Conn_free (&entry->proto.h2.conn);
        }
    }

  entry->closed = 1;
}

/**
 * Count connections to a specific host:port
 */
static size_t
pool_count_for_host (HTTPPool *pool, const char *host, int port, int is_secure)
{
  size_t count = 0;
  unsigned hash = httpclient_host_hash (host, port, pool->hash_size);

  HTTPPoolEntry *entry = pool->hash_table[hash];
  while (entry != NULL)
    {
      if (entry->port == port && entry->is_secure == is_secure
          && strcasecmp (entry->host, host) == 0)
        {
          count++;
        }
      entry = entry->hash_next;
    }

  return count;
}

/* ============================================================================
 * Pool Lifecycle
 * ============================================================================ */

HTTPPool *
httpclient_pool_new (Arena_T arena, const SocketHTTPClient_Config *config)
{
  HTTPPool *pool;
  size_t hash_size;

  assert (arena != NULL);
  assert (config != NULL);

  pool = Arena_alloc (arena, sizeof (*pool), __FILE__, __LINE__);
  if (pool == NULL)
    return NULL;

  memset (pool, 0, sizeof (*pool));
  pool->arena = arena;

  /* Calculate hash table size */
  hash_size = POOL_DEFAULT_HASH_SIZE;
  if (config->max_total_connections > 100)
    hash_size = 251; /* Larger prime for more connections */

  pool->hash_size = hash_size;
  pool->hash_table = Arena_calloc (arena, hash_size, sizeof (HTTPPoolEntry *),
                                   __FILE__, __LINE__);
  if (pool->hash_table == NULL)
    return NULL;

  pool->max_per_host = config->max_connections_per_host;
  pool->max_total = config->max_total_connections;
  pool->idle_timeout_ms = config->idle_timeout_ms;

  if (pthread_mutex_init (&pool->mutex, NULL) != 0)
    return NULL;

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
 * ============================================================================ */

HTTPPoolEntry *
httpclient_pool_get (HTTPPool *pool, const char *host, int port, int is_secure)
{
  HTTPPoolEntry *entry;
  unsigned hash;

  assert (pool != NULL);
  assert (host != NULL);

  pthread_mutex_lock (&pool->mutex);

  hash = httpclient_host_hash (host, port, pool->hash_size);

  /* Find an available connection */
  entry = pool->hash_table[hash];
  while (entry != NULL)
    {
      if (entry->port == port && entry->is_secure == is_secure && !entry->in_use
          && !entry->closed && strcasecmp (entry->host, host) == 0)
        {
          entry->in_use = 1;
          entry->last_used = pool_time ();
          pool->reused_connections++;
          pthread_mutex_unlock (&pool->mutex);
          return entry;
        }
      entry = entry->hash_next;
    }

  pthread_mutex_unlock (&pool->mutex);
  return NULL;
}

void
httpclient_pool_release (HTTPPool *pool, HTTPPoolEntry *entry)
{
  assert (pool != NULL);
  assert (entry != NULL);

  pthread_mutex_lock (&pool->mutex);

  entry->in_use = 0;
  entry->last_used = pool_time ();

  pthread_mutex_unlock (&pool->mutex);
}

void
httpclient_pool_close (HTTPPool *pool, HTTPPoolEntry *entry)
{
  assert (pool != NULL);
  assert (entry != NULL);

  pthread_mutex_lock (&pool->mutex);

  /* Remove from hash table */
  pool_hash_remove (pool, entry);

  /* Remove from connection list */
  pool_list_remove (pool, entry);

  /* Close resources */
  pool_entry_close (entry);

  /* Add to free list for reuse */
  entry->next = pool->free_entries;
  pool->free_entries = entry;

  pool->current_count--;

  pthread_mutex_unlock (&pool->mutex);
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
  idle_threshold = pool->idle_timeout_ms / 1000;

  HTTPPoolEntry *entry = pool->all_conns;
  while (entry != NULL)
    {
      HTTPPoolEntry *next = entry->next;

      if (!entry->in_use && !entry->closed
          && (now - entry->last_used) >= idle_threshold)
        {
          /* Remove from hash table */
          pool_hash_remove (pool, entry);

          /* Remove from connection list */
          pool_list_remove (pool, entry);

          /* Close resources */
          pool_entry_close (entry);

          /* Add to free list */
          entry->next = pool->free_entries;
          pool->free_entries = entry;

          pool->current_count--;
        }

      entry = next;
    }

  pthread_mutex_unlock (&pool->mutex);
}

/* ============================================================================
 * Connection Establishment
 * ============================================================================ */

/**
 * Create new HTTP/1.1 connection
 */
static HTTPPoolEntry *
create_http1_connection (HTTPPool *pool, Socket_T socket, const char *host,
                         int port, int is_secure)
{
  HTTPPoolEntry *entry;
  Arena_T conn_arena;
  size_t host_len;

  entry = pool_entry_alloc (pool);
  if (entry == NULL)
    return NULL;

  /* Copy host */
  host_len = strlen (host);
  entry->host = Arena_alloc (pool->arena, host_len + 1, __FILE__, __LINE__);
  if (entry->host == NULL)
    {
      entry->next = pool->free_entries;
      pool->free_entries = entry;
      return NULL;
    }
  memcpy (entry->host, host, host_len + 1);

  entry->port = port;
  entry->is_secure = is_secure;
  entry->version = HTTP_VERSION_1_1;
  entry->created_at = pool_time ();
  entry->last_used = entry->created_at;
  entry->in_use = 1;
  entry->closed = 0;

  /* Set up HTTP/1.1 protocol state */
  entry->proto.h1.socket = socket;

  /* Create parser */
  conn_arena = Arena_new ();
  if (conn_arena == NULL)
    {
      entry->proto.h1.socket = NULL;
      entry->next = pool->free_entries;
      pool->free_entries = entry;
      return NULL;
    }

  entry->proto.h1.parser
      = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, conn_arena);
  if (entry->proto.h1.parser == NULL)
    {
      Arena_dispose (&conn_arena);
      entry->proto.h1.socket = NULL;
      entry->next = pool->free_entries;
      pool->free_entries = entry;
      return NULL;
    }

  /* Create I/O buffers */
  entry->proto.h1.inbuf = SocketBuf_new (conn_arena, POOL_IO_BUFFER_SIZE);
  entry->proto.h1.outbuf = SocketBuf_new (conn_arena, POOL_IO_BUFFER_SIZE);

  /* Add to pool */
  pool_hash_add (pool, entry);
  pool_list_add (pool, entry);
  pool->current_count++;
  pool->total_requests++;

  return entry;
}

HTTPPoolEntry *
httpclient_connect (SocketHTTPClient_T client, const SocketHTTP_URI *uri)
{
  HTTPPoolEntry *entry;
  Socket_T socket;
  int port;
  int is_secure;
  SocketHE_Config_T he_config;
#ifdef SOCKET_HAS_TLS
  volatile SocketTLSContext_T tls_ctx = NULL;
#endif

  assert (client != NULL);
  assert (uri != NULL);
  assert (uri->host != NULL);

  /* Determine port and security */
  is_secure = SocketHTTP_URI_is_secure (uri);
  port = SocketHTTP_URI_get_port (uri, is_secure ? 443 : 80);

  /* Try to get existing connection from pool */
  if (client->pool != NULL)
    {
      entry = httpclient_pool_get (client->pool, uri->host, port, is_secure);
      if (entry != NULL)
        return entry;

      /* Check if we're at the per-host limit */
      pthread_mutex_lock (&client->pool->mutex);
      size_t host_count
          = pool_count_for_host (client->pool, uri->host, port, is_secure);
      int at_host_limit = (host_count >= client->pool->max_per_host);
      int at_total_limit
          = (client->pool->current_count >= client->pool->max_total);
      pthread_mutex_unlock (&client->pool->mutex);

      if (at_host_limit || at_total_limit)
        {
          /* Clean up idle connections and retry */
          httpclient_pool_cleanup_idle (client->pool);

          entry = httpclient_pool_get (client->pool, uri->host, port, is_secure);
          if (entry != NULL)
            return entry;
        }
    }

  /* Create new connection using Happy Eyeballs */
  SocketHappyEyeballs_config_defaults (&he_config);
  he_config.total_timeout_ms = client->config.connect_timeout_ms;
  he_config.attempt_timeout_ms = client->config.connect_timeout_ms / 2;

  TRY
    {
      socket = SocketHappyEyeballs_connect (uri->host, port, &he_config);
    }
  EXCEPT (SocketHE_Failed)
    {
      client->last_error = HTTPCLIENT_ERROR_CONNECT;
      HTTPCLIENT_ERROR_MSG ("Connection to %s:%d failed", uri->host, port);
      return NULL;
    }
  END_TRY;

  if (socket == NULL)
    {
      client->last_error = HTTPCLIENT_ERROR_CONNECT;
      return NULL;
    }

  /* Handle TLS if needed */
#ifdef SOCKET_HAS_TLS
  if (is_secure)
    {
      tls_ctx = client->config.tls_context;

      /* Create default TLS context if not provided */
      if (tls_ctx == NULL)
        {
          if (client->default_tls_ctx == NULL)
            {
              TRY
                {
                  client->default_tls_ctx = SocketTLSContext_new_client (NULL);
                }
              EXCEPT (SocketTLS_Failed)
                {
                  Socket_free (&socket);
                  client->last_error = HTTPCLIENT_ERROR_TLS;
                  return NULL;
                }
              END_TRY;
            }
          tls_ctx = client->default_tls_ctx;
        }

      /* Enable TLS on socket */
      TRY
        {
          SocketTLS_enable (socket, tls_ctx);
        }
      EXCEPT (SocketTLS_Failed)
        {
          Socket_free (&socket);
          client->last_error = HTTPCLIENT_ERROR_TLS;
          return NULL;
        }
      END_TRY;

      /* Set SNI hostname */
      SocketTLS_set_hostname (socket, uri->host);

      /* Perform handshake */
      TRY
        {
          int result = SocketTLS_handshake (socket);
          if (result != 0)
            {
              Socket_free (&socket);
              client->last_error = HTTPCLIENT_ERROR_TLS;
              return NULL;
            }
        }
      EXCEPT (SocketTLS_HandshakeFailed)
        {
          Socket_free (&socket);
          client->last_error = HTTPCLIENT_ERROR_TLS;
          return NULL;
        }
      EXCEPT (SocketTLS_VerifyFailed)
        {
          Socket_free (&socket);
          client->last_error = HTTPCLIENT_ERROR_TLS;
          return NULL;
        }
      END_TRY;
    }
#else
  if (is_secure)
    {
      Socket_free (&socket);
      client->last_error = HTTPCLIENT_ERROR_TLS;
      HTTPCLIENT_ERROR_MSG ("TLS not available (SOCKET_HAS_TLS not defined)");
      return NULL;
    }
#endif

  /* Create pool entry */
  if (client->pool != NULL)
    {
      pthread_mutex_lock (&client->pool->mutex);
      entry = create_http1_connection (client->pool, socket, uri->host, port,
                                       is_secure);
      pthread_mutex_unlock (&client->pool->mutex);

      if (entry == NULL)
        {
          Socket_free (&socket);
          client->last_error = HTTPCLIENT_ERROR_OUT_OF_MEMORY;
          return NULL;
        }

      return entry;
    }

  /* No pooling - create temporary entry */
  {
    /* Thread-local storage for non-pooled case */
    static __thread HTTPPoolEntry temp_entry;
    static __thread Arena_T temp_arena = NULL;

    /* Clean up previous temp arena if it exists */
    if (temp_arena != NULL)
      {
        Arena_dispose (&temp_arena);
      }

    memset (&temp_entry, 0, sizeof (temp_entry));
    temp_entry.host = (char *)uri->host;
    temp_entry.port = port;
    temp_entry.is_secure = is_secure;
    temp_entry.version = HTTP_VERSION_1_1;
    temp_entry.proto.h1.socket = socket;
    temp_entry.in_use = 1;

    /* Create parser in thread-local arena */
    temp_arena = Arena_new ();
    if (temp_arena != NULL)
      {
        temp_entry.proto.h1.parser
            = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, temp_arena);
      }

    return &temp_entry;
  }
}

/* ============================================================================
 * Request/Response Operations
 * ============================================================================ */

int
httpclient_send_request (HTTPPoolEntry *conn, SocketHTTPClient_Request_T req)
{
  /* This is handled in SocketHTTPClient.c execute_http1_request() */
  (void)conn;
  (void)req;
  return 0;
}

int
httpclient_receive_response (HTTPPoolEntry *conn,
                             SocketHTTPClient_Response *response, Arena_T arena)
{
  /* This is handled in SocketHTTPClient.c execute_http1_request() */
  (void)conn;
  (void)response;
  (void)arena;
  return 0;
}


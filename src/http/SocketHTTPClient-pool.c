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
#include "core/SocketUtil.h"

#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"
#endif

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
 * ============================================================================ */

/**
 * Get monotonic time in seconds
 *
 * REFACTOR: Uses Socket_get_monotonic_ms() from SocketUtil.h and converts
 * to seconds for backward compatibility with pool_time() callers.
 */
static time_t
pool_time (void)
{
  return (time_t)(Socket_get_monotonic_ms () / SOCKET_MS_PER_SECOND);
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
      /* Dispose of connection arena (frees parser, buffers memory) */
      if (entry->proto.h1.conn_arena != NULL)
        {
          Arena_dispose (&entry->proto.h1.conn_arena);
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
  hash_size = HTTPCLIENT_POOL_HASH_SIZE;
  if (config->max_total_connections > HTTPCLIENT_POOL_LARGE_THRESHOLD)
    hash_size = HTTPCLIENT_POOL_LARGE_HASH_SIZE; /* Larger prime for more connections */

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
 * Connection Establishment - Helper Functions
 * ============================================================================ */

/**
 * create_http1_entry_resources - Allocate HTTP/1.1 parser and buffers
 * @entry: Pool entry to initialize
 * @pool: Pool for arena allocation
 *
 * Returns: 0 on success, -1 on failure
 *
 * Creates a connection arena, parser, and I/O buffers for the entry.
 */
static int
create_http1_entry_resources (HTTPPoolEntry *entry, HTTPPool *pool)
{
  Arena_T conn_arena;

  conn_arena = Arena_new ();
  if (conn_arena == NULL)
    return -1;

  entry->proto.h1.parser
      = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, conn_arena);
  if (entry->proto.h1.parser == NULL)
    {
      Arena_dispose (&conn_arena);
      return -1;
    }

  entry->proto.h1.inbuf = SocketBuf_new (conn_arena, HTTPCLIENT_IO_BUFFER_SIZE);
  entry->proto.h1.outbuf = SocketBuf_new (conn_arena, HTTPCLIENT_IO_BUFFER_SIZE);
  entry->proto.h1.conn_arena = conn_arena;

  (void)pool; /* Used for consistency, arena comes from entry */
  return 0;
}

/**
 * create_http1_connection - Create new HTTP/1.1 pool entry
 * @pool: Connection pool
 * @socket: Connected socket
 * @host: Target hostname
 * @port: Target port
 * @is_secure: 1 for HTTPS, 0 for HTTP
 *
 * Returns: New pool entry, or NULL on failure
 *
 * Allocates entry, copies host, creates parser/buffers, adds to pool.
 */
static HTTPPoolEntry *
create_http1_connection (HTTPPool *pool, Socket_T socket, const char *host,
                         int port, int is_secure)
{
  HTTPPoolEntry *entry;
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

  /* Initialize entry fields */
  entry->port = port;
  entry->is_secure = is_secure;
  entry->version = HTTP_VERSION_1_1;
  entry->created_at = pool_time ();
  entry->last_used = entry->created_at;
  entry->in_use = 1;
  entry->closed = 0;
  entry->proto.h1.socket = socket;

  /* Create parser and buffers */
  if (create_http1_entry_resources (entry, pool) != 0)
    {
      entry->proto.h1.socket = NULL;
      entry->next = pool->free_entries;
      pool->free_entries = entry;
      return NULL;
    }

  /* Add to pool structures */
  pool_hash_add (pool, entry);
  pool_list_add (pool, entry);
  pool->current_count++;
  pool->total_requests++;

  return entry;
}

/**
 * pool_try_get_connection - Try to get existing connection from pool
 * @client: HTTP client
 * @host: Target hostname
 * @port: Target port
 * @is_secure: 1 for HTTPS, 0 for HTTP
 *
 * Returns: Pool entry if found, NULL otherwise
 *
 * First tries direct lookup, then checks limits and cleans idle if needed.
 */
static HTTPPoolEntry *
pool_try_get_connection (SocketHTTPClient_T client, const char *host, int port,
                         int is_secure)
{
  HTTPPoolEntry *entry;
  size_t host_count;
  int at_host_limit;
  int at_total_limit;

  if (client->pool == NULL)
    return NULL;

  /* Try direct lookup first */
  entry = httpclient_pool_get (client->pool, host, port, is_secure);
  if (entry != NULL)
    return entry;

  /* Check connection limits */
  pthread_mutex_lock (&client->pool->mutex);
  host_count = pool_count_for_host (client->pool, host, port, is_secure);
  at_host_limit = (host_count >= client->pool->max_per_host);
  at_total_limit = (client->pool->current_count >= client->pool->max_total);
  pthread_mutex_unlock (&client->pool->mutex);

  if (!at_host_limit && !at_total_limit)
    return NULL; /* No limits hit, proceed to create new connection */

  /* Clean up idle connections and retry */
  httpclient_pool_cleanup_idle (client->pool);
  return httpclient_pool_get (client->pool, host, port, is_secure);
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

#ifdef SOCKET_HAS_TLS
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

  TRY
    {
      client->default_tls_ctx = SocketTLSContext_new_client (NULL);
    }
  EXCEPT (SocketTLS_Failed)
    {
      return NULL;
    }
  END_TRY;

  return client->default_tls_ctx;
}

/**
 * setup_tls_connection - Enable TLS and perform handshake
 * @client: HTTP client
 * @socket: Connected TCP socket
 * @hostname: SNI hostname
 *
 * Returns: 0 on success, -1 on failure (socket freed on error)
 */
static int
setup_tls_connection (SocketHTTPClient_T client, Socket_T *socket,
                      const char *hostname)
{
  SocketTLSContext_T tls_ctx;

  tls_ctx = ensure_tls_context (client);
  if (tls_ctx == NULL)
    {
      Socket_free (socket);
      client->last_error = HTTPCLIENT_ERROR_TLS;
      return -1;
    }

  /* Enable TLS on socket */
  TRY
    {
      SocketTLS_enable (*socket, tls_ctx);
    }
  EXCEPT (SocketTLS_Failed)
    {
      Socket_free (socket);
      client->last_error = HTTPCLIENT_ERROR_TLS;
      return -1;
    }
  END_TRY;

  /* Set SNI hostname */
  SocketTLS_set_hostname (*socket, hostname);

  /* Perform handshake with timeout
   * Use connect_timeout_ms for TLS handshake as part of connection phase */
  TRY
    {
      int tls_timeout = client->config.connect_timeout_ms;
      if (tls_timeout <= 0)
        tls_timeout = SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS;

      TLSHandshakeState result = SocketTLS_handshake_loop (*socket, tls_timeout);
      if (result != TLS_HANDSHAKE_COMPLETE)
        {
          Socket_free (socket);
          client->last_error = HTTPCLIENT_ERROR_TLS;
          return -1;
        }
    }
  EXCEPT (SocketTLS_HandshakeFailed)
    {
      Socket_free (socket);
      client->last_error = HTTPCLIENT_ERROR_TLS;
      return -1;
    }
  EXCEPT (SocketTLS_VerifyFailed)
    {
      Socket_free (socket);
      client->last_error = HTTPCLIENT_ERROR_TLS;
      return -1;
    }
  END_TRY;

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

  /* Clean up previous temp arena if it exists.
   * This ensures we don't accumulate memory across multiple requests
   * within the same thread. */
  if (temp_arena != NULL)
    {
      Arena_dispose (&temp_arena);
      temp_arena = NULL;
    }

  memset (&temp_entry, 0, sizeof (temp_entry));
  temp_entry.host = (char *)host;
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

/**
 * create_pooled_entry - Create pool entry for new connection
 * @client: HTTP client
 * @socket: Connected socket (freed on error)
 * @host: Target hostname
 * @port: Target port
 * @is_secure: 1 for HTTPS, 0 for HTTP
 *
 * Returns: Pool entry, or NULL on failure
 */
static HTTPPoolEntry *
create_pooled_entry (SocketHTTPClient_T client, Socket_T socket,
                     const char *host, int port, int is_secure)
{
  HTTPPoolEntry *entry;

  pthread_mutex_lock (&client->pool->mutex);
  entry = create_http1_connection (client->pool, socket, host, port, is_secure);
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
 * ============================================================================ */

/**
 * httpclient_connect - Get or create connection to host
 * @client: HTTP client
 * @uri: Target URI
 *
 * Returns: Pool entry for connection, or NULL on failure
 *
 * Orchestrates connection establishment:
 * 1. Try existing pool connection
 * 2. Establish TCP via Happy Eyeballs
 * 3. Set up TLS if needed
 * 4. Create pool entry (or temporary for non-pooled)
 */
HTTPPoolEntry *
httpclient_connect (SocketHTTPClient_T client, const SocketHTTP_URI *uri)
{
  HTTPPoolEntry *entry;
  Socket_T socket;
  int port;
  int is_secure;

  assert (client != NULL);
  assert (uri != NULL);
  assert (uri->host != NULL);

  /* Determine port and security */
  is_secure = SocketHTTP_URI_is_secure (uri);
  port = SocketHTTP_URI_get_port (uri, is_secure ? 443 : 80);

  /* Try to get existing connection from pool */
  entry = pool_try_get_connection (client, uri->host, port, is_secure);
  if (entry != NULL)
    return entry;

  /* Establish new TCP connection */
  socket = establish_tcp_connection (client, uri->host, port);
  if (socket == NULL)
    return NULL;

  /* Handle TLS if needed */
#ifdef SOCKET_HAS_TLS
  if (is_secure)
    {
      if (setup_tls_connection (client, &socket, uri->host) != 0)
        return NULL;
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

  /* Create pool entry or temporary entry */
  if (client->pool != NULL)
    return create_pooled_entry (client, socket, uri->host, port, is_secure);

  return create_temp_entry (socket, uri->host, port, is_secure);
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


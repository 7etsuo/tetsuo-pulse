#ifndef SOCKETPOOL_PRIVATE_H_INCLUDED
#define SOCKETPOOL_PRIVATE_H_INCLUDED

/**
 * SocketPool-private.h - Private implementation details for SocketPool
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Contains internal structures, macros, and function declarations shared
 * across SocketPool implementation files. Not for public use.
 */

#include <pthread.h>
#include <time.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketIPTracker.h"
#include "core/SocketRateLimit.h"
#include "core/SocketUtil.h"
#include "pool/SocketPool.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"

#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLSContext.h"
#include <openssl/ssl.h>
#endif

/* ============================================================================
 * Hash Table Configuration
 * ============================================================================ */

/** Hash table size - uses central configuration for consistency */
#define SOCKET_HASH_SIZE SOCKET_HASH_TABLE_SIZE

/* ============================================================================
 * Thread-Local Exception Handling
 * ============================================================================ */

/**
 * Thread-local exception for detailed error messages.
 * Each thread gets its own copy to prevent race conditions.
 */
#ifdef _WIN32
extern __declspec (thread) Except_T SocketPool_DetailedException;
#else
extern __thread Except_T SocketPool_DetailedException;
#endif

/**
 * RAISE_POOL_ERROR - Raise exception with thread-local detailed message
 * @exception: Base exception type to raise
 *
 * Creates a thread-local copy of the exception with detailed reason
 * from socket_error_buf, then raises it.
 */
#define RAISE_POOL_ERROR(exception)                                           \
  do                                                                          \
    {                                                                         \
      SocketPool_DetailedException = (exception);                             \
      SocketPool_DetailedException.reason = socket_error_buf;                 \
      RAISE (SocketPool_DetailedException);                                   \
    }                                                                         \
  while (0)

/* ============================================================================
 * Connection Structure
 * ============================================================================ */

struct Connection
{
  Socket_T socket;
  SocketBuf_T inbuf;
  SocketBuf_T outbuf;
  void *data;
  time_t last_activity;
  int active;
  struct Connection *hash_next;
  struct Connection *free_next;
  SocketReconnect_T reconnect;      /**< Auto-reconnection context (NULL if disabled) */
  char *tracked_ip;                 /**< Tracked IP for per-IP limiting (NULL if not tracked) */
#ifdef SOCKET_HAS_TLS
  SocketTLSContext_T tls_ctx;       /**< TLS context for this connection */
  int tls_handshake_complete;       /**< TLS handshake state */
  SSL_SESSION *tls_session;         /**< Saved session for potential reuse */
#endif
};

typedef struct Connection *Connection_T;

/* ============================================================================
 * Pool Structure
 * ============================================================================ */

/* Forward declaration for async connect context */
struct AsyncConnectContext;
typedef struct AsyncConnectContext *AsyncConnectContext_T;

#define T SocketPool_T
struct T
{
  struct Connection *connections;   /**< Pre-allocated connection array */
  Connection_T *hash_table;         /**< Hash table for O(1) lookup */
  Connection_T free_list;           /**< Linked list of free slots */
  Socket_T *cleanup_buffer;         /**< Buffer for cleanup operations */
  size_t maxconns;                  /**< Maximum connections */
  size_t bufsize;                   /**< Buffer size per connection */
  size_t count;                     /**< Active connection count */
  Arena_T arena;                    /**< Memory arena */
  pthread_mutex_t mutex;            /**< Thread safety mutex */
  SocketDNS_T dns;                  /**< Internal DNS resolver (lazy init) */
  AsyncConnectContext_T async_ctx;  /**< Linked list of pending async connects */
  
  /* Reconnection support */
  SocketReconnect_Policy_T reconnect_policy; /**< Default reconnection policy */
  int reconnect_enabled;            /**< 1 if default reconnection enabled */
  
  /* Rate limiting support */
  SocketRateLimit_T conn_limiter;   /**< Connection rate limiter (NULL if disabled) */
  SocketIPTracker_T ip_tracker;     /**< Per-IP connection tracker (NULL if disabled) */
};
#undef T

extern struct Connection *
SocketPool_connections_allocate_array (size_t maxconns);

extern Connection_T *
SocketPool_connections_allocate_hash_table (Arena_T arena);

extern void SocketPool_connections_initialize_slot (struct Connection *conn);

extern int SocketPool_connections_alloc_buffers (Arena_T arena, size_t bufsize,
                                                 Connection_T conn);

extern Connection_T find_slot (SocketPool_T pool, const Socket_T socket);

extern Connection_T find_free_slot (const SocketPool_T pool);

extern int check_pool_full (const SocketPool_T pool);

extern void remove_from_free_list (SocketPool_T pool, Connection_T conn);

extern void return_to_free_list (SocketPool_T pool, Connection_T conn);

extern int prepare_free_slot (SocketPool_T pool, Connection_T conn);

extern void update_existing_slot (Connection_T conn, time_t now);

extern void insert_into_hash_table (SocketPool_T pool, Connection_T conn,
                                    Socket_T socket);

extern void increment_pool_count (SocketPool_T pool);

extern void initialize_connection (Connection_T conn, Socket_T socket,
                                   time_t now);

extern Connection_T find_or_create_slot (SocketPool_T pool, Socket_T socket,
                                         time_t now);

extern void remove_from_hash_table (SocketPool_T pool, Connection_T conn,
                                    Socket_T socket);

extern void SocketPool_connections_release_buffers (Connection_T conn);

extern void SocketPool_connections_reset_slot (Connection_T conn);

extern void decrement_pool_count (SocketPool_T pool);

extern void validate_saved_session (Connection_T conn);

extern Socket_T *SocketPool_cleanup_allocate_buffer (Arena_T arena,
                                                     size_t maxconns);

/**
 * socketpool_hash - Compute hash for socket (internal)
 * @socket: Socket to hash
 *
 * Returns: Hash value
 */
extern unsigned socketpool_hash (const Socket_T socket);

/* ============================================================================
 * Core Functions (from SocketPool-core.c)
 * ============================================================================ */

/**
 * safe_time - Get current time with error handling
 *
 * Returns: Current time
 * Raises: SocketPool_Failed on system error
 * Thread-safe: Yes
 */
extern time_t safe_time (void);

/* ============================================================================
 * Shared Range Enforcement (inline to avoid duplicate definitions)
 * ============================================================================ */

/**
 * socketpool_enforce_range - Clamp value to min/max bounds
 * @val: Value to clamp
 * @minv: Minimum allowed
 * @maxv: Maximum allowed
 *
 * Returns: Clamped value
 * Thread-safe: Yes - pure function
 */
static inline size_t
socketpool_enforce_range (size_t val, size_t minv, size_t maxv)
{
  return val < minv ? minv : (val > maxv ? maxv : val);
}

/**
 * socketpool_enforce_max_connections - Enforce the maximum connection limit
 * @maxconns: Requested maximum number of connections
 *
 * Returns: Enforced value (clamped to SOCKET_MAX_CONNECTIONS, min 1)
 */
static inline size_t
socketpool_enforce_max_connections (size_t maxconns)
{
  return socketpool_enforce_range (maxconns, 1, SOCKET_MAX_CONNECTIONS);
}

/**
 * socketpool_enforce_buffer_size - Enforce buffer size limits
 * @bufsize: Requested buffer size
 *
 * Returns: Enforced buffer size (clamped between min and max)
 */
static inline size_t
socketpool_enforce_buffer_size (size_t bufsize)
{
  return socketpool_enforce_range (bufsize, SOCKET_MIN_BUFFER_SIZE,
                                   SOCKET_MAX_BUFFER_SIZE);
}

#endif /* SOCKETPOOL_PRIVATE_H_INCLUDED */

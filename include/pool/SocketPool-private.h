#ifndef SOCKETPOOL_PRIVATE_H_INCLUDED
#define SOCKETPOOL_PRIVATE_H_INCLUDED

/**
 * @brief SocketPool-private.h - Private implementation details for SocketPool
 * @ingroup connection_mgmt
 *
 * Part of the Socket Library
 *
 * Contains internal structures, macros, and function declarations shared
 * across SocketPool implementation files. Not for public use.
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
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

#if SOCKET_HAS_TLS
#include "tls/SocketTLSContext.h"
#include <openssl/ssl.h>
#endif

/* ============================================================================
 * Hash Table Configuration
 * ============================================================================
 */

/** Hash table size - uses central configuration for consistency */
#define SOCKET_HASH_SIZE SOCKET_HASH_TABLE_SIZE

/* ============================================================================
 * Exception Handling
 * ============================================================================
 *
 * Thread-local exception for detailed error messages across all SocketPool
 * implementation files. Uses the centralized error buffer (socket_error_buf)
 * from SocketUtil.h for consistent error formatting.
 *
 * Benefits:
 * - Single thread-local error buffer (socket_error_buf) for all modules
 * - Consistent error formatting with SOCKET_ERROR_FMT/MSG macros
 * - Thread-safe exception raising
 * - Automatic logging integration via SocketLog_emit
 *
 * NOTE: For multi-file modules like SocketPool, we use an extern declaration
 * here and the actual definition in SocketPool-core.c. This allows all
 * implementation files to share the same thread-local exception variable.
 */

/**
 * @brief Thread-local exception for detailed error messages.
 * @ingroup connection_mgmt
 * Extern declaration - defined in SocketPool-core.c.
 */
#ifdef _WIN32
extern __declspec (thread) Except_T SocketPool_DetailedException;
#else
extern __thread Except_T SocketPool_DetailedException;
#endif

/**
 * @brief RAISE_POOL_ERROR - Raise exception with detailed error message
 * @ingroup connection_mgmt
 *
 * Creates a thread-local copy of the exception with reason from
 * socket_error_buf. Thread-safe: prevents race conditions when
 * multiple threads raise same exception type.
 */
#define RAISE_POOL_ERROR(exception)                                           \
  do                                                                          \
    {                                                                         \
      SocketPool_DetailedException = (exception);                             \
      SocketPool_DetailedException.reason = socket_error_buf;                 \
      RAISE (SocketPool_DetailedException);                                   \
    }                                                                         \
  while (0)

/**
 * @brief RAISE_POOL_MSG - Format error message (without errno) and raise in one step
 * @ingroup connection_mgmt
 *
 * Combines SOCKET_ERROR_MSG + RAISE_POOL_ERROR for cleaner code.
 * @note Thread-safe: Yes (uses thread-local buffers)
 * @ingroup connection_mgmt
 */
#define RAISE_POOL_MSG(exception, fmt, ...)                                   \
  do                                                                          \
    {                                                                         \
      SOCKET_ERROR_MSG (fmt, ##__VA_ARGS__);                                  \
      RAISE_POOL_ERROR (exception);                                           \
    }                                                                         \
  while (0)

/**
 * @brief RAISE_POOL_FMT - Format error message (with errno) and raise in one step
 * @ingroup connection_mgmt
 *
 * Combines SOCKET_ERROR_FMT + RAISE_POOL_ERROR for cleaner code.
 * @note Thread-safe: Yes (uses thread-local buffers)
 * @ingroup connection_mgmt
 */
#define RAISE_POOL_FMT(exception, fmt, ...)                                   \
  do                                                                          \
    {                                                                         \
      SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__);                                  \
      RAISE_POOL_ERROR (exception);                                           \
    }                                                                         \
  while (0)

/* ============================================================================
 * Connection Structure
 * ============================================================================
 */

struct Connection
{
  Socket_T socket;
  SocketBuf_T inbuf;
  SocketBuf_T outbuf;
  void *data;
  time_t last_activity;
  time_t created_at; /**< Connection creation timestamp (for age tracking) */
  int active;
  struct Connection *hash_next;
  struct Connection *free_next;
  SocketReconnect_T
      reconnect; /**< Auto-reconnection context (NULL if disabled) */
  char
      *tracked_ip; /**< Tracked IP for per-IP limiting (NULL if not tracked) */
#if SOCKET_HAS_TLS
  SocketTLSContext_T tls_ctx; /**< TLS context for this connection */
  int tls_handshake_complete; /**< TLS handshake state */
  SSL_SESSION *tls_session;   /**< Saved session for potential reuse */
  int last_socket_fd; /**< FD of last socket (for session persistence) */
#endif
};

typedef struct Connection *Connection_T;

/* ============================================================================
 * Async Connect Context Structure
 * ============================================================================
 */

/**
 * @brief AsyncConnectContext - Context for tracking async connect operations
 * @ingroup connection_mgmt
 *
 * Allocated from pool arena, linked in pool->async_ctx list.
 * Sockets in pending contexts must be freed when pool is freed.
 */
struct AsyncConnectContext
{
  SocketPool_T pool;                /**< Pool instance */
  Socket_T socket;                  /**< Socket being connected */
  Request_T req;          /**< DNS request handle */
  SocketPool_ConnectCallback cb;    /**< User callback */
  void *user_data;                  /**< User data for callback */
  struct AsyncConnectContext *next; /**< Next context in list */
};
typedef struct AsyncConnectContext *AsyncConnectContext_T;

/* ============================================================================
 * Pool Structure
 * ============================================================================
 */

#define T SocketPool_T
struct T
{
  struct Connection *connections; /**< Pre-allocated connection array */
  Connection_T *hash_table;       /**< Hash table for O(1) lookup */
  Connection_T free_list;         /**< Linked list of free slots */
  Socket_T *cleanup_buffer;       /**< Buffer for cleanup operations */
  size_t maxconns;                /**< Maximum connections */
  size_t bufsize;                 /**< Buffer size per connection */
  size_t count;                   /**< Active connection count */
  Arena_T arena;                  /**< Memory arena */
  pthread_mutex_t mutex;          /**< Thread safety mutex */
  SocketDNS_T dns;                /**< Internal DNS resolver (lazy init) */
  AsyncConnectContext_T
      async_ctx;              /**< Linked list of pending async connects */
  size_t async_pending_count; /**< Count of pending async connects (security
                                 limit) */

  /* Reconnection support */
  SocketReconnect_Policy_T
      reconnect_policy;  /**< Default reconnection policy */
  int reconnect_enabled; /**< 1 if default reconnection enabled */

  /* Rate limiting support */
  SocketRateLimit_T
      conn_limiter; /**< Connection rate limiter (NULL if disabled) */
  SocketIPTracker_T
      ip_tracker; /**< Per-IP connection tracker (NULL if disabled) */

  /* SYN flood protection */
  SocketSYNProtect_T
      syn_protect; /**< SYN flood protection (NULL if disabled) */

  /* Graceful shutdown (drain) state */
  _Atomic int state; /**< SocketPool_State (C11 atomic for lock-free reads) */
  int64_t drain_deadline_ms; /**< Monotonic deadline for forced shutdown */
  SocketPool_DrainCallback drain_cb; /**< Drain completion callback */
  void *drain_cb_data;               /**< User data for drain callback */

  /* Idle connection cleanup */
  time_t idle_timeout_sec;     /**< Idle timeout in seconds (0 = disabled) */
  int64_t last_cleanup_ms;     /**< Last cleanup timestamp (monotonic) */
  int64_t cleanup_interval_ms; /**< Interval between cleanup runs */

  /* Validation callback */
  SocketPool_ValidationCallback
      validation_cb;        /**< Connection validation callback */
  void *validation_cb_data; /**< User data for validation callback */

  /* Resize callback */
  SocketPool_ResizeCallback
      resize_cb;        /**< Pool resize notification callback */
  void *resize_cb_data; /**< User data for resize callback */

  /* Statistics tracking */
  uint64_t stats_total_added;     /**< Total connections added */
  uint64_t stats_total_removed;   /**< Total connections removed */
  uint64_t stats_total_reused;    /**< Total connections reused */
  uint64_t stats_health_checks;   /**< Total health checks performed */
  uint64_t stats_health_failures; /**< Total health check failures */
  uint64_t
      stats_validation_failures; /**< Total validation callback failures */
  uint64_t
      stats_idle_cleanups;     /**< Total connections cleaned up due to idle */
  int64_t stats_start_time_ms; /**< Statistics window start time */
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

extern void validate_saved_session (Connection_T conn, time_t now);

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
 * ============================================================================
 */

/**
 * safe_time - Get current time with error handling
 *
 * Returns: Current time
 * Raises: SocketPool_Failed on system error
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 */
extern time_t safe_time (void);

/* ============================================================================
 * Shared Range Enforcement (inline to avoid duplicate definitions)
 * ============================================================================
 */

/**
 * socketpool_enforce_range - Clamp value to min/max bounds
 * @val: Value to clamp
 * @minv: Minimum allowed
 * @maxv: Maximum allowed
 *
 * Returns: Clamped value
 * @note Thread-safe: Yes - pure function
 * @ingroup connection_mgmt
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

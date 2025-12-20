/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETPOOL_PRIVATE_H_INCLUDED
#define SOCKETPOOL_PRIVATE_H_INCLUDED

/**
 * @file SocketPool-private.h
 * @brief Private implementation details and internal structures for SocketPool
 * module.
 * @ingroup connection_mgmt
 * @internal
 *
 * NOT FOR PUBLIC USE** - Internal header shared across SocketPool source files
 * (SocketPool-*.c). Defines opaque structures, thread-local exceptions, helper
 * macros (RAISE_POOL_*), and utility functions for connection management,
 * hashing, and lifecycle operations.
 *
 * KEY COMPONENTS:
 * - struct Connection: Pre-allocated slot with socket, buffers, timestamps,
 * TLS/reconnect state
 * - struct AsyncConnectContext: Tracks pending DNS+connect operations
 * - struct SocketPool_T: Full pool state (connections array, hash table,
 * mutex, stats, etc.)
 * - Exception macros: RAISE_POOL_ERROR, RAISE_POOL_MSG, RAISE_POOL_FMT for
 * consistent error handling
 * - Hashing: socketpool_hash() using library-wide SOCKET_HASH_SIZE
 * - Utilities: Slot allocation/reset, buffer management, free list/hash table
 * ops
 *
 * USAGE GUIDELINES:
 * - Include only from SocketPool implementation files (.c in src/pool/)
 * - Use RAISE_POOL_* macros for exceptions with detailed errno/context
 * - All operations assume pool mutex protection (except atomic fields)
 * - Memory from pool arena; no manual free() for internal allocations
 * - Thread-local SocketPool_DetailedException defined in SocketPool-core.c
 *
 * DEPENDENCIES:
 * - Foundation (@ref foundation): Arena, Except, SocketConfig, SocketUtil
 * - Core I/O (@ref core_io): Socket, SocketBuf, SocketDNS
 * - Utilities (@ref utilities): SocketRateLimit, SocketIPTracker
 * - Security (@ref security): SocketSYNProtect (optional)
 * - Connection Mgmt (@ref connection_mgmt): SocketReconnect (optional)
 * - TLS (@ref security): SocketTLSContext (conditional on SOCKET_HAS_TLS)
 *
 * IMPLEMENTATION NOTES:
 * - Multi-file split: core.c (init/free), connections.c (add/remove/lookup),
 * etc.
 * - Hash table: FD-based with golden ratio multiplier for distribution
 * - Free list: Doubly-linked for O(1) allocation/deallocation
 * - Stats: Atomic counters for monitoring (total_added, removed, reused, etc.)
 * - Drain: Atomic state with monotonic deadlines for graceful shutdown
 *
 * @warning Direct use from application code undefined; may change without
 * notice.
 * @note Regenerate docs with `make doc` after changes to validate links.
 *
 * @see SocketPool.h for complete public API documentation and examples.
 * @see src/pool/ for split implementation files (core.c, connections.c,
 * drain.c, etc.).
 * @see docs/POOL.md (if exists) or README.md for architectural overview.
 * @see @ref connection_mgmt "Connection Management Group" for module
 * relationships.
 * @see Doxyfile for documentation generation configuration.
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
 * Logging Configuration
 * ============================================================================
 */

/**
 * @brief Default log component for all SocketPool implementation files.
 * @ingroup connection_mgmt
 *
 * Overrides SOCKET_LOG_COMPONENT from SocketUtil.h for consistent logging.
 * Each implementation file (.c) should not need to redefine this.
 */
#ifdef SOCKET_LOG_COMPONENT
#undef SOCKET_LOG_COMPONENT
#endif
#define SOCKET_LOG_COMPONENT "SocketPool"

/* ============================================================================
 * Mutex Convenience Macros
 * ============================================================================
 */

/**
 * @brief Acquire pool mutex.
 * @ingroup connection_mgmt
 * @param p Pool instance.
 *
 * Convenience macro for consistent mutex locking across implementation files.
 *
 * @see POOL_UNLOCK for releasing the mutex.
 * @see pthread_mutex_lock() for underlying operation.
 */
#define POOL_LOCK(p)                                                          \
  do                                                                          \
    {                                                                         \
      pthread_mutex_lock (&(p)->mutex);                                       \
    }                                                                         \
  while (0)

/**
 * @brief Release pool mutex.
 * @ingroup connection_mgmt
 * @param p Pool instance.
 *
 * Convenience macro for consistent mutex unlocking across implementation files.
 *
 * @see POOL_LOCK for acquiring the mutex.
 * @see pthread_mutex_unlock() for underlying operation.
 */
#define POOL_UNLOCK(p)                                                        \
  do                                                                          \
    {                                                                         \
      pthread_mutex_unlock (&(p)->mutex);                                     \
    }                                                                         \
  while (0)

/* ============================================================================
 * Hash Table Configuration
 * ============================================================================
 */

/**
 * @brief Alias for the library's central hash table size configuration.
 * @ingroup connection_mgmt
 * @details
 * Reuses @ref foundation::SOCKET_HASH_TABLE_SIZE (default: 1021, a prime
 * number) for consistent hash table sizing across modules like pools, polls,
 * DNS, and timers. This uniformity ensures predictable performance and
 * collision characteristics.
 *
 * Can be overridden at compile time via -DSOCKET_HASH_TABLE_SIZE=<value>.
 *
 * @note Prime table sizes minimize hash clustering and improve lookup
 * efficiency.
 * @warning Changing this may affect hash distribution; test thoroughly.
 *
 * @see SocketConfig.h::SOCKET_HASH_TABLE_SIZE for definition and rationale.
 * @see socketpool_hash() for SocketPool hash computation.
 * @see socket_util_hash_fd() and related functions in @ref utilities
 * "Utilities Module".
 * @see @ref foundation "Foundation Module" for core configs.
 * @see HASH_GOLDEN_RATIO constant in SocketUtil.h for hash multiplier.
 */
#define SOCKET_HASH_SIZE SOCKET_HASH_TABLE_SIZE

/* ============================================================================
 * Exception Handling
 * ============================================================================
 *
 * @brief Thread-local exception for detailed error messages.
 * @ingroup connection_mgmt
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
 *
 * Extern declaration - actual definition in SocketPool-core.c.
 * Uses shared socket_error_buf for consistent error formatting.
 *
 * @see RAISE_POOL_ERROR macro.
 * @see socket_error_buf in SocketUtil.h.
 * @see SocketPool_Failed exception type.
 */
#ifdef _WIN32
extern __declspec (thread) Except_T SocketPool_DetailedException;
#else
extern __thread Except_T SocketPool_DetailedException;
#endif

/**
 * @brief Raise exception with detailed error message.
 * @ingroup connection_mgmt
 *
 * Creates thread-local copy of exception with reason from socket_error_buf.
 * @threadsafe Prevents race conditions when multiple threads raise same
 * exception type. Used throughout SocketPool implementation.
 *
 * @see RAISE_POOL_MSG for formatted messages.
 * @see RAISE_POOL_FMT for errno-formatted messages.
 * @see SocketPool_Failed exception type.
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
 * @brief Format error message (without errno) and raise.
 * @ingroup connection_mgmt
 *
 * Combines SOCKET_ERROR_MSG + RAISE_POOL_ERROR for cleaner code.
 * @threadsafe Uses thread-local buffers.
 *
 * @see RAISE_POOL_FMT for errno-formatted messages.
 * @see RAISE_POOL_ERROR for direct exception raising.
 */
#define RAISE_POOL_MSG(exception, fmt, ...)                                   \
  do                                                                          \
    {                                                                         \
      SOCKET_ERROR_MSG (fmt, ##__VA_ARGS__);                                  \
      RAISE_POOL_ERROR (exception);                                           \
    }                                                                         \
  while (0)

/**
 * @brief Format error message (with errno) and raise.
 * @ingroup connection_mgmt
 *
 * Combines SOCKET_ERROR_FMT + RAISE_POOL_ERROR for cleaner code.
 * @threadsafe Uses thread-local buffers.
 *
 * @see RAISE_POOL_MSG for non-errno messages.
 * @see RAISE_POOL_ERROR for direct exception raising.
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

/**
 * @brief Internal structure representing a pooled connection slot.
 * @ingroup connection_mgmt
 * @details
 * Each instance manages a single socket connection with dedicated input/output
 * buffers, activity timestamps, user data, and optional advanced features
 * like auto-reconnection and TLS session persistence.
 *
 * CORE MANAGEMENT:
 * - Pre-allocated in fixed-size array (pool->connections) for predictable
 * memory
 * - Fast O(1) lookup via hash table (pool->hash_table) keyed on socket FD
 * - Free list (pool->free_list) for quick slot recycling
 * - Linked lists for hash collisions (hash_next) and free slots (free_next)
 *
 * STATE TRACKING:
 * - active flag distinguishes used vs free slots
 * - last_activity for idle timeout enforcement
 * - created_at for age-based cleanup and stats
 *
 * EXTENSIONS:
 * - reconnect: Optional SocketReconnect_T for automatic reconnection
 * - tracked_ip: Per-IP rate limiting via SocketIPTracker_T
 * - TLS fields: Context, handshake state, session reuse (conditional on
 * SOCKET_HAS_TLS)
 *
 * THREAD SAFETY: All modifications protected by pool->mutex. Readers should
 * acquire mutex or use atomic checks for count/state. Accessors in public API
 * handle locking transparently.
 *
 * LIFECYCLE:
 * - Initialized via SocketPool_connections_initialize_slot()
 * - Buffers allocated in SocketPool_connections_alloc_buffers()
 * - Added to pool via find_or_create_slot() / insert_into_hash_table()
 * - Removed via remove_from_hash_table() / SocketPool_connections_reset_slot()
 * - Buffers released in SocketPool_connections_release_buffers()
 *
 * @note Fields like hash_next/free_next are internal linking only; ignore for
 * app logic.
 * @warning Direct field access bypasses thread safety - use accessors or lock
 * pool.
 * @security TLS session reuse reduces handshake overhead but validate
 * saved_session via validate_saved_session() before reuse to prevent stale
 * sessions.
 *
 * @see SocketPool_T::connections for array allocation.
 * @see socketpool_hash() for FD-based hashing.
 * @see find_slot() / find_free_slot() for lookup/allocation logic.
 * @see SocketPool_add() / SocketPool_get() for public entry points.
 * @see SocketPool.h::Connection_T for public opaque interface.
 * @see @ref connection_mgmt "Connection Mgmt Module" for pooling patterns.
 * @see @ref connection_mgmt::SocketReconnect_T for reconnection integration.
 * @see @ref security::SocketTLSContext for TLS support.
 */
struct Connection
{
  Socket_T socket;      /**< Associated socket (NULL if free) */
  SocketBuf_T inbuf;    /**< Input buffer for reading data */
  SocketBuf_T outbuf;   /**< Output buffer for writing data */
  void *data;           /**< User data pointer */
  time_t last_activity; /**< Last activity timestamp for idle timeout */
  time_t created_at; /**< Connection creation timestamp (for age tracking) */
  int active;        /**< Non-zero if slot contains active connection */
  struct Connection *hash_next; /**< Next in hash table collision chain */
  struct Connection *free_next; /**< Next in free list (when inactive) */
  struct Connection *active_next; /**< Next in active connection list */
  struct Connection *active_prev; /**< Prev in active connection list */
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

/**
 * @brief Internal typedef for connection structure pointer.
 * @ingroup connection_mgmt
 *
 * Opaque externally; provides handle to managed connection state including
 * socket, buffers, timestamps, and optional TLS/reconnect contexts.
 * Access internal fields only within SocketPool implementation files.
 *
 * @note This typedef matches public Connection_T in SocketPool.h but includes
 * full struct definition here for implementation convenience.
 *
 * @see SocketPool.h::Connection_T for public opaque type documentation.
 * @see struct Connection for detailed field descriptions.
 * @see Connection_* accessor functions in SocketPool.h.
 * @see @ref connection_mgmt "Connection Mgmt Module" for usage patterns.
 */
typedef struct Connection *Connection_T;

/* ============================================================================
 * Async Connect Context Structure
 * ============================================================================
 */

/**
 * @brief Internal context structure for tracking asynchronous connect
 * operations.
 * @ingroup connection_mgmt
 *
 * Manages state for pending connections initiated via
 * SocketPool_connect_async(), which combines DNS resolution, socket
 * connection, and pool integration. Instances are allocated from the pool's
 * arena and chained in pool->async_ctx list.
 *
 * LIFECYCLE:
 * - Allocated in SocketPool_connect_async() with user callback and data
 * - DNS resolution started via SocketDNS_resolve() (req field)
 * - Socket created and connect() initiated upon DNS success
 * - Moved to active pool slot on successful connect, callback invoked
 * - Removed and freed on failure, timeout, or pool destruction
 * - Sockets in failed contexts are closed and freed during pool cleanup
 *
 * THREAD SAFETY: List operations protected by pool mutex. DNS callbacks
 * execute in worker threads; user SocketPool_ConnectCallback must be
 * thread-safe.
 *
 * MEMORY: All fields arena-allocated; no individual free() calls needed.
 *
 * @note Limit concurrent async connects via pool configuration to prevent
 * resource exhaustion.
 * @warning User callback runs in DNS worker thread context - avoid blocking
 * operations.
 *
 * @see SocketPool_connect_async() for public async connect initiation.
 * @see SocketPool_ConnectCallback for completion notification requirements.
 * @see SocketDNS.h::Request_T for DNS request handling (@ref dns).
 * @see AsyncConnectContext_T for opaque typedef.
 * @see SocketPool_free() for ensuring pending sockets are cleaned up.
 * @see SocketPool.h for overall connection pool API.
 * @see @ref connection_mgmt "Connection Management" for resilience patterns.
 * @see @ref dns "DNS Module" for asynchronous resolution details.
 */
struct AsyncConnectContext
{
  SocketPool_T pool; /**< Pool instance */
  Socket_T socket;   /**< Socket being connected */
  Request_T req;     /**< DNS resolution request (@ref dns::Request_T). Used to
                        track and retrieve results from async DNS lookup for host
                        resolution. @see SocketDNS_resolve() for initiating
                        resolution, SocketDNS_cancel() for aborting,
                        SocketDNS_getresult() for retrieving addrinfo results. */
  SocketPool_ConnectCallback cb;    /**< User callback */
  void *user_data;                  /**< User data for callback */
  struct AsyncConnectContext *next; /**< Next context in list */
};
/**
 * @brief Internal typedef for async connect context pointer.
 * @ingroup connection_mgmt
 *
 * Opaque handle for tracking asynchronous connection operations involving DNS
 * resolution, socket creation, and pool integration. Managed internally by
 * SocketPool during async connect lifecycle.
 *
 * @note Not exposed in public API; used only within SocketPool implementation.
 *
 * @see struct AsyncConnectContext for private fields.
 * @see SocketPool_connect_async() in SocketPool.h for public async API.
 * @see SocketPool-private.h for internal async connect details.
 */
typedef struct AsyncConnectContext *AsyncConnectContext_T;

/* ============================================================================
 * Pool Structure
 * ============================================================================
 */

/**
 * @brief Core internal structure defining the complete SocketPool state.
 * @ingroup connection_mgmt
 * @details
 * Comprehensive state container for connection pooling, including
 * pre-allocated slots, hash tables, rate limiters, SYN protection, drain
 * logic, and statistics. Designed for thread-safe concurrent access with
 * minimal contention.
 *
 * CORE STRUCTURES:
 * - connections[]: Fixed array of Connection slots (pre-allocated for
 * performance)
 * - hash_table[]: O(1) lookup by socket FD using socketpool_hash()
 * - free_list: Linked free slots for rapid recycling
 * - cleanup_buffer: Temp storage for bulk operations like idle cleanup
 *
 * SYNCHRONIZATION:
 * - mutex: pthread_mutex_t protects all mutable state except atomic fields
 * - state: _Atomic int for lock-free drain state reads (POOL_STATE_* enums)
 *
 * ASYNC OPERATIONS:
 * - dns: Lazy-init SocketDNS_T for async resolution in connect_async()
 * - async_ctx: Linked list of pending AsyncConnectContext_T
 * - async_pending_count: Security limit on concurrent async operations
 *
 * RESILIENCE FEATURES:
 * - reconnect_policy: Default policy for SocketReconnect integration
 * - conn_limiter: SocketRateLimit_T for global connection rate
 * - ip_tracker: SocketIPTracker_T for per-IP limits
 * - syn_protect: SocketSYNProtect_T for flood protection
 *
 * GRACEFUL SHUTDOWN (DRAIN):
 * - state: Atomic enum (RUNNING/DRAINING/STOPPED)
 * - drain_deadline_ms: Monotonic timer for force-stop after timeout
 * - drain_cb: Optional user notification on drain complete
 *
 * CLEANUP & MONITORING:
 * - idle_timeout_sec: Per-connection idle eviction
 * - last_cleanup_ms / cleanup_interval_ms: Periodic maintenance scheduling
 * - validation_cb: User-defined health checks before reuse
 * - resize_cb: Notification on pool capacity changes
 * - stats_*: Atomic counters for performance metrics
 * (added/removed/reused/etc.)
 * - stats_start_time_ms: Sliding window for rate calculations
 *
 * THREAD SAFETY:
 * - Mutex guards all operations except atomic state/count reads
 * - Accessors (public API) acquire/release mutex transparently
 * - Stats counters use atomic increments for concurrent updates
 * - DNS callbacks execute in worker threads (user must handle synchronization)
 *
 * MEMORY MANAGEMENT:
 * - arena: Root allocator; all internal allocations (buffers, lists, trackers)
 * from here
 * - No manual free(); arena_clear() or dispose() handles bulk cleanup
 * - Pre-warming allocates buffers proactively to reduce latency
 *
 * CONFIGURATION ENFORCEMENT:
 * - Limits clamped via socketpool_enforce_*() inline functions
 * - Compile-time overrides via SocketConfig.h defines
 *
 * @note Atomic state enables non-blocking checks for draining/stopped
 * conditions.
 * @warning Avoid long-held locks in callbacks; prefer quick operations or
 * defer work.
 * @security Rate limiters and trackers prevent DoS; configure conservatively
 * for prod.
 * @performance Hash table size (SOCKET_HASH_SIZE) impacts lookup speed; tune
 * if needed.
 *
 * @see #SocketPool_T for public opaque typedef (in SocketPool.h).
 * @see struct Connection for per-connection state.
 * @see socketpool_enforce_range() family for param validation.
 * @see SocketPool_new() / SocketPool_free() for lifecycle.
 * @see SocketPool_resize() / SocketPool_prewarm() for dynamic sizing.
 * @see SocketPool_cleanup() for idle management.
 * @see SocketPool_drain() for graceful shutdown.
 * @see SocketPool_setconnrate() / SocketPool_setmaxperip() for limits.
 * @see @ref connection_mgmt for module overview and patterns.
 * @see @ref foundation::Arena_T for memory model.
 * @see @ref utilities::SocketRateLimit_T for rate limiting details.
 */
#define T SocketPool_T
struct T
{
  /* Core data structures */
  struct Connection *connections; /**< Pre-allocated connection array */
  Connection_T *hash_table;       /**< Hash table for O(1) lookup */
  Connection_T free_list;         /**< Linked list of free slots */
  Connection_T active_head;       /**< Head of active connection list */
  Connection_T active_tail;       /**< Tail of active connection list */
  Socket_T *cleanup_buffer;       /**< Buffer for cleanup operations */
  size_t maxconns;                /**< Maximum connections */
  size_t bufsize;                 /**< Buffer size per connection */
  size_t count;                   /**< Active connection count */
  Arena_T arena;                  /**< Memory arena for all allocations */
  pthread_mutex_t mutex;          /**< Thread safety mutex */

  /* DNS and async operations */
  SocketDNS_T dns; /**< Internal DNS resolver (lazy init) */
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

  /* Pre-resize callback (called BEFORE realloc for pointer invalidation) */
  SocketPool_PreResizeCallback
      pre_resize_cb;        /**< Pre-resize notification callback */
  void *pre_resize_cb_data; /**< User data for pre-resize callback */

  /* Idle callback */
  SocketPool_IdleCallback
      idle_cb;        /**< Callback when connection becomes idle */
  void *idle_cb_data; /**< User data for idle callback */

  /* Health checking subsystem */
  struct SocketPoolHealth_T *health; /**< Health check context (NULL if disabled) */

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

/**
 * @brief Allocate and zero-initialize array of connection structures.
 * @ingroup connection_mgmt
 *
 * Pre-allocates fixed-size array of Connection structs for efficient pool slot
 * management. Uses direct system calloc() for large arrays to avoid arena
 * fragmentation and overhead. All slots are zero-initialized, ready for
 * SocketPool_connections_initialize_slot().
 *
 * @param[in] maxconns Number of Connection slots to allocate (enforced 1 to
 * SOCKET_MAX_CONNECTIONS).
 *
 * @return Pointer to allocated and zeroed array.
 *
 * @throws SocketPool_Failed if calloc() fails due to ENOMEM or system limits.
 *
 * @threadsafe Yes - no shared state, pure allocation function.
 *
 * @complexity O(maxconns) time and space - allocates and memset-zeros the
 * entire array.
 *
 *  Internal Usage Pattern
 *
 * @code
 * // Called during SocketPool_new() after parameter validation
 * TRY {
 *   pool->connections = SocketPool_connections_allocate_array(safe_maxconns);
 *   // Success: array allocated and zeroed
 * } EXCEPT(SocketPool_Failed) {
 *   // Handle allocation failure (e.g., log, propagate)
 *   RERAISE;  // Or clean up and return error
 * } END_TRY;
 * @endcode
 *
 *  Error Handling
 *
 * Allocation failure typically indicates:
 * - System memory exhaustion (ulimit -v exceeded)
 * - Process memory limits reached
 * - Kernel OOM killer intervention imminent
 *
 * @note Direct calloc() allocation - not managed by pool arena. Freed
 * explicitly with free() in SocketPool_free().
 * @warning Avoid calling with very large maxconns (>1M) without checking
 * system limits (e.g., via getrlimit(RLIMIT_AS)).
 * @warning Zero-initialization ensures safe default state but does not
 * initialize buffers or complex fields - use initialize_slot().
 *
 * @see socketpool_enforce_max_connections() for parameter clamping.
 * @see SocketPool_new() for full pool creation context.
 * @see SocketPool_connections_initialize_slot() for post-allocation slot setup
 * (links free list, etc.).
 * @see SocketPool_free() for explicit free() of this array.
 * @see calloc(3) for underlying POSIX allocation primitive.
 * @see @ref foundation::Arena_T for arena-based alternatives (used for other
 * components).
 */

/**
 * @brief Allocate and zero-initialize hash table array from arena.
 * @ingroup connection_mgmt
 *
 * Allocates fixed-size array of Connection_T* pointers for O(1) average-case
 * connection lookup. Uses arena-managed CALLOC for integration with pool's
 * memory lifecycle. All entries zero-initialized (NULL), ready for
 * insert_into_hash_table(). Table size fixed to SOCKET_HASH_SIZE (compile-time
 * prime for low collisions).
 *
 * @param[in] arena Arena_T for allocation (must not be NULL).
 *
 * @return Pointer to allocated and zeroed hash table array.
 *
 * @throws SocketPool_Failed if Arena_calloc() fails (Arena_Failed wrapped).
 * @throws Arena_Failed if arena has insufficient space (propagates through
 * wrapper).
 *
 * @threadsafe No - arena allocation not thread-safe without external
 * synchronization. Caller must ensure exclusive arena access or use
 * thread-local arenas.
 *
 * @complexity O(1) time and space - fixed-size allocation independent of pool
 * size.
 *
 *  Internal Usage Pattern
 *
 * @code
 * // Called during SocketPool_new() in allocate_pool_components()
 * TRY {
 *   pool->hash_table =
 * SocketPool_connections_allocate_hash_table(pool->arena);
 *   // Success: hash_table ready for insertions
 * } EXCEPT(SocketPool_Failed | Arena_Failed) {
 *   // Handle: log, cleanup partial allocations, propagate exception
 *   RERAISE;
 * } END_TRY;
 * @endcode
 *
 *  Allocation Details
 *
 * - Size: SOCKET_HASH_SIZE * sizeof(Connection_T*) (typically ~8KB for 1021
 * entries)
 * - Zero-initialized: All buckets NULL, no chaining needed initially
 * - Arena-managed: Freed automatically via Arena_clear/dispose in
 * SocketPool_free
 *
 * @note Fixed size at compile-time - override via -DSOCKET_HASH_SIZE=N (prime
 * recommended).
 * @warning Small table sizes increase collision chains, degrading to O(n)
 * worst-case lookup.
 * @warning Arena exhaustion may occur if pool creation coincides with high
 * memory pressure.
 *
 * @see SOCKET_HASH_SIZE in SocketConfig.h for configuration and rationale.
 * @see socketpool_hash() for FD-based hashing into table buckets.
 * @see insert_into_hash_table() / remove_from_hash_table() for chain
 * management.
 * @see find_slot() for traversal of collision chains.
 * @see @ref foundation::Arena_T::Arena_calloc() for underlying allocation (via
 * CALLOC macro).
 * @see @ref utilities::socket_util_hash_fd() for hash function implementation.
 */

/**
 * @brief Initialize a connection slot to default state.
 * @ingroup connection_mgmt
 * @param conn Connection structure to initialize.
 *
 * Zeroes all fields and sets up initial state for a connection slot.
 *
 * @see SocketPool_connections_reset_slot() for cleanup.
 * @see SocketPool_connections_allocate_array() for allocation.
 * @see find_free_slot() for finding available slots.
 */
extern void SocketPool_connections_initialize_slot (struct Connection *conn);

/**
 * @brief Allocate input/output buffers for connection.
 * @ingroup connection_mgmt
 * @param arena Memory arena for allocation.
 * @param bufsize Size of each buffer.
 * @param conn Connection to allocate buffers for.
 * @return 0 on success, -1 on allocation failure.
 *
 * Allocates SocketBuf_T instances for connection's input and output buffers.
 *
 * @see SocketPool_new() for buffer allocation.
 * @see SocketBuf_new() for buffer creation.
 * @see SocketPool_connections_release_buffers() for cleanup.
 * @see Connection_inbuf() and Connection_outbuf() for access.
 */
extern int SocketPool_connections_alloc_buffers (Arena_T arena, size_t bufsize,
                                                 Connection_T conn);

/**
 * @brief Find connection slot by socket (internal).
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param socket Socket to find.
 * @return Connection slot or NULL if not found.
 *
 * Performs O(1) hash table lookup to find existing connection.
 *
 * @see SocketPool_get() for public interface.
 * @see insert_into_hash_table() for insertion.
 * @see remove_from_hash_table() for removal.
 * @see socketpool_hash() for hash computation.
 */
extern Connection_T find_slot (SocketPool_T pool, const Socket_T socket);

/**
 * @brief Find first available free connection slot.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @return Free connection slot or NULL if pool is full.
 *
 * Scans free list to find available slot for new connections.
 *
 * @see SocketPool_add() for usage.
 * @see check_pool_full() for pool capacity checking.
 * @see remove_from_free_list() for slot activation.
 * @see return_to_free_list() for slot deactivation.
 */
extern Connection_T find_free_slot (const SocketPool_T pool);

/**
 * @brief Check if pool has reached maximum capacity.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @return Non-zero if pool is full, 0 if slots available.
 *
 * Fast check without acquiring locks.
 *
 * @see SocketPool_add() for capacity enforcement.
 */
extern int check_pool_full (const SocketPool_T pool);

/**
 * @brief Remove connection from free list.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param conn Connection to remove from free list.
 *
 * Updates free list pointers when slot becomes active.
 *
 * @see return_to_free_list() for reverse operation.
 */
extern void remove_from_free_list (SocketPool_T pool, Connection_T conn);

/**
 * @brief Return connection to free list.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param conn Connection to return to free list.
 *
 * Updates free list pointers when slot becomes inactive.
 *
 * @see remove_from_free_list() for reverse operation.
 */
extern void return_to_free_list (SocketPool_T pool, Connection_T conn);

/**
 * @brief Add connection to active list.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param conn Connection to add to active list.
 *
 * Appends connection to tail of active list for O(active_count) iteration.
 * Thread-safe: Call with mutex held.
 *
 * @see remove_from_active_list() for reverse operation.
 */
extern void add_to_active_list (SocketPool_T pool, Connection_T conn);

/**
 * @brief Remove connection from active list.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param conn Connection to remove from active list.
 *
 * Unlinks connection from active list in O(1) time using prev/next pointers.
 * Thread-safe: Call with mutex held.
 *
 * @see add_to_active_list() for reverse operation.
 */
extern void remove_from_active_list (SocketPool_T pool, Connection_T conn);

/**
 * @brief Prepare free slot for new connection.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param conn Free slot to prepare.
 * @return 0 on success, -1 on buffer allocation failure.
 *
 * Cleans up old connection state and allocates new buffers.
 *
 * @see initialize_connection() for connection setup.
 */
extern int prepare_free_slot (SocketPool_T pool, Connection_T conn);

/**
 * @brief Update existing connection slot activity.
 * @ingroup connection_mgmt
 * @param conn Connection slot to update.
 * @param now Current timestamp.
 *
 * Updates last activity timestamp for idle timeout tracking.
 *
 * @see SocketPool_get() for automatic updates.
 */
extern void update_existing_slot (Connection_T conn, time_t now);

/**
 * @brief Insert connection into hash table.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param conn Connection to insert.
 * @param socket Socket for hash computation.
 *
 * Inserts connection into hash table for O(1) lookup.
 *
 * @see remove_from_hash_table() for removal.
 * @see socketpool_hash() for hash computation.
 */
extern void insert_into_hash_table (SocketPool_T pool, Connection_T conn,
                                    Socket_T socket);

/**
 * @brief Increment active connection count.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 *
 * Thread-safe increment of pool's active connection counter.
 *
 * @see decrement_pool_count() for reverse operation.
 */
extern void increment_pool_count (SocketPool_T pool);

/**
 * @brief Initialize connection with socket and timestamp.
 * @ingroup connection_mgmt
 * @param conn Connection to initialize.
 * @param socket Socket for connection.
 * @param now Current timestamp.
 *
 * Sets up connection with socket, timestamps, and initial state.
 *
 * @see prepare_free_slot() for buffer allocation.
 */
extern void initialize_connection (Connection_T conn, Socket_T socket,
                                   time_t now);

/**
 * @brief Find existing connection or create new slot.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param socket Socket to find or add.
 * @param now Current timestamp.
 * @return Existing connection or new slot, NULL if pool full.
 *
 * Core function for SocketPool_get() and SocketPool_add().
 *
 * @see SocketPool_get() for lookup-only.
 * @see SocketPool_add() for add-only.
 */
extern Connection_T find_or_create_slot (SocketPool_T pool, Socket_T socket,
                                         time_t now);

/**
 * @brief Remove connection from hash table.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param conn Connection to remove.
 * @param socket Socket for hash computation.
 *
 * Removes connection from hash table during cleanup/removal.
 *
 * @see insert_into_hash_table() for insertion.
 */
extern void remove_from_hash_table (SocketPool_T pool, Connection_T conn,
                                    Socket_T socket);

/**
 * @brief Securely clear (zero) connection's input/output buffers.
 * @ingroup connection_mgmt
 *
 * Performs secure zeroing of buffer contents using SocketBuf_secureclear().
 * Used before buffer reuse (to erase sensitive data) or final disposal.
 * Does NOT deallocate memory (arena-managed) or NULL pointers - only clears
 * data. Callers typically follow with SocketBuf_release(&conn->inbuf) if
 * deallocating.
 *
 * @param[in,out] conn Connection whose buffers to securely clear.
 *
 * @threadsafe Yes - individual buffer operations are atomic/thread-safe.
 *
 * @complexity O(bufsize) - linearly scans and zeros buffer contents (inbuf +
 * outbuf).
 *
 *  Usage for Buffer Reuse
 *
 * @code
 * // Before reusing existing buffers in prepare_free_slot()
 * if (buffers_exist(conn)) {
 *   SocketPool_connections_release_buffers(conn);  // Zero sensitive data
 *   // Buffers now safe for reuse, pointers still valid
 * } else {
 *   SocketPool_connections_alloc_buffers(arena, bufsize, conn);
 * }
 * @endcode
 *
 *  Usage for Final Cleanup
 *
 * @code
 * // In SocketPool_connections_reset_slot() or removal
 * SocketPool_connections_release_buffers(conn);  // Zero data
 * SocketBuf_release(&conn->inbuf);               // NULL pointer
 * SocketBuf_release(&conn->outbuf);              // NULL pointer
 * @endcode
 *
 * @note Arena-managed buffers: Memory freed only on Arena_clear/dispose().
 * @warning Secure clearing prevents data leaks (e.g., passwords, tokens) on
 * reuse/disposal.
 * @warning Does not NULL pointers - use SocketBuf_release() for that (sets buf
 * = NULL).
 *
 * @see SocketBuf_secureclear() for underlying zeroing primitive (handles
 * circular buffer semantics).
 * @see SocketPool_connections_alloc_buffers() for buffer allocation.
 * @see SocketBuf_release() for pointer nullification (post-clearing).
 * @see SocketPool_connections_reset_slot() for full slot reset including
 * buffers.
 * @see @ref core_io::SocketBuf_T for buffer lifecycle management.
 */

/**
 * @brief Reset connection slot to clean state.
 * @ingroup connection_mgmt
 * @param conn Connection slot to reset.
 *
 * Clears all fields and prepares slot for reuse.
 *
 * @see SocketPool_connections_initialize_slot() for initial setup.
 */
extern void SocketPool_connections_reset_slot (Connection_T conn);

/**
 * @brief Decrement active connection count.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 *
 * Thread-safe decrement of pool's active connection counter.
 *
 * @see increment_pool_count() for reverse operation.
 */
extern void decrement_pool_count (SocketPool_T pool);

/**
 * @brief Validate TLS session for reuse.
 * @ingroup connection_mgmt
 * @param conn Connection with potential saved session.
 * @param now Current timestamp.
 *
 * Checks if saved TLS session is still valid for reuse.
 *
 * @see SocketPool_add() for session saving.
 */
extern void validate_saved_session (Connection_T conn, time_t now);

/**
 * @brief Allocate temporary buffer for bulk cleanup operations from arena.
 * @ingroup connection_mgmt
 *
 * Allocates array of Socket_T pointers sized to match pool's maxconns.
 * Used during SocketPool_cleanup() to collect idle connections for batch
 * processing. Arena-managed via CALLOC, zero-initialized (all NULL pointers).
 *
 * @param[in] arena Arena_T for allocation (must not be NULL).
 * @param[in] maxconns Pool's maximum connection count (determines buffer
 * size).
 *
 * @return Pointer to allocated and zeroed Socket_T* array.
 *
 * @throws SocketPool_Failed if Arena_calloc() fails (ENOMEM equivalent).
 * @throws Arena_Failed if insufficient arena space available.
 *
 * @threadsafe No - relies on non-thread-safe arena allocation.
 *
 * @complexity O(maxconns) time and space - linear in pool capacity.
 *
 *  Internal Usage Pattern
 *
 * @code
 * // Called in allocate_pool_components() during pool creation
 * pool->cleanup_buffer = SocketPool_cleanup_allocate_buffer(arena, maxconns);
 * // Later in SocketPool_cleanup():
 * size_t to_cleanup = 0;
 * for (size_t i = 0; i < pool->maxconns; ++i) {
 *   if (is_idle(&pool->connections[i])) {
 *     pool->cleanup_buffer[to_cleanup++] = pool->connections[i].socket;
 *   }
 * }
 * // Batch process/close sockets in cleanup_buffer[0..to_cleanup-1]
 * @endcode
 *
 *  Buffer Lifecycle
 *
 * - Purpose: Avoid realloc() during runtime cleanup scans
 * - Size: maxconns * sizeof(Socket_T*) (~8-64KB depending on arch)
 * - Zero-init: Ensures safe iteration (no dangling pointers)
 * - Arena-managed: Auto-freed on Arena_dispose() in SocketPool_free()
 *
 * @note Temporary work buffer - contents overwritten each cleanup cycle.
 * @warning Oversized pools consume unnecessary memory; tune via
 * SocketPool_resize().
 * @warning Arena pressure: Large pools may cause frequent Arena_calloc()
 * reallocations.
 *
 * @see SocketPool_cleanup() for buffer usage in idle connection eviction.
 * @see SocketPool_new() / allocate_pool_components() for allocation context.
 * @see SocketPool_free() for implicit cleanup via arena disposal.
 * @see @ref foundation::Arena_T::Arena_calloc() underlying mechanism (via
 * CALLOC).
 */

/**
 * @brief Compute hash for socket (internal).
 * @ingroup connection_mgmt
 * @param socket Socket_T to hash (must not be NULL).
 * @return unsigned hash value for hash table lookup.
 *
 * Uses golden ratio hash function for optimal distribution and collision
 * resistance. Hash is computed from socket file descriptor using
 * multiplication method.
 *
 * PERFORMANCE: O(1) constant time, optimized for cache performance.
 * DISTRIBUTION: Designed for low collision rate with typical FD ranges.
 *
 * @see SOCKET_HASH_SIZE for table size.
 * @see socket_util_hash_fd in SocketUtil.h for implementation.
 * @see insert_into_hash_table() for usage.
 * @see find_slot() for lookup.
 * @see HASH_GOLDEN_RATIO in SocketUtil.h for constants.
 * @see Socket_fd() for getting file descriptor.
 */
extern unsigned socketpool_hash (const Socket_T socket);

/* ============================================================================
 * Socket Close Helpers (Shared)
 * ============================================================================
 */

/**
 * @brief Safely close and remove socket from pool with error suppression.
 * @ingroup connection_mgmt
 *
 * Consolidated helper for safe socket closure during cleanup/resize operations.
 * Wraps SocketPool_remove() + Socket_free() in TRY/ELSE to suppress exceptions
 * (logged at DEBUG level instead). Prevents cascading failures during bulk
 * cleanup when sockets may be stale or already closed.
 *
 * Used to eliminate duplicate error-handling code in:
 * - close_single_socket() in SocketPool-connections.c
 * - close_socket_safe() in SocketPool-ops.c
 *
 * @param[in] pool Pool instance (for SocketPool_remove).
 * @param[in,out] socket_ptr Pointer to socket pointer (Socket_T*).
 *     Socket freed and pointer set to NULL on success.
 *     Unchanged on failure (logged only).
 * @param[in] context Optional context string for debug logging (e.g., "Cleanup",
 *     "Resize"). Pass NULL to omit context in log message.
 *
 * @threadsafe Yes - acquires pool mutex internally via SocketPool_remove().
 *
 * @complexity O(1) average for hash removal, O(1) for socket close.
 *
 *  Usage Example
 *
 * @code
 * // In SocketPool_cleanup() or similar
 * for (size_t i = 0; i < close_count; i++) {
 *   socketpool_close_socket_safe(pool, &sockets_to_close[i], "Cleanup");
 * }
 * @endcode
 *
 * @note Errors suppressed (not raised) to enable robust batch cleanup.
 * @warning Socket must be from the same pool instance, else remove fails.
 * @note Context string not copied; must remain valid during call.
 *
 * @see SocketPool_remove() for pool removal (may raise SocketPool_Failed).
 * @see Socket_free() for socket closure (may raise Socket_Failed).
 * @see SocketLog_emitf() for debug-level error logging.
 * @see close_single_socket() in SocketPool-connections.c (refactored to use this).
 * @see close_socket_safe() in SocketPool-ops.c (refactored to use this).
 */
static inline void
socketpool_close_socket_safe (SocketPool_T pool, Socket_T *socket_ptr,
                               const char *context)
{
  TRY
  {
    SocketPool_remove (pool, *socket_ptr);
    Socket_free (socket_ptr);
  }
  ELSE
  {
    /* Ignore SocketPool_Failed or Socket_Failed during cleanup -
     * socket may already be removed or closed */
    if (context)
      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "%s: socket close/remove failed (may be stale)", context);
    else
      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "Cleanup: socket close/remove failed (may be stale)");
  }
  END_TRY;
}

/* ============================================================================
 * Core Functions (from SocketPool-core.c)
 * ============================================================================
 */

/**
 * @brief Get current time with error handling.
 * @ingroup connection_mgmt
 * @return Current time as time_t.
 * @throws SocketPool_Failed on system error.
 * @threadsafe Yes.
 *
 * Safe wrapper around time() that raises exception on failure.
 * Used for connection timestamps and idle timeout tracking.
 *
 * @see Connection_lastactivity() for usage.
 * @see Connection_created_at() for creation timestamps.
 */
extern time_t safe_time (void);

/* ============================================================================
 * Shared Range Enforcement (inline to avoid duplicate definitions)
 * ============================================================================
 */

/**
 * @brief Clamp value to min/max bounds.
 * @ingroup connection_mgmt
 * @param val size_t value to clamp.
 * @param minv size_t minimum allowed value.
 * @param maxv size_t maximum allowed value.
 * @return Clamped value within bounds.
 * @threadsafe Yes - pure function, no side effects.
 *
 * Used for enforcing configuration limits on pool parameters.
 * Prevents invalid values from causing security issues or crashes.
 *
 * @see socketpool_enforce_max_connections().
 * @see socketpool_enforce_buffer_size().
 * @see SocketPool_new() for parameter validation.
 */
static inline size_t
socketpool_enforce_range (size_t val, size_t minv, size_t maxv)
{
  return val < minv ? minv : (val > maxv ? maxv : val);
}

/**
 * @brief Enforce maximum connection limit.
 * @ingroup connection_mgmt
 * @param maxconns Requested maximum number of connections.
 * @return Enforced value (clamped to SOCKET_MAX_CONNECTIONS, min 1).
 * @threadsafe Yes - pure function.
 *
 * @see SocketPool_resize() for runtime resizing.
 * @see SOCKET_MAX_CONNECTIONS for global limit.
 */
static inline size_t
socketpool_enforce_max_connections (size_t maxconns)
{
  return socketpool_enforce_range (maxconns, 1, SOCKET_MAX_CONNECTIONS);
}

/**
 * @brief Enforce buffer size limits.
 * @ingroup connection_mgmt
 * @param bufsize Requested buffer size.
 * @return Enforced buffer size (clamped between min and max).
 * @threadsafe Yes - pure function.
 *
 * @see SocketPool_set_bufsize() for runtime buffer size changes.
 * @see SOCKET_MIN_BUFFER_SIZE and SOCKET_MAX_BUFFER_SIZE.
 */
static inline size_t
socketpool_enforce_buffer_size (size_t bufsize)
{
  return socketpool_enforce_range (bufsize, SOCKET_MIN_BUFFER_SIZE,
                                   SOCKET_MAX_BUFFER_SIZE);
}

/* ============================================================================
 * Shared Inline Helpers
 * ============================================================================
 */

/**
 * @brief Overflow-safe millisecond addition with saturation.
 * @ingroup connection_mgmt
 * @param base Base time in milliseconds.
 * @param delta Delta to add in milliseconds.
 * @return base + delta, or INT64_MAX if overflow would occur.
 * @threadsafe Yes - pure function.
 *
 * Used for deadline calculations where overflow must saturate to
 * INT64_MAX rather than wrap around.
 */
static inline int64_t
pool_safe_add_ms (int64_t base, int64_t delta)
{
  if (delta > 0 && base > INT64_MAX - delta)
    return INT64_MAX;
  return base + delta;
}

/**
 * @brief Check if pool state is RUNNING (lock-free).
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @return Non-zero if pool is in RUNNING state.
 * @threadsafe Yes - uses C11 atomic acquire semantics.
 *
 * Lock-free state check for determining if pool is accepting connections.
 */
static inline int
pool_is_running (const SocketPool_T pool)
{
  return atomic_load_explicit (&pool->state, memory_order_acquire)
         == POOL_STATE_RUNNING;
}

/**
 * @brief Check if IP address is valid for tracking.
 * @ingroup connection_mgmt
 * @param ip IP address string (may be NULL).
 * @return Non-zero if IP is valid (non-NULL and non-empty).
 * @threadsafe Yes - pure function.
 */
static inline int
pool_is_valid_ip (const char *ip)
{
  return ip != NULL && ip[0] != '\0';
}

#endif /* SOCKETPOOL_PRIVATE_H_INCLUDED */

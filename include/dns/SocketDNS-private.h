/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDNS_PRIVATE_INCLUDED
#define SOCKETDNS_PRIVATE_INCLUDED

/**
 * @file SocketDNS-private.h
 * @brief Internal structures, enums, and prototypes for asynchronous DNS
 * resolver implementation.
 * @ingroup dns
 *
 * Defines private data structures, state enumerations, and internal function
 * prototypes for the thread-pool based DNS resolution module. Intended solely
 * for library maintainers. Applications must use public API in SocketDNS.h
 * exclusively.
 *
 * Core internal architecture:
 * - #SocketDNS_T: Resolver with arena, worker threads, request queue/hash,
 * sync primitives, completion pipe
 * - #SocketDNS_Request_T: Per-request state including hostname, callback,
 * result, timeout tracking
 * - RequestState enum: Lifecycle tracking (PENDING -> PROCESSING ->
 * COMPLETE/CANCELLED)
 * - Hash table (SOCKET_DNS_REQUEST_HASH_SIZE buckets) for O(1) request
 * lookup/removal
 * - Mutex-protected FIFO queue for pending requests
 * - Pipe FD for non-blocking completion notification to SocketPoll
 *
 * Dependencies:
 * - @ref foundation (Arena_T for memory, Except_T for errors)
 * - @ref core_io (SocketCommon.h for util, SocketUtil.h for hashing/timing)
 * - POSIX threads (pthread) and <netdb.h> for getaddrinfo()
 *
 * Security considerations:
 * - Deterministic pointer hashing mitigates collision attacks but monitor
 * max_pending
 * - Worker threads isolated; callbacks execute in worker context (no main
 * thread reentrancy)
 * - Timeouts prevent DoS from slow/broken DNS servers
 *
 * @see SocketDNS.h for public asynchronous API (resolve, pollfd, getresult).
 * @see src/dns/SocketDNS.c for public wrapper functions and exception setup.
 * @see src/dns/SocketDNS-internal.c for full implementation details.
 * @see @ref dns "DNS module overview" and @ref core_io "Core I/O group".
 * @see docs/ASYNC_IO.md for integration with event loops.
 * @warning INTERNAL USE ONLY - unstable ABI, may change without notice.
 * @warning Callback functions must be reentrant and fast; see
 * SocketDNS_Callback documentation.
 */

/* System headers */
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Project headers - Arena.h NOT included to avoid T macro conflicts.
 * Each .c file must include Arena.h before defining T. */
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include "socket/SocketCommon.h"

/**
 * @brief Opaque handle for a single DNS resolution request.
 * @ingroup dns
 *
 * Created by SocketDNS_resolve(), used to retrieve results, cancel, or via
 * callback. Lifetime managed by resolver; invalid after completion or
 * cancellation.
 * @see SocketDNS_resolve()
 * @see SocketDNS_cancel()
 * @see SocketDNS_getresult()
 */
typedef struct SocketDNS_Request_T SocketDNS_Request_T;

/**
 * @brief Forward declaration of Arena_T from core foundation module.
 * @ingroup foundation
 *
 * Used for arena-based memory allocation of requests and internal structures.
 * @see @ref foundation "Foundation module" for details.
 * @see Arena_new(), Arena_alloc() in include/core/Arena.h
 */
typedef struct Arena_T *Arena_T;

/**
 * @brief Completion callback type invoked when DNS resolution finishes.
 * @ingroup dns
 * @param req The original request handle (for identification).
 * @param result Resolution results as addrinfo linked list, or NULL on error.
 * @param error getaddrinfo() error code (0=success, see <netdb.h> for others).
 * @param data User data passed to SocketDNS_resolve().
 *
 * Called from worker thread context upon completion (success, error, or
 * timeout).
 * @note Executed in a dedicated DNS worker thread - NOT the thread that
 * submitted the request.
 * @note Must complete quickly; blocking stalls the worker pool.
 * @note Takes ownership of 'result'; free with freeaddrinfo() after use.
 * @note Do NOT call SocketDNS_free(dns) from callback (deadlock risk).
 * @warning No automatic synchronization; user must protect shared data.
 * @see SocketDNS_resolve() to submit request with callback.
 * @see SocketDNS_Callback safety notes in SocketDNS.h documentation.
 */
typedef void (*SocketDNS_Callback) (SocketDNS_Request_T *, struct addrinfo *,
                                    int, void *);

/*
 * =============================================================================
 * Internal Enumerations and Constants
 * =============================================================================
 */

/**
 * @brief Enumeration of DNS request lifecycle states.
 * @ingroup dns
 *
 * Defines the processing states for individual DNS resolution requests.
 * Requests transition linearly: REQ_PENDING → REQ_PROCESSING → (REQ_COMPLETE |
 * REQ_CANCELLED)
 *
 * State transitions are atomic under mutex protection to ensure consistency
 * across threads (submitters, workers, pollers). Used for:
 * - Queue management and worker assignment
 * - Timeout detection and forced completion
 * - Result availability checks
 * - Cancellation safety
 *
 *  State Transition Table
 *
 * | State       | Description                          | Transitions From |
 * Actions Available          |
 * |-------------|--------------------------------------|---------------------------|----------------------------|
 * | REQ_PENDING | Queued, waiting for worker           | SocketDNS_resolve()
 * | cancel, timeout check      | | REQ_PROCESSING | Worker executing
 * getaddrinfo()     | Worker dequeues           | no cancel (unsafe), timeout|
 * | REQ_COMPLETE | Result ready, callback pending      | getaddrinfo()
 * success/error| getresult, invoke callback | | REQ_CANCELLED | User
 * cancelled, no further action   | SocketDNS_cancel()        | geterror
 * (EAI_NONAME)      |
 *
 * @see SocketDNS_Request_T::state field for storage.
 * @see submit_dns_request() for PENDING insertion.
 * @see process_single_request() for PROCESSING → COMPLETE.
 * @see cancel_pending_request() for CANCELLED transition.
 * @see request_timed_out() for timeout handling.
 */
typedef enum
{
  REQ_PENDING, /**< Request enqueued, awaiting assignment to worker thread */
  REQ_PROCESSING, /**< Dequeued and actively being resolved by worker
                     (getaddrinfo active) */
  REQ_COMPLETE,   /**< Resolution complete; result/error stored, ready for
                     retrieval/callback */
  REQ_CANCELLED /**< Cancelled by user before processing; no result produced */
} RequestState;

/**
 * @brief Levels for partial cleanup during initialization failures.
 * @ingroup dns
 *
 * Defines cleanup scope for cleanup_on_init_failure() based on init progress.
 * Values correspond to initialization order to enable reverse-order resource
 * release. Used in TRY/EXCEPT blocks during SocketDNS_new() to ensure no leaks
 * on failure.
 *
 * @see initialize_dns_components()
 * @see cleanup_on_init_failure()
 * @see SocketDNS_new() constructor exception handling.
 */
/**
 * @brief Enum for DNS cleanup levels during partial failure recovery.
 * @ingroup dns
 * @details
 * Defines levels corresponding to initialization stages, enabling precise
 * resource cleanup on partial failure in SocketDNS_new().
 * Values match order: mutex -> conds -> pipe -> arena.
 * Used in TRY/EXCEPT for exception-safe initialization.
 *
 * @note Higher levels include cleanup for lower levels (reverse order).
 * @see SocketDNS_new() for usage in constructor.
 * @see cleanup_on_init_failure() for cleanup logic.
 * @see initialize_dns_components() for init sequence.
 */
enum DnsCleanupLevel
{
  DNS_CLEAN_NONE = 0, /**< No cleanup needed */
  DNS_CLEAN_MUTEX,    /**< Cleanup mutex only */
  DNS_CLEAN_CONDS,    /**< Cleanup condition variables and mutex */
  DNS_CLEAN_PIPE,     /**< Cleanup pipe, conditions, and mutex */
  DNS_CLEAN_ARENA     /**< Cleanup arena and all above */
};

/*
 * =============================================================================
 * Internal Structures
 * =============================================================================
 */

/**
 * @brief DNS resolution request structure.
 * @ingroup dns
 *
 * Represents a single DNS resolution request with all associated state.
 * Allocated from the resolver's arena and lives until result is retrieved
 * or request is cancelled.
 */
struct SocketDNS_Request_T
{
  char *host;                  /**< Hostname to resolve (arena-allocated) */
  int port;                    /**< Port number for service lookup */
  SocketDNS_Callback callback; /**< Completion callback (NULL for polling) */
  void *callback_data;         /**< User data passed to callback */
  RequestState state;          /**< Current request lifecycle state */
  struct addrinfo *result; /**< Resolution result (owned until retrieved) */
  int error;               /**< getaddrinfo() error code (0 on success) */
  struct SocketDNS_Request_T *queue_next; /**< Queue linked list pointer */
  struct SocketDNS_Request_T *hash_next;  /**< Hash table chain pointer */
  unsigned hash_value;                    /**< Cached hash for O(1) removal */
  int64_t submit_time_ms; /**< Monotonic timestamp (ms since boot) at submission for timeout calculation. Use Socket_get_monotonic_ms() for current time. */
  int timeout_override_ms;     /**< Per-request timeout (-1 = use default) */
  struct SocketDNS_T *dns_resolver; /**< Back-pointer to owning resolver */
};

/**
 * @brief DNS cache entry structure.
 * @ingroup dns
 *
 * Stores a cached DNS resolution result with TTL and LRU tracking.
 */
struct SocketDNS_CacheEntry
{
  char *hostname;          /**< Cached hostname key */
  struct addrinfo *result; /**< Cached addrinfo result (owned) */
  int64_t insert_time_ms;  /**< Monotonic time of insertion */
  int64_t last_access_ms;  /**< Monotonic time of last access (LRU) */
  struct SocketDNS_CacheEntry *hash_next; /**< Hash collision chain */
  struct SocketDNS_CacheEntry *lru_prev;  /**< LRU list prev pointer */
  struct SocketDNS_CacheEntry *lru_next;  /**< LRU list next pointer */
};

/**
 * @brief Async DNS resolver structure.
 * @ingroup dns
 *
 * Thread pool-based DNS resolver with queue management, hash table lookup,
 * and pipe-based completion signaling for integration with SocketPoll.
 *
 * SECURITY NOTE: The request hash table uses deterministic pointer-based
 * hashing via socket_util_hash_ptr(). While attackers cannot typically control
 * memory allocation addresses, a large number of concurrent requests could
 * theoretically cause hash collisions. This is mitigated by:
 * - max_pending limit (default SOCKET_DNS_MAX_PENDING = 1000)
 * - Hash table size is prime (SOCKET_DNS_REQUEST_HASH_SIZE = 1021)
 * - Worst case is O(n) lookup per bucket, not a security vulnerability
 */
struct SocketDNS_T
{
  Arena_T arena;      /**< Arena for request/hostname allocation */
  pthread_t *workers; /**< Worker thread array (arena-allocated) */
  int num_workers;    /**< Number of worker threads */
  struct SocketDNS_Request_T *queue_head; /**< Request queue FIFO head */
  struct SocketDNS_Request_T *queue_tail; /**< Request queue FIFO tail */
  size_t queue_size;                      /**< Current pending request count */
  size_t max_pending;                     /**< Queue capacity limit */
  struct SocketDNS_Request_T *request_hash[SOCKET_DNS_REQUEST_HASH_SIZE];
  /**< Hash table for O(1) request lookup */
  pthread_mutex_t mutex;      /**< Protects all mutable state */
  pthread_cond_t queue_cond;  /**< Signals workers when work available */
  pthread_cond_t result_cond; /**< Signals waiters when result ready */
  int shutdown;               /**< Shutdown flag (1 = shutting down) */
  int pipefd[2];              /**< Completion pipe [0]=read, [1]=write */
  int request_timeout_ms;     /**< Default timeout (0 = no timeout) */

  /* DNS Cache */
  struct SocketDNS_CacheEntry *cache_hash[SOCKET_DNS_CACHE_HASH_SIZE];
  /**< Cache hash table for O(1) lookup */
  struct SocketDNS_CacheEntry *cache_lru_head; /**< LRU list head (most recent)
                                                */
  struct SocketDNS_CacheEntry *cache_lru_tail; /**< LRU list tail (oldest) */
  size_t cache_size;       /**< Current number of cached entries */
  size_t cache_max_entries; /**< Maximum cache entries (0 = disabled) */
  int cache_ttl_seconds;   /**< TTL for cached entries (0 = disabled) */
  uint64_t cache_hits;     /**< Cache hit counter */
  uint64_t cache_misses;   /**< Cache miss counter */
  uint64_t cache_evictions; /**< Eviction counter */
  uint64_t cache_insertions; /**< Insertion counter */

  /* DNS Configuration */
  int prefer_ipv6;         /**< 1 = prefer IPv6, 0 = prefer IPv4 */
  char **custom_nameservers; /**< Custom nameserver list (NULL = use system) */
  size_t nameserver_count;  /**< Number of custom nameservers */
  char **search_domains;   /**< Custom search domains (NULL = use system) */
  size_t search_domain_count; /**< Number of search domains */
};

/* Internal macros - use centralized constant */
#define COMPLETION_SIGNAL_BYTE SOCKET_DNS_COMPLETION_SIGNAL_BYTE

/**
 * @brief Signal completion and wake waiters.
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Consolidates repeated signal_completion + pthread_cond_broadcast pattern.
 */
#define SIGNAL_DNS_COMPLETION(dns)                                            \
  do                                                                          \
    {                                                                         \
      signal_completion (dns);                                                \
      pthread_cond_broadcast (&(dns)->result_cond);                           \
    }                                                                         \
  while (0)

/**
 * @brief Sanitize timeout value (negative -> 0).
 * @ingroup dns
 * @param timeout_ms Timeout in milliseconds.
 * @return 0 if negative, otherwise original value.
 */
#define SANITIZE_TIMEOUT_MS(timeout_ms) ((timeout_ms) < 0 ? 0 : (timeout_ms))

/* ==================== Mutex-Protected Field Access Macros ==================== */

/**
 * @brief Thread-safe getter for int field with mutex protection.
 * @ingroup dns
 * @param dns DNS resolver instance
 * @param field Field name to read
 *
 * Returns field value with proper mutex locking/unlocking.
 * Reduces boilerplate in SocketDNS_gettimeout, SocketDNS_get_prefer_ipv6, etc.
 *
 * Usage: int timeout = DNS_LOCKED_INT_GETTER(dns, request_timeout_ms);
 */
#define DNS_LOCKED_INT_GETTER(dns, field)                                     \
  ({                                                                          \
    int _value;                                                               \
    pthread_mutex_lock (&(dns)->mutex);                                       \
    _value = (dns)->field;                                                    \
    pthread_mutex_unlock (&(dns)->mutex);                                     \
    _value;                                                                   \
  })

/**
 * @brief Thread-safe getter for size_t field with mutex protection.
 * @ingroup dns
 * @param dns DNS resolver instance
 * @param field Field name to read
 *
 * Returns field value with proper mutex locking/unlocking.
 * Reduces boilerplate in SocketDNS_getmaxpending and similar functions.
 *
 * Usage: size_t max = DNS_LOCKED_SIZE_GETTER(dns, max_pending);
 */
#define DNS_LOCKED_SIZE_GETTER(dns, field)                                    \
  ({                                                                          \
    size_t _value;                                                            \
    pthread_mutex_lock (&(dns)->mutex);                                       \
    _value = (dns)->field;                                                    \
    pthread_mutex_unlock (&(dns)->mutex);                                     \
    _value;                                                                   \
  })

/**
 * @brief Thread-safe setter for int field with mutex protection.
 * @ingroup dns
 * @param dns DNS resolver instance
 * @param field Field name to write
 * @param value Value to set
 *
 * Sets field value with proper mutex locking/unlocking.
 * Reduces boilerplate in SocketDNS_settimeout, SocketDNS_prefer_ipv6, etc.
 *
 * Usage: DNS_LOCKED_INT_SETTER(dns, request_timeout_ms, new_timeout);
 */
#define DNS_LOCKED_INT_SETTER(dns, field, value)                              \
  do                                                                          \
    {                                                                         \
      pthread_mutex_lock (&(dns)->mutex);                                     \
      (dns)->field = (value);                                                 \
      pthread_mutex_unlock (&(dns)->mutex);                                   \
    }                                                                         \
  while (0)

/* Thread-local exception - extern declaration (defined in SocketDNS.c) */
extern const Except_T SocketDNS_Failed;

/* NOTE: Error raising uses SOCKET_RAISE_MSG/FMT directly (combined
 * format+raise). Each .c file that raises exceptions must include
 * SOCKET_DECLARE_MODULE_EXCEPTION. See SocketDNS.c and SocketDNS-internal.c
 * for the pattern. */

/*
 * =============================================================================
 * Forward Declarations - SocketDNS-internal.c
 *
 * Internal implementation functions for initialization, synchronization,
 * cleanup, request management, timeout handling, and worker threads.
 * =============================================================================
 */

/* Initialization and allocation */

/**
 * @brief Allocate and zero-initialize DNS resolver structure from heap memory.
 * @ingroup dns
 *
 * Performs calloc(1, sizeof(struct SocketDNS_T)) for zero-initialization of
all fields.
 * Used during SocketDNS_new() bootstrap before arena allocation.
 * Caller must subsequently call initialize_dns_fields() and other init
functions.
 *
 * @return Pointer to allocated and zeroed SocketDNS_T instance.
 *
 * @throws SocketDNS_Failed on memory allocation failure (calloc failure).
 *
 * @threadsafe No - intended for single-threaded initialization in
SocketDNS_new().
 *
 *  Usage Example
 *
 * @code{.c}
 * struct SocketDNS_T *dns = allocate_dns_resolver();
 * if (dns == NULL) {

extern struct SocketDNS_T * allocate_dns_resolver (void);
 *     // Handle allocation failure (ENOMEM)
 *     RAISE(SocketDNS_Failed);
 * }
 * TRY {
 *     initialize_dns_fields(dns);
 *     initialize_dns_components(dns);

extern void initialize_dns_components (struct SocketDNS_T *dns);
 *     // Success: dns ready for use
 * } EXCEPT(SocketDNS_Failed) {
 *     cleanup_on_init_failure(dns, DNS_CLEAN_NONE);  // Or appropriate level
 *     free(dns);
 *     RAISE;
 * } END_TRY;
 * @endcode
 *
 * @note Heap allocation (not arena); arena is initialized later for requests.
 * Caller owns the pointer until cleanup_on_init_failure() or SocketDNS_free().
 *
 * @complexity O(1) - single calloc() call.
 *
 * @warning Do not use directly; part of internal SocketDNS_new()
implementation.
 * Applications must use public SocketDNS_new() API.
 *
 * @see initialize_dns_fields() for field initialization.
 * @see initialize_dns_components() for component setup (threads, sync
primitives).

extern void initialize_dns_components (struct SocketDNS_T *dns);
 * @see cleanup_on_init_failure() for error cleanup.
 * @see SocketDNS_new() public constructor that orchestrates this allocation.
 */

/**
 * @brief Initialize basic DNS resolver fields to safe default values.
 * @ingroup dns
 *
 * Sets all fields in the DNS resolver structure to safe defaults:
 * - NULL for pointers (arena, workers, queue pointers, hash table entries)
 * - 0/1 for counters and flags (num_workers, queue_size, shutdown, etc.)
 * - Default values for configurable limits (max_pending, timeout)
 *
 * This ensures the structure is in a consistent state before component
 * initialization (mutex, pipe, threads). Zero-initialization from calloc
 * is supplemented with explicit defaults for clarity and future-proofing.
 *
 * @param[in,out] dns Pre-allocated DNS resolver structure (from
allocate_dns_resolver()).
 *
 * @threadsafe No - called during single-threaded initialization.
 *
 *  Usage Example
 *
 * @code{.c}
 * struct SocketDNS_T *dns = allocate_dns_resolver();
 * TRY {
 *     initialize_dns_fields(dns);  // Set defaults

extern void initialize_dns_fields (struct SocketDNS_T *dns);
 *     // Now safe to call initialize_dns_components(dns)
 * } EXCEPT(SocketDNS_Failed) {
 *     // Minimal cleanup needed (already zeroed)
 * } END_TRY;
 * @endcode
 *
 * @note Explicitly sets defaults even after calloc() for code clarity
 * and to handle future field additions without relying on zero-init.
 *
 * @complexity O(1) - direct field assignments, no loops or allocations.
 *
 * @see allocate_dns_resolver() for structure allocation.
 * @see initialize_dns_components() next step after fields init.
 * @see reset_dns_state() for symmetric reset during cleanup.
 * @see SocketDNS_new() orchestrating function.
 */

/**
 * @brief Initialize core DNS resolver components including arena, sync
 * primitives, pipe, and threads.
 * @ingroup dns
 *
 * Orchestrates the complete setup of resolver internals:
 * 1. Arena allocation for request structures and hostnames
 * 2. Synchronization primitives (recursive mutex + 2 condition vars)
 * 3. Non-blocking completion pipe for event loop integration
 * 4. Worker thread pool creation (SOCKET_DNS_THREAD_COUNT threads)
 *
 * Uses TRY/EXCEPT blocks internally for exception-safe partial failure
 * recovery. Cleanup levels track init progress for precise resource release on
 * errors.
 *
 * @param[in,out] dns Pre-allocated and field-initialized DNS resolver (from
 * allocate_dns_resolver() + initialize_dns_fields()).
 *
 * @throws SocketDNS_Failed on:
 * - Arena_new() failure (ENOMEM)
 * - pthread_mutex_init() / pthread_cond_init() failure (EAGAIN, ENOMEM)
 * - pipe() or socketpair() failure for completion signaling (EMFILE,
 * EAFNOSUPPORT)
 * - pthread_create() failure for workers (EAGAIN, EINVAL, EMFILE, EPERM)
 *
 * @threadsafe No - single-threaded initialization phase only.
 *
 *  Usage Example
 *
 * @code{.c}
 * struct SocketDNS_T *dns = allocate_dns_resolver();
 * enum DnsCleanupLevel cleanup_level = DNS_CLEAN_NONE;
 * TRY {
 *     initialize_dns_fields(dns);
 *     cleanup_level = DNS_CLEAN_MUTEX;
 *     initialize_synchronization(dns);  // Or direct calls
 *     cleanup_level = DNS_CLEAN_PIPE;
 *     initialize_pipe(dns);
 *     cleanup_level = DNS_CLEAN_ARENA;
 *     create_worker_threads(dns);
 *     start_dns_workers(dns);
 *     // Full init complete - return dns to SocketDNS_new()
 * } EXCEPT(SocketDNS_Failed) {
 *     cleanup_on_init_failure(dns, cleanup_level);
 *     free(dns);
 *     RAISE;
 * } END_TRY;
 * @endcode
 *
 * @note Recursive mutex allows nested locking during init/cleanup.
 * @note Pipe FD [0] is pollfd for reading completions; [1] for writing
 * signals.
 * @note Worker threads start in suspended state until start_dns_workers().
 *
 * @complexity O(n) where n = number of worker threads (typically small, ~4-8).
 *
 * @warning Partial failures cleaned up automatically; do not reuse partially
 * init dns.
 * @warning Thread creation may fail under resource exhaustion (ulimit -u).
 *
 * @pre dns->arena == NULL, dns->workers == NULL, dns->mutex uninitialized,
 * etc.
 * @see cleanup_on_init_failure() for symmetric error handling.
 * @see create_worker_threads() for thread spawning details.
 * @see initialize_synchronization() / initialize_pipe() sub-components.
 * @see SocketDNS_new() public API entry point.
 * @see docs/ASYNC_IO.md for async integration patterns.
 */

/**
 * @brief Configure pthread attributes for DNS worker threads.
 * @ingroup dns
 *
 * Sets up thread attributes for detached operation with default stack size
 * and scheduling policy. Ensures workers run independently without join
 * requirements during shutdown.
 *
 * Specific settings:
 * - Detached state: PTHREAD_CREATE_DETACHED (no pthread_join needed)
 * - Inherit scheduler: PTHREAD_EXPLICIT_SCHED not set (inherits parent)
 * - Default stack size and guards (platform defaults)
 *
 * @param[in,out] attr Pointer to pthread_attr_t structure to configure.
 *     Must be initialized (via pthread_attr_init) before call.
 *     Modified in place with worker-specific attributes.
 *
 * @return Void - raises SocketDNS_Failed on pthread_attr_* failure (rare).
 *     Implementation uses TRY/EXCEPT internally.
 *
 * @throws SocketDNS_Failed if pthread_attr_setdetachstate() or other attr
 * calls fail.
 *
 * @threadsafe Yes - reentrant, modifies local attr structure only.
 *
 *  Usage Example
 *
 * @code{.c}
 * pthread_attr_t attr;
 * TRY {
 *     pthread_attr_init(&attr);
 *     setup_thread_attributes(&attr);
 *     // Now attr is ready for pthread_create()
 *     int ret = pthread_create(&thread_id, &attr, worker_thread, dns);
 *     if (ret != 0) RAISE_FMT(SocketDNS_Failed, "pthread_create failed: %s",
 * strerror(ret)); } EXCEPT(SocketDNS_Failed) {
 *     // Handle error
 * } FINALLY {
 *     pthread_attr_destroy(&attr);
 * } END_TRY;
 * @endcode
 *
 * @complexity O(1) - fixed number of pthread_attr_* calls.
 *
 * @note Detached threads simplify shutdown; no explicit joins required.
 * @note Defaults to platform scheduler policy (SCHED_OTHER typically).
 *
 * @warning Caller must pthread_attr_destroy(&attr) after use, even on failure.
 * Caller must pthread_attr_init(&attr) before calling this function.
 *
 * @see create_single_worker_thread() for using configured attributes.
 * @see create_worker_threads() for multi-thread creation.
 * @see worker_thread() thread entry point.
 * @see SocketDNS_new() high-level initialization.
 */

/**
 * @brief Create a single worker thread.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param thread_index Index of thread to create (0-based).
 * @return 0 on success, errno on failure.
 *
 * Creates one worker thread with proper attributes and error handling.
 */
extern int create_single_worker_thread (struct SocketDNS_T *dns,
                                        int thread_index);

/**
 * @brief Spawn the configured number of DNS worker threads.
 * @ingroup dns
 * @param dns DNS resolver instance (with num_workers set).
 * @throws SocketDNS_Failed if pthread_create() fails for any thread (ENOMEM,
 * etc.).
 *
 * Creates dns->num_workers (default SOCKET_DNS_THREAD_COUNT) detached worker
 * threads. Each thread runs worker_thread() loop until shutdown. Threads are
 * stored in dns->workers array (arena-allocated).
 *
 * @note Threads are created detached with default scheduling attributes.
 * @note Partial success: some threads may start before failure; cleanup
 * handles join.
 * @threadsafe Conditional - must be called under single thread during init.
 * @see setup_thread_attributes() for thread config.
 * @see create_single_worker_thread() low-level single thread creation.
 * @see worker_thread() entry point for each thread.
 * @see shutdown_workers() to stop all threads.
 */
extern void create_worker_threads (struct SocketDNS_T *dns);

/**
 * @brief Start DNS worker threads (transition from initialization to running).
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Signals workers to begin processing requests from the queue.
 */
extern void start_dns_workers (struct SocketDNS_T *dns);

/* Synchronization primitives */

/**
 * @brief Initialize the main mutex protecting DNS resolver state.
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Creates a recursive mutex for protecting all mutable resolver state.
 */
extern void initialize_mutex (struct SocketDNS_T *dns);

/**
 * @brief Initialize condition variable for queue empty/full signaling.
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Creates condition variable used to wake worker threads when requests arrive.
 */
extern void initialize_queue_condition (struct SocketDNS_T *dns);

/**
 * @brief Initialize condition variable for result availability signaling.
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Creates condition variable used to wake polling threads when results
 * complete.
 */
extern void initialize_result_condition (struct SocketDNS_T *dns);

/**
 * @brief Initialize all synchronization primitives (mutex + conditions).
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Calls initialize_mutex(), initialize_queue_condition(), and
 * initialize_result_condition().
 */
extern void initialize_synchronization (struct SocketDNS_T *dns);

/**
 * @brief Create pipe for completion signaling to event loops.
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Creates a pipe that can be polled for DNS completion events.
 * Used for integration with SocketPoll.
 *
 * @see @ref event_system::SocketPoll "SocketPoll" for event multiplexing.
 * @see SocketDNS_pollfd() for public API access to this pipe.
 */
extern void create_completion_pipe (struct SocketDNS_T *dns);

/**
 * @brief Set completion pipe to non-blocking mode.
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Ensures pipe reads/writes don't block, preventing deadlocks.
 */
extern void set_pipe_nonblocking (struct SocketDNS_T *dns);

/**
 * @brief Initialize completion pipe (create + configure).
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Calls create_completion_pipe() and set_pipe_nonblocking().
 */
extern void initialize_pipe (struct SocketDNS_T *dns);

/* Cleanup and shutdown */

/**
 * @brief Clean up mutex and condition variables.
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Destroys mutex and condition variables. Safe to call multiple times.
 */
extern void cleanup_mutex_cond (struct SocketDNS_T *dns);

/**
 * @brief Clean up completion pipe.
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Closes pipe file descriptors and drains any pending data.
 */
extern void cleanup_pipe (struct SocketDNS_T *dns);

/**
 * @brief Clean up resources based on initialization failure level.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param cleanup_level How much has been initialized (cleanup level).
 *
 * Used during initialization failure to clean up partially initialized state.
 * Cleans up resources in reverse order of initialization.
 */
extern void cleanup_on_init_failure (struct SocketDNS_T *dns,
                                     enum DnsCleanupLevel cleanup_level);

/**
 * @brief Signal worker threads to shut down.
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Sets shutdown flag and broadcasts to wake all waiting threads.
 */
extern void shutdown_workers (struct SocketDNS_T *dns);

/**
 * @brief Drain all pending completion signals from pipe.
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Reads all available bytes from completion pipe to clear pending signals.
 */
extern void drain_completion_pipe (struct SocketDNS_T *dns);

/**
 * @brief Reset DNS resolver state to uninitialized values.
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Clears all pointers and resets counters. Called during destruction.
 */
extern void reset_dns_state (struct SocketDNS_T *dns);

/**
 * @brief Destroy all DNS resolver resources.
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Calls all cleanup functions in proper order. Safe to call on partially
 * initialized instances.
 */
extern void destroy_dns_resources (struct SocketDNS_T *dns);

/**
 * @brief Free a linked list of DNS requests.
 * @ingroup dns
 * @param head Head of request list to free.
 * @param use_hash_next Whether to use hash_next (1) or queue_next (0) for
 * traversal.
 *
 * Frees all requests in the list and their associated memory.
 */
extern void free_request_list (struct SocketDNS_Request_T *head,
                               int use_hash_next);

/**
 * @brief Free all requests currently in the processing queue.
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Frees requests from queue_head/queue_tail linked list.
 */
extern void free_queued_requests (struct SocketDNS_T *dns);

/**
 * @brief Free all requests currently in the hash table.
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Frees requests from all hash table buckets.
 */
extern void free_hash_table_requests (struct SocketDNS_T *dns);

/**
 * @brief Free all pending and completed DNS requests.
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Calls free_queued_requests() and free_hash_table_requests().
 */
extern void free_all_requests (struct SocketDNS_T *dns);

/* Request allocation and queue management */

/**
 * @brief Compute hash value for request pointer.
 * @ingroup dns
 * @param req Request to hash.
 * @return Hash value for hash table lookup.
 *
 * Uses socket_util_hash_ptr() for deterministic hashing of request pointers.
 *
 * @see @ref foundation::SocketUtil "SocketUtil" for hash function utilities.
 */
extern unsigned request_hash_function (const struct SocketDNS_Request_T *req);

/**
 * @brief Allocate uninitialized request structure from resolver arena.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @return Newly allocated request structure.
 *
 * Allocates memory for request structure. Fields must be initialized before
 * use.
 */
extern struct SocketDNS_Request_T *
allocate_request_structure (struct SocketDNS_T *dns);

/**
 * @brief Allocate and copy hostname string for request.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request to store hostname in.
 * @param host Hostname string to copy.
 * @param host_len Length of hostname string.
 *
 * Allocates hostname buffer from arena and copies host string.
 */
extern void allocate_request_hostname (struct SocketDNS_T *dns,
                                       struct SocketDNS_Request_T *req,
                                       const char *host, size_t host_len);

/**
 * @brief Initialize request fields after allocation.
 * @ingroup dns
 * @param req Request to initialize.
 * @param port Port number for resolution.
 * @param callback Completion callback (NULL for polling).
 * @param data User data for callback.
 *
 * Sets all request fields except host (which is set separately).
 */
extern void initialize_request_fields (struct SocketDNS_Request_T *req,
                                       int port, SocketDNS_Callback callback,
                                       void *data);

/**
 * @brief Allocate and initialize complete DNS request.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param host Hostname to resolve.
 * @param host_len Length of hostname.
 * @param port Port number.
 * @param cb Completion callback.
 * @param data User callback data.
 * @return Fully initialized request structure.
 *
 * Combines allocation, hostname copying, and field initialization.
 */
extern struct SocketDNS_Request_T *
allocate_request (struct SocketDNS_T *dns, const char *host, size_t host_len,
                  int port, SocketDNS_Callback cb, void *data);

/**
 * @brief Insert request into hash table for O(1) lookup.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request to insert.
 *
 * Inserts request into hash table using pre-computed hash value.
 */
extern void hash_table_insert (struct SocketDNS_T *dns,
                               struct SocketDNS_Request_T *req);

/**
 * @brief Remove request from hash table.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request to remove.
 *
 * Removes request from hash table bucket chain.
 */
extern void hash_table_remove (struct SocketDNS_T *dns,
                               struct SocketDNS_Request_T *req);

/**
 * @brief Append a DNS request to the end of the FIFO processing queue.
 * @ingroup dns
 *
 * Inserts the request into the tail of the queue (FIFO order) and increments
 * the queue_size counter. Updates queue_tail pointer and sets req->queue_next
 * = NULL. Must be called under mutex lock (internal invariant).
 *
 * Queue is singly-linked via SocketDNS_Request_T::queue_next field.
 * Used during request submission after hash table insertion.
 *
 * @param[in,out] dns DNS resolver (queue_head/tail/size modified).
 * @param[in] req Request to append (req->queue_next set to NULL).
 *
 * @threadsafe No - requires exclusive access via dns->mutex.
 *
 *  Usage Example
 *
 * @code{.c}
 * pthread_mutex_lock(&dns->mutex);
 * if (check_queue_limit(dns)) {
 *     // Reject or queue overflow handling
 *     pthread_mutex_unlock(&dns->mutex);
 *     return;
 * }
 * hash_table_insert(dns, req);
 * queue_append(dns, req);
 * pthread_cond_broadcast(&dns->queue_cond);  // Wake workers
 * pthread_mutex_unlock(&dns->mutex);
 * @endcode
 *
 * @complexity O(1) - direct pointer updates, no traversal.
 *
 * @note FIFO ensures fair processing order for submitted requests.
 * @note Called only from submit_dns_request() under lock.
 *
 * @warning Invalid if called without holding dns->mutex (race conditions).
 * @warning req must not already be in queue or hash table.
 *
 * @see queue_remove() for removal operations.
 * @see check_queue_limit() for capacity check before append.
 * @see submit_dns_request() coordinating insert + append + signal.
 * @see dequeue_request() for head removal by workers.
 */

/**
 * @brief Remove request from queue head position.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request to remove (must be at queue head).
 *
 * Optimized removal when request is at queue head.
 */
extern void remove_from_queue_head (struct SocketDNS_T *dns,
                                    struct SocketDNS_Request_T *req);

/**
 * @brief Remove request from middle of queue.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request to remove (not at head).
 *
 * Traverses queue to find and remove request from middle.
 */
extern void remove_from_queue_middle (struct SocketDNS_T *dns,
                                      struct SocketDNS_Request_T *req);

/**
 * @brief Remove request from processing queue.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request to remove.
 *
 * Dispatches to head or middle removal based on position.
 */
extern void queue_remove (struct SocketDNS_T *dns,
                          struct SocketDNS_Request_T *req);

/**
 * @brief Check if queue has reached capacity limit.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @return 1 if at limit, 0 if can accept more requests.
 *
 * Compares current queue size against max_pending limit.
 */
extern int check_queue_limit (const struct SocketDNS_T *dns);

/**
 * @brief Submit request for processing by worker threads.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request to submit.
 *
 * Inserts into hash table and queue, then signals workers.
 */
extern void submit_dns_request (struct SocketDNS_T *dns,
                                struct SocketDNS_Request_T *req);

/**
 * @brief Cancel a pending request before it starts processing.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request to cancel.
 *
 * Removes from queue and hash table, marks as cancelled.
 */
extern void cancel_pending_request (struct SocketDNS_T *dns,
                                    struct SocketDNS_Request_T *req);

/* Timeout handling */

/**
 * @brief Get effective timeout for request (with fallback to default).
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request to check.
 * @return Effective timeout in milliseconds.
 *
 * Returns req->timeout_override_ms if >= 0, otherwise dns->request_timeout_ms.
 */
extern int
request_effective_timeout_ms (const struct SocketDNS_T *dns,
                              const struct SocketDNS_Request_T *req);

/**
 * @brief Check if request has exceeded its timeout.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request to check.
 * @return 1 if timed out, 0 if still within timeout.
 *
 * Compares elapsed time since submission against effective timeout.
 *
 * @see @ref foundation::SocketTimer "SocketTimer" for timer management
 * utilities.
 */
extern int request_timed_out (const struct SocketDNS_T *dns,
                              const struct SocketDNS_Request_T *req);

/**
 * @brief Mark request as timed out with appropriate error code.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request to mark as timed out.
 *
 * Sets state to REQ_COMPLETE, error to EAI_NONAME, and clears result.
 */
extern void mark_request_timeout (struct SocketDNS_T *dns,
                                  struct SocketDNS_Request_T *req);

/**
 * @brief Handle timeout for a specific request.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request that has timed out.
 *
 * Calls mark_request_timeout() and signals completion.
 */
extern void handle_request_timeout (struct SocketDNS_T *dns,
                                    struct SocketDNS_Request_T *req);

/* Worker thread and resolution */

/**
 * @brief Initialize addrinfo hints structure with defaults.
 * @ingroup dns
 * @param hints Hints structure to initialize.
 *
 * Sets AF_UNSPEC, SOCK_STREAM, and AI_NUMERICSERV flags.
 */
extern void initialize_addrinfo_hints (struct addrinfo *hints);

/**
 * @brief Main worker thread function for DNS resolution.
 * @ingroup dns
 * @param arg Pointer to SocketDNS_T instance.
 * @return NULL (threads run until shutdown).
 *
 * Worker thread main loop: wait for requests, process them, repeat.
 * Handles shutdown signaling gracefully.
 */
extern void *worker_thread (void *arg);

/**
 * @brief Prepare addrinfo hints for specific request.
 * @ingroup dns
 * @param local_hints Output hints structure.
 * @param base_hints Base hints to copy from.
 * @param req Request providing port/service information.
 *
 * Copies base hints and sets port from request.
 */
extern void prepare_local_hints (struct addrinfo *local_hints,
                                 const struct addrinfo *base_hints,
                                 const struct SocketDNS_Request_T *req);

/**
 * @brief Handle result of DNS resolution attempt.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request that was resolved.
 * @param result Resolution result (NULL on error).
 * @param res Error code from getaddrinfo().
 *
 * Updates request state, stores result, and signals completion.
 */
extern void handle_resolution_result (struct SocketDNS_T *dns,
                                      struct SocketDNS_Request_T *req,
                                      struct addrinfo *result, int res);

/**
 * @brief Process a single DNS request from the queue.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request to process.
 * @param base_hints Base addrinfo hints for resolution.
 *
 * Performs DNS resolution using getaddrinfo() with timeout checking.
 * Updates request state and signals completion on finish.
 */
extern void process_single_request (struct SocketDNS_T *dns,
                                    struct SocketDNS_Request_T *req,
                                    const struct addrinfo *base_hints);

/**
 * @brief Remove and return next request from processing queue.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @return Next request to process, or NULL if queue empty.
 *
 * Removes from queue head and updates queue_size counter.
 */
extern struct SocketDNS_Request_T *dequeue_request (struct SocketDNS_T *dns);

/**
 * @brief Wait for a request to become available in the queue.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @return Next request to process.
 *
 * Blocks until request available or shutdown signaled.
 */
extern struct SocketDNS_Request_T *wait_for_request (struct SocketDNS_T *dns);

/**
 * @brief Signal completion of DNS request to waiting threads/polls.
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Writes completion byte to pipe for SocketPoll integration.
 */
extern void signal_completion (struct SocketDNS_T *dns);

/**
 * @brief Store DNS resolution result in request structure.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request to update.
 * @param result Resolution result (NULL on error).
 * @param error Error code (0 on success).
 *
 * Updates request state to REQ_COMPLETE and stores result/error.
 */
extern void store_resolution_result (struct SocketDNS_T *dns,
                                     struct SocketDNS_Request_T *req,
                                     struct addrinfo *result, int error);

/**
 * @brief Get error code indicating request was cancelled.
 * @ingroup dns
 * @return Error code for cancelled requests.
 *
 * Returns EAI_NONAME as cancellation indicator.
 */
extern int dns_cancellation_error (void);

/**
 * @brief Perform actual DNS resolution using getaddrinfo().
 * @ingroup dns
 * @param req Request containing hostname and port.
 * @param hints addrinfo hints for resolution.
 * @param result Output parameter for result.
 * @return 0 on success, getaddrinfo error code on failure.
 *
 * Calls getaddrinfo() with hostname and service from request.
 */
extern int perform_dns_resolution (const struct SocketDNS_Request_T *req,
                                   const struct addrinfo *hints,
                                   struct addrinfo **result);

/**
 * @brief Invoke user callback for completed request.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Completed request with result.
 *
 * Calls req->callback with request, result, error, and user data.
 * Callback executes in worker thread context.
 */
extern void invoke_callback (struct SocketDNS_T *dns,
                             struct SocketDNS_Request_T *req);

/*
 * =============================================================================
 * Forward Declarations - SocketDNS.c
 *
 * Validation functions used by both public API and internal implementation.
 * =============================================================================
 */

/* Validation */

/**
 * @brief Validate hostname and port parameters for DNS resolution.
 * @ingroup dns
 * @param host Hostname string to validate.
 * @param port Port number to validate.
 *
 * Validates that host is non-NULL, non-empty, and port is in valid range
 * (1-65535). Raises SocketDNS_Failed exception on invalid parameters.
 */
extern void validate_resolve_params (const char *host, int port);

extern struct SocketDNS_T *allocate_dns_resolver (void);

#endif /* SOCKETDNS_PRIVATE_INCLUDED */

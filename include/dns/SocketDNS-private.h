#ifndef SOCKETDNS_PRIVATE_INCLUDED
#define SOCKETDNS_PRIVATE_INCLUDED

/**
 * @file SocketDNS-private.h
 * @brief Internal structures, enums, and prototypes for asynchronous DNS resolver implementation.
 * @ingroup dns
 *
 * Defines private data structures, state enumerations, and internal function prototypes
 * for the thread-pool based DNS resolution module. Intended solely for library maintainers.
 * Applications must use public API in SocketDNS.h exclusively.
 *
 * Core internal architecture:
 * - #SocketDNS_T: Resolver with arena, worker threads, request queue/hash, sync primitives, completion pipe
 * - #SocketDNS_Request_T: Per-request state including hostname, callback, result, timeout tracking
 * - RequestState enum: Lifecycle tracking (PENDING -> PROCESSING -> COMPLETE/CANCELLED)
 * - Hash table (SOCKET_DNS_REQUEST_HASH_SIZE buckets) for O(1) request lookup/removal
 * - Mutex-protected FIFO queue for pending requests
 * - Pipe FD for non-blocking completion notification to SocketPoll
 *
 * Dependencies:
 * - @ref foundation (Arena_T for memory, Except_T for errors)
 * - @ref core_io (SocketCommon.h for util, SocketUtil.h for hashing/timing)
 * - POSIX threads (pthread) and <netdb.h> for getaddrinfo()
 *
 * Security considerations:
 * - Deterministic pointer hashing mitigates collision attacks but monitor max_pending
 * - Worker threads isolated; callbacks execute in worker context (no main thread reentrancy)
 * - Timeouts prevent DoS from slow/broken DNS servers
 *
 * @see SocketDNS.h for public asynchronous API (resolve, pollfd, getresult).
 * @see src/dns/SocketDNS.c for public wrapper functions and exception setup.
 * @see src/dns/SocketDNS-internal.c for full implementation details.
 * @see @ref dns "DNS module overview" and @ref core_io "Core I/O group".
 * @see docs/ASYNC_IO.md for integration with event loops.
 * @warning INTERNAL USE ONLY - unstable ABI, may change without notice.
 * @warning Callback functions must be reentrant and fast; see SocketDNS_Callback documentation.
 */

/* System headers */
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
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
 * Created by SocketDNS_resolve(), used to retrieve results, cancel, or via callback.
 * Lifetime managed by resolver; invalid after completion or cancellation.
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
 * Called from worker thread context upon completion (success, error, or timeout).
 * @note Executed in a dedicated DNS worker thread - NOT the thread that submitted the request.
 * @note Must complete quickly; blocking stalls the worker pool.
 * @note Takes ownership of 'result'; free with freeaddrinfo() after use.
 * @note Do NOT call SocketDNS_free(dns) from callback (deadlock risk).
 * @warning No automatic synchronization; user must protect shared data.
 * @see SocketDNS_resolve() to submit request with callback.
 * @see SocketDNS_Callback safety notes in SocketDNS.h documentation.
 */
typedef void (*SocketDNS_Callback) (SocketDNS_Request_T *, struct addrinfo *, int, void *);

/*
 * =============================================================================
 * Internal Enumerations and Constants
 * =============================================================================
 */

/**
 * @brief Enumeration of DNS request processing states.
 * @ingroup dns
 *
 * Tracks the lifecycle of individual resolution requests through the async pipeline:
 * - Submitted requests transition PENDING -> PROCESSING -> COMPLETE/CANCELLED
 * - State used for synchronization, timeout checks, and result availability
 * - Atomic updates under mutex protection
 *
 * @see SocketDNS_Request_T::state field.
 * @see queue_append(), process_single_request(), cancel_pending_request()
 */
typedef enum
{
  REQ_PENDING,    /**< Request queued, awaiting worker assignment */
  REQ_PROCESSING, /**< Worker actively calling getaddrinfo() */
  REQ_COMPLETE,   /**< Resolution finished; result/error ready */
  REQ_CANCELLED   /**< User cancelled before processing complete */
} RequestState;

/**
 * @brief Levels for partial cleanup during initialization failures.
 * @ingroup dns
 *
 * Defines cleanup scope for cleanup_on_init_failure() based on init progress.
 * Values correspond to initialization order to enable reverse-order resource release.
 * Used in TRY/EXCEPT blocks during SocketDNS_new() to ensure no leaks on failure.
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
  struct addrinfo *result;     /**< Resolution result (owned until retrieved) */
  int error;                   /**< getaddrinfo() error code (0 on success) */
  struct SocketDNS_Request_T *queue_next; /**< Queue linked list pointer */
  struct SocketDNS_Request_T *hash_next;  /**< Hash table chain pointer */
  unsigned hash_value;         /**< Cached hash for O(1) removal */
  struct timespec submit_time; /**< CLOCK_MONOTONIC submission timestamp */
  int timeout_override_ms;     /**< Per-request timeout (-1 = use default) */
  struct SocketDNS_T *dns_resolver; /**< Back-pointer to owning resolver */
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
 * @return Pointer to allocated and zeroed SocketDNS_T instance.
 * @throws SocketDNS_Failed on memory allocation failure (calloc failure).
 *
 * Performs calloc(1, sizeof(struct SocketDNS_T)) for zero-initialization of all fields.
 * Used during SocketDNS_new() bootstrap before arena allocation.
 * Caller must subsequently call initialize_dns_fields() and other init functions.
 *
 * @note Heap allocation (not arena); arena is initialized later for requests.
 * @see initialize_dns_fields() to set default values.
 * @see initialize_dns_components() for full setup including threads and sync.
 * @see SocketDNS_new() public entry point that orchestrates allocation + init.
 */
extern struct SocketDNS_T *allocate_dns_resolver (void);

/**
 * @brief Initialize basic DNS resolver fields to default values.
 * @ingroup dns
 * @param dns DNS resolver to initialize.
 *
 * Sets all fields to safe defaults (NULL pointers, zero values).
 * Called before initialize_dns_components().
 */
extern void initialize_dns_fields (struct SocketDNS_T *dns);

/**
 * @brief Initialize core DNS resolver components: arena, synchronization primitives, pipe, and worker threads.
 * @ingroup dns
 * @param dns Pre-allocated DNS resolver structure (from allocate_dns_resolver()).
 * @throws SocketDNS_Failed on allocation failure (arena), synchronization init failure (pthread), pipe creation failure, or thread creation failure.
 *
 * Orchestrates full resolver setup:
 * - Arena allocation for requests/hostnames
 * - Mutex and condition variables for queue/result signaling
 * - Completion pipe for SocketPoll integration
 * - Worker thread pool startup
 *
 * Must be called after allocate_dns_resolver() and initialize_dns_fields().
 * Handles partial failure cleanup via cleanup_on_init_failure().
 * @pre dns is allocated and fields initialized to defaults.
 * @note All internal state protected by mutex post-init.
 * @threadsafe No - single-threaded initialization.
 * @see allocate_dns_resolver() for structure allocation.
 * @see start_dns_workers() to signal workers active.
 * @see destroy_dns_resources() for symmetric cleanup.
 * @see SocketDNS_new() public wrapper.
 */
extern void initialize_dns_components (struct SocketDNS_T *dns);

/**
 * @brief Configure thread attributes for worker thread creation.
 * @ingroup dns
 * @param attr Thread attributes structure to configure.
 *
 * Sets thread attributes for detached, default-priority worker threads.
 */
extern void setup_thread_attributes (pthread_attr_t *attr);

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
 * @throws SocketDNS_Failed if pthread_create() fails for any thread (ENOMEM, etc.).
 *
 * Creates dns->num_workers (default SOCKET_DNS_THREAD_COUNT) detached worker threads.
 * Each thread runs worker_thread() loop until shutdown.
 * Threads are stored in dns->workers array (arena-allocated).
 *
 * @note Threads are created detached with default scheduling attributes.
 * @note Partial success: some threads may start before failure; cleanup handles join.
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
 * Creates condition variable used to wake polling threads when results complete.
 */
extern void initialize_result_condition (struct SocketDNS_T *dns);

/**
 * @brief Initialize all synchronization primitives (mutex + conditions).
 * @ingroup dns
 * @param dns DNS resolver instance.
 *
 * Calls initialize_mutex(), initialize_queue_condition(), and initialize_result_condition().
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
 * Calls all cleanup functions in proper order. Safe to call on partially initialized instances.
 */
extern void destroy_dns_resources (struct SocketDNS_T *dns);

/**
 * @brief Free a linked list of DNS requests.
 * @ingroup dns
 * @param head Head of request list to free.
 * @param use_hash_next Whether to use hash_next (1) or queue_next (0) for traversal.
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
 * Allocates memory for request structure. Fields must be initialized before use.
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
 * @brief Append request to processing queue.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request to queue.
 *
 * Adds request to end of FIFO queue and updates queue size.
 */
extern void queue_append (struct SocketDNS_T *dns,
                          struct SocketDNS_Request_T *req);

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
 * @see @ref foundation::SocketTimer "SocketTimer" for timer management utilities.
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
 * Validates that host is non-NULL, non-empty, and port is in valid range (1-65535).
 * Raises SocketDNS_Failed exception on invalid parameters.
 */
extern void validate_resolve_params (const char *host, int port);

#endif /* SOCKETDNS_PRIVATE_INCLUDED */

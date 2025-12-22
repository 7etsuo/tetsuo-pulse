/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDNS_PRIVATE_INCLUDED
#define SOCKETDNS_PRIVATE_INCLUDED

/**
 * @file SocketDNS-private.h
 * @brief Internal structures and prototypes for DNS resolver implementation.
 * @ingroup dns
 * @warning INTERNAL USE ONLY - unstable ABI, may change without notice.
 */

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

/**
 * @brief DNS request lifecycle states.
 * @ingroup dns
 *
 * Transitions: REQ_PENDING → REQ_PROCESSING → REQ_COMPLETE | REQ_CANCELLED
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
 * @brief Cleanup levels for partial initialization failure recovery.
 * @ingroup dns
 */
enum DnsCleanupLevel
{
  DNS_CLEAN_NONE = 0, /**< No cleanup needed */
  DNS_CLEAN_MUTEX,    /**< Cleanup mutex only */
  DNS_CLEAN_CONDS,    /**< Cleanup condition variables and mutex */
  DNS_CLEAN_PIPE,     /**< Cleanup pipe, conditions, and mutex */
  DNS_CLEAN_ARENA     /**< Cleanup arena and all above */
};

/**
 * @brief DNS resolution request structure.
 * @ingroup dns
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

extern const Except_T SocketDNS_Failed;

/* NOTE: Error raising uses SOCKET_RAISE_MSG/FMT directly (combined
 * format+raise). Each .c file that raises exceptions must include
 * SOCKET_DECLARE_MODULE_EXCEPTION. See SocketDNS.c and SocketDNS-internal.c
 * for the pattern. */

/* Forward Declarations - SocketDNS-internal.c */

extern int create_single_worker_thread (struct SocketDNS_T *dns,
                                        int thread_index);
extern void create_worker_threads (struct SocketDNS_T *dns);
extern void start_dns_workers (struct SocketDNS_T *dns);

/* Synchronization primitives */
extern void initialize_mutex (struct SocketDNS_T *dns);
extern void initialize_queue_condition (struct SocketDNS_T *dns);
extern void initialize_result_condition (struct SocketDNS_T *dns);
extern void initialize_synchronization (struct SocketDNS_T *dns);
extern void create_completion_pipe (struct SocketDNS_T *dns);
extern void set_pipe_nonblocking (struct SocketDNS_T *dns);
extern void initialize_pipe (struct SocketDNS_T *dns);

/* Cleanup and shutdown */
extern void cleanup_mutex_cond (struct SocketDNS_T *dns);
extern void cleanup_pipe (struct SocketDNS_T *dns);
extern void cleanup_on_init_failure (struct SocketDNS_T *dns,
                                     enum DnsCleanupLevel cleanup_level);
extern void shutdown_workers (struct SocketDNS_T *dns);
extern void drain_completion_pipe (struct SocketDNS_T *dns);
extern void reset_dns_state (struct SocketDNS_T *dns);
extern void destroy_dns_resources (struct SocketDNS_T *dns);
extern void free_request_list (struct SocketDNS_Request_T *head,
                               int use_hash_next);
extern void free_queued_requests (struct SocketDNS_T *dns);
extern void free_hash_table_requests (struct SocketDNS_T *dns);
extern void free_all_requests (struct SocketDNS_T *dns);

/* Request allocation and queue management */
extern unsigned request_hash_function (const struct SocketDNS_Request_T *req);
extern struct SocketDNS_Request_T *
allocate_request_structure (struct SocketDNS_T *dns);
extern void allocate_request_hostname (struct SocketDNS_T *dns,
                                       struct SocketDNS_Request_T *req,
                                       const char *host, size_t host_len);
extern void initialize_request_fields (struct SocketDNS_Request_T *req,
                                       int port, SocketDNS_Callback callback,
                                       void *data);
extern struct SocketDNS_Request_T *
allocate_request (struct SocketDNS_T *dns, const char *host, size_t host_len,
                  int port, SocketDNS_Callback cb, void *data);
extern void hash_table_insert (struct SocketDNS_T *dns,
                               struct SocketDNS_Request_T *req);
extern void hash_table_remove (struct SocketDNS_T *dns,
                               struct SocketDNS_Request_T *req);
extern void remove_from_queue_head (struct SocketDNS_T *dns,
                                    struct SocketDNS_Request_T *req);
extern void remove_from_queue_middle (struct SocketDNS_T *dns,
                                      struct SocketDNS_Request_T *req);
extern void queue_remove (struct SocketDNS_T *dns,
                          struct SocketDNS_Request_T *req);
extern int check_queue_limit (const struct SocketDNS_T *dns);
extern void submit_dns_request (struct SocketDNS_T *dns,
                                struct SocketDNS_Request_T *req);
extern void cancel_pending_request (struct SocketDNS_T *dns,
                                    struct SocketDNS_Request_T *req);

/* Timeout handling */
extern int
request_effective_timeout_ms (const struct SocketDNS_T *dns,
                              const struct SocketDNS_Request_T *req);
extern int request_timed_out (const struct SocketDNS_T *dns,
                              const struct SocketDNS_Request_T *req);
extern void mark_request_timeout (struct SocketDNS_T *dns,
                                  struct SocketDNS_Request_T *req);
extern void handle_request_timeout (struct SocketDNS_T *dns,
                                    struct SocketDNS_Request_T *req);

/* Worker thread and resolution */
extern void initialize_addrinfo_hints (struct addrinfo *hints);
extern void *worker_thread (void *arg);
extern void prepare_local_hints (struct addrinfo *local_hints,
                                 const struct addrinfo *base_hints,
                                 const struct SocketDNS_Request_T *req);
extern void handle_resolution_result (struct SocketDNS_T *dns,
                                      struct SocketDNS_Request_T *req,
                                      struct addrinfo *result, int res);
extern void process_single_request (struct SocketDNS_T *dns,
                                    struct SocketDNS_Request_T *req,
                                    const struct addrinfo *base_hints);
extern struct SocketDNS_Request_T *dequeue_request (struct SocketDNS_T *dns);
extern struct SocketDNS_Request_T *wait_for_request (struct SocketDNS_T *dns);
extern void signal_completion (struct SocketDNS_T *dns);
extern void store_resolution_result (struct SocketDNS_T *dns,
                                     struct SocketDNS_Request_T *req,
                                     struct addrinfo *result, int error);
extern int dns_cancellation_error (void);
extern int perform_dns_resolution (const struct SocketDNS_Request_T *req,
                                   const struct addrinfo *hints,
                                   struct addrinfo **result);
extern void invoke_callback (struct SocketDNS_T *dns,
                             struct SocketDNS_Request_T *req);

/* Forward Declarations - SocketDNS.c */
extern void validate_resolve_params (const char *host, int port);
extern struct SocketDNS_T *allocate_dns_resolver (void);

/* Cache functions - defined in SocketDNS.c, used by SocketDNS-internal.c */
extern struct SocketDNS_CacheEntry *cache_lookup (struct SocketDNS_T *dns,
                                                   const char *hostname);
extern void cache_insert (struct SocketDNS_T *dns, const char *hostname,
                          struct addrinfo *result);
extern void cache_clear_locked (struct SocketDNS_T *dns);

#endif /* SOCKETDNS_PRIVATE_INCLUDED */

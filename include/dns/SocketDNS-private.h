#ifndef SOCKETDNS_PRIVATE_INCLUDED
#define SOCKETDNS_PRIVATE_INCLUDED

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

/* Forward declaration - full definition in Arena.h */
typedef struct Arena_T *Arena_T;

/* Forward typedef for callback */
typedef void (*SocketDNS_Callback) (struct SocketDNS_Request_T *, struct addrinfo *, int, void *);

/*
 * =============================================================================
 * Internal Enumerations
 * =============================================================================
 */

/**
 * RequestState - DNS request lifecycle states
 */
typedef enum {
  REQ_PENDING,    /**< In queue, not yet processed by worker */
  REQ_PROCESSING, /**< Worker thread currently resolving */
  REQ_COMPLETE,   /**< Result available for retrieval */
  REQ_CANCELLED   /**< Request cancelled by user */
} RequestState;

/**
 * DnsCleanupLevel - Cleanup levels for partial initialization failure
 *
 * Used by cleanup_on_init_failure() to know which resources need cleanup
 * when initialization fails partway through. Listed in initialization order.
 */
enum DnsCleanupLevel {
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
 * SocketDNS_Request_T - DNS resolution request structure
 *
 * Represents a single DNS resolution request with all associated state.
 * Allocated from the resolver's arena and lives until result is retrieved
 * or request is cancelled.
 */
struct SocketDNS_Request_T {
  char *host;                   /**< Hostname to resolve (arena-allocated) */
  int port;                     /**< Port number for service lookup */
  SocketDNS_Callback callback;  /**< Completion callback (NULL for polling) */
  void *callback_data;          /**< User data passed to callback */
  RequestState state;           /**< Current request lifecycle state */
  struct addrinfo *result;      /**< Resolution result (owned until retrieved) */
  int error;                    /**< getaddrinfo() error code (0 on success) */
  struct SocketDNS_Request_T *queue_next; /**< Queue linked list pointer */
  struct SocketDNS_Request_T *hash_next;  /**< Hash table chain pointer */
  unsigned hash_value;          /**< Cached hash for O(1) removal */
  struct timespec submit_time;  /**< CLOCK_MONOTONIC submission timestamp */
  int timeout_override_ms;      /**< Per-request timeout (-1 = use default) */
  struct SocketDNS_T *dns_resolver; /**< Back-pointer to owning resolver */
};

/**
 * SocketDNS_T - Async DNS resolver structure
 *
 * Thread pool-based DNS resolver with queue management, hash table lookup,
 * and pipe-based completion signaling for integration with SocketPoll.
 */
struct SocketDNS_T {
  Arena_T arena;                /**< Arena for request/hostname allocation */
  pthread_t *workers;           /**< Worker thread array (arena-allocated) */
  int num_workers;              /**< Number of worker threads */
  struct SocketDNS_Request_T *queue_head; /**< Request queue FIFO head */
  struct SocketDNS_Request_T *queue_tail; /**< Request queue FIFO tail */
  size_t queue_size;            /**< Current pending request count */
  size_t max_pending;           /**< Queue capacity limit */
  struct SocketDNS_Request_T *request_hash[SOCKET_DNS_REQUEST_HASH_SIZE];
                                /**< Hash table for O(1) request lookup */
  pthread_mutex_t mutex;        /**< Protects all mutable state */
  pthread_cond_t queue_cond;    /**< Signals workers when work available */
  pthread_cond_t result_cond;   /**< Signals waiters when result ready */
  int shutdown;                 /**< Shutdown flag (1 = shutting down) */
  int pipefd[2];                /**< Completion pipe [0]=read, [1]=write */
  int request_timeout_ms;       /**< Default timeout (0 = no timeout) */
};

/* Internal macros - use centralized constant */
#define COMPLETION_SIGNAL_BYTE SOCKET_DNS_COMPLETION_SIGNAL_BYTE

/**
 * SIGNAL_DNS_COMPLETION - Signal completion and wake waiters
 * @dns: DNS resolver instance
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
 * SANITIZE_TIMEOUT_MS - Sanitize timeout value (negative -> 0)
 * @timeout_ms: Timeout in milliseconds
 * Returns: 0 if negative, otherwise original value
 */
#define SANITIZE_TIMEOUT_MS(timeout_ms)                                       \
  ((timeout_ms) < 0 ? 0 : (timeout_ms))

/* Thread-local exception - extern declaration (defined in SocketDNS.c) */
extern const Except_T SocketDNS_Failed;

/* NOTE: Error raising uses SOCKET_RAISE_MSG/FMT directly (combined format+raise).
 * Each .c file that raises exceptions must include SOCKET_DECLARE_MODULE_EXCEPTION.
 * See SocketDNS.c and SocketDNS-internal.c for the pattern. */

/*
 * =============================================================================
 * Forward Declarations - SocketDNS-internal.c
 *
 * Internal implementation functions for initialization, synchronization,
 * cleanup, request management, timeout handling, and worker threads.
 * =============================================================================
 */

/* Initialization and allocation */
extern struct SocketDNS_T * allocate_dns_resolver (void);
extern void initialize_dns_fields (struct SocketDNS_T *dns);
extern void initialize_dns_components (struct SocketDNS_T *dns);
extern void setup_thread_attributes (pthread_attr_t *attr);
extern int create_single_worker_thread (struct SocketDNS_T *dns, int thread_index);
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
extern void shutdown_workers (struct SocketDNS_T *d);
extern void drain_completion_pipe (struct SocketDNS_T *dns);
extern void reset_dns_state (struct SocketDNS_T *d);
extern void destroy_dns_resources (struct SocketDNS_T *d);
extern void free_request_list (struct SocketDNS_Request_T *head,
                               int use_hash_next);
extern void free_queued_requests (struct SocketDNS_T *d);
extern void free_hash_table_requests (struct SocketDNS_T *d);
extern void free_all_requests (struct SocketDNS_T *d);

/* Request allocation and queue management */
extern unsigned request_hash_function (const struct SocketDNS_Request_T *req);
extern struct SocketDNS_Request_T *allocate_request_structure (
    struct SocketDNS_T *dns);
extern void allocate_request_hostname (struct SocketDNS_T *dns,
                                       struct SocketDNS_Request_T *req,
                                       const char *host, size_t host_len);
extern void initialize_request_fields (struct SocketDNS_Request_T *req,
                                       int port, SocketDNS_Callback callback,
                                       void *data);
extern struct SocketDNS_Request_T *allocate_request (struct SocketDNS_T *dns,
                                                     const char *host,
                                                     size_t host_len, int port,
                                                     SocketDNS_Callback cb,
                                                     void *data);
extern void hash_table_insert (struct SocketDNS_T *dns,
                               struct SocketDNS_Request_T *req);
extern void hash_table_remove (struct SocketDNS_T *dns,
                               struct SocketDNS_Request_T *req);
extern void queue_append (struct SocketDNS_T *dns,
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
extern int request_effective_timeout_ms (const struct SocketDNS_T *dns,
                                         const struct SocketDNS_Request_T *req);
extern int request_timed_out (const struct SocketDNS_T *dns,
                              const struct SocketDNS_Request_T *req);
extern void mark_request_timeout (struct SocketDNS_T *dns,
                                  struct SocketDNS_Request_T *req);
extern void handle_request_timeout (struct SocketDNS_T *dns,
                                    struct SocketDNS_Request_T *req);

/* Worker thread and resolution */
extern void initialize_addrinfo_hints (struct addrinfo *hints);
extern void * worker_thread (void *arg);
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
extern struct SocketDNS_Request_T * wait_for_request (struct SocketDNS_T *dns);
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

/*
 * =============================================================================
 * Forward Declarations - SocketDNS.c
 *
 * Validation functions used by both public API and internal implementation.
 * =============================================================================
 */

/* Validation */
extern bool is_ip_address (const char *host);
extern int validate_hostname_label (const char *label, size_t *len);
extern int validate_hostname (const char *hostname);
extern void validate_resolve_params (const char *host, int port);

#endif /* SOCKETDNS_PRIVATE_INCLUDED */

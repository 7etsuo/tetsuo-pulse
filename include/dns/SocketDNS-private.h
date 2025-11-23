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

/* Project headers */
#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "core/SocketEvents.h"
#include "core/SocketMetrics.h"
#include "socket/SocketCommon.h"

/* Forward typedef for callback */
typedef void (*SocketDNS_Callback) (struct SocketDNS_Request_T *, struct addrinfo *, int, void *);

/* Internal enums */
typedef enum {
  REQ_PENDING,    /* In queue, not yet processed */
  REQ_PROCESSING, /* Worker thread working on it */
  REQ_COMPLETE,   /* Result available */
  REQ_CANCELLED   /* Request cancelled */
} RequestState;

enum DnsCleanupLevel {
  DNS_CLEAN_NONE = 0,
  DNS_CLEAN_MUTEX,
  DNS_CLEAN_CONDS,
  DNS_CLEAN_PIPE,
  DNS_CLEAN_ARENA
};

/* Internal structures */
struct SocketDNS_Request_T {
  char *host;                   /* Hostname to resolve (allocated) */
  int port;                     /* Port number */
  SocketDNS_Callback callback;  /* Completion callback (NULL for polling) */
  void *callback_data;          /* User data for callback */
  RequestState state;           /* Current request state */
  struct addrinfo *result;      /* Completed result (NULL on error) */
  int error;                    /* Error code from getaddrinfo() */
  struct SocketDNS_Request_T *queue_next; /* Next in request queue */
  struct SocketDNS_Request_T *hash_next;  /* Next in hash table chain */
  unsigned hash_value;          /* Hash value for lookup */
  struct timespec submit_time;  /* Time request was submitted */
  int timeout_override_ms;      /* Per-request timeout override (ms) */
  struct SocketDNS_T *dns_resolver; /* Back pointer to owning resolver for cancellation checks */
};

struct SocketDNS_T {
  Arena_T arena;                /* Arena for request storage */
  pthread_t *workers;           /* Worker thread array */
  int num_workers;              /* Number of worker threads */
  struct SocketDNS_Request_T *queue_head; /* Request queue head */
  struct SocketDNS_Request_T *queue_tail; /* Request queue tail */
  size_t queue_size;            /* Current queue size */
  size_t max_pending;           /* Maximum pending requests */
  struct SocketDNS_Request_T *request_hash[SOCKET_DNS_REQUEST_HASH_SIZE]; /* Hash table for request lookup */
  pthread_mutex_t mutex;        /* Mutex for thread-safe operations */
  pthread_cond_t queue_cond;    /* Condition variable for queue */
  pthread_cond_t result_cond;   /* Condition variable for results */
  int shutdown;                 /* Shutdown flag */
  int pipefd[2];                /* Pipe for completion signaling */
  unsigned request_counter;     /* Request ID counter */
  int request_timeout_ms;       /* Default request timeout (ms) */
};

/* Internal macros */
#define COMPLETION_SIGNAL_BYTE 1

/* Thread-local exception */
extern const Except_T SocketDNS_Failed;
#ifdef _WIN32
extern __declspec(thread) Except_T SocketDNS_DetailedException;
#else
extern __thread Except_T SocketDNS_DetailedException;
#endif

#define RAISE_DNS_ERROR(exception)                                            \
  do                                                                          \
    {                                                                         \
      SocketDNS_DetailedException = (exception);                              \
      SocketDNS_DetailedException.reason = socket_error_buf;                  \
      RAISE (SocketDNS_DetailedException);                                    \
    }                                                                         \
  while (0)

/* Forward declarations for module-internal functions */
extern unsigned request_hash_function (struct SocketDNS_Request_T *req);
extern void signal_completion (struct SocketDNS_T *dns);
extern int dns_cancellation_error (void);
extern int request_effective_timeout_ms (struct SocketDNS_T *dns, const struct SocketDNS_Request_T *req);
extern int request_timed_out (struct SocketDNS_T *dns, const struct SocketDNS_Request_T *req);
extern void mark_request_timeout (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req);
extern struct SocketDNS_Request_T *dequeue_request (struct SocketDNS_T *dns);
extern int perform_dns_resolution (struct SocketDNS_Request_T *req, const struct addrinfo *hints, struct addrinfo **result);
extern void store_resolution_result (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req, struct addrinfo *result, int error);
extern void invoke_callback (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req);
extern void handle_request_timeout (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req);
extern void prepare_local_hints (struct addrinfo *local_hints, const struct addrinfo *base_hints, const struct SocketDNS_Request_T *req);
extern void handle_resolution_result (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req, struct addrinfo *result, int res);
extern void process_single_request (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req, struct addrinfo *base_hints);
extern struct SocketDNS_Request_T * wait_for_request (struct SocketDNS_T *dns);
extern void * worker_thread (void *arg);
extern void cleanup_mutex_cond (struct SocketDNS_T *dns);
extern void cleanup_pipe (struct SocketDNS_T *dns);
extern void cleanup_on_init_failure (struct SocketDNS_T *dns, enum DnsCleanupLevel cleanup_level);
extern void initialize_mutex (struct SocketDNS_T *dns);
extern void initialize_queue_condition (struct SocketDNS_T *dns);
extern void initialize_result_condition (struct SocketDNS_T *dns);
extern void initialize_synchronization (struct SocketDNS_T *dns);
extern void create_completion_pipe (struct SocketDNS_T *dns);
extern void set_pipe_nonblocking (struct SocketDNS_T *dns);
extern void initialize_pipe (struct SocketDNS_T *dns);
extern struct SocketDNS_T * allocate_dns_resolver (void);
extern void initialize_dns_fields (struct SocketDNS_T *dns);
extern void initialize_dns_components (struct SocketDNS_T *dns);
extern int create_single_worker_thread (struct SocketDNS_T *dns, int thread_index);
extern void create_worker_threads (struct SocketDNS_T *dns);
extern void start_dns_workers (struct SocketDNS_T *dns);
extern void free_request_list (struct SocketDNS_Request_T *head, int use_hash_next);
extern void free_queued_requests (struct SocketDNS_T *d);
extern void free_hash_table_requests (struct SocketDNS_T *d);
extern void free_all_requests (struct SocketDNS_T *d);
extern void shutdown_workers (struct SocketDNS_T *d);
extern void drain_completion_pipe (struct SocketDNS_T *dns);
extern void reset_dns_state (struct SocketDNS_T *d);
extern void destroy_dns_resources (struct SocketDNS_T *d);
extern void drain_completed_requests (struct SocketDNS_T *dns);
extern bool is_ip_address (const char *host);
extern int validate_hostname (const char *hostname);
extern void validate_resolve_params (const char *host, int port);
extern struct SocketDNS_Request_T *allocate_request_structure (struct SocketDNS_T *dns);
extern void allocate_request_hostname (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req, const char *host, size_t host_len);
extern void initialize_request_fields (struct SocketDNS_Request_T *req, int port, SocketDNS_Callback callback, void *data);
extern struct SocketDNS_Request_T *allocate_request (struct SocketDNS_T *dns, const char *host, size_t host_len, int port, SocketDNS_Callback callback, void *data);
extern void hash_table_insert (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req);
extern void queue_append (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req);
extern void check_queue_limit (struct SocketDNS_T *dns);
extern void submit_dns_request (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req);
extern void hash_table_remove (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req);
extern void remove_from_queue_head (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req);
extern void remove_from_queue_middle (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req);
extern void queue_remove (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req);
extern void cancel_pending_request (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req);

#endif /* SOCKETDNS_PRIVATE_INCLUDED */

/**
 * SocketDNS.c - Async DNS resolution implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * PLATFORM: POSIX-compliant systems (Linux, BSD, macOS)
 * - POSIX threads (pthread) for thread pool
 * - getaddrinfo() for DNS resolution
 * - pipe() for completion signaling
 */

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "dns/SocketDNS.h"
#include "core/SocketError.h"

#define T SocketDNS_T
#define Request_T SocketDNS_Request_T

Except_T SocketDNS_Failed = {"SocketDNS operation failed"};

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec(thread) Except_T SocketDNS_DetailedException;
#else
static __thread Except_T SocketDNS_DetailedException;
#endif

/* Macro to raise exception with detailed error message */
#define RAISE_DNS_ERROR(exception)                                                                                      \
    do                                                                                                                   \
    {                                                                                                                    \
        SocketDNS_DetailedException = (exception);                                                                       \
        SocketDNS_DetailedException.reason = socket_error_buf;                                                           \
        RAISE(SocketDNS_DetailedException);                                                                            \
    } while (0)

/* Request states */
typedef enum
{
    REQ_PENDING,    /* In queue, not yet processed */
    REQ_PROCESSING, /* Worker thread working on it */
    REQ_COMPLETE,   /* Result available */
    REQ_CANCELLED   /* Request cancelled */
} RequestState;

/* DNS request structure */
struct Request_T
{
    char *host;                        /* Hostname to resolve (allocated) */
    int port;                          /* Port number */
    SocketDNS_Callback callback;       /* Completion callback (NULL for polling) */
    void *callback_data;               /* User data for callback */
    RequestState state;                /* Current request state */
    struct addrinfo *result;           /* Completed result (NULL on error) */
    int error;                         /* Error code from getaddrinfo() */
    struct Request_T *queue_next;     /* Next in request queue */
    struct Request_T *hash_next;       /* Next in hash table chain */
    unsigned hash_value;               /* Hash value for lookup */
    time_t submit_time;                /* Time request was submitted */
};

/* DNS resolver structure */
struct T
{
    Arena_T arena;                    /* Arena for request storage */
    pthread_t *workers;               /* Worker thread array */
    int num_workers;                   /* Number of worker threads */
    struct Request_T *queue_head;      /* Request queue head */
    struct Request_T *queue_tail;     /* Request queue tail */
    size_t queue_size;                 /* Current queue size */
    size_t max_pending;                /* Maximum pending requests */
    struct Request_T *request_hash[SOCKET_DNS_REQUEST_HASH_SIZE]; /* Hash table for request lookup */
    pthread_mutex_t mutex;             /* Mutex for thread-safe operations */
    pthread_cond_t queue_cond;        /* Condition variable for queue */
    pthread_cond_t result_cond;       /* Condition variable for results */
    int shutdown;                      /* Shutdown flag */
    int pipefd[2];                     /* Pipe for completion signaling */
    unsigned request_counter;          /* Request ID counter */
};

/* Completion signal byte constant */
#define COMPLETION_SIGNAL_BYTE 1


/**
 * request_hash_function - Calculate hash for request pointer
 * @req: Request pointer to hash
 *
 * Returns: Hash value in range [0, SOCKET_DNS_REQUEST_HASH_SIZE)
 *
 * Uses golden ratio multiplicative hashing for good distribution.
 */
static unsigned
request_hash_function(struct Request_T *req)
{
    uintptr_t ptr = (uintptr_t)req;
    return ((unsigned)ptr * HASH_GOLDEN_RATIO) % SOCKET_DNS_REQUEST_HASH_SIZE;
}

/**
 * signal_completion - Signal completion via pipe
 * @dns: DNS resolver instance
 *
 * Writes completion signal to pipe. Non-blocking best-effort operation.
 * Pipe may be full, which is acceptable - signals are cumulative.
 */
static void
signal_completion(T dns)
{
    char byte = COMPLETION_SIGNAL_BYTE;
    ssize_t n;

    n = write(dns->pipefd[1], &byte, 1);
    (void)n; /* Ignore result - pipe may be full, that's OK */
}

/**
 * dequeue_request - Dequeue next request from queue
 * @dns: DNS resolver instance
 *
 * Returns: Next request or NULL if queue empty
 *
 * Thread-safe: Must be called with mutex locked
 */
static struct Request_T *
dequeue_request(T dns)
{
    struct Request_T *req;

    if (!dns->queue_head)
        return NULL;

    req = dns->queue_head;
    dns->queue_head = req->queue_next;
    if (!dns->queue_head)
        dns->queue_tail = NULL;
    dns->queue_size--;
    req->queue_next = NULL;
    req->state = REQ_PROCESSING;

    return req;
}

/**
 * perform_dns_resolution - Perform actual DNS lookup
 * @req: Request to resolve
 * @hints: getaddrinfo hints structure
 *
 * Returns: getaddrinfo result code
 * @result: Set to resolved addresses (or NULL on error)
 *
 * Performs DNS resolution with optional port parameter.
 */
static int
perform_dns_resolution(struct Request_T *req, const struct addrinfo *hints, struct addrinfo **result)
{
    char port_str[SOCKET_DNS_PORT_STR_SIZE];
    int res;

    if (req->port > 0)
    {
        snprintf(port_str, sizeof(port_str), "%d", req->port);
        res = getaddrinfo(req->host, port_str, hints, result);
    }
    else
    {
        res = getaddrinfo(req->host, NULL, hints, result);
    }

    return res;
}

/**
 * store_resolution_result - Store completed resolution result
 * @dns: DNS resolver instance
 * @req: Completed request
 * @result: Resolution result
 * @error: Error code from getaddrinfo
 *
 * Thread-safe: Must be called with mutex locked
 */
static void
store_resolution_result(T dns, struct Request_T *req, struct addrinfo *result, int error)
{
    if (req->state == REQ_PROCESSING)
    {
        req->state = REQ_COMPLETE;
        req->result = result;
        req->error = error;

        signal_completion(dns);
        pthread_cond_broadcast(&dns->result_cond);
    }
    else
    {
        /* Request was cancelled, free result */
        if (result)
            freeaddrinfo(result);
    }
}

/**
 * invoke_callback - Invoke completion callback if provided
 * @req: Completed request
 *
 * Thread-safe: Called without mutex (callback may take time)
 */
static void
invoke_callback(struct Request_T *req)
{
    if (req->callback && req->state == REQ_COMPLETE)
    {
        req->callback((Request_T)req, req->result, req->error, req->callback_data);
    }
}

/**
 * process_single_request - Process one DNS resolution request
 * @dns: DNS resolver instance
 * @req: Request to process
 * @hints: getaddrinfo hints structure
 *
 * Performs DNS resolution for one request and stores result.
 */
static void
process_single_request(T dns, struct Request_T *req, const struct addrinfo *hints)
{
    struct addrinfo *result = NULL;
    int res;

    res = perform_dns_resolution(req, hints, &result);

    pthread_mutex_lock(&dns->mutex);
    store_resolution_result(dns, req, result, res);
    pthread_mutex_unlock(&dns->mutex);

    invoke_callback(req);
}

/**
 * wait_for_request - Wait for next request or shutdown
 * @dns: DNS resolver instance
 *
 * Returns: Request to process, or NULL if shutdown
 *
 * Thread-safe: Must be called with mutex locked, unlocks on return
 */
static struct Request_T *
wait_for_request(T dns)
{
    while (dns->queue_head == NULL && !dns->shutdown)
    {
        pthread_cond_wait(&dns->queue_cond, &dns->mutex);
    }

    if (dns->shutdown && dns->queue_head == NULL)
    {
        pthread_mutex_unlock(&dns->mutex);
        return NULL;
    }

    return dequeue_request(dns);
}

/**
 * worker_thread - Worker thread for DNS resolution
 * @arg: DNS resolver instance
 *
 * Returns: NULL
 *
 * Worker thread that processes DNS resolution requests from queue.
 * Blocks waiting for requests, performs resolution, stores results.
 */
static void *
worker_thread(void *arg)
{
    T dns = (T)arg;
    struct Request_T *req;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    while (1)
    {
        pthread_mutex_lock(&dns->mutex);
        req = wait_for_request(dns);
        pthread_mutex_unlock(&dns->mutex);

        if (!req)
            break;

        process_single_request(dns, req, &hints);
    }

    return NULL;
}

/**
 * cleanup_mutex_cond - Cleanup mutex and condition variables
 * @dns: DNS resolver instance
 *
 * Destroys mutex and condition variables in reverse order of creation.
 */
static void
cleanup_mutex_cond(T dns)
{
    pthread_cond_destroy(&dns->result_cond);
    pthread_cond_destroy(&dns->queue_cond);
    pthread_mutex_destroy(&dns->mutex);
}

/**
 * cleanup_pipe - Close pipe file descriptors
 * @dns: DNS resolver instance
 *
 * Safely closes both pipe file descriptors.
 */
static void
cleanup_pipe(T dns)
{
    SAFE_CLOSE(dns->pipefd[0]);
    SAFE_CLOSE(dns->pipefd[1]);
}

/**
 * cleanup_on_init_failure - Cleanup resources on initialization failure
 * @dns: DNS resolver instance
 * @cleanup_level: How much cleanup needed (0=none, 1=mutex, 2=cond, 3=pipe, 4=arena)
 *
 * Cleans up partially initialized resolver. cleanup_level indicates how far
 * initialization got before failure.
 */
static void
cleanup_on_init_failure(T dns, int cleanup_level)
{
    if (cleanup_level >= 4)
        Arena_dispose(&dns->arena);
    if (cleanup_level >= 3)
        cleanup_pipe(dns);
    if (cleanup_level >= 2)
        cleanup_mutex_cond(dns);
    if (cleanup_level >= 1)
        pthread_mutex_destroy(&dns->mutex);
    free(dns);
}

/**
 * initialize_synchronization - Initialize mutex and condition variables
 * @dns: DNS resolver instance
 *
 * Raises: SocketDNS_Failed on initialization failure
 */
static void
initialize_synchronization(T dns)
{
    if (pthread_mutex_init(&dns->mutex, NULL) != 0)
    {
        cleanup_on_init_failure(dns, 0);
        SOCKET_ERROR_MSG("Failed to initialize DNS resolver mutex");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    if (pthread_cond_init(&dns->queue_cond, NULL) != 0)
    {
        cleanup_on_init_failure(dns, 1);
        SOCKET_ERROR_MSG("Failed to initialize DNS resolver condition variable");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    if (pthread_cond_init(&dns->result_cond, NULL) != 0)
    {
        cleanup_on_init_failure(dns, 2);
        SOCKET_ERROR_MSG("Failed to initialize DNS resolver result condition variable");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }
}

/**
 * initialize_pipe - Create pipe for completion signaling
 * @dns: DNS resolver instance
 *
 * Raises: SocketDNS_Failed on pipe creation failure
 */
static void
initialize_pipe(T dns)
{
    if (pipe(dns->pipefd) < 0)
    {
        cleanup_on_init_failure(dns, 3);
        SOCKET_ERROR_FMT("Failed to create completion pipe");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }
}

/**
 * allocate_dns_resolver - Allocate and initialize basic DNS resolver structure
 *
 * Returns: Allocated DNS resolver or NULL on failure
 * Raises: SocketDNS_Failed on allocation failure
 *
 * Allocates DNS resolver structure and sets up basic fields.
 */
static T
allocate_dns_resolver(void)
{
    T dns;

    dns = calloc(1, sizeof(*dns));
    if (!dns)
    {
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate DNS resolver");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    return dns;
}

/**
 * initialize_dns_fields - Set default field values for DNS resolver
 * @dns: DNS resolver instance
 *
 * Initializes configuration fields to default values.
 */
static void
initialize_dns_fields(T dns)
{
    dns->num_workers = SOCKET_DNS_THREAD_COUNT;
    dns->max_pending = SOCKET_DNS_MAX_PENDING;
    dns->shutdown = 0;
    dns->request_counter = 0;

    dns->queue_head = NULL;
    dns->queue_tail = NULL;
    dns->queue_size = 0;
}

/**
 * initialize_dns_components - Initialize arena and synchronization primitives
 * @dns: DNS resolver instance
 *
 * Raises: SocketDNS_Failed on initialization failure
 *
 * Sets up arena, mutex, condition variables, and pipe for completion signaling.
 */
static void
initialize_dns_components(T dns)
{
    dns->arena = Arena_new();
    if (!dns->arena)
    {
        free(dns);
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate DNS resolver arena");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    initialize_synchronization(dns);
    initialize_pipe(dns);
}

/**
 * create_single_worker_thread - Create a single worker thread
 * @dns: DNS resolver instance
 * @thread_index: Index of thread to create
 *
 * Returns: 0 on success, -1 on failure
 *
 * Creates one worker thread and handles partial cleanup on failure.
 */
static int
create_single_worker_thread(T dns, int thread_index)
{
    if (pthread_create(&dns->workers[thread_index], NULL, worker_thread, dns) != 0)
    {
        /* Signal shutdown and join already created threads */
        dns->shutdown = 1;
        pthread_cond_broadcast(&dns->queue_cond);

        /* Join previously created threads */
        for (int j = 0; j < thread_index; j++)
        {
            pthread_join(dns->workers[j], NULL);
        }

        return -1; /* Signal failure */
    }

    return 0; /* Success */
}

/**
 * create_worker_threads - Create worker thread pool
 * @dns: DNS resolver instance
 *
 * Raises: SocketDNS_Failed on thread creation failure
 *
 * Creates all worker threads, with proper cleanup on partial failure.
 */
static void
create_worker_threads(T dns)
{
    for (int i = 0; i < dns->num_workers; i++)
    {
        if (create_single_worker_thread(dns, i) != 0)
        {
            /* Thread creation failed - cleanup and raise error */
            cleanup_on_init_failure(dns, 4);
            SOCKET_ERROR_FMT("Failed to create DNS worker thread %d", i);
            RAISE_DNS_ERROR(SocketDNS_Failed);
        }
    }
}

/**
 * start_dns_workers - Create and start worker thread pool
 * @dns: DNS resolver instance
 *
 * Raises: SocketDNS_Failed on thread creation failure
 *
 * Creates worker threads and allocates thread array from arena.
 */
static void
start_dns_workers(T dns)
{
    dns->workers = ALLOC(dns->arena, dns->num_workers * sizeof(pthread_t));
    if (!dns->workers)
    {
        cleanup_on_init_failure(dns, 4);
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate worker thread array");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    memset(dns->request_hash, 0, sizeof(dns->request_hash));
    create_worker_threads(dns);
}

T
SocketDNS_new(void)
{
    T dns;

    dns = allocate_dns_resolver();
    initialize_dns_fields(dns);
    initialize_dns_components(dns);
    start_dns_workers(dns);

    return dns;
}

/**
 * free_request_list - Free all requests in a list
 * @head: Head of request list
 *
 * Frees getaddrinfo results for all requests in list.
 * Request structures themselves are in Arena, so not freed here.
 */
static void
free_request_list(struct Request_T *head)
{
    struct Request_T *req = head;
    struct Request_T *next;

    while (req)
    {
        next = req->queue_next;
        if (req->result)
            freeaddrinfo(req->result);
        req = next;
    }
}

/**
 * free_queued_requests - Free all requests in the request queue
 * @d: DNS resolver instance
 *
 * Thread-safe: Must be called with mutex locked
 *
 * Frees all requests currently in the processing queue.
 */
static void
free_queued_requests(T d)
{
    free_request_list(d->queue_head);
}

/**
 * free_hash_table_requests - Free all requests in hash table
 * @d: DNS resolver instance
 *
 * Thread-safe: Must be called with mutex locked
 *
 * Frees all requests currently registered in the hash table.
 */
static void
free_hash_table_requests(T d)
{
    for (int i = 0; i < SOCKET_DNS_REQUEST_HASH_SIZE; i++)
    {
        free_request_list(d->request_hash[i]);
    }
}

/**
 * free_all_requests - Free all pending requests
 * @d: DNS resolver instance
 *
 * Thread-safe: Must be called with mutex locked
 *
 * Frees all requests from both queue and hash table.
 */
static void
free_all_requests(T d)
{
    free_queued_requests(d);
    free_hash_table_requests(d);
}

/**
 * shutdown_workers - Signal and wait for worker threads
 * @d: DNS resolver instance
 *
 * Signals shutdown and joins all worker threads.
 */
static void
shutdown_workers(T d)
{
    int i;

    pthread_mutex_lock(&d->mutex);
    d->shutdown = 1;
    pthread_cond_broadcast(&d->queue_cond);
    pthread_mutex_unlock(&d->mutex);

    for (i = 0; i < d->num_workers; i++)
    {
        pthread_join(d->workers[i], NULL);
    }
}

void
SocketDNS_free(T *dns)
{
    T d;

    assert(dns && *dns);

    d = *dns;

    shutdown_workers(d);

    pthread_mutex_lock(&d->mutex);
    free_all_requests(d);
    pthread_mutex_unlock(&d->mutex);

    cleanup_pipe(d);
    cleanup_mutex_cond(d);
    Arena_dispose(&d->arena);
    free(d);
    *dns = NULL;
}

/**
 * validate_resolve_params - Validate parameters for DNS resolution
 * @host: Hostname to validate
 * @port: Port number to validate
 *
 * Raises: SocketDNS_Failed on invalid parameters
 */
static void
validate_resolve_params(const char *host, int port)
{
    size_t host_len;

    host_len = strlen(host);
    if (host_len == 0 || host_len > SOCKET_ERROR_MAX_HOSTNAME)
    {
        SOCKET_ERROR_MSG("Invalid hostname length (max %d characters)", SOCKET_ERROR_MAX_HOSTNAME);
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    if (port < 0 || port > 65535)
    {
        SOCKET_ERROR_MSG("Invalid port number: %d (must be 0-65535)", port);
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }
}

/**
 * allocate_request_structure - Allocate request structure
 * @dns: DNS resolver instance
 *
 * Returns: Allocated request structure
 * Raises: SocketDNS_Failed on allocation failure
 *
 * Allocates memory for the request structure from arena.
 */
static struct Request_T *
allocate_request_structure(T dns)
{
    struct Request_T *req;

    req = ALLOC(dns->arena, sizeof(*req));
    if (!req)
    {
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate DNS request");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    return req;
}

/**
 * allocate_request_hostname - Allocate and copy hostname
 * @dns: DNS resolver instance
 * @req: Request structure to initialize
 * @host: Hostname to copy
 * @host_len: Length of hostname
 *
 * Raises: SocketDNS_Failed on allocation failure
 *
 * Allocates memory for hostname and copies it.
 */
static void
allocate_request_hostname(T dns, struct Request_T *req, const char *host, size_t host_len)
{
    req->host = ALLOC(dns->arena, host_len + 1);
    if (!req->host)
    {
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate hostname");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    strncpy(req->host, host, host_len + 1);
    req->host[host_len] = '\0';
}

/**
 * initialize_request_fields - Initialize request fields
 * @req: Request structure to initialize
 * @port: Port number
 * @callback: Completion callback
 * @data: User data for callback
 *
 * Sets all request fields to initial values.
 */
static void
initialize_request_fields(struct Request_T *req, int port, SocketDNS_Callback callback, void *data)
{
    req->port = port;
    req->callback = callback;
    req->callback_data = data;
    req->state = REQ_PENDING;
    req->result = NULL;
    req->error = 0;
    req->queue_next = NULL;
    req->hash_next = NULL;
    req->submit_time = time(NULL);
}

/**
 * allocate_request - Allocate and initialize request structure
 * @dns: DNS resolver instance
 * @host: Hostname to resolve
 * @host_len: Length of hostname
 * @port: Port number
 * @callback: Completion callback
 * @data: User data for callback
 *
 * Returns: Allocated request structure
 * Raises: SocketDNS_Failed on allocation failure
 *
 * Allocates and fully initializes a DNS request structure.
 */
static struct Request_T *
allocate_request(T dns, const char *host, size_t host_len, int port, SocketDNS_Callback callback, void *data)
{
    struct Request_T *req;

    req = allocate_request_structure(dns);
    allocate_request_hostname(dns, req, host, host_len);
    initialize_request_fields(req, port, callback, data);

    return req;
}

/**
 * hash_table_insert - Insert request into hash table
 * @dns: DNS resolver instance
 * @req: Request to insert
 *
 * Thread-safe: Must be called with mutex locked
 */
static void
hash_table_insert(T dns, struct Request_T *req)
{
    unsigned hash;

    hash = request_hash_function(req);
    req->hash_value = hash;
    req->hash_next = dns->request_hash[hash];
    dns->request_hash[hash] = req;
}

/**
 * queue_append - Append request to queue
 * @dns: DNS resolver instance
 * @req: Request to append
 *
 * Thread-safe: Must be called with mutex locked
 */
static void
queue_append(T dns, struct Request_T *req)
{
    if (dns->queue_tail)
    {
        dns->queue_tail->queue_next = req;
        dns->queue_tail = req;
    }
    else
    {
        dns->queue_head = req;
        dns->queue_tail = req;
    }
    dns->queue_size++;
}

/**
 * check_queue_limit - Check if queue has reached limit
 * @dns: DNS resolver instance
 *
 * Raises: SocketDNS_Failed if queue is full
 *
 * Thread-safe: Must be called with mutex locked
 */
static void
check_queue_limit(T dns)
{
    if (dns->queue_size >= dns->max_pending)
    {
        pthread_mutex_unlock(&dns->mutex);
        SOCKET_ERROR_MSG("DNS request queue full (max %zu pending)", dns->max_pending);
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }
}

/**
 * submit_dns_request - Submit request to queue and hash table
 * @dns: DNS resolver instance
 * @req: Request to submit
 *
 * Thread-safe: Must be called with mutex locked
 *
 * Inserts request into hash table, appends to queue, and signals workers.
 */
static void
submit_dns_request(T dns, struct Request_T *req)
{
    hash_table_insert(dns, req);
    queue_append(dns, req);
    pthread_cond_signal(&dns->queue_cond);
}

Request_T
SocketDNS_resolve(T dns, const char *host, int port, SocketDNS_Callback callback, void *data)
{
    struct Request_T *req;
    size_t host_len;

    assert(dns);
    assert(host);

    host_len = strlen(host);
    validate_resolve_params(host, port);
    req = allocate_request(dns, host, host_len, port, callback, data);

    pthread_mutex_lock(&dns->mutex);
    check_queue_limit(dns);
    submit_dns_request(dns, req);
    pthread_mutex_unlock(&dns->mutex);

    return (Request_T)req;
}

/**
 * hash_table_remove - Remove request from hash table
 * @dns: DNS resolver instance
 * @req: Request to remove
 *
 * Thread-safe: Must be called with mutex locked
 */
static void
hash_table_remove(T dns, struct Request_T *req)
{
    unsigned hash;
    struct Request_T **pp;

    hash = req->hash_value;
    pp = &dns->request_hash[hash];
    while (*pp)
    {
        if (*pp == req)
        {
            *pp = req->hash_next;
            break;
        }
        pp = &(*pp)->hash_next;
    }
}

/**
 * remove_from_queue_head - Remove request from queue head
 * @dns: DNS resolver instance
 * @req: Request to remove
 */
static void
remove_from_queue_head(T dns, struct Request_T *req)
{
    dns->queue_head = req->queue_next;
    if (!dns->queue_head)
        dns->queue_tail = NULL;
}

/**
 * remove_from_queue_middle - Remove request from queue middle/tail
 * @dns: DNS resolver instance
 * @req: Request to remove
 */
static void
remove_from_queue_middle(T dns, struct Request_T *req)
{
    struct Request_T *prev = dns->queue_head;
    while (prev && prev->queue_next != req)
        prev = prev->queue_next;
    if (prev)
    {
        prev->queue_next = req->queue_next;
        if (dns->queue_tail == req)
            dns->queue_tail = prev;
    }
}

/**
 * queue_remove - Remove request from queue
 * @dns: DNS resolver instance
 * @req: Request to remove
 *
 * Thread-safe: Must be called with mutex locked
 */
static void
queue_remove(T dns, struct Request_T *req)
{
    if (dns->queue_head == req)
        remove_from_queue_head(dns, req);
    else
        remove_from_queue_middle(dns, req);
    dns->queue_size--;
}

/**
 * cancel_pending_request - Cancel a pending request
 * @dns: DNS resolver instance
 * @req: Request to cancel
 *
 * Thread-safe: Must be called with mutex locked
 */
static void
cancel_pending_request(T dns, struct Request_T *req)
{
    queue_remove(dns, req);
    req->state = REQ_CANCELLED;
}

void
SocketDNS_cancel(T dns, Request_T req)
{
    struct Request_T *r = (struct Request_T *)req;

    assert(dns);
    assert(req);

    pthread_mutex_lock(&dns->mutex);

    if (r->state == REQ_PENDING)
    {
        cancel_pending_request(dns, r);
    }
    else if (r->state == REQ_PROCESSING)
    {
        r->state = REQ_CANCELLED;
    }

    hash_table_remove(dns, r);
    pthread_mutex_unlock(&dns->mutex);
}

int
SocketDNS_pollfd(T dns)
{
    assert(dns);
    return dns->pipefd[0];
}

int
SocketDNS_check(T dns)
{
    char buffer[SOCKET_DNS_PIPE_BUFFER_SIZE];
    ssize_t n;
    int count = 0;

    assert(dns);

    while ((n = read(dns->pipefd[0], buffer, sizeof(buffer))) > 0)
    {
        count += n;
    }

    return count;
}

struct addrinfo *
SocketDNS_getresult(T dns, Request_T req)
{
    struct Request_T *r = (struct Request_T *)req;
    struct addrinfo *result = NULL;

    assert(dns);
    assert(req);

    pthread_mutex_lock(&dns->mutex);

    if (r->state == REQ_COMPLETE)
    {
        result = r->result;
        r->result = NULL;

        hash_table_remove(dns, r);
    }

    pthread_mutex_unlock(&dns->mutex);

    return result;
}

#undef T
#undef Request_T

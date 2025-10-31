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

/* Hash table size for request lookup - prime number */
#define REQUEST_HASH_SIZE 1021

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
    struct Request_T *request_hash[REQUEST_HASH_SIZE]; /* Hash table for request lookup */
    pthread_mutex_t mutex;             /* Mutex for thread-safe operations */
    pthread_cond_t queue_cond;        /* Condition variable for queue */
    pthread_cond_t result_cond;       /* Condition variable for results */
    int shutdown;                      /* Shutdown flag */
    int pipefd[2];                     /* Pipe for completion signaling */
    unsigned request_counter;          /* Request ID counter */
};

/* Hash function for request handles */
static unsigned request_hash_function(struct Request_T *req)
{
    /* Use pointer value with golden ratio hash */
    uintptr_t ptr = (uintptr_t)req;
    return ((unsigned)ptr * HASH_GOLDEN_RATIO) % REQUEST_HASH_SIZE;
}

/* Signal completion via pipe */
static void signal_completion(T dns)
{
    char byte = 1;
    ssize_t n;

    /* Write to pipe (non-blocking, best effort) */
    n = write(dns->pipefd[1], &byte, 1);
    (void)n; /* Ignore result - pipe may be full, that's OK */
}

/* Worker thread function */
static void *worker_thread(void *arg)
{
    T dns = (T)arg;
    struct Request_T *req;
    struct addrinfo hints, *result = NULL;
    char port_str[16];
    int res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    while (1)
    {
        /* Get next request from queue */
        pthread_mutex_lock(&dns->mutex);

        /* Wait for request or shutdown */
        while (dns->queue_head == NULL && !dns->shutdown)
        {
            pthread_cond_wait(&dns->queue_cond, &dns->mutex);
        }

        /* Check for shutdown */
        if (dns->shutdown && dns->queue_head == NULL)
        {
            pthread_mutex_unlock(&dns->mutex);
            break;
        }

        /* Get request from queue */
        req = dns->queue_head;
        if (req)
        {
            dns->queue_head = req->queue_next;
            if (!dns->queue_head)
                dns->queue_tail = NULL;
            dns->queue_size--;
            req->queue_next = NULL;
            req->state = REQ_PROCESSING;
        }

        pthread_mutex_unlock(&dns->mutex);

        if (!req)
            continue;

        /* Perform DNS resolution */
        if (req->port > 0)
        {
            snprintf(port_str, sizeof(port_str), "%d", req->port);
            res = getaddrinfo(req->host, port_str, &hints, &result);
        }
        else
        {
            res = getaddrinfo(req->host, NULL, &hints, &result);
        }

        /* Store result */
        pthread_mutex_lock(&dns->mutex);

        if (req->state == REQ_PROCESSING) /* Not cancelled */
        {
            req->state = REQ_COMPLETE;
            req->result = result;
            req->error = res;

            /* Signal completion */
            signal_completion(dns);
            pthread_cond_broadcast(&dns->result_cond);
        }
        else
        {
            /* Request was cancelled, free result */
            if (result)
                freeaddrinfo(result);
        }

        pthread_mutex_unlock(&dns->mutex);

        /* Invoke callback if provided */
        if (req->callback && req->state == REQ_COMPLETE)
        {
            req->callback((Request_T)req, req->result, req->error, req->callback_data);
        }
    }

    return NULL;
}

T SocketDNS_new(void)
{
    T dns;
    int i;
    int pipe_result;

    /* Allocate resolver structure */
    dns = calloc(1, sizeof(*dns));
    if (!dns)
    {
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate DNS resolver");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    /* Create arena */
    dns->arena = Arena_new();
    if (!dns->arena)
    {
        free(dns);
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate DNS resolver arena");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    /* Initialize configuration */
    dns->num_workers = SOCKET_DNS_THREAD_COUNT;
    dns->max_pending = SOCKET_DNS_MAX_PENDING;
    dns->shutdown = 0;
    dns->request_counter = 0;

    /* Initialize mutex and condition variables */
    if (pthread_mutex_init(&dns->mutex, NULL) != 0)
    {
        Arena_dispose(&dns->arena);
        free(dns);
        SOCKET_ERROR_MSG("Failed to initialize DNS resolver mutex");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    if (pthread_cond_init(&dns->queue_cond, NULL) != 0)
    {
        pthread_mutex_destroy(&dns->mutex);
        Arena_dispose(&dns->arena);
        free(dns);
        SOCKET_ERROR_MSG("Failed to initialize DNS resolver condition variable");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    if (pthread_cond_init(&dns->result_cond, NULL) != 0)
    {
        pthread_cond_destroy(&dns->queue_cond);
        pthread_mutex_destroy(&dns->mutex);
        Arena_dispose(&dns->arena);
        free(dns);
        SOCKET_ERROR_MSG("Failed to initialize DNS resolver result condition variable");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    /* Create pipe for completion signaling */
    pipe_result = pipe(dns->pipefd);
    if (pipe_result < 0)
    {
        pthread_cond_destroy(&dns->result_cond);
        pthread_cond_destroy(&dns->queue_cond);
        pthread_mutex_destroy(&dns->mutex);
        Arena_dispose(&dns->arena);
        free(dns);
        SOCKET_ERROR_FMT("Failed to create completion pipe");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    /* Initialize hash table */
    memset(dns->request_hash, 0, sizeof(dns->request_hash));

    /* Initialize queue */
    dns->queue_head = NULL;
    dns->queue_tail = NULL;
    dns->queue_size = 0;

    /* Allocate worker thread array */
    dns->workers = ALLOC(dns->arena, dns->num_workers * sizeof(pthread_t));
    if (!dns->workers)
    {
        SAFE_CLOSE(dns->pipefd[0]);
        SAFE_CLOSE(dns->pipefd[1]);
        pthread_cond_destroy(&dns->result_cond);
        pthread_cond_destroy(&dns->queue_cond);
        pthread_mutex_destroy(&dns->mutex);
        Arena_dispose(&dns->arena);
        free(dns);
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate worker thread array");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    /* Create worker threads */
    for (i = 0; i < dns->num_workers; i++)
    {
        if (pthread_create(&dns->workers[i], NULL, worker_thread, dns) != 0)
        {
            /* Failed to create thread - shutdown */
            dns->shutdown = 1;
            pthread_cond_broadcast(&dns->queue_cond);

            /* Join threads created so far */
            for (int j = 0; j < i; j++)
            {
                pthread_join(dns->workers[j], NULL);
            }

            free(dns->workers);
            SAFE_CLOSE(dns->pipefd[0]);
            SAFE_CLOSE(dns->pipefd[1]);
            pthread_cond_destroy(&dns->result_cond);
            pthread_cond_destroy(&dns->queue_cond);
            pthread_mutex_destroy(&dns->mutex);
            Arena_dispose(&dns->arena);
            free(dns);
            SOCKET_ERROR_FMT("Failed to create DNS worker thread %d", i);
            RAISE_DNS_ERROR(SocketDNS_Failed);
        }
    }

    return dns;
}

void SocketDNS_free(T *dns)
{
    T d;
    int i;
    struct Request_T *req, *next;

    assert(dns && *dns);

    d = *dns;

    /* Signal shutdown */
    pthread_mutex_lock(&d->mutex);
    d->shutdown = 1;
    pthread_cond_broadcast(&d->queue_cond);
    pthread_mutex_unlock(&d->mutex);

    /* Join worker threads */
    for (i = 0; i < d->num_workers; i++)
    {
        pthread_join(d->workers[i], NULL);
    }

    /* Cancel and free all pending requests */
    pthread_mutex_lock(&d->mutex);

    /* Free queue requests (free getaddrinfo results only - hostname from Arena) */
    req = d->queue_head;
    while (req)
    {
        next = req->queue_next;
        if (req->result)
            freeaddrinfo(req->result);
        req = next;
    }

    /* Free hash table requests (free getaddrinfo results only) */
    for (i = 0; i < REQUEST_HASH_SIZE; i++)
    {
        req = d->request_hash[i];
        while (req)
        {
            next = req->hash_next;
            if (req->result)
                freeaddrinfo(req->result);
            req = next;
        }
    }

    pthread_mutex_unlock(&d->mutex);

    /* Cleanup resources */
    SAFE_CLOSE(d->pipefd[0]);
    SAFE_CLOSE(d->pipefd[1]);
    pthread_cond_destroy(&d->result_cond);
    pthread_cond_destroy(&d->queue_cond);
    pthread_mutex_destroy(&d->mutex);
    Arena_dispose(&d->arena);
    free(d);
    *dns = NULL;
}

Request_T SocketDNS_resolve(T dns, const char *host, int port, SocketDNS_Callback callback, void *data)
{
    struct Request_T *req;
    size_t host_len;
    unsigned hash;

    assert(dns);
    assert(host);

    /* Validate hostname length */
    host_len = strlen(host);
    if (host_len == 0 || host_len > SOCKET_ERROR_MAX_HOSTNAME)
    {
        SOCKET_ERROR_MSG("Invalid hostname length (max %d characters)", SOCKET_ERROR_MAX_HOSTNAME);
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    /* Validate port if provided */
    if (port < 0 || port > 65535)
    {
        SOCKET_ERROR_MSG("Invalid port number: %d (must be 0-65535)", port);
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    /* Allocate request */
    req = ALLOC(dns->arena, sizeof(*req));
    if (!req)
    {
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate DNS request");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    /* Allocate hostname */
    req->host = ALLOC(dns->arena, host_len + 1);
    if (!req->host)
    {
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate hostname");
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    /* Initialize request */
    strncpy(req->host, host, host_len + 1);
    req->host[host_len] = '\0';
    req->port = port;
    req->callback = callback;
    req->callback_data = data;
    req->state = REQ_PENDING;
    req->result = NULL;
    req->error = 0;
    req->queue_next = NULL;
    req->hash_next = NULL;
    req->submit_time = time(NULL);

    /* Add to hash table */
    pthread_mutex_lock(&dns->mutex);

    /* Check queue size limit */
    if (dns->queue_size >= dns->max_pending)
    {
        pthread_mutex_unlock(&dns->mutex);
        SOCKET_ERROR_MSG("DNS request queue full (max %zu pending)", dns->max_pending);
        RAISE_DNS_ERROR(SocketDNS_Failed);
    }

    hash = request_hash_function(req);
    req->hash_value = hash;
    req->hash_next = dns->request_hash[hash];
    dns->request_hash[hash] = req;

    /* Add to queue */
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

    /* Signal worker threads */
    pthread_cond_signal(&dns->queue_cond);
    pthread_mutex_unlock(&dns->mutex);

    return (Request_T)req;
}

void SocketDNS_cancel(T dns, Request_T req)
{
    struct Request_T *r = (struct Request_T *)req;
    struct Request_T **pp;
    unsigned hash;

    assert(dns);
    assert(req);

    pthread_mutex_lock(&dns->mutex);

    /* Check if request is still pending */
    if (r->state == REQ_PENDING)
    {
        /* Remove from queue */
        if (dns->queue_head == r)
        {
            dns->queue_head = r->queue_next;
            if (!dns->queue_head)
                dns->queue_tail = NULL;
        }
        else
        {
            struct Request_T *prev = dns->queue_head;
            while (prev && prev->queue_next != r)
                prev = prev->queue_next;
            if (prev)
            {
                prev->queue_next = r->queue_next;
                if (dns->queue_tail == r)
                    dns->queue_tail = prev;
            }
        }
        dns->queue_size--;

        /* Mark as cancelled */
        r->state = REQ_CANCELLED;
    }
    else if (r->state == REQ_PROCESSING)
    {
        /* Mark as cancelled - worker will clean up */
        r->state = REQ_CANCELLED;
    }

    /* Remove from hash table */
    hash = r->hash_value;
    pp = &dns->request_hash[hash];
    while (*pp)
    {
        if (*pp == r)
        {
            *pp = r->hash_next;
            break;
        }
        pp = &(*pp)->hash_next;
    }

    pthread_mutex_unlock(&dns->mutex);
}

int SocketDNS_pollfd(T dns)
{
    assert(dns);
    return dns->pipefd[0]; /* Read end of pipe */
}

int SocketDNS_check(T dns)
{
    char buffer[256];
    ssize_t n;
    int count = 0;

    assert(dns);

    /* Drain pipe (read all available bytes) */
    while ((n = read(dns->pipefd[0], buffer, sizeof(buffer))) > 0)
    {
        count += n;
    }

    /* Return number of bytes read (indicates completion count) */
    return count;
}

struct addrinfo *SocketDNS_getresult(T dns, Request_T req)
{
    struct Request_T *r = (struct Request_T *)req;
    struct addrinfo *result = NULL;

    assert(dns);
    assert(req);

    pthread_mutex_lock(&dns->mutex);

    if (r->state == REQ_COMPLETE)
    {
        result = r->result;
        r->result = NULL; /* Transfer ownership */

        /* Remove from hash table */
        unsigned hash = r->hash_value;
        struct Request_T **pp = &dns->request_hash[hash];
        while (*pp)
        {
            if (*pp == r)
            {
                *pp = r->hash_next;
                break;
            }
            pp = &(*pp)->hash_next;
        }
    }

    pthread_mutex_unlock(&dns->mutex);

    return result;
}

#undef T
#undef Request_T

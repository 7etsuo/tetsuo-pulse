/**
 * SocketPoll.c - Event polling implementation using epoll
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * PLATFORM: Linux-only (requires epoll)
 * - Linux: Full support via epoll (kernel 2.6+)
 * - BSD/macOS: Not supported (would need kqueue backend)
 * - Windows: Not supported (would need IOCP backend)
 * - Portable: Could fall back to poll() for basic portability
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>

#include "Arena.h"
#include "Except.h"
#include "Socket.h"
#include "SocketPoll.h"
#include "SocketConfig.h"
#include "SocketError.h"

#define T SocketPoll_T

Except_T SocketPoll_Failed = {"SocketPoll operation failed"};

/* Thread-local exception for detailed error messages
 * This is a COPY of the base exception with thread-local reason string.
 * Each thread gets its own exception instance, preventing race conditions
 * when multiple threads raise the same exception type simultaneously. */
#ifdef _WIN32
static __declspec(thread) Except_T SocketPoll_DetailedException;
#else
static __thread Except_T SocketPoll_DetailedException;
#endif

/* Macro to raise exception with detailed error message
 * Creates a thread-local copy of the exception with detailed reason */
#define RAISE_POLL_ERROR(exception)                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        SocketPoll_DetailedException = (exception);                                                                    \
        SocketPoll_DetailedException.reason = socket_error_buf;                                                        \
        RAISE(SocketPoll_DetailedException);                                                                           \
    } while (0)

/* Socket data mapping entry */
typedef struct SocketData
{
    Socket_T socket;
    void *data;
    struct SocketData *next;
} SocketData;

/* Use configured hash table size for socket data mapping */
#define SOCKET_DATA_HASH_SIZE SOCKET_HASH_TABLE_SIZE

struct T
{
    int epfd;
    int maxevents;
    struct epoll_event *events;
    SocketEvent_T *socketevents;
    Arena_T arena;
    SocketData *socket_data_map[SOCKET_DATA_HASH_SIZE]; /* Hash table for O(1) socket->data mapping */
    pthread_mutex_t mutex;                              /* Mutex for thread-safe socket data mapping */
};

/* Hash function for socket file descriptors
 *
 * Uses multiplicative hashing with golden ratio constant for better
 * distribution than simple modulo, especially for sequential file descriptors.
 *
 * The constant 2654435761u = 2^32 / phi where phi = (1 + sqrt(5)) / 2
 * is the golden ratio. This value has the property that when used in
 * multiplicative hashing, it spreads consecutive integers uniformly
 * across the hash space, preventing clustering that would occur with
 * sequential FDs using simple modulo.
 *
 * IMPORTANT: Hash table size (SOCKET_DATA_HASH_SIZE) should be a prime number
 * for optimal distribution and minimal collisions. The configured value (1021)
 * is prime.
 *
 * Reference: Knuth, TAOCP Vol 3, Section 6.4
 */
static unsigned socket_hash(const Socket_T socket)
{
    int fd;

    assert(socket);
    fd = Socket_fd(socket);

    /* Defensive check: socket FDs should never be negative */
    assert(fd >= 0);

    /* Multiplicative hash for better distribution of sequential FDs */
    return ((unsigned)fd * 2654435761u) % SOCKET_DATA_HASH_SIZE;
}

/* translate_to_epoll - Convert poll events to epoll events
 * @events: Poll event flags (POLL_READ, POLL_WRITE)
 *
 * Returns: epoll event flags with edge-triggered mode (EPOLLET)
 *
 * Edge-triggered mode provides better performance by reducing spurious
 * wakeups. Applications must read/write until EAGAIN. */
static unsigned translate_to_epoll(unsigned events)
{
    unsigned epoll_events = 0;

    if (events & POLL_READ)
        epoll_events |= EPOLLIN;
    if (events & POLL_WRITE)
        epoll_events |= EPOLLOUT;

    return epoll_events | EPOLLET;
}

/* translate_from_epoll - Convert epoll events to poll events
 * @epoll_events: epoll event flags
 *
 * Returns: Poll event flags (POLL_READ, POLL_WRITE, POLL_ERROR, POLL_HANGUP) */
static unsigned translate_from_epoll(unsigned epoll_events)
{
    unsigned events = 0;

    if (epoll_events & EPOLLIN)
        events |= POLL_READ;
    if (epoll_events & EPOLLOUT)
        events |= POLL_WRITE;
    if (epoll_events & EPOLLERR)
        events |= POLL_ERROR;
    if (epoll_events & EPOLLHUP)
        events |= POLL_HANGUP;

    return events;
}

/* socket_data_add - Add socket->data mapping to hash table
 * @poll: Poll instance
 * @socket: Socket to map
 * @data: User data to associate
 *
 * Raises: SocketPoll_Failed if allocation fails
 *
 * O(1) operation. Thread-safe via internal mutex. */
static void socket_data_add(T poll, Socket_T socket, void *data)
{
    unsigned hash = socket_hash(socket);
    SocketData *entry;

    /* Allocate entry - this is the only operation that can fail */
    entry = ALLOC(poll->arena, sizeof(*entry));
    if (!entry)
    {
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate socket data mapping");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    /* Initialize entry before adding to map - atomic from this point */
    entry->socket = socket;
    entry->data = data;

    /* Add to hash table atomically */
    pthread_mutex_lock(&poll->mutex);
    entry->next = poll->socket_data_map[hash];
    poll->socket_data_map[hash] = entry;
    pthread_mutex_unlock(&poll->mutex);
}

/* socket_data_get - Retrieve user data for socket
 * @poll: Poll instance
 * @socket: Socket to look up
 *
 * Returns: User data or NULL if not found
 *
 * O(1) average case. Thread-safe via internal mutex. */
static void *socket_data_get(T poll, Socket_T socket)
{
    unsigned hash = socket_hash(socket);
    void *data = NULL;

    pthread_mutex_lock(&poll->mutex);
    SocketData *entry = poll->socket_data_map[hash];
    while (entry)
    {
        if (entry->socket == socket)
        {
            data = entry->data;
            break;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&poll->mutex);

    return data;
}

/* socket_data_remove - Remove socket->data mapping from hash table
 * @poll: Poll instance
 * @socket: Socket to remove
 *
 * Silently succeeds if socket not found. O(1) average case.
 * Thread-safe via internal mutex. Memory is freed with arena. */
static void socket_data_remove(T poll, Socket_T socket)
{
    unsigned hash = socket_hash(socket);

    pthread_mutex_lock(&poll->mutex);

    SocketData **pp = &poll->socket_data_map[hash];
    while (*pp)
    {
        if ((*pp)->socket == socket)
        {
            SocketData *old = *pp;
            *pp = old->next;
            /* Memory is managed by arena, no need to free */
            pthread_mutex_unlock(&poll->mutex);
            return;
        }
        pp = &(*pp)->next;
    }

    pthread_mutex_unlock(&poll->mutex);
}

/* socket_data_update - Update user data for existing socket mapping
 * @poll: Poll instance
 * @socket: Socket to update
 * @data: New user data
 *
 * Atomically updates existing mapping or inserts if not found (upsert).
 * The fallback insert should not occur in normal operation (socket should
 * already be in map via SocketPoll_add), but provides robustness.
 * Thread-safe via internal mutex. */
static void socket_data_update(T poll, Socket_T socket, void *data)
{
    unsigned hash = socket_hash(socket);
    SocketData *entry;
    int found = 0;

    pthread_mutex_lock(&poll->mutex);

    /* Find and update existing entry */
    entry = poll->socket_data_map[hash];
    while (entry)
    {
        if (entry->socket == socket)
        {
            entry->data = data;
            found = 1;
            break;
        }
        entry = entry->next;
    }

    if (!found)
    {
        /* This indicates a programming error - socket should already be in map.
         * This fallback provides robustness but should not occur in normal operation. */
#ifndef NDEBUG
        fprintf(
            stderr,
            "WARNING: socket_data_update fallback - socket should have been added via SocketPoll_add first (fd %d)\n",
            Socket_fd(socket));
#endif

        /* Allocate new entry while holding lock */
        entry = ALLOC(poll->arena, sizeof(*entry));
        if (!entry)
        {
            pthread_mutex_unlock(&poll->mutex);
            SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate socket data mapping");
            RAISE_POLL_ERROR(SocketPoll_Failed);
        }
        entry->socket = socket;
        entry->data = data;
        entry->next = poll->socket_data_map[hash];
        poll->socket_data_map[hash] = entry;
    }

    pthread_mutex_unlock(&poll->mutex);
}

T SocketPoll_new(int maxevents)
{
    T poll;

    assert(SOCKET_VALID_POLL_EVENTS(maxevents));

    /* Enforce configured limit */
    if (maxevents > SOCKET_MAX_POLL_EVENTS)
        maxevents = SOCKET_MAX_POLL_EVENTS;

    poll = malloc(sizeof(*poll));
    if (poll == NULL)
    {
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate poll structure");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    poll->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (poll->epfd < 0)
    {
        SOCKET_ERROR_FMT("Failed to create epoll instance");
        free(poll);
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    poll->maxevents = maxevents;
    poll->arena = Arena_new();
    if (!poll->arena)
    {
        SAFE_CLOSE(poll->epfd);
        free(poll);
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate poll arena");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    poll->events = CALLOC(poll->arena, maxevents, sizeof(*poll->events));
    poll->socketevents = CALLOC(poll->arena, maxevents, sizeof(*poll->socketevents));

    if (!poll->events || !poll->socketevents)
    {
        SAFE_CLOSE(poll->epfd);
        Arena_dispose(&poll->arena);
        free(poll);
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate event arrays");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    /* Initialize hash table */
    memset(poll->socket_data_map, 0, sizeof(poll->socket_data_map));

    /* Initialize mutex */
    if (pthread_mutex_init(&poll->mutex, NULL) != 0)
    {
        SAFE_CLOSE(poll->epfd);
        Arena_dispose(&poll->arena);
        free(poll);
        SOCKET_ERROR_MSG("Failed to initialize poll mutex");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    return poll;
}

void SocketPoll_free(T *poll)
{
    assert(poll && *poll);

    if ((*poll)->epfd >= 0)
        SAFE_CLOSE((*poll)->epfd);

    /* Destroy mutex */
    pthread_mutex_destroy(&(*poll)->mutex);

    if ((*poll)->arena)
        Arena_dispose(&(*poll)->arena);

    free(*poll);
    *poll = NULL;
}

void SocketPoll_add(T poll, Socket_T socket, unsigned events, void *data)
{
    struct epoll_event ev;
    int fd;

    assert(poll);
    assert(socket);

    fd = Socket_fd(socket);

    /* Set non-blocking mode before adding to epoll
     * If this fails, we don't want the socket in epoll */
    Socket_setnonblocking(socket);

    memset(&ev, 0, sizeof(ev));
    ev.events = translate_to_epoll(events);
    ev.data.ptr = socket;

    if (epoll_ctl(poll->epfd, EPOLL_CTL_ADD, fd, &ev) < 0)
    {
        if (errno == EEXIST)
        {
            SOCKET_ERROR_FMT("Socket already in poll set (fd=%d)", fd);
        }
        else
        {
            SOCKET_ERROR_FMT("Failed to add socket to poll (fd=%d)", fd);
        }
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    /* Store the socket->data mapping - remove from epoll on failure */
    TRY socket_data_add(poll, socket, data);
    EXCEPT(SocketPoll_Failed)
    /* Remove from epoll to prevent orphaned entry */
    epoll_ctl(poll->epfd, EPOLL_CTL_DEL, fd, NULL);
    RERAISE;
    END_TRY;
}

void SocketPoll_mod(T poll, Socket_T socket, unsigned events, void *data)
{
    struct epoll_event ev;
    int fd;

    assert(poll);
    assert(socket);

    fd = Socket_fd(socket);

    memset(&ev, 0, sizeof(ev));
    ev.events = translate_to_epoll(events);
    ev.data.ptr = socket;

    if (epoll_ctl(poll->epfd, EPOLL_CTL_MOD, fd, &ev) < 0)
    {
        if (errno == ENOENT)
        {
            SOCKET_ERROR_FMT("Socket not in poll set (fd=%d)", fd);
        }
        else
        {
            SOCKET_ERROR_FMT("Failed to modify socket in poll (fd=%d)", fd);
        }
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    /* Update the socket->data mapping atomically */
    socket_data_update(poll, socket, data);
}

void SocketPoll_del(T poll, Socket_T socket)
{
    int fd;

    assert(poll);
    assert(socket);

    fd = Socket_fd(socket);

    if (epoll_ctl(poll->epfd, EPOLL_CTL_DEL, fd, NULL) < 0)
    {
        if (errno != ENOENT)
        {
            SOCKET_ERROR_FMT("Failed to remove socket from poll (fd=%d)", fd);
            RAISE_POLL_ERROR(SocketPoll_Failed);
        }
    }

    /* Remove the socket->data mapping */
    socket_data_remove(poll, socket);
}

int SocketPoll_wait(T poll, SocketEvent_T **events, int timeout)
{
    int nfds;
    int i;

    assert(poll);
    assert(events);

    nfds = epoll_wait(poll->epfd, poll->events, poll->maxevents, timeout);
    if (nfds < 0)
    {
        if (errno == EINTR)
            return 0;
        SOCKET_ERROR_FMT("epoll_wait failed (timeout=%d)", timeout);
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    for (i = 0; i < nfds; i++)
    {
        Socket_T socket = poll->events[i].data.ptr;
        poll->socketevents[i].socket = socket;
        poll->socketevents[i].data = socket_data_get(poll, socket);
        poll->socketevents[i].events = translate_from_epoll(poll->events[i].events);
    }

    *events = poll->socketevents;
    return nfds;
}

#undef T

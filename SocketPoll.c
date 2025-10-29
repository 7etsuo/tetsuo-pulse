/**
 * SocketPoll.c - Event polling implementation with backend abstraction
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * PLATFORM: Cross-platform (Linux/BSD/macOS/POSIX)
 * - Linux: epoll backend (best performance)
 * - BSD/macOS: kqueue backend (best performance)
 * - Other POSIX: poll(2) fallback (portable)
 *
 * Backend selection is done at compile-time via Makefile
 * See SocketPoll_backend.h for backend interface details
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include "Arena.h"
#include "Except.h"
#include "Socket.h"
#include "SocketPoll.h"
#include "SocketPoll_backend.h"
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
    PollBackend_T backend; /* Backend-specific poll implementation */
    int maxevents;
    SocketEvent_T *socketevents;
    Arena_T arena;
    SocketData *socket_data_map[SOCKET_DATA_HASH_SIZE]; /* Hash table for O(1) socket->data mapping */
    pthread_mutex_t mutex;                              /* Mutex for thread-safe socket data mapping */
};

/* Hash function for socket file descriptors */
static unsigned socket_hash(const Socket_T socket)
{
    int fd;

    assert(socket);
    fd = Socket_fd(socket);

    /* Defensive check: socket FDs should never be negative */
    assert(fd >= 0);

    /* Multiplicative hash with golden ratio */
    return ((unsigned)fd * 2654435761u) % SOCKET_DATA_HASH_SIZE;
}

/* Add socket->data mapping to hash table */
static void socket_data_add(T poll, Socket_T socket, void *data)
{
    unsigned hash = socket_hash(socket);
    SocketData *entry;

    /* Allocate entry */
    entry = ALLOC(poll->arena, sizeof(*entry));
    if (!entry)
    {
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate socket data mapping");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    /* Initialize entry */
    entry->socket = socket;
    entry->data = data;

    /* Add to hash table atomically */
    pthread_mutex_lock(&poll->mutex);
    entry->next = poll->socket_data_map[hash];
    poll->socket_data_map[hash] = entry;
    pthread_mutex_unlock(&poll->mutex);
}

/* Retrieve user data for socket */
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

/* Remove socket->data mapping from hash table */
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
            /* Memory managed by arena */
            pthread_mutex_unlock(&poll->mutex);
            return;
        }
        pp = &(*pp)->next;
    }

    pthread_mutex_unlock(&poll->mutex);
}

/* Update user data for existing socket mapping */
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
        /* Programming error - socket should already be in map */
#ifndef NDEBUG
        fprintf(stderr, "WARNING: socket_data_update fallback (fd %d)\n", Socket_fd(socket));
#endif

        /* Allocate new entry */
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

    poll->backend = backend_new(maxevents);
    if (!poll->backend)
    {
        SOCKET_ERROR_FMT("Failed to create %s backend", backend_name());
        free(poll);
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    poll->maxevents = maxevents;
    poll->arena = Arena_new();
    if (!poll->arena)
    {
        backend_free(poll->backend);
        free(poll);
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate poll arena");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    poll->socketevents = CALLOC(poll->arena, maxevents, sizeof(*poll->socketevents));

    if (!poll->socketevents)
    {
        backend_free(poll->backend);
        Arena_dispose(&poll->arena);
        free(poll);
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate event arrays");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    /* Initialize hash table to NULL */
    memset(poll->socket_data_map, 0, sizeof(poll->socket_data_map));

    /* Initialize mutex */
    if (pthread_mutex_init(&poll->mutex, NULL) != 0)
    {
        backend_free(poll->backend);
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

    if ((*poll)->backend)
        backend_free((*poll)->backend);

    /* Destroy mutex */
    pthread_mutex_destroy(&(*poll)->mutex);

    if ((*poll)->arena)
        Arena_dispose(&(*poll)->arena);

    free(*poll);
    *poll = NULL;
}

void SocketPoll_add(T poll, Socket_T socket, unsigned events, void *data)
{
    int fd;

    assert(poll);
    assert(socket);

    fd = Socket_fd(socket);

    /* Set non-blocking mode before adding to poll */
    Socket_setnonblocking(socket);

    if (backend_add(poll->backend, fd, events) < 0)
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

    /* Store socket->data mapping */
    TRY socket_data_add(poll, socket, data);
    EXCEPT(SocketPoll_Failed)
    /* Remove from poll to prevent orphaned entry */
    backend_del(poll->backend, fd);
    RERAISE;
    END_TRY;
}

void SocketPoll_mod(T poll, Socket_T socket, unsigned events, void *data)
{
    int fd;

    assert(poll);
    assert(socket);

    fd = Socket_fd(socket);

    if (backend_mod(poll->backend, fd, events) < 0)
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

    if (backend_del(poll->backend, fd) < 0)
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

    nfds = backend_wait(poll->backend, timeout);
    if (nfds < 0)
    {
        if (errno == EINTR)
            return 0;
        SOCKET_ERROR_FMT("%s backend wait failed (timeout=%d)", backend_name(), timeout);
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    /* Translate backend events to SocketEvent_T structures */
    for (i = 0; i < nfds; i++)
    {
        int fd;
        unsigned event_flags;
        Socket_T socket;

        /* Get event from backend */
        if (backend_get_event(poll->backend, i, &fd, &event_flags) < 0)
        {
            SOCKET_ERROR_MSG("Failed to get event from backend");
            RAISE_POLL_ERROR(SocketPoll_Failed);
        }

        /* Find socket by FD */
        socket = NULL;
        for (int hash = 0; hash < SOCKET_DATA_HASH_SIZE; hash++)
        {
            SocketData *entry = poll->socket_data_map[hash];
            while (entry)
            {
                if (Socket_fd(entry->socket) == fd)
                {
                    socket = entry->socket;
                    break;
                }
                entry = entry->next;
            }
            if (socket)
                break;
        }

        if (!socket)
        {
            /* Socket not found */
            SOCKET_ERROR_MSG("Event for unknown socket (fd=%d)", fd);
            continue;
        }

        poll->socketevents[i].socket = socket;
        poll->socketevents[i].data = socket_data_get(poll, socket);
        poll->socketevents[i].events = event_flags;
    }

    *events = poll->socketevents;
    return nfds;
}

#undef T

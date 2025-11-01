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

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "poll/SocketPoll.h"
#include "poll/SocketPoll_backend.h"
#include "core/SocketConfig.h"
#include "core/SocketError.h"

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

/* FD to socket mapping entry for reverse lookup */
typedef struct FdSocketEntry
{
    int fd;
    Socket_T socket;
    struct FdSocketEntry *next;
} FdSocketEntry;

/* Use configured hash table size for socket data mapping */
#define SOCKET_DATA_HASH_SIZE SOCKET_HASH_TABLE_SIZE

struct T
{
    PollBackend_T backend; /* Backend-specific poll implementation */
    int maxevents;
    SocketEvent_T *socketevents;
    Arena_T arena;
    SocketData *socket_data_map[SOCKET_DATA_HASH_SIZE];     /* Hash table for O(1) socket->data mapping */
    FdSocketEntry *fd_to_socket_map[SOCKET_DATA_HASH_SIZE]; /* Hash table for O(1) fd->socket mapping */
    pthread_mutex_t mutex;                                  /* Mutex for thread-safe socket data mapping */
};

/* ==================== Hash Functions ==================== */

/**
 * socket_hash - Hash function for socket file descriptors
 * @socket: Socket to hash
 *
 * Returns: Hash value in range [0, SOCKET_DATA_HASH_SIZE)
 *
 * Uses multiplicative hashing with the golden ratio constant for
 * good distribution across hash buckets. This provides O(1) average
 * case performance for socket data lookups.
 */
static unsigned socket_hash(const Socket_T socket)
{
    int fd;

    assert(socket);
    fd = Socket_fd(socket);

    /* Defensive check: socket FDs should never be negative */
    assert(fd >= 0);

    /* Multiplicative hash with golden ratio for good distribution */
    return ((unsigned)fd * HASH_GOLDEN_RATIO) % SOCKET_DATA_HASH_SIZE;
}

/* ==================== Socket Data Management ==================== */

/**
 * socket_data_add - Add socket->data mapping to hash tables
 * @poll: Poll instance
 * @socket: Socket to add
 * @data: User data to associate with socket
 *
 * Raises: SocketPoll_Failed on allocation failure
 * Thread-safe: Yes - uses internal mutex
 *
 * Adds both socket->data and fd->socket mappings to enable O(1)
 * lookups in both directions. The fd->socket mapping provides
 * efficient reverse lookup during event processing.
 */
static void socket_data_add(T poll, Socket_T socket, void *data)
{
    unsigned hash = socket_hash(socket);
    unsigned fd_hash;
    int fd;
    SocketData *data_entry;
    FdSocketEntry *fd_entry;

    fd = Socket_fd(socket);
    fd_hash = ((unsigned)fd * HASH_GOLDEN_RATIO) % SOCKET_DATA_HASH_SIZE;

    /* Allocate socket->data entry */
    data_entry = ALLOC(poll->arena, sizeof(*data_entry));
    if (!data_entry)
    {
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate socket data mapping");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    /* Allocate fd->socket entry */
    fd_entry = ALLOC(poll->arena, sizeof(*fd_entry));
    if (!fd_entry)
    {
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate fd to socket mapping");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    /* Initialize entries */
    data_entry->socket = socket;
    data_entry->data = data;

    fd_entry->fd = fd;
    fd_entry->socket = socket;

    /* Add to hash tables atomically */
    pthread_mutex_lock(&poll->mutex);
    data_entry->next = poll->socket_data_map[hash];
    poll->socket_data_map[hash] = data_entry;

    fd_entry->next = poll->fd_to_socket_map[fd_hash];
    poll->fd_to_socket_map[fd_hash] = fd_entry;
    pthread_mutex_unlock(&poll->mutex);
}

/**
 * socket_data_get - Retrieve user data for socket
 * @poll: Poll instance
 * @socket: Socket to look up
 *
 * Returns: User data associated with socket, or NULL if not found
 * Thread-safe: Yes - uses internal mutex
 *
 * Performs O(1) average case lookup in the socket data hash table.
 * Returns the user data pointer that was associated with the socket
 * when it was added to the poll.
 */
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

/**
 * socket_data_remove - Remove socket->data mapping from hash tables
 * @poll: Poll instance
 * @socket: Socket to remove
 *
 * Thread-safe: Yes - uses internal mutex
 *
 * Removes both socket->data and fd->socket mappings from the hash tables.
 * Memory is managed by arena - no explicit freeing needed.
 */
static void socket_data_remove(T poll, Socket_T socket)
{
    unsigned hash = socket_hash(socket);
    unsigned fd_hash;
    int fd;

    fd = Socket_fd(socket);
    fd_hash = ((unsigned)fd * HASH_GOLDEN_RATIO) % SOCKET_DATA_HASH_SIZE;

    pthread_mutex_lock(&poll->mutex);

    /* Remove from socket->data hash table */
    SocketData **pp = &poll->socket_data_map[hash];
    while (*pp)
    {
        if ((*pp)->socket == socket)
        {
            SocketData *old = *pp;
            *pp = old->next;
            /* Memory managed by arena - no free needed */
            break;
        }
        pp = &(*pp)->next;
    }

    /* Remove from fd->socket hash table */
    FdSocketEntry **fd_pp = &poll->fd_to_socket_map[fd_hash];
    while (*fd_pp)
    {
        if ((*fd_pp)->fd == fd)
        {
            FdSocketEntry *old = *fd_pp;
            *fd_pp = old->next;
            /* Memory managed by arena - no free needed */
            break;
        }
        fd_pp = &(*fd_pp)->next;
    }

    pthread_mutex_unlock(&poll->mutex);
}

/**
 * socket_data_update - Update user data for existing socket mapping
 * @poll: Poll instance
 * @socket: Socket whose data to update
 * @data: New user data to associate
 *
 * Raises: SocketPoll_Failed on allocation failure (fallback case only)
 * Thread-safe: Yes - uses internal mutex
 *
 * Updates the user data associated with an existing socket. If the socket
 * is not found in the map (programming error), it falls back to adding
 * a new entry. This fallback should not normally occur in correct usage.
 */
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

        /* Allocate new entry as fallback */
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

    /* Initialize hash tables to NULL */
    memset(poll->socket_data_map, 0, sizeof(poll->socket_data_map));
    memset(poll->fd_to_socket_map, 0, sizeof(poll->fd_to_socket_map));

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

/* ==================== Event Translation Functions ==================== */

/**
 * find_socket_by_fd - Find socket by file descriptor
 * @poll: Poll instance
 * @fd: File descriptor to search for
 *
 * Returns: Socket_T if found, NULL otherwise
 * Thread-safe: No (must be called with poll mutex held)
 *
 * Performs O(1) lookup using the fd_to_socket_map hash table.
 * This provides efficient reverse lookup during event processing.
 */
static Socket_T find_socket_by_fd(T poll, int fd)
{
    unsigned fd_hash = ((unsigned)fd * HASH_GOLDEN_RATIO) % SOCKET_DATA_HASH_SIZE;
    FdSocketEntry *entry = poll->fd_to_socket_map[fd_hash];

    /* Search the hash bucket for matching FD */
    while (entry)
    {
        if (entry->fd == fd)
            return entry->socket;
        entry = entry->next;
    }

    return NULL;
}

/**
 * translate_backend_events_to_socket_events - Convert backend events to SocketEvent_T
 * @poll: Poll instance
 * @nfds: Number of events to process
 *
 * Returns: Number of successfully translated events
 * Raises: SocketPoll_Failed on backend error
 * Thread-safe: No (caller must ensure thread safety)
 *
 * Translates events from the backend-specific format to the
 * standardized SocketEvent_T format used by the public API.
 * Handles socket lookup and data association for each event.
 */
static int translate_backend_events_to_socket_events(T poll, int nfds)
{
    int translated_count = 0;

    for (int i = 0; i < nfds; i++)
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
        socket = find_socket_by_fd(poll, fd);
        if (!socket)
        {
            /* Socket not found - skip this event */
            SOCKET_ERROR_MSG("Event for unknown socket (fd=%d)", fd);
            continue;
        }

        /* Fill in SocketEvent_T structure */
        poll->socketevents[translated_count].socket = socket;
        poll->socketevents[translated_count].data = socket_data_get(poll, socket);
        poll->socketevents[translated_count].events = event_flags;
        translated_count++;
    }

    return translated_count;
}

/* ==================== Public API Functions ==================== */

int SocketPoll_wait(T poll, SocketEvent_T **events, int timeout)
{
    int nfds;

    assert(poll);
    assert(events);

    /* Wait for events from backend */
    nfds = backend_wait(poll->backend, timeout);
    if (nfds < 0)
    {
        if (errno == EINTR)
            return 0; /* Interrupted - not an error */
        SOCKET_ERROR_FMT("%s backend wait failed (timeout=%d)", backend_name(), timeout);
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    /* Translate backend events to SocketEvent_T structures */
    nfds = translate_backend_events_to_socket_events(poll, nfds);

    *events = poll->socketevents;
    return nfds;
}

#undef T

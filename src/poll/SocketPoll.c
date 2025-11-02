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
 * allocate_socket_data_entry - Allocate socket data entry
 * @poll: Poll instance
 *
 * Returns: Allocated SocketData entry
 * Raises: SocketPoll_Failed on allocation failure
 */
static SocketData *allocate_socket_data_entry(T poll)
{
    volatile SocketData *volatile_entry = NULL;

    TRY
    {
        volatile_entry = ALLOC(poll->arena, sizeof(SocketData));
    }
    EXCEPT(Arena_Failed)
    {
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate socket data mapping");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }
    END_TRY;

    return (SocketData *)volatile_entry;
}

/**
 * allocate_fd_socket_entry - Allocate FD to socket mapping entry
 * @poll: Poll instance
 *
 * Returns: Allocated FdSocketEntry
 * Raises: SocketPoll_Failed on allocation failure
 */
static FdSocketEntry *allocate_fd_socket_entry(T poll)
{
    volatile FdSocketEntry *volatile_entry = NULL;

    TRY
    {
        volatile_entry = ALLOC(poll->arena, sizeof(FdSocketEntry));
    }
    EXCEPT(Arena_Failed)
    {
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate fd to socket mapping");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }
    END_TRY;

    return (FdSocketEntry *)volatile_entry;
}

/**
 * compute_fd_hash - Compute hash for file descriptor
 * @fd: File descriptor
 *
 * Returns: Hash value in range [0, SOCKET_DATA_HASH_SIZE)
 */
static unsigned compute_fd_hash(int fd)
{
    return ((unsigned)fd * HASH_GOLDEN_RATIO) % SOCKET_DATA_HASH_SIZE;
}

/**
 * insert_socket_data_entry - Insert socket data entry into hash table
 * @poll: Poll instance
 * @hash: Hash bucket index
 * @entry: Entry to insert
 *
 * Thread-safe: Yes - caller must hold mutex
 */
static void insert_socket_data_entry(T poll, unsigned hash, SocketData *entry)
{
    entry->next = poll->socket_data_map[hash];
    poll->socket_data_map[hash] = entry;
}

/**
 * insert_fd_socket_entry - Insert FD to socket entry into hash table
 * @poll: Poll instance
 * @fd_hash: Hash bucket index
 * @entry: Entry to insert
 *
 * Thread-safe: Yes - caller must hold mutex
 */
static void insert_fd_socket_entry(T poll, unsigned fd_hash, FdSocketEntry *entry)
{
    entry->next = poll->fd_to_socket_map[fd_hash];
    poll->fd_to_socket_map[fd_hash] = entry;
}

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
    volatile Socket_T volatile_socket = socket;
    volatile unsigned hash;
    volatile unsigned fd_hash;
    volatile int fd;
    SocketData *data_entry = NULL;
    FdSocketEntry *fd_entry = NULL;

    hash = socket_hash(volatile_socket);
    fd = Socket_fd(volatile_socket);
    fd_hash = compute_fd_hash(fd);

    data_entry = allocate_socket_data_entry(poll);
    fd_entry = allocate_fd_socket_entry(poll);

    data_entry->socket = volatile_socket;
    data_entry->data = data;
    fd_entry->fd = fd;
    fd_entry->socket = volatile_socket;

    pthread_mutex_lock(&poll->mutex);
    insert_socket_data_entry(poll, hash, data_entry);
    insert_fd_socket_entry(poll, fd_hash, fd_entry);
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
    volatile Socket_T volatile_socket = socket;  /* Preserve socket across exception boundaries */
    unsigned hash = socket_hash(volatile_socket);
    void *data = NULL;

    pthread_mutex_lock(&poll->mutex);
    SocketData *entry = poll->socket_data_map[hash];
    while (entry)
    {
        if (entry->socket == volatile_socket)
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
 * remove_socket_data_entry - Remove socket data entry from hash table
 * @poll: Poll instance
 * @hash: Hash bucket index
 * @socket: Socket to remove
 *
 * Thread-safe: Yes - caller must hold mutex
 */
static void remove_socket_data_entry(T poll, unsigned hash, Socket_T socket)
{
    SocketData **pp = &poll->socket_data_map[hash];
    while (*pp)
    {
        if ((*pp)->socket == socket)
        {
            *pp = (*pp)->next;
            break;
        }
        pp = &(*pp)->next;
    }
}

/**
 * remove_fd_socket_entry - Remove FD to socket entry from hash table
 * @poll: Poll instance
 * @fd_hash: Hash bucket index
 * @fd: File descriptor to remove
 *
 * Thread-safe: Yes - caller must hold mutex
 */
static void remove_fd_socket_entry(T poll, unsigned fd_hash, int fd)
{
    FdSocketEntry **fd_pp = &poll->fd_to_socket_map[fd_hash];
    while (*fd_pp)
    {
        if ((*fd_pp)->fd == fd)
        {
            *fd_pp = (*fd_pp)->next;
            break;
        }
        fd_pp = &(*fd_pp)->next;
    }
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
    volatile Socket_T volatile_socket = socket;
    unsigned hash = socket_hash(volatile_socket);
    unsigned fd_hash;
    int fd;

    fd = Socket_fd(volatile_socket);
    fd_hash = compute_fd_hash(fd);

    pthread_mutex_lock(&poll->mutex);
    remove_socket_data_entry(poll, hash, volatile_socket);
    remove_fd_socket_entry(poll, fd_hash, fd);
    pthread_mutex_unlock(&poll->mutex);
}

/**
 * find_socket_data_entry - Find socket data entry in hash table
 * @poll: Poll instance
 * @hash: Hash bucket index
 * @socket: Socket to find
 *
 * Returns: SocketData entry if found, NULL otherwise
 * Thread-safe: Yes - caller must hold mutex
 */
static SocketData *find_socket_data_entry(T poll, unsigned hash, Socket_T socket)
{
    SocketData *entry = poll->socket_data_map[hash];
    while (entry)
    {
        if (entry->socket == socket)
            return entry;
        entry = entry->next;
    }
    return NULL;
}

/**
 * add_fallback_socket_data_entry - Add socket data entry as fallback
 * @poll: Poll instance
 * @hash: Hash bucket index
 * @socket: Socket to add
 * @data: User data to associate
 *
 * Raises: SocketPoll_Failed on allocation failure
 * Thread-safe: Yes - caller must hold mutex
 */
static void add_fallback_socket_data_entry(T poll, unsigned hash, Socket_T socket, void *data)
{
    SocketData *entry;

#ifndef NDEBUG
    fprintf(stderr, "WARNING: socket_data_update fallback (fd %d)\n", Socket_fd(socket));
#endif

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
    volatile Socket_T volatile_socket = socket;
    unsigned hash = socket_hash(volatile_socket);
    SocketData *entry;

    pthread_mutex_lock(&poll->mutex);
    entry = find_socket_data_entry(poll, hash, volatile_socket);
    if (entry)
    {
        entry->data = data;
    }
    else
    {
        add_fallback_socket_data_entry(poll, hash, volatile_socket, data);
    }
    pthread_mutex_unlock(&poll->mutex);
}

/**
 * allocate_poll_structure - Allocate poll structure
 *
 * Returns: Allocated poll structure
 * Raises: SocketPoll_Failed on allocation failure
 */
static T allocate_poll_structure(void)
{
    T poll = malloc(sizeof(*poll));
    if (poll == NULL)
    {
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate poll structure");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }
    return poll;
}

/**
 * initialize_poll_backend - Initialize poll backend
 * @poll: Poll instance
 * @maxevents: Maximum events
 *
 * Raises: SocketPoll_Failed on failure
 */
static void initialize_poll_backend(T poll, int maxevents)
{
    poll->backend = backend_new(maxevents);
    if (!poll->backend)
    {
        SOCKET_ERROR_FMT("Failed to create %s backend", backend_name());
        free(poll);
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }
}

/**
 * initialize_poll_arena - Initialize poll arena
 * @poll: Poll instance
 *
 * Raises: SocketPoll_Failed on failure
 */
static void initialize_poll_arena(T poll)
{
    poll->arena = Arena_new();
    if (!poll->arena)
    {
        backend_free(poll->backend);
        free(poll);
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate poll arena");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }
}

/**
 * allocate_poll_event_arrays - Allocate event arrays
 * @poll: Poll instance
 * @maxevents: Maximum events
 *
 * Raises: SocketPoll_Failed on failure
 */
static void allocate_poll_event_arrays(T poll, int maxevents)
{
    poll->socketevents = CALLOC(poll->arena, maxevents, sizeof(*poll->socketevents));
    if (!poll->socketevents)
    {
        backend_free(poll->backend);
        Arena_dispose(&poll->arena);
        free(poll);
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate event arrays");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }
}

/**
 * initialize_poll_hash_tables - Initialize hash tables
 * @poll: Poll instance
 */
static void initialize_poll_hash_tables(T poll)
{
    memset(poll->socket_data_map, 0, sizeof(poll->socket_data_map));
    memset(poll->fd_to_socket_map, 0, sizeof(poll->fd_to_socket_map));
}

/**
 * initialize_poll_mutex - Initialize poll mutex
 * @poll: Poll instance
 *
 * Raises: SocketPoll_Failed on failure
 */
static void initialize_poll_mutex(T poll)
{
    if (pthread_mutex_init(&poll->mutex, NULL) != 0)
    {
        backend_free(poll->backend);
        Arena_dispose(&poll->arena);
        free(poll);
        SOCKET_ERROR_MSG("Failed to initialize poll mutex");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }
}

T SocketPoll_new(int maxevents)
{
    T poll;

    assert(SOCKET_VALID_POLL_EVENTS(maxevents));

    if (maxevents > SOCKET_MAX_POLL_EVENTS)
        maxevents = SOCKET_MAX_POLL_EVENTS;

    poll = allocate_poll_structure();
    initialize_poll_backend(poll, maxevents);
    poll->maxevents = maxevents;
    initialize_poll_arena(poll);
    allocate_poll_event_arrays(poll, maxevents);
    initialize_poll_hash_tables(poll);
    initialize_poll_mutex(poll);

    return poll;
}

void SocketPoll_free(T *poll)
{
    if (!poll || !*poll)
        return;

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
    volatile Socket_T volatile_socket = socket;  /* Preserve socket across exception boundaries */

    assert(poll);
    assert(socket);

    /* Cast to non-volatile for Socket API calls - these don't need volatile */
    fd = Socket_fd((Socket_T)volatile_socket);

    /* Set non-blocking mode before adding to poll */
    Socket_setnonblocking((Socket_T)volatile_socket);

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

    /* Store socket->data mapping - if this fails, we need to clean up backend entry */
    TRY
    {
        socket_data_add(poll, volatile_socket, data);
    }
    EXCEPT(SocketPoll_Failed)
    {
        /* Remove from poll to prevent orphaned entry */
        backend_del(poll->backend, fd);
        RERAISE;
    }
    END_TRY;
}

void SocketPoll_mod(T poll, Socket_T socket, unsigned events, void *data)
{
    int fd;
    volatile Socket_T volatile_socket = socket;  /* Preserve socket across exception boundaries */

    assert(poll);
    assert(socket);

    fd = Socket_fd((Socket_T)volatile_socket);

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
    socket_data_update(poll, volatile_socket, data);
}

void SocketPoll_del(T poll, Socket_T socket)
{
    int fd;
    volatile Socket_T volatile_socket = socket;  /* Preserve socket across exception boundaries */

    assert(poll);
    assert(socket);

    fd = Socket_fd((Socket_T)volatile_socket);

    if (backend_del(poll->backend, fd) < 0)
    {
        if (errno != ENOENT)
        {
            SOCKET_ERROR_FMT("Failed to remove socket from poll (fd=%d)", fd);
            RAISE_POLL_ERROR(SocketPoll_Failed);
        }
    }

    /* Remove the socket->data mapping */
    socket_data_remove(poll, volatile_socket);
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
 * get_backend_event - Get event from backend
 * @poll: Poll instance
 * @index: Event index
 * @fd_out: Output - file descriptor
 * @events_out: Output - event flags
 *
 * Raises: SocketPoll_Failed on backend error
 */
static void get_backend_event(T poll, int index, int *fd_out, unsigned *events_out)
{
    if (backend_get_event(poll->backend, index, fd_out, events_out) < 0)
    {
        SOCKET_ERROR_MSG("Failed to get event from backend");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }
}

/**
 * translate_single_event - Translate single backend event to SocketEvent_T
 * @poll: Poll instance
 * @index: Backend event index
 * @translated_index: Index in translated events array
 *
 * Returns: 1 if event was translated, 0 if skipped
 * Raises: SocketPoll_Failed on backend error
 */
static int translate_single_event(T poll, int index, int translated_index)
{
    volatile int fd;
    volatile unsigned event_flags;
    volatile Socket_T socket;

    get_backend_event(poll, index, (int *)&fd, (unsigned *)&event_flags);

    pthread_mutex_lock(&poll->mutex);
    socket = find_socket_by_fd(poll, fd);
    pthread_mutex_unlock(&poll->mutex);

    if (!socket)
        return 0;

    poll->socketevents[translated_index].socket = (Socket_T)socket;
    poll->socketevents[translated_index].data = socket_data_get(poll, (Socket_T)socket);
    poll->socketevents[translated_index].events = event_flags;
    return 1;
}

/**
 * translate_backend_events_to_socket_events - Convert backend events to SocketEvent_T
 * @poll: Poll instance
 * @nfds: Number of events to process
 *
 * Returns: Number of successfully translated events
 * Raises: SocketPoll_Failed on backend error
 * Thread-safe: Yes (socket_data_get handles its own mutex locking)
 *
 * Translates events from the backend-specific format to the
 * standardized SocketEvent_T format used by the public API.
 * Handles socket lookup and data association for each event.
 *
 * Note: find_socket_by_fd requires mutex but socket_data_get also locks mutex,
 * so we lock mutex only for find_socket_by_fd, then unlock before calling socket_data_get.
 */
static int translate_backend_events_to_socket_events(T poll, int nfds)
{
    volatile int translated_count = 0;
    volatile int i;

    TRY
    {
        for (i = 0; i < nfds; i++)
        {
            if (translate_single_event(poll, i, translated_count))
                translated_count++;
        }
    }
    EXCEPT(SocketPoll_Failed)
    {
        /* Handle translation errors - exception already raised */
    }
    END_TRY;

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

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

/* Macro to raise exception with detailed error message
 * Creates a thread-local copy of the exception with detailed reason.
 * CRITICAL: Uses volatile local variable on ARM64 to prevent corruption across setjmp/longjmp */
#define RAISE_POLL_ERROR(exception)                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        volatile Except_T volatile_exception = (exception);                                                            \
        volatile_exception.reason = socket_error_buf;                                                                  \
        Except_T non_volatile_exception = *(const Except_T *)&volatile_exception;                                     \
        RAISE(non_volatile_exception);                                                                                 \
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
    volatile SocketData *volatile_data_entry = NULL;
    volatile FdSocketEntry *volatile_fd_entry = NULL;

    hash = socket_hash((Socket_T)volatile_socket);
    fd = Socket_fd((Socket_T)volatile_socket);
    fd_hash = compute_fd_hash(fd);

    volatile_data_entry = allocate_socket_data_entry(poll);
    volatile_fd_entry = allocate_fd_socket_entry(poll);

    volatile_data_entry->socket = (Socket_T)volatile_socket;
    volatile_data_entry->data = data;
    volatile_fd_entry->fd = fd;
    volatile_fd_entry->socket = (Socket_T)volatile_socket;

    pthread_mutex_lock(&poll->mutex);
    insert_socket_data_entry(poll, hash, (SocketData *)volatile_data_entry);
    insert_fd_socket_entry(poll, fd_hash, (FdSocketEntry *)volatile_fd_entry);
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
    unsigned hash;
    void *data = NULL;

    if (!poll || !socket)
        return NULL;
    
    hash = socket_hash((Socket_T)volatile_socket);
    if (hash >= SOCKET_DATA_HASH_SIZE)
        return NULL;

    pthread_mutex_lock(&poll->mutex);
    SocketData *entry = poll->socket_data_map[hash];
    while (entry)
    {
        if (entry->socket == (Socket_T)volatile_socket)
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
    unsigned hash = socket_hash((Socket_T)volatile_socket);
    unsigned fd_hash;
    int fd;

    fd = Socket_fd((Socket_T)volatile_socket);
    fd_hash = compute_fd_hash(fd);

    pthread_mutex_lock(&poll->mutex);
    remove_socket_data_entry(poll, hash, (Socket_T)volatile_socket);
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
    volatile SocketData *volatile_entry = NULL;

#ifndef NDEBUG
    fprintf(stderr, "WARNING: socket_data_update fallback (fd %d)\n", Socket_fd(socket));
#endif

    TRY
    {
        volatile_entry = ALLOC(poll->arena, sizeof(SocketData));
    }
    EXCEPT(Arena_Failed)
    {
        /* Don't unlock mutex here - caller is responsible for unlocking */
        SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate socket data mapping");
        RAISE_POLL_ERROR(SocketPoll_Failed);
        /* NOTREACHED */
    }
    END_TRY;

    SocketData *entry = (SocketData *)volatile_entry;
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
    volatile unsigned hash = socket_hash((Socket_T)volatile_socket);
    volatile SocketData *volatile_entry = NULL;

    pthread_mutex_lock(&poll->mutex);
    TRY
    {
        volatile_entry = find_socket_data_entry(poll, hash, (Socket_T)volatile_socket);
        if (volatile_entry)
        {
            volatile_entry->data = data;
            pthread_mutex_unlock(&poll->mutex);
        }
        else
        {
            add_fallback_socket_data_entry(poll, hash, (Socket_T)volatile_socket, data);
            pthread_mutex_unlock(&poll->mutex);
        }
    }
    EXCEPT(SocketPoll_Failed)
    {
        pthread_mutex_unlock(&poll->mutex);
        RERAISE;
    }
    END_TRY;
    /* Mutex already unlocked in TRY block */
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
    /* Zero-initialize to ensure all fields start in a known state */
    memset(poll, 0, sizeof(*poll));
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
    size_t array_size;

    /* Validate maxevents before allocation */
    if (maxevents <= 0 || maxevents > SOCKET_MAX_POLL_EVENTS)
    {
        backend_free(poll->backend);
        Arena_dispose(&poll->arena);
        free(poll);
        SOCKET_ERROR_MSG("Invalid maxevents value");
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    /* Calculate array size with overflow check */
    array_size = (size_t)maxevents * sizeof(*poll->socketevents);
    if (array_size / sizeof(*poll->socketevents) != (size_t)maxevents)
    {
        backend_free(poll->backend);
        Arena_dispose(&poll->arena);
        free(poll);
        SOCKET_ERROR_MSG("Array size overflow");
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
    volatile int fd;
    volatile Socket_T volatile_socket = socket;  /* Preserve socket across exception boundaries */

    assert(poll);
    assert(socket);

    /* Cast to non-volatile for Socket API calls - these don't need volatile */
    fd = Socket_fd((Socket_T)volatile_socket);
    assert(fd >= 0); /* Socket FD should be valid */

    /* Set non-blocking mode before adding to poll */
    Socket_setnonblocking((Socket_T)volatile_socket);

    /* Check if socket is already in poll set (works for all backends)
     * kqueue doesn't fail on duplicate adds, so we need to check our internal state */
    volatile unsigned dup_check_hash = ((unsigned)fd * HASH_GOLDEN_RATIO) % SOCKET_DATA_HASH_SIZE;
    volatile SocketData *volatile_entry = NULL;
    volatile int is_duplicate = 0;

    pthread_mutex_lock(&poll->mutex);
    volatile_entry = poll->socket_data_map[dup_check_hash];
    while (volatile_entry != NULL)
    {
        /* Store next pointer before comparison to prevent issues with volatile access */
        volatile SocketData *next_entry = (volatile SocketData *)volatile_entry->next;
        
        if (volatile_entry->socket == (Socket_T)volatile_socket)
        {
            is_duplicate = 1;
            break;
        }
        /* Move to next entry */
        volatile_entry = next_entry;
    }
    pthread_mutex_unlock(&poll->mutex);

    if (is_duplicate)
    {
        SOCKET_ERROR_MSG("Socket already in poll set");
        RAISE_POLL_ERROR(SocketPoll_Failed);
        /* NOTREACHED */
    }

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
        socket_data_add(poll, (Socket_T)volatile_socket, data);
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
    socket_data_update(poll, (Socket_T)volatile_socket, data);
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
    socket_data_remove(poll, (Socket_T)volatile_socket);
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
    volatile int max_events;

    if (!poll || index < 0 || translated_index < 0)
        return 0;

    /* Cache maxevents to prevent reading corrupted value */
    max_events = poll->maxevents;
    if (max_events <= 0 || max_events > SOCKET_MAX_POLL_EVENTS)
        return 0;

    if (!poll->socketevents || translated_index >= max_events)
        return 0;

    get_backend_event(poll, index, (int *)&fd, (unsigned *)&event_flags);

    pthread_mutex_lock(&poll->mutex);
    socket = find_socket_by_fd(poll, fd);
    if (!socket)
    {
        pthread_mutex_unlock(&poll->mutex);
        return 0;
    }
    /* Store socket pointer before unlocking - socket_data_get will re-lock mutex */
    Socket_T non_volatile_socket = (Socket_T)socket;
    pthread_mutex_unlock(&poll->mutex);

    /* Use cached maxevents value for bounds checking */
    /* Ensure translated_index is strictly less than max_events (valid indices are 0 to max_events-1) */
    if (translated_index < 0 || translated_index >= max_events || !poll->socketevents)
        return 0;
    
    /* Validate bounds using pointer arithmetic to prevent any potential overrun */
    SocketEvent_T *event_ptr = poll->socketevents + translated_index;
    SocketEvent_T *array_start = poll->socketevents;
    SocketEvent_T *array_end = array_start + max_events;
    
    /* Additional pointer validation */
    if (event_ptr < array_start || event_ptr >= array_end)
        return 0;

    event_ptr->socket = non_volatile_socket;
    event_ptr->data = socket_data_get(poll, non_volatile_socket);
    event_ptr->events = event_flags;
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
    volatile int max_events; /* Cache maxevents to prevent corruption issues */
    volatile int volatile_nfds = nfds; /* Preserve nfds across exception boundaries */

    if (!poll || volatile_nfds < 0 || !poll->socketevents || poll->maxevents <= 0)
        return 0;

    /* Cache maxevents value to ensure consistency */
    max_events = poll->maxevents;

    /* Ensure we don't exceed the allocated event array size */
    if (volatile_nfds > max_events)
        volatile_nfds = max_events;

    TRY
    {
        for (i = 0; i < volatile_nfds; i++)
        {
            /* Stop if we've filled the array */
            if (translated_count >= max_events)
                break;
            
            /* translate_single_event validates bounds internally */
            if (translate_single_event(poll, i, translated_count))
            {
                translated_count++;
            }
        }
    }
    EXCEPT(SocketPoll_Failed)
    {
        /* Handle translation errors - exception already raised */
    }
    END_TRY;

    /* Ensure we never return a count exceeding maxevents */
    if (translated_count > max_events)
        translated_count = max_events;

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
        {
            *events = NULL;
            return 0; /* Interrupted - not an error */
        }
        SOCKET_ERROR_FMT("%s backend wait failed (timeout=%d)", backend_name(), timeout);
        RAISE_POLL_ERROR(SocketPoll_Failed);
    }

    /* If no events, return immediately */
    if (nfds == 0)
    {
        *events = poll->socketevents; /* Return valid pointer even if empty */
        return 0;
    }

    /* Translate backend events to SocketEvent_T structures */
    nfds = translate_backend_events_to_socket_events(poll, nfds);

    /* Validate poll structure is still intact before returning pointer */
    if (!poll || !poll->socketevents)
    {
        *events = NULL;
        return 0;
    }

    *events = poll->socketevents;
    return nfds;
}

#undef T

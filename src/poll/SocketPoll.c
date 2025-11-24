/**
 * SocketPoll.c - Event polling with backend abstraction
 * PLATFORM: Cross-platform (Linux/BSD/macOS/POSIX)
 * - Linux: epoll backend (best performance)
 * - BSD/macOS: kqueue backend (best performance)
 * - Other POSIX: poll(2) fallback (portable)
 * Backend selection is done at compile-time via Makefile
 * See SocketPoll_backend.h for backend interface details
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "poll/SocketPoll.h"
#include "poll/SocketPoll_backend.h"
#include "socket/Socket.h"
#include "socket/SocketAsync.h"
#define SOCKET_LOG_COMPONENT "SocketPoll"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "core/SocketEvents.h"
#include "core/SocketMetrics.h"

/* Include timer private header after struct definition to avoid circular deps */
#include "core/SocketTimer-private.h"

#ifdef SOCKET_HAS_TLS
#include "socket/Socket-private.h"
#include "socket/SocketIO.h"
#include "tls/SocketTLS.h"
#endif

#define T SocketPoll_T

const Except_T SocketPoll_Failed
    = { &SocketPoll_Failed, "SocketPoll operation failed" };

/* Macro to raise exception with detailed error message
 * Creates a thread-local copy of the exception with detailed reason.
 * CRITICAL: Uses volatile local variable on ARM64 to prevent corruption across
 * setjmp/longjmp */
#define RAISE_POLL_ERROR(exception)                                           \
  do                                                                          \
    {                                                                         \
      volatile Except_T volatile_exception = (exception);                     \
      volatile_exception.reason = socket_error_buf;                           \
      Except_T non_volatile_exception                                         \
          = *(const Except_T *)&volatile_exception;                           \
      RAISE (non_volatile_exception);                                         \
    }                                                                         \
  while (0)

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
  PollBackend_T backend;
  int maxevents;
  int default_timeout_ms;
  SocketEvent_T *socketevents;
  Arena_T arena;
  SocketData
      *socket_data_map[SOCKET_DATA_HASH_SIZE]; /* Hash table for O(1)
                                                  socket->data mapping */
  FdSocketEntry
      *fd_to_socket_map[SOCKET_DATA_HASH_SIZE]; /* Hash table for O(1)
                                                   fd->socket mapping */
  pthread_mutex_t mutex; /* Mutex for thread-safe socket data mapping */
  SocketAsync_T async;   /* Optional async I/O context */
  SocketTimer_heap_T *timer_heap; /* Timer heap for integrated timers */
};

/* ==================== Hash Functions ==================== */

/**
 * socket_hash - Hash function for socket file descriptors
 * @socket: Socket to hash
 * Returns: Hash value in range [0, SOCKET_DATA_HASH_SIZE)
 * Uses multiplicative hashing with the golden ratio constant for
 * good distribution across hash buckets. This provides O(1) average
 * case performance for socket data lookups.
 */
static unsigned
socket_hash (const Socket_T socket)
{
  int fd;

  assert (socket);
  fd = Socket_fd (socket);

  if (fd < 0)
    {
      SocketLog_emitf (
          SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
          "Attempt to hash closed/invalid socket (fd=%d); returning 0", fd);
      return 0;
    }

  /* Multiplicative hash with golden ratio for good distribution */
  return ((unsigned)fd * HASH_GOLDEN_RATIO) % SOCKET_DATA_HASH_SIZE;
}

/* ==================== Socket Data Management ==================== */

/**
 * allocate_socket_data_entry
 * Raises: SocketPoll_Failed on allocation failure
 */
static SocketData *
allocate_socket_data_entry (T poll)
{
  SocketData *volatile volatile_entry = NULL;

  TRY { volatile_entry = CALLOC (poll->arena, 1, sizeof (SocketData)); }
  EXCEPT (Arena_Failed)
  {
    SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate socket data mapping");
    RAISE_POLL_ERROR (SocketPoll_Failed);
  }
  END_TRY;

  return volatile_entry;
}

/**
 * allocate_fd_socket_entry
 * Raises: SocketPoll_Failed on allocation failure
 */
static FdSocketEntry *
allocate_fd_socket_entry (T poll)
{
  FdSocketEntry *volatile volatile_entry = NULL;

  TRY { volatile_entry = CALLOC (poll->arena, 1, sizeof (FdSocketEntry)); }
  EXCEPT (Arena_Failed)
  {
    SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate fd to socket mapping");
    RAISE_POLL_ERROR (SocketPoll_Failed);
  }
  END_TRY;

  return volatile_entry;
}

/**
 * compute_fd_hash - Compute hash for file descriptor
 * @fd: File descriptor
 * Returns: Hash value in range [0, SOCKET_DATA_HASH_SIZE)
 */
static unsigned
compute_fd_hash (int fd)
{
  return ((unsigned)fd * HASH_GOLDEN_RATIO) % SOCKET_DATA_HASH_SIZE;
}

/**
 * insert_socket_data_entry - Insert socket data entry into hash table
 * @poll: Poll instance
 * @hash: Hash bucket index
 * @entry: Entry to insert
 * Thread-safe: Yes - caller must hold mutex
 */
static void
insert_socket_data_entry (T poll, unsigned hash, SocketData *entry)
{
  entry->next = poll->socket_data_map[hash];
  poll->socket_data_map[hash] = entry;
}

/**
 * insert_fd_socket_entry - Insert FD to socket entry into hash table
 * @poll: Poll instance
 * @fd_hash: Hash bucket index
 * @entry: Entry to insert
 * Thread-safe: Yes - caller must hold mutex
 */
static void
insert_fd_socket_entry (T poll, unsigned fd_hash, FdSocketEntry *entry)
{
  entry->next = poll->fd_to_socket_map[fd_hash];
  poll->fd_to_socket_map[fd_hash] = entry;
}

/**
 * socket_data_get - Retrieve user data for socket
 * @poll: Poll instance
 * @socket: Socket to look up
 * Returns: User data associated with socket, or NULL if not found
 * Thread-safe: Yes - uses internal mutex
 * Performs O(1) average case lookup in the socket data hash table.
 * Returns the user data pointer that was associated with the socket
 * when it was added to the poll.
 */
static void *
socket_data_lookup_unlocked (T poll, Socket_T socket)
{
  unsigned hash;
  SocketData *entry;

  if (!poll || !socket)
    return NULL;

  hash = socket_hash (socket);
  if (hash >= SOCKET_DATA_HASH_SIZE)
    return NULL;

  entry = poll->socket_data_map[hash];
  while (entry)
    {
      if (entry->socket == socket)
        return entry->data;
      entry = entry->next;
    }

  return NULL;
}

/**
 * remove_socket_data_entry - Remove socket data entry from hash table
 * @poll: Poll instance
 * @hash: Hash bucket index
 * @socket: Socket to remove
 * Thread-safe: Yes - caller must hold mutex
 */
static void
remove_socket_data_entry (T poll, unsigned hash, Socket_T socket)
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
 * Thread-safe: Yes - caller must hold mutex
 */
static void
remove_fd_socket_entry (T poll, unsigned fd_hash, int fd)
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
 * find_socket_data_entry
 * Thread-safe: Yes - caller must hold mutex
 */
static SocketData *
find_socket_data_entry (T poll, unsigned hash, Socket_T socket)
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
 * Raises: SocketPoll_Failed on allocation failure
 * Thread-safe: Yes - caller must hold mutex
 */
static void
add_fallback_socket_data_entry (T poll, unsigned hash, Socket_T socket,
                                void *data)
{
  SocketData *volatile volatile_entry = NULL;

#ifndef NDEBUG
  fprintf (stderr, "WARNING: socket_data_update fallback (fd %d)\n",
           Socket_fd (socket));
#endif

  TRY { volatile_entry = CALLOC (poll->arena, 1, sizeof (SocketData)); }
  EXCEPT (Arena_Failed)
  {
    /* Don't unlock mutex here - caller is responsible for unlocking */
    SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate socket data mapping");
    RAISE_POLL_ERROR (SocketPoll_Failed);
    /* NOTREACHED */
  }
  END_TRY;

  volatile_entry->socket = socket;
  volatile_entry->data = data;
  volatile_entry->next = poll->socket_data_map[hash];
  poll->socket_data_map[hash] = volatile_entry;
}

/* ==================== UNLOCKED Socket Data Helpers ==================== */

/**
 * socket_data_add_unlocked - Add socket data mapping (caller holds lock)
 * @poll: Poll instance
 * @socket: Socket
 * @data: User data
 * Raises: SocketPoll_Failed on alloc fail
 */
static void
socket_data_add_unlocked (T poll, Socket_T socket, void *data)
{
  unsigned hash = socket_hash (socket);
  unsigned fd_hash = compute_fd_hash (Socket_fd (socket));
  SocketData *data_entry = allocate_socket_data_entry (poll);
  FdSocketEntry *fd_entry = allocate_fd_socket_entry (poll);

  data_entry->socket = socket;
  data_entry->data = data;
  fd_entry->fd = Socket_fd (socket);
  fd_entry->socket = socket;

  insert_socket_data_entry (poll, hash, data_entry);
  insert_fd_socket_entry (poll, fd_hash, fd_entry);
}

/**
 * socket_data_update_unlocked - Update data (caller holds lock)
 * @poll: Poll instance
 * @socket: Socket
 * @data: New data
 * Raises: SocketPoll_Failed on alloc fail (fallback)
 */
static void
socket_data_update_unlocked (T poll, Socket_T socket, void *data)
{
  unsigned hash = socket_hash (socket);
  SocketData *entry = find_socket_data_entry (poll, hash, socket);
  if (entry)
    {
      entry->data = data;
    }
  else
    {
#ifndef NDEBUG
      fprintf (stderr,
               "WARNING: socket_data_update_unlocked fallback (fd %d)\n",
               Socket_fd (socket));
#endif
      add_fallback_socket_data_entry (poll, hash, socket, data);
    }
}

/**
 * socket_data_remove_unlocked - Remove mappings (caller holds lock)
 * @poll: Poll instance
 * @socket: Socket
 */
static void
socket_data_remove_unlocked (T poll, Socket_T socket)
{
  unsigned hash = socket_hash (socket);
  int fd = Socket_fd (socket);
  unsigned fd_hash = compute_fd_hash (fd);

  remove_socket_data_entry (poll, hash, socket);
  remove_fd_socket_entry (poll, fd_hash, fd);
}

/**
 * allocate_poll_structure
 * Raises: SocketPoll_Failed on allocation failure
 */
static T
allocate_poll_structure (void)
{
  T poll = malloc (sizeof (*poll));
  if (poll == NULL)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate poll structure");
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }
  /* Zero-initialize to ensure all fields start in a known state */
  memset (poll, 0, sizeof (*poll));
  return poll;
}

#ifdef SOCKET_HAS_TLS
/**
 * socketpoll_update_tls_events - Update poll events based on TLS handshake
 * state
 * @poll: Poll instance
 * @socket: Socket with TLS enabled
 *
 * Updates the poll event mask for a TLS-enabled socket based on its current
 * handshake state. If TLS handshake is in progress and wants read/write,
 * adjusts the monitored events accordingly. Only updates if socket is in poll.
 *
 * Thread-safe: Yes (SocketPoll_mod handles mutex locking, we lock for data
 * lookup) Uses existing socket_data_lookup_unlocked() pattern from
 * translate_single_event()
 */
static void
socketpoll_update_tls_events (T poll, Socket_T socket)
{
  unsigned events = 0;
  void *user_data;

  assert (poll);
  assert (socket);

  /* Only process TLS-enabled sockets */
  if (!socket_is_tls_enabled (socket))
    return;

  /* Only update if handshake is in progress */
  if (!socket->tls_handshake_done)
    {
      /* Check if TLS wants read/write based on last handshake state */
      if (socket_tls_want_read (socket))
        events |= POLL_READ;
      if (socket_tls_want_write (socket))
        events |= POLL_WRITE;

      /* Update poll events if TLS state requires it */
      if (events != 0)
        {
          /* Get user data to preserve it - use existing
           * socket_data_lookup_unlocked pattern */
          /* Same pattern as translate_single_event() uses */
          pthread_mutex_lock (&poll->mutex);
          user_data = socket_data_lookup_unlocked (poll, socket);
          pthread_mutex_unlock (&poll->mutex);

          /* Update events - SocketPoll_mod handles socket not found gracefully
           */
          /* If user_data is NULL, socket might not be in poll, but mod will
           * handle it */
          SocketPoll_mod (poll, socket, events, user_data);
        }
    }
}
#endif /* SOCKET_HAS_TLS */

/**
 * initialize_poll_backend
 * Raises: SocketPoll_Failed on failure
 */
static void
initialize_poll_backend (T poll, int maxevents)
{
  poll->backend = backend_new (maxevents);
  if (!poll->backend)
    {
      SOCKET_ERROR_FMT ("Failed to create %s backend", backend_name ());
      free (poll);
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }
}

/**
 * initialize_poll_arena
 * Raises: SocketPoll_Failed on failure
 */
static void
initialize_poll_arena (T poll)
{
  poll->arena = Arena_new ();
  if (!poll->arena)
    {
      backend_free (poll->backend);
      free (poll);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate poll arena");
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }
}

/**
 * allocate_poll_event_arrays
 * Raises: SocketPoll_Failed on failure
 */
static void
allocate_poll_event_arrays (T poll, int maxevents)
{
  size_t array_size;

  /* Validate maxevents before allocation */
  if (maxevents <= 0 || maxevents > SOCKET_MAX_POLL_EVENTS)
    {
      backend_free (poll->backend);
      Arena_dispose (&poll->arena);
      free (poll);
      SOCKET_ERROR_MSG ("Invalid maxevents value");
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }

  /* Calculate array size with overflow check */
  array_size = (size_t)maxevents * sizeof (*poll->socketevents);
  if (array_size / sizeof (*poll->socketevents) != (size_t)maxevents)
    {
      backend_free (poll->backend);
      Arena_dispose (&poll->arena);
      free (poll);
      SOCKET_ERROR_MSG ("Array size overflow");
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }

  poll->socketevents
      = CALLOC (poll->arena, maxevents, sizeof (*poll->socketevents));
  if (!poll->socketevents)
    {
      backend_free (poll->backend);
      Arena_dispose (&poll->arena);
      free (poll);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate event arrays");
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }
}

/**
 * initialize_poll_hash_tables
 */
static void
initialize_poll_hash_tables (T poll)
{
  memset (poll->socket_data_map, 0, sizeof (poll->socket_data_map));
  memset (poll->fd_to_socket_map, 0, sizeof (poll->fd_to_socket_map));
}

/**
 * initialize_poll_mutex
 * Raises: SocketPoll_Failed on failure
 */
static void
initialize_poll_mutex (T poll)
{
  if (pthread_mutex_init (&poll->mutex, NULL) != 0)
    {
      backend_free (poll->backend);
      Arena_dispose (&poll->arena);
      free (poll);
      SOCKET_ERROR_MSG ("Failed to initialize poll mutex");
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }
}

T
SocketPoll_new (int maxevents)
{
  volatile T poll = NULL;

  assert (SOCKET_VALID_POLL_EVENTS (maxevents));

  if (maxevents > SOCKET_MAX_POLL_EVENTS)
    maxevents = SOCKET_MAX_POLL_EVENTS;

  TRY
  {
    poll = allocate_poll_structure ();
    initialize_poll_backend (poll, maxevents);
    poll->maxevents = maxevents;
    poll->default_timeout_ms = SOCKET_DEFAULT_POLL_TIMEOUT;
    initialize_poll_arena (poll);
    allocate_poll_event_arrays (poll, maxevents);
    initialize_poll_hash_tables (poll);
    initialize_poll_mutex (poll);

  /* Initialize timer heap */
  poll->timer_heap = SocketTimer_heap_new (poll->arena);
  if (!poll->timer_heap)
    {
      backend_free (poll->backend);
      Arena_dispose (&poll->arena);
      free (poll);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate timer heap");
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }

    /* Initialize async context (optional - graceful degradation if fails) */
    poll->async = NULL;
    volatile SocketAsync_T volatile_async = NULL;
    TRY
    {
      volatile_async = SocketAsync_new (poll->arena);
      poll->async = (SocketAsync_T)volatile_async;
    }
    EXCEPT (SocketAsync_Failed)
    {
      /* Async unavailable - continue without it */
      poll->async = NULL;
      volatile_async = NULL;
    }
    END_TRY;
  }

  EXCEPT (Arena_Failed)
  {
    if (poll->arena)
      Arena_dispose (&poll->arena);
    if (poll->backend)
      backend_free (poll->backend);
    free (poll);
    RAISE_POLL_ERROR (SocketPoll_Failed);
  }
  EXCEPT (SocketPoll_Failed)
  {
    if (poll->arena)
      Arena_dispose (&poll->arena);
    if (poll->backend)
      backend_free (poll->backend);
    free (poll);
    RERAISE;
  }
  END_TRY;

  return poll;
}

void
SocketPoll_free (T *poll)
{
  if (!poll || !*poll)
    return;

  if ((*poll)->backend)
    backend_free ((*poll)->backend);

  /* Free async context if exists */
  if ((*poll)->async)
    SocketAsync_free (&(*poll)->async);

  /* Free timer heap */
  if ((*poll)->timer_heap)
    SocketTimer_heap_free (&(*poll)->timer_heap);

  /* Destroy mutex */
  pthread_mutex_destroy (&(*poll)->mutex);

  if ((*poll)->arena)
    Arena_dispose (&(*poll)->arena);

  free (*poll);
  *poll = NULL;
}

void
SocketPoll_add (T poll, Socket_T socket, unsigned events, void *data)
{
  volatile int fd;
  volatile Socket_T volatile_socket
      = socket; /* Preserve socket across exception boundaries */
  volatile unsigned hash;
  volatile int is_duplicate = 0;
  volatile SocketData *volatile_entry;

  assert (poll);
  assert (socket);

  /* Cast to non-volatile for Socket API calls */
  fd = Socket_fd ((Socket_T)volatile_socket);
  if (fd < 0)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Adding invalid socket fd=%d to poll; ignoring", fd);
      return;
    }
  /* Socket FD should be valid */

  /* Set non-blocking mode before adding to poll */
  Socket_setnonblocking ((Socket_T)volatile_socket);

  hash = socket_hash ((Socket_T)volatile_socket);

  /* Lock for entire operation to ensure atomicity between dup check, backend
   * add, and data map */
  pthread_mutex_lock (&poll->mutex);
  TRY
  {
    /* Check for duplicates */
    volatile_entry = poll->socket_data_map[hash];
    while (volatile_entry)
      {
        if (volatile_entry->socket == (Socket_T)volatile_socket)
          {
            is_duplicate = 1;
            break;
          }
        volatile_entry = volatile_entry->next;
      }

    if (is_duplicate)
      {
        SOCKET_ERROR_MSG ("Socket already in poll set");
        RAISE_POLL_ERROR (SocketPoll_Failed);
      }

    /* Add to backend - safe to call under lock (non-blocking syscalls) */
    if (backend_add (poll->backend, fd, events) < 0)
      {
        if (errno == EEXIST)
          {
            SOCKET_ERROR_FMT ("Socket already in poll set (fd=%d)", fd);
          }
        else
          {
            SOCKET_ERROR_FMT ("Failed to add socket to poll (fd=%d)", fd);
          }
        RAISE_POLL_ERROR (SocketPoll_Failed);
      }

    /* Add to data map - wrapped in TRY to cleanup backend on failure */
    TRY socket_data_add_unlocked (poll, (Socket_T)volatile_socket, data);
    EXCEPT (SocketPoll_Failed)
    {
      backend_del (poll->backend, fd);
      RERAISE;
    }
    END_TRY;
  }
  FINALLY
  pthread_mutex_unlock (&poll->mutex);
  END_TRY;
  /* Orphaned EXCEPT block fully removed. See TODO above for logic. */
}

void
SocketPoll_mod (T poll, Socket_T socket, unsigned events, void *data)
{
  int fd;
  volatile Socket_T volatile_socket
      = socket; /* Preserve socket across exception boundaries */

  assert (poll);
  assert (socket);

  fd = Socket_fd ((Socket_T)volatile_socket);

  pthread_mutex_lock (&poll->mutex);
  TRY
  {
    /* Modify backend first */
    if (backend_mod (poll->backend, fd, events) < 0)
      {
        if (errno == ENOENT)
          {
            SOCKET_ERROR_FMT ("Socket not in poll set (fd=%d)", fd);
          }
        else
          {
            SOCKET_ERROR_FMT ("Failed to modify socket in poll (fd=%d)", fd);
          }
        /* Unlock before raise */
        pthread_mutex_unlock (&poll->mutex);
        RAISE_POLL_ERROR (SocketPoll_Failed);
      }

    /* Update the socket->data mapping atomically */
    socket_data_update_unlocked (poll, (Socket_T)volatile_socket, data);

    pthread_mutex_unlock (&poll->mutex);
  }
  EXCEPT (SocketPoll_Failed)
  {
    /* See note in SocketPoll_add about lock state */
    pthread_mutex_unlock (&poll->mutex);
    RERAISE;
  }
  END_TRY;
}

void
SocketPoll_del (T poll, Socket_T socket)
{
  int fd;
  volatile Socket_T volatile_socket
      = socket; /* Preserve socket across exception boundaries */

  assert (poll);
  assert (socket);

  fd = Socket_fd ((Socket_T)volatile_socket);

  pthread_mutex_lock (&poll->mutex);

  /* Remove from data map first (so no lookups find it while we delete backend)
   */
  socket_data_remove_unlocked (poll, (Socket_T)volatile_socket);

  pthread_mutex_unlock (&poll->mutex);

  /* Remove from backend - allowed to fail silently */
  if (backend_del (poll->backend, fd) < 0)
    {
      if (errno != ENOENT)
        {
          SOCKET_ERROR_FMT ("Failed to remove socket from poll (fd=%d)", fd);
          RAISE_POLL_ERROR (SocketPoll_Failed);
        }
    }
}

/* ==================== Event Translation Functions ==================== */

/**
 * find_socket_by_fd
 * Thread-safe: No (must be called with poll mutex held)
 * Performs O(1) lookup using the fd_to_socket_map hash table.
 * This provides efficient reverse lookup during event processing.
 */
static Socket_T
find_socket_by_fd (T poll, int fd)
{
  unsigned fd_hash
      = ((unsigned)fd * HASH_GOLDEN_RATIO) % SOCKET_DATA_HASH_SIZE;
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
 * get_backend_event
 * Raises: SocketPoll_Failed on backend error
 */
static void
get_backend_event (T poll, int index, int *fd_out, unsigned *events_out)
{
  if (backend_get_event (poll->backend, index, fd_out, events_out) < 0)
    {
      SOCKET_ERROR_MSG ("Failed to get event from backend");
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }
}

/**
 * translate_single_event - Translate single backend event to SocketEvent_T
 * @poll: Poll instance
 * @index: Backend event index
 * @translated_index: Index in translated events array
 * Returns: 1 if event was translated, 0 if skipped
 * Raises: SocketPoll_Failed on backend error
 */
static int
translate_single_event (T poll, int index, int translated_index)
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

  get_backend_event (poll, index, (int *)&fd, (unsigned *)&event_flags);

  pthread_mutex_lock (&poll->mutex);
  socket = find_socket_by_fd (poll, fd);
  if (!socket)
    {
      pthread_mutex_unlock (&poll->mutex);
      return 0;
    }

  void *associated_data = socket_data_lookup_unlocked (poll, (Socket_T)socket);
  Socket_T non_volatile_socket = (Socket_T)socket;
  pthread_mutex_unlock (&poll->mutex);

  /* Use cached maxevents value for bounds checking */
  /* Ensure translated_index is strictly less than max_events (valid indices
   * are 0 to max_events-1) */
  if (translated_index < 0 || translated_index >= max_events
      || !poll->socketevents)
    return 0;

  /* Validate bounds using pointer arithmetic to prevent any potential overrun
   */
  SocketEvent_T *event_ptr = poll->socketevents + translated_index;
  SocketEvent_T *array_start = poll->socketevents;
  SocketEvent_T *array_end = array_start + max_events;

  /* Additional pointer validation */
  if (event_ptr < array_start || event_ptr >= array_end)
    return 0;

  event_ptr->socket = non_volatile_socket;
  event_ptr->data = associated_data;
  event_ptr->events = event_flags;
  return 1;
}

/**
 * translate_backend_events_to_socket_events - Convert backend events to
 * SocketEvent_T
 * @poll: Poll instance
 * @nfds: Number of events to process
 * Returns: Number of successfully translated events
 * Raises: SocketPoll_Failed on backend error
 * Thread-safe: Yes (socket_data_get handles its own mutex locking)
 * Translates events from the backend-specific format to the
 * standardized SocketEvent_T format used by the public API.
 * Handles socket lookup and data association for each event.
 * Note: find_socket_by_fd requires mutex but socket_data_get also locks mutex,
 * so we lock mutex only for find_socket_by_fd, then unlock before calling
 * socket_data_get.
 */
static int
translate_backend_events_to_socket_events (T poll, int nfds)
{
  volatile int translated_count = 0;
  volatile int i;
  volatile int max_events; /* Cache maxevents to prevent corruption issues */
  volatile int volatile_nfds
      = nfds; /* Preserve nfds across exception boundaries */

  if (!poll || volatile_nfds < 0 || !poll->socketevents
      || poll->maxevents <= 0)
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
        if (translate_single_event (poll, i, translated_count))
          {
            translated_count++;
          }
      }
  }
  EXCEPT (SocketPoll_Failed)
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

int
SocketPoll_getdefaulttimeout (T poll)
{
  int current;

  assert (poll);

  pthread_mutex_lock (&poll->mutex);
  current = poll->default_timeout_ms;
  pthread_mutex_unlock (&poll->mutex);

  return current;
}

void
SocketPoll_setdefaulttimeout (T poll, int timeout)
{
  int sanitized = timeout;

  assert (poll);

  if (sanitized < -1)
    sanitized = 0;

  pthread_mutex_lock (&poll->mutex);
  poll->default_timeout_ms = sanitized;
  pthread_mutex_unlock (&poll->mutex);
}

int
SocketPoll_wait (T poll, SocketEvent_T **events, int timeout)
{
  int nfds;
  int async_completions = 0;
  int timer_completions = 0;

  assert (poll);
  assert (events);

  if (timeout == SOCKET_POLL_TIMEOUT_USE_DEFAULT)
    timeout = poll->default_timeout_ms;

  /* Calculate effective timeout considering timers */
  if (poll->timer_heap)
    {
      int64_t next_timer_ms = SocketTimer_heap_peek_delay (poll->timer_heap);
      if (next_timer_ms >= 0 && (timeout < 0 || next_timer_ms < timeout))
        {
          /* Define maximum reasonable timeout for timer-based wakeups
           * Prevents excessive wait times for timers far in the future */
          const int64_t MAX_TIMER_TIMEOUT_MS = 300000; /* 5 minutes */

          /* Clamp timer delay to maximum reasonable timeout */
          if (next_timer_ms > MAX_TIMER_TIMEOUT_MS)
            next_timer_ms = MAX_TIMER_TIMEOUT_MS;

          /* Ensure the clamped value fits in int */
          if (next_timer_ms > INT_MAX)
            next_timer_ms = INT_MAX;

          timeout = (int)next_timer_ms;
        }
    }

  /* Process async completions first (non-blocking) */
  if (poll->async)
    {
      async_completions = SocketAsync_process_completions (poll->async, 0);
    }

  /* Wait for events from backend */
  nfds = backend_wait (poll->backend, timeout);
  SocketMetrics_increment (SOCKET_METRIC_POLL_WAKEUPS, 1);
  if (nfds < 0)
    {
      if (errno == EINTR)
        {
          *events = NULL;
          return 0; /* Interrupted - not an error */
        }
      SOCKET_ERROR_FMT ("%s backend wait failed (timeout=%d)", backend_name (),
                        timeout);
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }

  /* Process async completions after backend wait (non-blocking) */
  if (poll->async)
    {
      async_completions += SocketAsync_process_completions (poll->async, 0);
    }

  /* Process expired timers after backend wait */
  if (poll->timer_heap)
    {
      timer_completions = SocketTimer_process_expired (poll->timer_heap);
    }

  /* If no events, return immediately */
  if (nfds == 0)
    {
      *events = poll->socketevents; /* Return valid pointer even if empty */
      return 0;
    }

  /* Translate backend events to SocketEvent_T structures */
  nfds = translate_backend_events_to_socket_events (poll, nfds);
  if (nfds > 0)
    SocketMetrics_increment (SOCKET_METRIC_POLL_EVENTS_DISPATCHED,
                             (unsigned long)nfds);
  SocketEvent_emit_poll_wakeup (nfds, timeout);

#ifdef SOCKET_HAS_TLS
  /* Update poll events for TLS sockets that had events and need handshake */
  /* Only check sockets that actually had events (efficient - O(nfds) not
   * O(total sockets)) */
  for (int i = 0; i < nfds; i++)
    {
      Socket_T socket = poll->socketevents[i].socket;
      if (socket && socket_is_tls_enabled (socket))
        {
          /* If handshake is in progress, update events based on TLS state */
          if (!socket->tls_handshake_done)
            {
              socketpoll_update_tls_events (poll, socket);
            }
        }
    }
#endif

  /* Validate poll structure is still intact before returning pointer */
  if (!poll || !poll->socketevents)
    {
      *events = NULL;
      return 0;
    }

  /* Note: Async completions invoke callbacks directly, they don't appear
   * in SocketEvent_T array. The nfds return value only counts backend events.
   */
  (void)async_completions; /* Suppress unused warning */
  (void)timer_completions; /* Suppress unused warning */

  *events = poll->socketevents;
  return nfds;
}

SocketAsync_T
SocketPoll_get_async (T poll)
{
  assert (poll);
  return poll->async;
}

/**
 * socketpoll_get_timer_heap - Get timer heap from poll (private function)
 * @poll: Poll instance
 * Returns: Timer heap pointer or NULL if not available
 * Thread-safe: No (internal use only)
 */
SocketTimer_heap_T *
socketpoll_get_timer_heap (T poll)
{
  assert (poll);
  return poll->timer_heap;
}

#undef T

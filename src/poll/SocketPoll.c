/**
 * SocketPoll.c - Event polling with backend abstraction
 *
 * PLATFORM: Cross-platform (Linux/BSD/macOS/POSIX)
 * - Linux: epoll backend (best performance)
 * - BSD/macOS: kqueue backend (best performance)
 * - Other POSIX: poll(2) fallback (portable)
 *
 * Backend selection is done at compile-time via CMake.
 * See SocketPoll_backend.h for backend interface details.
 *
 * This file contains:
 * - Hash table management for socket-to-data mapping
 * - Initialization and cleanup helpers
 * - Event translation from backend to SocketEvent_T
 * - TLS handshake event handling (conditionally compiled)
 * - Public API implementation
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "poll/SocketPoll-private.h"
#include "poll/SocketPoll_backend.h"
/* Arena.h, Except.h, Socket.h, SocketAsync.h included via SocketPoll-private.h */

#define SOCKET_LOG_COMPONENT "SocketPoll"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "core/SocketEvents.h"
#include "core/SocketLog.h"
#include "core/SocketMetrics.h"

/* Include timer private header after struct definition */
#include "core/SocketTimer-private.h"

#ifdef SOCKET_HAS_TLS
#include "socket/Socket-private.h"
#include "socket/SocketIO.h"
#include "tls/SocketTLS.h"
#endif

#define T SocketPoll_T

const Except_T SocketPoll_Failed
    = { &SocketPoll_Failed, "SocketPoll operation failed" };

/* ==================== Forward Declarations ==================== */

static void cleanup_poll_partial (T poll);

/* ==================== Hash Functions ==================== */

/**
 * compute_fd_hash - Compute hash for file descriptor
 * @fd: File descriptor
 * Returns: Hash value in range [0, SOCKET_DATA_HASH_SIZE)
 *
 * Uses multiplicative hashing with the golden ratio constant for
 * good distribution across hash buckets.
 */
static unsigned
compute_fd_hash (int fd)
{
  return ((unsigned)fd * HASH_GOLDEN_RATIO) % SOCKET_DATA_HASH_SIZE;
}

/**
 * socket_hash - Hash function for socket file descriptors
 * @socket: Socket to hash
 * Returns: Hash value in range [0, SOCKET_DATA_HASH_SIZE)
 *
 * Delegates to compute_fd_hash after extracting file descriptor.
 * Provides O(1) average case performance for socket data lookups.
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

  return compute_fd_hash (fd);
}

/* ==================== Allocation Helpers ==================== */

/**
 * allocate_socket_data_entry - Allocate socket data entry from arena
 * @poll: Poll instance
 * Returns: Allocated entry
 * Raises: SocketPoll_Failed on allocation failure
 */
static SocketData *
allocate_socket_data_entry (T poll)
{
  SocketData *volatile entry = NULL;

  TRY
  entry = CALLOC (poll->arena, 1, sizeof (SocketData));
  EXCEPT (Arena_Failed)
  {
    SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate socket data mapping");
    RAISE_POLL_ERROR (SocketPoll_Failed);
  }
  END_TRY;

  return entry;
}

/**
 * allocate_fd_socket_entry - Allocate FD to socket entry from arena
 * @poll: Poll instance
 * Returns: Allocated entry
 * Raises: SocketPoll_Failed on allocation failure
 */
static FdSocketEntry *
allocate_fd_socket_entry (T poll)
{
  FdSocketEntry *volatile entry = NULL;

  TRY
  entry = CALLOC (poll->arena, 1, sizeof (FdSocketEntry));
  EXCEPT (Arena_Failed)
  {
    SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate fd to socket mapping");
    RAISE_POLL_ERROR (SocketPoll_Failed);
  }
  END_TRY;

  return entry;
}

/* ==================== Hash Table Insertion ==================== */

/**
 * insert_socket_data_entry - Insert socket data entry into hash table
 * @poll: Poll instance
 * @hash: Hash bucket index
 * @entry: Entry to insert
 * Thread-safe: Caller must hold mutex
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
 * Thread-safe: Caller must hold mutex
 */
static void
insert_fd_socket_entry (T poll, unsigned fd_hash, FdSocketEntry *entry)
{
  entry->next = poll->fd_to_socket_map[fd_hash];
  poll->fd_to_socket_map[fd_hash] = entry;
}

/* ==================== Hash Table Lookup ==================== */

/**
 * socket_data_lookup_unlocked - Retrieve user data for socket
 * @poll: Poll instance
 * @socket: Socket to look up
 * Returns: User data associated with socket, or NULL if not found
 * Thread-safe: No (caller must hold mutex)
 *
 * Performs O(1) average case lookup in the socket data hash table.
 */
static void *
socket_data_lookup_unlocked (T poll, Socket_T socket)
{
  unsigned hash;
  SocketData *entry;

  if (!poll || !socket)
    return NULL;

  hash = socket_hash (socket);
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
 * find_socket_data_entry - Find socket data entry in hash table
 * @poll: Poll instance
 * @hash: Hash bucket index
 * @socket: Socket to find
 * Returns: Entry or NULL if not found
 * Thread-safe: No (caller must hold mutex)
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

/* ==================== Hash Table Removal ==================== */

/**
 * remove_socket_data_entry - Remove socket data entry from hash table
 * @poll: Poll instance
 * @hash: Hash bucket index
 * @socket: Socket to remove
 * Thread-safe: No (caller must hold mutex)
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
          return;
        }
      pp = &(*pp)->next;
    }
}

/**
 * remove_fd_socket_entry - Remove FD to socket entry from hash table
 * @poll: Poll instance
 * @fd_hash: Hash bucket index
 * @fd: File descriptor to remove
 * Thread-safe: No (caller must hold mutex)
 */
static void
remove_fd_socket_entry (T poll, unsigned fd_hash, int fd)
{
  FdSocketEntry **pp = &poll->fd_to_socket_map[fd_hash];

  while (*pp)
    {
      if ((*pp)->fd == fd)
        {
          *pp = (*pp)->next;
          return;
        }
      pp = &(*pp)->next;
    }
}

/* ==================== Unlocked Hash Table Operations ==================== */

/**
 * socket_data_add_unlocked - Add socket data mapping (caller holds lock)
 * @poll: Poll instance
 * @socket: Socket
 * @data: User data
 * Raises: SocketPoll_Failed on allocation failure
 */
static void
socket_data_add_unlocked (T poll, Socket_T socket, void *data)
{
  int fd = Socket_fd (socket);
  unsigned hash = socket_hash (socket);
  unsigned fd_hash = compute_fd_hash (fd);
  SocketData *data_entry = allocate_socket_data_entry (poll);
  FdSocketEntry *fd_entry = allocate_fd_socket_entry (poll);

  data_entry->socket = socket;
  data_entry->data = data;
  fd_entry->fd = fd;
  fd_entry->socket = socket;

  insert_socket_data_entry (poll, hash, data_entry);
  insert_fd_socket_entry (poll, fd_hash, fd_entry);
}

/**
 * socket_data_update_unlocked - Update data (caller holds lock)
 * @poll: Poll instance
 * @socket: Socket
 * @data: New data
 * Raises: SocketPoll_Failed on allocation failure (fallback)
 */
static void
socket_data_update_unlocked (T poll, Socket_T socket, void *data)
{
  unsigned hash = socket_hash (socket);
  SocketData *entry = find_socket_data_entry (poll, hash, socket);

  if (entry)
    {
      entry->data = data;
      return;
    }

  /* Fallback: socket not found, add new entry */
#ifndef NDEBUG
  SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                   "socket_data_update_unlocked fallback (fd %d)",
                   Socket_fd (socket));
#endif

  entry = allocate_socket_data_entry (poll);
  entry->socket = socket;
  entry->data = data;
  insert_socket_data_entry (poll, hash, entry);
}

/**
 * socket_data_remove_unlocked - Remove mappings (caller holds lock)
 * @poll: Poll instance
 * @socket: Socket
 */
static void
socket_data_remove_unlocked (T poll, Socket_T socket)
{
  int fd = Socket_fd (socket);
  unsigned hash = socket_hash (socket);
  unsigned fd_hash = compute_fd_hash (fd);

  remove_socket_data_entry (poll, hash, socket);
  remove_fd_socket_entry (poll, fd_hash, fd);
}

/* ==================== Initialization Helpers ==================== */

/**
 * INIT_FAIL - Cleanup and raise exception during init
 * Reduces repeated error handling pattern in init functions.
 */
#define INIT_FAIL(msg)                                                         \
  do                                                                           \
    {                                                                          \
      SOCKET_ERROR_MSG (msg);                                                  \
      cleanup_poll_partial (poll);                                             \
      RAISE_POLL_ERROR (SocketPoll_Failed);                                    \
    }                                                                          \
  while (0)

#define INIT_FAIL_FMT(fmt, ...)                                                \
  do                                                                           \
    {                                                                          \
      SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__);                                   \
      cleanup_poll_partial (poll);                                             \
      RAISE_POLL_ERROR (SocketPoll_Failed);                                    \
    }                                                                          \
  while (0)

/**
 * cleanup_poll_partial - Free partially initialized poll structure
 * @poll: Poll instance to clean up
 *
 * Cleans up resources in reverse order of acquisition.
 * Safe to call with NULL members.
 */
static void
cleanup_poll_partial (T poll)
{
  if (!poll)
    return;

  if (poll->backend)
    backend_free (poll->backend);

  if (poll->arena)
    Arena_dispose (&poll->arena);

  free (poll);
}

/**
 * allocate_poll_structure - Allocate poll structure
 * Returns: Allocated poll structure (zero-initialized)
 * Raises: SocketPoll_Failed on allocation failure
 */
static T
allocate_poll_structure (void)
{
  T poll = calloc (1, sizeof (*poll));

  if (!poll)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate poll structure");
      RAISE_POLL_ERROR (SocketPoll_Failed); /* No cleanup needed yet */
    }

  return poll;
}

/**
 * initialize_poll_backend - Initialize poll backend
 * @poll: Poll instance
 * @maxevents: Maximum events
 * Raises: SocketPoll_Failed on failure
 */
static void
initialize_poll_backend (T poll, int maxevents)
{
  poll->backend = backend_new (maxevents);

  if (!poll->backend)
    INIT_FAIL_FMT ("Failed to create %s backend", backend_name ());
}

/**
 * initialize_poll_arena - Initialize poll arena
 * @poll: Poll instance
 * Raises: SocketPoll_Failed on failure
 */
static void
initialize_poll_arena (T poll)
{
  poll->arena = Arena_new ();

  if (!poll->arena)
    INIT_FAIL (SOCKET_ENOMEM ": Cannot allocate poll arena");
}

/**
 * allocate_poll_event_arrays - Allocate event arrays
 * @poll: Poll instance
 * @maxevents: Maximum events
 * Raises: SocketPoll_Failed on failure
 */
static void
allocate_poll_event_arrays (T poll, int maxevents)
{
  size_t array_size;

  if (maxevents <= 0 || maxevents > SOCKET_MAX_POLL_EVENTS)
    INIT_FAIL ("Invalid maxevents value");

  /* Calculate array size with overflow check */
  array_size = (size_t)maxevents * sizeof (*poll->socketevents);
  if (array_size / sizeof (*poll->socketevents) != (size_t)maxevents)
    INIT_FAIL ("Array size overflow");

  poll->socketevents
      = CALLOC (poll->arena, maxevents, sizeof (*poll->socketevents));

  if (!poll->socketevents)
    INIT_FAIL (SOCKET_ENOMEM ": Cannot allocate event arrays");
}

/**
 * initialize_poll_mutex - Initialize mutex
 * @poll: Poll instance
 * Raises: SocketPoll_Failed on failure
 */
static void
initialize_poll_mutex (T poll)
{
  if (pthread_mutex_init (&poll->mutex, NULL) != 0)
    INIT_FAIL ("Failed to initialize poll mutex");
}

/**
 * initialize_poll_timer_heap - Initialize timer heap
 * @poll: Poll instance
 * Raises: SocketPoll_Failed on allocation failure
 */
static void
initialize_poll_timer_heap (T poll)
{
  poll->timer_heap = SocketTimer_heap_new (poll->arena);

  if (!poll->timer_heap)
    INIT_FAIL (SOCKET_ENOMEM ": Cannot allocate timer heap");
}

/**
 * initialize_poll_async - Initialize async context (optional)
 * @poll: Poll instance
 *
 * Async context is optional - graceful degradation if unavailable.
 * Does not raise exceptions on failure.
 */
static void
initialize_poll_async (T poll)
{
  /* async starts NULL from calloc; only set if init succeeds */
  TRY
  poll->async = SocketAsync_new (poll->arena);
  EXCEPT (SocketAsync_Failed)
  poll->async = NULL; /* Graceful degradation - async is optional */
  END_TRY;
}

/* ==================== FD to Socket Lookup ==================== */

/**
 * find_socket_by_fd - Find socket by file descriptor
 * @poll: Poll instance
 * @fd: File descriptor to look up
 * Returns: Socket or NULL if not found
 * Thread-safe: No (must be called with poll mutex held)
 *
 * Performs O(1) lookup using the fd_to_socket_map hash table.
 */
static Socket_T
find_socket_by_fd (T poll, int fd)
{
  unsigned fd_hash = compute_fd_hash (fd);
  FdSocketEntry *entry = poll->fd_to_socket_map[fd_hash];

  while (entry)
    {
      if (entry->fd == fd)
        return entry->socket;
      entry = entry->next;
    }

  return NULL;
}

/* ==================== Event Translation ==================== */

/**
 * get_backend_event - Get event from backend
 * @poll: Poll instance
 * @index: Event index
 * @fd_out: Output file descriptor
 * @events_out: Output event flags
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
 * @max_events: Maximum events (bounds check)
 * Returns: 1 if event was translated, 0 if skipped
 * Raises: SocketPoll_Failed on backend error
 */
static int
translate_single_event (T poll, int index, int translated_index, int max_events)
{
  int fd;
  unsigned event_flags;
  Socket_T socket;
  void *data;
  SocketEvent_T *event;

  /* Bounds check */
  if (translated_index >= max_events)
    return 0;

  get_backend_event (poll, index, &fd, &event_flags);

  pthread_mutex_lock (&poll->mutex);
  socket = find_socket_by_fd (poll, fd);

  if (!socket)
    {
      pthread_mutex_unlock (&poll->mutex);
      return 0;
    }

  data = socket_data_lookup_unlocked (poll, socket);
  pthread_mutex_unlock (&poll->mutex);

  event = &poll->socketevents[translated_index];
  event->socket = socket;
  event->data = data;
  event->events = event_flags;

  return 1;
}

/**
 * translate_backend_events_to_socket_events - Convert backend events
 * @poll: Poll instance
 * @nfds: Number of events to process
 * Returns: Number of successfully translated events
 * Raises: SocketPoll_Failed on backend error
 * Thread-safe: Yes (socket_data_lookup handles its own mutex locking)
 *
 * Translates events from the backend-specific format to the
 * standardized SocketEvent_T format used by the public API.
 */
static int
translate_backend_events_to_socket_events (T poll, int nfds)
{
  /* volatile to prevent clobbering by setjmp/longjmp in TRY/EXCEPT */
  volatile int translated_count = 0;
  volatile int nfds_local;
  int max_events;
  int i;

  assert (poll);

  if (nfds <= 0 || !poll->socketevents || poll->maxevents <= 0)
    return 0;

  max_events = poll->maxevents;

  /* Copy nfds to volatile local and clamp to max_events */
  nfds_local = (nfds > max_events) ? max_events : nfds;

  TRY
  {
    for (i = 0; i < nfds_local && translated_count < max_events; i++)
      {
        if (translate_single_event (poll, i, translated_count, max_events))
          translated_count++;
      }
  }
  EXCEPT (SocketPoll_Failed)
  {
    /* Exception already handled, return partial results */
  }
  END_TRY;

  return translated_count;
}

/* ==================== TLS Event Handling ==================== */

#ifdef SOCKET_HAS_TLS

/**
 * socketpoll_update_tls_events - Update poll events based on TLS state
 * @poll: Poll instance
 * @socket: Socket with TLS enabled
 *
 * Updates the poll event mask for a TLS-enabled socket based on its
 * current handshake state. Called during event processing to ensure
 * the socket is monitored for the correct I/O direction.
 *
 * Thread-safe: Yes - uses poll mutex for data lookup.
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
      if (socket_tls_want_read (socket))
        events |= POLL_READ;
      if (socket_tls_want_write (socket))
        events |= POLL_WRITE;

      if (events != 0)
        {
          pthread_mutex_lock (&poll->mutex);
          user_data = socket_data_lookup_unlocked (poll, socket);
          pthread_mutex_unlock (&poll->mutex);

          SocketPoll_mod (poll, socket, events, user_data);
        }
    }
}

/**
 * socketpoll_process_tls_handshakes - Process TLS handshakes for ready events
 * @poll: Poll instance
 * @nfds: Number of events to process
 *
 * Iterates through ready events and updates poll registration for any
 * TLS sockets that are still completing their handshake.
 *
 * Thread-safe: Yes - internal locking handled by socketpoll_update_tls_events.
 */
static void
socketpoll_process_tls_handshakes (T poll, int nfds)
{
  int i;
  Socket_T socket;

  assert (poll);

  if (!poll->socketevents || nfds <= 0)
    return;

  for (i = 0; i < nfds; i++)
    {
      socket = poll->socketevents[i].socket;
      /* socketpoll_update_tls_events handles TLS check internally */
      if (socket && !socket->tls_handshake_done)
        socketpoll_update_tls_events (poll, socket);
    }
}

#endif /* SOCKET_HAS_TLS */

/* ==================== Constructor ==================== */

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
    initialize_poll_backend ((T)poll, maxevents);
    ((T)poll)->maxevents = maxevents;
    ((T)poll)->default_timeout_ms = SOCKET_DEFAULT_POLL_TIMEOUT;
    initialize_poll_arena ((T)poll);
    allocate_poll_event_arrays ((T)poll, maxevents);
    /* Note: Hash tables already zeroed by calloc in allocate_poll_structure */
    initialize_poll_mutex ((T)poll);
    initialize_poll_timer_heap ((T)poll);
    initialize_poll_async ((T)poll);
  }
  EXCEPT (Arena_Failed)
  EXCEPT (SocketPoll_Failed)
  {
    cleanup_poll_partial ((T)poll);
    RAISE_POLL_ERROR (SocketPoll_Failed);
  }
  END_TRY;

  return (T)poll;
}

/* ==================== Destructor ==================== */

void
SocketPoll_free (T *poll)
{
  if (!poll || !*poll)
    return;

  if ((*poll)->backend)
    backend_free ((*poll)->backend);

  if ((*poll)->async)
    SocketAsync_free (&(*poll)->async);

  if ((*poll)->timer_heap)
    SocketTimer_heap_free (&(*poll)->timer_heap);

  pthread_mutex_destroy (&(*poll)->mutex);

  if ((*poll)->arena)
    Arena_dispose (&(*poll)->arena);

  free (*poll);
  *poll = NULL;
}

/* ==================== Add Socket to Poll ==================== */

void
SocketPoll_add (T poll, Socket_T socket, unsigned events, void *data)
{
  int fd;
  unsigned hash;
  SocketData *entry;

  assert (poll);
  assert (socket);

  fd = Socket_fd (socket);
  if (fd < 0)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Adding invalid socket fd=%d to poll; ignoring", fd);
      return;
    }

  Socket_setnonblocking (socket);
  hash = socket_hash (socket);

  pthread_mutex_lock (&poll->mutex);
  TRY
  {
    /* Check for duplicates */
    entry = poll->socket_data_map[hash];
    while (entry)
      {
        if (entry->socket == socket)
          {
            SOCKET_ERROR_MSG ("Socket already in poll set");
            RAISE_POLL_ERROR (SocketPoll_Failed);
          }
        entry = entry->next;
      }

    /* Add to backend */
    if (backend_add (poll->backend, fd, events) < 0)
      {
        if (errno == EEXIST)
          SOCKET_ERROR_FMT ("Socket already in poll set (fd=%d)", fd);
        else
          SOCKET_ERROR_FMT ("Failed to add socket to poll (fd=%d)", fd);
        RAISE_POLL_ERROR (SocketPoll_Failed);
      }

    /* Add to data map */
    TRY
    socket_data_add_unlocked (poll, socket, data);
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
}

/* ==================== Modify Socket Events ==================== */

void
SocketPoll_mod (T poll, Socket_T socket, unsigned events, void *data)
{
  int fd;

  assert (poll);
  assert (socket);

  fd = Socket_fd (socket);

  pthread_mutex_lock (&poll->mutex);
  TRY
  {
    if (backend_mod (poll->backend, fd, events) < 0)
      {
        if (errno == ENOENT)
          SOCKET_ERROR_FMT ("Socket not in poll set (fd=%d)", fd);
        else
          SOCKET_ERROR_FMT ("Failed to modify socket in poll (fd=%d)", fd);
        RAISE_POLL_ERROR (SocketPoll_Failed);
      }

    socket_data_update_unlocked (poll, socket, data);
  }
  FINALLY
  pthread_mutex_unlock (&poll->mutex);
  END_TRY;
}

/* ==================== Remove Socket from Poll ==================== */

void
SocketPoll_del (T poll, Socket_T socket)
{
  int fd;

  assert (poll);
  assert (socket);

  fd = Socket_fd (socket);

  pthread_mutex_lock (&poll->mutex);
  socket_data_remove_unlocked (poll, socket);
  pthread_mutex_unlock (&poll->mutex);

  if (backend_del (poll->backend, fd) < 0 && errno != ENOENT)
    {
      SOCKET_ERROR_FMT ("Failed to remove socket from poll (fd=%d)", fd);
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }
}

/* ==================== Timeout Accessors ==================== */

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
  assert (poll);

  if (timeout < -1)
    timeout = 0;

  pthread_mutex_lock (&poll->mutex);
  poll->default_timeout_ms = timeout;
  pthread_mutex_unlock (&poll->mutex);
}

/* ==================== Wait for Events ==================== */

int
SocketPoll_wait (T poll, SocketEvent_T **events, int timeout)
{
  int nfds;

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
          if (next_timer_ms > SOCKET_MAX_TIMER_TIMEOUT_MS)
            next_timer_ms = SOCKET_MAX_TIMER_TIMEOUT_MS;
          if (next_timer_ms > INT_MAX)
            next_timer_ms = INT_MAX;
          timeout = (int)next_timer_ms;
        }
    }

  /* Process async completions first */
  if (poll->async)
    SocketAsync_process_completions (poll->async, 0);

  /* Wait for events from backend */
  nfds = backend_wait (poll->backend, timeout);
  SocketMetrics_increment (SOCKET_METRIC_POLL_WAKEUPS, 1);

  if (nfds < 0)
    {
      if (errno == EINTR)
        {
          *events = NULL;
          return 0;
        }
      SOCKET_ERROR_FMT ("%s backend wait failed (timeout=%d)", backend_name (),
                        timeout);
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }

  /* Process async completions after wait */
  if (poll->async)
    SocketAsync_process_completions (poll->async, 0);

  /* Process expired timers */
  if (poll->timer_heap)
    SocketTimer_process_expired (poll->timer_heap);

  if (nfds == 0)
    {
      *events = poll->socketevents;
      return 0;
    }

  /* Translate backend events */
  nfds = translate_backend_events_to_socket_events (poll, nfds);

  if (nfds > 0)
    SocketMetrics_increment (SOCKET_METRIC_POLL_EVENTS_DISPATCHED,
                             (unsigned long)nfds);

  SocketEvent_emit_poll_wakeup (nfds, timeout);

#ifdef SOCKET_HAS_TLS
  /* Update poll events for TLS sockets in handshake */
  socketpoll_process_tls_handshakes (poll, nfds);
#endif

  *events = poll->socketevents;
  return nfds;
}

/* ==================== Accessors ==================== */

SocketAsync_T
SocketPoll_get_async (T poll)
{
  assert (poll);
  return poll->async;
}

/**
 * socketpoll_get_timer_heap - Get timer heap from poll (private function)
 * @poll: Poll instance
 * Returns: Timer heap pointer or NULL
 */
SocketTimer_heap_T *
socketpoll_get_timer_heap (T poll)
{
  assert (poll);
  return poll->timer_heap;
}

#undef T

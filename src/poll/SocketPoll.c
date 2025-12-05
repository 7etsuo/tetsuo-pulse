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
/* Arena.h, Except.h, Socket.h, SocketAsync.h, SocketUtil.h included via SocketPoll-private.h */

/* Override default log component (SocketUtil.h sets "Socket") */
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketPoll"
#include "core/SocketConfig.h"

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

/**
 * Thread-local exception for detailed error messages.
 * REFACTOR: Now uses centralized SOCKET_DECLARE_MODULE_EXCEPTION macro
 * from SocketUtil.h instead of manual platform-specific declarations.
 */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketPoll);

/* ==================== Forward Declarations ==================== */

static void cleanup_poll_partial (T poll);

/* ==================== Allocation Helpers ==================== */

/**
 * ALLOC_ENTRY - Generic arena allocation with exception handling
 * Eliminates duplicate allocation helpers for SocketData and FdSocketEntry.
 */
#define ALLOC_ENTRY(poll, type, errmsg)                                        \
  ({                                                                           \
    type *volatile _entry = NULL;                                              \
    TRY                                                                        \
    _entry = CALLOC ((poll)->arena, 1, sizeof (type));                         \
    EXCEPT (Arena_Failed)                                                      \
    {                                                                          \
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": " errmsg);                            \
      RAISE_POLL_ERROR (SocketPoll_Failed);                                    \
    }                                                                          \
    END_TRY;                                                                   \
    _entry;                                                                    \
  })

/**
 * allocate_socket_data_entry - Allocate socket data entry from arena
 * @poll: Poll instance
 * Returns: Allocated entry
 * Raises: SocketPoll_Failed on allocation failure
 */
static inline SocketData *
allocate_socket_data_entry (T poll)
{
  return ALLOC_ENTRY (poll, SocketData, "Cannot allocate socket data mapping");
}

/**
 * allocate_fd_socket_entry - Allocate FD to socket entry from arena
 * @poll: Poll instance
 * Returns: Allocated entry
 * Raises: SocketPoll_Failed on allocation failure
 */
static inline FdSocketEntry *
allocate_fd_socket_entry (T poll)
{
  return ALLOC_ENTRY (poll, FdSocketEntry,
                      "Cannot allocate fd to socket mapping");
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
 * find_socket_data_entry - Find socket data entry in hash table
 * @poll: Poll instance
 * @hash: Hash bucket index
 * @socket: Socket to find
 * Returns: Entry or NULL if not found
 * Thread-safe: No (caller must hold mutex)
 *
 * Core lookup function - O(1) average case with hash chain traversal.
 */
static SocketData *
find_socket_data_entry (const T poll, const unsigned hash,
                        const Socket_T socket)
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
 * socket_data_lookup_unlocked - Retrieve user data for socket
 * @poll: Poll instance
 * @socket: Socket to look up
 * Returns: User data associated with socket, or NULL if not found
 * Thread-safe: No (caller must hold mutex)
 *
 * Wrapper around find_socket_data_entry that extracts user data.
 * Uses fd directly for hashing to avoid redundant Socket_fd calls.
 */
static void *
socket_data_lookup_unlocked (const T poll, const Socket_T socket)
{
  int fd;
  unsigned hash;
  SocketData *entry;

  if (!poll || !socket)
    return NULL;

  fd = Socket_fd (socket);
  if (fd < 0)
    return NULL;

  hash = socket_util_hash_fd (fd, SOCKET_DATA_HASH_SIZE);
  entry = find_socket_data_entry (poll, hash, socket);

  return entry ? entry->data : NULL;
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
 *
 * Uses fd directly for hashing to avoid redundant Socket_fd calls.
 */
static void
socket_data_add_unlocked (T poll, Socket_T socket, void *data)
{
  int fd = Socket_fd (socket);
  unsigned hash = socket_util_hash_fd (fd, SOCKET_DATA_HASH_SIZE);
  SocketData *data_entry = allocate_socket_data_entry (poll);
  FdSocketEntry *fd_entry = allocate_fd_socket_entry (poll);

  data_entry->socket = socket;
  data_entry->data = data;
  fd_entry->fd = fd;
  fd_entry->socket = socket;

  insert_socket_data_entry (poll, hash, data_entry);
  insert_fd_socket_entry (poll, hash, fd_entry);
}

/**
 * socket_data_remove_unlocked - Remove mappings (caller holds lock)
 * @poll: Poll instance
 * @socket: Socket
 *
 * Uses fd directly for hashing to avoid redundant Socket_fd calls.
 */
static void
socket_data_remove_unlocked (T poll, Socket_T socket)
{
  int fd = Socket_fd (socket);
  unsigned hash = socket_util_hash_fd (fd, SOCKET_DATA_HASH_SIZE);

  remove_socket_data_entry (poll, hash, socket);
  remove_fd_socket_entry (poll, hash, fd);
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

/* ==================== Combined FD Lookup (Optimized) ==================== */

/**
 * lookup_socket_and_data_by_fd - Find socket and user data by FD in one pass
 * @poll: Poll instance
 * @fd: File descriptor to look up
 * @fd_hash: Pre-computed hash bucket index
 * @socket_out: Output socket (NULL if not found)
 * @data_out: Output user data (NULL if not found)
 * Thread-safe: No (caller must hold mutex)
 *
 * Optimized lookup that finds both socket and user data using the same
 * hash bucket, avoiding redundant Socket_fd() calls and double chain walks.
 * Both fd_to_socket_map and socket_data_map use fd-based hashing.
 */
static void
lookup_socket_and_data_by_fd (const T poll, const int fd,
                              const unsigned fd_hash, Socket_T *socket_out,
                              void **data_out)
{
  FdSocketEntry *fd_entry;
  SocketData *data_entry;
  Socket_T socket = NULL;

  /* Find socket via fd_to_socket_map */
  fd_entry = poll->fd_to_socket_map[fd_hash];
  while (fd_entry)
    {
      if (fd_entry->fd == fd)
        {
          socket = fd_entry->socket;
          break;
        }
      fd_entry = fd_entry->next;
    }

  if (!socket)
    {
      *socket_out = NULL;
      *data_out = NULL;
      return;
    }

  /* Find user data via socket_data_map (same hash bucket) */
  data_entry = poll->socket_data_map[fd_hash];
  while (data_entry)
    {
      if (data_entry->socket == socket)
        {
          *socket_out = socket;
          *data_out = data_entry->data;
          return;
        }
      data_entry = data_entry->next;
    }

  /* Socket found but no data entry (shouldn't happen in normal use) */
  *socket_out = socket;
  *data_out = NULL;
}

/* ==================== Event Translation ==================== */

/**
 * translate_backend_events_to_socket_events - Convert backend events
 * @poll: Poll instance
 * @nfds: Number of events to process
 * Returns: Number of successfully translated events
 * Thread-safe: Yes (uses batched mutex acquisition)
 *
 * Translates events from the backend-specific format to the
 * standardized SocketEvent_T format. Uses batched mutex handling
 * to minimize lock contention. Optimized to avoid redundant fd
 * lookups by computing hash once and reusing for both maps.
 */
static int
translate_backend_events_to_socket_events (T poll, int nfds)
{
  int translated_count = 0;
  int nfds_local;
  int i;

  assert (poll);

  if (nfds <= 0 || !poll->socketevents)
    return 0;

  /* Clamp to maxevents (validated at construction) */
  nfds_local = (nfds > poll->maxevents) ? poll->maxevents : nfds;

  pthread_mutex_lock (&poll->mutex);

  for (i = 0; i < nfds_local && translated_count < poll->maxevents; i++)
    {
      int fd;
      unsigned event_flags;
      unsigned fd_hash;
      Socket_T socket;
      void *data;

      /* Get event directly from backend (inlined) */
      if (backend_get_event (poll->backend, i, &fd, &event_flags) < 0)
        continue;

      /* Compute hash once, use for both lookups */
      fd_hash = socket_util_hash_fd (fd, SOCKET_DATA_HASH_SIZE);
      lookup_socket_and_data_by_fd (poll, fd, fd_hash, &socket, &data);

      if (!socket)
        continue;

      /* Populate event directly (inlined) */
      poll->socketevents[translated_count].socket = socket;
      poll->socketevents[translated_count].data = data;
      poll->socketevents[translated_count].events = event_flags;
      translated_count++;
    }

  pthread_mutex_unlock (&poll->mutex);

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

/* ==================== Add Socket Helpers ==================== */

/**
 * validate_socket_fd_for_add - Validate socket FD is usable
 * @socket: Socket to validate
 * Returns: FD if valid, -1 if invalid (logs warning)
 */
static int
validate_socket_fd_for_add (const Socket_T socket)
{
  int fd = Socket_fd (socket);

  if (fd < 0)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Adding invalid socket fd=%d to poll; ignoring", fd);
      return -1;
    }

  return fd;
}

/**
 * check_socket_not_duplicate - Check socket not already in poll set
 * @poll: Poll instance
 * @hash: Hash bucket index
 * @socket: Socket to check
 * Raises: SocketPoll_Failed if socket already present
 * Thread-safe: No (caller must hold mutex)
 */
static void
check_socket_not_duplicate (T poll, unsigned hash, Socket_T socket)
{
  SocketData *entry = poll->socket_data_map[hash];

  while (entry)
    {
      if (entry->socket == socket)
        {
          SOCKET_ERROR_MSG ("Socket already in poll set");
          RAISE_POLL_ERROR (SocketPoll_Failed);
        }
      entry = entry->next;
    }
}

/**
 * add_socket_to_backend - Add socket FD to backend
 * @poll: Poll instance
 * @fd: File descriptor
 * @events: Events to monitor
 * Raises: SocketPoll_Failed on backend error
 */
static void
add_socket_to_backend (T poll, int fd, unsigned events)
{
  if (backend_add (poll->backend, fd, events) < 0)
    {
      if (errno == EEXIST)
        SOCKET_ERROR_FMT ("Socket already in poll set (fd=%d)", fd);
      else
        SOCKET_ERROR_FMT ("Failed to add socket to poll (fd=%d)", fd);
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }
}

/**
 * add_socket_to_data_map_with_rollback - Add to data map, rollback on failure
 * @poll: Poll instance
 * @socket: Socket
 * @data: User data
 * @fd: File descriptor (for rollback)
 * Raises: SocketPoll_Failed on allocation failure
 * Thread-safe: No (caller must hold mutex)
 */
static void
add_socket_to_data_map_with_rollback (T poll, Socket_T socket, void *data,
                                      int fd)
{
  TRY
  socket_data_add_unlocked (poll, socket, data);
  EXCEPT (SocketPoll_Failed)
  {
    backend_del (poll->backend, fd);
    RERAISE;
  }
  END_TRY;
}

/* ==================== Add Socket to Poll ==================== */

void
SocketPoll_add (T poll, Socket_T socket, unsigned events, void *data)
{
  int fd;
  unsigned hash;

  assert (poll);
  assert (socket);

  fd = validate_socket_fd_for_add (socket);
  if (fd < 0)
    return;

  Socket_setnonblocking (socket);
  hash = socket_util_hash_fd (fd, SOCKET_DATA_HASH_SIZE);

  pthread_mutex_lock (&poll->mutex);
  TRY
  {
    check_socket_not_duplicate (poll, hash, socket);
    add_socket_to_backend (poll, fd, events);
    add_socket_to_data_map_with_rollback (poll, socket, data, fd);
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
  unsigned hash;

  assert (poll);
  assert (socket);

  fd = Socket_fd (socket);
  hash = socket_util_hash_fd (fd, SOCKET_DATA_HASH_SIZE);

  pthread_mutex_lock (&poll->mutex);
  TRY
  {
    /* Check socket is in poll set BEFORE modifying backend.
     * This is required because kqueue's mod uses delete+add which would
     * silently succeed for sockets never added to the poll set. */
    SocketData *entry = find_socket_data_entry (poll, hash, socket);
    if (!entry)
      {
        SOCKET_ERROR_FMT ("Socket not in poll set (fd=%d)", fd);
        RAISE_POLL_ERROR (SocketPoll_Failed);
      }

    if (backend_mod (poll->backend, fd, events) < 0)
      {
        if (errno == ENOENT)
          SOCKET_ERROR_FMT ("Socket not in poll set (fd=%d)", fd);
        else
          SOCKET_ERROR_FMT ("Failed to modify socket in poll (fd=%d)", fd);
        RAISE_POLL_ERROR (SocketPoll_Failed);
      }

    entry->data = data; /* Update data directly since we found the entry */
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

/* ==================== Wait Helper Functions ==================== */

/**
 * resolve_timeout_from_default - Resolve timeout using default if requested
 * @poll: Poll instance
 * @timeout: Input timeout (may be SOCKET_POLL_TIMEOUT_USE_DEFAULT)
 * Returns: Resolved timeout value
 */
static int
resolve_timeout_from_default (const T poll, const int timeout)
{
  if (timeout == SOCKET_POLL_TIMEOUT_USE_DEFAULT)
    return poll->default_timeout_ms;
  return timeout;
}

/**
 * clamp_timer_timeout - Clamp timer delay to safe range
 * @next_timer_ms: Timer delay in milliseconds
 * Returns: Clamped timeout value safe for int conversion
 */
static int
clamp_timer_timeout (const int64_t next_timer_ms)
{
  int64_t clamped = next_timer_ms;

  if (clamped > SOCKET_MAX_TIMER_TIMEOUT_MS)
    clamped = SOCKET_MAX_TIMER_TIMEOUT_MS;
  if (clamped > INT_MAX)
    clamped = INT_MAX;

  return (int)clamped;
}

/**
 * calculate_effective_timeout - Compute timeout considering timers
 * @poll: Poll instance
 * @timeout: Requested timeout
 * Returns: Effective timeout that respects pending timers
 */
static int
calculate_effective_timeout (const T poll, const int timeout)
{
  int64_t next_timer_ms;

  if (!poll->timer_heap)
    return timeout;

  next_timer_ms = SocketTimer_heap_peek_delay (poll->timer_heap);

  if (next_timer_ms >= 0 && (timeout < 0 || next_timer_ms < timeout))
    return clamp_timer_timeout (next_timer_ms);

  return timeout;
}

/**
 * process_async_completions_if_available - Process async completions
 * @poll: Poll instance
 *
 * Processes any pending async I/O completions if async context exists.
 */
static void
process_async_completions_if_available (T poll)
{
  if (poll->async)
    SocketAsync_process_completions (poll->async, 0);
}

/**
 * wait_for_backend_events - Wait for events from backend
 * @poll: Poll instance
 * @timeout: Timeout in milliseconds
 * Returns: Number of ready events, or -1 on error
 */
static int
wait_for_backend_events (T poll, int timeout)
{
  int nfds = backend_wait (poll->backend, timeout);
  SocketMetrics_increment (SOCKET_METRIC_POLL_WAKEUPS, 1);
  return nfds;
}

/**
 * handle_backend_wait_error - Handle error from backend_wait
 * @timeout: Timeout that was used
 * Returns: 0 if EINTR (caller should return)
 * Raises: SocketPoll_Failed on non-EINTR errors (does not return)
 */
static int
handle_backend_wait_error (int timeout)
{
  if (errno == EINTR)
    return 0;

  SOCKET_ERROR_FMT ("%s backend wait failed (timeout=%d)", backend_name (),
                    timeout);
  RAISE_POLL_ERROR (SocketPoll_Failed);
  return -1; /* NOTREACHED - satisfies compiler warning */
}

/**
 * process_timers_if_available - Process expired timers
 * @poll: Poll instance
 */
static void
process_timers_if_available (T poll)
{
  if (poll->timer_heap)
    SocketTimer_process_expired (poll->timer_heap);
}

/**
 * emit_event_metrics - Emit metrics for dispatched events
 * @nfds: Number of events
 * @timeout: Timeout used
 */
static void
emit_event_metrics (const int nfds, const int timeout)
{
  if (nfds > 0)
    SocketMetrics_increment (SOCKET_METRIC_POLL_EVENTS_DISPATCHED,
                             (unsigned long)nfds);

  SocketEvent_emit_poll_wakeup (nfds, timeout);
}

/* ==================== Wait for Events ==================== */

int
SocketPoll_wait (T poll, SocketEvent_T **events, int timeout)
{
  int nfds;

  assert (poll);
  assert (events);

  timeout = resolve_timeout_from_default (poll, timeout);
  timeout = calculate_effective_timeout (poll, timeout);

  process_async_completions_if_available (poll);

  nfds = wait_for_backend_events (poll, timeout);

  if (nfds < 0)
    {
      *events = NULL;
      return handle_backend_wait_error (timeout);
    }

  process_async_completions_if_available (poll);
  process_timers_if_available (poll);

  if (nfds == 0)
    {
      *events = poll->socketevents;
      return 0;
    }

  nfds = translate_backend_events_to_socket_events (poll, nfds);
  emit_event_metrics (nfds, timeout);

#ifdef SOCKET_HAS_TLS
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

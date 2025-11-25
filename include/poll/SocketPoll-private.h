#ifndef SOCKETPOLL_PRIVATE_INCLUDED
#define SOCKETPOLL_PRIVATE_INCLUDED

/**
 * SocketPoll-private.h - Private internal definitions for SocketPoll module
 *
 * This header defines internal types and functions used across SocketPoll
 * implementation files. Not part of public API.
 *
 * Thread-safe where noted.
 */

#include <pthread.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketTimer-private.h"
#include "poll/SocketPoll.h"
#include "poll/SocketPoll_backend.h"
#include "socket/Socket.h"
#include "socket/SocketAsync.h"

#define T SocketPoll_T

/* Use configured hash table size for socket data mapping */
#define SOCKET_DATA_HASH_SIZE SOCKET_HASH_TABLE_SIZE

/* ==================== Internal Type Definitions ==================== */

/**
 * SocketData - Socket to user data mapping entry
 * Used in hash table for O(1) socket->data lookup.
 */
typedef struct SocketData
{
  Socket_T socket;         /**< Socket reference */
  void *data;              /**< User-associated data */
  struct SocketData *next; /**< Next entry in hash bucket */
} SocketData;

/**
 * FdSocketEntry - File descriptor to socket mapping entry
 * Used for reverse lookup during event translation.
 */
typedef struct FdSocketEntry
{
  int fd;                      /**< File descriptor */
  Socket_T socket;             /**< Associated socket */
  struct FdSocketEntry *next;  /**< Next entry in hash bucket */
} FdSocketEntry;

/**
 * struct SocketPoll_T - Poll instance structure
 * Contains backend, event arrays, hash tables, and synchronization primitives.
 */
struct T
{
  PollBackend_T backend;                             /**< Platform-specific backend */
  int maxevents;                                     /**< Maximum events per wait */
  int default_timeout_ms;                            /**< Default timeout for wait */
  SocketEvent_T *socketevents;                       /**< Translated event array */
  Arena_T arena;                                     /**< Memory arena */
  SocketData *socket_data_map[SOCKET_DATA_HASH_SIZE];     /**< Socket->data hash table */
  FdSocketEntry *fd_to_socket_map[SOCKET_DATA_HASH_SIZE]; /**< FD->socket hash table */
  pthread_mutex_t mutex;                             /**< Thread-safety mutex */
  SocketAsync_T async;                               /**< Optional async I/O context */
  SocketTimer_heap_T *timer_heap;                    /**< Timer heap for integrated timers */
};

/* ==================== Exception Handling ==================== */

/**
 * RAISE_POLL_ERROR - Raise exception with detailed error message
 * Creates a thread-local copy of the exception with detailed reason.
 * CRITICAL: Uses volatile local variable on ARM64 to prevent corruption
 * across setjmp/longjmp.
 */
#define RAISE_POLL_ERROR(exception)                                            \
  do                                                                           \
    {                                                                          \
      volatile Except_T volatile_exception = (exception);                      \
      volatile_exception.reason = socket_error_buf;                            \
      Except_T non_volatile_exception                                          \
          = *(const Except_T *)&volatile_exception;                            \
      RAISE (non_volatile_exception);                                          \
    }                                                                          \
  while (0)

/* ==================== Hash Functions (SocketPoll-data.c) ==================== */

/**
 * socket_hash - Hash function for socket file descriptors
 * @socket: Socket to hash
 * Returns: Hash value in range [0, SOCKET_DATA_HASH_SIZE)
 */
extern unsigned socket_hash (const Socket_T socket);

/**
 * compute_fd_hash - Compute hash for file descriptor
 * @fd: File descriptor
 * Returns: Hash value in range [0, SOCKET_DATA_HASH_SIZE)
 */
extern unsigned compute_fd_hash (int fd);

/* ==================== Socket Data Management (SocketPoll-data.c) ==================== */

/**
 * allocate_socket_data_entry - Allocate socket data entry from arena
 * @poll: Poll instance
 * Returns: Allocated entry
 * Raises: SocketPoll_Failed on allocation failure
 */
extern SocketData *allocate_socket_data_entry (T poll);

/**
 * allocate_fd_socket_entry - Allocate FD to socket entry from arena
 * @poll: Poll instance
 * Returns: Allocated entry
 * Raises: SocketPoll_Failed on allocation failure
 */
extern FdSocketEntry *allocate_fd_socket_entry (T poll);

/**
 * socket_data_add_unlocked - Add socket data mapping (caller holds lock)
 * @poll: Poll instance
 * @socket: Socket to add
 * @data: User data to associate
 * Raises: SocketPoll_Failed on allocation failure
 */
extern void socket_data_add_unlocked (T poll, Socket_T socket, void *data);

/**
 * socket_data_update_unlocked - Update socket data (caller holds lock)
 * @poll: Poll instance
 * @socket: Socket to update
 * @data: New user data
 * Raises: SocketPoll_Failed on allocation failure (fallback case)
 */
extern void socket_data_update_unlocked (T poll, Socket_T socket, void *data);

/**
 * socket_data_remove_unlocked - Remove socket mappings (caller holds lock)
 * @poll: Poll instance
 * @socket: Socket to remove
 */
extern void socket_data_remove_unlocked (T poll, Socket_T socket);

/**
 * socket_data_lookup_unlocked - Lookup socket data (caller holds lock)
 * @poll: Poll instance
 * @socket: Socket to look up
 * Returns: Associated user data or NULL
 */
extern void *socket_data_lookup_unlocked (T poll, Socket_T socket);

/* ==================== Initialization (SocketPoll-init.c) ==================== */

/**
 * allocate_poll_structure - Allocate poll structure
 * Returns: Allocated poll structure
 * Raises: SocketPoll_Failed on allocation failure
 */
extern T allocate_poll_structure (void);

/**
 * initialize_poll_backend - Initialize poll backend
 * @poll: Poll instance
 * @maxevents: Maximum events
 * Raises: SocketPoll_Failed on failure
 */
extern void initialize_poll_backend (T poll, int maxevents);

/**
 * initialize_poll_arena - Initialize poll arena
 * @poll: Poll instance
 * Raises: SocketPoll_Failed on failure
 */
extern void initialize_poll_arena (T poll);

/**
 * allocate_poll_event_arrays - Allocate event arrays
 * @poll: Poll instance
 * @maxevents: Maximum events
 * Raises: SocketPoll_Failed on failure
 */
extern void allocate_poll_event_arrays (T poll, int maxevents);

/**
 * initialize_poll_hash_tables - Initialize hash tables to zero
 * @poll: Poll instance
 */
extern void initialize_poll_hash_tables (T poll);

/**
 * initialize_poll_mutex - Initialize mutex
 * @poll: Poll instance
 * Raises: SocketPoll_Failed on failure
 */
extern void initialize_poll_mutex (T poll);

/**
 * initialize_poll_timer_heap - Initialize timer heap
 * @poll: Poll instance
 * Raises: SocketPoll_Failed on allocation failure
 */
extern void initialize_poll_timer_heap (T poll);

/**
 * initialize_poll_async - Initialize async context (optional)
 * @poll: Poll instance
 * Does not raise exceptions - graceful degradation.
 */
extern void initialize_poll_async (T poll);

/* ==================== Event Translation (SocketPoll-events.c) ==================== */

/**
 * find_socket_by_fd - Find socket by file descriptor
 * @poll: Poll instance
 * @fd: File descriptor
 * Returns: Socket or NULL if not found
 * Thread-safe: No (caller must hold mutex)
 */
extern Socket_T find_socket_by_fd (T poll, int fd);

/**
 * translate_backend_events_to_socket_events - Translate backend events
 * @poll: Poll instance
 * @nfds: Number of events from backend
 * Returns: Number of translated events
 * Raises: SocketPoll_Failed on backend error
 */
extern int translate_backend_events_to_socket_events (T poll, int nfds);

/* ==================== Timer Heap Access ==================== */

/**
 * socketpoll_get_timer_heap - Get timer heap from poll (private function)
 * @poll: Poll instance
 * Returns: Timer heap pointer or NULL if not available
 * Thread-safe: No (internal use only)
 */
extern SocketTimer_heap_T *socketpoll_get_timer_heap (T poll);

/* ==================== TLS Event Handling (SocketPoll-tls.c) ==================== */

#ifdef SOCKET_HAS_TLS
/**
 * socketpoll_update_tls_events - Update poll events based on TLS state
 * @poll: Poll instance
 * @socket: Socket with TLS enabled
 * Thread-safe: Yes - uses poll mutex for data lookup
 */
extern void socketpoll_update_tls_events (T poll, Socket_T socket);

/**
 * socketpoll_process_tls_handshakes - Process TLS handshakes for ready events
 * @poll: Poll instance
 * @nfds: Number of events to process
 * Thread-safe: Yes
 */
extern void socketpoll_process_tls_handshakes (T poll, int nfds);
#endif /* SOCKET_HAS_TLS */

#undef T

#endif /* SOCKETPOLL_PRIVATE_INCLUDED */

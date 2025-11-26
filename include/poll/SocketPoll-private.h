#ifndef SOCKETPOLL_PRIVATE_INCLUDED
#define SOCKETPOLL_PRIVATE_INCLUDED

/**
 * SocketPoll-private.h - Private internal definitions for SocketPoll module
 *
 * This header defines internal types used by the SocketPoll implementation.
 * Not part of public API.
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
 * Thread-local exception for detailed error messages.
 * Persists across longjmp, unlike stack-local variables.
 */
#ifdef _WIN32
extern __declspec (thread) Except_T SocketPoll_DetailedException;
#else
extern __thread Except_T SocketPoll_DetailedException;
#endif

/**
 * RAISE_POLL_ERROR - Raise exception with detailed error message
 * Creates a thread-local copy of the exception with detailed reason.
 * Uses thread-local storage to ensure the exception persists across longjmp.
 */
#define RAISE_POLL_ERROR(exception)                                            \
  do                                                                           \
    {                                                                          \
      SocketPoll_DetailedException = (exception);                              \
      SocketPoll_DetailedException.reason = socket_error_buf;                  \
      RAISE (SocketPoll_DetailedException);                                    \
    }                                                                          \
  while (0)

/* ==================== Timer Heap Access ==================== */

/**
 * socketpoll_get_timer_heap - Get timer heap from poll (private function)
 * @poll: Poll instance
 * Returns: Timer heap pointer or NULL if not available
 * Thread-safe: No (internal use only)
 */
extern SocketTimer_heap_T *socketpoll_get_timer_heap (T poll);

#undef T

#endif /* SOCKETPOLL_PRIVATE_INCLUDED */

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
#include "core/SocketUtil.h" /* REFACTOR: For SOCKET_RAISE_MODULE_ERROR */
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
  int registered_count;                              /**< Current registered socket count */
  int max_registered;                                /**< Max registered (0=unlimited) */
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
 *
 * REFACTOR: Now uses centralized SOCKET_RAISE_MODULE_ERROR from SocketUtil.h
 * which handles thread-local exception copy with socket_error_buf reason.
 * Use SOCKET_ERROR_FMT/MSG macros to populate socket_error_buf first.
 *
 * Thread-safe: Creates thread-local copy of exception.
 *
 * NOTE: The thread-local exception SocketPoll_DetailedException is declared
 * in SocketPoll.c using SOCKET_DECLARE_MODULE_EXCEPTION(SocketPoll).
 */
#define RAISE_POLL_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketPoll, e)

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

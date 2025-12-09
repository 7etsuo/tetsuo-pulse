#ifndef SOCKETPOLL_PRIVATE_INCLUDED
#define SOCKETPOLL_PRIVATE_INCLUDED

/**
 * @file SocketPoll-private.h
 * @brief Internal implementation details for SocketPoll module.
 * @ingroup event_system
 *
 * Defines private types and structures used by the SocketPoll implementation.
 * Not part of the public API - for internal implementation use only.
 *
 * Key Components:
 * - SocketData: Hash table entries for O(1) socket-to-userdata mapping
 * - FdSocketEntry: Reverse mapping from file descriptor to socket for event translation
 * - SocketPoll_T: Main poll instance structure with all internal state
 * - Thread-safe exception handling macros
 * - Internal timer heap access functions
 *
 * Hash Table Design:
 * - Golden ratio hash function for optimal collision resistance
 * - Separate tables for socket->data and fd->socket mappings
 * - Thread-safe operations with mutex protection
 * - Efficient O(1) average-case lookups for event processing
 *
 * Thread Safety:
 * - Public operations are thread-safe via mutex protection
 * - Internal functions assume caller holds appropriate locks
 * - Hash table operations are protected by poll instance mutex
 * - Memory allocations use arena for efficient cleanup
 *
 * @note Not part of public API - subject to change without notice.
 * @note Thread-safe where noted; internal functions may not be.
 * @see SocketPoll.h for public API.
 * @see SocketPoll_backend.h for backend abstraction layer.
 * @see @ref foundation for memory management patterns.
 * @see @ref core_io for socket primitives that integrate with polling.
 * @see docs/cross-platform-backends.md for backend implementation patterns.
 * @see socket_util_hash_fd() for hash function implementation details.
 */

#include <pthread.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketTimer-private.h"
#include "core/SocketUtil.h"
#include "poll/SocketPoll.h"
#include "poll/SocketPoll_backend.h"
#include "socket/Socket.h"
#include "socket/SocketAsync.h"

/**
 * @brief Opaque type macro for internal SocketPoll_T structure definition.
 * @ingroup event_system
 *
 * Standard opaque pointer pattern used for private implementation hiding.
 * Allows compile-time definition of struct T while keeping internal fields
 * inaccessible from public headers.
 *
 * @note Used only in private implementation files (.c and -private.h).
 * @note Matches public typedef in SocketPoll.h for ABI compatibility.
 *
 * @see SocketPoll_T in SocketPoll.h for public opaque type.
 * @see struct T below for complete internal structure.
 */
#define T SocketPoll_T

/**
 * @brief Configured hash table size for internal socket data and FD-to-socket mappings.
 * @ingroup event_system
 *
 * Aliases the global SOCKET_HASH_TABLE_SIZE (default: 1021) for consistent hash table sizing
 * across modules. Enables O(1) average-case lookups during event processing and socket management.
 * The size is chosen as a prime number for optimal hash distribution with the golden ratio hash function.
 *
 * @note Value can be overridden at compile-time via -DSOCKET_HASH_TABLE_SIZE=N in CMake.
 * @note Larger sizes reduce collisions but increase memory usage for hash tables.
 * @note Used for both socket_data_map and fd_to_socket_map arrays.
 *
 * @see SocketConfig.h for SOCKET_HASH_TABLE_SIZE definition and configuration.
 * @see socket_util_hash_fd() and socket_util_hash_uint() for hash functions.
 * @see SocketData for socket-to-data mapping entries.
 * @see FdSocketEntry for FD-to-socket reverse mapping entries.
 * @see @ref foundation for hash table design patterns in foundation modules.
 */
#define SOCKET_DATA_HASH_SIZE SOCKET_HASH_TABLE_SIZE

/* ==================== Internal Type Definitions ==================== */

/**
 * @brief Hash table entry for socket-to-userdata mapping.
 * @ingroup event_system
 *
 * Used in internal hash table for O(1) average-case socket-to-userdata lookup
 * during event processing. Hash table uses golden ratio multiplication hash
 * function for optimal distribution and collision resistance.
 *
 * Thread Safety: Access protected by poll instance mutex for all operations.
 * Memory Management: Allocated from poll's arena for efficient cleanup.
 *
 * @see socket_data_add_unlocked() for hash table insertion (internal).
 * @see socket_data_lookup_unlocked() for hash table lookup (returns user data).
 * @see socket_data_remove_unlocked() for hash table deletion (internal).
 * @see SocketPoll_mod() for updating user data and monitored events.
 * @see SocketPoll_add() for public interface that uses this mapping.
 * @see @ref foundation for hash function implementation details.
 * @see socket_util_hash_fd() for hash function implementation.
 * @see poll_fd_hash() for seeded FD hashing used internally.
 */
typedef struct SocketData
{
  Socket_T socket;         /**< Socket reference */
  void *data;              /**< User-associated data */
  struct SocketData *next; /**< Next entry in hash bucket */
} SocketData;

/**
 * @brief Hash table entry for file descriptor to socket reverse mapping.
 * @ingroup event_system
 *
 * Enables O(1) reverse lookup from file descriptor to Socket_T during event
 * translation. Required because polling backends return raw file descriptors,
 * but SocketPoll API returns Socket_T objects with associated user data.
 *
 * Used in event translation pipeline:
 * 1. Backend returns (fd, events) pairs from backend_wait()
 * 2. backend_get_event() provides fd->events mapping
 * 3. Reverse lookup finds Socket_T for each fd
 * 4. Forward lookup retrieves user data for each socket
 * 5. SocketEvent_T populated with (socket, data, events)
 *
 * Thread Safety: Access protected by poll instance mutex for all operations.
 * Memory Management: Allocated from poll's arena for efficient cleanup.
 *
 * @see translate_backend_events_to_socket_events() for general event translation implementation.
 * @see backend_get_event() for backend event retrieval interface.
 * @see SocketEvent_T for final translated event structure.
 * @see SocketPoll_wait() for complete event processing pipeline.
 * @see translate_from_epoll() for epoll-specific event translation example.
 */
typedef struct FdSocketEntry
{
  int fd;                     /**< File descriptor */
  Socket_T socket;            /**< Associated socket */
  struct FdSocketEntry *next; /**< Next entry in hash bucket */
} FdSocketEntry;

/**
 * @brief Complete internal state for SocketPoll instance.
 * @ingroup event_system
 *
 * Contains all state for a socket polling instance including backend,
 * event arrays, hash tables, synchronization primitives, and optional
 * extensions. Thread-safe through mutex protection for all operations.
 * All memory allocated from arena for efficient cleanup on destruction.
 *
 * Core Components:
 * - backend: Platform-specific polling implementation (epoll/kqueue/poll)
 * - maxevents: Configurable limit on events per wait() call
 * - default_timeout_ms: Configurable default timeout for wait operations
 * - registered_count/max_registered: Resource usage tracking and limits
 * - socketevents: Pre-allocated array for translated SocketEvent_T structures
 *
 * Hash Tables (O(1) lookups):
 * - socket_data_map: Socket_T -> user data mapping for event delivery
 * - fd_to_socket_map: File descriptor -> Socket_T reverse mapping for translation
 * - hash_seed: Random seed for collision resistance in hash functions
 *
 * Extensions:
 * - mutex: Pthread mutex for thread-safe operations
 * - async: Optional SocketAsync context for high-throughput I/O
 * - timer_heap: SocketTimer heap for integrated timer management
 *
 * Memory Layout: All components allocated from arena for single cleanup operation.
 *
 * @see PollBackend_T for backend abstraction layer.
 * @see SocketData for socket-to-userdata hash table entries.
 * @see FdSocketEntry for file descriptor reverse mapping entries.
 * @see SocketTimer_heap_T for integrated timer heap.
 * @see SocketAsync_T for optional async I/O context.
 * @see Arena_T for memory management.
 * @see SocketPoll_new() for instance creation.
 */
struct T
{
  PollBackend_T backend;       /**< Platform-specific backend */
  int maxevents;               /**< Maximum events per wait */
  int default_timeout_ms;      /**< Default timeout for wait */
  int registered_count;        /**< Current registered socket count */
  int max_registered;          /**< Max registered (0=unlimited) */
  SocketEvent_T *socketevents; /**< Translated event array */
  Arena_T arena;               /**< Memory arena */
  SocketData
      *socket_data_map[SOCKET_DATA_HASH_SIZE]; /**< Socket->data hash table */
  FdSocketEntry
      *fd_to_socket_map[SOCKET_DATA_HASH_SIZE]; /**< FD->socket hash table */
  pthread_mutex_t mutex;                        /**< Thread-safety mutex */
  SocketAsync_T async;            /**< Optional async I/O context */
  SocketTimer_heap_T *timer_heap; /**< Timer heap for integrated timers */
  unsigned hash_seed; /**< Random seed for FD hashing to mitigate collisions */
};

/* ==================== Exception Handling ==================== */

/**
 * @brief Thread-safe exception raising with detailed error messages.
 * @ingroup event_system
 *
 * Uses centralized SOCKET_RAISE_MODULE_ERROR macro from SocketUtil.h
 * which handles thread-local exception copying to prevent race conditions
 * when multiple threads raise the same exception type simultaneously.
 *
 * Thread Safety Mechanism:
 * - Creates thread-local copy of SocketPoll_DetailedException
 * - Populates copy with current error message from socket_error_buf
 * - Raises the copy, leaving global exception unchanged for other threads
 *
 * Usage Pattern:
 * @code
 * SOCKET_ERROR_FMT("Operation failed on fd=%d", fd);
 * RAISE_POLL_ERROR(SocketPoll_Failed);
 * @endcode
 *
 * Error Message Population:
 * - Use SOCKET_ERROR_FMT() for formatted messages with errno
 * - Use SOCKET_ERROR_MSG() for simple messages without errno
 * - Messages stored in thread-local socket_error_buf
 *
 * @threadsafe Yes - Uses thread-local exception copies.
 * @note Thread-local SocketPoll_DetailedException declared in SocketPoll.c.
 * @note Error message must be populated before calling this macro.
 * @see SOCKET_RAISE_MODULE_ERROR for implementation details.
 * @see SocketPoll_Failed for the exception type definition.
 * @see @ref error_handling for complete exception handling patterns.
 * @see SOCKET_ERROR_FMT for error message formatting macros.
 * @see SOCKET_ERROR_MSG for simple error messages.
 * @see SocketUtil.h for centralized exception handling utilities.
 */
#define RAISE_POLL_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketPoll, e)

/* ==================== Timer Heap Access ==================== */

/**
 * @brief Access timer heap for internal SocketTimer integration.
 * @ingroup event_system
 * @param poll Poll instance.
 * @return Timer heap pointer or NULL if not available.
 * @threadsafe No - Internal use only, assumes caller holds poll mutex.
 *
 * Provides access to the internal timer heap used for SocketTimer integration.
 * The timer heap manages all active timers with efficient O(log n) operations
 * for insertion, deletion, and timeout processing.
 *
 * @note Used by SocketTimer module for timer heap integration.
 * @note Returns NULL if timer heap not initialized (timer integration disabled).
 * @note Caller must hold poll instance mutex before calling.
 * @note Timer heap is automatically processed during SocketPoll_wait() calls.
 *
 * @see SocketTimer_heap_T for timer heap structure definition.
 * @see SocketTimer_add() for public timer creation interface.
 * @see SocketPoll_wait() for automatic timer processing during event waits.
 * @see SocketTimer_heap_T for complete timer heap documentation.
 * @see SocketTimer-private.h for timer heap internal details.
 * @see @ref foundation for timer heap memory management patterns.
 */
extern SocketTimer_heap_T *socketpoll_get_timer_heap (T poll);

#undef T

#endif /* SOCKETPOLL_PRIVATE_INCLUDED */

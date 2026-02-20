/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETPOLL_PRIVATE_INCLUDED
#define SOCKETPOLL_PRIVATE_INCLUDED

/**
 * @file SocketPoll-private.h
 * @defgroup poll_private SocketPoll Private Implementation Details
 * @brief Internal structures and utilities for cross-platform event polling.
 * @ingroup event_system
 * @internal
 *
 * This header exposes private implementation details for the SocketPoll
 * module, enabling efficient event multiplexing across platforms
 * (epoll/kqueue/poll). Includes hash tables for fast socket/FD mappings,
 * internal state structure, exception macros, and integration points for
 * timers and async I/O.
 *
 * Not part of the public API - for module-internal use and maintenance only.
 * Subject to change without notice; use public SocketPoll.h for API.
 *
 *  Key Components
 *
 * | Component | Purpose | Key Features |
 * |-----------|---------|--------------|
 * | SocketData | Socket-to-userdata hash mapping | O(1) lookup, chained
 * collisions, arena-allocated | | FdSocketEntry | FD-to-socket reverse mapping
 * | Event translation from backend FDs to Socket_T | | SocketPoll_T | Core
 * instance state | Backend, mutex, hash tables, event arrays, extensions | |
 * RAISE_POLL_ERROR | Exception macro | Thread-safe error raising with detailed
 * messages | | socketpoll_get_timer_heap | Timer integration | Access to
 * internal timer heap for SocketTimer |
 *
 *  Hash Table Design
 *
 * - **Algorithm**: Golden ratio multiplication hash with random seed for
 * security
 * - **Tables**: Separate chains for socket_data_map (Socket_T -> userdata) and
 * fd_to_socket_map (fd -> Socket_T)
 * - **Size**: SOCKET_DATA_HASH_SIZE (prime for distribution, default 1021)
 * - **Performance**: O(1) average lookup/insert/delete; mutex-protected for
 * concurrency
 * - **Security**: Hash seed mitigates DoS via predictable collisions
 *
 *  Thread Safety Model
 *
 * - **Public API**: Fully thread-safe; acquires/releases instance mutex
 * - **Internal Functions**: Assume caller holds poll->mutex; not safe
 * otherwise
 * - **Data Structures**: Hash tables and arrays protected by mutex
 * - **Memory**: Arena allocations safe within mutex scope; no external locking
 * needed
 * - **Backends**: Serialized via mutex; backend_wait() exclusive
 *
 *  Architecture Integration
 *
 * ```
 * Application --> SocketPoll_add/mod/del/wait (public API)
 *                  |
 *                  v (mutex lock)
 * Internal: Hash tables <--> Backend (epoll/kqueue/poll)
 *                  |
 *                  v
 * Event Translation: FD events -> SocketEvent_T -> user callbacks
 * Extensions: Timer heap processing during wait(), async I/O delegation
 * ```
 *
 * @note Use only within SocketPoll and dependent modules (e.g., SocketTimer)
 * @note All allocations from poll->arena for lifecycle management
 * @note Compile with -DSOCKET_DATA_HASH_SIZE=N to tune table size
 * @warning Internal functions may change ABI; prefer public wrappers
 * @complexity Most operations O(1) avg due to hashing; wait() O(n_events)
 *
 * @see SocketPoll.h for public event polling API
 * @see SocketPoll_backend.h for platform backend abstraction
 * @see @ref event_system for full event system overview
 * @see @ref foundation for arena and exception patterns
 * @see docs/ASYNC_IO.md for async integration guide
 * @see docs/cross-platform-backends.md for backend details
 * @see socket_util_hash_fd() for underlying hash implementation
 * @{
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
 * @brief Opaque type alias macro enabling private struct definition.
 * @ingroup event_system
 * @internal
 *
 * Defines T as SocketPoll_T for use in private headers and .c files.
 * Enables forward declaration and full struct definition in implementation
 * while maintaining opaque type in public API (include/socket/SocketPoll.h).
 *
 * Pattern: #define T Module_T then typedef struct T *T in private, #undef T
 * before public includes Ensures ABI stability: public sees pointer, private
 * sees full struct. // fixed
 *
 * Purpose and Benefits
 *
 * - Encapsulation: Hides internals from users/extensions
 * - Binary Compatibility: Struct changes don't break public ABI
 * - Compile-Time: Allows sizeof(T) and field access in .c only
 * - Consistency: Matches foundation module patterns (Arena_T, etc.)
 *
 * Usage restricted to SocketPoll-private.h and SocketPoll.c.
 *
 * @note Defined after includes, undefined before #endif
 * @note Public API: extern functions take/return SocketPoll_T (pointer)
 * @note Private: struct T { ... } defines actual layout
 * @warning Undefine before public includes to avoid conflicts
 * @complexity N/A - preprocessor macro
 *
 * @see SocketPoll.h public typedef struct SocketPoll_T *SocketPoll_T;
 * @see struct T full private definition below
 * @see @ref foundation opaque type patterns in core modules
 * @see Arena.h example of similar pattern
 */
#define T SocketPoll_T

/**
 * @brief Compile-time constant for hash table capacity in socket mappings.
 * @ingroup event_system
 * @internal
 *
 * Defines the number of buckets in internal hash tables (socket_data_map and
 * fd_to_socket_map). Aliases SOCKET_HASH_TABLE_SIZE from SocketConfig.h
 * (default prime: 1021) for module consistency. Prime size + golden ratio hash
 * minimizes collisions for even distribution.
 *
 * Memory: sizeof(SocketData* [size]) + sizeof(FdSocketEntry* [size]) ~ 16KB
 * default (64-bit). Performance: Larger reduces chain lengths, improving
 * worst-case to near O(1).
 *
 *  Configuration Guidelines
 *
 * | Value | Scenario | Pros | Cons |
 * |-------|----------|------|------|
 * | 1021 (default) | General apps (1K-10K conns) | Balanced | Minor collisions
 * possible | | 4093-16381 | High-load servers (>10K conns) | Low collisions |
 * Increased memory (~64KB+) | | 251-509 | Embedded/low-mem | Low footprint |
 * Higher collision risk |
 *
 * Override via CMake: cmake -DSOCKET_HASH_TABLE_SIZE=4093 ..
 *
 * @note Must be compile-time constant; affects struct T layout
 * @note Prime recommended for hash quality; powers-of-2 suboptimal
 * @note Shared across modules for consistency; change impacts all
 * @complexity Influences avg chain length: collisions ~ 1/size
 * @warning Non-prime sizes degrade performance; test under load
 * @note Used in struct T array declarations; sizeof impacts cache
 *
 * @see SocketConfig.h SOCKET_HASH_TABLE_SIZE source
 * @see socket_util_hash_fd() FD hashing
 * @see socket_util_hash_uint() general uint hashing
 * @see poll_fd_hash() module-specific seeded hash
 * @see SocketData table entries
 * @see FdSocketEntry reverse entries
 * @see struct T poll->*_map arrays using this
 * @see @ref foundation hashing best practices
 */
#define SOCKET_DATA_HASH_SIZE SOCKET_HASH_TABLE_SIZE

/**
 * @brief Linked-list node for socket-to-userdata mapping in internal hash
 * table.
 * @ingroup event_system
 * @internal
 *
 * Represents a single entry in the socket_data_map hash table, enabling O(1)
 * average-case lookup of user data during event delivery. Each entry chains
 * via 'next' for collision resolution using open hashing.
 *
 * The mapping is essential for translating backend events (fd + events) to
 * user-facing SocketEvent_T (socket + data + events), preserving userdata
 * registered via SocketPoll_add().
 *
 * Thread Safety: All access (read/write) protected by poll->mutex.
 * Memory Management: Arena-allocated; no manual free, cleaned via
 * Arena_dispose().
 *
 *  Structure Fields
 *
 * | Field  | Type              | Description |
 * |--------|-------------------|-------------|
 * | socket | Socket_T          | Registered socket identifier for matching
 * events | | data   | void *            | Userdata payload from
 * SocketPoll_add()/mod() | | next   | struct SocketData * | Chain pointer for
 * hash collisions |
 *
 *  Internal Usage Pattern
 *
 * @code{.c}
 * // Simplified insertion (internal, mutex-held)
 * SocketData *entry = CALLOC(poll->arena, 1, sizeof(*entry));
 * entry->socket = socket;
 * entry->data = userdata;
 * unsigned idx = poll_fd_hash(poll, Socket_fd(socket));
 * entry->next = poll->socket_data_map[idx];
 * poll->socket_data_map[idx] = entry;
 * poll->registered_count++;
 * @endcode
 *
 * @code{.c}
 * // Simplified lookup during event processing
 * unsigned idx = poll_fd_hash(poll, event_fd);
 * for (SocketData *entry = poll->socket_data_map[idx]; entry; entry =
 * entry->next) { if (Socket_fd(entry->socket) == event_fd) { SocketEvent_T ev
 * = { .socket = entry->socket, .data = entry->data, .events = ... };
 *         // Deliver ev to user
 *         break;
 *     }
 * }
 * @endcode
 *
 * @complexity Insert/Lookup/Delete: O(1) average, O(n_bucket) worst-case
 * @threadsafe No - requires poll->mutex held by caller
 * @note Chain length minimized by prime table size and quality hash
 * @warning Userdata 'data' must not be freed while socket registered
 * @note Used only in SocketPoll.c; not accessible via public API
 *
 * @see FdSocketEntry for FD-to-socket reverse mapping
 * @see socket_data_add_unlocked() for insertion helper
 * @see socket_data_lookup_unlocked() for lookup helper
 * @see socket_data_remove_unlocked() for removal helper
 * @see SocketPoll_add() public interface populating this structure
 * @see SocketPoll_mod() for userdata updates
 * @see SocketEvent_T for event structure using retrieved data
 * @see @ref event_system for event delivery pipeline
 * @see socket_util_hash_fd() underlying hash computation
 * @see poll_fd_hash() seeded variant for this module
 */
typedef struct SocketData
{
  Socket_T socket;         /**< Socket reference */
  void *data;              /**< User-associated data */
  struct SocketData *next; /**< Next entry in hash bucket */
} SocketData;

/**
 * @brief Linked-list node for FD-to-socket reverse mapping in internal hash
 * table.
 * @ingroup event_system
 * @internal
 *
 * Critical structure for translating raw file descriptors from polling
 * backends (epoll/kqueue/poll) back to higher-level Socket_T objects during
 * event processing. Enables the pipeline: backend FD events -> SocketEvent_T
 * with full context.
 *
 * Without this mapping, event delivery would require linear scans over all
 * registered sockets, degrading to O(n) performance. Hashing ensures O(1)
 * average resolution.
 *
 * Thread Safety: Protected by poll->mutex for concurrent access.
 * Memory Management: Arena-allocated from poll->arena; collective cleanup.
 *
 *  Structure Fields
 *
 * | Field | Type                   | Description |
 * |-------|------------------------|-------------|
 * | fd    | int                    | Raw file descriptor from socket |
 * | socket| Socket_T               | Associated opaque socket wrapper |
 * | next  | struct FdSocketEntry * | Collision chain pointer |
 *
 *  Event Translation Role
 *
 * Part of the core event processing pipeline:
 *
 * 1. SocketPoll_wait() calls backend_wait() -> array of (fd, backend_events)
 * 2. For each fd: lookup FdSocketEntry via hash(fd) -> get Socket_T
 * 3. For each Socket_T: lookup SocketData via hash(Socket_T) -> get userdata
 * 4. Construct SocketEvent_T {socket, data, events} for user delivery
 * 5. Return array to caller
 *
 *  Internal Usage Example
 *
 * @code{.c}
 * // During event wait processing (internal, mutex-held)
 * ssize_t nevents = backend_wait(poll->backend, ...);
 * for (int i = 0; i < nevents; i++) {
 *     int fd = backend_get_fd(poll->backend, i);
 *     unsigned idx = poll_fd_hash(poll, fd);
 *     FdSocketEntry *fse = poll->fd_to_socket_map[idx];
 *     while (fse && fse->fd != fd) fse = fse->next;
 *     if (fse) {
 *         Socket_T sock = fse->socket;
 *         // Proceed to SocketData lookup and event construction
 *     }
 * }
 * @endcode
 *
 * @complexity Lookup: O(1) avg / O(chain) worst; chains short due to hashing
 * @threadsafe No - caller must hold poll->mutex
 * @note FD uniqueness assumed; one-to-one mapping per registered socket
 * @warning FD reuse by kernel possible; removal on socket del prevents stale
 * entries
 * @note Synced with socket_data_map during add/mod/del operations
 *
 * @see SocketData for complementary socket-to-data mapping
 * @see translate_backend_events_to_socket_events() master translation function
 * @see backend_get_event() backend-specific event extraction
 * @see SocketEvent_T output structure after translation
 * @see SocketPoll_wait() orchestrates the full pipeline
 * @see translate_from_epoll() example epoll translation using this
 * @see poll_fd_hash() hash computation for FD indexing
 * @see @ref event_system for complete event flow
 */
typedef struct FdSocketEntry
{
  int fd;                     /**< File descriptor */
  Socket_T socket;            /**< Associated socket */
  struct FdSocketEntry *next; /**< Next entry in hash bucket */
} FdSocketEntry;

/**
 * @brief Opaque internal state structure for SocketPoll instance.
 * @ingroup event_system
 * @internal
 *
 * Encapsulates complete runtime state for a polling instance, including
 * platform backend, configuration, registered sockets mappings, event buffers,
 * synchronization, and optional extensions like timers and async I/O. Designed
 * for efficient operation with O(1) lookups via hashing and arena-based memory
 * management.
 *
 * All fields are private and accessed only within the module or trusted
 * dependents. Thread safety enforced via embedded mutex; direct access
 * bypasses protection.
 *
 *  State Categories
 *
 * | Category       | Fields                          | Role |
 * |----------------|---------------------------------|------|
 * | Backend        | backend                         | Platform I/O
 * multiplexing (epoll/kqueue/poll) | | Configuration  | maxevents,
 * default_timeout_ms   | Limits and defaults for wait operations | |
 * Registration   | registered_count, max_registered| Active sockets count and
 * capacity enforcement | | Events         | socketevents                    |
 * Output buffer for translated events | | Memory         | arena | Single
 * source for all internal allocations | | Mappings       | socket_data_map[],
 * fd_to_socket_map[], hash_seed | Fast bidirectional lookups | |
 * Synchronization| mutex                           | Pthread lock for
 * concurrent access | | Extensions     | async, timer_heap               |
 * Optional advanced I/O and timing |
 *
 *  Initialization and Lifecycle
 *
 * - Created by SocketPoll_new(): initializes backend, allocates arrays/tables,
 * seeds hash
 * - Registered sockets populate hash tables via add/mod operations
 * - wait() loops: backend_wait() -> translate -> deliver events -> process
 * timers
 * - Destroyed by SocketPoll_free(): clears tables, disposes arena, closes
 * backend
 *
 * Memory: Everything arena-allocated for O(1) cleanup; no leaks on exceptions.
 *
 *  Access Pattern
 *
 * @code{.c}
 * // Safe internal access (mutex required)
 * pthread_mutex_lock(&poll->mutex);
 * TRY {
 *     // Modify state, e.g., poll->registered_count++;
 *     // Hash table operations, backend calls
 *     backend_add(poll->backend, Socket_fd(sock), events);
 * } EXCEPT(SocketPoll_Failed) {
 *     // Rollback changes if partial
 *     RERAISE;
 * } FINALLY {
 *     pthread_mutex_unlock(&poll->mutex);
 * } END_TRY;
 * @endcode
 *
 * @threadsafe Partial - mutex enables; direct field access unsafe in MT env
 * @complexity Individual field O(1); table ops O(1) avg
 * @note Layout optimized for cache locality; arrays contiguous
 * @note hash_seed randomized to prevent hash DoS attacks
 * @warning NULL extensions require checks; feature-dependent
 * @note Backend may embed platform-specific state (e.g., epoll_fd)
 *
 * @see SocketPoll_new() initialization
 * @see SocketPoll_free() cleanup
 * @see PollBackend_T platform layer
 * @see SocketData socket mappings
 * @see FdSocketEntry FD mappings
 * @see SocketTimer_heap_T timers
 * @see SocketAsync_T async
 * @see Arena_T allocation
 * @see pthread_mutex_t locking
 * @see @ref event_system overview
 * @see docs/cross-platform-backends.md backends
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

/**
 * @brief Generic linked-list removal from hash chain (double-pointer
 * traversal).
 * @ingroup event_system
 * @internal
 * @param head Pointer to head pointer of chain (e.g.,
 * &poll->socket_data_map[hash])
 * @param entry_type Type of entries in chain (e.g., SocketData)
 * @param key_field Field name to match (e.g., socket)
 * @param key_value Value to match against key_field
 * @param next_field Field name for next pointer (e.g., next)
 *
 * Removes first matching entry from a hash chain by updating
 * pointer-to-pointer. Uses double-pointer traversal for clean removal without
 * special head case. Consolidates duplicate removal logic in
 * remove_socket_data_entry and remove_fd_socket_entry which had identical
 * patterns.
 *
 * Thread-safe: No (caller must hold mutex)
 * Complexity: O(n) where n = chain length
 *
 * Usage Example:
 * @code
 * // Remove socket from data map
 * HASH_CHAIN_REMOVE(&poll->socket_data_map[hash], SocketData, socket,
 *                   target_socket, next);
 * // Remove FD from socket map
 * HASH_CHAIN_REMOVE(&poll->fd_to_socket_map[hash], FdSocketEntry, fd,
 *                   target_fd, next);
 * @endcode
 *
 * @see remove_socket_data_entry() for usage in socket data removal
 * @see remove_fd_socket_entry() for usage in FD socket removal
 */
#define HASH_CHAIN_REMOVE(head, entry_type, key_field, key_value, next_field) \
  do                                                                          \
    {                                                                         \
      entry_type **_pp = (head);                                              \
      while (*_pp)                                                            \
        {                                                                     \
          if ((*_pp)->key_field == (key_value))                               \
            {                                                                 \
              *_pp = (*_pp)->next_field;                                      \
              break;                                                          \
            }                                                                 \
          _pp = &(*_pp)->next_field;                                          \
        }                                                                     \
    }                                                                         \
  while (0)

/**
 * @brief Module-specific exception raising macro for SocketPoll errors.
 * @ingroup event_system
 * @internal
 * @param e Exception type (e.g., SocketPoll_Failed)
 *
 * Convenience wrapper over SOCKET_RAISE_MODULE_ERROR for SocketPoll module
 * exceptions. Ensures thread-safe raising by copying to thread-local exception
 * state, avoiding races in multi-threaded environments where multiple errors
 * occur concurrently.
 *
 * Integrates with foundation Except_T system and SocketUtil error formatting.
 * Automatically populates detailed message from thread-local error buffer.
 *
 *  Thread Safety Features
 *
 * - Thread-local exception copy prevents global state corruption
 * - Compatible with TRY/EXCEPT/FINALLY/END_TRY blocks
 * - Safe in signal handlers? No - not async-signal-safe due to TLS
 *
 *  Usage Patterns
 *
 * # Basic Error with errno
 *
 * @code{.c}
 * if (some_syscall() == -1) {
 *     SOCKET_ERROR_FMT("bind failed: %s", strerror(errno));
 *     RAISE_POLL_ERROR(SocketPoll_Failed);
 * }
 * @endcode
 *
 * # Custom Message
 *
 * @code{.c}
 * if (condition_invalid) {
 *     SOCKET_ERROR_MSG("Invalid maxevents=%d (<0)", maxevents);
 *     RAISE_POLL_ERROR(SocketPoll_InvalidParam);
 * }
 * @endcode
 *
 * # In TRY Block
 *
 * @code{.c}
 * TRY {
 *     // Operations that may fail
 *     backend_init(...);
 * } EXCEPT(SocketPoll_Failed) {
 *     // Local handling
 *     LOG_ERROR("Backend init failed: %s", Except_message(Except_stack));
 *     RERAISE;  // Or return error code
 * } END_TRY;
 * @endcode
 *
 *  Supported Exception Types
 *
 * Defined in SocketPoll.h (public) or private exceptions:
 * - SocketPoll_Failed: General failure (system calls, allocations)
 * - SocketPoll_InvalidParam: Caller error (null pointers, invalid limits)
 * - SocketPoll_Closed: Socket closed unexpectedly
 * - Others module-specific
 *
 * @note Precede with SOCKET_ERROR_*() macro to set message
 * @note Declares local SocketPoll_DetailedException in SocketPoll.c
 * @note Message buffer size: SOCKET_ERROR_BUF_SIZE (256 bytes)
 * @complexity O(1) - TLS copy and raise
 * @threadsafe Yes - per-thread exception stack and buffers
 * @warning Not async-signal-safe; avoid in signal handlers
 * @note Integrates with RAISE_POLL_ERROR in private code only
 *
 * @see SocketUtil.h SOCKET_RAISE_MODULE_ERROR base macro
 * @see SocketPoll_Failed primary exception
 * @see @ref foundation Except_T system
 * @see @ref error_handling patterns and best practices
 * @see SOCKET_ERROR_FMT() with errno formatting
 * @see SOCKET_ERROR_MSG() custom messages
 * @see Except_stack thread-local stack
 */
#define RAISE_POLL_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketPoll, e)

/**
 * @brief Retrieve integrated timer heap from SocketPoll instance.
 * @ingroup event_system
 * @internal
 * @param[in] poll Non-NULL SocketPoll_T instance
 * @return Pointer to SocketTimer_heap_T or NULL
 * @threadsafe No - Internal accessor; requires poll->mutex held by caller
 *
 * Safe getter for the optional timer heap extension embedded in SocketPoll_T.
 * Enables SocketTimer module to manage timers with automatic processing during
 * SocketPoll_wait() calls, integrating timeouts into the main event loop
 * without extra poll() syscalls.
 *
 * The heap supports priority queue operations for timer expiration, using heap
 * structure for O(log n) insert/cancel and O(1) peek nearest timeout.
 *
 * Timer integration optional: compiled/enabled via feature flags; NULL if
 * disabled.
 *
 *  Usage Example
 *
 * @code{.c}
 * // In SocketTimer.c or similar dependent module
 * TRY {
 *     SocketTimer_heap_T *heap = socketpoll_get_timer_heap(poll);
 *     if (!heap) {
 *         RAISE_MSG(SocketTimer_Failed, "Timer heap unavailable");
 *     }
 *     // Insert timer or perform heap operations
 *     SocketTimer_heap_insert(heap, delay_ms, callback, userdata);
 * } EXCEPT(SocketTimer_Failed) {
 *     // Handle gracefully or propagate
 * } END_TRY;
 * @endcode
 *
 *  Return Conditions
 *
 * | Value | Condition |
 * |-------|-----------|
 * | Non-NULL | Heap initialized and ready |
 * | NULL | poll NULL, feature disabled, or init failed |
 *
 * @return Internal timer heap pointer or NULL if unavailable
 *
 * @throws None - accessor only; caller handles NULL via check/RAISE
 *
 * @complexity O(1) - direct poll->timer_heap field return
 *
 * @note Call within mutex lock: pthread_mutex_lock(&poll->mutex); ... unlock
 * @note Heap processed automatically: wait() checks nearest timeout before
 * backend_wait()
 * @note Disabled if SOCKET_TIMER_INTEGRATION not defined or poll_new failed
 * init
 * @warning Do not free returned heap; owned by poll, freed on
 * SocketPoll_free()
 * @note Used exclusively by SocketTimer; not for general-purpose timer mgmt
 *
 * @see SocketPoll_wait() implicit timer processing
 * @see SocketTimer_add() public API using this internally
 * @see SocketTimer_heap_T heap structure and ops
 * @see SocketTimer_heap_insert() example heap usage
 * @see SocketTimer-private.h full private timer details
 * @see poll->timer_heap field embedding this
 * @see @ref event_system timer-event integration
 * @see @ref foundation arena management for heap
 */
extern SocketTimer_heap_T *socketpoll_get_timer_heap (T poll);

#undef T

/** @} */

#endif /* SOCKETPOLL_PRIVATE_INCLUDED */

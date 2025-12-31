/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETPOLL_INCLUDED
#define SOCKETPOLL_INCLUDED

#include "core/Except.h"
#include "core/SocketTimer.h" /* Re-export timer functions */
#include "socket/Socket.h"

/**
 * @brief Asynchronous I/O context for high-throughput, zero-copy operations,
 * integrated with SocketPoll_T.
 * @ingroup async_io
 * Enables automatic completion processing during event waits and advanced
 * patterns like scatter-gather I/O and non-blocking file operations.
 *
 * @see @ref event_system for core polling infrastructure.
 * @see SocketPoll_get_async() to retrieve from a poll instance.
 * @see @ref async_io "Async I/O module" for detailed usage and patterns.
 * @see docs/ASYNC_IO.md for implementation examples and best practices.
 */

struct SocketAsync_T;
typedef struct SocketAsync_T *SocketAsync_T;

/**
 * @defgroup event_system Event System Modules
 * @brief High-performance I/O multiplexing with cross-platform backends.
 * @{
 * Key components: SocketPoll_T (cross-platform I/O multiplexing),
 * SocketTimer_T (timer management). Enables scalable event-driven network
 * applications with automatic platform adaptation.
 *
 * Architecture Overview:
 * - # SocketPoll_T: Core polling interface with backend abstraction for
 * epoll/kqueue/poll.
 * - # SocketTimer_T: Heap-based timer scheduling integrated with poll wait
 * cycles.
 * - Integration with @ref async_io::SocketAsync_T via SocketPoll_get_async()
 * for zero-copy, high-throughput async operations.
 *
 * Backend Selection:
 * - Linux: epoll(7) for O(1) edge-triggered notifications.
 * - BSD/macOS: kqueue(2) for efficient event filtering and file descriptor
 * monitoring.
 * - Fallback: poll(2) for broad POSIX compatibility (level-triggered).
 *
 * Design Principles:
 * - Thread-safe: Internal mutexes protect shared state across operations.
 * - Arena-allocated: Efficient memory management tied to poll lifecycle.
 * - Non-blocking: Automatically configures sockets for async operation.
 *
 * Usage Patterns:
 * - Servers: Combine with @ref connection_mgmt::SocketPool_T for connection
 * handling.
 * - Clients: Use with @ref utilities::SocketReconnect_T for resilient
 * connections.
 * - Timeouts: Integrate SocketTimer_add() for idle connection management.
 *
 * Error Handling: Uses @ref foundation exceptions with detailed errno mapping.
 * Performance: Minimizes syscalls; supports up to system limits (e.g.,
 * /proc/sys/fs/epoll/max_user_watches).
 *
 * @see @ref foundation for base infrastructure (Arena_T, Except_T).
 * @see @ref core_io for Socket_T primitives compatible with event
 * registration.
 * @see @ref connection_mgmt for advanced connection lifecycle management.
 * @see @ref async_io for SocketAsync_T usage in high-performance scenarios.
 * @see @ref utilities for rate limiting and retry logic integration.
 * @see SocketPoll_T for polling API details.
 * @see SocketTimer_T for timer API (re-exported here).
 * @see @ref async_io::SocketAsync_T for async extensions (integrated via
 * SocketPoll_get_async()).
 * @see docs/ASYNC_IO.md for event-driven programming examples and best
 * practices.
 * @see docs/ERROR_HANDLING.md for exception patterns in event loops.
 * @}
 */

/**
 * @file SocketPoll.h
 * @ingroup event_system
 * @brief Cross-platform high-level interface for monitoring multiple sockets
 * for I/O events.
 *
 * Automatically selects optimal backend: epoll (Linux), kqueue (BSD/macOS),
 * poll (POSIX fallback). Supports edge-triggered and level-triggered modes
 * depending on backend capabilities.
 *
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS, etc.)
 * - Linux: kernel 2.6.8+ for full epoll support
 * - BSD/macOS: kqueue system call availability
 * - POSIX threads (pthreads) for internal mutex synchronization
 * - Windows not supported (would require IOCP or WSAPoll backend)
 *
 * Features:
 * - Scalable event delivery (O(1) with epoll/kqueue backends)
 * - Edge-triggered notifications for efficiency where supported
 * - User data association with monitored sockets
 * - Configurable default timeout for wait operations
 * - Thread-safe implementation with internal locking
 * - Integrated async I/O completion processing
 *
 * Maintains an internal mapping of sockets to user data for efficient event
 * dispatching and context retrieval. Registered sockets are automatically
 * configured for non-blocking I/O.
 *
 * @see SocketPoll_new() for poll instance creation.
 * @see SocketPoll_add() for socket registration with events and user data.
 * @see SocketPoll_wait() for blocking on and retrieving I/O events.
 * @see SocketPoll_Events for bitmask values (POLL_READ, POLL_WRITE, etc.).
 * @see SocketEvent_T for event notification structure details.
 * @see @ref core_io for compatible socket primitives.
 * @see @ref connection_mgmt for connection pool integration examples.
 * @see @ref async_io for advanced asynchronous patterns.
 * @see include/poll/SocketPoll_backend.h for backend abstraction interface.
 * @see docs/ASYNC_IO.md for event-driven programming guide.
 */

/**
 * @brief High-performance socket polling abstraction with cross-platform
 * backends.
 * @ingroup event_system
 *
 * Provides scalable event notification for network applications with O(1)
 * event delivery regardless of the number of monitored sockets. Automatically
 * selects the best available backend for the platform: epoll (Linux), kqueue
 * (BSD/macOS), or poll (POSIX fallback).
 *
 * Key Features:
 * - O(1) event delivery with edge-triggered mode for efficiency
 * - Automatic backend selection based on platform capabilities
 * - Thread-safe operations with internal mutex protection
 * - Integrated timer management via SocketTimer
 * - Optional asynchronous I/O support via SocketAsync
 * - Configurable limits for resource protection
 *
 * @see SocketPoll_new() for creation.
 * @see SocketPoll_add() for socket registration.
 * @see SocketPoll_wait() for event waiting.
 * @see SocketPoll_Events for available event types.
 * @see SocketEvent_T for event structure.
 */
#define T SocketPoll_T
typedef struct T *T;

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @brief SocketPoll operation failure exception.
 * @ingroup event_system
 *
 * Raised for various poll operation failures including backend creation,
 * invalid socket operations, and resource exhaustion.
 *
 * @see SocketError_categorize_errno() for error categorization.
 * @see SocketError_is_retryable_errno() for retryability checking.
 */
extern const Except_T SocketPoll_Failed;

/**
 * @brief Event types for socket I/O monitoring.
 * @ingroup event_system
 *
 * Bitmask values specifying which I/O events to monitor on sockets.
 * Multiple events can be combined using bitwise OR operations.
 * Used in SocketPoll_add() and SocketPoll_mod() for event registration.
 *
 * @note POLL_ERROR and POLL_HANGUP are always monitored automatically.
 * @note Edge-triggered mode delivers events only when state changes.
 *
 * @see SocketPoll_add() for registering sockets with specific events.
 * @see SocketPoll_mod() for modifying monitored events.
 * @see SocketEvent_T for event delivery structure.
 * @see SocketPoll_wait() for event retrieval.
 */
typedef enum
{
  POLL_READ = 1 << 0,  /**< Data available for reading */
  POLL_WRITE = 1 << 1, /**< Socket ready for writing */
  POLL_ERROR = 1 << 2, /**< Error condition occurred */
  POLL_HANGUP = 1 << 3 /**< Connection hang up / disconnection */
} SocketPoll_Events;

/**
 * @brief Event notification structure returned by polling operations.
 * @ingroup event_system
 *
 * Contains information about I/O events that occurred on monitored sockets.
 * Returned as an array from SocketPoll_wait() calls. The array is managed
 * internally by the poll instance and should not be freed by the caller.
 *
 * Memory Management:
 * - Array lifetime tied to poll instance
 * - Valid until next SocketPoll_wait() call or poll destruction
 * - Do not free or modify the returned array
 *
 * @see SocketPoll_wait() for event retrieval.
 * @see SocketPoll_Events for possible event types.
 * @see SocketPoll_add() for associating user data with sockets.
 * @see Socket_T for socket type definition.
 */
typedef struct SocketEvent
{
  Socket_T socket; /**< Socket that triggered the event */
  void *data;      /**< User data associated with socket at registration */
  unsigned events; /**< Bitmask of events that occurred (SocketPoll_Events) */
} SocketEvent_T;

/**
 * @brief Special timeout value to use the poll's default timeout.
 * @ingroup event_system
 *
 * When passed to SocketPoll_wait(), this value instructs the function
 * to use the default timeout configured via SocketPoll_setdefaulttimeout().
 * Useful for consistent timeout behavior across multiple wait calls.
 *
 * @note This constant ensures timeout consistency across multiple wait
 * operations.
 * @note Equivalent to calling SocketPoll_getdefaulttimeout() for each wait.
 *
 * @see SocketPoll_wait() for timeout parameter usage.
 * @see SocketPoll_setdefaulttimeout() for setting the default timeout.
 * @see SocketPoll_getdefaulttimeout() for retrieving the current default.
 */
#define SOCKET_POLL_TIMEOUT_USE_DEFAULT (-2)

/**
 * @brief Create a new event poll instance.
 * @ingroup event_system
 *
 * Initializes a cross-platform event polling context capable of monitoring
 * multiple sockets for I/O readiness. Automatically detects and configures the
 * optimal backend based on platform capabilities, ensuring high-performance
 * event delivery suitable for servers handling thousands of concurrent
 * connections.
 *
 * The maxevents parameter determines the capacity of the internal event queue,
 * which affects how many events can be retrieved in a single SocketPoll_wait()
 * call. Recommended values:
 * - Small clients: 64-256
 * - Medium servers: 1024-4096
 * - High-throughput: 8192+ (monitor memory usage)
 *
 * Edge cases and error conditions:
 * - If maxevents <= 0, defaults to system-specific value (e.g., 64 for epoll).
 * - Backend initialization failures due to resource limits (ulimit -n,
 * /proc/sys/fs/epoll/max_user_watches).
 * - Unsupported platforms fall back to poll(2) with level-triggered semantics.
 *
 * @param[in] maxevents Maximum number of events to process per wait call (0
 * for system default; suggest 1024+ for servers).
 *
 * @return New SocketPoll_T instance, fully initialized and ready for use.
 *
 * @throws SocketPoll_Failed On backend creation failure, such as:
 *                           - EMFILE/ENFILE: Process/system file descriptor
 * limit reached.
 *                           - ENOMEM: Memory allocation failure for internal
 * structures.
 *                           - ENOSYS: Backend not supported on platform.
 *
 * @threadsafe Yes - Creation is atomic and instances operate independently
 * across threads.
 *
 * @complexity O(1) - Involves a single system call for backend setup and
 * initial allocations.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Basic TCP echo server setup
 * SocketPoll_T poll = SocketPoll_new(1024);  // Tune based on expected load
 * if (poll == NULL) {
 *     // Handle initialization failure
 *     exit(1);
 * }
 *
 * Socket_T listener = Socket_new(AF_INET, SOCK_STREAM, 0);
 * TRY {
 *     Socket_bind(listener, "127.0.0.1", 8080);
 *     Socket_listen(listener, SOMAXCONN);
 *     Socket_setnonblocking(listener, 1);
 *     SocketPoll_add(poll, listener, POLL_READ, (void*)listener);
 * } EXCEPT(Socket_Failed) {
 *     // Log error
 * } END_TRY;
 *
 * // Event loop would follow...
 * SocketPoll_free(&poll);
 * @endcode
 *
 * ## Advanced Usage with Configuration
 *
 * @code{.c}
 * SocketPoll_T poll = SocketPoll_new(2048);
 * SocketPoll_setdefaulttimeout(poll, 100);  // 100ms default wait
 * SocketPoll_setmaxregistered(poll, 10000); // Limit connections
 *
 * // Integrate with timers for heartbeats
 * SocketTimer_T heartbeat = SocketTimer_add(poll, 30000, heartbeat_cb, NULL);
 *
 * // ... main loop ...
 * @endcode
 *
 * @note Each poll instance manages its own internal arena; no external Arena_T
 * required.
 * @warning High maxevents values increase per-wait memory footprint; profile
 * under load.
 * @see SocketPoll_free() for proper disposal and resource release.
 * @see SocketPoll_setmaxregistered() for post-creation registration limits.
 * @see SocketPoll_wait() for the core event waiting mechanism.
 * @see SocketPoll_add() for registering sockets to monitor.
 * @see SocketTimer_add() for scheduling timers integrated with the poll cycle.
 * @see @ref event_system for full event system architecture.
 * @see docs/ASYNC_IO.md for event-driven server examples and best practices.
 */
extern T SocketPoll_new (int maxevents);

/**
 * @brief Dispose of a SocketPoll instance and release all associated
 * resources.
 * @ingroup event_system
 *
 * Completes the lifecycle of a poll instance by:
 * - Closing the platform-specific backend file descriptor (e.g., epoll fd).
 * - Implicitly deregistering all monitored file descriptors by destroying
 * backend state.
 * - Canceling all integrated timers via heap cleanup.
 * - Destroying synchronization primitives (mutex).
 * - Disposing the internal arena, which frees all hash table entries, event
 * buffers, and mappings.
 * - Freeing the main poll structure.
 *
 * Sockets registered with the poll are NOT closed or freed; the user remains
 * responsible for calling Socket_free() or Socket_close() on them separately.
 * The internal mappings (socket-to-data and fd-to-socket) are cleared,
 * preventing further event delivery for those sockets.
 *
 * Post-cleanup, the poll pointer is set to NULL to prevent accidental reuse.
 * If called on NULL or invalid, it's a no-op.
 *
 * Edge cases:
 * - Concurrent wait/add/del operations: May result in incomplete cleanup;
 * internal locks mitigate but prefer sequential access.
 * - Backend close failures: Logged via SOCKET_LOG_ERROR but do not halt
 * cleanup.
 *
 * @param[in,out] poll Pointer to the poll instance (set to NULL on
 * completion).
 *
 * @threadsafe Yes - Uses internal mutex to protect shared state during
 * cleanup.
 *
 * @complexity O(n + m) where n=registered sockets (hash table traversal
 * implicit via arena dispose), m=timers.
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketPoll_T poll = SocketPoll_new(1024);
 * // ... register sockets, run event loop ...
 *
 * // Cleanup
 * SocketPoll_free(&poll);  // poll now NULL, all internal resources released
 * @endcode
 *
 * ## In Exception-Safe Context
 *
 * @code{.c}
 * TRY {
 *     SocketPoll_T poll = SocketPoll_new(1024);
 *     // Operations that may throw
 *     SocketPoll_add(poll, sock, events, data);
 * } FINALLY {
 *     SocketPoll_free(&poll);  // Ensures cleanup even if exceptions occur
 * } END_TRY;
 * @endcode
 *
 * @note Sockets must be explicitly closed by user code post-deregistration.
 * @warning Avoid calling during active SocketPoll_wait(); use signals or
 * timeouts for graceful shutdown.
 * @see SocketPoll_new() for creation counterpart.
 * @see SocketPoll_del() for deregistering individual sockets before full
 * cleanup.
 * @see SocketPoll_getregisteredcount() to monitor and verify count drops to 0.
 * @see Arena_dispose() indirectly called via internal arena.
 * @see SocketTimer_heap_free() for timer cleanup details.
 * @see docs/MEMORY_MANAGEMENT.md for comprehensive resource disposal
 * guidelines.
 */
extern void SocketPoll_free (T *poll);

/**
 * @brief Register a socket for I/O event monitoring within the poll instance.
 * @ingroup event_system
 *
 * Adds the specified socket to the poll's internal monitoring set, enabling
 * event notifications for the requested I/O conditions. Internally performs:
 * - Socket validity check and duplicate registration detection.
 * - Idempotent configuration of socket to non-blocking mode.
 * - O(1) hash table insertion for socket-to-userdata mapping.
 * - Platform-specific backend registration (epoll_ctl add, kevent add, poll
 * array update).
 * - registered_count increment with max_registered limit enforcement.
 *
 * Event monitoring includes explicit flags (read/write) plus implicit error
 * and hangup detection. User data is preserved and delivered verbatim in event
 * notifications.
 *
 * Error conditions trigger SocketPoll_Failed with detailed messages via
 * Socket_GetLastError(). Common failures: duplicate socket, bad fd, resource
 * limits (EMFILE), permissions (EPERM).
 *
 * ## Event Flags Table
 *
 * | Flag          | Description                  | Backend Equivalent |
 * |---------------|------------------------------|-----------------------------|
 * | POLL_READ     | Data ready to read           | EPOLLIN / EVFILT_READ | |
 * POLL_WRITE    | Ready to write               | EPOLLOUT / EVFILT_WRITE     |
 * | POLL_ERROR    | Error condition              | EPOLLERR / NOTE_ERROR | |
 * POLL_HANGUP   | Peer disconnect              | EPOLLHUP / EVFILT_READ eof  |
 *
 * @param[in] poll Poll instance (non-NULL, valid).
 * @param[in] socket Socket to add for monitoring (valid open fd required).
 * @param[in] events Bitmask of events to monitor (0 invalid; use
 * SocketPoll_Events).
 * @param[in] data Opaque userdata (may be NULL; stored and returned in
 * events).
 *
 * @throws SocketPoll_Failed For:
 *                          - Duplicate registration (socket already in poll).
 *                          - Invalid socket (NULL, closed, bad fd).
 *                          - Backend failure (EMFILE, ENOMEM, EPERM, ENOSYS).
 *                          - Exceeds configured max_registered limit.
 *
 * @threadsafe Yes - Fully atomic with mutex; concurrent safe.
 *
 * @complexity O(1) average case - Hash insert + O(1) backend syscall.
 *
 * ## Basic Server Listener Registration
 *
 * @code{.c}
 * Socket_T listener;
 * TRY {
 *     listener = Socket_new(AF_INET, SOCK_STREAM, 0);
 *     Socket_bind(listener, "0.0.0.0", 8080);
 *     Socket_listen(listener, SOMAXCONN);
 *     Socket_setnonblocking(listener, 1);  // Recommended
 *     SocketPoll_add(poll, listener, POLL_READ, listener);  // Self-reference
 * common } EXCEPT(Socket_Failed) {
 *     // Handle bind/listen failure
 * } END_TRY;
 * @endcode
 *
 * ## Client Connection Handling
 *
 * @code{.c}
 * // After accept(2)
 * Socket_T client = Socket_new_from_fd(accepted_fd);
 * if (client) {
 *     TRY {
 *         SocketPoll_add(poll, client, POLL_READ | POLL_WRITE, client_ctx);
 *     } EXCEPT(SocketPoll_Failed) {
 *         Socket_free(&client);
 *         // Log registration failure
 *     } END_TRY;
 * }
 * @endcode
 *
 * ## With Custom User Data
 *
 * @code{.c}
 * struct ConnCtx { void *app_data; time_t last_active; };
 * struct ConnCtx *ctx = CALLOC(poll_arena, 1, sizeof(struct ConnCtx));
 * ctx->app_data = user_object;
 * SocketPoll_add(poll, sock, POLL_READ, ctx);  // Retrieved in
 * SocketEvent_T.data
 * @endcode
 *
 * @note User data lifetime must exceed poll lifetime or until
 * SocketPoll_del().
 * @warning Do not register the same socket in multiple polls; use one primary
 * poll per socket.
 * @see SocketPoll_mod() for event/data updates without re-registration.
 * @see SocketPoll_del() for explicit removal.
 * @see SocketPoll_wait() to process resulting events.
 * @see SocketPoll_Events enum for flag values.
 * @see Socket_setnonblocking() if manual control needed.
 * @see @ref connection_mgmt::SocketPool_add() for pool-integrated registration
 * patterns.
 * @see docs/ASYNC_IO.md for full event-driven examples.
 */
extern void
SocketPoll_add (T poll, Socket_T socket, unsigned events, void *data);

/**
 * @brief Update event monitoring and/or user data for a registered socket.
 * @ingroup event_system
 * @param poll Poll instance.
 * @param socket Registered socket to modify.
 * @param events Updated event bitmask to monitor (can change from previous).
 * @param data Updated user data pointer (replaces previous association).
 * @threadsafe Yes - atomic update protecting against concurrent access.
 * @throws SocketPoll_Failed if socket not registered or backend modification
 * fails.
 * @note Equivalent to del + add internally on some backends (e.g., kqueue).
 * @note Does not change socket's non-blocking state.
 *
 * Use to dynamically adjust monitoring (e.g., enable write after connect
 * success).
 *
 * @see SocketPoll_add() for initial socket registration.
 * @see SocketPoll_del() for complete deregistration.
 * @see SocketPoll_Events for event bitmask options.
 * @see SocketEvent_T::data for how user data is delivered in events.
 */
extern void
SocketPoll_mod (T poll, Socket_T socket, unsigned events, void *data);

/**
 * @brief Deregister a socket from the poll's event monitoring set.
 * @ingroup event_system
 *
 * Removes the specified socket from internal monitoring, stopping future event
 * notifications for it. Internally executes:
 * - Hash table removal for socket-data and fd-socket mappings (O(1) average).
 * - Backend deregistration (epoll_ctl del, kevent delete, poll array removal).
 * - registered_count decrement.
 * - Cleanup of any associated state (e.g., event filters).
 *
 * Idempotent operation: No-op if socket not registered or already removed.
 * On backend transient errors (e.g., ENOENT), local state cleaned for
 * consistency. Persistent errors (EBADF, EPERM) raise exception. Logs warnings
 * for detected inconsistencies via SOCKET_LOG_WARN.
 *
 * Call this during connection closure, error handling, or resource reclamation
 * to prevent stale events and free backend slots. Does NOT close or free the
 * socket; manage separately.
 *
 * @param[in] poll Valid poll instance.
 * @param[in] socket Socket to remove (ignored if NULL or unregistered).
 *
 * @throws SocketPoll_Failed Rarely, on backend del failure (e.g., EBADF
 * invalid fd, EPERM permissions).
 *
 * @threadsafe Yes - Atomic with mutex; concurrent safe.
 *
 * @complexity O(1) average - Hash removal + single backend del syscall.
 *
 * ## Usage in Event Handling
 *
 * @code{.c}
 * // In event loop, on error or hangup
 * if (ev->events & (POLL_ERROR | POLL_HANGUP)) {
 *     SOCKET_LOG_INFO("Disconnecting socket %d", Socket_fd(ev->socket));
 *     SocketPoll_del(poll, ev->socket);
 *     Socket_free(&ev->socket);  // Or Socket_close() if reusing fd
 * }
 * @endcode
 *
 * ## Bulk Cleanup with Pool
 *
 * @code{.c}
 * // Graceful shutdown
 * SocketPool_foreach(pool, cleanup_cb, NULL);
 *
 * void cleanup_cb(Connection_T conn, void *arg) {
 *     Socket_T sock = Connection_socket(conn);
 *     SocketPoll_del(poll, sock);  // Deregister before pool remove
 *     // Pool handles further cleanup
 * }
 * @endcode
 *
 * @note After del, socket can be re-registered with SocketPoll_add() or used
 * elsewhere.
 * @warning Failing to del before Socket_free() may leak backend state (rare;
 * auto-clean on close).
 * @see SocketPoll_add() for registration counterpart.
 * @see SocketPoll_mod() for updates without full removal.
 * @see SocketPoll_getregisteredcount() to verify removal (decrements count).
 * @see Socket_free() for socket disposal post-del.
 * @see @ref connection_mgmt::SocketPool_remove() for pool integration.
 * @see docs/ASYNC_IO.md for cleanup patterns in event-driven apps.
 */
extern void SocketPoll_del (T poll, Socket_T socket);

/**
 * @brief Get default wait timeout in milliseconds.
 * @ingroup event_system
 * @param poll Poll instance.
 * @return Default timeout in milliseconds.
 * @threadsafe Yes.
 * @see SocketPoll_setdefaulttimeout() for setting the timeout.
 * @see SocketPoll_wait() for how the default timeout is used.
 */
extern int SocketPoll_getdefaulttimeout (T poll);

/**
 * @brief Set default wait timeout in milliseconds.
 * @ingroup event_system
 * @param poll Poll instance.
 * @param timeout Timeout in milliseconds (0 = immediate, -1 = infinite).
 * @threadsafe Yes.
 * @see SocketPoll_getdefaulttimeout() for retrieving the current timeout.
 * @see SocketPoll_wait() for how the default timeout is used.
 */
extern void SocketPoll_setdefaulttimeout (T poll, int timeout);

/**
 * @brief Block and wait for I/O events or timeout on registered sockets.
 * @ingroup event_system
 *
 * Core event loop primitive: suspends execution until I/O events occur on
 * monitored sockets, timers expire, or timeout elapses. Internally
 * orchestrates:
 * - Timer heap check for due timers (integrated SocketTimer support).
 * - Backend wait syscall (epoll_wait, kevent, poll) for raw fd events.
 * - Event translation from backend fd/events to SocketEvent_T with userdata.
 * - Optional async I/O completion processing (SocketAsync).
 * - Automatic cleanup of expired/closed registrations.
 *
 * Returns array of SocketEvent_T populated with occurred events. Array is
 * valid until next wait call. 0 return indicates timeout (no events); negative
 * or exception on errors.
 *
 * Timeout semantics:
 * - -1: Infinite wait (block until event).
 * - 0: Non-blocking poll (immediate return).
 * - >0: Wait up to N ms.
 * - SOCKET_POLL_TIMEOUT_USE_DEFAULT: Use poll->default_timeout_ms.
 *
 * Errors: Backend syscalls fail (EINTR handled), invalid state, or resource
 * issues. Also processes and delivers timer callbacks if timers due.
 *
 * ## Timeout Values Table
 *
 * | Value | Behavior | Use Case |
 * |-------|----------|----------|
 * | -1 | Infinite block | Primary server loop |
 * | 0 | Non-blocking | Edge-triggered checks |
 * | >0 | Bounded wait | With external timeouts |
 * | USE_DEFAULT | Configured default | Consistent loops |
 *
 * @param[in] poll Valid poll instance with registered sockets.
 * @param[out] events Pointer to array of events (internal; do not
 * free/modify).
 * @param[in] timeout_ms Wait timeout (-1 infinite, 0 immediate, USE_DEFAULT
 * for default).
 *
 * @return >=0 Number of occurred events (0=timeout, no events).
 *         Exceptions or negative on fatal errors (rare; check throws).
 *
 * @throws SocketPoll_Failed On backend wait failure (e.g., EINVAL, EBADF,
 * ENOMEM).
 *
 * @threadsafe Yes - Returns thread-local event array; mutex protects internal
 * state.
 *
 * @complexity O(k) where k=number of ready events (backend delivers in batch).
 *
 * ## Simple Event Loop
 *
 * @code{.c}
 * while (running) {
 *     SocketEvent_T *events;
 *     int nev = SocketPoll_wait(poll, &events, 100);  // 100ms timeout
 *     for (int i = 0; i < nev; ++i) {
 *         SocketEvent_T *ev = &events[i];
 *         if (ev->events & POLL_READ) {
 *             // Handle read: recv, accept, etc.
 *         }
 *         if (ev->events & POLL_WRITE) {
 *             // Handle write: send, connect completion
 *         }
 *         if (ev->events & (POLL_ERROR | POLL_HANGUP)) {
 *             // Handle error/disconnect: close, log
 *             SocketPoll_del(poll, ev->socket);
 *             Socket_free(&ev->socket);
 *         }
 *         void *data = ev->data;  // User data from add/mod
 *         // Use data for context-specific handling
 *     }
 * }
 * @endcode
 *
 * ## With Timers and Default Timeout
 *
 * @code{.c}
 * SocketPoll_setdefaulttimeout(poll, -1);  // Infinite default
 * SocketTimer_T timer = SocketTimer_add_repeating(poll, 5000, periodic_cb,
 * NULL);
 *
 * while (running) {
 *     SocketEvent_T *events;
 *     int nev = SocketPoll_wait(poll, &events,
 * SOCKET_POLL_TIMEOUT_USE_DEFAULT);
 *     // Process events + timers (periodic_cb called if due)
 * }
 * @endcode
 *
 * @note Events array overwritten on next wait; process immediately.
 * @warning Infinite timeout (-1) without signals/timers risks deadlock; prefer
 * bounded.
 * @see SocketPoll_add() to populate monitoring set before wait.
 * @see SocketEvent_T structure for event details.
 * @see SocketPoll_Events for event flags in returned events.
 * @see SOCKET_POLL_TIMEOUT_USE_DEFAULT constant.
 * @see SocketPoll_setdefaulttimeout() for configuring default.
 * @see SocketTimer_add() for timer integration.
 * @see SocketPoll_get_async() for async extensions processed here.
 * @see docs/ASYNC_IO.md for complete event loop examples.
 * @see docs/ERROR_HANDLING.md for exception safety in loops.
 */
extern int SocketPoll_wait (T poll, SocketEvent_T **events, int timeout);

/**
 * @brief Get async I/O context associated with poll instance.
 * @ingroup event_system
 * @param poll Poll instance.
 * @return Async context or NULL if unavailable.
 * @threadsafe Yes.
 * @note Returns NULL if async I/O is not available on this platform.
 * @see SocketAsync_T for async I/O operations.
 * @see SocketPoll_wait() for automatic async completion processing.
 */
extern SocketAsync_T SocketPoll_get_async (T poll);

/**
 * @brief Get maximum registered sockets limit.
 * @ingroup event_system
 * @param poll Poll instance.
 * @return Maximum limit (0 = unlimited).
 * @threadsafe Yes.
 * @note Defense-in-depth: Returns the configured limit on socket
 * registrations.
 * @note Compile-time default is SOCKET_POLL_MAX_REGISTERED (0 = disabled).
 * @see SocketPoll_setmaxregistered() for setting the limit.
 * @see SocketPoll_getregisteredcount() for current count.
 * @see SocketPoll_add() for socket registration that respects limits.
 */
extern int SocketPoll_getmaxregistered (T poll);

/**
 * @brief Set maximum registered sockets limit.
 * @ingroup event_system
 * @param poll Poll instance.
 * @param max Maximum limit (0 = unlimited).
 * @threadsafe Yes.
 * @throws SocketPoll_Failed if max < registered_count and max > 0.
 * @note Defense-in-depth: Limits the number of sockets that can be registered
 * to prevent resource exhaustion attacks.
 * @note Set to 0 to disable limit.
 * @note Cannot set limit below current registered_count.
 * @see SocketPoll_getmaxregistered() for retrieving the current limit.
 * @see SocketPoll_getregisteredcount() for current count.
 */
extern void SocketPoll_setmaxregistered (T poll, int max);

/**
 * @brief Get current registered socket count.
 * @ingroup event_system
 * @param poll Poll instance.
 * @return Number of currently registered sockets.
 * @threadsafe Yes.
 * @see SocketPoll_getmaxregistered() for the maximum allowed.
 * @see SocketPoll_add() for registering sockets.
 * @see SocketPoll_del() for removing sockets.
 */
extern int SocketPoll_getregisteredcount (T poll);

/**
 * @brief Get the name of the polling backend in use.
 * @ingroup event_system
 * @param poll Poll instance (may be NULL).
 * @return Static string: "epoll", "kqueue", or "poll".
 *
 * Returns the name of the platform-specific backend used for I/O multiplexing.
 * Useful for logging, debugging, and runtime platform detection.
 *
 * @threadsafe Yes - returns static string.
 * @complexity O(1)
 *
 * ## Example
 *
 * @code{.c}
 * SocketPoll_T poll = SocketPoll_new(1024);
 * printf("Using backend: %s\n", SocketPoll_get_backend_name(poll));
 * // Output on Linux: "Using backend: epoll"
 * // Output on macOS: "Using backend: kqueue"
 * @endcode
 *
 * @note poll parameter is for API consistency but currently unused;
 *       backend is determined at compile time.
 * @see SocketPoll_new() which selects backend automatically.
 */
extern const char *SocketPoll_get_backend_name (T poll);

/**
 * @brief Get list of currently registered sockets.
 * @ingroup event_system
 * @param[in] poll Poll instance.
 * @param[out] sockets Array to populate with registered Socket_T handles.
 * @param[in] max Maximum number of sockets to return.
 * @return Number of sockets copied to array (may be < registered_count if max
 * too small).
 *
 * Retrieves up to `max` sockets currently registered with the poll instance.
 * Useful for debugging, cleanup operations, or iterating over monitored
 * connections.
 *
 * @throws SocketPoll_Failed if poll NULL or sockets NULL with max > 0.
 * @threadsafe Yes - acquires internal mutex.
 * @complexity O(n) where n = number of registered sockets.
 *
 * ## Example
 *
 * @code{.c}
 * Socket_T sockets[100];
 * int count = SocketPoll_get_registered_sockets(poll, sockets, 100);
 * for (int i = 0; i < count; i++) {
 *     printf("Registered: fd=%d\n", Socket_fd(sockets[i]));
 * }
 * @endcode
 *
 * @see SocketPoll_getregisteredcount() for just the count.
 * @see SocketPoll_del() to remove specific sockets.
 */
extern int
SocketPoll_get_registered_sockets (T poll, Socket_T *sockets, int max);

/**
 * @brief Modify event mask for a registered socket (add or remove flags).
 * @ingroup event_system
 * @param[in] poll Poll instance.
 * @param[in] socket Registered socket to modify.
 * @param[in] add_events Event flags to add (OR'ed with current).
 * @param[in] remove_events Event flags to remove (AND NOT with current).
 *
 * Provides fine-grained control over monitored events without needing to
 * track the current event mask. Internally computes:
 *   new_events = (current_events | add_events) & ~remove_events
 *
 * @throws SocketPoll_Failed if socket not registered or backend fails.
 * @threadsafe Yes - acquires internal mutex.
 * @complexity O(1) - hash lookup + backend mod.
 *
 * ## Example
 *
 * @code{.c}
 * // Add write monitoring when we have data to send
 * SocketPoll_modify_events(poll, socket, POLL_WRITE, 0);
 *
 * // Remove write monitoring when send buffer empty
 * SocketPoll_modify_events(poll, socket, 0, POLL_WRITE);
 *
 * // Switch from read to write only
 * SocketPoll_modify_events(poll, socket, POLL_WRITE, POLL_READ);
 * @endcode
 *
 * @see SocketPoll_mod() for setting exact event mask with data.
 * @see SocketPoll_Events for available event flags.
 */
extern void SocketPoll_modify_events (T poll,
                                      Socket_T socket,
                                      unsigned add_events,
                                      unsigned remove_events);

#undef T

#endif

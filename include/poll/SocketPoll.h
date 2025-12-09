#ifndef SOCKETPOLL_INCLUDED
#define SOCKETPOLL_INCLUDED

#include "core/Except.h"
#include "core/SocketTimer.h" /* Re-export timer functions */
#include "socket/Socket.h"

/**
 * @brief Asynchronous I/O context for high-throughput, zero-copy operations.
 * @ingroup async_io
 * @ingroup event_system
 * Integrates with SocketPoll_T for automatic completion processing during event waits.
 * Enables advanced patterns like scatter-gather I/O and non-blocking file operations.
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
 * Key components: SocketPoll (epoll/kqueue/poll), SocketTimer (timers), SocketAsync (async I/O).
 * Enables scalable event-driven network applications with automatic platform adaptation.
 *
 * Architecture Overview:
 * - # SocketPoll_T: Core polling interface with backend abstraction for epoll/kqueue/poll.
 * - # SocketTimer_T: Heap-based timer scheduling integrated with poll wait cycles.
 * - # SocketAsync_T: Asynchronous I/O extensions for zero-copy, high-throughput operations.
 *
 * Backend Selection:
 * - Linux: epoll(7) for O(1) edge-triggered notifications.
 * - BSD/macOS: kqueue(2) for efficient event filtering and file descriptor monitoring.
 * - Fallback: poll(2) for broad POSIX compatibility (level-triggered).
 *
 * Design Principles:
 * - Thread-safe: Internal mutexes protect shared state across operations.
 * - Arena-allocated: Efficient memory management tied to poll lifecycle.
 * - Non-blocking: Automatically configures sockets for async operation.
 *
 * Usage Patterns:
 * - Servers: Combine with @ref connection_mgmt::SocketPool_T for connection handling.
 * - Clients: Use with @ref utilities::SocketReconnect_T for resilient connections.
 * - Timeouts: Integrate SocketTimer_add() for idle connection management.
 *
 * Error Handling: Uses @ref foundation exceptions with detailed errno mapping.
 * Performance: Minimizes syscalls; supports up to system limits (e.g., /proc/sys/fs/epoll/max_user_watches).
 *
 * @see @ref foundation for base infrastructure (Arena_T, Except_T).
 * @see @ref core_io for Socket_T primitives compatible with event registration.
 * @see @ref connection_mgmt for advanced connection lifecycle management.
 * @see @ref async_io for SocketAsync_T usage in high-performance scenarios.
 * @see @ref utilities for rate limiting and retry logic integration.
 * @see SocketPoll_T for polling API details.
 * @see SocketTimer_T for timer API (re-exported here).
 * @see SocketAsync_T for async extensions (forward declared).
 * @see docs/ASYNC_IO.md for event-driven programming examples and best practices.
 * @see docs/ERROR_HANDLING.md for exception patterns in event loops.
 * @}
 */

/**
 * @file SocketPoll.h
 * @ingroup event_system
 * @brief Cross-platform high-level interface for monitoring multiple sockets for I/O events.
 *
 * Automatically selects optimal backend: epoll (Linux), kqueue (BSD/macOS), poll (POSIX fallback).
 * Supports edge-triggered and level-triggered modes depending on backend capabilities.
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
 * Maintains an internal mapping of sockets to user data for efficient event dispatching and context retrieval.
 * Registered sockets are automatically configured for non-blocking I/O.
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
 * @brief High-performance socket polling abstraction with cross-platform backends.
 * @ingroup event_system
 *
 * Provides scalable event notification for network applications with O(1) event delivery
 * regardless of the number of monitored sockets. Automatically selects the best available
 * backend for the platform: epoll (Linux), kqueue (BSD/macOS), or poll (POSIX fallback).
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
  POLL_ERROR = 1 << 2,  /**< Error condition occurred */
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
 * @note This constant ensures timeout consistency across multiple wait operations.
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
 * @param maxevents Maximum number of events to process per wait call (suggest 1024+ for servers).
 * @return New SocketPoll_T instance or NULL on failure.
 * @throws SocketPoll_Failed if backend initialization fails (e.g., resource limits).
 * @threadsafe Yes - each instance is independent.
 * @note Automatically selects and initializes platform-optimal backend (epoll/kqueue/poll) with edge-triggered mode where supported.
 * @note Allocates internal structures using caller's arena if provided; otherwise uses default.
 *
 * Example usage:
 * ~~~c
 * SocketPoll_T poll = SocketPoll_new(1024);
 * if (!poll) { /* handle error */ }
 * // Register sockets...
 * SocketPoll_free(&poll);
 * ~~~
 *
 * @see SocketPoll_free() for resource cleanup.
 * @see SocketPoll_setmaxregistered() for configuring registration limits.
 * @see SocketPoll_wait() for primary event loop integration.
 * @see SocketPoll_add() for adding sockets to monitor.
 * @see @ref event_system "Event System" for complete module overview.
 */
extern T SocketPoll_new (int maxevents);

/**
 * @brief Dispose of an event poll instance and release resources.
 * @ingroup event_system
 * @param poll Pointer to poll instance (set to NULL on success).
 * @threadsafe Yes - safe from any thread.
 * @note Closes underlying backend file descriptor (epoll fd, kqueue, or poll structures).
 * @note Automatically deregisters and closes all tracked sockets if configured.
 * @note Releases internal mappings, timers, and arena-allocated memory.
 * @warning Ensure no concurrent SocketPoll_wait() or registrations are active.
 *
 * Always pair with SocketPoll_new() and call before program exit to avoid leaks.
 *
 * @see SocketPoll_new() for instance creation.
 * @see SocketPoll_getregisteredcount() to verify cleanup (should be 0 post-free).
 * @see @ref foundation::Arena_dispose() for managing the arena used by poll.
 * @see docs/MEMORY_MANAGEMENT.md for arena lifecycle best practices.
 */
extern void SocketPoll_free (T *poll);

/**
 * @brief Register a socket for event monitoring in the poll set.
 * @ingroup event_system
 * @param poll Poll instance to register with.
 * @param socket Socket_T to monitor for I/O events.
 * @param events Bitmask of events (POLL_READ | POLL_WRITE | etc.).
 * @param data Opaque user data pointer associated with this socket (retrieved in events).
 * @threadsafe Yes - atomic registration with mutex protection.
 * @note Automatically configures socket to non-blocking mode if not already set.
 * @note POLL_ERROR and POLL_HANGUP are always implicitly monitored.
 * @throws SocketPoll_Failed if socket already registered, invalid fd, or backend registration fails (e.g., EMFILE).
 * @note Respects SocketPoll_setmaxregistered() limit; raises if exceeded.
 *
 * User data is stored internally and returned unchanged in SocketEvent_T.data during notifications.
 *
 * @see SocketPoll_mod() to update events or data for existing registration.
 * @see SocketPoll_del() to deregister a socket.
 * @see SocketPoll_wait() to receive events for registered sockets.
 * @see SocketPoll_Events for event bitmask definitions.
 * @see Socket_setnonblocking() for manual non-blocking configuration.
 * @see @ref core_io::Socket_T for socket lifecycle management.
 */
extern void SocketPoll_add (T poll, Socket_T socket, unsigned events,
                            void *data);

/**
 * @brief Update event monitoring and/or user data for a registered socket.
 * @ingroup event_system
 * @param poll Poll instance.
 * @param socket Registered socket to modify.
 * @param events Updated event bitmask to monitor (can change from previous).
 * @param data Updated user data pointer (replaces previous association).
 * @threadsafe Yes - atomic update protecting against concurrent access.
 * @throws SocketPoll_Failed if socket not registered or backend modification fails.
 * @note Equivalent to del + add internally on some backends (e.g., kqueue).
 * @note Does not change socket's non-blocking state.
 *
 * Use to dynamically adjust monitoring (e.g., enable write after connect success).
 *
 * @see SocketPoll_add() for initial socket registration.
 * @see SocketPoll_del() for complete deregistration.
 * @see SocketPoll_Events for event bitmask options.
 * @see SocketEvent_T::data for how user data is delivered in events.
 */
extern void SocketPoll_mod (T poll, Socket_T socket, unsigned events,
                            void *data);

/**
 * @brief Deregister a socket from event monitoring.
 * @ingroup event_system
 * @param poll Poll instance.
 * @param socket Socket to deregister (no-op if not registered).
 * @threadsafe Yes - mutex-protected removal from internal mappings.
 * @note Idempotent: safe to call multiple times or on unregistered sockets.
 * @note On transient backend errors, cleans local state for consistency.
 * @note Logs warnings for inconsistent state (e.g., backend already removed).
 * @throws SocketPoll_Failed on persistent backend errors (rare, e.g., EBADF).
 *
 * Call during connection cleanup or error recovery to free poll resources.
 * Does not close the socket fd; user must manage socket lifecycle.
 *
 * @see SocketPoll_add() and SocketPoll_mod() for registration/modification.
 * @see SocketPoll_getregisteredcount() to track active registrations.
 * @see Socket_free() for full socket disposal after deregistration.
 * @see @ref connection_mgmt for pool-based connection cleanup patterns.
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
 * @brief Wait for I/O events on registered sockets.
 * @ingroup event_system
 * @param poll Poll instance.
 * @param events Output - array of events that occurred.
 * @param timeout Timeout in milliseconds (-1 for infinite, 0 for immediate,
 *                SOCKET_POLL_TIMEOUT_USE_DEFAULT for poll's default timeout).
 * @return Number of events (0 on timeout).
 * @threadsafe Yes - event array is thread-local to poll instance.
 * @throws SocketPoll_Failed on error.
 * @note The events array points to internal memory - do not free.
 * @note Also processes async I/O completions automatically.
 * @note Use SOCKET_POLL_TIMEOUT_USE_DEFAULT for consistent timeout behavior.
 * @see SocketPoll_add() for registering sockets to monitor.
 * @see SocketPoll_getdefaulttimeout() for default timeout configuration.
 * @see SocketPoll_setdefaulttimeout() for setting default timeout.
 * @see SOCKET_POLL_TIMEOUT_USE_DEFAULT for special timeout constant.
 * @see SocketEvent_T for event structure details.
 * @see SocketPoll_Events for available event types.
 * @see SocketAsync_T for async I/O integration.
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
 * @note Defense-in-depth: Returns the configured limit on socket registrations.
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
 * @note Defense-in-depth: Limits the number of sockets that can be registered to prevent resource exhaustion attacks.
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

#undef T

#endif

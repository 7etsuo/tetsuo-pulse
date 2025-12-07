#ifndef SOCKETPOLL_INCLUDED
#define SOCKETPOLL_INCLUDED

#include "core/Except.h"
#include "core/SocketTimer.h" /* Re-export timer functions */
#include "socket/Socket.h"

/* Forward declaration for async I/O */
struct SocketAsync_T;
typedef struct SocketAsync_T *SocketAsync_T;

/**
 * Socket Event Polling
 *
 * High-level interface for monitoring multiple sockets for I/O events.
 * Uses epoll on Linux for scalable event notification. Supports both
 * edge-triggered and level-triggered modes.
 * PLATFORM REQUIREMENTS:
 * - Linux kernel 2.6.8+ (epoll with EPOLLET support)
 * - POSIX threads (pthread) for mutex synchronization
 * - NOT portable to BSD/macOS (would require kqueue backend)
 * - NOT portable to Windows (would require IOCP backend)
 * - For portable code, consider falling back to poll(2)
 * Features:
 * - O(1) event delivery regardless of total sockets
 * - Edge-triggered mode for efficiency
 * - User data association with sockets
 * - Configurable default timeout applied when requested
 * - Thread-safe implementation
 * The poll maintains a mapping of sockets to user data, allowing
 * efficient context retrieval when events occur.
 */

#define T SocketPoll_T
typedef struct T *T;

/* ============================================================================
 * Exception Types
 * ============================================================================ */

/**
 * SocketPoll_Failed - Poll operation failure
 *
 * Category: RESOURCE or PROTOCOL
 * Retryable: Depends on errno
 *
 * Raised for:
 * - epoll/kqueue creation failure (RESOURCE, not retryable)
 * - Invalid socket (PROTOCOL, not retryable)
 * - Duplicate socket add (PROTOCOL, not retryable)
 * - EMFILE/ENFILE (RESOURCE, retryable after fd cleanup)
 */
extern const Except_T SocketPoll_Failed;

/**
 * Event types that can be monitored
 */
typedef enum
{
  POLL_READ = 1 << 0,  /**< Data available for reading */
  POLL_WRITE = 1 << 1, /**< Socket ready for writing */
  POLL_ERROR = 1 << 2, /**< Error condition */
  POLL_HANGUP = 1 << 3 /**< Hang up / disconnection */
} SocketPoll_Events;

/**
 * Event structure returned by SocketPoll_wait
 */
typedef struct SocketEvent
{
  Socket_T socket; /**< Socket that triggered event */
  void *data;      /**< User data associated with socket */
  unsigned events; /**< Bitmask of events that occurred */
} SocketEvent_T;

#define SOCKET_POLL_TIMEOUT_USE_DEFAULT (-2)

/**
 * SocketPoll_new - Create a new event poll
 * @maxevents: Maximum events to return per wait call
 * Returns: New poll instance
 * Raises: SocketPoll_Failed on error
 * Thread-safe: Yes - returns new instance
 * Creates an edge-triggered epoll instance for high-performance I/O.
 */
extern T SocketPoll_new (int maxevents);

/**
 * SocketPoll_free - Free an event poll
 * @poll: Pointer to poll (will be set to NULL)
 * Closes the underlying epoll descriptor
 */
extern void SocketPoll_free (T *poll);

/**
 * SocketPoll_add - Add socket to poll set
 * @poll: Poll instance
 * @socket: Socket to monitor
 * @events: Events to monitor (POLL_READ | POLL_WRITE)
 * @data: User data to associate with socket
 * Socket is automatically set to non-blocking mode
 * Raises: SocketPoll_Failed if socket already added or epoll_ctl fails
 * Thread-safe: Yes - uses internal mutex for socket data mapping
 */
extern void SocketPoll_add (T poll, Socket_T socket, unsigned events,
                            void *data);

/**
 * SocketPoll_mod - Modify monitored events
 * @poll: Poll instance
 * @socket: Socket to modify
 * @events: New events to monitor
 * @data: New user data (updates association)
 * Raises: SocketPoll_Failed if socket not in poll or epoll_ctl fails
 * Thread-safe: Yes - atomic update of socket data mapping
 */
extern void SocketPoll_mod (T poll, Socket_T socket, unsigned events,
                            void *data);

/**
 * SocketPoll_del - Remove socket from poll set
 * @poll: Poll instance
 * @socket: Socket to remove
 * Silently succeeds if socket not in poll
 * Thread-safe: Yes - uses internal mutex for socket data mapping
 */
/**
 * Note: On backend error (non-ENOENT), raises leaving state intact for retry.
 * Logs ENOENT warning and cleans data map. Security: Prioritizes backend clean.
 * Single-threaded socket access assumed.
 */
extern void SocketPoll_del (T poll, Socket_T socket);

/**
 * SocketPoll_getdefaulttimeout - Get default wait timeout in milliseconds
 * @poll: Poll instance
 * Returns: Default timeout in milliseconds
 */
extern int SocketPoll_getdefaulttimeout (T poll);

/**
 * SocketPoll_setdefaulttimeout - Set default wait timeout in milliseconds
 * @poll: Poll instance
 * @timeout: Timeout in milliseconds (0 = immediate, -1 = infinite)
 * Returns: Nothing
 */
extern void SocketPoll_setdefaulttimeout (T poll, int timeout);

/**
 * SocketPoll_wait - Wait for events
 * @poll: Poll instance
 * @events: Output - array of events that occurred
 * @timeout: Timeout in milliseconds (-1 for infinite)
 * Returns: Number of events (0 on timeout)
 * Raises: SocketPoll_Failed on error
 * Thread-safe: Yes - event array is thread-local to poll instance
 * The events array points to internal memory - do not free
 * Note: Also processes async I/O completions automatically
 */
extern int SocketPoll_wait (T poll, SocketEvent_T **events, int timeout);

/**
 * SocketPoll_get_async - Get async I/O context from poll
 * @poll: Poll instance
 * Returns: Async context or NULL if unavailable
 * Thread-safe: Yes
 * Note: Returns NULL if async I/O is not available on this platform
 */
extern SocketAsync_T SocketPoll_get_async (T poll);

/**
 * SocketPoll_getmaxregistered - Get maximum registered sockets limit
 * @poll: Poll instance
 * Returns: Maximum limit (0 = unlimited)
 * Thread-safe: Yes
 *
 * Defense-in-depth: Returns the configured limit on socket registrations.
 * Compile-time default is SOCKET_POLL_MAX_REGISTERED (0 = disabled).
 */
extern int SocketPoll_getmaxregistered (T poll);

/**
 * SocketPoll_setmaxregistered - Set maximum registered sockets limit
 * @poll: Poll instance
 * @max: Maximum limit (0 = unlimited)
 * Thread-safe: Yes
 *
 * Defense-in-depth: Limits the number of sockets that can be registered
 * to prevent resource exhaustion attacks. Set to 0 to disable.
 *
 * Note: Cannot set limit below current registered_count.
 * Raises: SocketPoll_Failed if max < registered_count and max > 0
 */
extern void SocketPoll_setmaxregistered (T poll, int max);

/**
 * SocketPoll_getregisteredcount - Get current registered socket count
 * @poll: Poll instance
 * Returns: Number of currently registered sockets
 * Thread-safe: Yes
 */
extern int SocketPoll_getregisteredcount (T poll);

#undef T
#endif

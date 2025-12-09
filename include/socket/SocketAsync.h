#ifndef SOCKETASYNC_INCLUDED
#define SOCKETASYNC_INCLUDED

#include "core/Except.h"
#include "socket/Socket.h"

/**
 * @file SocketAsync.h
 * @ingroup core_io
 * @brief Asynchronous I/O operations using platform-optimized mechanisms.
 *
 * Provides non-blocking I/O operations using platform-optimized async
 * mechanisms:
 * - Linux: io_uring (kernel 5.1+)
 * - macOS/BSD: kqueue AIO
 * - Fallback: Edge-triggered polling (if async unavailable)
 *
 * Features:
 * - Zero-copy operations where supported
 * - Callback-based completion handling
 * - Integration with SocketPoll for event-driven completion
 * - Thread-safe operation
 *
 * Platform Requirements:
 * - Linux: kernel 5.1+ for io_uring (falls back to edge-triggered if
 * unavailable)
 * - macOS/BSD: kqueue with AIO support
 * - All platforms: Non-blocking sockets (automatically handled)
 *
 * @see SocketPoll_get_async() for obtaining async interface.
 * @see SocketAsync_send() for asynchronous send operations.
 * @see SocketAsync_recv() for asynchronous receive operations.
 */

#define T SocketAsync_T
typedef struct T *T;

/* Exception types */
extern const Except_T SocketAsync_Failed; /**< Async operation failure */

/**
 * @brief SocketAsync_Callback - Callback function for async operation completion
 * @ingroup core_io
 * @socket: Socket that completed the operation
 * @bytes: Number of bytes transferred (negative on error)
 * @err: Error code (0 on success, errno value on error)
 * @user_data: User data passed to async function
 *
 * Returns: Nothing
 *
 * Note: bytes < 0 indicates error, check err for details.
 * For send operations: bytes is total bytes sent (may be partial)
 * For recv operations: bytes is total bytes received (0 = EOF)
 * Callback is invoked from SocketPoll_wait() context - keep it fast!
 * @note Thread-safe: Yes - invoked from single-threaded poll context
 * @ingroup core_io
 */
typedef void (*SocketAsync_Callback) (Socket_T socket, ssize_t bytes, int err,
                                      void *user_data);

/**
 * Async operation flags
 */
typedef enum
{
  ASYNC_FLAG_NONE = 0, /**< No special flags */
  ASYNC_FLAG_ZERO_COPY
  = 1 << 0, /**< Use zero-copy (sendfile/splice) if available */
  ASYNC_FLAG_URGENT
  = 1 << 1 /**< High-priority operation (io_uring IOSQE_IO_LINK) */
} SocketAsync_Flags;

/**
 * @brief SocketAsync_new - Create a new async I/O context
 * @ingroup core_io
 * @arena: Arena for memory allocation
 * Returns: New async context (never returns NULL)
 * Raises: SocketAsync_Failed on initialization failure
 * @note Thread-safe: Yes - returns new instance
 * @ingroup core_io
 *
 * Creates an async context with platform-specific backend initialization.
 * Falls back gracefully if async I/O is unavailable on this platform.
 */
extern T SocketAsync_new (Arena_T arena);

/**
 * @brief SocketAsync_free - Free an async I/O context
 * @ingroup core_io
 * @async: Pointer to async context (will be set to NULL)
 * @note Thread-safe: Yes - frees resources
 * @ingroup core_io
 */
extern void SocketAsync_free (T *async);

/**
 * @brief SocketAsync_send - Submit asynchronous send operation
 * @ingroup core_io
 * @async: Async context (from SocketPoll_get_async)
 * @socket: Socket to send on (must be non-blocking)
 * @buf: Data to send
 * @len: Length of data to send
 * @cb: Callback to call on completion
 * @user_data: User data passed to callback
 * @flags: Operation flags (ASYNC_FLAG_ZERO_COPY, etc.)
 *
 * Returns: Request ID (> 0) on success, 0 on failure
 * Raises: SocketAsync_Failed if submission fails
 *
 * @note Thread-safe: Yes - uses internal mutex for request tracking
 * @ingroup core_io
 *
 * Note: Operation is submitted immediately. Completion will be delivered
 * via callback when data is sent (or error occurs). Callback is invoked
 * from SocketPoll_wait() context - keep it fast!
 *
 * Partial sends: If only part of data is sent, callback is called with
 * partial byte count. Use SocketAsync_send_continue() to send remainder.
 *
 * Fallback mode: If async I/O is unavailable (SocketAsync_is_available() ==
 * 0), the request is queued but not submitted to kernel. Application must
 * complete the operation manually using regular Socket_send()/Socket_recv()
 * and then invoke the callback. Check SocketAsync_is_available() to determine
 * mode.
 */
extern unsigned SocketAsync_send (T async, Socket_T socket, const void *buf,
                                  size_t len, SocketAsync_Callback cb,
                                  void *user_data, SocketAsync_Flags flags);

/**
 * @brief SocketAsync_recv - Submit asynchronous receive operation
 * @ingroup core_io
 * @async: Async context (from SocketPoll_get_async)
 * @socket: Socket to receive on (must be non-blocking)
 * @buf: Buffer to receive into (must remain valid until callback invoked)
 * @len: Maximum length to receive
 * @cb: Callback to call on completion
 * @user_data: User data passed to callback
 * @flags: Operation flags (currently unused)
 *
 * Returns: Request ID (> 0) on success, 0 on failure
 * Raises: SocketAsync_Failed if submission fails
 *
 * @note Thread-safe: Yes
 * @ingroup core_io
 *
 * Note: Callback receives bytes received (0 = EOF, < 0 = error).
 * Buffer must remain valid until callback is invoked.
 */
extern unsigned SocketAsync_recv (T async, Socket_T socket, void *buf,
                                  size_t len, SocketAsync_Callback cb,
                                  void *user_data, SocketAsync_Flags flags);

/**
 * @brief SocketAsync_cancel - Cancel pending async operation
 * @ingroup core_io
 * @async: Async context
 * @request_id: Request ID returned from send/recv
 *
 * Returns: 0 on success, -1 if request not found or already completed
 *
 * @note Thread-safe: Yes
 * @ingroup core_io
 *
 * Note: Cancellation is best-effort. Operation may complete before
 * cancellation takes effect.
 */
extern int SocketAsync_cancel (T async, unsigned request_id);

/**
 * @brief SocketAsync_process_completions - Process pending async completions
 * @ingroup core_io
 * @async: Async context
 * @timeout_ms: Timeout in milliseconds (0 = non-blocking)
 *
 * Returns: Number of completions processed
 *
 * @note Thread-safe: Yes - uses internal mutex
 * @ingroup core_io
 *
 * Note: This is called automatically by SocketPoll_wait(). Applications
 * typically don't need to call this directly.
 */
extern int SocketAsync_process_completions (T async, int timeout_ms);

/**
 * @brief SocketAsync_is_available - Check if async I/O is available on this platform
 * @ingroup core_io
 * @async: Async context (read-only)
 *
 * Returns: Non-zero if async I/O is available, 0 if fallback mode
 *
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern int SocketAsync_is_available (const T async);

/**
 * @brief SocketAsync_backend_name - Get name of async backend in use
 * @ingroup core_io
 * @async: Async context (read-only)
 *
 * Returns: String describing backend ("io_uring", "kqueue", "edge-triggered")
 *
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern const char *SocketAsync_backend_name (const T async);

#undef T
#endif

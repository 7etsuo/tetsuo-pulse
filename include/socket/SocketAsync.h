#ifndef SOCKETASYNC_INCLUDED
#define SOCKETASYNC_INCLUDED

#include "core/Except.h"
#include "socket/Socket.h"

/**
 * SocketAsync - Asynchronous I/O Operations
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
 * PLATFORM REQUIREMENTS:
 * - Linux: kernel 5.1+ for io_uring (falls back to edge-triggered if
 * unavailable)
 * - macOS/BSD: kqueue with AIO support
 * - All platforms: Non-blocking sockets (automatically handled)
 *
 * Usage example:
 *   SocketPoll_T poll = SocketPoll_new(4096);
 *   SocketAsync_T async = SocketPoll_get_async(poll);
 *
 *   void send_callback(Socket_T sock, ssize_t bytes, int err, void *data) {
 *       if (err != 0) {
 *           // Handle error
 *           return;
 *       }
 *       // Process completion
 *   }
 *
 *   unsigned req_id = SocketAsync_send(sock, buf, len, send_callback,
 * user_data, 0);
 */

#define T SocketAsync_T
typedef struct T *T;

/* Exception types */
extern const Except_T SocketAsync_Failed; /**< Async operation failure */

/**
 * SocketAsync_Callback - Callback function for async operation completion
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
 * Thread-safe: Yes - invoked from single-threaded poll context
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
 * SocketAsync_new - Create a new async I/O context
 * @arena: Arena for memory allocation
 * Returns: New async context (never returns NULL)
 * Raises: SocketAsync_Failed on initialization failure
 * Thread-safe: Yes - returns new instance
 *
 * Creates an async context with platform-specific backend initialization.
 * Falls back gracefully if async I/O is unavailable on this platform.
 */
extern T SocketAsync_new (Arena_T arena);

/**
 * SocketAsync_free - Free an async I/O context
 * @async: Pointer to async context (will be set to NULL)
 * Thread-safe: Yes - frees resources
 */
extern void SocketAsync_free (T *async);

/**
 * SocketAsync_send - Submit asynchronous send operation
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
 * Thread-safe: Yes - uses internal mutex for request tracking
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
 * SocketAsync_recv - Submit asynchronous receive operation
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
 * Thread-safe: Yes
 *
 * Note: Callback receives bytes received (0 = EOF, < 0 = error).
 * Buffer must remain valid until callback is invoked.
 */
extern unsigned SocketAsync_recv (T async, Socket_T socket, void *buf,
                                  size_t len, SocketAsync_Callback cb,
                                  void *user_data, SocketAsync_Flags flags);

/**
 * SocketAsync_cancel - Cancel pending async operation
 * @async: Async context
 * @request_id: Request ID returned from send/recv
 *
 * Returns: 0 on success, -1 if request not found or already completed
 *
 * Thread-safe: Yes
 *
 * Note: Cancellation is best-effort. Operation may complete before
 * cancellation takes effect.
 */
extern int SocketAsync_cancel (T async, unsigned request_id);

/**
 * SocketAsync_process_completions - Process pending async completions
 * @async: Async context
 * @timeout_ms: Timeout in milliseconds (0 = non-blocking)
 *
 * Returns: Number of completions processed
 *
 * Thread-safe: Yes - uses internal mutex
 *
 * Note: This is called automatically by SocketPoll_wait(). Applications
 * typically don't need to call this directly.
 */
extern int SocketAsync_process_completions (T async, int timeout_ms);

/**
 * SocketAsync_is_available - Check if async I/O is available on this platform
 * @async: Async context (read-only)
 *
 * Returns: Non-zero if async I/O is available, 0 if fallback mode
 *
 * Thread-safe: Yes
 */
extern int SocketAsync_is_available (const T async);

/**
 * SocketAsync_backend_name - Get name of async backend in use
 * @async: Async context (read-only)
 *
 * Returns: String describing backend ("io_uring", "kqueue", "edge-triggered")
 *
 * Thread-safe: Yes
 */
extern const char *SocketAsync_backend_name (const T async);

#undef T
#endif

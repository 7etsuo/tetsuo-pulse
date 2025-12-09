/**
 * @defgroup async_io Async I/O Modules
 * @brief Advanced asynchronous I/O and connection establishment patterns for high-performance networking.
 * @{
 * Key components:
 * - @ref SocketAsync_T: Platform-optimized async send/recv (io_uring, kqueue, fallback)
 * - @ref SocketHappyEyeballs: RFC 8305 Happy Eyeballs for fast dual-stack (IPv6/IPv4) connections
 *
 * These modules enable non-blocking, scalable I/O suitable for servers handling thousands of connections.
 * They integrate seamlessly with the event_system for completion notifications.
 *
 * Dependencies: Requires core_io primitives and event_system for full functionality.
 *
 * @see @ref core_io "Core I/O" for basic sockets (Socket_T).
 * @see @ref event_system "Event System" for SocketPoll integration.
 * @see @ref connection_mgmt "Connection Mgmt" for pooling async sockets.
 * @see @ref http "HTTP" modules for async HTTP/2 streams.
 * @see docs/ASYNC_IO.md for usage examples and performance tuning.
 */
/* Happy Eyeballs module documentation updated and grouped under async_io. See include/socket/SocketHappyEyeballs.h */

#ifndef SOCKETASYNC_INCLUDED
#define SOCKETASYNC_INCLUDED

#include "core/Except.h"
#include "socket/Socket.h"

/**
 * @file SocketAsync.h
 * @ingroup async_io
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
/**
 * @brief Opaque type representing the asynchronous I/O context.
 * @ingroup async_io
 *
 * Manages the lifecycle of async operations, including submission to platform
 * backends (io_uring, kqueue, fallback) and completion notification via callbacks.
 * Supports zero-copy and priority flags where available.
 *
 * Thread-safe for concurrent submissions and processing, with internal locking.
 * Callbacks are serialized in the poll context.
 *
 * @see SocketAsync_new() to create.
 * @see SocketAsync_free() to destroy.
 * @see SocketPoll_get_async() alternative for poll integration.
 */
typedef struct T *T;

/* Exception types */
/**
 * @brief Exception raised on asynchronous I/O operation failures.
 * @ingroup async_io
 *
 * Thrown when:
 * - Backend initialization fails (io_uring setup, kqueue errors)
 * - Request submission fails (queue full, invalid params)
 * - Internal state corruption or resource exhaustion
 * - Platform-specific async errors (e.g., io_uring ring corruption)
 *
 * @see @ref error-handling.mdc for TRY/EXCEPT patterns.
 * @see SocketAsync_new() which may throw on init failure.
 * @see SocketAsync_send()/recv() which may throw on submit failure.
 */
extern const Except_T SocketAsync_Failed;

/**
 * @brief Completion callback type for asynchronous I/O operations.
 * @ingroup async_io
 * @param socket Socket_T that completed the operation.
 * @param bytes ssize_t bytes transferred (<0 on error, 0=EOF for recv, partial possible).
 * @param err int error code (0 success, errno on failure, check Socket_geterrorcode()).
 * @param user_data void* user-provided data from submit call.
 * @threadsafe Conditional - invoked from SocketPoll_wait() thread context.
 *
 * Invoked upon operation completion (success or failure). For partial transfers,
 * application may resubmit remaining data. Keep callback fast to avoid blocking
 * event loop.
 *
 * Error handling: bytes < 0 signals error, use err for details. Common errors:
 * - EAGAIN/ EWOULDBLOCK: Temporary, retry possible
 * - ECONNRESET/ ECONNREFUSED: Connection issues
 * - ENOMEM: Resource exhaustion
 *
 * Integration: Typically invoked during SocketPoll_wait() processing, single-threaded.
 *
 * @note For fallback mode (no native async), callback still used but app must drive I/O.
 * @see SocketAsync_send() / SocketAsync_recv() for submission with this callback.
 * @see SocketAsync_Callback in context of @ref SocketPoll_T event loop.
 * @see docs/ASYNC_IO.md "Callback Best Practices" for performance tips.
 */
typedef void (*SocketAsync_Callback) (Socket_T socket, ssize_t bytes, int err,
                                      void *user_data);

/**
 * @brief Enumeration of flags controlling asynchronous I/O operation options.
 * @ingroup async_io
 *
 * These flags modify operation behavior, such as enabling zero-copy or priority.
 * Flags are bitwise OR'ed and passed to SocketAsync_send() or SocketAsync_recv().
 * Unsupported flags are ignored, with fallback to standard behavior.
 *
 * Backend support varies: e.g., zero-copy requires kernel capabilities and proper
 * socket configuration (e.g., TCP_NODELAY off for some opts).
 *
 * @see SocketAsync_send()
 * @see SocketAsync_recv()
 * @see SocketAsync_is_available()
 * @see docs/ASYNC_IO.md for backend-specific flag support.
 */
typedef enum {
  ASYNC_FLAG_NONE = 0, /**< Default operation with no special features enabled. */

  /**
   * @brief Request zero-copy I/O to minimize data copying.
   *
   * Utilizes efficient kernel mechanisms to send/receive without unnecessary
   * user-space copies. Examples:
   * - Linux io_uring: IORING_OP_SEND_ZC / IORING_OP_RECV_ZC
   * - sendfile(2) or splice(2) for file/socket transfers
   *
   * Fallback to conventional buffered I/O if not supported (small data, opts).
   * @note Best for large payloads; small data may incur overhead. Requires
   * compatible socket (TCP) and system calls.
   */
  ASYNC_FLAG_ZERO_COPY = 1 << 0,

  /**
   * @brief Mark operation for urgent or linked processing.
   *
   * Optimizes for low latency by prioritizing or chaining the operation:
   * - io_uring: IOSQE_IO_LINK or IOSQE_IO_URING_LINK for sequencing
   * - Other: May use high-priority queues or immediate dispatch
   *
   * Suitable for time-critical small messages (e.g., ACKs, probes) in high-throughput
   * scenarios.
   * @note Semantics backend-dependent; may be noop if unsupported.
   */
  ASYNC_FLAG_URGENT = 1 << 1
} SocketAsync_Flags;

/**
 * @brief Create a new standalone asynchronous I/O context.
 * @ingroup async_io
 * @param arena Arena_T for internal memory allocations.
 * @return New SocketAsync_T instance (never NULL on success).
 * @throws SocketAsync_Failed if backend initialization fails (e.g., io_uring setup).
 * @threadsafe Yes - individual contexts are thread-safe for submission/processing.
 *
 * Initializes platform-specific async backend (io_uring on Linux, kqueue AIO on BSD/macOS,
 * or fallback polling). Standalone contexts can be used without SocketPoll but require
 * manual SocketAsync_process_completions() calls for completion handling.
 *
 * @note Preferred method is SocketPoll_get_async() for integrated event loop usage.
 * @see SocketPoll_get_async() for poll-integrated async interface (recommended).
 * @see SocketAsync_free() for cleanup.
 * @see SocketAsync_is_available() to check backend capabilities post-creation.
 * @see docs/ASYNC_IO.md for backend-specific details and fallback behavior.
 */
extern T SocketAsync_new (Arena_T arena);

/**
 * @brief Release resources associated with an async I/O context.
 * @ingroup async_io
 * @param async Pointer to SocketAsync_T (set to NULL on success).
 * @threadsafe Yes - safe to call from any thread, cancels pending operations.
 *
 * Frees backend resources (io_uring ring, kqueue, etc.) and cancels any pending
 * requests. Callbacks for cancelled operations may still be invoked with error.
 * Safe to call with NULL pointer.
 *
 * @see SocketAsync_new() for creation.
 * @see SocketAsync_cancel() for explicit pending operation cancellation.
 * @see SocketPoll_get_async() if context obtained from poll (poll manages lifetime).
 */
extern void SocketAsync_free (T *async);

/**
 * @brief Submit asynchronous send operation.
 * @ingroup async_io
 * @param async Async context (from SocketPoll_get_async).
 * @param socket Socket to send on (must be non-blocking).
 * @param buf Data to send.
 * @param len Length of data to send.
 * @param cb Callback to call on completion.
 * @param user_data User data passed to callback.
 * @param flags Operation flags (ASYNC_FLAG_ZERO_COPY, etc.).
 * @return Request ID (> 0) on success, 0 on failure.
 * @throws SocketAsync_Failed if submission fails.
 * @note Thread-safe: Yes - uses internal mutex for request tracking.
 *
 * Operation is submitted immediately. Completion will be delivered
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
 *
 * @see SocketAsync_recv() for asynchronous receive operations.
 * @see SocketAsync_cancel() for canceling pending operations.
 * @see SocketPoll_wait() for processing completions.
 */
extern unsigned SocketAsync_send (T async, Socket_T socket, const void *buf,
                                  size_t len, SocketAsync_Callback cb,
                                  void *user_data, SocketAsync_Flags flags);

/**
 * @brief Submit asynchronous receive operation.
 * @ingroup async_io
 * @param async Async context (from SocketPoll_get_async).
 * @param socket Socket to receive on (must be non-blocking).
 * @param buf Buffer to receive into (must remain valid until callback invoked).
 * @param len Maximum length to receive.
 * @param cb Callback to call on completion.
 * @param user_data User data passed to callback.
 * @param flags Operation flags (currently unused).
 * @return Request ID (> 0) on success, 0 on failure.
 * @throws SocketAsync_Failed if submission fails.
 * @note Thread-safe: Yes.
 *
 * Callback receives bytes received (0 = EOF, < 0 = error).
 * Buffer must remain valid until callback is invoked.
 *
 * @see SocketAsync_send() for asynchronous send operations.
 * @see SocketAsync_cancel() for canceling pending operations.
 * @see SocketPoll_wait() for processing completions.
 */
extern unsigned SocketAsync_recv (T async, Socket_T socket, void *buf,
                                  size_t len, SocketAsync_Callback cb,
                                  void *user_data, SocketAsync_Flags flags);

/**
 * @brief Cancel pending async operation.
 * @ingroup async_io
 * @param async Async context.
 * @param request_id Request ID returned from send/recv.
 * @return 0 on success, -1 if request not found or already completed.
 * @note Thread-safe: Yes.
 *
 * Cancellation is best-effort. Operation may complete before
 * cancellation takes effect.
 *
 * @see SocketAsync_send() for submitting operations.
 * @see SocketAsync_recv() for receiving operations.
 */
extern int SocketAsync_cancel (T async, unsigned request_id);

/**
 * @brief Process pending async completions.
 * @ingroup async_io
 * @param async Async context.
 * @param timeout_ms Timeout in milliseconds (0 = non-blocking).
 * @return Number of completions processed.
 * @note Thread-safe: Yes - uses internal mutex.
 *
 * This is called automatically by SocketPoll_wait(). Applications
 * typically don't need to call this directly.
 *
 * @see SocketPoll_wait() for automatic completion processing.
 * @see SocketAsync_send() for submitting operations.
 */
extern int SocketAsync_process_completions (T async, int timeout_ms);

/**
 * @brief Check if async I/O is available on this platform.
 * @ingroup async_io
 * @param async Async context (read-only).
 * @return Non-zero if async I/O is available, 0 if fallback mode.
 * @note Thread-safe: Yes.
 * @see SocketAsync_backend_name() for getting the backend name.
 */
extern int SocketAsync_is_available (const T async);

/**
 * @brief Get name of async backend in use.
 * @ingroup async_io
 * @param async Async context (read-only).
 * @return String describing backend ("io_uring", "kqueue", "edge-triggered").
 * @note Thread-safe: Yes.
 * @see SocketAsync_is_available() for checking availability.
 */
extern const char *SocketAsync_backend_name (const T async);

#undef T

/** @} */ /* end of async_io group */

#endif

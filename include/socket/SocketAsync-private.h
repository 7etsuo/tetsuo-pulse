/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETASYNC_PRIVATE_H_INCLUDED
#define SOCKETASYNC_PRIVATE_H_INCLUDED

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "socket/Socket.h"
#include "socket/SocketAsync.h"

/**
 * @file SocketAsync-private.h
 * @brief Private internal definitions for the SocketAsync module.
 *
 * Contains opaque structure definitions for asynchronous I/O context and
 * request tracking. Included only by implementation files (e.g.,
 * SocketAsync.c). Not for public use or direct inclusion.
 *
 * @internal
 * @ingroup async_io
 * @{
 *
 * @see SocketAsync.h for public interface.
 * @see docs/ASYNC_IO.md for module overview.
 */

/**
 * @brief Internal structure for tracking asynchronous I/O requests.
 * @internal
 * @ingroup async_io
 *
 * Manages state of pending async send/recv operations submitted via public
 * API. Tracks metadata, buffers, progress for partial operations, callbacks,
 * and hash linking.
 *
 * Supports:
 * - Request identification and cancellation by ID
 * - Buffer lifetime management until completion
 * - Partial transfer progress tracking (completed bytes)
 * - Timeout monitoring via submission timestamp
 * - Thread-safe hash table storage and lookup
 *
 * @threadsafe No - direct access unsafe without external synchronization.
 * Access serialized exclusively by parent SocketAsync_T::mutex.
 *
 * @note
 * - Buffers (send_buf for REQ_SEND, recv_buf for REQ_RECV) must remain
 * pinned/valid until callback invocation, cancellation, or explicit removal.
 * - For sensitive data (e.g., keys, tokens), use SocketBuf_secureclear()
 * post-completion.
 * - In fallback mode, buffers may be accessed synchronously during
 * process_completions().
 *
 *  Lifecycle Management
 *
 * Typical flow for a request:
 * 1. **Allocation**: CALLOC from arena in socket_async_allocate_request()
 * 2. **Initialization**: Populate fields, generate unique request_id
 * 3. **Insertion**: Hashed into SocketAsync_T::requests[] via request_hash()
 * 4. **Submission**: Backend prepares (e.g., io_uring sqe setup)
 * 5. **Completion/Cancellation**:
 *    - find_and_remove_request() extracts from hash chain
 *    - Callback invoked with results
 *    - socket_async_free_request() clears for arena reuse
 *
 *  Partial Transfer Support
 *
 * Enables handling of large or interrupted transfers:
 * - completed accumulates bytes across multiple backend invocations
 * - Remaining data: send_buf + completed, length (len - completed)
 * - Library can resubmit automatically in future enhancements
 * - App can use SocketAsync_send_continue() (planned) for seamless remainder
 * handling
 *
 * @code{.c}
 * // Example partial handling in callback
 * void partial_cb(Socket_T sock, ssize_t bytes, int err, void *ud) {
 *   AsyncRequest *req = (AsyncRequest*)ud; // If passed req as user_data
 *   if (err == 0 && bytes > 0) {
 *     req->completed += bytes;
 *     if (req->completed < req->len) {
 *       // Resubmit remainder: buf + completed, len - completed
 *       SocketAsync_send_continue(async, req->request_id);
 *     }
 *   }
 * }
 * @endcode
 *
 *  Timeout Integration
 *
 * submitted_at enables per-request timeouts:
 * @code{.c}
 * int64_t now = Socket_get_monotonic_ms();
 * int64_t age_ms = now - req->submitted_at;
 * if (age_ms > REQUEST_TIMEOUT_MS) {
 *   // Cancel or mark as failed
 *   SocketAsync_cancel(async, req->request_id);
 * }
 * @endcode
 *
 * @complexity
 * - Allocation: O(1) arena alloc
 * - Hash operations: O(1) avg, O(n) worst (collisions)
 * - Lookup/removal: Same as hash
 *
 * @warning
 * - Never free buffers externally while request pending - leads to segfaults
 * or data corruption
 * - In multi-threaded env, only access via protected methods (no direct field
 * manipulation)
 * - Fallback mode may invoke callback synchronously during submit if immediate
 * completion
 *
 * @see SocketAsync_T parent context managing this request
 * @see SocketAsync_Callback invoked on completion/cancel
 * @see SocketAsync_Flags controlling backend behavior
 * @see docs/ASYNC_IO.md#partial-operations for advanced patterns
 * @see socket_async_allocate_request() / socket_async_free_request() internal
 * helpers
 * @see handle_completion() for processing logic
 */
struct AsyncRequest
{
  /**
   * @brief Unique request identifier.
   *
   * Assigned sequentially by SocketAsync_new_request_id().
   * Used for cancellation via SocketAsync_cancel() and internal hashing.
   * 0 is invalid.
   */
  unsigned request_id;

  /**
   * @brief Socket associated with this request.
   *
   * The target socket for the I/O operation. Must remain valid until
   * completion.
   * @see Socket_T
   */
  Socket_T socket;

  /**
   * @brief Completion callback function.
   *
   * Invoked upon operation completion or error, from poll context.
   * @see SocketAsync_Callback
   */
  SocketAsync_Callback cb;

  /**
   * @brief User data passed to the callback.
   *
   * Opaque data provided by caller, forwarded unchanged to cb().
   */
  void *user_data;

  /**
   * @brief Type of asynchronous operation.
   *
   * Distinguishes between send and recv requests for backend-specific
   * handling.
   */
  enum AsyncRequestType
  {
    /**
     * @brief Send operation (SocketAsync_send).
     */
    REQ_SEND,
    /**
     * @brief Receive operation (SocketAsync_recv).
     */
    REQ_RECV
  } type;

  /**
   * @brief Input buffer for send operations.
   *
   * Pointer to data to send (REQ_SEND only). Must remain valid and unmodified
   * until callback.
   * @note For zero-copy modes, this may reference file mappings or other
   * kernel-accessible memory.
   */
  const void *send_buf; /* For send: data to send */

  /**
   * @brief Output buffer for recv operations.
   *
   * Buffer to receive data into (REQ_RECV only). Must remain valid until
   * callback invocation. Data is written here by kernel or driver.
   * @warning Do not access or free until callback completes the request.
   */
  void *recv_buf; /* For recv: user's buffer (must remain valid) */

  /**
   * @brief Original requested transfer length.
   *
   * Total bytes to send/recv as submitted by caller.
   * Used to track partial completions.
   */
  size_t len; /* Original length */

  /**
   * @brief Bytes transferred so far in this request.
   *
   * Initialized to 0 at submission. Updated after partial completion with the
   * number of bytes transferred in that invocation. Allows calculation of
   * remaining bytes: len - completed.
   *
   * Supports resubmission of remaining data for large transfers or when
   * backend reports partial results (e.g., io_uring CQE res < requested).
   *
   * @note Enables future SocketAsync_send_continue() and
   * SocketAsync_recv_continue() for automatic handling without application
   * offset tracking.
   * @see SocketAsync_send_continue() (planned)
   */
  size_t completed; /* Bytes completed so far */

  /**
   * @brief Monotonic timestamp of request submission (milliseconds).
   *
   * Set to Socket_get_monotonic_ms() upon successful submission to backend.
   * Used for:
   * - Timeout detection in process_completions()
   * - Operation age statistics
   * - Stale request cleanup
   *
   * 0 indicates not yet submitted or cancelled.
   *
   * @note Integrates with SocketTimeout utilities for deadline calculations.
   * @see Socket_get_monotonic_ms()
   * @see SocketTimeout_remaining_ms()
   */
  int64_t submitted_at; /* Submission time (ms, monotonic) */

  /**
   * @brief Operation flags.
   *
   * Controls backend behavior (e.g., zero-copy, priority).
   * @see SocketAsync_Flags
   */
  SocketAsync_Flags flags;

  /**
   * @brief Pointer to next request in hash chain.
   *
   * For collision resolution in requests[] hash table.
   * @see request_hash()
   */
  struct AsyncRequest *next; /* Hash table chain */
};

/**
 * @brief Core structure for asynchronous I/O context management.
 * @internal
 * @ingroup async_io
 *
 * Central opaque type managing all async operations: backend initialization,
 * request submission/tracking, completion processing, and thread safety.
 *
 * Key responsibilities:
 * - Platform backend lifecycle (io_uring ring setup, kqueue fd monitoring)
 * - Request hash table for O(1) lookups and cancellations
 * - Mutex-protected concurrent access from multiple threads
 * - Availability detection and fallback to simulated async
 * - Completion queue draining and callback dispatching
 *
 * @threadsafe Yes - all public methods (send/recv/cancel/process) acquire
 * mutex. Internal state modifications serialized. Callbacks invoked under lock
 * but expected to be fast (no long operations). Backend-specific thread safety
 * varies (io_uring is lock-free post-setup).
 *
 * @note
 * - Created via SocketAsync_new() or SocketPoll_get_async() (preferred for
 * integration)
 * - Freed via SocketAsync_free() - cancels pending ops, drains queue
 * - In fallback mode (available==0), simulates async via edge-triggered poll
 * events
 * - Arena used for all internal allocs; dispose parent arena after free()
 *
 *  Component Breakdown
 *
 * # Request Management
 * - requests[]: Fixed-size hash table (SOCKET_HASH_TABLE_SIZE buckets)
 * - next_request_id: Atomic counter for uniqueness (skips 0)
 * - mutex: pthread_mutex_t protecting table and ID gen
 *
 * # Backend Integration
 * - Conditional fields based on platform:
 *   - io_uring: ring for SQ/CQ, eventfd for notifications
 *   - kqueue: fd for AIO kevents
 *   - Fallback: flag for poll-based simulation
 * - available: 1 if native async supported/initialized, 0 for fallback
 * - backend_name: Static string ID ("io_uring", "kqueue AIO",
 * "edge-triggered")
 *
 *  Integration Patterns
 *
 * # With SocketPoll (Recommended)
 * @code{.c}
 * SocketPoll_T poll = SocketPoll_new(max_events);
 * SocketAsync_T async = SocketPoll_get_async(poll); // Shared context
 *
 * // Submit requests...
 * unsigned id = SocketAsync_send(async, sock, buf, len, cb, data, flags);
 *
 * // Poll processes completions automatically
 * SocketPoll_wait(poll, &events, timeout);
 * @endcode
 *
 * # Standalone Usage
 * @code{.c}
 * Arena_T arena = Arena_new();
 * SocketAsync_T async = SocketAsync_new(arena);
 *
 * // Manual completion processing
 * while (running) {
 *   int completed = SocketAsync_process_completions(async, 10); // 10ms
 * timeout
 *   // Handle other logic
 * }
 *
 * SocketAsync_free(&async);
 * Arena_dispose(&arena);
 * @endcode
 *
 *  Backend-Specific Notes
 *
 * # io_uring (Linux)
 * - High performance, zero-copy support via flags
 * - Batch submission/completion for throughput
 * - Eventfd polled internally or via SocketPoll integration
 *
 * # kqueue AIO (BSD/macOS)
 * - Uses kevent with EVFILT_AIO for completion events
 * - Limited zero-copy; synchronous I/O on event trigger
 *
 * # Fallback Mode
 * - Tracks requests but performs I/O synchronously in process_completions()
 * - Emulates async via non-blocking sockets + edge-triggered events
 * - Gradual migration path for unsupported platforms
 *
 * @complexity
 * - new/free: O(1) backend init + mutex setup
 * - send/recv: O(1) hash insert + backend submit
 * - cancel: O(1) avg hash lookup + removal
 * - process_completions: O(n) where n=completions drained
 *
 * @warning
 * - Do not free arena while context active - leads to use-after-free
 * - Callbacks must not block or perform I/O that deadlocks mutex
 * - Backend fds (io_uring_fd, kqueue_fd) must not be closed externally
 * - In multi-threaded use, avoid submitting from callback (potential
 * reentrancy)
 *
 * @see AsyncRequest tracked requests
 * @see SocketAsync_new() / SocketAsync_free() lifecycle
 * @see SocketPoll_get_async() for poll integration
 * @see SocketAsync_is_available() / backend_name() status queries
 * @see docs/ASYNC_IO.md full guide with benchmarks
 * @see src/socket/SocketAsync.c implementation details
 */
struct SocketAsync_T
{
  /**
   * @brief Memory arena for internal allocations.
   *
   * Used for allocating AsyncRequest structures and other transient data.
   * Lifetime tied to context; cleared on free().
   * @see Arena_T
   */
  Arena_T arena;

  /**
   * @brief Hash table for fast request lookup by ID.
   *
   * Array of chains for O(1) average-case retrieval of pending requests.
   * Indexed by request_hash(request_id).
   * @see SOCKET_HASH_TABLE_SIZE
   * @see request_hash()
   */
  /* Request tracking */
  struct AsyncRequest *requests[SOCKET_HASH_TABLE_SIZE];

  /**
   * @brief Counter for generating unique request IDs.
   *
   * Incremented atomically under mutex to assign request_id.
   * Wraps around but skips 0.
   */
  unsigned next_request_id;

  /**
   * @brief Mutex protecting request table and ID generation.
   *
   * Ensures thread-safe submission, cancellation, and completion processing.
   * @note Recursive mutex not used; avoid reentrancy in callbacks.
   */
  pthread_mutex_t mutex;

  /**
   * @brief Platform-specific asynchronous I/O backend context.
   *
   * Conditional compilation selects appropriate fields:
   * - Linux io_uring: ring and eventfd for submission/completion queue.
   * - BSD/macOS: kqueue_fd for AIO event monitoring.
   * - Fallback: fallback_mode flag for edge-triggered polling simulation.
   *
   * Initialized in SocketAsync_new(), detecting available backend.
   * @see SocketAsync_is_available()
   * @see SocketAsync_backend_name()
   */
  /* Platform-specific async context */
#ifdef SOCKET_HAS_IO_URING
  /**
   * @brief io_uring instance for kernel async I/O.
   *
   * Submission and completion queue ring for efficient batch operations.
   * Supports zero-copy, multi-shot accepts, and linked requests.
   * @see liburing.h
   */
  struct io_uring *ring; /* io_uring ring (if available) */

  /**
   * @brief Eventfd for io_uring completion notifications.
   *
   * Polled via SocketPoll to detect when to drain completion queue.
   * @see eventfd(2)
   */
  int io_uring_fd; /* Eventfd for completion notifications */
#elif defined(__APPLE__) || defined(__FreeBSD__)
  /**
   * @brief kqueue file descriptor for AIO events.
   *
   * Monitors AIO completion events from kernel.
   * @see kqueue(2), kevent(2)
   */
  int kqueue_fd; /* kqueue fd for AIO */
#else
  /**
   * @brief Fallback mode flag for non-async platforms.
   *
   * Indicates edge-triggered polling simulation using SocketPoll.
   * Requests are tracked but I/O performed synchronously in
   * process_completions().
   */
  /* Fallback: edge-triggered polling */
  int fallback_mode;
#endif

  /**
   * @brief Availability flag for async backend.
   *
   * Non-zero if platform-optimized async I/O is supported and initialized.
   * Zero indicates fallback to simulated async via polling.
   * @see SocketAsync_is_available()
   */
  int available; /* Non-zero if async available */

  /**
   * @brief String identifier of the active backend.
   *
   * E.g., "io_uring", "kqueue", "edge-triggered". Read-only after init.
   * @see SocketAsync_backend_name()
   */
  const char *backend_name;
};

/** @} */ /* end of async_io private definitions */

/*
 * Note: This private header should be included in SocketAsync.c after public
 * headers to access internal structures. Public headers forward-declare types
 * only.
 */

#endif /* SOCKETASYNC_PRIVATE_H_INCLUDED */

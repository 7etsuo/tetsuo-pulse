/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @defgroup async_io Async I/O Modules
 * @brief Asynchronous I/O and dual-stack connection racing for scalable,
 * performant networking.
 * @{
 *
 * Enables high-concurrency servers and clients with non-blocking I/O and fast
 * connection establishment. Core focus on platform-optimized async primitives
 * and RFC-compliant dual-stack resolution (Happy Eyeballs).
 *
 * ## Key Components
 *
 * - **SocketAsync**: Async send/recv with callbacks, zero-copy,
 * backend-agnostic
 * - **SocketHappyEyeballs**: Parallel IPv6/IPv4 connection attempts per RFC
 * 8305
 *
 * ## Architecture Overview
 *
 * ```
 * ┌─────────────────────────────────────┐
 * │         Application Layer           │
 * │ HTTP/2 Streams, WS, Custom Protocols│
 * └─────────────────────┬───────────────┘
 *                       │ Uses
 * ┌─────────────────────▼───────────────┐
 * │        Async I/O Layer              │
 * │ SocketAsync_T + HappyEyeballs_T     │
 * │ Callbacks, Flags, Backends          │
 * └─────────────────────┬───────────────┘
 *                       │ Integrates
 * ┌─────────────────────▼───────────────┐
 * │      Event System Layer             │
 * │      SocketPoll + Timers            │
 * └─────────────────────┬───────────────┘
 *                       │ Depends on
 * ┌─────────────────────▼───────────────┐
 * │        Core I/O Layer               │
 * │     Socket_T, DNS, Buffers          │
 * └─────────────────────────────────────┘
 * ```
 *
 * ## Module Relationships
 *
 * - **Depends on**: @ref core_io (sockets), @ref event_system
 * (polling/timers), @ref foundation (arena/except)
 * - **Used by**: @ref connection_mgmt (async pools), @ref http (HTTP/2
 * streams), @ref utilities (rate-limit compat)
 * - **Threading**: Safe for multi-thread submit/process, callbacks
 * single-threaded per context
 *
 * Ideal for 10K+ connections, reducing latency by 50-90% vs synchronous I/O.
 *
 * @see SocketAsync_T - Main async context.
 * @see SocketHappyEyeballs_T - Dual-stack connector.
 * @see @ref core_io "Core I/O Modules" - Socket primitives.
 * @see @ref event_system "Event System" - Integration point.
 * @see docs/ASYNC_IO.md - Usage, backends, benchmarks.
 * @see docs/cross-platform-backends.md - Backend details.
 */

#ifndef SOCKETASYNC_INCLUDED
#define SOCKETASYNC_INCLUDED

#include "core/Except.h"
#include "socket/Socket.h"

/**
 * @file SocketAsync.h
 * @ingroup async_io
 * @brief Platform-optimized asynchronous I/O for high-performance networking.
 *
 * This header defines the SocketAsync API for submitting non-blocking
 * send/recv operations to kernel or user-space async mechanisms, with callback
 * completion. Enables scalable I/O without busy-waiting or
 * thread-per-connection models.
 *
 * ## Features
 *
 * - **Native Backends**: io_uring (Linux), kqueue AIO (BSD/macOS), poll
 * fallback
 * - **Zero-Copy Support**: Minimize copies for large transfers where possible
 * - **Flags for Optimization**: Urgent ops, linking for low-latency
 * - **Seamless Integration**: With SocketPoll for event-driven apps
 * - **Thread-Safe**: Concurrent submissions and processing
 * - **Fallback Graceful**: Transparent degradation on unsupported platforms
 *
 * ## Platform Support
 *
 * | Platform | Backend | Full Async | Zero-Copy | Notes |
 * |----------|---------|------------|-----------|-------|
 * | Linux 5.1+ | io_uring | Yes | Yes | Requires liburing-dev |
 * | macOS/FreeBSD | kqueue | Partial (edge) | No | AIO limited |
 * | Other POSIX | poll/epoll | No (fallback) | No | Manual I/O in events |
 *
 * All backends require non-blocking sockets (auto-set). SIGPIPE handled
 * internally.
 *
 * Typical usage: Obtain via SocketPoll_get_async() for event loops, or
 * standalone SocketAsync_new() for custom loops. Submit ops, process
 * completions via poll or manual.
 *
 * @see @ref async_io "Async I/O Modules" - Group overview including Happy
 * Eyeballs integration.
 * @see SocketAsync_T - Opaque context type.
 * @see SocketAsync_new() - Standalone creation.
 * @see SocketPoll_get_async() - Recommended poll integration.
 * @see SocketAsync_Flags - Operation modifiers.
 * @see docs/ASYNC_IO.md - Complete guide, examples, benchmarks.
 */

#define T SocketAsync_T
/**
 * @brief Opaque handle for asynchronous I/O context and operations.
 * @ingroup async_io
 *
 * Encapsulates platform-specific async I/O state, request queues, backend
 * resources (e.g., io_uring ring fd, kqueue), and completion tracking. Opaque
 * design hides implementation details, ensuring portability across backends.
 *
 * Key responsibilities:
 * - Submit send/recv requests with optional flags (zero-copy, urgent)
 * - Track pending/completed ops via IDs
 * - Deliver completions via callbacks (serialized)
 * - Handle fallback to manual I/O when native async unavailable
 *
 * ## Lifecycle Management
 *
 * 1. **Creation**: Via SocketAsync_new(arena) for standalone or
 * SocketPoll_get_async(poll) for integrated
 * 2. **Usage**: Submit ops, process completions (auto in poll, manual
 * otherwise)
 * 3. **Query**: Check availability, backend name, cancel pending
 * 4. **Destruction**: SocketAsync_free(&ctx) or via owning poll free
 *
 * Thread-safety: Full for submissions/processing/cancels; callbacks invoked
 * single-threaded per context (from poll thread). Internal mutexes protect
 * shared state.
 *
 * @note Opaque type - no user access to internal fields or direct
 * manipulation. Use provided API only to avoid undefined behavior.
 *
 * @warning Context must be freed before arena disposal (if standalone).
 *
 * @see SocketAsync_new() - Standalone allocation.
 * @see SocketPoll_get_async() - Poll-managed instance (recommended).
 * @see SocketAsync_free() - Explicit cleanup.
 * @see SocketAsync_send() / SocketAsync_recv() - Core operations.
 * @see docs/ASYNC_IO.md - Detailed lifecycle and threading model.
 */
typedef struct T *T;

/* Exception types */
/**
 * @brief Module-specific exception for fatal async I/O errors.
 * @ingroup async_io
 *
 * Raised by TRY/EXCEPT blocks in async operations for irrecoverable failures.
 * Non-fatal/transient errors (e.g., queue full, EAGAIN) are signaled via
 * return values (0/-1) and errno instead of exceptions to avoid overhead in
 * hot paths.
 *
 * Common triggers:
 * - **Initialization**: Backend setup fails (e.g., io_uring_queue_init returns
 * -1, insufficient mem/privs, kernel too old)
 * - **Submission**: Invalid socket/params, arena alloc fail, internal
 * corruption
 * - **Runtime**: Backend resource exhaustion, ring overflow, platform bugs
 * - **Cleanup**: Free errors (e.g., pending ops can't cancel)
 *
 * Use Except_message() or Socket_GetLastError() for details. Always pair with
 * SocketAsync_is_available() post-error to check recovery.
 *
 * @see core/Except.h - Exception handling framework (TRY/EXCEPT/RAISE).
 * @see SocketAsync_new() - Throws on backend init failure.
 * @see SocketAsync_send() / SocketAsync_recv() - Throws on submit failures.
 * @see SocketAsync_free() - May log but typically non-throwing.
 * @see Socket_geterrorcode() - For non-exception errno errors.
 */
extern const Except_T SocketAsync_Failed;

/**
 * @brief Completion callback invoked when an async I/O operation finishes.
 * @ingroup async_io
 *
 * This callback type is used for both send and receive operations. It is
 * called from the context of SocketPoll_wait() (or manual
 * SocketAsync_process_completions()) upon operation completion, delivering
 * results and allowing further actions like resubmission for partial transfers
 * or error recovery.
 *
 * Callbacks should be lightweight to avoid blocking the event loop. Heavy
 * processing should be offloaded to worker threads. Always check err for
 * errors before using bytes.
 *
 * Behavior:
 * - Success: err == 0, bytes >= 0 (full or partial transfer)
 * - EOF (recv only): err == 0, bytes == 0
 * - Error: err != 0, bytes may be partial or -1 (check specific backend)
 *
 * @param[in] socket The Socket_T on which the operation completed.
 * @param[in] bytes Number of bytes transferred: >=0 success/partial/EOF, <0
 * error indicator.
 * @param[in] err 0 on success, errno value on failure (e.g., ECONNRESET). Use
 * strerror(err) or Socket_safe_strerror(err).
 * @param[in] user_data Opaque user data provided at submission time.
 *
 * @threadsafe Conditional - Invoked serially from the thread calling
 * SocketPoll_wait() or process_completions(). No concurrent invocations for
 * same req, but multiple callbacks may interleave for different ops. Socket
 * access in callback requires care if multi-threaded.
 *
 * ## Example Implementation
 *
 * @code{.c}
 * // Generic callback for send or recv
 * void async_io_complete(Socket_T socket, ssize_t bytes, int err, void
 * *user_data) { if (err != 0) {
 *         // Error occurred
 *         const char *err_msg = (err > 0) ? strerror(err) : "Unknown error";
 *         SOCKET_LOG_ERROR_MSG("Async op failed: %s (err=%d)", err_msg, err);
 *         // Common handling: close socket, cleanup user_data
 *         if (user_data) free(user_data);  // e.g., buffer
 *         Socket_free(&socket);
 *         return;
 *     }
 *
 *     if (bytes == 0) {
 *         // EOF for recv - connection closed gracefully
 *         SOCKET_LOG_INFO_MSG("Connection EOF on socket %d",
 * Socket_fd(socket)); if (user_data) free(user_data); Socket_free(&socket);
 *         return;
 *     }
 *
 *     // Success: bytes > 0
 *     SOCKET_LOG_DEBUG_MSG("Transferred %zd bytes on socket %d", bytes,
 * Socket_fd(socket));
 *
 *     // For partial transfer (bytes < original len), resubmit remainder
 *     // Track state in user_data struct
 *     AsyncState *state = (AsyncState *)user_data;
 *     state->total_sent += bytes;
 *     if (state->total_sent < state->total_len) {
 *         // Resubmit remaining
 *         SocketAsync_T async = // retrieve async context from user data or
 * global const void *remaining_buf = (char *)state->buf + state->total_sent;
 *         size_t remaining = state->total_len - state->total_sent;
 *         SocketAsync_send(async, socket, remaining_buf, remaining,
 *                          async_io_complete, state, state->flags);
 *     } else {
 *         // Complete - cleanup
 *         free(user_data);
 *     }
 * }
 * @endcode
 *
 * ## Common Error Codes
 *
 * | Error | Meaning | Action |
 * |-------|---------|--------|
 * | 0 | Success | Process bytes |
 * | EAGAIN/EWOULDBLOCK | No data (fallback) | Retry later |
 * | ECONNRESET | Peer reset | Close connection |
 * | ETIMEDOUT | Timeout | Retry or fail |
 * | ECANCELED | Cancelled | Cleanup |
 * | ENOMEM | Resource limit | Backoff, retry |
 *
 * @note In fallback mode, application must manually invoke this callback after
 *       performing I/O with Socket_send()/Socket_recv(), simulating
 * completion.
 *
 * @warning Do not perform blocking operations (e.g., malloc/large allocs, disk
 * I/O) in callbacks - blocks entire event loop. Use queues to worker threads.
 *
 * @see SocketAsync_send() - Submits ops using this callback type.
 * @see SocketAsync_recv() - Receive-specific usage.
 * @see Socket_geterrorcode() - For detailed error info.
 * @see docs/ASYNC_IO.md#callback-best-practices - Optimization and pitfalls.
 */
typedef void (*SocketAsync_Callback) (Socket_T socket,
                                      ssize_t bytes,
                                      int err,
                                      void *user_data);

/**
 * @brief Bit flags to control behavior of asynchronous I/O operations.
 * @ingroup async_io
 *
 * Optional modifiers passed to SocketAsync_send() and SocketAsync_recv() to
 * enable performance optimizations or specific semantics. Flags are combined
 * with bitwise OR. Unsupported flags on a given backend are silently ignored,
 * falling back to default behavior without error.
 *
 * Selection of flags should consider backend capabilities (query via
 * SocketAsync_backend_name() and SocketAsync_is_available()). For example,
 * zero-copy requires native async support and compatible socket types
 * (typically TCP).
 *
 * ## Flag Support Matrix
 *
 * | Flag          | io_uring (Linux 5.1+) | kqueue (macOS/BSD) |
 * Edge-Triggered Fallback | Notes |
 * |---------------|-----------------------|--------------------|-------------------------|-------|
 * | ASYNC_FLAG_NONE | Yes                  | Yes               | Yes | Default
 * | | ASYNC_FLAG_ZERO_COPY | Yes (SEND_ZC/RECV_ZC) | No               | No |
 * Large payloads; TCP only | | ASYNC_FLAG_URGENT | Yes (IOSQE_URGENT/IOLINK) |
 * Partial (priority queue) | No | Low-latency small ops |
 *
 * @warning Combining incompatible flags may degrade performance or fail
 * silently. Always test with target backend.
 *
 * @see SocketAsync_send() - Usage in send operations.
 * @see SocketAsync_recv() - Usage in receive operations.
 * @see SocketAsync_is_available() - Check native async support for advanced
 * flags.
 * @see SocketAsync_backend_name() - Identify current backend for flag
 * compatibility.
 * @see docs/ASYNC_IO.md#performance-tuning - Backend-specific optimizations.
 */
typedef enum
{
  /**
   * @brief Default operation with no special features enabled.
   */
  ASYNC_FLAG_NONE = 0,

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
   * Suitable for time-critical small messages (e.g., ACKs, probes) in
   * high-throughput scenarios.
   * @note Semantics backend-dependent; may be noop if unsupported.
   */
  ASYNC_FLAG_URGENT = 1 << 1,

  /**
   * @brief Defer io_uring submission until flush.
   *
   * When set, the SQE is prepared but io_uring_submit() is not called
   * immediately. This enables batching multiple operations before a single
   * submit syscall, reducing overhead for high-throughput scenarios.
   *
   * Use SocketAsync_flush() to submit all pending operations, or let
   * SocketAsync_submit_batch() handle it automatically.
   *
   * @note io_uring only; ignored on other backends.
   * @note SQ will auto-submit when nearly full to prevent blocking.
   * @see SocketAsync_flush()
   * @see SocketAsync_submit_batch()
   */
  ASYNC_FLAG_NOSYNC = 1 << 2,

  /**
   * @brief Use pre-registered fixed buffer for I/O.
   *
   * When set, the operation uses a pre-registered buffer from the buffer pool
   * registered via SocketAsync_register_buffers(). The buffer index is encoded
   * in the operation's buffer pointer.
   *
   * Benefits:
   * - Eliminates per-operation buffer mapping overhead (10-20% improvement)
   * - Reduces kernel memory pressure for high-throughput scenarios
   *
   * Requirements:
   * - Buffer must be registered via SocketAsync_register_buffers() first
   * - io_uring backend only; ignored on other backends
   *
   * @note Use SocketAsync_send_fixed() / SocketAsync_recv_fixed() for cleaner
   * API.
   * @see SocketAsync_register_buffers()
   * @see SocketAsync_send_fixed()
   * @see SocketAsync_recv_fixed()
   */
  ASYNC_FLAG_FIXED_BUFFER = 1 << 3
} SocketAsync_Flags;

/* ==================== Advanced io_uring Configuration ==================== */

/**
 * @brief Configuration options for advanced io_uring features.
 * @ingroup async_io
 *
 * Controls optional io_uring performance features that may require elevated
 * privileges or specific kernel versions. Use with
 * SocketAsync_new_with_config().
 *
 * All options default to disabled (0) for maximum compatibility.
 */
typedef struct SocketAsync_Config
{
  /**
   * @brief Enable SQPOLL mode for kernel-side submission polling.
   *
   * When enabled, the kernel spawns a dedicated thread that polls the SQ for
   * new submissions, eliminating the need for io_uring_submit() syscalls.
   *
   * Trade-offs:
   * - Pro: Eliminates submit syscall entirely (5-15% throughput improvement)
   * - Con: Dedicates a CPU core to polling
   * - Con: Requires CAP_SYS_ADMIN or io_uring credential registration
   *
   * The kernel thread will idle after idle_ms milliseconds without submissions
   * (see sqpoll_idle_ms). Set to 0 to disable SQPOLL mode.
   *
   * @note Requires Linux kernel 5.4+ for SQPOLL support.
   * @note Falls back gracefully to standard submission if privileges
   * insufficient.
   */
  int enable_sqpoll;

  /**
   * @brief SQPOLL idle timeout in milliseconds.
   *
   * Time the kernel polling thread waits before going to sleep when no
   * submissions are pending. Lower values save CPU but increase latency
   * for sporadic workloads.
   *
   * Recommended values:
   * - High-throughput: 0 (never sleep) - requires dedicated CPU
   * - Balanced: 1000 (1 second)
   * - Power-saving: 100-500 ms
   *
   * Only used when enable_sqpoll is non-zero. Default: 1000 ms.
   */
  unsigned sqpoll_idle_ms;

  /**
   * @brief CPU affinity for SQPOLL kernel thread.
   *
   * Pin the kernel polling thread to a specific CPU core. Use -1 to allow
   * kernel scheduling (default). Setting this can improve cache locality
   * but reduces flexibility.
   *
   * Only used when enable_sqpoll is non-zero. Default: -1 (no affinity).
   */
  int sqpoll_cpu;

  /**
   * @brief Number of entries in the submission queue.
   *
   * Size of the io_uring submission ring. Must be a power of 2.
   * Larger values allow more concurrent operations but consume more memory.
   *
   * Recommended: 256-1024 for most applications, 4096+ for high-throughput.
   * Default: 256 (SOCKET_DEFAULT_IO_URING_ENTRIES).
   */
  unsigned ring_size;

} SocketAsync_Config;

/**
 * @brief Default configuration for standard io_uring operation.
 * @ingroup async_io
 *
 * Use this to initialize a config struct before customizing:
 * @code{.c}
 * SocketAsync_Config config = SOCKETASYNC_CONFIG_DEFAULT;
 * config.enable_sqpoll = 1;
 * SocketAsync_T async = SocketAsync_new_with_config(arena, &config);
 * @endcode
 */
#define SOCKETASYNC_CONFIG_DEFAULT \
  {                                \
    0, 1000, -1, 256               \
  }

/**
 * @brief Create a new standalone asynchronous I/O context.
 * @ingroup async_io
 *
 * Creates and initializes a platform-optimized asynchronous I/O backend for
 * high-performance, non-blocking send and receive operations. The backend
 * automatically selects the best available mechanism based on the platform:
 * - Linux (kernel 5.1+): io_uring for true async I/O with zero-copy support
 * - macOS/FreeBSD: kqueue with edge-triggered polling and AIO where available
 * - Other POSIX: Fallback to efficient edge-triggered polling
 *
 * Standalone contexts require manual calls to
 * SocketAsync_process_completions() to poll for and process operation
 * completions. This mode is suitable for custom event loops or testing. For
 * production event-driven applications, prefer SocketPoll_get_async() which
 * integrates seamlessly with SocketPoll_wait().
 *
 * @param[in] arena Arena_T used for internal memory allocations. The arena
 * must outlive the lifetime of the async context to avoid use-after-free
 * issues.
 *
 * @return New SocketAsync_T instance, ready for operation submission.
 *
 * @throws SocketAsync_Failed On backend initialization failure, including:
 *                            - System resource limits (e.g., RLIMIT_NOFILE too
 * low)
 *                            - Insufficient privileges (e.g., io_uring
 * requires CAP_SYS_NICE on some setups)
 *                            - Unsupported kernel version or missing libraries
 * (e.g., liburing)
 *                            - Memory allocation failures via arena
 *
 * @threadsafe Yes - creation is thread-safe; resulting context supports
 * concurrent submission and processing from multiple threads via internal
 * synchronization.
 *
 * ## Usage Example: Standalone Context
 *
 * @code{.c}
 * // Standalone usage - requires manual completion processing
 * Arena_T arena = Arena_new();
 * SocketAsync_T async = NULL;
 * TRY {
 *     async = SocketAsync_new(arena);
 *     if (!SocketAsync_is_available(async)) {
 *         fprintf(stderr, "Warning: Async I/O unavailable, fallback mode
 * enabled\n"); fprintf(stderr, "Backend: %s\n",
 * SocketAsync_backend_name(async));
 *     }
 *     // Submit operations here...
 *     // In your main loop:
 *     // int completed = SocketAsync_process_completions(async, 10); // 10ms
 * timeout } EXCEPT(SocketAsync_Failed) { fprintf(stderr, "Failed to init
 * async: %s\n", Except_message(Except_stack)); } FINALLY {
 *     SocketAsync_free(&async);
 * } END_TRY;
 * Arena_dispose(&arena);
 * @endcode
 *
 * ## Recommended: Integrated with SocketPoll
 *
 * @code{.c}
 * SocketPoll_T poll = SocketPoll_new(1024); // Create event poll
 * SocketAsync_T async = SocketPoll_get_async(poll); // Get integrated async
 * context if (async && SocketAsync_is_available(async)) {
 *     // Completions auto-processed during SocketPoll_wait()
 *     // Submit async operations using this async context
 * }
 * // async lifetime tied to poll - free poll to cleanup
 * @endcode
 *
 * @note Standalone contexts require periodic calls to
 * SocketAsync_process_completions() to handle operation completions and invoke
 * callbacks. Neglecting this leads to pending operations never completing.
 *
 * @warning The provided arena must remain valid for the entire lifetime of the
 * async context. Early disposal causes memory corruption or crashes.
 *
 * @complexity O(1) - Initialization time is constant, though backend setup
 * (e.g., ring allocation) may involve small fixed overhead.
 *
 * @see SocketPoll_get_async() - Recommended for most applications with event
 * loops.
 * @see SocketAsync_free() - Corresponding cleanup function.
 * @see SocketAsync_send() - Example of operation submission.
 * @see SocketAsync_recv() - Receive operation submission.
 * @see SocketAsync_process_completions() - Manual completion processing for
 * standalone mode.
 * @see SocketAsync_is_available() - Verify backend capabilities after
 * creation.
 * @see docs/ASYNC_IO.md - Comprehensive guide, examples, and performance
 * tuning.
 */
extern T SocketAsync_new (Arena_T arena);

/**
 * @brief Create async I/O context with advanced configuration.
 * @ingroup async_io
 *
 * Creates an async context with optional advanced io_uring features like SQPOLL
 * mode. Falls back gracefully when features unavailable or insufficient
 * privileges.
 *
 * @param[in] arena Arena_T for internal allocations.
 * @param[in] config Configuration options (NULL for defaults).
 * @return New SocketAsync_T instance.
 *
 * @throws SocketAsync_Failed On backend initialization failure.
 * @threadsafe Yes.
 *
 * ## Example: Enable SQPOLL
 *
 * @code{.c}
 * SocketAsync_Config config = SOCKETASYNC_CONFIG_DEFAULT;
 * config.enable_sqpoll = 1;
 * config.sqpoll_idle_ms = 0;  // Never idle (max performance)
 *
 * SocketAsync_T async = SocketAsync_new_with_config(arena, &config);
 * if (SocketAsync_is_sqpoll_active(async)) {
 *     printf("SQPOLL mode enabled - no submit syscalls needed\n");
 * }
 * @endcode
 *
 * @note SQPOLL requires CAP_SYS_ADMIN or unprivileged io_uring setup
 * (kernel 5.12+).
 * @see SocketAsync_new() for simple creation with defaults.
 * @see SocketAsync_Config for configuration options.
 * @see SocketAsync_is_sqpoll_active() to verify SQPOLL activation.
 */
extern T
SocketAsync_new_with_config (Arena_T arena, const SocketAsync_Config *config);

/**
 * @brief Check if SQPOLL mode is active.
 * @ingroup async_io
 * @param[in] async Async context.
 * @return 1 if SQPOLL kernel polling is active, 0 otherwise.
 *
 * SQPOLL may not be active even if requested due to insufficient privileges
 * or kernel version requirements.
 *
 * @threadsafe Yes - read-only query.
 */
extern int SocketAsync_is_sqpoll_active (const T async);

/**
 * @brief Destroy an asynchronous I/O context and release associated resources.
 * @ingroup async_io
 *
 * Cleans up the async I/O context, freeing platform-specific resources such as
 * io_uring rings, kqueue file descriptors, or internal polling structures.
 * Any pending operations are cancelled, and their callbacks may be invoked
 * with an error code indicating cancellation (e.g., ECANCELED or EINTR).
 *
 * This function is idempotent and safe to call multiple times or with NULL.
 * Internal synchronization ensures thread-safety during cleanup.
 *
 * @param[in,out] async Pointer to the SocketAsync_T instance. Set to NULL on
 * success.
 *
 * @throws None - Does not throw exceptions; errors are logged internally if
 * cleanup fails.
 *
 * @threadsafe Yes - Can be called concurrently from any thread. Cancels
 * pending operations atomically and waits for in-flight operations where
 * necessary. However, avoid concurrent calls with active submissions for best
 * performance.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Paired with SocketAsync_new() for standalone context
 * Arena_T arena = Arena_new();
 * SocketAsync_T async;
 * TRY {
 *     async = SocketAsync_new(arena);
 *     // ... use async for send/recv operations ...
 * } FINALLY {
 *     SocketAsync_free(&async);  // Cancels pending ops, invokes callbacks
 * with error } END_TRY; Arena_dispose(&arena);
 * @endcode
 *
 * @note If the async context was obtained via SocketPoll_get_async(), do NOT
 * call this function directly. The poll instance manages the lifetime - free
 * the SocketPoll_T instead to avoid double-free or resource leaks.
 *
 * @warning Pending callbacks may execute after free() returns, with error
 * codes. Ensure callback code handles cancellation gracefully (check err !=
 * 0).
 *
 * @complexity O(P) where P is number of pending operations - time to cancel
 * and notify.
 *
 * @see SocketAsync_new() - Creation counterpart.
 * @see SocketAsync_cancel() - Cancel specific operations before full cleanup.
 * @see SocketPoll_get_async() - For poll-managed contexts (preferred).
 * @see SocketAsync_process_completions() - Flush completions before free if
 * needed.
 * @see docs/ASYNC_IO.md - Resource management best practices.
 */
extern void SocketAsync_free (T *async);

/**
 * @brief Submit an asynchronous send operation on a socket.
 * @ingroup async_io
 *
 * Queues an asynchronous send operation for the specified socket. The
 * operation is submitted to the platform's async backend (io_uring, kqueue,
 * etc.) immediately if supported, or queued for fallback processing otherwise.
 * Upon completion (success, partial transfer, or error), the provided callback
 * is invoked with the results.
 *
 * Supports advanced features like zero-copy transmission (for large payloads)
 * and urgent prioritization for low-latency needs. Partial sends are possible
 * and reported via the callback's bytes parameter; resubmit remaining data as
 * needed.
 *
 * In fallback mode (no native async support), the operation is not submitted
 * to the kernel but tracked internally. The application must manually perform
 * the send using Socket_send() during event processing and invoke the callback
 * accordingly.
 *
 * @param[in] async Async context obtained from SocketAsync_new() or
 * SocketPoll_get_async().
 * @param[in] socket Non-blocking Socket_T to send data on. Must be connected
 * and valid.
 * @param[in] buf Pointer to data buffer to send. Must remain valid until
 * callback invocation.
 * @param[in] len Number of bytes to send from buf.
 * @param[in] cb Completion callback function, invoked when operation finishes.
 * @param[in] user_data Arbitrary user data passed unchanged to the callback.
 * @param[in] flags Bitwise OR of SocketAsync_Flags to control operation
 * behavior (e.g., ASYNC_FLAG_ZERO_COPY for efficient large transfers).
 *
 * @return Request identifier (>0) on successful queuing/submission, 0 on
 * failure.
 *
 * ## Return Values
 *
 * | Value | Meaning |
 * |-------|---------|
 * | > 0   | Unique request ID for tracking/cancellation |
 * | 0     | Submission failed (e.g., queue full, invalid params); check
 * Socket_geterrorcode() |
 *
 * @throws SocketAsync_Failed On fatal submission errors (e.g., invalid socket,
 * resource exhaustion). Transient failures return 0 without throwing.
 *
 * @threadsafe Yes - Internal mutex protects request queue and submission.
 * Concurrent submissions from multiple threads are serialized safely.
 *
 * ## Basic Usage
 *
 * @code{.c}
 * // Define completion callback
 * void send_complete(Socket_T socket, ssize_t bytes, int err, void *user_data)
 * { if (err != 0) { printf("Send error: %s (errno=%d)\n", strerror(err), err);
 *         // Handle error, e.g., close socket
 *         return;
 *     }
 *     if (bytes > 0) {
 *         printf("Successfully sent %zd bytes\n", bytes);
 *         // If bytes < requested len, resubmit remainder
 *     } else {
 *         printf("Send completed with 0 bytes (unlikely)\n");
 *     }
 * }
 *
 * // Submit async send
 * const char *message = "Hello, asynchronous world!";
 * unsigned req_id = SocketAsync_send(async, client_socket, message,
 * strlen(message), send_complete, NULL, ASYNC_FLAG_NONE); if (req_id == 0) {
 *     // Handle submission failure
 *     perror("SocketAsync_send failed");
 * }
 * @endcode
 *
 * ## Advanced: Zero-Copy for Large Data
 *
 * @code{.c}
 * // For large payloads, enable zero-copy if backend supports it
 * if (SocketAsync_is_available(async)) {  // Ensure native async
 *     unsigned req_id = SocketAsync_send(async, socket, large_file_buf,
 * file_size, cb, user_data, ASYNC_FLAG_ZERO_COPY);
 *     // Zero-copy reduces CPU overhead for bulk transfers
 * }
 * @endcode
 *
 * ## Error Handling in Callback
 *
 * Common errors in callback (err parameter):
 * - EAGAIN/EWOULDBLOCK: Temporary, retry possible in fallback mode
 * - ECONNRESET: Peer closed connection
 * - ENOMEM: Out of kernel buffers
 * - ECANCELED: Operation cancelled via SocketAsync_cancel()
 *
 * @warning The buf must remain valid and unmodified until the callback is
 * invoked. Do not free or alter buf in other threads before completion.
 *
 * @note In fallback mode, manually drive I/O: poll socket for writability,
 * call Socket_send(), then invoke cb with results. See docs/ASYNC_IO.md for
 * details.
 *
 * @note Partial sends (bytes < len) require application logic to resubmit the
 * remainder. Track sent bytes in user_data if needed for multi-part sends.
 *
 * @complexity O(1) amortized - Constant time queue insertion/submission;
 * occasional backend flush may be O(batch size).
 *
 * @see SocketAsync_recv() - Counterpart for receive operations.
 * @see SocketAsync_cancel() - Cancel a pending send by req_id.
 * @see SocketAsync_Flags - Details on available flags and backend support.
 * @see SocketPoll_wait() - Processes completions automatically in event loop.
 * @see docs/ASYNC_IO.md#async-send - Examples and fallback handling.
 */
extern unsigned SocketAsync_send (T async,
                                  Socket_T socket,
                                  const void *buf,
                                  size_t len,
                                  SocketAsync_Callback cb,
                                  void *user_data,
                                  SocketAsync_Flags flags);

/**
 * @brief Submit an asynchronous receive operation on a socket.
 * @ingroup async_io
 *
 * Queues an asynchronous receive (read) operation for incoming data on the
 * socket. Data is received into the provided buffer up to the specified
 * length. Completion is notified via callback with the number of bytes
 * received: positive for success, 0 for EOF (connection closed gracefully),
 * negative for errors.
 *
 * Supports platform-optimized async receive mechanisms, including zero-copy
 * where available (e.g., io_uring RECV_ZC). Partial receives are reported via
 * bytes < len; resubmit for more data if needed (e.g., for stream protocols).
 *
 * Buffer safety: The buf must not be freed or modified until the callback
 * executes. In fallback mode, manual recv via Socket_recv() is required during
 * socket-readable events.
 *
 * @param[in] async Async context for operation queuing and backend submission.
 * @param[in] socket Non-blocking Socket_T to receive data from. Must be
 * connected.
 * @param[out] buf Buffer to store received data. Valid until callback.
 * @param[in] len Maximum bytes to receive (buffer size).
 * @param[in] cb Completion callback invoked with receive results.
 * @param[in] user_data User-supplied data for callback context.
 * @param[in] flags Operation modifiers (e.g., ASYNC_FLAG_ZERO_COPY for
 * efficiency; some flags backend-dependent or reserved for future).
 *
 * @return Request ID (>0 success, 0 failure). See return table below.
 *
 * ## Return Values
 *
 * | Value | Meaning |
 * |-------|---------|
 * | > 0   | Request queued/submitted successfully |
 * | 0     | Failed to queue (e.g., invalid args, full queue); errno set |
 *
 * @throws SocketAsync_Failed Fatal errors during submission (e.g., bad socket,
 * OOM). Non-fatal issues return 0.
 *
 * @threadsafe Yes - Safe for concurrent submissions; internal locking used.
 *
 * ## Basic Usage
 *
 * @code{.c}
 * // Receive callback
 * void recv_complete(Socket_T socket, ssize_t bytes, int err, void *user_data)
 * { char *buffer = (char *)user_data; if (err != 0) { printf("Recv error:
 * %s\n", strerror(err)); Socket_free(&socket);  // e.g., close on error
 *         free(buffer);
 *         return;
 *     }
 *     if (bytes == 0) {
 *         printf("EOF - connection closed\n");
 *         Socket_free(&socket);
 *         free(buffer);
 *         return;
 *     }
 *     // Process received data
 *     printf("Received %zd bytes: %.20s...\n", bytes, buffer);
 *     // Resubmit for more data if stream not complete
 *     SocketAsync_T async = get_async_context(); // pseudocode
 *     SocketAsync_recv(async, socket, buffer, 4096, recv_complete, buffer,
 * ASYNC_FLAG_NONE);
 * }
 *
 * // Initial receive submission (e.g., after accept)
 * char *recv_buf = malloc(4096);
 * unsigned req_id = SocketAsync_recv(async, client_socket, recv_buf, 4096,
 *                                    recv_complete, recv_buf,
 * ASYNC_FLAG_NONE); if (req_id == 0) { free(recv_buf);
 *     // Handle failure
 * }
 * @endcode
 *
 * ## Handling Partial Receives and EOF
 *
 * In the callback:
 * - bytes > 0: Partial or full data received; process and resubmit if more
 * expected
 * - bytes == 0: Graceful EOF; close socket if appropriate
 * - bytes < 0 or err != 0: Error; check err for details (e.g., ECONNRESET)
 *
 * @warning buf is [out] - data written by kernel/user-space recv. App must
 * handle overlapping resubmits carefully to avoid data races.
 *
 * @note Flags like ASYNC_FLAG_ZERO_COPY may be supported for recv in future
 * backends or specific platforms; currently limited use - check
 * SocketAsync_backend_name().
 *
 * @complexity O(1) amortized - Quick queue operation; backend submit may
 * batch.
 *
 * @see SocketAsync_send() - Companion send operation.
 * @see SocketAsync_Callback - Callback signature and error codes.
 * @see SocketAsync_Flags - Potential flags for recv (expanding support).
 * @see SocketAsync_cancel() - Abort pending recv.
 * @see docs/ASYNC_IO.md#async-receive - Fallback mode and echo server example.
 */
extern unsigned SocketAsync_recv (T async,
                                  Socket_T socket,
                                  void *buf,
                                  size_t len,
                                  SocketAsync_Callback cb,
                                  void *user_data,
                                  SocketAsync_Flags flags);

/**
 * @brief Cancel a pending asynchronous I/O operation by request ID.
 * @ingroup async_io
 *
 * Attempts to cancel a previously submitted operation (send or recv). If
 * successful, the operation is aborted, and the callback is eventually invoked
 * with err = ECANCELED (or equivalent). Cancellation is asynchronous and
 * best-effort: the operation may complete normally before cancellation
 * propagates to the backend, or in-flight kernel ops may finish despite cancel
 * request.
 *
 * Useful for timeouts, connection closure, or resource cleanup. After cancel,
 * the request ID is invalidated and cannot be cancelled again.
 *
 * @param[in] async The async context managing the operation.
 * @param[in] request_id ID returned from SocketAsync_send() or
 * SocketAsync_recv().
 *
 * @return 0 if cancel request accepted (may still complete), -1 if invalid ID
 * or already done.
 *
 * ## Return Values
 *
 * | Value | Meaning |
 * |-------|---------|
 * | 0     | Cancel initiated (check callback for ECANCELED confirmation) |
 * | -1    | Request not found, already completed/cancelled, or invalid ID |
 *
 * @throws None - Non-throwing; returns -1 on errors.
 *
 * @threadsafe Yes - Atomic operation with internal locking.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Cancel a pending request (e.g., on timeout)
 * unsigned req_id = // from send/recv call
 * int cancelled = SocketAsync_cancel(async, req_id);
 * if (cancelled == 0) {
 *     printf("Cancel requested for req %u\n", req_id);
 *     // Callback will receive err == ECANCELED
 * } else {
 *     printf("Cancel failed: req %u not pending\n", req_id);
 * }
 * @endcode
 *
 * @note Even after successful cancel (return 0), the callback may fire with
 * success if completion raced with cancel. Always check err in callback for
 * ECANCELED.
 *
 * @warning Frequent cancels may impact performance due to backend overhead
 * (e.g., io_uring CQE signaling).
 *
 * @complexity O(1) average - Hash table lookup for request; worst O(n) if
 * collisions.
 *
 * @see SocketAsync_send() - Obtains request_id to cancel.
 * @see SocketAsync_recv() - Similar for recv ops.
 * @see SocketAsync_Callback - Handles ECANCELED in err param.
 * @see SocketAsync_free() - Cancels all pending on context destruction.
 * @see docs/ASYNC_IO.md#cancellation - Best practices and race conditions.
 */
extern int SocketAsync_cancel (T async, unsigned request_id);

/**
 * @brief Poll and process completed asynchronous I/O operations.
 * @ingroup async_io
 *
 * Drains the async backend's completion queue (e.g., io_uring CQE ring, kqueue
 * events) and invokes callbacks for finished operations. This must be called
 * regularly for standalone contexts to ensure timely callback delivery and
 * resource recycling.
 *
 * In integrated mode (SocketPoll_get_async()), this is invoked automatically
 * during SocketPoll_wait(). For standalone, call in your main loop with
 * appropriate timeout to balance responsiveness and CPU usage.
 *
 * Returns the number of callbacks invoked. Negative return indicates error
 * (rare, e.g., backend corruption).
 *
 * @param[in] async The async context to process completions for.
 * @param[in] timeout_ms Maximum wait time in ms before returning
 * (0=non-blocking, -1=block indefinitely - avoid in event loops).
 *
 * @return Number of completions processed (>=0), or -1 on error (check errno).
 *
 * ## Return Values
 *
 * | Value | Meaning |
 * |-------|---------|
 * | > 0   | Number of callbacks invoked this call |
 * | 0     | No completions ready within timeout |
 * | -1    | Processing error (e.g., backend failure); errno set |
 *
 * @throws None - Errors returned via return value/errno, not exceptions.
 *
 * @threadsafe Yes - Internal mutex serializes access; safe concurrent calls
 * (but inefficient).
 *
 * ## Usage Example: Standalone Mode
 *
 * @code{.c}
 * // In main loop for standalone async context
 * while (running) {
 *     // Submit new operations as needed...
 *
 *     // Process completions non-blocking
 *     int processed = SocketAsync_process_completions(async, 0);
 *     if (processed < 0) {
 *         SOCKET_LOG_ERROR_MSG("Completion processing failed: %s",
 * strerror(errno));
 *         // Handle error, e.g., recreate async
 *     } else if (processed > 0) {
 *         SOCKET_LOG_DEBUG_MSG("Processed %d completions", processed);
 *     }
 *
 *     // Other loop work (e.g., poll other fds)
 *     usleep(1000);  // Yield CPU if no events
 * }
 * @endcode
 *
 * ## Integrated Mode (Automatic)
 *
 * No manual call needed:
 * @code{.c}
 * SocketPoll_wait(poll, &events, timeout);  // Auto-processes async
 * completions
 * @endcode
 *
 * @note For high-throughput, use small timeouts or non-blocking to avoid
 * latency. Batch multiple calls if backend supports (e.g., process up to N
 * completions).
 *
 * @warning Blocking indefinitely (timeout_ms = -1) in event loops causes
 * starvation. Use only in dedicated worker threads.
 *
 * @complexity O(C + B) where C is completions processed, B backend poll
 * overhead.
 *
 * @see SocketPoll_wait() - Automatic processing in event-driven apps.
 * @see SocketAsync_Callback - Invoked for each processed completion.
 * @see SocketAsync_new() - Standalone contexts require this call.
 * @see docs/ASYNC_IO.md#processing-completions - Tuning and batching tips.
 */
extern int SocketAsync_process_completions (T async, int timeout_ms);

/**
 * @brief Query if native asynchronous I/O backend is operational.
 * @ingroup async_io
 *
 * Returns whether the async context uses a true asynchronous backend (e.g.,
 * io_uring, kqueue AIO) or fallback mode (edge-triggered polling with manual
 * I/O). Native async enables kernel-level async processing, zero-copy, and
 * higher throughput.
 *
 * Fallback mode (return 0) means operations are queued but require manual
 * completion via Socket_send()/recv() in events, simulating async behavior.
 * Flags like zero-copy are unavailable in fallback.
 *
 * Call this after SocketAsync_new() to determine capabilities and adjust
 * application logic (e.g., enable/disable optimizations).
 *
 * @param[in] async Const reference to async context.
 *
 * @return 1 if native async I/O available and initialized, 0 if fallback or
 * error.
 *
 * @throws None.
 *
 * @threadsafe Yes - Read-only query.
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketAsync_T async = SocketAsync_new(arena);
 * if (SocketAsync_is_available(async)) {
 *     printf("Native async supported\n");
 *     // Enable advanced features like zero-copy
 * } else {
 *     printf("Fallback mode - manual I/O required\n");
 *     // Adjust for lower performance
 * }
 * const char *backend = SocketAsync_backend_name(async);
 * printf("Backend: %s\n", backend);
 * @endcode
 *
 * @note Availability checked at init time; may change if backend fails (rare).
 *       Re-check after errors in process_completions().
 *
 * @complexity O(1) - Simple state check.
 *
 * @see SocketAsync_backend_name() - Get specific backend details.
 * @see SocketAsync_Flags - Flags requiring native support (e.g., ZERO_COPY).
 * @see docs/ASYNC_IO.md#fallback-mode - Handling and limitations.
 */
extern int SocketAsync_is_available (const T async);

/**
 * @brief Retrieve the name of the active asynchronous backend.
 * @ingroup async_io
 *
 * Returns a static string identifying the underlying async I/O mechanism.
 * Useful for logging, configuration, or conditional logic based on
 * capabilities.
 *
 * Possible values:
 * - "io_uring": Linux kernel 5.1+ true async with zero-copy
 * - "kqueue": BSD/macOS AIO or edge-triggered
 * - "poll": Generic POSIX fallback (edge-triggered polling)
 * - "unknown": Init failure or unhandled platform
 *
 * String is statically allocated - do not free or modify.
 *
 * @param[in] async Const async context to query.
 *
 * @return Const char* backend name (never NULL).
 *
 * @throws None.
 *
 * @threadsafe Yes - Returns static string, safe concurrent reads.
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketAsync_T async = // created via SocketAsync_new()
 * const char *backend = SocketAsync_backend_name(async);
 * printf("Using backend: %s (available: %s)\n",
 *        backend,
 *        SocketAsync_is_available(async) ? "yes" : "no (fallback)");
 *
 * if (strcmp(backend, "io_uring") == 0) {
 *     // Enable io_uring-specific optimizations
 * }
 * @endcode
 *
 * @note Backend name is set at initialization and immutable. Does not reflect
 * runtime errors.
 *
 * @complexity O(1) - Direct string return.
 *
 * @see SocketAsync_is_available() - Complement: check if native/full features.
 * @see SocketAsync_Flags - Backend determines supported flags.
 * @see docs/ASYNC_IO.md#platform-support - Backend details and requirements.
 */
extern const char *SocketAsync_backend_name (const T async);

/**
 * @brief Async operation descriptor for batch submission.
 * @ingroup async_io
 *
 * Describes a single async operation for use with SocketAsync_submit_batch().
 * Enables efficient submission of multiple operations in a single call,
 * reducing syscall overhead for high-throughput applications.
 */
typedef struct SocketAsync_Op
{
  Socket_T socket;         /**< Target socket for operation */
  int is_send;             /**< 1 = send operation, 0 = recv operation */
  const void *send_buf;    /**< Buffer for send (NULL if recv) */
  void *recv_buf;          /**< Buffer for recv (NULL if send) */
  size_t len;              /**< Buffer length */
  SocketAsync_Callback cb; /**< Completion callback */
  void *user_data;         /**< User data for callback */
  SocketAsync_Flags flags; /**< Operation flags */
  unsigned request_id;     /**< [OUT] Assigned request ID on success */
} SocketAsync_Op;

/**
 * @brief Submit multiple async operations in a single call.
 * @ingroup async_io
 * @param[in] async Async context.
 * @param[in,out] ops Array of operation descriptors. request_id field is
 * populated on success.
 * @param[in] count Number of operations to submit.
 * @return Number of operations successfully submitted (0 to count).
 *
 * Enables efficient batch submission of multiple async operations, reducing
 * syscall overhead. For io_uring, all operations are prepared as SQEs first,
 * then submitted with a single io_uring_submit() call at the end.
 *
 * Successfully submitted operations have their request_id field populated.
 *
 * @throws None - Returns count of successful submissions.
 * @threadsafe Yes - Internal mutex protects submission.
 * @complexity O(n) where n = count.
 *
 * ## Example
 *
 * @code{.c}
 * SocketAsync_Op ops[3] = {
 *     {sock1, 1, send_buf, NULL, len1, cb, ud1, ASYNC_FLAG_NONE, 0},
 *     {sock2, 0, NULL, recv_buf, len2, cb, ud2, ASYNC_FLAG_NONE, 0},
 *     {sock3, 1, send_buf2, NULL, len3, cb, ud3, ASYNC_FLAG_URGENT, 0}
 * };
 * int submitted = SocketAsync_submit_batch(async, ops, 3);
 * printf("Submitted %d of 3 operations\n", submitted);
 * for (int i = 0; i < submitted; i++) {
 *     printf("Op %d request_id: %u\n", i, ops[i].request_id);
 * }
 * @endcode
 *
 * @note io_uring backend uses deferred submission for batching efficiency.
 * @see SocketAsync_send() for single send operation.
 * @see SocketAsync_recv() for single recv operation.
 * @see SocketAsync_cancel() to cancel by request_id.
 */
extern int
SocketAsync_submit_batch (T async, SocketAsync_Op *ops, size_t count);

/**
 * @brief Flush all pending io_uring submissions.
 * @ingroup async_io
 * @param[in] async Async context.
 * @return Number of SQEs submitted to kernel, or -1 on error.
 *
 * Submits all pending SQEs that were prepared with ASYNC_FLAG_NOSYNC.
 * This function is called automatically by SocketAsync_submit_batch()
 * after preparing all operations.
 *
 * For non-io_uring backends, this is a no-op that returns 0.
 *
 * @throws None - Errors returned via return value.
 * @threadsafe Yes - Internal mutex protects submission.
 * @complexity O(1) - Single syscall to io_uring_submit().
 *
 * ## Example
 *
 * @code{.c}
 * // Submit multiple operations with deferred submission
 * SocketAsync_send(async, sock1, buf1, len1, cb, ud1, ASYNC_FLAG_NOSYNC);
 * SocketAsync_send(async, sock2, buf2, len2, cb, ud2, ASYNC_FLAG_NOSYNC);
 * SocketAsync_recv(async, sock3, buf3, len3, cb, ud3, ASYNC_FLAG_NOSYNC);
 *
 * // Now flush all pending to kernel in one syscall
 * int submitted = SocketAsync_flush(async);
 * printf("Flushed %d operations\n", submitted);
 * @endcode
 *
 * @note Pending operations are auto-flushed when SQ is nearly full.
 * @see ASYNC_FLAG_NOSYNC for deferred submission flag.
 * @see SocketAsync_submit_batch() for batch submission.
 * @see SocketAsync_pending_count() to check pending count.
 */
extern int SocketAsync_flush (T async);

/**
 * @brief Get count of pending (unflushed) io_uring operations.
 * @ingroup async_io
 * @param[in] async Async context.
 * @return Number of SQEs prepared but not yet submitted to kernel.
 *
 * Returns the count of operations submitted with ASYNC_FLAG_NOSYNC that
 * have not yet been flushed to the kernel via io_uring_submit().
 *
 * For non-io_uring backends, always returns 0.
 *
 * @throws None.
 * @threadsafe Yes - Read-only query with internal locking.
 * @complexity O(1).
 *
 * @see SocketAsync_flush() to submit pending operations.
 * @see ASYNC_FLAG_NOSYNC for deferred submission flag.
 */
extern unsigned SocketAsync_pending_count (const T async);

/**
 * @brief Cancel all pending async operations.
 * @ingroup async_io
 * @param[in] async Async context.
 * @return Number of operations cancelled.
 *
 * Cancels all pending async operations in the context. Callbacks are NOT
 * invoked for cancelled operations. Useful for cleanup during shutdown or
 * connection reset.
 *
 * @throws None - Non-throwing cleanup operation.
 * @threadsafe Yes - Internal mutex protects cancellation.
 * @complexity O(n) where n = pending operations.
 *
 * ## Example
 *
 * @code{.c}
 * // During shutdown
 * int cancelled = SocketAsync_cancel_all(async);
 * printf("Cancelled %d pending operations\n", cancelled);
 * SocketAsync_free(&async);
 * @endcode
 *
 * @see SocketAsync_cancel() to cancel specific operation by ID.
 * @see SocketAsync_free() which implicitly cancels all pending.
 */
extern int SocketAsync_cancel_all (T async);

/**
 * @brief Backend type identifiers for runtime selection.
 * @ingroup async_io
 *
 * Identifies available async I/O backends. Used with
 * SocketAsync_backend_available() for runtime capability checking.
 */
typedef enum
{
  ASYNC_BACKEND_AUTO = 0, /**< Automatic best-available selection (default) */
  ASYNC_BACKEND_IO_URING, /**< Linux io_uring (kernel 5.1+) */
  ASYNC_BACKEND_KQUEUE,   /**< BSD/macOS kqueue */
  ASYNC_BACKEND_POLL,     /**< POSIX poll fallback */
  ASYNC_BACKEND_NONE      /**< Explicitly disable async (sync mode) */
} SocketAsync_Backend;

/**
 * @brief Check if a specific backend is available at runtime.
 * @ingroup async_io
 * @param[in] backend Backend type to check.
 * @return 1 if backend available and usable, 0 otherwise.
 *
 * Tests runtime availability of a specific async backend. Useful for
 * applications that need to verify platform capabilities before configuring
 * async I/O behavior.
 *
 * @threadsafe Yes - Read-only capability check.
 * @complexity O(1) for most backends; io_uring may probe kernel.
 *
 * ## Example
 *
 * @code{.c}
 * if (SocketAsync_backend_available(ASYNC_BACKEND_IO_URING)) {
 *     printf("io_uring available - optimal async I/O\n");
 * } else if (SocketAsync_backend_available(ASYNC_BACKEND_KQUEUE)) {
 *     printf("kqueue available - good async I/O\n");
 * } else {
 *     printf("Fallback to poll-based async\n");
 * }
 * @endcode
 *
 * @note Compile-time support required; checks runtime kernel/library
 * availability.
 * @see SocketAsync_backend_name() for current backend in use.
 * @see SocketAsync_set_backend() to request specific backend.
 */
extern int SocketAsync_backend_available (SocketAsync_Backend backend);

/**
 * @brief Request a specific async backend for new contexts.
 * @ingroup async_io
 * @param[in] backend Desired backend type.
 * @return 0 on success (preference set), -1 if backend unavailable.
 *
 * Sets a preference for the async backend used by subsequent SocketAsync_new()
 * calls. If the requested backend is unavailable, returns -1 and keeps the
 * current preference unchanged.
 *
 * **Note**: Backend selection is primarily determined at compile-time. This
 * function allows runtime override within available compiled backends.
 *
 * @threadsafe Yes - Thread-safe preference update.
 * @complexity O(1)
 *
 * ## Example
 *
 * @code{.c}
 * // Prefer io_uring if available
 * if (SocketAsync_set_backend(ASYNC_BACKEND_IO_URING) == 0) {
 *     printf("Will use io_uring for new async contexts\n");
 * }
 *
 * SocketAsync_T async = SocketAsync_new(arena);  // Uses preferred backend
 * @endcode
 *
 * @note Use ASYNC_BACKEND_AUTO to restore automatic selection.
 * @see SocketAsync_backend_available() to check availability first.
 * @see SocketAsync_backend_name() to verify actual backend after creation.
 */
extern int SocketAsync_set_backend (SocketAsync_Backend backend);

/* ==================== Progress and Continuation API ==================== */

/**
 * @brief Query progress of a pending async request.
 * @ingroup async_io
 * @param[in] async Async context.
 * @param[in] request_id ID of request to query.
 * @param[out] completed Output: bytes completed so far (set to 0 if not found).
 * @param[out] total Output: total bytes requested (set to 0 if not found).
 * @return 1 if request found, 0 if not found or already completed.
 *
 * Allows applications to check progress of in-flight operations before
 * deciding whether to continue or cancel them.
 *
 * @threadsafe Yes.
 * @complexity O(1) average.
 *
 * @see SocketAsync_send_continue() to resume partial transfers.
 * @see SocketAsync_recv_continue() to resume partial receives.
 */
extern int SocketAsync_get_progress (T async,
                                     unsigned request_id,
                                     size_t *completed,
                                     size_t *total);

/**
 * @brief Continue a partially completed send operation.
 * @ingroup async_io
 * @param[in] async Async context.
 * @param[in] request_id ID of the original request to continue.
 * @return New request ID (>0) on success, 0 if original not found or complete.
 *
 * Looks up the original request, calculates remaining buffer (buf + completed,
 * len - completed), and resubmits with the same callback/user_data. Original
 * request is removed and freed.
 *
 * @threadsafe Yes.
 * @complexity O(1) average.
 *
 * ## Example
 *
 * @code{.c}
 * void send_callback(Socket_T sock, ssize_t bytes, int err, void *ud) {
 *     struct SendState *state = (struct SendState *)ud;
 *     if (err != 0) {
 *         // Handle error
 *         return;
 *     }
 *     if (bytes > 0 && bytes < (ssize_t)(state->total_len - state->sent)) {
 *         // Partial send - continue with remainder
 *         state->sent += bytes;
 *         unsigned new_id = SocketAsync_send_continue(state->async,
 * state->req_id); if (new_id > 0) state->req_id = new_id;
 *     }
 * }
 * @endcode
 *
 * @see SocketAsync_get_progress() to check progress before continuing.
 * @see SocketAsync_send() for initial submission.
 */
extern unsigned SocketAsync_send_continue (T async, unsigned request_id);

/**
 * @brief Continue a partially completed receive operation.
 * @ingroup async_io
 * @param[in] async Async context.
 * @param[in] request_id ID of the original request to continue.
 * @return New request ID (>0) on success, 0 if original not found or complete.
 *
 * @threadsafe Yes.
 * @complexity O(1) average.
 *
 * @see SocketAsync_recv() for initial submission.
 * @see SocketAsync_get_progress() to check progress before continuing.
 */
extern unsigned SocketAsync_recv_continue (T async, unsigned request_id);

/* ==================== Timeout Configuration API ==================== */

/**
 * @brief Set the global request timeout for an async context.
 * @ingroup async_io
 * @param[in] async Async context.
 * @param[in] timeout_ms Timeout in milliseconds (0 = disable timeout).
 *
 * Requests older than this timeout will be cancelled with ETIMEDOUT during
 * SocketAsync_process_completions() or SocketAsync_expire_stale().
 * Per-request deadlines (set via send_timeout/recv_timeout) override this.
 *
 * @threadsafe Yes.
 *
 * ## Example
 *
 * @code{.c}
 * // Set 30-second timeout for all requests
 * SocketAsync_set_timeout(async, 30000);
 *
 * // Later, disable timeout
 * SocketAsync_set_timeout(async, 0);
 * @endcode
 *
 * @see SocketAsync_get_timeout() to query current timeout.
 * @see SocketAsync_send_timeout() for per-request timeouts.
 * @see SocketAsync_expire_stale() for manual expiration.
 */
extern void SocketAsync_set_timeout (T async, int64_t timeout_ms);

/**
 * @brief Get the current global request timeout.
 * @ingroup async_io
 * @param[in] async Async context.
 * @return Timeout in milliseconds (0 = disabled).
 *
 * @threadsafe Yes.
 */
extern int64_t SocketAsync_get_timeout (T async);

/**
 * @brief Manually check and cancel stale (timed-out) requests.
 * @ingroup async_io
 * @param[in] async Async context.
 * @return Number of requests cancelled due to timeout.
 *
 * Iterates all pending requests and cancels those that have exceeded their
 * deadline (per-request or global). Callbacks are invoked with err=ETIMEDOUT.
 *
 * Called automatically from SocketAsync_process_completions() when global
 * timeout is configured. Can also be called manually for finer control.
 *
 * @threadsafe Yes.
 * @complexity O(n) where n = pending requests.
 *
 * @see SocketAsync_set_timeout() to configure global timeout.
 * @see SocketAsync_send_timeout() for per-request timeouts.
 */
extern int SocketAsync_expire_stale (T async);

/* ==================== Timeout-Aware Send/Recv API ==================== */

/**
 * @brief Submit async send with per-request timeout.
 * @ingroup async_io
 * @param[in] async Async context.
 * @param[in] socket Target socket.
 * @param[in] buf Data buffer to send.
 * @param[in] len Length of data.
 * @param[in] cb Completion callback (required).
 * @param[in] user_data User data passed to callback.
 * @param[in] flags Operation flags.
 * @param[in] timeout_ms Per-request timeout in milliseconds (0 = use global).
 * @return Unique request ID on success.
 * @throws SocketAsync_Failed on error.
 *
 * Like SocketAsync_send() but with explicit per-request timeout. The request
 * will be cancelled with ETIMEDOUT if not completed within timeout_ms.
 *
 * @threadsafe Yes.
 *
 * ## Example
 *
 * @code{.c}
 * // Send with 5-second timeout
 * unsigned req_id = SocketAsync_send_timeout(async, sock, buf, len,
 *                                             callback, user_data,
 *                                             ASYNC_FLAG_NONE, 5000);
 * @endcode
 *
 * @see SocketAsync_send() for sends using global timeout.
 * @see SocketAsync_set_timeout() for global timeout configuration.
 */
extern unsigned SocketAsync_send_timeout (T async,
                                          Socket_T socket,
                                          const void *buf,
                                          size_t len,
                                          SocketAsync_Callback cb,
                                          void *user_data,
                                          SocketAsync_Flags flags,
                                          int64_t timeout_ms);

/**
 * @brief Submit async recv with per-request timeout.
 * @ingroup async_io
 * @param[in] async Async context.
 * @param[in] socket Target socket.
 * @param[out] buf Receive buffer.
 * @param[in] len Buffer length.
 * @param[in] cb Completion callback (required).
 * @param[in] user_data User data passed to callback.
 * @param[in] flags Operation flags.
 * @param[in] timeout_ms Per-request timeout in milliseconds (0 = use global).
 * @return Unique request ID on success.
 * @throws SocketAsync_Failed on error.
 *
 * Like SocketAsync_recv() but with explicit per-request timeout. The request
 * will be cancelled with ETIMEDOUT if not completed within timeout_ms.
 *
 * @threadsafe Yes.
 *
 * @see SocketAsync_recv() for receives using global timeout.
 * @see SocketAsync_set_timeout() for global timeout configuration.
 */
extern unsigned SocketAsync_recv_timeout (T async,
                                          Socket_T socket,
                                          void *buf,
                                          size_t len,
                                          SocketAsync_Callback cb,
                                          void *user_data,
                                          SocketAsync_Flags flags,
                                          int64_t timeout_ms);

/* ==================== Registered Buffers API ==================== */

/**
 * @brief Register a buffer pool for fixed buffer I/O operations.
 * @ingroup async_io
 * @param[in] async Async context.
 * @param[in] bufs Array of buffer pointers (must remain valid until
 * unregistered).
 * @param[in] lens Array of buffer lengths corresponding to bufs.
 * @param[in] count Number of buffers to register.
 * @return 0 on success, -1 on failure (check errno).
 *
 * Pre-registers buffers with the kernel for use with IORING_OP_READ_FIXED
 * and IORING_OP_WRITE_FIXED operations. Eliminates per-operation buffer
 * mapping overhead for 10-20% improvement with small I/O operations.
 *
 * After registration, use SocketAsync_send_fixed() and SocketAsync_recv_fixed()
 * with buffer indices instead of pointers.
 *
 * @note io_uring only; returns -1 with ENOTSUP on other backends.
 * @note Buffers must remain valid and at the same address until unregistered.
 * @note Maximum buffers limited by system (typically UIO_MAXIOV = 1024).
 *
 * ## Example
 *
 * @code{.c}
 * #define NUM_BUFFERS 64
 * #define BUF_SIZE 4096
 *
 * void *bufs[NUM_BUFFERS];
 * size_t lens[NUM_BUFFERS];
 *
 * for (int i = 0; i < NUM_BUFFERS; i++) {
 *     bufs[i] = aligned_alloc(4096, BUF_SIZE);  // Page-aligned for DMA
 *     lens[i] = BUF_SIZE;
 * }
 *
 * if (SocketAsync_register_buffers(async, bufs, lens, NUM_BUFFERS) == 0) {
 *     printf("Registered %d buffers for fixed I/O\n", NUM_BUFFERS);
 * }
 * @endcode
 *
 * @threadsafe Yes - internal mutex protects registration.
 * @see SocketAsync_unregister_buffers() to release registration.
 * @see SocketAsync_send_fixed() for fixed buffer send.
 * @see SocketAsync_recv_fixed() for fixed buffer receive.
 */
extern int SocketAsync_register_buffers (T async,
                                         void **bufs,
                                         size_t *lens,
                                         unsigned count);

/**
 * @brief Unregister previously registered buffer pool.
 * @ingroup async_io
 * @param[in] async Async context.
 * @return 0 on success, -1 on failure.
 *
 * Unregisters all buffers previously registered with
 * SocketAsync_register_buffers(). After this call, fixed buffer operations will
 * fail until new buffers are registered.
 *
 * @note Ensure no fixed buffer operations are in-flight before unregistering.
 * @threadsafe Yes.
 * @see SocketAsync_register_buffers()
 */
extern int SocketAsync_unregister_buffers (T async);

/**
 * @brief Check if buffers are currently registered.
 * @ingroup async_io
 * @param[in] async Async context.
 * @return Number of registered buffers, or 0 if none.
 * @threadsafe Yes - read-only query.
 */
extern unsigned SocketAsync_registered_buffer_count (const T async);

/**
 * @brief Send using a pre-registered fixed buffer.
 * @ingroup async_io
 * @param[in] async Async context.
 * @param[in] socket Target socket.
 * @param[in] buf_index Index into registered buffer array.
 * @param[in] offset Offset within the buffer to start sending from.
 * @param[in] len Number of bytes to send.
 * @param[in] cb Completion callback.
 * @param[in] user_data User data for callback.
 * @param[in] flags Operation flags (ASYNC_FLAG_FIXED_BUFFER added
 * automatically).
 * @return Request ID on success, 0 on failure.
 *
 * Uses IORING_OP_SEND_FIXED for zero-copy send from registered buffer.
 * Eliminates per-operation buffer mapping for improved throughput.
 *
 * @throws SocketAsync_Failed if buf_index out of range or buffers not
 * registered.
 * @threadsafe Yes.
 * @see SocketAsync_register_buffers() to register buffer pool.
 */
extern unsigned SocketAsync_send_fixed (T async,
                                        Socket_T socket,
                                        unsigned buf_index,
                                        size_t offset,
                                        size_t len,
                                        SocketAsync_Callback cb,
                                        void *user_data,
                                        SocketAsync_Flags flags);

/**
 * @brief Receive into a pre-registered fixed buffer.
 * @ingroup async_io
 * @param[in] async Async context.
 * @param[in] socket Target socket.
 * @param[in] buf_index Index into registered buffer array.
 * @param[in] offset Offset within the buffer to receive into.
 * @param[in] len Maximum bytes to receive.
 * @param[in] cb Completion callback.
 * @param[in] user_data User data for callback.
 * @param[in] flags Operation flags (ASYNC_FLAG_FIXED_BUFFER added
 * automatically).
 * @return Request ID on success, 0 on failure.
 *
 * Uses IORING_OP_RECV_FIXED for zero-copy receive into registered buffer.
 *
 * @throws SocketAsync_Failed if buf_index out of range or buffers not
 * registered.
 * @threadsafe Yes.
 * @see SocketAsync_register_buffers() to register buffer pool.
 */
extern unsigned SocketAsync_recv_fixed (T async,
                                        Socket_T socket,
                                        unsigned buf_index,
                                        size_t offset,
                                        size_t len,
                                        SocketAsync_Callback cb,
                                        void *user_data,
                                        SocketAsync_Flags flags);

/* ==================== Fixed Files API ==================== */

/**
 * @brief Register file descriptors for faster kernel lookup.
 * @ingroup async_io
 * @param[in] async Async context.
 * @param[in] fds Array of file descriptors to register.
 * @param[in] count Number of file descriptors.
 * @return 0 on success, -1 on failure.
 *
 * Pre-registers file descriptors with io_uring using IORING_REGISTER_FILES.
 * Subsequent operations can use fixed file indices for 5-10% faster fd lookup
 * in the kernel, beneficial for connection pools with stable fd sets.
 *
 * Use SocketAsync_get_fixed_fd_index() to get the index for a registered fd,
 * then pass that index to SocketAsync_send/recv with ASYNC_FLAG_FIXED_FD.
 *
 * @note io_uring only; returns -1 with ENOTSUP on other backends.
 * @note File descriptors must remain open until unregistered.
 *
 * ## Example
 *
 * @code{.c}
 * // Register pool connection fds
 * int fds[MAX_POOL_SIZE];
 * for (int i = 0; i < pool_size; i++) {
 *     fds[i] = Socket_fd(pool_connections[i]);
 * }
 *
 * if (SocketAsync_register_files(async, fds, pool_size) == 0) {
 *     printf("Registered %d fds for fixed file operations\n", pool_size);
 * }
 * @endcode
 *
 * @threadsafe Yes.
 * @see SocketAsync_unregister_files()
 * @see SocketAsync_update_registered_fd()
 */
extern int SocketAsync_register_files (T async, int *fds, unsigned count);

/**
 * @brief Unregister previously registered file descriptors.
 * @ingroup async_io
 * @param[in] async Async context.
 * @return 0 on success, -1 on failure.
 * @threadsafe Yes.
 */
extern int SocketAsync_unregister_files (T async);

/**
 * @brief Update a single registered file descriptor.
 * @ingroup async_io
 * @param[in] async Async context.
 * @param[in] index Index in the registered fd array to update.
 * @param[in] new_fd New file descriptor to register at this index (-1 to
 * clear).
 * @return 0 on success, -1 on failure.
 *
 * Allows dynamic updating of the registered fd table without re-registering
 * the entire set. Useful for connection pool fd recycling.
 *
 * @threadsafe Yes.
 * @see SocketAsync_register_files()
 */
extern int
SocketAsync_update_registered_fd (T async, unsigned index, int new_fd);

/**
 * @brief Get the fixed file index for a registered fd.
 * @ingroup async_io
 * @param[in] async Async context.
 * @param[in] fd File descriptor to look up.
 * @return Fixed file index (>=0) if found, -1 if not registered.
 *
 * @threadsafe Yes - read-only lookup.
 */
extern int SocketAsync_get_fixed_fd_index (const T async, int fd);

/**
 * @brief Check if files are currently registered.
 * @ingroup async_io
 * @param[in] async Async context.
 * @return Number of registered file descriptors, or 0 if none.
 * @threadsafe Yes.
 */
extern unsigned SocketAsync_registered_file_count (const T async);

/* ==================== io_uring Availability API ==================== */

/**
 * @brief io_uring kernel version information.
 * @ingroup async_io
 *
 * Contains kernel version info and io_uring feature availability.
 */
typedef struct SocketAsync_IOUringInfo
{
  int major;        /**< Kernel major version (e.g., 5) */
  int minor;        /**< Kernel minor version (e.g., 10) */
  int patch;        /**< Kernel patch version (e.g., 0) */
  int supported;    /**< 1 if io_uring is supported (kernel 5.1+) */
  int full_support; /**< 1 if full features available (kernel 5.6+) */
  int compiled;     /**< 1 if library was compiled with io_uring support */
} SocketAsync_IOUringInfo;

/**
 * @brief Check io_uring availability and kernel version.
 * @ingroup async_io
 * @param[out] info Optional: filled with version info (may be NULL).
 * @return 1 if io_uring is available and usable, 0 otherwise.
 *
 * Checks both compile-time support (SOCKET_HAS_IO_URING) and runtime kernel
 * version. io_uring requires Linux kernel 5.1+ for basic support and 5.6+
 * for full features (multi-shot, SQPOLL, registered buffers).
 *
 * When info is provided, fills in kernel version and feature flags.
 *
 * @threadsafe Yes - read-only system call.
 * @complexity O(1) - single uname() call, cached after first invocation.
 *
 * ## Example
 *
 * @code{.c}
 * SocketAsync_IOUringInfo info;
 * if (SocketAsync_io_uring_available(&info)) {
 *     printf("io_uring available: kernel %d.%d.%d\n",
 *            info.major, info.minor, info.patch);
 *     if (info.full_support) {
 *         printf("Full io_uring features (5.6+)\n");
 *     } else {
 *         printf("Basic io_uring (5.1-5.5)\n");
 *     }
 * } else {
 *     if (!info.compiled) {
 *         printf("Library built without io_uring support\n");
 *     } else {
 *         printf("Kernel %d.%d.%d too old for io_uring\n",
 *                info.major, info.minor, info.patch);
 *     }
 * }
 * @endcode
 *
 * @note This checks kernel capability, not actual io_uring ring creation.
 * @see SOCKET_HAS_IO_URING - Compile-time flag in SocketConfig.h.
 * @see SocketAsync_backend_available() - General backend availability check.
 */
extern int SocketAsync_io_uring_available (SocketAsync_IOUringInfo *info);

/**
 * @brief Get the notification file descriptor for async completion events.
 * @ingroup async_io
 * @param[in] async Async context.
 * @return File descriptor for completion notifications, or -1 if unavailable.
 *
 * Returns the eventfd used by io_uring to signal operation completions.
 * This fd can be registered with a poll backend (epoll/kqueue) to wake up
 * the event loop when async operations complete, enabling timely timer
 * processing and callback delivery.
 *
 * When the returned fd becomes readable, call SocketAsync_process_completions()
 * to process pending completions and invoke callbacks.
 *
 * @threadsafe Yes - read-only access.
 * @complexity O(1)
 *
 * ## Example
 *
 * @code{.c}
 * int notify_fd = SocketAsync_get_notification_fd(async);
 * if (notify_fd >= 0) {
 *     // Register with epoll for POLLIN events
 *     epoll_ctl(epfd, EPOLL_CTL_ADD, notify_fd, &ev);
 * }
 * @endcode
 *
 * @note Returns -1 if async is NULL, not available, or backend doesn't use
 * eventfd.
 * @see SocketAsync_process_completions() to handle notifications.
 * @see SocketPoll_wait() automatically integrates this for poll-managed async.
 */
extern int SocketAsync_get_notification_fd (const T async);

#undef T

/** @} */ // end of async_io group

#endif

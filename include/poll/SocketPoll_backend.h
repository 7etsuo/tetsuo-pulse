/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETPOLL_BACKEND_INCLUDED
#define SOCKETPOLL_BACKEND_INCLUDED

/**
 * @defgroup event_system_backend Polling Backend Interface
 * @brief Internal platform abstraction for efficient I/O event multiplexing.
 * @ingroup event_system
 *
 * This module provides the backend interface that abstracts platform-specific
 * polling mechanisms (epoll, kqueue, poll) into a uniform API used by
 * SocketPoll. Designed for backend implementors; applications use SocketPoll
 * directly.
 *
 * ## Architecture Overview
 *
 * ```
 * ┌──────────────────────────────────┐
 * │       SocketPoll_T (Public)      │
 * │   add() mod() del() wait()       │
 * └─────────┬────────────────────────┘
 *           │ delegates to
 * ┌─────────▼────────────────────────┐
 * │     PollBackend_T (Internal)     │
 * │ backend_add() backend_wait() etc.│
 * └─────────┬────────────────────────┘
 *           │ platform-specific
 * ┌─────────▼────────────────────────┐
 * │   System Calls (epoll/kqueue/    │
 * │            poll)                 │
 * └──────────────────────────────────┘
 * ```
 *
 * ## Backend Implementations
 *
 * | Backend | Primary Platforms     | Trigger Type | Key Advantages |
 * |---------|-----------------------|--------------|---------------------------------|
 * | epoll   | Linux (2.6.8+)        | Edge         | High performance, low
 * overhead  | | kqueue  | BSD, macOS, FreeBSD   | Edge         | Scalable,
 * supports files/timers | | poll    | All POSIX systems     | Level        |
 * Portable, no special privileges |
 *
 * ## Selection Strategy
 *
 * - Compile-time auto-detection via CMake
 * - Prioritizes high-performance backends when available
 * - Fallback to portable poll for unsupported platforms
 *
 * ## Interface Guarantees
 *
 * - Identical API across all backends
 * - errno-based error reporting (POSIX standard)
 * - Arena_T memory management for lifecycle control
 * - Event translation to SocketPoll_Events bitmasks
 * - No thread-safety in backends; SocketPoll provides mutex
 *
 * ## Implementation Requirements
 *
 * - Use VALIDATE_MAXEVENTS and VALIDATE_FD macros
 * - Handle EINTR signals gracefully
 * - Support all SocketPoll_Events (READ, WRITE, ERROR, HANGUP)
 * - Implement backend_name() for diagnostics
 * - Ensure idempotent del() operations
 *
 * ## Module Relationships
 *
 * - **Depends on**: @ref foundation (Arena_T), Socket.h (fd handling)
 * - **Used by**: SocketPoll module exclusively
 * - **Related to**: @ref async_io for advanced patterns
 *
 * @see SocketPoll.h for public API
 * @see @ref event_system for full event system
 * @see docs/ASYNC_IO.md for usage guides
 * @{
 */

/**
 * @file SocketPoll_backend.h
 * @brief Defines internal backend abstraction for cross-platform polling.
 * @ingroup event_system_backend
 *
 * Not part of public API - include SocketPoll.h for application use.
 * Backend implementors must provide epoll/kqueue/poll specific code in
 * src/poll/.
 *
 * @note Internal header; subject to change without notice.
 * @warning Backends assume non-threaded access; do not use concurrently.
 *
 * @see @ref event_system_backend for interface details
 * @see PollBackend_T for opaque backend type
 */

#include "core/Arena.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"

/**
 * @brief Opaque handle for platform-specific polling backend implementation.
 * @ingroup event_system_backend
 *
 * Represents the platform-optimized polling mechanism (epoll/kqueue/poll)
 * abstracted into a uniform interface for SocketPoll. Handles fd registration,
 * event waiting, and notification delivery with platform-specific efficiency.
 *
 * ## Lifecycle Management
 *
 * - **Creation**: backend_new(arena, maxevents) - allocates from arena,
 * initializes platform resources (e.g., epoll_create)
 * - **Operations**: add/mod/del/wait via backend methods - monitor sockets and
 * retrieve events
 * - **Cleanup**: backend_free(backend) - releases platform resources (e.g.,
 * epoll_ctl delete all, close fd); memory freed by arena dispose
 * - **Destruction**: Arena_clear/dispose handles remaining memory;
 * backend_free must be called first for resource leak prevention
 *
 * ## Thread Safety
 *
 * @threadsafe No - Individual backends are not thread-safe. SocketPoll_T
 * enforces single-threaded access via internal mutex. Concurrent calls to the
 * same backend instance result in race conditions and undefined behavior.
 *
 * ## Key Characteristics
 *
 * - Opaque structure: Internal fields platform-specific (e.g., epoll_fd, event
 * array)
 * - Resource ownership: Owns platform fd (epoll/kqueue) but not monitored
 * socket fds
 * - Error handling: Sets errno on failures (EINVAL, ENOMEM, EBADF, etc.)
 * - Event capacity: Fixed at creation (maxevents); resize requires new backend
 *
 * ## Usage Patterns (Internal)
 *
 * Backends are exclusively used within SocketPoll implementations:
 *
 * @code{.c}
 * // Typical backend lifecycle in poll module
 * static PollBackend_T
 * create_backend(Arena_T arena, int maxevents) {
 *     VALIDATE_MAXEVENTS(maxevents, struct epoll_event);  // or equivalent
 *     PollBackend_T backend = backend_new(arena, maxevents);
 *     if (backend == NULL) {
 *         // errno set (ENOMEM, EINVAL)
 *         return NULL;
 *     }
 *     return backend;
 * }
 *
 * // Event loop integration
 * int nfds = backend_wait(backend, timeout_ms);
 * if (nfds < 0) {
 *     // errno: EINTR, EINVAL
 *     return -1;
 * }
 * for (int i = 0; i < nfds; ++i) {
 *     int fd; unsigned events;
 *     if (backend_get_event(backend, i, &fd, &events) == 0) {
 *         // Process fd + events (translate to SocketEvent_T)
 *         handle_event(fd, events);
 *     }
 * }
 * @endcode
 *
 * @warning Failing to call backend_free() before arena dispose leaks platform
 * resources (fd descriptors)
 * @note Use backend_name() for logging/diagnostics (e.g., "Using epoll
 * backend")
 * @note Backends automatically handle EINTR; no manual restart needed
 * @note For high-load servers, set maxevents to expected concurrent
 * connections
 *
 * @complexity Creation: O(maxevents) - allocates event array; Operations: O(1)
 * avg / O(n) worst
 *
 * @see backend_new() for instantiation
 * @see backend_free() for cleanup
 * @see @ref event_system_backend for full backend interface
 * @see VALIDATE_MAXEVENTS() for safe initialization
 * @see SocketPoll_T for public wrapper that manages backends
 * @see docs/ASYNC_IO.md for event-driven server patterns
 */
typedef struct PollBackend_T *PollBackend_T;

/**
 * @brief Safeguard macro for validating maxevents against invalid values and
 * overflow risks.
 * @ingroup event_system_backend
 *
 * Essential defensive programming macro invoked at backend initialization to
 * validate the maximum event capacity parameter. Mitigates potential integer
 * overflow in memory allocations for event structures and blocks zero/negative
 * values that could lead to denial-of-service or undefined behavior.
 *
 * ## Validation Criteria
 *
 * | Condition                  | Action                  | errno Set To |
 * |----------------------------|-------------------------|--------------|
 * | maxevents <= 0             | Return from caller      | EINVAL      |
 * | maxevents > SIZE_MAX / sizeof(event_type) | Return from caller | EOVERFLOW
 * |
 *
 * The macro performs safe casting to size_t and uses division to detect
 * potential overflow before any allocation occurs.
 *
 * ## Error Propagation
 *
 * Sets appropriate errno and executes 'return NULL;' (assumes caller returns
 * pointer). For functions returning int, adjust manually or use variant macro.
 *
 * @param[in] maxevents Integer value representing desired maximum events
 * (checked > 0).
 * @param[in] event_type Type of event structure (used solely for sizeof() in
 * overflow check).
 *
 * @note No return value - macro either validates successfully (no-op) or
 * aborts function via return.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // In platform-specific backend_new() e.g., epoll backend
 * #include <limits.h>  // for SIZE_MAX
 *
 * PollBackend_T
 * epoll_backend_new(Arena_T arena, int maxevents) {
 *     VALIDATE_MAXEVENTS(maxevents, struct epoll_event);
 *
 *     // Safe to allocate now
 *     void *mem = Arena_alloc(arena, sizeof(struct EpollBackend));
 *     if (mem == NULL) {
 *         errno = ENOMEM;
 *         return NULL;
 *     }
 *     struct EpollBackend *self = mem;
 *
 *     // Allocate event array
 *     self->events = Arena_calloc(arena, 1, maxevents * sizeof(struct
 * epoll_event), __FILE__, __LINE__); if (self->events == NULL) { errno =
 * ENOMEM; return NULL;
 *     }
 *
 *     // Initialize epoll fd
 *     self->epfd = epoll_create1(EPOLL_CLOEXEC);
 *     if (self->epfd < 0) {
 *         // errno set by epoll_create1 (e.g., EMFILE, ENFILE)
 *         return NULL;
 *     }
 *     // ... continue initialization
 * }
 * @endcode
 *
 * @complexity O(1) - Constant-time integer operations and comparisons.
 *
 * @warning Without this macro, large maxevents could cause Arena_alloc()
 * overflow and heap corruption.
 * @note Compatible with C11 _Static_assert if desired for compile-time checks
 * on event_type size.
 * @note EOVERFLOW defined in POSIX.1-2008; some systems may require <errno.h>
 * explicitly.
 *
 * @see VALIDATE_FD(fd) complementary macro for fd validation
 * @see backend_new() all implementations must invoke this early
 * @see SIZE_MAX limit in <limits.h> or <stdint.h>
 * @see Arena_alloc() / Arena_calloc() for validated allocation
 * @see SocketPoll_new() public API that indirectly uses this validation
 */
#ifndef VALIDATE_MAXEVENTS
#define VALIDATE_MAXEVENTS(maxevents, event_type)                             \
  do                                                                          \
    {                                                                         \
      if ((size_t)(maxevents) <= 0)                                           \
        {                                                                     \
          errno = EINVAL;                                                     \
          return NULL;                                                        \
        }                                                                     \
      if ((size_t)(maxevents) > SIZE_MAX / sizeof (event_type))               \
        {                                                                     \
          errno = EOVERFLOW;                                                  \
          return NULL;                                                        \
        }                                                                     \
    }                                                                         \
  while (0)
#endif

/* ==================== Common Backend Macros ==================== */

/**
 * @brief Convert milliseconds to timespec for kqueue/poll backends.
 * @ingroup event_system_backend
 *
 * Common helper to avoid code duplication between kqueue and poll backends
 * which both need to convert millisecond timeouts to timespec structures.
 * Uses constants from SocketConfig.h for the conversion.
 *
 * @param[in] timeout_ms Timeout in milliseconds (must be >= 0).
 * @param[out] ts Pointer to timespec structure to populate.
 *
 * @note Only call when timeout_ms >= 0; infinite wait (-1) should bypass.
 * @note Uses SOCKET_MS_PER_SECOND and SOCKET_NS_PER_MS from SocketConfig.h.
 *
 * @see backend_wait() in kqueue and poll backends.
 * @see SOCKET_MS_PER_SECOND time conversion constant.
 * @see SOCKET_NS_PER_MS nanosecond conversion constant.
 */
#define TIMEOUT_MS_TO_TIMESPEC(timeout_ms, ts)                                \
  do                                                                          \
    {                                                                         \
      (ts)->tv_sec = (timeout_ms) / SOCKET_MS_PER_SECOND;                     \
      (ts)->tv_nsec                                                           \
          = ((timeout_ms) % SOCKET_MS_PER_SECOND) * SOCKET_NS_PER_MS;         \
    }                                                                         \
  while (0)

/**
 * @brief Essential macro to validate file descriptors before backend system
 * calls.
 * @ingroup event_system_backend
 *
 * Defensive check ensuring fd parameters to backend functions are valid (>=0)
 * prior to platform invocations like epoll_ctl or kevent. Prevents propagation
 * of uninitialized or erroneous fds that could lead to system call failures
 * or resource leaks.
 *
 * ## Validation Details
 *
 * Single condition: fd >= 0 (standard POSIX requirement for valid fds).
 *
 * Failure mode: errno = EBADF; return -1; (tailored for int-returning
 * functions).
 *
 * @param[in] fd Candidate file descriptor to verify as non-negative.
 *
 * @note Macro effect: Conditional return -1 with errno set; no explicit return
 * value.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Universal pattern in backend_add/mod/del
 * int backend_add(PollBackend_T self, int fd, unsigned events) {
 *     VALIDATE_FD(fd);  // Early exit if fd < 0
 *
 *     // Safe to proceed with platform call
 *     // e.g., for kqueue:
 *     struct kevent kev[2];
 *     EV_SET(&kev[0], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
 *     EV_SET(&kev[1], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, NULL);
 *     int nchanges = (events & POLL_READ) ? 1 : 0;
 *     nchanges += (events & POLL_WRITE) ? 1 : 0;
 *     if (kevent(self->kqueue_fd, kev, nchanges, NULL, 0, NULL) < 0) {
 *         return -1;  // errno from kevent (e.g., EBADF if fd invalid despite
 * check)
 *     }
 *     return 0;
 * }
 * @endcode
 *
 * @complexity O(1) - Trivial integer comparison.
 *
 * @warning Skipping this can result in erratic platform behavior (e.g.,
 * epoll_ctl ignoring invalid fd silently in some cases).
 * @note Does not check if fd refers to a socket or is open; use fcntl(fd,
 * F_GETFD, 0) >= 0 for full validity (costly).
 * @note Integrates with Socket_fd(Socket_T) which guarantees >=0 for valid
 * sockets.
 *
 * @see VALIDATE_MAXEVENTS() for event capacity checks
 * @see backend_add() / backend_mod() / backend_del() - must call this first
 * @see Socket_fd() library function providing validated fds
 * @see errno(3) for EBADF details
 * @see SocketPoll_add() public method invoking backend_add indirectly
 */
#define VALIDATE_FD(fd)                                                       \
  do                                                                          \
    {                                                                         \
      if ((fd) < 0)                                                           \
        {                                                                     \
          errno = EBADF;                                                      \
          return -1;                                                          \
        }                                                                     \
    }                                                                         \
  while (0)

/**
 * @defgroup backend_functions Backend Function API
 * @brief Essential functions for polling backend operations and lifecycle.
 * @ingroup event_system_backend
 *
 * Encapsulates the full backend contract: initialization, socket management,
 * event polling, and teardown. Ensures uniform behavior across platform
 * backends while allowing optimized implementations.
 *
 * ## Backend Selection & Platform Mapping
 *
 * | Priority | Backend | Platforms/Requirements | Trigger Mode | Notes |
 * |----------|---------|------------------------|--------------|-------|
 * | 1        | epoll   | Linux >= 2.6.8         | Edge         | Requires
 * CAP_SYS_NICE? No; O(1) ops | | 2        | kqueue  | BSD/macOS/FreeBSD      |
 * Edge         | Supports > fds (files/signals) | | 3        | poll    | Any
 * POSIX              | Level        | Simple, but scans all fds each wait |
 *
 * Selection via CMake (autoconf-like probes); logs via backend_name().
 *
 * ## API Contract Summary
 *
 * - **Success**: 0 or valid pointer
 * - **Failure**: -1 / NULL + errno (no exceptions; caller checks errno)
 * - **Memory**: Arena_T owned; backend_free closes fds only
 * - **Threads**: @threadsafe No per function; SocketPoll serializes calls
 * - **Events**: Bitmask translation mandatory (POLL_* -> platform equiv)
 * - **Cleanup**: Idempotent; safe post-arena dispose but recommended before
 *
 * ## Common Error Codes (errno)
 *
 * | errno  | Context | Description |
 * |--------|---------|-------------|
 * | EBADF  | add/mod/del/get | Invalid/closed fd |
 * | EINVAL | params | Bad maxevents, events mask, index out-of-bounds |
 * | ENOMEM | new/alloc | Arena allocation failure |
 * | EMFILE | new/wait | Per-process fd limit hit |
 * | ENFILE | new/wait | System-wide fd table full |
 * | EINTR  | wait    | Signal interrupted; retry recommended |
 * | EAGAIN | wait    | Non-blocking timeout (0 ms) |
 *
 * ## Implementation Guidelines
 *
 * - **Validation**: Mandatory VALIDATE_FD(fd) in add/mod/del;
 * VALIDATE_MAXEVENTS in new
 * - **EINTR**: Wait loops should retry or propagate (no infinite loops)
 * - **Event Completeness**: Map all platform events incl. errors/hangups/pri
 * changes
 * - **Efficiency**: Minimize syscalls; batch where possible (e.g., poll no
 * batch needed)
 * - **Debug**: backend_name() for runtime identification/logging
 * - **Portability**: Use #ifdefs for platform features (e.g., EPOLLEXCLUSIVE)
 *
 * @note Functions are internal; exposed only for backend .c files (epoll.c
 * etc.)
 * @warning Partial implementations risk missed events or resource leaks
 * @note Integrate with SocketLog for error diagnostics in backends
 *
 * @see PollBackend_T handle type
 * @see SocketPoll_Events unified event types
 * @see @ref event_system_backend module overview
 * @see VALIDATE_* macros for input sanitization
 * @see docs/ASYNC_IO.md event loop best practices
 */

/**
 * @brief Allocate and initialize a platform-optimized polling backend.
 * @ingroup backend_functions
 *
 * Creates backend instance with platform-specific resources (e.g., epoll fd,
 * kqueue descriptor, pollfd array). Allocates internal state and event buffer
 * from arena. Performs essential validations to ensure safe operation.
 *
 * Detailed behavior:
 * - Calls VALIDATE_MAXEVENTS internally
 * - Initializes platform polling structure
 * - Prepares event translation arrays if needed
 * - Returns opaque handle ready for socket registration
 *
 * @param[in] arena Arena_T for backend memory (structure + event array; not
 * freed by backend_free).
 * @param[in] maxevents Maximum simultaneous events supported (affects buffer
 * size; >0 required).
 *
 * @return Opaque PollBackend_T on success; NULL on error (errno set, partial
 * allocations cleaned by arena).
 *
 * Error conditions:
 * - EINVAL: Invalid maxevents (<=0 or overflow with event_type size)
 * - ENOMEM: Failed to allocate from arena
 * - EMFILE / ENFILE / EACCES: Platform init failure (e.g., epoll_create1)
 *
 * @threadsafe Yes - Creates isolated instance; safe from any thread (arena
 * must be thread-local or locked).
 *
 * ## Basic Usage (Internal)
 *
 * @code{.c}
 * // Example in backend factory function
 * PollBackend_T
 * init_backend(Arena_T arena, int max_ev) {
 *     PollBackend_T b = backend_new(arena, max_ev);
 *     if (b == NULL) {
 *         const char *err = Socket_safe_strerror(errno);
 *         SOCKET_LOG_ERROR_MSG("backend_new failed: %s", err);
 *         return NULL;
 *     }
 *     SOCKET_LOG_DEBUG_MSG("Initialized %s backend (maxevents=%d)",
 * backend_name(), max_ev); return b;
 * }
 * @endcode
 *
 * ## With Error Handling
 *
 * @code{.c}
 * TRY {
 *     self->backend = backend_new(self->arena, SOCKET_POLL_DEFAULT_MAXEVENTS);
 *     SocketMetrics_increment(METRIC_BACKEND_CREATED, 1);
 * } EXCEPT_ANY {
 *     // Except frame catches errno via wrapper? Or manual
 *     self->backend = NULL;
 *     RAISE(SocketPoll_Failed);
 * } FINALLY {
 *     // No cleanup needed on success/failure (arena owns mem)
 * } END_TRY;
 * @endcode
 *
 * @complexity O(maxevents) - Time and space for event buffer
 * allocation/zeroing.
 *
 * @note Caller responsible for backend_free() before arena_clear/dispose to
 * release OS fds.
 * @warning Oversized maxevents wastes arena memory; undersized limits
 * scalability.
 * @note Logs creation via SocketLog if enabled (debug level).
 *
 * @see backend_free() for resource release (closes platform fd)
 * @see VALIDATE_MAXEVENTS() internal validation mechanism
 * @see backend_name() to identify created backend type
 * @see SocketPoll_new() typical consumer in public API
 * @see Arena_T docs/foundation for allocation details
 */
extern PollBackend_T backend_new (Arena_T arena, int maxevents);

/**
 * @brief Perform backend cleanup: close platform resources but retain arena
 * memory.
 * @ingroup backend_functions
 *
 * Releases OS-level resources managed by the backend (e.g., epoll fd close,
 * kqueue unregister all, pollfd array discard). Memory structures remain
 * allocated in arena until Arena_clear/dispose. Idempotent operation.
 *
 * Post-call: Backend unusable for further operations; set to NULL recommended.
 *
 * @param[in] backend Backend instance whose resources to release (may be NULL
 * - no-op).
 *
 * @note Void return - best-effort cleanup; platform close errors logged/not
 * propagated.
 * @note Call before arena disposal to prevent fd exhaustion on reuse.
 * @note Internal state reset; safe for multiple invocations on same instance.
 *
 * Potential side effects:
 * - All registered fds automatically unmanaged (no explicit del needed)
 * - errno may be set by close but ignored (leak already occurred)
 *
 * @threadsafe Partial - Safe if serialized; concurrent with active wait/add
 * risky.
 *
 * ## Standard Usage Pattern
 *
 * @code{.c}
 * // Cleanup in SocketPoll destructor or error path
 * if (self->backend != NULL) {
 *     backend_free(self->backend);
 *     self->backend = NULL;  // Defensive nulling
 *     SOCKET_LOG_INFO_MSG("Released %s backend resources", backend_name());
 * }
 * // Optional: Arena_clear(self->arena);  // If reusing arena
 * @endcode
 *
 * ## In Error Handling Context
 *
 * @code{.c}
 * TRY {
 *     // ... operations using backend ...
 * } FINALLY {
 *     if (backend) {
 *         backend_free(backend);  // Ensure fd close even on exceptions
 *         backend = NULL;
 *     }
 * } END_TRY;
 * @endcode
 *
 * @complexity O(1) average; O(registered_sockets) worst-case for explicit
 * unreg (e.g., epoll del all).
 *
 * @warning Without this, arena reuse accumulates leaked fds leading to
 * EMFILE/ENFILE.
 * @note Integrates with Socket_debug_live_count() indirectly via fd tracking.
 * @note No metrics emitted; caller should increment METRIC_BACKEND_FREED if
 * tracking.
 *
 * @see backend_new() initialization pair
 * @see Arena_dispose() / Arena_clear() for memory lifecycle
 * @see SocketPoll_free() typical invocation site
 * @see backend_name() for logging freed backend type
 */
extern void backend_free (PollBackend_T backend);

/**
 * @brief Register file descriptor for I/O event notifications.
 * @ingroup backend_functions
 *
 * Associates the given fd with the backend for monitoring specified events.
 * Performs translation of generic SocketPoll_Events to platform-specific flags
 * (e.g., POLLIN/EPOLLIN for read readiness). Idempotent if fd already present.
 *
 * Pre-conditions:
 * - fd non-blocking (enforced by SocketPoll_add)
 * - Backend initialized and not freed
 * - Events valid bitmask subset
 *
 * @param[in] backend Initialized PollBackend_T instance.
 * @param[in] fd Open file descriptor to watch (socket, pipe, etc.; >=0
 * validated).
 * @param[in] events Requested events as bitmask (POLL_READ | POLL_WRITE;
 * others implicit).
 *
 * @return 0 on successful registration/update; -1 on error (errno set).
 *
 * Typical errors:
 * - EBADF: fd invalid or closed
 * - EINVAL: Invalid events (e.g., unknown bits) or backend error state
 * - EPERM / EACCES: fd permissions prevent monitoring
 * - ENOMEM: Backend internal tracking allocation
 * - Platform: EEXIST (already added), ENOSYS (unsupported)
 *
 * @threadsafe No - Modifies shared backend state; SocketPoll mutex required.
 *
 * ## Integration Example
 *
 * @code{.c}
 * // Internal backend_add with logging/validation
 * int backend_add(PollBackend_T self, int fd, unsigned events) {
 *     VALIDATE_FD(fd);
 *
 *     // Translate events (platform-specific)
 *     int plat_events = 0;
 *     if (events & POLL_READ) plat_events |= EPOLLIN | EPOLLPRI | EPOLLERR |
 * EPOLLHUP; if (events & POLL_WRITE) plat_events |= EPOLLOUT;
 *
 *     struct epoll_event ev = { .events = plat_events, .data.fd = fd };
 *     if (epoll_ctl(self->epfd, fd_already_registered ? EPOLL_CTL_MOD :
 * EPOLL_CTL_ADD, fd, &ev) < 0) { int err = errno;
 *         SOCKET_LOG_WARN_MSG("epoll_ctl(%d, %s) failed for fd=%d: %s",
 *                             self->epfd, fd_already ? "MOD" : "ADD", fd,
 * strerror(err)); errno = err; return -1;
 *     }
 *     // Update internal count/tracking
 *     self->registered_count++;
 *     return 0;
 * }
 * @endcode
 *
 * @complexity O(1) - Single platform registration call (epoll_ctl O(1), poll
 * O(n) scan but amortized).
 *
 * @note POLL_ERROR and POLL_HANGUP detected implicitly by platform (no
 * explicit flag needed).
 * @note Caller must handle edge cases like fd closure during monitoring
 * (backend del on close).
 * @warning Monitoring non-socket fds (files) may not work as expected on all
 * platforms.
 * @note Metrics: Caller should track added fds for capacity monitoring.
 *
 * @see backend_mod() for event reconfiguration
 * @see backend_del() for unregistration
 * @see VALIDATE_FD() prerequisite validation
 * @see SocketPoll_add() / SocketPoll_mod() public wrappers
 * @see Socket_setnonblocking() ensures compatibility
 */
extern int backend_add (PollBackend_T backend, int fd, unsigned events);

/**
 * @brief Update event monitoring configuration for existing file descriptor.
 * @ingroup backend_functions
 *
 * Changes the set of events watched for a previously registered fd without
 * full deregistration/re-registration. Optimizes for backends supporting
 * direct modification (epoll_ctl MOD, kevent ADD/DELETE combo). Falls back to
 * del+add if not supported (poll backend).
 *
 * Behavior:
 * - Validates fd presence implicitly (error if not registered in some
 * backends)
 * - Translates new events bitmask to platform flags
 * - Preserves other fd state (data ptr if used)
 *
 * @param[in] backend Active backend with fd already registered.
 * @param[in] fd Registered file descriptor to reconfigure (>=0 validated).
 * @param[in] events Updated event mask (POLL_READ, POLL_WRITE, or both; clears
 * others).
 *
 * @return 0 success (events updated); -1 failure (errno set).
 *
 * Errors:
 * - EBADF / ENOENT: fd not registered or invalid
 * - EINVAL: Invalid new events or platform limit
 * - ENOMEM: Temporary allocation for mod operation
 * - Platform: e.g., EOPNOTSUPP if mod unsupported
 *
 * @threadsafe No - Alters shared registration state; requires locking.
 *
 * ## Usage Pattern
 *
 * @code{.c}
 * // Dynamic event adjustment e.g., after socket state change
 * int update_events(PollBackend_T backend, int fd, unsigned new_evs) {
 *     VALIDATE_FD(fd);
 *
 *     // Check current vs new for optimization
 *     unsigned current_evs = get_current_events(backend, fd);  // Internal
 * query if (new_evs == current_evs) return 0;  // No-op
 *
 *     if (backend_mod(backend, fd, new_evs) < 0) {
 *         // Fallback: del then add
 *         backend_del(backend, fd);
 *         return backend_add(backend, fd, new_evs);
 *     }
 *     return 0;
 * }
 * @endcode
 *
 * @complexity O(1) - Direct mod syscall; O(n) fallback for poll.
 *
 * @note More efficient than del+add cycle (avoids re-translation/state reset).
 * @note Not all events need explicit set; platforms infer ERROR/HUP.
 * @warning Modifying closed fd triggers error events; handle in loop.
 * @note Use after Socket_setnodelay or timeout changes if affecting readiness.
 *
 * @see backend_add() for initial add (use if unregistered)
 * @see backend_del() for complete removal
 * @see VALIDATE_FD() entry validation
 * @see SocketPoll_mod() public equivalent
 * @see backend_wait() observes updated events
 */
extern int backend_mod (PollBackend_T backend, int fd, unsigned events);

/**
 * @brief Remove socket from poll set.
 * @ingroup event_system
 * @param backend Backend instance.
 * @param fd File descriptor to remove.
 * @return 0 on success, -1 on failure (sets errno).
 * @note Should succeed silently if fd not in set (idempotent operation).
 * @note Validates fd parameter before backend operations.
 * @see VALIDATE_FD for file descriptor validation.
 * @see backend_add() for registration.
 * @see backend_mod() for modification.
 */
extern int backend_del (PollBackend_T backend, int fd);

/**
 * @brief Wait for events.
 * @ingroup event_system
 * @param backend Backend instance (modifies internal events array for output).
 * @param timeout_ms Timeout in milliseconds (-1 for infinite, 0 for
 * immediate).
 * @return Number of events ready (>= 0), or -1 on error (sets errno).
 * @note Returns 0 on timeout, EINTR (signal interrupt), or immediate return.
 * @note Internal event array updated for backend_get_event() retrieval.
 * @note Thread-safe: Assumes single-threaded access via SocketPoll mutex.
 * @see backend_get_event() for retrieving event details.
 * @see backend_add() for socket registration.
 * @see SocketPoll_wait() for public interface that calls this.
 */
extern int backend_wait (PollBackend_T backend, int timeout_ms);

/**
 * @brief Get event details for index.
 * @ingroup event_system
 * @param backend Backend instance (const - read-only access to events array).
 * @param index Event index (0 to count-1 from backend_wait return value).
 * @param fd_out Output parameter - file descriptor that triggered event.
 * @param events_out Output parameter - events that occurred (POLL_READ |
 * POLL_WRITE).
 * @return 0 on success, -1 on invalid index.
 * @threadsafe Yes - Read-only access to backend's internal event array.
 * @note Called repeatedly by SocketPoll to translate backend events to
 * SocketEvent_T.
 * @note Used in event translation pipeline: fd -> events -> SocketEvent_T.
 * @see backend_wait() for event waiting that populates the array.
 * @see SocketPoll_Events for event type definitions.
 * @see SocketEvent_T for translated event structure.
 * @see SocketPoll_wait() for complete event processing pipeline.
 */
extern int backend_get_event (const PollBackend_T backend, int index,
                              int *fd_out, unsigned *events_out);

/**
 * @brief Get human-readable backend name for debugging and logging.
 * @ingroup event_system
 * @return Static string identifying the backend ("epoll", "kqueue", or
 * "poll").
 * @note Returned string is compile-time constant and safe for repeated calls.
 * @note Useful for logging backend-specific behavior and performance
 * characteristics.
 * @note Helps identify active backend for platform-specific issue diagnosis.
 * @note Never NULL - always returns valid string for current backend.
 * @see backend_new() for compile-time backend selection logic.
 * @see SocketPoll_new() for backend initialization during poll creation.
 */
extern const char *backend_name (void);

/** @} */

#endif /* SOCKETPOLL_BACKEND_INCLUDED */

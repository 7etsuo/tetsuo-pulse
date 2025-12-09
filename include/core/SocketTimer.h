#ifndef SOCKETTIMER_INCLUDED
#define SOCKETTIMER_INCLUDED

#include "core/Except.h"
#include <stdint.h>

/**
 * @defgroup event_system Event System Modules
 * @brief High-performance I/O multiplexing with cross-platform backends
 *
 * Comprehensive event-driven I/O subsystem providing multiplexing, timers, and
 * async operations for scalable network servers and clients. Supports epoll
 * (Linux), kqueue (BSD/macOS), and poll (fallback) backends with automatic
 * selection. Timers integrate seamlessly with poll loops for timeout handling.
 *
 * ## Architecture Overview
 *
 * ```
 * ┌───────────────────────────────────────────────────────────┐
 * │                Application Layer                          │
 * │  SocketPool, SocketReconnect, SocketHTTPClient, Servers   │
 * └─────────────┬─────────────────────────────────────────────┘
 *              │ Uses / Integrates
 * ┌─────────────▼─────────────────────────────────────────────┐
 * │              Event System Layer                           │
 * │  SocketPoll (I/O multiplexing)                            │
 * │  SocketTimer (min-heap timers, O(log n))                  │
 * │  SocketAsync (non-blocking connect/accept)                │
 * └─────────────┬─────────────────────────────────────────────┘
 *              │ Depends on
 * ┌─────────────▼─────────────────────────────────────────────┐
 * │             Foundation Layer                              │
 * │  Arena, Except, SocketUtil, SocketConfig, Monotonic Time  │
 * └───────────────────────────────────────────────────────────┘
 * ```
 *
 * ## Module Relationships
 *
 * - **Depends on**: Foundation (@ref foundation) for memory allocation
 * (Arena), error handling (Except), utilities (SocketUtil), and global config.
 * - **Used by**: Connection management (@ref connection_mgmt) for idle
 * timeouts and drain scheduling; HTTP (@ref http) for request timeouts;
 * Security
 *   (@ref security) for protection sweeps.
 * - **Integration Points**: Timers fire during `SocketPoll_wait()`; async ops
 *   use poll for completion notification.
 * - **Thread Safety**: All operations thread-safe; callbacks execute in poll
 *   thread context.
 * - **Performance**: O(log n) timer operations; zero-copy event delivery.
 *
 * ## Key Features
 *
 * - Cross-platform poll backends with unified API
 * - Min-heap timers with lazy cancellation for efficiency
 * - Monotonic timestamps immune to clock adjustments
 * - Automatic SIGPIPE/EINTR handling
 * - Arena-managed memory for lifecycle control
 *
 * ## Platform Requirements
 *
 * - POSIX-compliant system (Unix/Linux/BSD/macOS)
 * - pthreads for thread safety (mutex protection)
 * - CLOCK_MONOTONIC support for accurate timing
 * - File descriptor limits sufficient for registered sockets/timers
 *
 * @see @ref foundation Base infrastructure dependencies
 * @see @ref connection_mgmt Connection pooling with timer integration
 * @see @ref http HTTP client/server timeout handling
 * @see docs/ASYNC_IO.md Detailed async patterns
 * @see docs/cross-platform-backends.md Backend selection and tuning
 * @{
 */

/**
 * @file SocketTimer.h
 * @ingroup event_system
 * @brief High-performance timer subsystem integrated with the event loop.
 *
 * Provides high-performance timer functionality integrated with the event
 * loop. Timers are stored in a min-heap for O(log n) insert/delete and O(1)
 * next-timer lookup. Timer callbacks fire automatically during
 * SocketPoll_wait().
 *
 * Features:
 * - One-shot and repeating timers
 * - Monotonic clock timestamps (immune to wall-clock changes)
 * - Integrated with SocketPoll event loop
 * - Thread-safe operations with mutex protection
 * - Arena-based memory management for efficient allocation
 *
 * Timing Precision:
 * - Uses CLOCK_MONOTONIC for timestamps (immune to NTP adjustments)
 * - Millisecond resolution for delays and intervals
 * - Timers may fire slightly after deadline due to event loop scheduling and
 * system load
 *
 * ## Default Values and Limits
 *
 * | Setting | Value | Description |
 * |---------|-------|-------------|
 * | Heap initial capacity | 16 | Starting size of internal timer array |
 * | Heap growth factor | 2x | Doubles capacity when full (amortized O(1)
 * append) | | Min one-shot delay | 0 ms | Allows immediate or near-immediate
 * firing | | Min repeating interval | 1 ms | Prevents zero-interval CPU spin |
 * | Max timers per poll | 100,000 | Compile-time limit to prevent DoS
 * (SOCKET_MAX_TIMERS_PER_HEAP) | | Max delay/interval | 365 days | Clamped to
 * prevent int64_t overflow (SOCKET_MAX_TIMER_DELAY_MS) | | Max poll timeout |
 * 300 seconds | Backend limit for long timers (SOCKET_MAX_TIMER_TIMEOUT_MS) |
 * | Timer ID start | 1 | Sequential uint64_t IDs, wraps rarely |
 *
 * Thread Safety:
 * - All public operations thread-safe via per-heap mutex
 * - Callbacks execute in SocketPoll_wait() calling thread context
 * - @warning Do not call SocketTimer_cancel() or SocketTimer_remaining() from
 * timer callbacks (may deadlock on mutex)
 * - Safe to create/cancel from any thread; firing serialized
 *
 * Limitations:
 * - Lazy cancellation: Cancelled timers removed only when reaching heap root
 * during processing (memory held until then)
 * - No support for sub-millisecond precision (system clock granularity)
 * - Heap resize allocates new array and copies (brief pause under mutex)
 * - Maximum timers limited to prevent memory exhaustion or DoS
 * - Timer expiry clamped on overflow; logged as warning
 * - Dependent on poll backend timeout limits for very long delays
 *
 * ## Usage Patterns
 *
 * ### Basic Event Loop with Timer
 *
 * @code{.c}
 * SocketPoll_T poll = SocketPoll_new(1024);
 * Arena_T arena = Arena_new();
 *
 * // Add timer
 * SocketTimer_T timer = SocketTimer_add(poll, 5000, cleanup_cb, userdata);
 *
 * // Event loop automatically handles timer firing
 * while (running) {
 *     int events = SocketPoll_wait(poll, &event_list, -1);
 *     // Process I/O events...
 *     // Timers fired during wait() if expired
 * }
 *
 * SocketPoll_free(&poll);
 * Arena_dispose(&arena);
 * @endcode
 *
 * ### Cleanup and Resource Management
 *
 * Timers are arena-allocated; dispose arena to free all timers in heap.
 * Cancel pending timers before arena dispose to avoid leaks if arena reused.
 *
 * @see SocketPoll_T for full event loop documentation.
 * @see SocketTimer_add() primary creation function.
 * @see @ref event_system for multiplexing and async integration.
 * @see SocketReconnect_T for backoff timer usage example.
 * @see docs/ASYNC_IO.md for advanced timer patterns in async ops.
 * @see SocketConfig.h for compile-time tuning of limits.
 */

/**
 * @brief Opaque pointer to a timer instance.
 * @ingroup event_system
 *
 * Represents a timer created by SocketTimer_add() or
 * SocketTimer_add_repeating(). Used to cancel the timer or query remaining
 * time via public API functions. Becomes invalid after the timer fires or is
 * cancelled; subsequent use leads to undefined behavior.
 *
 * @note Internal storage managed by per-poll heap (min-heap structure); not
 * direct pointer to struct SocketTimer_T.
 * @note Do not free or access directly; use SocketTimer_cancel() to
 * invalidate.
 * @warning Using invalid (fired/cancelled) timer handle in cancel/remaining
 * may return -1 or cause assertion failures in debug builds.
 * @threadsafe Handle valid only through thread-safe public functions;
 * concurrent access safe but serialized by mutex.
 *
 * @see SocketTimer_add() for creation
 * @see SocketTimer_add_repeating() for periodic timers
 * @see SocketTimer_cancel() for invalidation
 * @see SocketTimer_remaining() for time queries
 */
#define T SocketTimer_T
typedef struct T *T;
/**
 * @brief Opaque handle for event poll instance.
 * @ingroup event_system
 *
 * Forward declaration used for timer integration with SocketPoll.
 * Timers are scheduled and fired automatically during poll wait operations.
 *
 * @see SocketPoll.h for full documentation of poll operations.
 * @see SocketPoll_wait() for how timers are processed alongside I/O events.
 * @see SocketPoll_T for poll type details.
 */
struct SocketPoll_T;
typedef struct SocketPoll_T *SocketPoll_T;

/**
 * @brief Type for timer expiration callback functions.
 * @ingroup event_system
 * @param userdata Opaque user data provided at timer creation time.
 *
 * Invoked automatically when timer expires, during SocketPoll_wait() call.
 * Executes in the thread/context of the SocketPoll_wait() caller.
 *
 * @note Callback must complete promptly; long-running ops may block event
 * loop.
 * @note Must not call SocketTimer_cancel() on any timer in same heap (mutex
 * deadlock risk).
 * @note Safe for resource allocation/freeing within arena scope, but avoid
 * deep recursion.
 * @warning Avoid adding/cancelling timers recursively on the same heap to
 * prevent stack overflow or deadlocks.
 * @warning Do not block indefinitely (e.g., no synchronous I/O); use
 * non-blocking or defer work.
 * @threadsafe No - executes under heap mutex briefly; user code should be
 * reentrant if needed.
 *
 * ## Best Practices
 *
 * - Keep lightweight: Log, schedule work, update state - defer heavy
 * computation.
 * - Use userdata for context: Pass structures with needed data.
 * - Handle errors gracefully: No exceptions from callbacks; use logging.
 *
 * @code{.c}
 * static void timeout_callback(void *ud) {
 *     MyContext_T *ctx = ud;
 *     SOCKET_LOG_INFO_MSG("Timeout for ctx=%p", ctx);
 *     // Schedule deferred work or update state
 *     // Do NOT: SocketTimer_add(poll, ... ) // potential recursion
 * }
 *
 * // Usage
 * SocketTimer_T t = SocketTimer_add(poll, 30000, timeout_callback, ctx);
 * @endcode
 *
 * @see SocketTimer_add() for associating callback with timer
 * @see SocketTimer_add_repeating() for periodic callbacks
 */
typedef void (*SocketTimerCallback) (void *userdata);

/* Exception types */
/**
 * @brief Timer subsystem operation failure.
 * @ingroup event_system
 *
 * Generic exception raised for all errors in timer operations, covering
 * allocation failures, invalid parameters, heap inconsistencies, mutex errors,
 * and capacity limits.
 *
 * Provides consistent error handling via Except_T mechanism. Catch with
 * TRY/EXCEPT(SocketTimer_Failed). Detailed diagnostics via
 * Socket_GetLastError(), Socket_geterrorcode(), or errno.
 *
 * ## Common Triggers
 *
 * | Operation | Common Causes |
 * |-----------|---------------|
 * | SocketTimer_add / add_repeating | Invalid delay/interval (<0, <min, >max
 * days), NULL poll/callback/userdata, memory allocation failure (arena), heap
 * full (>100k timers), mutex lock/init fail | | Internal heap ops | Capacity
 * overflow (rare, after many resizes), sift up/down violations (consistency
 * error), ID wrap-around (unlikely) | | Parameter validation | Negative
 * delays/intervals, excessive values clamped but logged; validation fails on
 * bounds | | Threading | pthread_mutex_lock/unlock failures (system resource
 * exhaustion), race conditions in extreme concurrency | | System |
 * CLOCK_MONOTONIC query fail (rare kernel issue), arithmetic overflow in
 * expiry calc |
 *
 * @note Extreme delays/intervals clamped to max (365 days) with warning log;
 * does not raise but may affect precision.
 * @note Non-blocking functions (cancel, remaining) return -1 instead of
 * raising.
 * @note Recoverable: Often retryable after freeing resources (e.g., cancel old
 * timers).
 *
 * ## Error Handling Example
 *
 * @code{.c}
 * TRY {
 *     SocketTimer_T t = SocketTimer_add(poll, delay_ms, cb, ud);
 *     // Use timer...
 * } EXCEPT(SocketTimer_Failed) {
 *     SOCKET_LOG_ERROR_MSG("Timer add failed: %s (errno=%d)",
 * Socket_GetLastError(), errno);
 *     // Handle: reduce delay, check params, free resources, retry or fallback
 *     if (SocketError_is_retryable_errno(errno)) {
 *         // Exponential backoff retry logic
 *     }
 * } END_TRY;
 * @endcode
 *
 * @see SocketTimer_add() Creation entry points
 * @see SocketTimer_cancel() Non-raising cancellation
 * @see SocketTimer_remaining() Non-raising query
 * @see Except_T Structured exceptions
 * @see Socket_GetLastError() Detailed messages
 * @see SocketError_categorize_errno() Classify system errors
 * @see docs/ERROR_HANDLING.md Best practices for library errors
 * @see SocketConfig.h Compile-time limits tuning (e.g.,
 * SOCKET_MAX_TIMERS_PER_HEAP)
 */
extern const Except_T SocketTimer_Failed;

/**
 * @brief Add a one-shot timer to the event poll.
 * @ingroup event_system
 *
 * Schedules a single timer expiration after specified delay. The timer
 * integrates with the provided SocketPoll instance, firing the callback
 * automatically during SocketPoll_wait() when expired. Uses monotonic clock
 * for reliable timing.
 *
 * @param[in] poll Event poll instance; timers fired during its wait() calls
 * @param[in] delay_ms Delay from now in milliseconds (>=0; clamped if
 * excessive)
 * @param[in] callback Non-NULL function invoked on expiry
 * @param[in] userdata Opaque data passed to callback (may be NULL)
 *
 * @return Valid timer handle on success; NULL if exception raised
 *
 * @throws SocketTimer_Failed Invalid args (delay_ms <0 or >max, NULL
 * poll/callback), alloc fail, heap full (>max timers), mutex error
 *
 * @threadsafe Yes - internal mutex protects heap; safe from any thread
 *
 * @complexity O(log n) - min-heap insertion; O(1) amortized for capacity
 * growth
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Cleanup timer after 5 seconds of inactivity
 * static void cleanup_callback(void *ud) {
 *     Connection_T *conn = ud;
 *     SOCKET_LOG_DEBUG_MSG("Cleaning idle connection %p", conn);
 *     SocketPool_remove(pool, Connection_socket(conn));
 * }
 *
 * // In server init or connection handler
 * SocketTimer_T idle_timer = SocketTimer_add(poll, 5000, cleanup_callback,
 * conn); if (idle_timer) {
 *     // Timer will auto-fire during poll loop
 * } // else handle exception
 * @endcode
 *
 * ## Error Handling
 *
 * @code{.c}
 * TRY {
 *     SocketTimer_T t = SocketTimer_add(poll, delay, cb, data);
 * } EXCEPT(SocketTimer_Failed) {
 *     // Log and fallback: e.g., use longer delay or skip timeout
 *     SOCKET_LOG_WARN_MSG("Failed to add timer: %s", Socket_GetLastError());
 * } END_TRY;
 * @endcode
 *
 * @note Delay of 0 ms schedules for next poll cycle (near-immediate).
 * @note Extreme delays (>365 days) clamped with warning log.
 * @note Timer memory arena-allocated; free via arena dispose or cancel.
 * @warning Callback executes in poll thread; keep short to avoid blocking I/O.
 *
 * @see SocketTimer_add_repeating() for periodic scheduling
 * @see SocketTimer_cancel() to abort before firing
 * @see SocketPoll_wait() where firing occurs
 * @see SocketTimerCallback for callback guidelines
 */
extern T SocketTimer_add (SocketPoll_T poll, int64_t delay_ms,
                          SocketTimerCallback callback, void *userdata);

/**
 * @brief Add a repeating (periodic) timer to the event poll.
 * @ingroup event_system
 *
 * Schedules periodic timer firings every interval_ms milliseconds, starting
 * after the first interval. Integrates with SocketPoll for automatic callback
 * invocation during wait(). Uses monotonic clock; reschedules after each
 * firing.
 *
 * @param[in] poll Event poll instance; manages firing during wait()
 * @param[in] interval_ms Repeat interval in ms (>=1; clamped if excessive)
 * @param[in] callback Non-NULL function invoked periodically
 * @param[in] userdata Opaque data for callback (may be NULL)
 *
 * @return Valid timer handle; NULL on exception
 *
 * @throws SocketTimer_Failed Invalid interval/delay (>=1 ms min), NULL args,
 * alloc/heap full/mutex errors
 *
 * @threadsafe Yes - mutex-protected; concurrent safe
 *
 * @complexity O(log n) - heap insert; repeated for rescheduling on fire
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Periodic heartbeat or metrics collection every 10 seconds
 * static void heartbeat_callback(void *ud) {
 *     ServerStats_T *stats = ud;
 *     stats->heartbeat_count++;
 *     SOCKET_LOG_INFO_MSG("Heartbeat %lu", stats->heartbeat_count);
 *     // Send metrics or check health
 * }
 *
 * // Setup in server init
 * SocketTimer_T heart_timer = SocketTimer_add_repeating(poll, 10000,
 * heartbeat_callback, &server_stats);
 * // Continues until cancelled or poll freed
 * @endcode
 *
 * ## Stopping Periodic Timer
 *
 * @code{.c}
 * // Graceful stop on shutdown signal
 * if (SocketTimer_cancel(poll, periodic_timer) == 0) {
 *     SOCKET_LOG_INFO_MSG("Periodic timer cancelled");
 * } // -1 if already invalid/fired
 * @endcode
 *
 * @note First fire after interval_ms; subsequent every interval_ms from expiry
 * (not wall-clock aligned).
 * @note Interval clamped >365 days with warning; min 1ms to avoid loops.
 * @note Rescheduling happens after callback; drift accumulates if callback
 * slow.
 * @warning For precise intervals, use shorter intervals or adjust in callback.
 * @note Memory managed by poll's arena; persists until cancel or arena
 * dispose.
 *
 * @see SocketTimer_add() for single-fire timers
 * @see SocketTimer_cancel() to stop repetition
 * @see SocketTimerCallback Guidelines for periodic callbacks
 * @see SocketPoll_wait() Automatic firing mechanism
 */
extern T SocketTimer_add_repeating (SocketPoll_T poll, int64_t interval_ms,
                                    SocketTimerCallback callback,
                                    void *userdata);

/**
 * @brief Cancel a pending timer (lazy deletion).
 * @ingroup event_system
 *
 * Marks the specified timer as cancelled, preventing future firing. Uses lazy
 * deletion: flag set immediately, but timer removed from heap only when it
 * reaches root during processing (efficient, no immediate heap restructure).
 *
 * @param[in] poll Event poll associated with the timer heap
 * @param[in] timer Handle of timer to cancel (must match poll's heap)
 *
 * @return 0 if timer was pending and marked cancelled; -1 if invalid handle,
 * mismatch, already invalid/fired, or heap unavailable
 *
 * @note Non-blocking, no exceptions raised - check return for success
 * @note Idempotent: Repeated calls or on invalid timers return -1 harmlessly
 * @note Lazy: Memory freed later; callback never called post-cancel
 *
 * @threadsafe Yes - quick mutex lock for flag set
 *
 * @complexity O(1) - direct heap_index access to set flag; no sift operations
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Cancel idle timeout if activity resumes
 * if (SocketTimer_cancel(poll, idle_timer) == 0) {
 *     SOCKET_LOG_DEBUG_MSG("Idle timer cancelled due to activity");
 * } else {
 *     // Already fired or invalid - no action needed
 *     SOCKET_LOG_DEBUG_MSG("Timer already invalid");
 * }
 * @endcode
 *
 * ## In Shutdown
 *
 * @code{.c}
 * // Cancel all timers before poll free
 * SocketTimer_cancel(poll, timer1);
 * SocketTimer_cancel(poll, timer2);
 * // Ignore returns; ensures no pending fires
 * @endcode
 *
 * @warning Do NOT call from timer callback (deadlock on heap mutex)
 * @note For repeating timers, stops future firings immediately
 * @note After cancel, timer handle invalid for further ops (remaining returns
 * -1)
 * @note To free memory sooner, consider arena clear/dispose after batch
 * cancels
 *
 * @see SocketTimer_add() One-shot timer creation
 * @see SocketTimer_add_repeating() Periodic timers
 * @see SocketTimer_remaining() Check status post-cancel
 */
extern int SocketTimer_cancel (SocketPoll_T poll, T timer);

/**
 * @brief Query milliseconds remaining until timer expiry.
 * @ingroup event_system
 *
 * Computes time left until the timer's scheduled expiry using current
 * monotonic clock. Useful for monitoring, logging, or dynamic timeout
 * adjustments. Returns approximate value; actual firing may vary slightly due
 * to scheduling.
 *
 * @param[in] poll Poll instance owning the timer heap
 * @param[in] timer Timer handle to query (must match poll)
 *
 * @return >=0 ms remaining (0 if due or overdue); -1 if invalid, mismatch,
 * fired/cancelled, or heap unavailable
 *
 * @note Non-raising, non-blocking - always safe to call
 * @note Value decreases over time; snapshot only, race possible in
 * multi-thread
 * @note For cancelled timers, returns -1 (not overdue)
 *
 * @threadsafe Yes - brief mutex for validation and expiry read
 *
 * @complexity O(1) - direct index lookup + monotonic clock query
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Log remaining time for monitoring
 * int64_t remaining = SocketTimer_remaining(poll, timer);
 * if (remaining > 0) {
 *     SOCKET_LOG_DEBUG_MSG("Timer %p has %" PRId64 " ms left", timer,
 * remaining); } else if (remaining == 0) {
 *     // Due now - expect imminent firing
 * } else {
 *     // Invalid - perhaps already fired
 *     SOCKET_LOG_DEBUG_MSG("Timer %p invalid", timer);
 * }
 * @endcode
 *
 * ## Dynamic Adjustment
 *
 * @code{.c}
 * // Check if enough time left before critical op
 * if (SocketTimer_remaining(poll, deadline_timer) < 1000) {
 *     // Less than 1s - extend or cancel
 *     SocketTimer_cancel(poll, deadline_timer);
 *     // Reschedule with longer delay
 * }
 * @endcode
 *
 * @note Approximate: CLOCK_MONOTONIC query + expiry diff; may be negative
 * internally but clamped >=0
 * @note Overdue timers (negative remaining) return 0; firing pending in next
 * poll_wait
 * @note Useful for health checks, logging, or before/after callback timing
 * @warning Not real-time precise; for critical timing use shorter intervals
 * @note Invalidates assumption if called post-fire (use-after-invalid)
 *
 * @see SocketTimer_add() Timer creation
 * @see SocketTimer_cancel() Invalidates timer
 * @see SocketTimerCallback Where expiry confirmed
 */
extern int64_t SocketTimer_remaining (SocketPoll_T poll, T timer);

/**
 * @brief Reschedule a timer with a new delay.
 * @ingroup event_system
 * @param[in] poll Poll instance owning the timer heap.
 * @param[in] timer Timer handle to reschedule.
 * @param[in] new_delay_ms New delay from now in milliseconds.
 * @return 0 on success, -1 if timer invalid or cancelled.
 *
 * Changes the expiry time of an existing timer without creating a new one.
 * For repeating timers, this also updates the interval.
 *
 * @threadsafe Yes - acquires heap mutex.
 * @complexity O(log n) - may need to reheapify.
 *
 * ## Example
 *
 * @code{.c}
 * // Extend timeout on activity
 * SocketTimer_reschedule(poll, idle_timer, 30000);  // Reset to 30 seconds
 * @endcode
 *
 * @note More efficient than cancel + add for timer renewal.
 * @see SocketTimer_add() for creating new timers.
 * @see SocketTimer_cancel() to stop a timer.
 */
extern int SocketTimer_reschedule (SocketPoll_T poll, T timer,
                                   int64_t new_delay_ms);

/**
 * @brief Pause a timer, preserving remaining time.
 * @ingroup event_system
 * @param[in] poll Poll instance owning the timer heap.
 * @param[in] timer Timer handle to pause.
 * @return 0 on success, -1 if timer invalid, cancelled, or already paused.
 *
 * Temporarily stops a timer from firing. The remaining time is preserved
 * and restored when SocketTimer_resume() is called. Paused timers do not
 * fire during poll waits.
 *
 * @threadsafe Yes - acquires heap mutex.
 * @complexity O(1) - sets flag and stores remaining time.
 *
 * ## Example
 *
 * @code{.c}
 * // Pause during long operation
 * SocketTimer_pause(poll, watchdog);
 * perform_long_operation();
 * SocketTimer_resume(poll, watchdog);
 * @endcode
 *
 * @see SocketTimer_resume() to resume paused timer.
 * @see SocketTimer_remaining() to check time before pause.
 */
extern int SocketTimer_pause (SocketPoll_T poll, T timer);

/**
 * @brief Resume a paused timer.
 * @ingroup event_system
 * @param[in] poll Poll instance owning the timer heap.
 * @param[in] timer Timer handle to resume.
 * @return 0 on success, -1 if timer invalid, cancelled, or not paused.
 *
 * Resumes a previously paused timer. The timer's expiry is set to
 * now + remaining_time_at_pause, preserving the original deadline relative
 * to when it was paused.
 *
 * @threadsafe Yes - acquires heap mutex.
 * @complexity O(log n) - may need to reheapify.
 *
 * ## Example
 *
 * @code{.c}
 * // Resume after user interaction pause
 * if (SocketTimer_resume(poll, idle_timer) < 0) {
 *     // Timer was not paused or is invalid
 *     idle_timer = SocketTimer_add(poll, 30000, idle_cb, ctx);
 * }
 * @endcode
 *
 * @see SocketTimer_pause() to pause timer.
 * @see SocketTimer_reschedule() for different timing control.
 */
extern int SocketTimer_resume (SocketPoll_T poll, T timer);

#undef T

/** @} */ /* end of group event_system */

/* Undefine T after all uses */
#endif /* SOCKETTIMER_INCLUDED */

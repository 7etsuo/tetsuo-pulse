#ifndef SOCKETTIMER_INCLUDED
#define SOCKETTIMER_INCLUDED

#include "core/Except.h"
#include <stdint.h>

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
 * - Thread-safe operations
 * - Arena-based memory management
 *
 * Timing Precision:
 * - Uses CLOCK_MONOTONIC for timestamps
 * - Millisecond resolution
 * - Timers may fire slightly after their deadline due to event loop scheduling
 *
 * Thread Safety:
 * - All operations are thread-safe
 * - Callbacks execute in the calling thread (SocketPoll_wait thread)
 * - Do not call SocketTimer_cancel() from within timer callbacks
 *
 * Limitations:
 * - Maximum timer delay: ~9.2 billion milliseconds (~107 days)
 * - Timer IDs wrap around at ~4 billion (unsigned int)
 *
 * @see SocketPoll_T for event loop integration.
 * @see SocketTimer_add() for creating timers.
 * @see @ref event_system for other event-driven components.
 * @see SocketReconnect_T for reconnection timers.
 */

/**
 * @brief Opaque pointer to a timer instance.
 * @ingroup event_system
 *
 * Represents a timer created by SocketTimer_add() or SocketTimer_add_repeating().
 * Used to cancel the timer or query remaining time.
 * Becomes invalid after the timer fires or is cancelled.
 * @note Not a pointer to the internal SocketTimer_T structure; heap manages actual storage.
 * @see SocketTimer_add()
 * @see SocketTimer_cancel()
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
 * @param userdata Opaque user data provided at timer creation.
 *
 * Invoked when timer expires during SocketPoll_wait().
 * Executes in the thread calling SocketPoll_wait().
 * @note Must not call SocketTimer_cancel() on itself or block indefinitely.
 * @note Safe to allocate/free resources, but avoid recursive timer operations.
 * @see SocketTimer_add()
 */
typedef void (*SocketTimerCallback) (void *userdata);

/* Exception types */
/**
 * @brief Timer subsystem operation failure.
 * @ingroup event_system
 *
 * Generic exception for all timer-related errors, including allocation failures,
 * invalid timer handles, heap operations, parameter validation, and internal
 * state inconsistencies.
 *
 * Specific error details available via Socket_geterrorcode() or errno after catch.
 *
 * @see SocketTimer_add(), SocketTimer_add_repeating() - creation failures (e.g., invalid delay, memory)
 * @see SocketTimer_cancel() - invalid handle or race conditions
 * @see SocketTimer_remaining() - invalid timer or computation errors
 * @see Except_T for structured exception handling
 * @see SocketError_categorize_errno() for classifying underlying system errors
 * @see docs/ERROR_HANDLING.md for best practices on handling library exceptions
 */
extern const Except_T SocketTimer_Failed;

/**
 * @brief Add a one-shot timer.
 * @ingroup event_system
 * @param poll Event poll instance to associate timer with.
 * @param delay_ms Delay in milliseconds (must be >= 0).
 * @param callback Function to call when timer expires.
 * @param userdata User data passed to callback.
 * @return Timer handle for cancellation and management.
 * @throws SocketTimer_Failed on invalid parameters (e.g., negative delay/interval, null callback/poll), memory allocation failure, or internal heap error.
 * @threadsafe Yes.
 * @note Timer fires once after delay_ms milliseconds. Callbacks execute during SocketPoll_wait() in the calling thread.
 * @see SocketTimer_add_repeating() for repeating timers.
 * @see SocketTimer_cancel() for cancellation.
 */
extern T SocketTimer_add (SocketPoll_T poll, int64_t delay_ms,
                          SocketTimerCallback callback, void *userdata);

/**
 * @brief Add a repeating timer.
 * @ingroup event_system
 * @param poll Event poll instance to associate timer with.
 * @param interval_ms Interval in milliseconds between firings (must be >= 1).
 * @param callback Function to call when timer expires.
 * @param userdata User data passed to callback.
 * @return Timer handle for cancellation and management.
 * @throws SocketTimer_Failed on invalid parameters (e.g., negative delay/interval, null callback/poll), memory allocation failure, or internal heap error.
 * @threadsafe Yes.
 * @note Timer fires repeatedly every interval_ms milliseconds. First firing occurs after interval_ms milliseconds.
 * @note Use SocketTimer_cancel() to stop.
 * @see SocketTimer_add() for one-shot timers.
 * @see SocketTimer_cancel() for cancellation.
 */
extern T SocketTimer_add_repeating (SocketPoll_T poll, int64_t interval_ms,
                                    SocketTimerCallback callback,
                                    void *userdata);

/**
 * @brief Cancel a pending timer.
 * @ingroup event_system
 * @param poll Event poll instance timer is associated with.
 * @param timer Timer handle to cancel.
 * @return 0 on success (pending timer was cancelled), -1 if timer invalid, already fired/cancelled, poll heap unavailable, or poll/timer mismatch.
 * @note Does not raise exceptions; all failure modes return -1 (non-blocking).
 * @threadsafe Yes.
 * @note Safe to call on already-fired or cancelled timers.
 * @note Do not call from within a timer callback function.
 * @see SocketTimer_add() for creating timers.
 * @see SocketTimer_add_repeating() for repeating timers.
 */
extern int SocketTimer_cancel (SocketPoll_T poll, T timer);

/**
 * @brief Get milliseconds until timer expiry.
 * @ingroup event_system
 * @param poll Event poll instance timer is associated with.
 * @param timer Timer handle to query.
 * @return Milliseconds remaining until expiry (>= 0 even if overdue), -1 if timer invalid, fired/cancelled, poll heap unavailable, or poll/timer mismatch.
 * @note Does not raise exceptions; all failure modes return -1 (non-blocking). Returns approximate value based on monotonic clock.
 * @threadsafe Yes.
 * @note Returns 0 if timer has already expired but not yet fired.
 * @note Useful for debugging and implementing timeout logic.
 * @see SocketTimer_add() for creating timers.
 * @see SocketTimer_cancel() for checking timer state.
 */
extern int64_t SocketTimer_remaining (SocketPoll_T poll, T timer);

#undef T
#endif /* SOCKETTIMER_INCLUDED */

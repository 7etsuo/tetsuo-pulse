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
 */

#define T SocketTimer_T
typedef struct T *T;

/* Forward declaration for SocketPoll_T */
struct SocketPoll_T;
typedef struct SocketPoll_T *SocketPoll_T;

/* Timer callback function type */
typedef void (*SocketTimerCallback) (void *userdata);

/* Exception types */
extern const Except_T
    SocketTimer_Failed; /**< General timer operation failure */

/**
 * @brief Add a one-shot timer.
 * @ingroup event_system
 * @param poll Event poll instance to associate timer with.
 * @param delay_ms Delay in milliseconds (must be >= 0).
 * @param callback Function to call when timer expires.
 * @param userdata User data passed to callback.
 * @return Timer handle for cancellation, or NULL on error.
 * @throws SocketTimer_Failed on error.
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
 * @return Timer handle for cancellation, or NULL on error.
 * @throws SocketTimer_Failed on error.
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
 * @return 0 on success, -1 if timer already fired or invalid.
 * @throws SocketTimer_Failed on error.
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
 * @return Milliseconds until expiry (>= 0), or -1 if timer fired/cancelled.
 * @throws SocketTimer_Failed on error.
 * @threadsafe Yes.
 * @note Returns 0 if timer has already expired but not yet fired.
 * @note Useful for debugging and implementing timeout logic.
 * @see SocketTimer_add() for creating timers.
 * @see SocketTimer_cancel() for checking timer state.
 */
extern int64_t SocketTimer_remaining (SocketPoll_T poll, T timer);

#undef T
#endif /* SOCKETTIMER_INCLUDED */

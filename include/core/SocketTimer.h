#ifndef SOCKETTIMER_INCLUDED
#define SOCKETTIMER_INCLUDED

#include "core/Except.h"
#include <stdint.h>

/**
 * SocketTimer - Timer Subsystem
 *
 * Provides high-performance timer functionality integrated with the event loop.
 * Timers are stored in a min-heap for O(log n) insert/delete and O(1) next-timer
 * lookup. Timer callbacks fire automatically during SocketPoll_wait().
 *
 * FEATURES:
 * - One-shot and repeating timers
 * - Monotonic clock timestamps (immune to wall-clock changes)
 * - Integrated with SocketPoll event loop
 * - Thread-safe operations
 * - Arena-based memory management
 *
 * TIMING PRECISION:
 * - Uses CLOCK_MONOTONIC for timestamps
 * - Millisecond resolution
 * - Timers may fire slightly after their deadline due to event loop scheduling
 *
 * THREAD SAFETY:
 * - All operations are thread-safe
 * - Callbacks execute in the calling thread (SocketPoll_wait thread)
 * - Do not call SocketTimer_cancel() from within timer callbacks
 *
 * LIMITATIONS:
 * - Maximum timer delay: ~9.2 billion milliseconds (~107 days)
 * - Timer IDs wrap around at ~4 billion (unsigned int)
 */

#define T SocketTimer_T
typedef struct T *T;

/* Forward declaration for SocketPoll_T */
struct SocketPoll_T;
typedef struct SocketPoll_T *SocketPoll_T;

/* Timer callback function type */
typedef void (*SocketTimerCallback)(void *userdata);

/* Exception types */
extern const Except_T SocketTimer_Failed; /**< General timer operation failure */

/**
 * SocketTimer_add - Add a one-shot timer
 * @poll: Event poll instance to associate timer with
 * @delay_ms: Delay in milliseconds (must be >= 0)
 * @callback: Function to call when timer expires
 * @userdata: User data passed to callback
 * Returns: Timer handle for cancellation, or NULL on error
 * Raises: SocketTimer_Failed on error
 * Thread-safe: Yes
 * Note: Timer fires once after delay_ms milliseconds. Callbacks execute
 * during SocketPoll_wait() in the calling thread.
 */
extern T SocketTimer_add (SocketPoll_T poll, int64_t delay_ms,
                          SocketTimerCallback callback, void *userdata);

/**
 * SocketTimer_add_repeating - Add a repeating timer
 * @poll: Event poll instance to associate timer with
 * @interval_ms: Interval in milliseconds between firings (must be >= 1)
 * @callback: Function to call when timer expires
 * @userdata: User data passed to callback
 * Returns: Timer handle for cancellation, or NULL on error
 * Raises: SocketTimer_Failed on error
 * Thread-safe: Yes
 * Note: Timer fires repeatedly every interval_ms milliseconds. First firing
 * occurs after interval_ms milliseconds. Use SocketTimer_cancel() to stop.
 */
extern T SocketTimer_add_repeating (SocketPoll_T poll, int64_t interval_ms,
                                    SocketTimerCallback callback, void *userdata);

/**
 * SocketTimer_cancel - Cancel a pending timer
 * @poll: Event poll instance timer is associated with
 * @timer: Timer handle to cancel
 * Returns: 0 on success, -1 if timer already fired or invalid
 * Raises: SocketTimer_Failed on error
 * Thread-safe: Yes
 * Note: Safe to call on already-fired or cancelled timers.
 * Do not call from within a timer callback function.
 */
extern int SocketTimer_cancel (SocketPoll_T poll, T timer);

/**
 * SocketTimer_remaining - Get milliseconds until timer expiry
 * @poll: Event poll instance timer is associated with
 * @timer: Timer handle to query
 * Returns: Milliseconds until expiry (>= 0), or -1 if timer fired/cancelled
 * Raises: SocketTimer_Failed on error
 * Thread-safe: Yes
 * Note: Returns 0 if timer has already expired but not yet fired.
 * Useful for debugging and implementing timeout logic.
 */
extern int64_t SocketTimer_remaining (SocketPoll_T poll, T timer);

#undef T
#endif /* SOCKETTIMER_INCLUDED */

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETTIMER_INCLUDED
#define SOCKETTIMER_INCLUDED

#include "core/Except.h"
#include <stdint.h>

/**
 * @defgroup event_system Event System Modules
 * @brief High-performance I/O multiplexing with cross-platform backends
 *
 * Event-driven I/O subsystem providing multiplexing (epoll/kqueue/poll),
 * min-heap timers, and async operations. Timers integrate with SocketPoll
 * for automatic timeout handling using monotonic timestamps and O(log n)
 * operations.
 *
 * @see @ref foundation Base infrastructure dependencies
 * @see docs/ASYNC_IO.md Detailed async patterns
 * @{
 */

/**
 * @file SocketTimer.h
 * @ingroup event_system
 * @brief High-performance timer subsystem integrated with the event loop.
 *
 * Min-heap based timers with O(log n) insert/delete and O(1) lookup. Timers
 * fire automatically during SocketPoll_wait(). Supports one-shot and repeating
 * timers with monotonic timestamps (immune to clock adjustments).
 *
 * Thread Safety: All operations thread-safe via mutex. Do not call
 * SocketTimer_cancel() or SocketTimer_remaining() from timer callbacks to
 * avoid deadlock.
 *
 * @see SocketPoll_T for event loop integration
 * @see SocketConfig.h for compile-time limits
 */

/**
 * @brief Opaque pointer to a timer instance.
 * @ingroup event_system
 *
 * Handle to a timer created by SocketTimer_add() or
 * SocketTimer_add_repeating(). Becomes invalid after firing or cancellation.
 *
 * @warning Using invalid handles may return -1 or cause assertion failures.
 * @threadsafe Safe via mutex protection.
 */
#define T SocketTimer_T
typedef struct T *T;
/**
 * @brief Opaque handle for event poll instance.
 * @ingroup event_system
 *
 * Forward declaration for timer integration with SocketPoll.
 *
 * @see SocketPoll.h
 */
struct SocketPoll_T;
typedef struct SocketPoll_T *SocketPoll_T;

/**
 * @brief Type for timer expiration callback functions.
 * @ingroup event_system
 * @param userdata Opaque user data provided at timer creation.
 *
 * Invoked when timer expires during SocketPoll_wait(). Executes in poll
 * thread context.
 *
 * @warning Keep lightweight to avoid blocking event loop.
 * @warning Do not call SocketTimer_cancel() or SocketTimer_remaining() to
 * avoid deadlock.
 * @threadsafe Executes under heap mutex; avoid recursion.
 */
typedef void (*SocketTimerCallback) (void *userdata);

/**
 * @brief Timer subsystem operation failure.
 * @ingroup event_system
 *
 * Raised for timer operation errors including allocation failures, invalid
 * parameters, heap full, or mutex errors. Catch with
 * TRY/EXCEPT(SocketTimer_Failed).
 *
 * @note SocketTimer_cancel() and SocketTimer_remaining() return -1 instead of
 * raising.
 * @see Socket_GetLastError() for detailed error messages
 */
extern const Except_T SocketTimer_Failed;

/**
 * @brief Add a one-shot timer to the event poll.
 * @ingroup event_system
 *
 * @param[in] poll Event poll instance
 * @param[in] delay_ms Delay in milliseconds (>=0)
 * @param[in] callback Function invoked on expiry
 * @param[in] userdata Opaque data passed to callback
 *
 * @return Timer handle on success
 * @throws SocketTimer_Failed Invalid parameters, allocation failure, or heap
 * full
 * @threadsafe Yes
 * @complexity O(log n)
 *
 * @see SocketTimer_add_repeating()
 * @see SocketTimer_cancel()
 */
extern T SocketTimer_add (SocketPoll_T poll, int64_t delay_ms,
                          SocketTimerCallback callback, void *userdata);

/**
 * @brief Add a repeating (periodic) timer to the event poll.
 * @ingroup event_system
 *
 * @param[in] poll Event poll instance
 * @param[in] interval_ms Repeat interval in milliseconds (>=1)
 * @param[in] callback Function invoked periodically
 * @param[in] userdata Opaque data for callback
 *
 * @return Timer handle on success
 * @throws SocketTimer_Failed Invalid parameters, allocation failure, or heap
 * full
 * @threadsafe Yes
 * @complexity O(log n)
 *
 * @note First fire after interval_ms; reschedules after each firing.
 * @see SocketTimer_add()
 * @see SocketTimer_cancel()
 */
extern T SocketTimer_add_repeating (SocketPoll_T poll, int64_t interval_ms,
                                    SocketTimerCallback callback,
                                    void *userdata);

/**
 * @brief Cancel a pending timer (lazy deletion).
 * @ingroup event_system
 *
 * @param[in] poll Event poll associated with timer
 * @param[in] timer Timer handle to cancel
 *
 * @return 0 on success; -1 if invalid or already fired
 * @threadsafe Yes
 * @complexity O(1)
 *
 * @warning Do NOT call from timer callback to avoid deadlock.
 * @note Lazy deletion: memory freed when timer reaches heap root.
 * @see SocketTimer_add()
 */
extern int SocketTimer_cancel (SocketPoll_T poll, T timer);

/**
 * @brief Query milliseconds remaining until timer expiry.
 * @ingroup event_system
 *
 * @param[in] poll Poll instance owning the timer
 * @param[in] timer Timer handle to query
 *
 * @return Milliseconds remaining (>=0); -1 if invalid or cancelled
 * @threadsafe Yes
 * @complexity O(1)
 *
 * @note Returns 0 if timer is due or overdue.
 * @see SocketTimer_add()
 */
extern int64_t SocketTimer_remaining (SocketPoll_T poll, T timer);

/**
 * @brief Reschedule a timer with a new delay.
 * @ingroup event_system
 *
 * @param[in] poll Poll instance owning the timer
 * @param[in] timer Timer handle to reschedule
 * @param[in] new_delay_ms New delay in milliseconds
 *
 * @return 0 on success; -1 if invalid or cancelled
 * @threadsafe Yes
 * @complexity O(log n)
 *
 * @note For repeating timers, also updates the interval.
 * @see SocketTimer_add()
 */
extern int SocketTimer_reschedule (SocketPoll_T poll, T timer,
                                   int64_t new_delay_ms);

/**
 * @brief Pause a timer, preserving remaining time.
 * @ingroup event_system
 *
 * @param[in] poll Poll instance owning the timer
 * @param[in] timer Timer handle to pause
 *
 * @return 0 on success; -1 if invalid, cancelled, or already paused
 * @threadsafe Yes
 * @complexity O(1)
 *
 * @see SocketTimer_resume()
 */
extern int SocketTimer_pause (SocketPoll_T poll, T timer);

/**
 * @brief Resume a paused timer.
 * @ingroup event_system
 *
 * @param[in] poll Poll instance owning the timer
 * @param[in] timer Timer handle to resume
 *
 * @return 0 on success; -1 if invalid, cancelled, or not paused
 * @threadsafe Yes
 * @complexity O(log n)
 *
 * @note Expiry set to now + remaining_time_at_pause.
 * @see SocketTimer_pause()
 */
extern int SocketTimer_resume (SocketPoll_T poll, T timer);

#undef T

/** @} */ /* end of group event_system */

/* Undefine T after all uses */
#endif /* SOCKETTIMER_INCLUDED */

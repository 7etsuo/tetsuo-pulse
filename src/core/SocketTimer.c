/**
 * SocketTimer.c - Public timer API
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This file contains the public API for the timer subsystem.
 * Internal helpers are in SocketTimer-internal.c.
 * Heap implementation is in SocketTimer-heap.c.
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
 * - Timers may fire slightly after their deadline
 *
 * THREAD SAFETY:
 * - All operations are thread-safe
 * - Callbacks execute in the calling thread
 * - Do not call SocketTimer_cancel() from within timer callbacks
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketTimer-internal.h"
#include "core/SocketTimer-private.h"
#include "core/SocketTimer.h"

/* Timer exception definition */
const Except_T SocketTimer_Failed
    = { &SocketTimer_Failed, "Timer operation failed" };

/* Forward declaration for timer heap getter */
struct SocketTimer_heap_T *socketpoll_get_timer_heap (SocketPoll_T poll);

/* ============================================================================
 * Internal Timer Creation
 * ============================================================================ */

/**
 * sockettimer_add_internal - Internal helper to add a timer
 * @poll: Event poll instance
 * @delay_ms: Initial delay in milliseconds
 * @interval_ms: Interval for repeating (0 for one-shot)
 * @callback: Callback function
 * @userdata: User data for callback
 * @validate_fn: Validation function for timing parameter
 *
 * Returns: Timer handle
 * Raises: SocketTimer_Failed on error
 */
static SocketTimer_T
sockettimer_add_internal (SocketPoll_T poll, int64_t delay_ms,
                          int64_t interval_ms, SocketTimerCallback callback,
                          void *userdata, void (*validate_fn) (int64_t))
{
  SocketTimer_heap_T *heap;
  struct SocketTimer_T *timer;

  assert (poll);
  assert (callback);

  heap = sockettimer_validate_heap (poll);
  validate_fn (delay_ms);

  timer = sockettimer_allocate_timer (heap->arena);

  if (interval_ms > 0)
    sockettimer_init_repeating (timer, interval_ms, callback, userdata);
  else
    sockettimer_init_oneshot (timer, delay_ms, callback, userdata);

  SocketTimer_heap_push (heap, timer);

  return timer;
}

/* ============================================================================
 * Public Timer API
 * ============================================================================ */

/**
 * SocketTimer_add - Add a one-shot timer
 * @poll: Event poll instance to associate timer with
 * @delay_ms: Delay in milliseconds (must be >= 0)
 * @callback: Function to call when timer expires
 * @userdata: User data passed to callback
 *
 * Returns: Timer handle for cancellation
 * Raises: SocketTimer_Failed on error
 * Thread-safe: Yes
 *
 * Timer fires once after delay_ms milliseconds. Callbacks execute
 * during SocketPoll_wait() in the calling thread.
 */
SocketTimer_T
SocketTimer_add (SocketPoll_T poll, int64_t delay_ms,
                 SocketTimerCallback callback, void *userdata)
{
  return sockettimer_add_internal (poll, delay_ms, 0, callback, userdata,
                                   sockettimer_validate_delay);
}

/**
 * SocketTimer_add_repeating - Add a repeating timer
 * @poll: Event poll instance to associate timer with
 * @interval_ms: Interval in milliseconds between firings (must be >= 1)
 * @callback: Function to call when timer expires
 * @userdata: User data passed to callback
 *
 * Returns: Timer handle for cancellation
 * Raises: SocketTimer_Failed on error
 * Thread-safe: Yes
 *
 * Timer fires repeatedly every interval_ms milliseconds. First firing
 * occurs after interval_ms milliseconds. Use SocketTimer_cancel() to stop.
 */
SocketTimer_T
SocketTimer_add_repeating (SocketPoll_T poll, int64_t interval_ms,
                           SocketTimerCallback callback, void *userdata)
{
  return sockettimer_add_internal (poll, interval_ms, interval_ms, callback,
                                   userdata, sockettimer_validate_interval);
}

/**
 * SocketTimer_cancel - Cancel a pending timer
 * @poll: Event poll instance timer is associated with
 * @timer: Timer handle to cancel
 *
 * Returns: 0 on success, -1 if timer already fired or invalid
 * Thread-safe: Yes
 *
 * Safe to call on already-fired or cancelled timers.
 * Do not call from within a timer callback function.
 */
int
SocketTimer_cancel (SocketPoll_T poll, SocketTimer_T timer)
{
  SocketTimer_heap_T *heap;

  assert (poll);
  assert (timer);

  heap = socketpoll_get_timer_heap (poll);
  if (!heap)
    return -1;

  return SocketTimer_heap_cancel (heap, timer);
}

/**
 * SocketTimer_remaining - Get milliseconds until timer expiry
 * @poll: Event poll instance timer is associated with
 * @timer: Timer handle to query
 *
 * Returns: Milliseconds until expiry (>= 0), or -1 if timer fired/cancelled
 * Thread-safe: Yes
 *
 * Returns 0 if timer has already expired but not yet fired.
 * Useful for debugging and implementing timeout logic.
 */
int64_t
SocketTimer_remaining (SocketPoll_T poll, SocketTimer_T timer)
{
  SocketTimer_heap_T *heap;

  assert (poll);
  assert (timer);

  heap = socketpoll_get_timer_heap (poll);
  if (!heap)
    return -1;

  return SocketTimer_heap_remaining (heap, timer);
}

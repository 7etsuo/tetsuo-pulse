/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_TIMER_INCLUDED
#define SOCKETSIMPLE_TIMER_INCLUDED

/**
 * @file SocketSimple-timer.h
 * @brief Simple timer API for event loop integration.
 *
 * Provides one-shot and repeating timers that integrate with
 * SocketSimple_Poll for event-driven timeout handling.
 *
 * ## Quick Start
 *
 * ```c
 * #include <simple/SocketSimple.h>
 *
 * void on_timeout(void *data) {
 *     printf("Timer fired! data=%p\n", data);
 * }
 *
 * // Create poll with timer support
 * SocketSimple_Poll_T poll = Socket_simple_poll_new(64);
 *
 * // Add a one-shot timer (fires after 1000ms)
 * SocketSimple_Timer_T timer = Socket_simple_timer_add(poll, 1000, on_timeout,
 * mydata);
 *
 * // Add a repeating timer (fires every 5000ms)
 * SocketSimple_Timer_T repeat = Socket_simple_timer_add_repeating(poll, 5000,
 * on_tick, NULL);
 *
 * // Event loop
 * SocketSimple_PollEvent events[64];
 * while (running) {
 *     int timeout = Socket_simple_timer_next_timeout(poll);
 *     int n = Socket_simple_poll_wait(poll, events, 64, timeout);
 *     // Process socket events...
 *     Socket_simple_timer_process(poll);  // Fire expired timers
 * }
 *
 * Socket_simple_timer_cancel(poll, repeat);
 * Socket_simple_poll_free(&poll);
 * ```
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

  /* Forward declaration */
  typedef struct SocketSimple_Poll *SocketSimple_Poll_T;

  /**
   * @brief Opaque timer handle.
   */
  typedef struct SocketSimple_Timer *SocketSimple_Timer_T;

  /**
   * @brief Timer callback function type.
   *
   * @param userdata User data provided when timer was created.
   */
  typedef void (*SocketSimple_TimerCallback) (void *userdata);

  /**
   * @brief Add a one-shot timer.
   *
   * The timer fires once after the specified delay and is automatically
   * removed.
   *
   * @param poll Poll instance to attach timer to.
   * @param delay_ms Delay in milliseconds before firing.
   * @param callback Function to call when timer fires.
   * @param userdata User data passed to callback.
   * @return Timer handle on success, NULL on error.
   *
   * Example:
   * @code
   * SocketSimple_Timer_T timer = Socket_simple_timer_add(poll, 5000,
   * on_timeout, ctx); if (!timer) { fprintf(stderr, "Timer error: %s\n",
   * Socket_simple_error());
   * }
   * @endcode
   */
  extern SocketSimple_Timer_T
  Socket_simple_timer_add (SocketSimple_Poll_T poll,
                           int64_t delay_ms,
                           SocketSimple_TimerCallback callback,
                           void *userdata);

  /**
   * @brief Add a repeating timer.
   *
   * The timer fires repeatedly at the specified interval until cancelled.
   *
   * @param poll Poll instance to attach timer to.
   * @param interval_ms Interval in milliseconds between firings.
   * @param callback Function to call when timer fires.
   * @param userdata User data passed to callback.
   * @return Timer handle on success, NULL on error.
   *
   * Example:
   * @code
   * // Heartbeat every 30 seconds
   * SocketSimple_Timer_T heartbeat = Socket_simple_timer_add_repeating(
   *     poll, 30000, send_heartbeat, conn);
   * @endcode
   */
  extern SocketSimple_Timer_T
  Socket_simple_timer_add_repeating (SocketSimple_Poll_T poll,
                                     int64_t interval_ms,
                                     SocketSimple_TimerCallback callback,
                                     void *userdata);

  /**
   * @brief Cancel a pending timer.
   *
   * @param poll Poll instance the timer belongs to.
   * @param timer Timer handle to cancel.
   * @return 0 on success, -1 if timer invalid or already fired.
   */
  extern int Socket_simple_timer_cancel (SocketSimple_Poll_T poll,
                                         SocketSimple_Timer_T timer);

  /**
   * @brief Reschedule a timer with a new delay.
   *
   * @param poll Poll instance the timer belongs to.
   * @param timer Timer handle to reschedule.
   * @param new_delay_ms New delay in milliseconds.
   * @return 0 on success, -1 on error.
   */
  extern int Socket_simple_timer_reschedule (SocketSimple_Poll_T poll,
                                             SocketSimple_Timer_T timer,
                                             int64_t new_delay_ms);

  /**
   * @brief Pause a timer.
   *
   * Preserves remaining time for later resumption.
   *
   * @param poll Poll instance the timer belongs to.
   * @param timer Timer handle to pause.
   * @return 0 on success, -1 on error.
   */
  extern int Socket_simple_timer_pause (SocketSimple_Poll_T poll,
                                        SocketSimple_Timer_T timer);

  /**
   * @brief Resume a paused timer.
   *
   * @param poll Poll instance the timer belongs to.
   * @param timer Timer handle to resume.
   * @return 0 on success, -1 on error.
   */
  extern int Socket_simple_timer_resume (SocketSimple_Poll_T poll,
                                         SocketSimple_Timer_T timer);

  /**
   * @brief Get milliseconds remaining until timer fires.
   *
   * @param poll Poll instance the timer belongs to.
   * @param timer Timer handle to query.
   * @return Milliseconds remaining (>=0), or -1 if invalid/cancelled.
   */
  extern int64_t Socket_simple_timer_remaining (SocketSimple_Poll_T poll,
                                                SocketSimple_Timer_T timer);

  /**
   * @brief Check if timer is valid and pending.
   *
   * @param poll Poll instance the timer belongs to.
   * @param timer Timer handle to check.
   * @return 1 if valid and pending, 0 otherwise.
   */
  extern int Socket_simple_timer_is_pending (SocketSimple_Poll_T poll,
                                             SocketSimple_Timer_T timer);

  /**
   * @brief Get timeout for next timer expiry.
   *
   * Use this as the timeout for Socket_simple_poll_wait().
   *
   * @param poll Poll instance.
   * @return Milliseconds until next timer, or -1 if no timers pending.
   *
   * Example:
   * @code
   * while (running) {
   *     int timeout = Socket_simple_timer_next_timeout(poll);
   *     int n = Socket_simple_poll_wait(poll, events, max, timeout);
   *     // Handle socket events...
   *     Socket_simple_timer_process(poll);
   * }
   * @endcode
   */
  extern int Socket_simple_timer_next_timeout (SocketSimple_Poll_T poll);

  /**
   * @brief Process expired timers.
   *
   * Fires callbacks for all expired timers. Call this after poll_wait().
   * For repeating timers, reschedules them for the next interval.
   *
   * @param poll Poll instance.
   * @return Number of timers fired, or -1 on error.
   */
  extern int Socket_simple_timer_process (SocketSimple_Poll_T poll);

  /**
   * @brief Cancel all pending timers.
   *
   * @param poll Poll instance.
   * @return Number of timers cancelled, or -1 on error.
   */
  extern int Socket_simple_timer_cancel_all (SocketSimple_Poll_T poll);

  /**
   * @brief Get number of active timers.
   *
   * @param poll Poll instance.
   * @return Number of active timers, or -1 on error.
   */
  extern int Socket_simple_timer_count (SocketSimple_Poll_T poll);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_TIMER_INCLUDED */

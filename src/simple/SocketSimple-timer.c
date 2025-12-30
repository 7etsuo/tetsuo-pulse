/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-timer.c
 * @brief Timer implementation for Simple API.
 */

#include "SocketSimple-internal.h"
#include "simple/SocketSimple-timer.h"
#include "simple/SocketSimple-poll.h"

#include "core/SocketTimer.h"
#include "poll/SocketPoll.h"

/*============================================================================
 * Internal Structure
 *============================================================================*/

struct SocketSimple_Timer
{
  SocketTimer_T core_timer;
  SocketSimple_TimerCallback callback;
  void *userdata;
  int is_valid;
};

/*============================================================================
 * Forward declaration: Access internal poll structure
 *============================================================================*/

/* Need access to SocketPoll_T from the Simple poll handle */
extern SocketPoll_T simple_poll_get_core (SocketSimple_Poll_T poll);

/*============================================================================
 * Timer Callback Wrapper
 *============================================================================*/

static void
timer_callback_wrapper (void *data)
{
  struct SocketSimple_Timer *timer = (struct SocketSimple_Timer *)data;
  if (timer && timer->is_valid && timer->callback)
    {
      timer->callback (timer->userdata);
    }
}

/*============================================================================
 * Timer Creation
 *============================================================================*/

/**
 * @brief Function pointer type for core timer creation functions.
 *
 * This type represents the signature of SocketTimer_add() and
 * SocketTimer_add_repeating().
 */
typedef SocketTimer_T (*TimerCreateFn) (SocketPoll_T, int64_t,
                                        SocketTimerCallback, void *);

/**
 * @brief Common implementation for timer creation.
 *
 * This helper function consolidates the shared logic between
 * Socket_simple_timer_add() and Socket_simple_timer_add_repeating().
 *
 * @param poll Poll handle.
 * @param time_ms Delay or interval in milliseconds.
 * @param callback User callback function.
 * @param userdata User data to pass to callback.
 * @param allow_zero Whether to allow zero time_ms (1 = allow, 0 = reject).
 * @param time_error_msg Error message for invalid time parameter.
 * @param create_fn Core timer creation function.
 * @param fail_msg Error message for timer creation failure.
 * @return Timer handle on success, NULL on error.
 */
static SocketSimple_Timer_T
timer_add_common (SocketSimple_Poll_T poll, int64_t time_ms,
                  SocketSimple_TimerCallback callback, void *userdata,
                  int allow_zero, const char *time_error_msg,
                  TimerCreateFn create_fn, const char *fail_msg)
{
  volatile SocketTimer_T core_timer = NULL;

  Socket_simple_clear_error ();

  if (!poll)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid poll handle");
      return NULL;
    }

  if (!callback)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Timer callback required");
      return NULL;
    }

  if (allow_zero ? (time_ms < 0) : (time_ms <= 0))
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, time_error_msg);
      return NULL;
    }

  struct SocketSimple_Timer *handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      return NULL;
    }

  handle->callback = callback;
  handle->userdata = userdata;
  handle->is_valid = 1;

  SocketPoll_T core_poll = simple_poll_get_core (poll);
  if (!core_poll)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid poll handle");
      free (handle);
      return NULL;
    }

  TRY
  {
    core_timer
        = create_fn (core_poll, time_ms, timer_callback_wrapper, handle);
    handle->core_timer = core_timer;
  }
  EXCEPT (SocketTimer_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_POLL, fail_msg);
    free (handle);
    return NULL;
  }
  END_TRY;

  return handle;
}

SocketSimple_Timer_T
Socket_simple_timer_add (SocketSimple_Poll_T poll, int64_t delay_ms,
                          SocketSimple_TimerCallback callback, void *userdata)
{
  return timer_add_common (poll, delay_ms, callback, userdata, 1,
                           "Delay must be non-negative", SocketTimer_add,
                           "Failed to add timer");
}

SocketSimple_Timer_T
Socket_simple_timer_add_repeating (SocketSimple_Poll_T poll,
                                    int64_t interval_ms,
                                    SocketSimple_TimerCallback callback,
                                    void *userdata)
{
  return timer_add_common (poll, interval_ms, callback, userdata, 0,
                           "Interval must be positive",
                           SocketTimer_add_repeating,
                           "Failed to add repeating timer");
}

/*============================================================================
 * Timer Control
 *============================================================================*/

int
Socket_simple_timer_cancel (SocketSimple_Poll_T poll,
                             SocketSimple_Timer_T timer)
{
  Socket_simple_clear_error ();

  if (!poll || !timer)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  if (!timer->is_valid)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Timer already cancelled or fired");
      return -1;
    }

  SocketPoll_T core_poll = simple_poll_get_core (poll);
  if (!core_poll)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid poll handle");
      return -1;
    }

  int result = SocketTimer_cancel (core_poll, timer->core_timer);
  if (result < 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_POLL, "Failed to cancel timer");
      return -1;
    }

  timer->is_valid = 0;
  return 0;
}

int
Socket_simple_timer_reschedule (SocketSimple_Poll_T poll,
                                 SocketSimple_Timer_T timer,
                                 int64_t new_delay_ms)
{
  Socket_simple_clear_error ();

  if (!poll || !timer)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  if (!timer->is_valid)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Timer cancelled or fired");
      return -1;
    }

  SocketPoll_T core_poll = simple_poll_get_core (poll);
  if (!core_poll)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid poll handle");
      return -1;
    }

  int result
      = SocketTimer_reschedule (core_poll, timer->core_timer, new_delay_ms);
  if (result < 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_POLL, "Failed to reschedule timer");
      return -1;
    }

  return 0;
}

int
Socket_simple_timer_pause (SocketSimple_Poll_T poll, SocketSimple_Timer_T timer)
{
  Socket_simple_clear_error ();

  if (!poll || !timer)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  if (!timer->is_valid)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Timer cancelled or fired");
      return -1;
    }

  SocketPoll_T core_poll = simple_poll_get_core (poll);
  if (!core_poll)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid poll handle");
      return -1;
    }

  int result = SocketTimer_pause (core_poll, timer->core_timer);
  if (result < 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_POLL, "Failed to pause timer");
      return -1;
    }

  return 0;
}

int
Socket_simple_timer_resume (SocketSimple_Poll_T poll,
                             SocketSimple_Timer_T timer)
{
  Socket_simple_clear_error ();

  if (!poll || !timer)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  if (!timer->is_valid)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Timer cancelled or fired");
      return -1;
    }

  SocketPoll_T core_poll = simple_poll_get_core (poll);
  if (!core_poll)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid poll handle");
      return -1;
    }

  int result = SocketTimer_resume (core_poll, timer->core_timer);
  if (result < 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_POLL, "Failed to resume timer");
      return -1;
    }

  return 0;
}

/*============================================================================
 * Timer Query
 *============================================================================*/

int64_t
Socket_simple_timer_remaining (SocketSimple_Poll_T poll,
                                SocketSimple_Timer_T timer)
{
  if (!poll || !timer || !timer->is_valid)
    return -1;

  SocketPoll_T core_poll = simple_poll_get_core (poll);
  if (!core_poll)
    return -1;

  return SocketTimer_remaining (core_poll, timer->core_timer);
}

int
Socket_simple_timer_is_pending (SocketSimple_Poll_T poll,
                                 SocketSimple_Timer_T timer)
{
  if (!poll || !timer)
    return 0;

  if (!timer->is_valid)
    return 0;

  SocketPoll_T core_poll = simple_poll_get_core (poll);
  if (!core_poll)
    return 0;

  int64_t remaining = SocketTimer_remaining (core_poll, timer->core_timer);
  return (remaining >= 0) ? 1 : 0;
}

/*============================================================================
 * Timer Processing
 *============================================================================*/

int
Socket_simple_timer_next_timeout (SocketSimple_Poll_T poll
                                   __attribute__ ((unused)))
{
  /* Timer timeout calculation is handled internally by SocketPoll_wait.
   * This function is provided for API completeness but returns -1
   * to indicate the caller should use default timeout. */
  return -1;
}

int
Socket_simple_timer_process (SocketSimple_Poll_T poll
                              __attribute__ ((unused)))
{
  /* Timer processing is handled internally by SocketPoll_wait.
   * This function is provided for API completeness. */
  return 0;
}

int
Socket_simple_timer_cancel_all (SocketSimple_Poll_T poll
                                 __attribute__ ((unused)))
{
  Socket_simple_clear_error ();

  /* Not currently supported - timers must be cancelled individually. */
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "Cancel all timers not supported");
  return -1;
}

/*============================================================================
 * Timer Statistics
 *============================================================================*/

int
Socket_simple_timer_count (SocketSimple_Poll_T poll __attribute__ ((unused)))
{
  Socket_simple_clear_error ();

  /* Timer count not available from core API. */
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "Timer count not supported");
  return -1;
}

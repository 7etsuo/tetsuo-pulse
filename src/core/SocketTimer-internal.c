/**
 * SocketTimer-internal.c - Internal helpers for timer subsystem
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This file contains internal helper functions for the timer subsystem
 * including time utilities, validation, and timer initialization.
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketTimer-internal.h"
#include "core/SocketTimer-private.h"
#include "core/SocketTimer.h"

/* Forward declaration for timer heap getter */
struct SocketTimer_heap_T *socketpoll_get_timer_heap (SocketPoll_T poll);

/* Thread-local error buffer */
#ifdef _WIN32
__declspec (thread) char sockettimer_error_buf[SOCKET_TIMER_ERROR_BUFSIZE];
__declspec (thread) Except_T SocketTimer_DetailedException;
#else
__thread char sockettimer_error_buf[SOCKET_TIMER_ERROR_BUFSIZE];
__thread Except_T SocketTimer_DetailedException;
#endif

/* ============================================================================
 * Time Utilities
 * ============================================================================ */

/**
 * sockettimer_now_ms - Get current monotonic time in milliseconds
 *
 * Returns: Current time in milliseconds since arbitrary monotonic epoch
 * Raises: SocketTimer_Failed if clock_gettime fails
 * Thread-safe: Yes
 */
int64_t
sockettimer_now_ms (void)
{
  struct timespec ts;

  if (clock_gettime (CLOCK_MONOTONIC, &ts) < 0)
    {
      SOCKETTIMER_ERROR_FMT ("Failed to get monotonic time");
      RAISE_SOCKETTIMER_ERROR (SocketTimer_Failed);
    }

  return (int64_t)ts.tv_sec * SOCKET_MS_PER_SECOND
         + (int64_t)ts.tv_nsec / SOCKET_NS_PER_MS;
}

/* ============================================================================
 * Validation Helpers
 * ============================================================================ */

/**
 * sockettimer_validate_heap - Validate heap is available from poll
 * @poll: Poll instance
 *
 * Returns: Heap pointer
 * Raises: SocketTimer_Failed if heap not available
 */
SocketTimer_heap_T *
sockettimer_validate_heap (SocketPoll_T poll)
{
  SocketTimer_heap_T *heap;

  heap = socketpoll_get_timer_heap (poll);
  if (!heap)
    {
      SOCKETTIMER_ERROR_MSG ("Timer heap not available");
      RAISE_SOCKETTIMER_ERROR (SocketTimer_Failed);
    }

  return heap;
}

/**
 * sockettimer_validate_delay - Validate delay parameter
 * @delay_ms: Delay in milliseconds
 *
 * Raises: SocketTimer_Failed if delay is invalid
 */
void
sockettimer_validate_delay (int64_t delay_ms)
{
  if (delay_ms < 0)
    {
      SOCKETTIMER_ERROR_MSG ("Invalid delay: %" PRId64 " (must be >= 0)",
                            delay_ms);
      RAISE_SOCKETTIMER_ERROR (SocketTimer_Failed);
    }
}

/**
 * sockettimer_validate_interval - Validate interval parameter
 * @interval_ms: Interval in milliseconds
 *
 * Raises: SocketTimer_Failed if interval is invalid
 */
void
sockettimer_validate_interval (int64_t interval_ms)
{
  if (interval_ms < 1)
    {
      SOCKETTIMER_ERROR_MSG ("Invalid interval: %" PRId64 " (must be >= 1)",
                            interval_ms);
      RAISE_SOCKETTIMER_ERROR (SocketTimer_Failed);
    }
}

/* ============================================================================
 * Timer Allocation and Initialization
 * ============================================================================ */

/**
 * sockettimer_allocate_timer - Allocate timer structure from arena
 * @arena: Arena to allocate from
 *
 * Returns: Allocated timer structure
 * Raises: SocketTimer_Failed on allocation failure
 */
struct SocketTimer_T *
sockettimer_allocate_timer (Arena_T arena)
{
  struct SocketTimer_T *timer;

  timer = CALLOC (arena, 1, sizeof (*timer));
  if (!timer)
    {
      SOCKETTIMER_ERROR_MSG ("Failed to allocate timer structure");
      RAISE_SOCKETTIMER_ERROR (SocketTimer_Failed);
    }

  return timer;
}

/**
 * sockettimer_init_oneshot - Initialize a one-shot timer
 * @timer: Timer to initialize
 * @delay_ms: Delay in milliseconds
 * @callback: Callback function
 * @userdata: User data for callback
 */
void
sockettimer_init_oneshot (struct SocketTimer_T *timer, int64_t delay_ms,
                          SocketTimerCallback callback, void *userdata)
{
  int64_t now_ms = sockettimer_now_ms ();

  timer->expiry_ms = now_ms + delay_ms;
  timer->interval_ms = 0; /* One-shot */
  timer->callback = callback;
  timer->userdata = userdata;
  timer->cancelled = 0;
}

/**
 * sockettimer_init_repeating - Initialize a repeating timer
 * @timer: Timer to initialize
 * @interval_ms: Interval in milliseconds
 * @callback: Callback function
 * @userdata: User data for callback
 */
void
sockettimer_init_repeating (struct SocketTimer_T *timer, int64_t interval_ms,
                            SocketTimerCallback callback, void *userdata)
{
  int64_t now_ms = sockettimer_now_ms ();

  timer->expiry_ms = now_ms + interval_ms;
  timer->interval_ms = interval_ms; /* Repeating */
  timer->callback = callback;
  timer->userdata = userdata;
  timer->cancelled = 0;
}

/* ============================================================================
 * Heap Index Calculations
 * ============================================================================ */

/**
 * sockettimer_heap_parent - Get parent index in heap
 * @index: Current index
 *
 * Returns: Parent index
 */
size_t
sockettimer_heap_parent (size_t index)
{
  return (index - 1) / 2;
}

/**
 * sockettimer_heap_left_child - Get left child index in heap
 * @index: Current index
 *
 * Returns: Left child index
 */
size_t
sockettimer_heap_left_child (size_t index)
{
  return 2 * index + 1;
}

/**
 * sockettimer_heap_right_child - Get right child index in heap
 * @index: Current index
 *
 * Returns: Right child index
 */
size_t
sockettimer_heap_right_child (size_t index)
{
  return 2 * index + 2;
}

/**
 * sockettimer_heap_swap - Swap two timers in heap array
 * @timers: Timer array
 * @i: First index
 * @j: Second index
 */
void
sockettimer_heap_swap (struct SocketTimer_T **timers, size_t i, size_t j)
{
  struct SocketTimer_T *temp = timers[i];
  timers[i] = timers[j];
  timers[j] = temp;
}

/* ============================================================================
 * Heap Operations
 * ============================================================================ */

/**
 * sockettimer_heap_sift_up - Restore heap property by moving element up
 * @timers: Timer array
 * @index: Starting index
 */
void
sockettimer_heap_sift_up (struct SocketTimer_T **timers, size_t index)
{
  while (index > 0)
    {
      size_t parent = sockettimer_heap_parent (index);
      if (timers[index]->expiry_ms >= timers[parent]->expiry_ms)
        break;
      sockettimer_heap_swap (timers, index, parent);
      index = parent;
    }
}

/**
 * sockettimer_heap_sift_down - Restore heap property by moving element down
 * @timers: Timer array
 * @count: Number of elements
 * @index: Starting index
 */
void
sockettimer_heap_sift_down (struct SocketTimer_T **timers, size_t count,
                            size_t index)
{
  while (1)
    {
      size_t left = sockettimer_heap_left_child (index);
      size_t right = sockettimer_heap_right_child (index);
      size_t smallest = index;

      if (left < count
          && timers[left]->expiry_ms < timers[smallest]->expiry_ms)
        smallest = left;

      if (right < count
          && timers[right]->expiry_ms < timers[smallest]->expiry_ms)
        smallest = right;

      if (smallest == index)
        break;

      sockettimer_heap_swap (timers, index, smallest);
      index = smallest;
    }
}

/**
 * sockettimer_heap_resize - Resize heap array to new capacity
 * @heap: Heap to resize
 * @new_capacity: New capacity (must be > current count)
 *
 * Raises: SocketTimer_Failed on allocation failure
 */
void
sockettimer_heap_resize (SocketTimer_heap_T *heap, size_t new_capacity)
{
  struct SocketTimer_T **new_timers;

  assert (new_capacity > heap->count);

  new_timers = CALLOC (heap->arena, new_capacity, sizeof (*new_timers));
  if (!new_timers)
    {
      SOCKETTIMER_ERROR_MSG ("Failed to resize timer heap array");
      RAISE_SOCKETTIMER_ERROR (SocketTimer_Failed);
    }

  memcpy (new_timers, heap->timers, heap->count * sizeof (*new_timers));
  heap->timers = new_timers;
  heap->capacity = new_capacity;
}

/**
 * sockettimer_skip_cancelled - Skip cancelled timers at root of heap
 * @heap: Timer heap
 *
 * Thread-safe: No (caller must hold heap->mutex)
 */
void
sockettimer_skip_cancelled (SocketTimer_heap_T *heap)
{
  while (heap->count > 0 && heap->timers[0]->cancelled)
    {
      heap->timers[0] = heap->timers[heap->count - 1];
      heap->count--;

      if (heap->count > 0)
        sockettimer_heap_sift_down (heap->timers, heap->count, 0);
    }
}

/**
 * sockettimer_find_in_heap - Find timer in heap
 * @heap: Timer heap
 * @timer: Timer to find
 *
 * Returns: 1 if found and not cancelled, 0 otherwise
 * Thread-safe: No (caller must hold heap->mutex)
 */
int
sockettimer_find_in_heap (SocketTimer_heap_T *heap,
                          const struct SocketTimer_T *timer)
{
  size_t i;

  for (i = 0; i < heap->count; i++)
    {
      if (heap->timers[i] == timer && !heap->timers[i]->cancelled)
        return 1;
    }

  return 0;
}


/**
 * SocketTimer.c - Timer subsystem with min-heap implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This module provides a timer subsystem for scheduling callbacks
 * using a min-heap data structure for efficient O(log n) operations.
 *
 * FEATURES:
 * - One-shot and repeating timers
 * - Monotonic clock timestamps (immune to wall-clock changes)
 * - O(log n) insert/delete, O(1) next-timer lookup
 * - Lazy cancellation (timers marked cancelled, removed when popped)
 * - Thread-safe operations with mutex protection
 * - Arena-based memory management
 *
 * TIMING PRECISION:
 * - Uses CLOCK_MONOTONIC for timestamps
 * - Millisecond resolution
 * - Timers may fire slightly after their deadline
 *
 * THREAD SAFETY:
 * - All public operations are thread-safe
 * - Callbacks execute in the calling thread
 * - Do not call SocketTimer_cancel() from within timer callbacks
 */

#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketTimer-private.h"
#include "core/SocketTimer.h"
#include "core/SocketUtil.h"

/* ===========================================================================
 * Thread-Local Error Handling
 * ===========================================================================*/

/* Timer exception definition */
const Except_T SocketTimer_Failed
    = { &SocketTimer_Failed, "Timer operation failed" };

/* Thread-local exception using centralized macro */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketTimer);

/* Forward declaration for timer heap getter */
struct SocketTimer_heap_T *socketpoll_get_timer_heap (SocketPoll_T poll);

/* ===========================================================================
 * Validation Helpers (Static)
 * ===========================================================================*/

/**
 * sockettimer_validate_heap - Validate heap is available from poll
 * @poll: Poll instance
 *
 * Returns: Heap pointer
 * Raises: SocketTimer_Failed if heap not available
 */
static SocketTimer_heap_T *
sockettimer_validate_heap (SocketPoll_T poll)
{
  SocketTimer_heap_T *heap;

  heap = socketpoll_get_timer_heap (poll);
  if (!heap)
    {
      SOCKET_ERROR_MSG ("Timer heap not available");
      SOCKET_RAISE_MODULE_ERROR (SocketTimer, SocketTimer_Failed);
    }

  return heap;
}

/**
 * sockettimer_validate_delay - Validate delay parameter
 * @delay_ms: Delay in milliseconds
 *
 * Raises: SocketTimer_Failed if delay is invalid
 */
static void
sockettimer_validate_delay (int64_t delay_ms)
{
  if (delay_ms < 0)
    {
      SOCKET_ERROR_MSG ("Invalid delay: %" PRId64 " (must be >= 0)",
                            delay_ms);
      SOCKET_RAISE_MODULE_ERROR (SocketTimer, SocketTimer_Failed);
    }
}

/**
 * sockettimer_validate_interval - Validate interval parameter
 * @interval_ms: Interval in milliseconds
 *
 * Raises: SocketTimer_Failed if interval is invalid
 */
static void
sockettimer_validate_interval (int64_t interval_ms)
{
  if (interval_ms < 1)
    {
      SOCKET_ERROR_MSG ("Invalid interval: %" PRId64 " (must be >= 1)",
                            interval_ms);
      SOCKET_RAISE_MODULE_ERROR (SocketTimer, SocketTimer_Failed);
    }
}

/* ===========================================================================
 * Timer Allocation and Initialization (Static)
 * ===========================================================================*/

/**
 * sockettimer_allocate_timer - Allocate timer structure from arena
 * @arena: Arena to allocate from
 *
 * Returns: Allocated timer structure
 * Raises: SocketTimer_Failed on allocation failure
 */
static struct SocketTimer_T *
sockettimer_allocate_timer (Arena_T arena)
{
  struct SocketTimer_T *timer;

  timer = CALLOC (arena, 1, sizeof (*timer));
  if (!timer)
    {
      SOCKET_ERROR_MSG ("Failed to allocate timer structure");
      SOCKET_RAISE_MODULE_ERROR (SocketTimer, SocketTimer_Failed);
    }

  return timer;
}

/**
 * sockettimer_init_timer - Initialize a timer (one-shot or repeating)
 * @timer: Timer to initialize
 * @delay_ms: Initial delay in milliseconds
 * @interval_ms: Interval for repeating (0 for one-shot)
 * @callback: Callback function
 * @userdata: User data for callback
 *
 * Internal helper that consolidates one-shot and repeating timer init.
 */
static void
sockettimer_init_timer (struct SocketTimer_T *timer, int64_t delay_ms,
                        int64_t interval_ms, SocketTimerCallback callback,
                        void *userdata)
{
  int64_t now_ms = Socket_get_monotonic_ms ();

  timer->expiry_ms = now_ms + delay_ms;
  timer->interval_ms = interval_ms;
  timer->callback = callback;
  timer->userdata = userdata;
  timer->cancelled = 0;
}


/* ===========================================================================
 * Heap Index Calculations (Static)
 * ===========================================================================*/

/**
 * sockettimer_heap_parent - Get parent index in heap
 * @index: Current index
 *
 * Returns: Parent index
 */
static size_t
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
static size_t
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
static size_t
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
static void
sockettimer_heap_swap (struct SocketTimer_T **timers, size_t i, size_t j)
{
  struct SocketTimer_T *temp = timers[i];
  timers[i] = timers[j];
  timers[j] = temp;
}

/* ===========================================================================
 * Heap Operations (Static)
 * ===========================================================================*/

/**
 * sockettimer_heap_sift_up - Restore heap property by moving element up
 * @timers: Timer array
 * @index: Starting index
 */
static void
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
static void
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
static void
sockettimer_heap_resize (SocketTimer_heap_T *heap, size_t new_capacity)
{
  struct SocketTimer_T **new_timers;

  assert (new_capacity > heap->count);

  new_timers = CALLOC (heap->arena, new_capacity, sizeof (*new_timers));
  if (!new_timers)
    {
      SOCKET_ERROR_MSG ("Failed to resize timer heap array");
      SOCKET_RAISE_MODULE_ERROR (SocketTimer, SocketTimer_Failed);
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
static void
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
 * sockettimer_find_in_heap - Find timer in heap and return its index
 * @heap: Timer heap
 * @timer: Timer to find
 *
 * Returns: Index of timer if found and not cancelled, -1 otherwise
 * Thread-safe: No (caller must hold heap->mutex)
 */
static ssize_t
sockettimer_find_in_heap (const SocketTimer_heap_T *heap,
                          const struct SocketTimer_T *timer)
{
  size_t i;

  for (i = 0; i < heap->count; i++)
    {
      if (heap->timers[i] == timer && !heap->timers[i]->cancelled)
        return (ssize_t)i;
    }

  return -1;
}

/**
 * sockettimer_ensure_capacity - Ensure heap has capacity for new element
 * @heap: Timer heap
 *
 * Raises: SocketTimer_Failed on capacity overflow or allocation failure
 * Thread-safe: No (caller must hold heap->mutex)
 */
static void
sockettimer_ensure_capacity (SocketTimer_heap_T *heap)
{
  size_t new_capacity;

  if (heap->count < heap->capacity)
    return;

  new_capacity = heap->capacity * SOCKET_TIMER_HEAP_GROWTH_FACTOR;
  if (new_capacity <= heap->capacity)
    {
      SOCKET_ERROR_MSG ("Timer heap capacity overflow");
      SOCKET_RAISE_MODULE_ERROR (SocketTimer, SocketTimer_Failed);
    }

  sockettimer_heap_resize (heap, new_capacity);
}

/**
 * sockettimer_assign_id - Assign unique ID to timer
 * @heap: Timer heap
 * @timer: Timer to assign ID to
 *
 * Thread-safe: No (caller must hold heap->mutex)
 */
static void
sockettimer_assign_id (SocketTimer_heap_T *heap, struct SocketTimer_T *timer)
{
  timer->id = heap->next_id++;
  if (heap->next_id == 0)
    heap->next_id = 1;
}

/**
 * sockettimer_extract_root - Extract root timer from heap
 * @heap: Timer heap
 *
 * Returns: Root timer
 * Thread-safe: No (caller must hold heap->mutex)
 */
static struct SocketTimer_T *
sockettimer_extract_root (SocketTimer_heap_T *heap)
{
  struct SocketTimer_T *result = heap->timers[0];

  heap->timers[0] = heap->timers[heap->count - 1];
  heap->count--;

  if (heap->count > 0)
    sockettimer_heap_sift_down (heap->timers, heap->count, 0);

  return result;
}

/**
 * sockettimer_handle_expired - Handle a single expired timer
 * @heap: Timer heap
 * @timer: Expired timer
 * @now_ms: Current time
 *
 * Returns: 1 if timer was fired, 0 if timer not yet expired
 * Thread-safe: No (caller should not hold mutex during callback)
 */
static int
sockettimer_handle_expired (SocketTimer_heap_T *heap,
                            struct SocketTimer_T *timer, int64_t now_ms)
{
  SocketTimerCallback callback;
  void *userdata;

  if (timer->expiry_ms > now_ms)
    {
      SocketTimer_heap_push (heap, timer);
      return 0;
    }

  callback = timer->callback;
  userdata = timer->userdata;

  if (timer->interval_ms > 0)
    {
      timer->expiry_ms += timer->interval_ms;
      SocketTimer_heap_push (heap, timer);
    }

  if (callback)
    callback (userdata);

  return 1;
}

/* ===========================================================================
 * Heap Allocation Helpers (Static)
 * ===========================================================================*/

/**
 * sockettimer_heap_alloc_structure - Allocate heap structure from arena
 * @arena: Arena to allocate from
 *
 * Returns: Allocated heap or NULL on failure
 */
static SocketTimer_heap_T *
sockettimer_heap_alloc_structure (Arena_T arena)
{
  return CALLOC (arena, 1, sizeof (SocketTimer_heap_T));
}

/**
 * sockettimer_heap_alloc_timers - Allocate timers array from arena
 * @arena: Arena to allocate from
 *
 * Returns: Allocated timer array or NULL on failure
 */
static struct SocketTimer_T **
sockettimer_heap_alloc_timers (Arena_T arena)
{
  return CALLOC (arena, SOCKET_TIMER_HEAP_INITIAL_CAPACITY,
                 sizeof (struct SocketTimer_T *));
}

/**
 * sockettimer_heap_init_state - Initialize heap state fields
 * @heap: Heap to initialize
 * @timers: Timer array to assign
 * @arena: Arena to store
 */
static void
sockettimer_heap_init_state (SocketTimer_heap_T *heap,
                             struct SocketTimer_T **timers, Arena_T arena)
{
  heap->timers = timers;
  heap->count = 0;
  heap->capacity = SOCKET_TIMER_HEAP_INITIAL_CAPACITY;
  heap->next_id = 1;
  heap->arena = arena;
}

/* ===========================================================================
 * Heap Public API
 * ===========================================================================*/

/**
 * SocketTimer_heap_new - Create a new timer heap
 * @arena: Arena to allocate from
 *
 * Returns: New heap instance or NULL on error
 * Thread-safe: No (heap not yet initialized)
 */
SocketTimer_heap_T *
SocketTimer_heap_new (Arena_T arena)
{
  SocketTimer_heap_T *heap;
  struct SocketTimer_T **timers;

  if (!arena)
    return NULL;

  heap = sockettimer_heap_alloc_structure (arena);
  if (!heap)
    return NULL;

  timers = sockettimer_heap_alloc_timers (arena);
  if (!timers)
    return NULL;

  sockettimer_heap_init_state (heap, timers, arena);

  if (pthread_mutex_init (&heap->mutex, NULL) != 0)
    return NULL;

  return heap;
}

/**
 * SocketTimer_heap_free - Free timer heap and all timers
 * @heap: Heap to free (may be NULL)
 *
 * Thread-safe: No (caller must ensure no concurrent access)
 */
void
SocketTimer_heap_free (SocketTimer_heap_T **heap)
{
  if (!heap || !*heap)
    return;

  pthread_mutex_destroy (&(*heap)->mutex);
  *heap = NULL;
}

/**
 * SocketTimer_heap_push - Add timer to heap
 * @heap: Timer heap
 * @timer: Timer to add (takes ownership)
 *
 * Raises: SocketTimer_Failed on allocation failure
 * Thread-safe: Yes - uses heap mutex
 */
void
SocketTimer_heap_push (SocketTimer_heap_T *heap, struct SocketTimer_T *timer)
{
  assert (heap);
  assert (timer);

  pthread_mutex_lock (&heap->mutex);

  TRY
    {
      sockettimer_ensure_capacity (heap);
      sockettimer_assign_id (heap, timer);

      heap->timers[heap->count] = timer;
      heap->count++;

      sockettimer_heap_sift_up (heap->timers, heap->count - 1);
    }
  FINALLY
    {
      pthread_mutex_unlock (&heap->mutex);
    }
  END_TRY;
}

/**
 * SocketTimer_heap_pop - Remove and return earliest timer
 * @heap: Timer heap
 *
 * Returns: Earliest timer or NULL if heap empty
 * Thread-safe: Yes - uses heap mutex
 */
struct SocketTimer_T *
SocketTimer_heap_pop (SocketTimer_heap_T *heap)
{
  struct SocketTimer_T *result;

  assert (heap);

  pthread_mutex_lock (&heap->mutex);

  sockettimer_skip_cancelled (heap);

  if (heap->count == 0)
    {
      pthread_mutex_unlock (&heap->mutex);
      return NULL;
    }

  result = sockettimer_extract_root (heap);

  pthread_mutex_unlock (&heap->mutex);
  return result;
}

/**
 * SocketTimer_heap_peek - Get earliest timer without removing
 * @heap: Timer heap
 *
 * Returns: Earliest timer or NULL if heap empty
 * Thread-safe: Yes - uses heap mutex
 */
struct SocketTimer_T *
SocketTimer_heap_peek (SocketTimer_heap_T *heap)
{
  struct SocketTimer_T *result;

  assert (heap);

  pthread_mutex_lock (&heap->mutex);

  sockettimer_skip_cancelled (heap);

  result = (heap->count > 0) ? heap->timers[0] : NULL;

  pthread_mutex_unlock (&heap->mutex);
  return result;
}

/**
 * SocketTimer_heap_peek_delay - Get milliseconds until next timer expiry
 * @heap: Timer heap
 *
 * Returns: Milliseconds until next timer (>= 0), or -1 if no timers
 * Thread-safe: Yes - uses heap mutex
 */
int64_t
SocketTimer_heap_peek_delay (const SocketTimer_heap_T *heap)
{
  const struct SocketTimer_T *timer;
  int64_t now_ms;
  int64_t delay_ms;

  assert (heap);

  timer = SocketTimer_heap_peek ((SocketTimer_heap_T *)heap);
  if (!timer)
    return -1;

  now_ms = Socket_get_monotonic_ms ();
  delay_ms = timer->expiry_ms - now_ms;

  return delay_ms > 0 ? delay_ms : 0;
}

/**
 * SocketTimer_heap_cancel - Mark timer as cancelled (lazy deletion)
 * @heap: Timer heap
 * @timer: Timer to cancel
 *
 * Returns: 0 on success, -1 if timer not found
 * Thread-safe: Yes - uses heap mutex
 */
int
SocketTimer_heap_cancel (SocketTimer_heap_T *heap, struct SocketTimer_T *timer)
{
  ssize_t idx;

  assert (heap);
  assert (timer);

  pthread_mutex_lock (&heap->mutex);

  idx = sockettimer_find_in_heap (heap, timer);
  if (idx >= 0)
    heap->timers[idx]->cancelled = 1;

  pthread_mutex_unlock (&heap->mutex);
  return (idx >= 0) ? 0 : -1;
}

/**
 * SocketTimer_heap_remaining - Get milliseconds until timer expiry
 * @heap: Timer heap
 * @timer: Timer to query
 *
 * Returns: Milliseconds until expiry (>= 0), or -1 if timer not found/cancelled
 * Thread-safe: Yes - uses heap mutex
 */
int64_t
SocketTimer_heap_remaining (SocketTimer_heap_T *heap,
                            const struct SocketTimer_T *timer)
{
  int64_t now_ms;
  int64_t remaining;
  ssize_t idx;

  assert (heap);
  assert (timer);

  pthread_mutex_lock (&heap->mutex);

  idx = sockettimer_find_in_heap (heap, timer);

  if (idx < 0)
    {
      pthread_mutex_unlock (&heap->mutex);
      return -1;
    }

  now_ms = Socket_get_monotonic_ms ();
  remaining = timer->expiry_ms - now_ms;

  pthread_mutex_unlock (&heap->mutex);

  return remaining > 0 ? remaining : 0;
}

/**
 * SocketTimer_process_expired - Fire all expired timers and return count
 * @heap: Timer heap
 *
 * Returns: Number of timers that fired
 * Thread-safe: Yes - uses heap mutex
 *
 * Callbacks are invoked outside the mutex to prevent deadlocks.
 * Repeating timers are rescheduled after firing.
 */
int
SocketTimer_process_expired (SocketTimer_heap_T *heap)
{
  int fired_count = 0;
  int64_t now_ms;

  assert (heap);

  now_ms = Socket_get_monotonic_ms ();

  while (1)
    {
      struct SocketTimer_T *timer = SocketTimer_heap_pop (heap);
      if (!timer)
        break;

      if (!sockettimer_handle_expired (heap, timer, now_ms))
        break;

      fired_count++;
    }

  return fired_count;
}

/* ===========================================================================
 * Internal Timer Creation Helper
 * ===========================================================================*/

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

  /* Initialize timer: repeating uses interval for both delay and interval,
   * one-shot uses delay_ms with zero interval */
  if (interval_ms > 0)
    sockettimer_init_timer (timer, interval_ms, interval_ms, callback, userdata);
  else
    sockettimer_init_timer (timer, delay_ms, 0, callback, userdata);

  SocketTimer_heap_push (heap, timer);

  return timer;
}

/* ===========================================================================
 * Public Timer API
 * ===========================================================================*/

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

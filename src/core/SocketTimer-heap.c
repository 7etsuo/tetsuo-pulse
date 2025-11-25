/**
 * SocketTimer-heap.c - Min-heap implementation for timer subsystem
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This file contains the min-heap implementation for efficient timer
 * management with O(log n) insert/delete and O(1) next-timer lookup.
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketTimer-internal.h"
#include "core/SocketTimer-private.h"
#include "core/SocketTimer.h"

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

  if (!arena)
    return NULL;

  heap = CALLOC (arena, 1, sizeof (*heap));
  if (!heap)
    return NULL;

  heap->timers
      = CALLOC (arena, SOCKET_TIMER_HEAP_INITIAL_CAPACITY, sizeof (*heap->timers));
  if (!heap->timers)
    return NULL;

  heap->count = 0;
  heap->capacity = SOCKET_TIMER_HEAP_INITIAL_CAPACITY;
  heap->next_id = 1; /* Start IDs at 1 */
  heap->arena = arena;

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
      SOCKETTIMER_ERROR_MSG ("Timer heap capacity overflow");
      RAISE_SOCKETTIMER_ERROR (SocketTimer_Failed);
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
  struct SocketTimer_T *timer;
  int64_t now_ms;
  int64_t delay_ms;

  assert (heap);

  timer = SocketTimer_heap_peek ((SocketTimer_heap_T *)heap);
  if (!timer)
    return -1;

  now_ms = sockettimer_now_ms ();
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

  now_ms = sockettimer_now_ms ();
  remaining = timer->expiry_ms - now_ms;

  pthread_mutex_unlock (&heap->mutex);

  return remaining > 0 ? remaining : 0;
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
  struct SocketTimer_T *timer;

  assert (heap);

  now_ms = sockettimer_now_ms ();

  while (1)
    {
      timer = SocketTimer_heap_pop (heap);
      if (!timer)
        break;

      if (!sockettimer_handle_expired (heap, timer, now_ms))
        break;

      fired_count++;
    }

  return fired_count;
}


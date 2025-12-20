/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketTimer.c - Timer subsystem with min-heap implementation
 *
 * Part of the Socket Library
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
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketSecurity.h"
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
  SocketTimer_heap_T *heap = socketpoll_get_timer_heap (poll);

  if (!heap)
    SOCKET_RAISE_MSG (SocketTimer, SocketTimer_Failed,
                      "Timer heap not available");

  return heap;
}

/**
 * sockettimer_validate_time - Validate time parameter (delay or interval)
 * @time_ms: Time value in milliseconds
 * @min_time: Minimum allowed value
 * @time_name: Name for error message ("delay" or "interval")
 *
 * Raises: SocketTimer_Failed if time_ms < min_time
 */
static void
sockettimer_validate_time (int64_t time_ms, int64_t min_time, int64_t max_time,
                           const char *time_name)
{
  if (time_ms < min_time)
    SOCKET_RAISE_MSG (SocketTimer, SocketTimer_Failed,
                      "Invalid %s: %" PRId64 " (must be >= %" PRId64 ")",
                      time_name, time_ms, min_time);

  if (max_time >= 0 && time_ms > max_time)
    SOCKET_RAISE_MSG (SocketTimer, SocketTimer_Failed,
                      "Invalid %s: %" PRId64 " (must be <= %" PRId64 ")",
                      time_name, time_ms, max_time);
}

/**
 * sockettimer_validate_timer_params - Validate delay and interval parameters
 * @delay_ms: Initial delay in ms
 * @interval_ms: Repeat interval in ms (0 for one-shot)
 * @is_repeating: Non-zero if repeating timer
 *
 * Raises: SocketTimer_Failed on invalid parameters
 * Thread-safe: Yes
 */
static void
sockettimer_validate_timer_params (int64_t delay_ms, int64_t interval_ms,
                                   int is_repeating)
{
  int64_t max_delay_ms = SOCKET_MAX_TIMER_DELAY_MS;

  if (is_repeating)
    {
      sockettimer_validate_time (interval_ms, SOCKET_TIMER_MIN_INTERVAL_MS,
                                 max_delay_ms, "interval");
      sockettimer_validate_time (delay_ms, SOCKET_TIMER_MIN_INTERVAL_MS,
                                 max_delay_ms, "initial delay");
    }
  else
    {
      sockettimer_validate_time (delay_ms, SOCKET_TIMER_MIN_DELAY_MS,
                                 max_delay_ms, "delay");
    }
}

/* ===========================================================================
 * Timer Allocation and Initialization (Static)
 * ===========================================================================*/

/**
 * sockettimer_calloc_with_raise - Arena CALLOC with error raising
 * @arena: Arena to allocate from
 * @nmemb: Number of elements
 * @size: Size of each element
 * @desc: Description for error message
 *
 * Returns: Allocated memory or raises SocketTimer_Failed
 */
static void *
sockettimer_calloc_with_raise (Arena_T arena, size_t nmemb, size_t size,
                               const char *desc)
{
  void *p = CALLOC (arena, nmemb, size);
  if (!p)
    SOCKET_RAISE_MSG (SocketTimer, SocketTimer_Failed,
                      "Failed to CALLOC %s: %zu * %zu bytes", desc, nmemb,
                      size);
  return p;
}

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
  return sockettimer_calloc_with_raise (
      arena, 1, sizeof (struct SocketTimer_T), "timer structure");
}

/**
 * sockettimer_init_timer - Initialize a timer with given parameters
 * @timer: Timer to initialize
 * @delay_ms: Initial delay in milliseconds
 * @interval_ms: Repeat interval (0 for one-shot timers)
 * @callback: Callback function
 * @userdata: User data for callback
 *
 * Unified initialization for both one-shot and repeating timers.
 */
static void
sockettimer_init_timer (struct SocketTimer_T *timer, int64_t delay_ms,
                        int64_t interval_ms, SocketTimerCallback callback,
                        void *userdata)
{
  int64_t now_ms = Socket_get_monotonic_ms ();

  int64_t safe_delay = delay_ms;
  if (delay_ms > 0 && now_ms > INT64_MAX - delay_ms)
    {
      safe_delay = INT64_MAX - now_ms;
      SOCKET_LOG_WARN_MSG (
          "Timer delay clamped to prevent expiry overflow: %" PRId64
          " -> %" PRId64 " ms",
          delay_ms, safe_delay);
    }
  timer->expiry_ms = now_ms + safe_delay;
  timer->interval_ms = interval_ms;
  timer->callback = callback;
  timer->userdata = userdata;
  timer->cancelled = 0;
  timer->heap_index = SOCKET_TIMER_INVALID_HEAP_INDEX;
}

/**
 * sockettimer_create_timer - Allocate and initialize timer structure
 * @arena: Arena for allocation
 * @delay_ms: Initial delay
 * @interval_ms: Repeat interval (0 for one-shot)
 * @callback: Callback function
 * @userdata: User data
 *
 * Returns: Initialized timer
 * Raises: SocketTimer_Failed on allocation failure
 * Thread-safe: No
 */
static struct SocketTimer_T *
sockettimer_create_timer (Arena_T arena, int64_t delay_ms, int64_t interval_ms,
                          SocketTimerCallback callback, void *userdata)
{
  struct SocketTimer_T *timer = sockettimer_allocate_timer (arena);
  sockettimer_init_timer (timer, delay_ms, interval_ms, callback, userdata);
  return timer;
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

  /* Update heap indices after swap */
  timers[i]->heap_index = i;
  timers[j]->heap_index = j;
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
 * sockettimer_find_smallest_child - Find index of smallest child
 * @timers: Timer array
 * @count: Number of elements
 * @index: Parent index
 *
 * Returns: Index of smallest child, or index if no smaller child
 */
static size_t
sockettimer_find_smallest_child (struct SocketTimer_T **timers, size_t count,
                                 size_t index)
{
  size_t left = sockettimer_heap_left_child (index);
  size_t right = sockettimer_heap_right_child (index);
  size_t smallest = index;

  if (left < count && timers[left]->expiry_ms < timers[smallest]->expiry_ms)
    smallest = left;

  if (right < count && timers[right]->expiry_ms < timers[smallest]->expiry_ms)
    smallest = right;

  return smallest;
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
      size_t smallest = sockettimer_find_smallest_child (timers, count, index);

      if (smallest == index)
        break;

      sockettimer_heap_swap (timers, index, smallest);
      index = smallest;
    }
}

/**
 * sockettimer_heap_move_last_to_root - Move last element to root position and
 * restore heap property
 * @timers: Timer array
 * @count: Pointer to current count (will be decremented by 1)
 *
 * Common logic for removing the root: replaces root with last element,
 * decrements count, and sifts down to restore min-heap property.
 * Used by extract_root and remove_cancelled_root.
 *
 * Thread-safe: No (caller must hold heap mutex)
 */
static void
sockettimer_heap_move_last_to_root (struct SocketTimer_T **timers,
                                    size_t *count)
{
  assert (*count > 0);

  timers[0] = timers[*count - 1];
  timers[0]->heap_index = 0;
  (*count)--;

  if (*count > 0)
    sockettimer_heap_sift_down (timers, *count, 0);
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

  new_timers = sockettimer_calloc_with_raise (
      heap->arena, new_capacity, sizeof (*new_timers), "heap timers array");

  memcpy (new_timers, heap->timers, heap->count * sizeof (*new_timers));
  heap->timers = new_timers;
  heap->capacity = new_capacity;
}

/**
 * sockettimer_remove_cancelled_root - Remove cancelled timer at root
 * @heap: Timer heap
 *
 * Thread-safe: No (caller must hold heap->mutex)
 */
static void
sockettimer_remove_cancelled_root (SocketTimer_heap_T *heap)
{
  sockettimer_heap_move_last_to_root (heap->timers, &heap->count);
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
    sockettimer_remove_cancelled_root (heap);
}

/**
 * sockettimer_find_in_heap - Find timer in heap and return its index
 * @heap: Timer heap
 * @timer: Timer to find
 *
 * Returns: Index of timer if found and not cancelled, -1 otherwise
 * Thread-safe: No (caller must hold heap->mutex)
 * Note: O(1) time using maintained heap_index field
 */
static ssize_t
sockettimer_find_in_heap (const SocketTimer_heap_T *heap,
                          const struct SocketTimer_T *timer)
{
  size_t idx = timer->heap_index;
  if (idx != SOCKET_TIMER_INVALID_HEAP_INDEX && idx < heap->count
      && heap->timers[idx] == timer && !timer->cancelled)
    return (ssize_t)idx;

  return -1;
}

/**
 * sockettimer_check_capacity_overflow - Check if capacity growth overflows
 * @current_capacity: Current capacity
 *
 * Returns: 1 if overflow would occur, 0 otherwise
 *
 * Uses SocketSecurity_check_multiply() for consistent overflow-safe arithmetic.
 */
static int
sockettimer_check_capacity_overflow (size_t current_capacity)
{
  size_t new_capacity;
  if (!SocketSecurity_check_multiply (current_capacity,
                                      SOCKET_TIMER_HEAP_GROWTH_FACTOR,
                                      &new_capacity))
    return 1; /* Would overflow */
  return 0;
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

  if (sockettimer_check_capacity_overflow (heap->capacity))
    SOCKET_RAISE_MSG (SocketTimer, SocketTimer_Failed,
                      "Timer heap capacity overflow");

  new_capacity = heap->capacity * SOCKET_TIMER_HEAP_GROWTH_FACTOR;
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
    heap->next_id = SOCKET_TIMER_INITIAL_ID;
}

/**
 * sockettimer_insert_into_heap - Insert timer at end and restore heap
 * @heap: Timer heap
 * @timer: Timer to insert
 *
 * Thread-safe: No (caller must hold heap->mutex)
 */
static void
sockettimer_insert_into_heap (SocketTimer_heap_T *heap,
                              struct SocketTimer_T *timer)
{
  size_t pos = heap->count;
  heap->timers[pos] = timer;
  timer->heap_index = pos;
  heap->count++;
  sockettimer_heap_sift_up (heap->timers, heap->count - 1);
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

  sockettimer_heap_move_last_to_root (heap->timers, &heap->count);

  return result;
}

/**
 * sockettimer_reschedule_repeating - Reschedule a repeating timer
 * @heap: Timer heap
 * @timer: Timer to reschedule
 */
static void
sockettimer_reschedule_repeating (SocketTimer_heap_T *heap,
                                  struct SocketTimer_T *timer)
{
  int64_t new_expiry;
  if (timer->interval_ms > 0
      && timer->expiry_ms > INT64_MAX - timer->interval_ms)
    {
      new_expiry = INT64_MAX;
      SOCKET_LOG_WARN_MSG ("Repeating timer expiry clamped to INT64_MAX due "
                           "to repeated additions overflowing");
    }
  else
    {
      new_expiry = timer->expiry_ms + timer->interval_ms;
    }
  timer->expiry_ms = new_expiry;
  SocketTimer_heap_push (heap, timer);
}

/**
 * sockettimer_invoke_callback - Invoke timer callback if set
 * @timer: Timer with callback to invoke
 */
static void
sockettimer_invoke_callback (struct SocketTimer_T *timer)
{
  if (timer->callback)
    timer->callback (timer->userdata);
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
  if (timer->expiry_ms > now_ms)
    {
      SocketTimer_heap_push (heap, timer);
      return 0;
    }

  if (timer->interval_ms > 0)
    sockettimer_reschedule_repeating (heap, timer);

  sockettimer_invoke_callback (timer);
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
  heap->next_id = SOCKET_TIMER_INITIAL_ID;
  heap->arena = arena;
}

/**
 * sockettimer_heap_init_mutex - Initialize heap mutex
 * @heap: Heap to initialize
 *
 * Returns: 0 on success, non-zero on failure
 */
static int
sockettimer_heap_init_mutex (SocketTimer_heap_T *heap)
{
  return pthread_mutex_init (&heap->mutex, NULL);
}

static inline void
sockettimer_heap_lock (SocketTimer_heap_T *heap)
{
  int ret = pthread_mutex_lock (&heap->mutex);
  if (ret != 0)
    SOCKET_RAISE_MSG (SocketTimer, SocketTimer_Failed,
                      "pthread_mutex_lock failed: %d", ret);
}

static inline void
sockettimer_heap_unlock (SocketTimer_heap_T *heap)
{
  int ret = pthread_mutex_unlock (&heap->mutex);
  if (ret != 0)
    SOCKET_RAISE_MSG (SocketTimer, SocketTimer_Failed,
                      "pthread_mutex_unlock failed: %d", ret);
}

/* ===========================================================================
 * Internal Peek (Unlocked)
 * ===========================================================================*/

/**
 * sockettimer_peek_unlocked - Get earliest timer without lock
 * @heap: Timer heap (already locked)
 *
 * Returns: Earliest timer or NULL if heap empty
 * Thread-safe: No (caller must hold heap->mutex)
 */
static struct SocketTimer_T *
sockettimer_peek_unlocked (SocketTimer_heap_T *heap)
{
  sockettimer_skip_cancelled (heap);
  return (heap->count > 0) ? heap->timers[0] : NULL;
}

/* ===========================================================================
 * Internal Helpers for Public API
 * ===========================================================================*/

/**
 * sockettimer_get_heap_from_poll - Get timer heap from poll, return NULL if
 * unavailable
 * @poll: Poll instance
 *
 * Returns: Heap pointer or NULL
 * Thread-safe: Yes
 *
 * Unlike sockettimer_validate_heap(), this does not raise on failure.
 * Used by cancel/remaining which return -1 on error instead of raising.
 */
static SocketTimer_heap_T *
sockettimer_get_heap_from_poll (SocketPoll_T poll)
{
  return socketpoll_get_timer_heap (poll);
}

/**
 * sockettimer_add_timer_internal - Internal implementation for adding timers
 * @poll: Event poll instance
 * @delay_ms: Initial delay in milliseconds
 * @interval_ms: Repeat interval (0 for one-shot)
 * @callback: Callback function
 * @userdata: User data for callback
 * @is_repeating: Whether this is a repeating timer (for validation)
 *
 * Returns: Timer handle for cancellation
 * Raises: SocketTimer_Failed on error
 * Thread-safe: Yes
 */
static SocketTimer_T
sockettimer_add_timer_internal (SocketPoll_T poll, int64_t delay_ms,
                                int64_t interval_ms,
                                SocketTimerCallback callback, void *userdata,
                                int is_repeating)
{
  SocketTimer_heap_T *heap;
  struct SocketTimer_T *timer;

  assert (poll);
  assert (callback);

  heap = sockettimer_validate_heap (poll);

  sockettimer_validate_timer_params (delay_ms, interval_ms, is_repeating);

  timer = sockettimer_create_timer (heap->arena, delay_ms, interval_ms,
                                    callback, userdata);

  SocketTimer_heap_push (heap, timer);

  return timer;
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
 *
 * @note All allocations below are from the arena. On initialization failure,
 *       partial allocations remain in the arena until Arena_dispose() is
 *       called. This is by design - arena provides batch deallocation only.
 *       Callers must dispose the arena to reclaim memory from partial
 *       initialization failures. This is standard arena semantics, not a leak.
 */
SocketTimer_heap_T *
SocketTimer_heap_new (Arena_T arena)
{
  SocketTimer_heap_T *heap;
  struct SocketTimer_T **timers;

  if (!arena)
    return NULL;

  /* Allocations from arena - freed only when arena is disposed */
  heap = sockettimer_heap_alloc_structure (arena);
  if (!heap)
    return NULL;

  timers = sockettimer_heap_alloc_timers (arena);
  if (!timers)
    /* heap allocation remains in arena until Arena_dispose() */
    return NULL;

  sockettimer_heap_init_state (heap, timers, arena);

  if (sockettimer_heap_init_mutex (heap) != 0)
    /* heap + timers remain in arena until Arena_dispose() */
    return NULL;

  return heap;
}

/**
 * SocketTimer_heap_free - Free timer heap structure and destroy mutex
 * @heap: Heap to free (may be NULL)
 *
 * Frees the heap control structure and destroys the mutex. Individual timers
 * and the timers array are allocated from the arena provided to
 * SocketTimer_heap_new(). To free timer memory, dispose the arena (e.g., via
 * Socket_free or Arena_dispose). Callers typically manage the arena lifetime
 * separately.
 *
 * Thread-safe: No (caller must ensure no concurrent access to heap)
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

  sockettimer_heap_lock (heap);

  TRY
  {
    if (heap->count >= SOCKET_MAX_TIMERS_PER_HEAP)
      SOCKET_RAISE_MSG (
          SocketTimer, SocketTimer_Failed,
          "Cannot add timer: maximum %u timers per heap exceeded",
          SOCKET_MAX_TIMERS_PER_HEAP);

    sockettimer_ensure_capacity (heap);
    sockettimer_assign_id (heap, timer);
    sockettimer_insert_into_heap (heap, timer);
  }
  FINALLY { sockettimer_heap_unlock (heap); }
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

  sockettimer_heap_lock (heap);

  sockettimer_skip_cancelled (heap);

  if (heap->count == 0)
    {
      sockettimer_heap_unlock (heap);
      return NULL;
    }

  result = sockettimer_extract_root (heap);

  sockettimer_heap_unlock (heap);
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

  sockettimer_heap_lock (heap);
  result = sockettimer_peek_unlocked (heap);
  sockettimer_heap_unlock (heap);

  return result;
}

/**
 * SocketTimer_heap_peek_delay - Get milliseconds until next timer expiry
 * @heap: Timer heap
 *
 * Returns: Milliseconds until next timer (>= 0), or -1 if no timers
 * Thread-safe: Yes - uses heap mutex
 *
 * Cleans cancelled timers from heap on peek.
 */
int64_t
SocketTimer_heap_peek_delay (SocketTimer_heap_T *heap)
{
  struct SocketTimer_T *timer;
  int64_t now_ms;
  int64_t delay_ms;

  assert (heap);

  sockettimer_heap_lock (heap);
  timer = sockettimer_peek_unlocked (heap);
  sockettimer_heap_unlock (heap);

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

  sockettimer_heap_lock (heap);

  idx = sockettimer_find_in_heap (heap, timer);
  if (idx >= 0)
    heap->timers[idx]->cancelled = 1;

  sockettimer_heap_unlock (heap);
  return (idx >= 0) ? 0 : -1;
}

/**
 * SocketTimer_heap_remaining - Get milliseconds until timer expiry
 * @heap: Timer heap
 * @timer: Timer to query
 *
 * Returns: Milliseconds until expiry (>= 0), or -1 if timer not
 * found/cancelled Thread-safe: Yes - uses heap mutex
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

  sockettimer_heap_lock (heap);

  idx = sockettimer_find_in_heap (heap, timer);

  if (idx < 0)
    {
      sockettimer_heap_unlock (heap);
      return -1;
    }

  now_ms = Socket_get_monotonic_ms ();
  remaining = timer->expiry_ms - now_ms;

  sockettimer_heap_unlock (heap);

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
  int64_t now_ms = Socket_get_monotonic_ms ();

  assert (heap);

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
 * Public Timer API - One-Shot and Repeating
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
  return sockettimer_add_timer_internal (poll, delay_ms, 0, callback, userdata,
                                         0);
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
  return sockettimer_add_timer_internal (poll, interval_ms, interval_ms,
                                         callback, userdata, 1);
}

/* ===========================================================================
 * Public Timer API - Cancel and Query
 * ===========================================================================*/

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

  heap = sockettimer_get_heap_from_poll (poll);
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

  heap = sockettimer_get_heap_from_poll (poll);
  if (!heap)
    return -1;

  return SocketTimer_heap_remaining (heap, timer);
}

/**
 * sockettimer_is_timer_active - Check if timer is valid and active
 * @timer: Timer to check
 *
 * Returns: 1 if timer is active, 0 otherwise
 * Thread-safe: No (caller must hold heap->mutex)
 */
static int
sockettimer_is_timer_active (const struct SocketTimer_T *timer)
{
  return !timer->cancelled
         && timer->heap_index != SOCKET_TIMER_INVALID_HEAP_INDEX;
}

/**
 * sockettimer_calculate_safe_expiry - Calculate expiry with overflow protection
 * @now_ms: Current monotonic time
 * @delay_ms: Delay to add
 *
 * Returns: Safe expiry time, clamped to prevent overflow
 * Thread-safe: Yes (no state)
 */
static int64_t
sockettimer_calculate_safe_expiry (int64_t now_ms, int64_t delay_ms)
{
  int64_t clamped_delay = delay_ms;

  /* Clamp delay to maximum allowed */
  if (delay_ms > SOCKET_MAX_TIMER_DELAY_MS)
    clamped_delay = SOCKET_MAX_TIMER_DELAY_MS;

  /* Check for overflow */
  if (clamped_delay > 0 && now_ms > INT64_MAX - clamped_delay)
    return INT64_MAX;

  return now_ms + clamped_delay;
}

/**
 * sockettimer_reheapify - Restore heap property after expiry change
 * @heap: Timer heap
 * @timer: Timer that was modified
 *
 * Thread-safe: No (caller must hold heap->mutex)
 */
static void
sockettimer_reheapify (SocketTimer_heap_T *heap, struct SocketTimer_T *timer)
{
  size_t idx = timer->heap_index;
  size_t parent_idx = sockettimer_heap_parent (idx);

  if (idx > 0 && timer->expiry_ms < heap->timers[parent_idx]->expiry_ms)
    sockettimer_heap_sift_up (heap->timers, idx);
  else
    sockettimer_heap_sift_down (heap->timers, heap->count, idx);
}

/**
 * SocketTimer_reschedule - Reschedule a timer with a new delay
 * @poll: Event poll instance timer is associated with
 * @timer: Timer handle to reschedule
 * @new_delay_ms: New delay from now in milliseconds
 *
 * Returns: 0 on success, -1 if timer invalid or cancelled
 * Thread-safe: Yes
 */
int
SocketTimer_reschedule (SocketPoll_T poll, SocketTimer_T timer,
                        int64_t new_delay_ms)
{
  SocketTimer_heap_T *heap;
  int64_t now_ms;

  assert (poll);
  assert (timer);

  heap = sockettimer_get_heap_from_poll (poll);
  if (!heap)
    return -1;

  sockettimer_heap_lock (heap);

  /* Check if timer is valid and not cancelled */
  if (!sockettimer_is_timer_active (timer))
    {
      sockettimer_heap_unlock (heap);
      return -1;
    }

  /* Calculate new expiry time with overflow protection */
  now_ms = Socket_get_monotonic_ms ();
  timer->expiry_ms = sockettimer_calculate_safe_expiry (now_ms, new_delay_ms);

  /* Also update interval for repeating timers */
  if (timer->interval_ms > 0)
    timer->interval_ms = new_delay_ms;

  /* Restore heap property */
  sockettimer_reheapify (heap, timer);

  sockettimer_heap_unlock (heap);

  return 0;
}

/**
 * SocketTimer_pause - Pause a timer, preserving remaining time
 * @poll: Event poll instance timer is associated with
 * @timer: Timer handle to pause
 *
 * Returns: 0 on success, -1 if timer invalid, cancelled, or already paused
 * Thread-safe: Yes
 */
int
SocketTimer_pause (SocketPoll_T poll, SocketTimer_T timer)
{
  SocketTimer_heap_T *heap;
  int64_t now_ms;
  int64_t remaining;

  assert (poll);
  assert (timer);

  heap = sockettimer_get_heap_from_poll (poll);
  if (!heap)
    return -1;

  sockettimer_heap_lock (heap);

  /* Check if timer is valid, not cancelled, and not already paused */
  if (!sockettimer_is_timer_active (timer) || timer->paused)
    {
      sockettimer_heap_unlock (heap);
      return -1;
    }

  /* Calculate and store remaining time */
  now_ms = Socket_get_monotonic_ms ();
  remaining = timer->expiry_ms - now_ms;
  if (remaining < 0)
    remaining = 0;

  timer->paused_remaining_ms = remaining;
  timer->paused = 1;

  /* Set expiry to far future so it won't fire while paused */
  timer->expiry_ms = INT64_MAX;

  /* Reheapify (move to end since expiry is now maximum) */
  sockettimer_heap_sift_down (heap->timers, heap->count, timer->heap_index);

  sockettimer_heap_unlock (heap);

  return 0;
}

/**
 * SocketTimer_resume - Resume a paused timer
 * @poll: Event poll instance timer is associated with
 * @timer: Timer handle to resume
 *
 * Returns: 0 on success, -1 if timer invalid, cancelled, or not paused
 * Thread-safe: Yes
 */
int
SocketTimer_resume (SocketPoll_T poll, SocketTimer_T timer)
{
  SocketTimer_heap_T *heap;
  int64_t now_ms;

  assert (poll);
  assert (timer);

  heap = sockettimer_get_heap_from_poll (poll);
  if (!heap)
    return -1;

  sockettimer_heap_lock (heap);

  /* Check if timer is valid, not cancelled, and paused */
  if (!sockettimer_is_timer_active (timer) || !timer->paused)
    {
      sockettimer_heap_unlock (heap);
      return -1;
    }

  /* Restore expiry from paused remaining time */
  now_ms = Socket_get_monotonic_ms ();
  timer->expiry_ms
      = sockettimer_calculate_safe_expiry (now_ms, timer->paused_remaining_ms);
  timer->paused = 0;
  timer->paused_remaining_ms = 0;

  /* Reheapify (move toward front since expiry is now smaller) */
  sockettimer_heap_sift_up (heap->timers, timer->heap_index);

  sockettimer_heap_unlock (heap);

  return 0;
}

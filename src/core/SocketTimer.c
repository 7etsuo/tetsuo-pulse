/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
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




const Except_T SocketTimer_Failed
    = { &SocketTimer_Failed, "Timer operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketTimer);

struct SocketTimer_heap_T *socketpoll_get_timer_heap (SocketPoll_T poll);



static SocketTimer_heap_T *
sockettimer_validate_heap (SocketPoll_T poll)
{
  SocketTimer_heap_T *heap = socketpoll_get_timer_heap (poll);

  if (!heap)
    SOCKET_RAISE_MSG (SocketTimer, SocketTimer_Failed,
                      "Timer heap not available");

  return heap;
}

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

static struct SocketTimer_T *
sockettimer_allocate_timer (Arena_T arena)
{
  return sockettimer_calloc_with_raise (
      arena, 1, sizeof (struct SocketTimer_T), "timer structure");
}

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

static struct SocketTimer_T *
sockettimer_create_timer (Arena_T arena, int64_t delay_ms, int64_t interval_ms,
                          SocketTimerCallback callback, void *userdata)
{
  struct SocketTimer_T *timer = sockettimer_allocate_timer (arena);
  sockettimer_init_timer (timer, delay_ms, interval_ms, callback, userdata);
  return timer;
}



static size_t
sockettimer_heap_parent (size_t index)
{
  return (index - 1) / 2;
}

static size_t
sockettimer_heap_left_child (size_t index)
{
  return 2 * index + 1;
}

static size_t
sockettimer_heap_right_child (size_t index)
{
  return 2 * index + 2;
}

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

static void
sockettimer_remove_cancelled_root (SocketTimer_heap_T *heap)
{
  sockettimer_heap_move_last_to_root (heap->timers, &heap->count);
}

static void
sockettimer_skip_cancelled (SocketTimer_heap_T *heap)
{
  while (heap->count > 0 && heap->timers[0]->cancelled)
    sockettimer_remove_cancelled_root (heap);
}


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

static void
sockettimer_assign_id (SocketTimer_heap_T *heap, struct SocketTimer_T *timer)
{
  timer->id = heap->next_id++;

  if (heap->next_id == 0)
    heap->next_id = SOCKET_TIMER_INITIAL_ID;
}

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

static struct SocketTimer_T *
sockettimer_extract_root (SocketTimer_heap_T *heap)
{
  struct SocketTimer_T *result = heap->timers[0];

  sockettimer_heap_move_last_to_root (heap->timers, &heap->count);

  return result;
}

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

static void
sockettimer_invoke_callback (struct SocketTimer_T *timer)
{
  if (timer->callback)
    timer->callback (timer->userdata);
}

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



static SocketTimer_heap_T *
sockettimer_heap_alloc_structure (Arena_T arena)
{
  return CALLOC (arena, 1, sizeof (SocketTimer_heap_T));
}

static struct SocketTimer_T **
sockettimer_heap_alloc_timers (Arena_T arena)
{
  return CALLOC (arena, SOCKET_TIMER_HEAP_INITIAL_CAPACITY,
                 sizeof (struct SocketTimer_T *));
}

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



static struct SocketTimer_T *
sockettimer_peek_unlocked (SocketTimer_heap_T *heap)
{
  sockettimer_skip_cancelled (heap);
  return (heap->count > 0) ? heap->timers[0] : NULL;
}



/* Returns NULL instead of raising on failure */
static SocketTimer_heap_T *
sockettimer_get_heap_from_poll (SocketPoll_T poll)
{
  return socketpoll_get_timer_heap (poll);
}

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



/* Partial allocations remain in arena until Arena_dispose() */
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

void
SocketTimer_heap_free (SocketTimer_heap_T **heap)
{
  if (!heap || !*heap)
    return;

  pthread_mutex_destroy (&(*heap)->mutex);
  *heap = NULL;
}

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

/* Callbacks invoked outside mutex; repeating timers rescheduled after firing */
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



SocketTimer_T
SocketTimer_add (SocketPoll_T poll, int64_t delay_ms,
                 SocketTimerCallback callback, void *userdata)
{
  return sockettimer_add_timer_internal (poll, delay_ms, 0, callback, userdata,
                                         0);
}

SocketTimer_T
SocketTimer_add_repeating (SocketPoll_T poll, int64_t interval_ms,
                           SocketTimerCallback callback, void *userdata)
{
  return sockettimer_add_timer_internal (poll, interval_ms, interval_ms,
                                         callback, userdata, 1);
}



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

static int
sockettimer_is_timer_active (const struct SocketTimer_T *timer)
{
  return !timer->cancelled
         && timer->heap_index != SOCKET_TIMER_INVALID_HEAP_INDEX;
}

static int64_t
sockettimer_calculate_safe_expiry (int64_t now_ms, int64_t delay_ms)
{
  int64_t clamped_delay = delay_ms;


  if (delay_ms > SOCKET_MAX_TIMER_DELAY_MS)
    clamped_delay = SOCKET_MAX_TIMER_DELAY_MS;


  if (clamped_delay > 0 && now_ms > INT64_MAX - clamped_delay)
    return INT64_MAX;

  return now_ms + clamped_delay;
}

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

  if (!sockettimer_is_timer_active (timer))
    {
      sockettimer_heap_unlock (heap);
      return -1;
    }

  now_ms = Socket_get_monotonic_ms ();
  timer->expiry_ms = sockettimer_calculate_safe_expiry (now_ms, new_delay_ms);

  if (timer->interval_ms > 0)
    timer->interval_ms = new_delay_ms;

  sockettimer_reheapify (heap, timer);

  sockettimer_heap_unlock (heap);

  return 0;
}

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

  if (!sockettimer_is_timer_active (timer) || timer->paused)
    {
      sockettimer_heap_unlock (heap);
      return -1;
    }

  now_ms = Socket_get_monotonic_ms ();
  remaining = timer->expiry_ms - now_ms;
  if (remaining < 0)
    remaining = 0;

  timer->paused_remaining_ms = remaining;
  timer->paused = 1;
  timer->expiry_ms = INT64_MAX;

  sockettimer_heap_sift_down (heap->timers, heap->count, timer->heap_index);

  sockettimer_heap_unlock (heap);

  return 0;
}

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

  if (!sockettimer_is_timer_active (timer) || !timer->paused)
    {
      sockettimer_heap_unlock (heap);
      return -1;
    }

  now_ms = Socket_get_monotonic_ms ();
  timer->expiry_ms
      = sockettimer_calculate_safe_expiry (now_ms, timer->paused_remaining_ms);
  timer->paused = 0;
  timer->paused_remaining_ms = 0;

  sockettimer_heap_sift_up (heap->timers, timer->heap_index);

  sockettimer_heap_unlock (heap);

  return 0;
}

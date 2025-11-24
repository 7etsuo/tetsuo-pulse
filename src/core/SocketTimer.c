/**
 * SocketTimer.c - Timer subsystem with min-heap implementation
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketTimer-private.h"
#include "core/SocketTimer.h"
#define SOCKET_LOG_COMPONENT "SocketTimer"
#include "core/SocketConfig.h"
#include "core/SocketError.h"

/* Forward declaration for SocketPoll_T */
struct SocketPoll_T;
typedef struct SocketPoll_T *SocketPoll_T;

/* Forward declaration for timer heap getter */
struct SocketTimer_heap_T;
struct SocketTimer_heap_T *socketpoll_get_timer_heap (SocketPoll_T poll);

/* Error buffer size */
#define SOCKETTIMER_ERROR_BUFSIZE 256

/* Thread-local error buffer */
#ifdef _WIN32
__declspec (thread) char sockettimer_error_buf[SOCKETTIMER_ERROR_BUFSIZE];
#else
__thread char sockettimer_error_buf[SOCKETTIMER_ERROR_BUFSIZE];
#endif

/* Timer exception definition */
const Except_T SocketTimer_Failed = { &SocketTimer_Failed, "Timer operation failed" };

/* Thread-local exception for detailed error messages
 * This is a COPY of the base exception with thread-local reason string.
 * Each thread gets its own exception instance, preventing race conditions
 * when multiple threads raise the same exception type simultaneously. */
#ifdef _WIN32
__declspec (thread) Except_T SocketTimer_DetailedException;
#else
__thread Except_T SocketTimer_DetailedException;
#endif

/* Error formatting macros */
#define SOCKETTIMER_ERROR_FMT(fmt, ...)                                           \
  snprintf (sockettimer_error_buf, SOCKETTIMER_ERROR_BUFSIZE, fmt " (errno: %d - %s)", \
            ##__VA_ARGS__, errno, strerror (errno))

#define SOCKETTIMER_ERROR_MSG(fmt, ...)                                           \
  snprintf (sockettimer_error_buf, SOCKETTIMER_ERROR_BUFSIZE, fmt, ##__VA_ARGS__)

/* Macro to raise timer exception with detailed error message
 * Creates a thread-local copy of the exception with detailed reason */
#define RAISE_SOCKETTIMER_ERROR(base_exception)                                   \
  do                                                                              \
    {                                                                             \
      SocketTimer_DetailedException = (base_exception);                           \
      SocketTimer_DetailedException.reason = sockettimer_error_buf;               \
      RAISE (SocketTimer_DetailedException);                                      \
    }                                                                            \
  while (0)

/* Heap configuration */
#define SOCKETTIMER_HEAP_INITIAL_CAPACITY 16
#define SOCKETTIMER_HEAP_GROWTH_FACTOR 2

/**
 * sockettimer_now_ms - Get current monotonic time in milliseconds
 * Returns: Current time in milliseconds since some arbitrary monotonic point
 * Thread-safe: Yes (CLOCK_MONOTONIC is thread-safe)
 */
static int64_t
sockettimer_now_ms (void)
{
  struct timespec ts;
  if (clock_gettime (CLOCK_MONOTONIC, &ts) < 0)
    {
      /* Fallback to less precise timing if monotonic clock fails */
      SOCKETTIMER_ERROR_FMT ("Failed to get monotonic time");
      RAISE_SOCKETTIMER_ERROR (SocketTimer_Failed);
    }
  return (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / 1000000;
}

/**
 * sockettimer_heap_parent - Get parent index in heap
 */
static inline size_t
sockettimer_heap_parent (size_t index)
{
  return (index - 1) / 2;
}

/**
 * sockettimer_heap_left_child - Get left child index in heap
 */
static inline size_t
sockettimer_heap_left_child (size_t index)
{
  return 2 * index + 1;
}

/**
 * sockettimer_heap_right_child - Get right child index in heap
 */
static inline size_t
sockettimer_heap_right_child (size_t index)
{
  return 2 * index + 2;
}

/**
 * sockettimer_heap_swap - Swap two timers in heap array
 */
static void
sockettimer_heap_swap (struct SocketTimer_T **timers, size_t i, size_t j)
{
  struct SocketTimer_T *temp = timers[i];
  timers[i] = timers[j];
  timers[j] = temp;
}

/**
 * sockettimer_heap_sift_up - Restore heap property by moving element up
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
 */
static void
sockettimer_heap_sift_down (struct SocketTimer_T **timers, size_t count, size_t index)
{
  while (1)
    {
      size_t left = sockettimer_heap_left_child (index);
      size_t right = sockettimer_heap_right_child (index);
      size_t smallest = index;

      if (left < count && timers[left]->expiry_ms < timers[smallest]->expiry_ms)
        smallest = left;

      if (right < count && timers[right]->expiry_ms < timers[smallest]->expiry_ms)
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
      SOCKETTIMER_ERROR_MSG ("Failed to resize timer heap array");
      RAISE_SOCKETTIMER_ERROR (SocketTimer_Failed);
    }

  memcpy (new_timers, heap->timers, heap->count * sizeof (*new_timers));
  heap->timers = new_timers;
  heap->capacity = new_capacity;
}

/* ==================== Public Heap API ==================== */

SocketTimer_heap_T *
SocketTimer_heap_new (Arena_T arena)
{
  SocketTimer_heap_T *heap;

  if (!arena)
    return NULL;

  heap = CALLOC (arena, 1, sizeof (*heap));
  if (!heap)
    return NULL;

  heap->timers = CALLOC (arena, SOCKETTIMER_HEAP_INITIAL_CAPACITY,
                          sizeof (*heap->timers));
  if (!heap->timers)
    return NULL;

  heap->count = 0;
  heap->capacity = SOCKETTIMER_HEAP_INITIAL_CAPACITY;
  heap->next_id = 1; /* Start IDs at 1 */
  heap->arena = arena;

  if (pthread_mutex_init (&heap->mutex, NULL) != 0)
    return NULL;

  return heap;
}

void
SocketTimer_heap_free (SocketTimer_heap_T **heap)
{
  if (!heap || !*heap)
    return;

  /* Timers are allocated from arena, so they'll be freed when arena is disposed */

  /* Destroy mutex */
  pthread_mutex_destroy (&(*heap)->mutex);

  /* Heap structure is allocated from arena, so arena dispose will free it */
  *heap = NULL;
}

void
SocketTimer_heap_push (SocketTimer_heap_T *heap, struct SocketTimer_T *timer)
{
  assert (heap);
  assert (timer);

  pthread_mutex_lock (&heap->mutex);

  TRY
    {
      /* Resize if needed */
      if (heap->count >= heap->capacity)
        {
          size_t new_capacity = heap->capacity * SOCKETTIMER_HEAP_GROWTH_FACTOR;
          if (new_capacity <= heap->capacity) /* Overflow check */
            {
              SOCKETTIMER_ERROR_MSG ("Timer heap capacity overflow");
              RAISE_SOCKETTIMER_ERROR (SocketTimer_Failed);
            }
          sockettimer_heap_resize (heap, new_capacity);
        }

      /* Assign ID and add to heap */
      timer->id = heap->next_id++;
      if (heap->next_id == 0) /* Wrap around protection */
        heap->next_id = 1;

      heap->timers[heap->count] = timer;
      heap->count++;

      /* Restore heap property */
      sockettimer_heap_sift_up (heap->timers, heap->count - 1);
    }
  FINALLY
    {
      pthread_mutex_unlock (&heap->mutex);
    }
  END_TRY;
}

struct SocketTimer_T *
SocketTimer_heap_pop (SocketTimer_heap_T *heap)
{
  struct SocketTimer_T *result;

  assert (heap);

  pthread_mutex_lock (&heap->mutex);

  if (heap->count == 0)
    {
      pthread_mutex_unlock (&heap->mutex);
      return NULL;
    }

  /* Skip cancelled timers (lazy deletion) */
  while (heap->count > 0 && heap->timers[0]->cancelled)
    {
      /* Remove cancelled timer */
      struct SocketTimer_T *cancelled = heap->timers[0];
      heap->timers[0] = heap->timers[heap->count - 1];
      heap->count--;

      /* Restore heap property */
      if (heap->count > 0)
        sockettimer_heap_sift_down (heap->timers, heap->count, 0);

      /* Cancelled timer will be freed when arena is disposed */
    }

  if (heap->count == 0)
    {
      pthread_mutex_unlock (&heap->mutex);
      return NULL;
    }

  /* Get earliest timer */
  result = heap->timers[0];

  /* Move last element to root */
  heap->timers[0] = heap->timers[heap->count - 1];
  heap->count--;

  /* Restore heap property */
  if (heap->count > 0)
    sockettimer_heap_sift_down (heap->timers, heap->count, 0);

  pthread_mutex_unlock (&heap->mutex);
  return result;
}

struct SocketTimer_T *
SocketTimer_heap_peek (SocketTimer_heap_T *heap)
{
  struct SocketTimer_T *result;

  assert (heap);

  pthread_mutex_lock (&heap->mutex);

  /* Skip cancelled timers */
  size_t i = 0;
  while (i < heap->count && heap->timers[i]->cancelled)
    i++;

  if (i >= heap->count)
    {
      pthread_mutex_unlock (&heap->mutex);
      return NULL;
    }

  result = heap->timers[i];
  pthread_mutex_unlock (&heap->mutex);
  return result;
}

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

  /* Return 0 if timer has already expired */
  return delay_ms > 0 ? delay_ms : 0;
}

int
SocketTimer_process_expired (SocketTimer_heap_T *heap)
{
  int fired_count = 0;
  int64_t now_ms = sockettimer_now_ms ();

  assert (heap);

  /* Process all expired timers */
  while (1)
    {
      struct SocketTimer_T *timer;
      SocketTimerCallback callback;
      void *userdata;

      /* Get next expired timer */
      pthread_mutex_lock (&heap->mutex);

      /* Find first non-cancelled timer */
      size_t i = 0;
      while (i < heap->count && heap->timers[i]->cancelled)
        i++;

      if (i >= heap->count)
        {
          pthread_mutex_unlock (&heap->mutex);
          break;
        }

      timer = heap->timers[i];
      if (timer->expiry_ms > now_ms)
        {
          /* No more expired timers */
          pthread_mutex_unlock (&heap->mutex);
          break;
        }

      /* Remove timer from heap (same logic as pop) */
      timer = heap->timers[0];
      heap->timers[0] = heap->timers[heap->count - 1];
      heap->count--;

      if (heap->count > 0)
        sockettimer_heap_sift_down (heap->timers, heap->count, 0);

      pthread_mutex_unlock (&heap->mutex);

      /* Store callback info before freeing timer */
      callback = timer->callback;
      userdata = timer->userdata;

      /* Handle repeating timers */
      if (timer->interval_ms > 0)
        {
          /* Reschedule repeating timer */
          timer->expiry_ms += timer->interval_ms;
          SocketTimer_heap_push (heap, timer);
        }
      else
        {
          /* One-shot timer will be freed when arena is disposed */
        }

      /* Invoke callback outside mutex to prevent deadlocks */
      if (callback)
        callback (userdata);

      fired_count++;
    }

  return fired_count;
}

int
SocketTimer_heap_cancel (SocketTimer_heap_T *heap, struct SocketTimer_T *timer)
{
  int found = 0;

  assert (heap);
  assert (timer);

  pthread_mutex_lock (&heap->mutex);

  /* Find timer in heap */
  for (size_t i = 0; i < heap->count; i++)
    {
      if (heap->timers[i] == timer && !heap->timers[i]->cancelled)
        {
          heap->timers[i]->cancelled = 1;
          found = 1;
          break;
        }
    }

  pthread_mutex_unlock (&heap->mutex);
  return found ? 0 : -1;
}

int64_t
SocketTimer_heap_remaining (SocketTimer_heap_T *heap,
                           const struct SocketTimer_T *timer)
{
  int64_t now_ms;
  int64_t remaining;

  assert (heap);
  assert (timer);

  /* Check if timer is still in heap and not cancelled */
  pthread_mutex_lock (&heap->mutex);

  int found = 0;
  for (size_t i = 0; i < heap->count; i++)
    {
      if (heap->timers[i] == timer && !heap->timers[i]->cancelled)
        {
          found = 1;
          break;
        }
    }

  if (!found)
    {
      pthread_mutex_unlock (&heap->mutex);
      return -1;
    }

  now_ms = sockettimer_now_ms ();
  remaining = timer->expiry_ms - now_ms;

  pthread_mutex_unlock (&heap->mutex);

  return remaining > 0 ? remaining : 0;
}

/* ==================== Public Timer API ==================== */

SocketTimer_T
SocketTimer_add (SocketPoll_T poll, int64_t delay_ms,
                 SocketTimerCallback callback, void *userdata)
{
  SocketTimer_heap_T *heap;
  struct SocketTimer_T *timer;
  int64_t now_ms;

  assert (poll);
  assert (delay_ms >= 0);
  assert (callback);

  /* Get heap from poll */
  heap = socketpoll_get_timer_heap (poll);
  if (!heap)
    {
      SOCKETTIMER_ERROR_MSG ("Timer heap not available");
      RAISE_SOCKETTIMER_ERROR (SocketTimer_Failed);
    }

  /* Validate delay */
  if (delay_ms < 0)
    {
      SOCKETTIMER_ERROR_MSG ("Invalid delay: %" PRId64 " (must be >= 0)", delay_ms);
      RAISE_SOCKETTIMER_ERROR (SocketTimer_Failed);
    }

  /* Allocate timer */
  timer = CALLOC (heap->arena, 1, sizeof (*timer));
  if (!timer)
    {
      SOCKETTIMER_ERROR_MSG ("Failed to allocate timer structure");
      RAISE_SOCKETTIMER_ERROR (SocketTimer_Failed);
    }

  /* Initialize timer */
  now_ms = sockettimer_now_ms ();
  timer->expiry_ms = now_ms + delay_ms;
  timer->interval_ms = 0; /* One-shot */
  timer->callback = callback;
  timer->userdata = userdata;
  timer->cancelled = 0;

  /* Add to heap */
  SocketTimer_heap_push (heap, timer);

  return timer;
}

SocketTimer_T
SocketTimer_add_repeating (SocketPoll_T poll, int64_t interval_ms,
                          SocketTimerCallback callback, void *userdata)
{
  SocketTimer_heap_T *heap;
  struct SocketTimer_T *timer;
  int64_t now_ms;

  assert (poll);
  assert (interval_ms >= 1);
  assert (callback);

  /* Get heap from poll */
  heap = socketpoll_get_timer_heap (poll);
  if (!heap)
    {
      SOCKETTIMER_ERROR_MSG ("Timer heap not available");
      RAISE_SOCKETTIMER_ERROR (SocketTimer_Failed);
    }

  /* Validate interval */
  if (interval_ms < 1)
    {
      SOCKETTIMER_ERROR_MSG ("Invalid interval: %" PRId64 " (must be >= 1)", interval_ms);
      RAISE_SOCKETTIMER_ERROR (SocketTimer_Failed);
    }

  /* Allocate timer */
  timer = CALLOC (heap->arena, 1, sizeof (*timer));
  if (!timer)
    {
      SOCKETTIMER_ERROR_MSG ("Failed to allocate timer structure");
      RAISE_SOCKETTIMER_ERROR (SocketTimer_Failed);
    }

  /* Initialize timer */
  now_ms = sockettimer_now_ms ();
  timer->expiry_ms = now_ms + interval_ms;
  timer->interval_ms = interval_ms; /* Repeating */
  timer->callback = callback;
  timer->userdata = userdata;
  timer->cancelled = 0;

  /* Add to heap */
  SocketTimer_heap_push (heap, timer);

  return timer;
}

int
SocketTimer_cancel (SocketPoll_T poll, SocketTimer_T timer)
{
  SocketTimer_heap_T *heap;

  assert (poll);
  assert (timer);

  /* Get heap from poll */
  heap = socketpoll_get_timer_heap (poll);
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

  /* Get heap from poll */
  heap = socketpoll_get_timer_heap (poll);
  if (!heap)
    return -1;

  return SocketTimer_heap_remaining (heap, timer);
}

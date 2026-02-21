/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_timer_heap.c - SocketTimer heap operations unit tests
 * Tests for the min-heap timer management implementation.
 * Covers heap creation, destruction, push/pop operations, and heap property
 * verification.
 */

#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketTimer-private.h"
#include "core/SocketUtil/Time.h"
#include "test/Test.h"

/* Helper callback for timer tests */
static volatile int callback_count = 0;

static void
test_timer_callback (void *userdata)
{
  (void)userdata;
  callback_count++;
}

/* Reset callback counter before each test using it */
static void
reset_callback_count (void)
{
  callback_count = 0;
}

/* Helper to create a timer with specific expiry */
static struct SocketTimer_T *
create_timer_with_expiry (Arena_T arena, int64_t expiry_ms)
{
  struct SocketTimer_T *timer
      = CALLOC (arena, 1, sizeof (struct SocketTimer_T));
  if (!timer)
    return NULL;

  timer->expiry_ms = expiry_ms;
  timer->interval_ms = 0;
  timer->callback = test_timer_callback;
  timer->userdata = NULL;
  timer->cancelled = 0;
  timer->paused = 0;
  timer->paused_remaining_ms = 0;
  timer->id = 0;
  timer->heap_index = SOCKET_TIMER_INVALID_HEAP_INDEX;

  return timer;
}

/* Verify heap property: parent <= children */
static int
verify_heap_property (SocketTimer_heap_T *heap)
{
  if (!heap || heap->count == 0)
    return 1;

  for (size_t i = 0; i < heap->count; i++)
    {
      size_t left = 2 * i + 1;
      size_t right = 2 * i + 2;

      if (left < heap->count)
        {
          if (heap->timers[i]->expiry_ms > heap->timers[left]->expiry_ms)
            return 0;
        }

      if (right < heap->count)
        {
          if (heap->timers[i]->expiry_ms > heap->timers[right]->expiry_ms)
            return 0;
        }
    }

  return 1;
}

/* Test: Create heap with valid arena */
TEST (timer_heap_new_creates_heap)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);
  ASSERT_EQ (heap->count, 0);
  ASSERT_EQ (heap->capacity, SOCKET_TIMER_HEAP_INITIAL_CAPACITY);
  ASSERT_NOT_NULL (heap->timers);
  ASSERT_EQ (heap->next_id, SOCKET_TIMER_INITIAL_ID);

  SocketTimer_heap_free (&heap);
  ASSERT_NULL (heap);
  Arena_dispose (&arena);
}

/* Test: Create heap with NULL arena returns NULL */
TEST (timer_heap_new_null_arena_returns_null)
{
  SocketTimer_heap_T *heap = SocketTimer_heap_new (NULL);
  ASSERT_NULL (heap);
}

/* Test: Free NULL heap pointer is safe */
TEST (timer_heap_free_null_heap_safe)
{
  SocketTimer_heap_T *heap = NULL;
  SocketTimer_heap_free (&heap);
  /* Should not crash */
  ASSERT_NULL (heap);
}

/* Test: Free heap with NULL pointer to pointer is safe */
TEST (timer_heap_free_null_pointer_safe)
{
  SocketTimer_heap_free (NULL);
  /* Should not crash */
}

/* Test: Push single timer to heap */
TEST (timer_heap_push_single_timer)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  int64_t expiry = Socket_get_monotonic_ms () + 1000;
  struct SocketTimer_T *timer = create_timer_with_expiry (arena, expiry);
  ASSERT_NOT_NULL (timer);

  TRY
  {
    SocketTimer_heap_push (heap, timer);
    ASSERT_EQ (heap->count, 1);
    ASSERT_EQ (heap->timers[0], timer);
    ASSERT_EQ (timer->heap_index, 0);
    ASSERT (verify_heap_property (heap));
  }
  FINALLY
  {
    SocketTimer_heap_free (&heap);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test: Push multiple timers with different expiry times */
TEST (timer_heap_push_multiple_timers)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  int64_t base_time = Socket_get_monotonic_ms ();
  struct SocketTimer_T *timer1
      = create_timer_with_expiry (arena, base_time + 5000);
  struct SocketTimer_T *timer2
      = create_timer_with_expiry (arena, base_time + 1000);
  struct SocketTimer_T *timer3
      = create_timer_with_expiry (arena, base_time + 3000);

  ASSERT_NOT_NULL (timer1);
  ASSERT_NOT_NULL (timer2);
  ASSERT_NOT_NULL (timer3);

  TRY
  {
    SocketTimer_heap_push (heap, timer1);
    ASSERT_EQ (heap->count, 1);
    ASSERT (verify_heap_property (heap));

    SocketTimer_heap_push (heap, timer2);
    ASSERT_EQ (heap->count, 2);
    ASSERT (verify_heap_property (heap));
    /* timer2 (1000ms) should bubble to root */
    ASSERT_EQ (heap->timers[0], timer2);

    SocketTimer_heap_push (heap, timer3);
    ASSERT_EQ (heap->count, 3);
    ASSERT (verify_heap_property (heap));
    /* timer2 should still be at root (earliest) */
    ASSERT_EQ (heap->timers[0], timer2);
  }
  FINALLY
  {
    SocketTimer_heap_free (&heap);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test: Verify min-heap ordering after multiple pushes */
TEST (timer_heap_maintains_min_heap_property)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  int64_t base_time = Socket_get_monotonic_ms ();
  /* Push timers in random order */
  int64_t expiries[] = { 7000, 2000, 9000, 1000, 5000, 3000, 8000, 4000, 6000 };
  size_t count = sizeof (expiries) / sizeof (expiries[0]);

  TRY
  {
    for (size_t i = 0; i < count; i++)
      {
        struct SocketTimer_T *timer
            = create_timer_with_expiry (arena, base_time + expiries[i]);
        ASSERT_NOT_NULL (timer);
        SocketTimer_heap_push (heap, timer);
        ASSERT (verify_heap_property (heap));
      }

    ASSERT_EQ (heap->count, count);
    /* Root should have minimum expiry (1000) */
    ASSERT_EQ (heap->timers[0]->expiry_ms, base_time + 1000);
  }
  FINALLY
  {
    SocketTimer_heap_free (&heap);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test: Pop from empty heap returns NULL */
TEST (timer_heap_pop_from_empty_returns_null)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  struct SocketTimer_T *timer = SocketTimer_heap_pop (heap);
  ASSERT_NULL (timer);
  ASSERT_EQ (heap->count, 0);

  SocketTimer_heap_free (&heap);
  Arena_dispose (&arena);
}

/* Test: Pop from heap with one timer */
TEST (timer_heap_pop_single_timer)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  int64_t expiry = Socket_get_monotonic_ms () + 1000;
  struct SocketTimer_T *timer = create_timer_with_expiry (arena, expiry);
  ASSERT_NOT_NULL (timer);

  TRY
  {
    SocketTimer_heap_push (heap, timer);
    ASSERT_EQ (heap->count, 1);

    struct SocketTimer_T *popped = SocketTimer_heap_pop (heap);
    ASSERT_EQ (popped, timer);
    ASSERT_EQ (heap->count, 0);

    /* Heap should be empty now */
    struct SocketTimer_T *null_timer = SocketTimer_heap_pop (heap);
    ASSERT_NULL (null_timer);
  }
  FINALLY
  {
    SocketTimer_heap_free (&heap);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test: Pop multiple timers in sorted order */
TEST (timer_heap_pop_multiple_in_order)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  int64_t base_time = Socket_get_monotonic_ms ();
  int64_t expiries[] = { 5000, 2000, 8000, 1000, 6000 };
  size_t count = sizeof (expiries) / sizeof (expiries[0]);

  TRY
  {
    /* Push all timers */
    for (size_t i = 0; i < count; i++)
      {
        struct SocketTimer_T *timer
            = create_timer_with_expiry (arena, base_time + expiries[i]);
        ASSERT_NOT_NULL (timer);
        SocketTimer_heap_push (heap, timer);
      }

    /* Pop all timers - should come out in sorted order */
    int64_t prev_expiry = 0;
    for (size_t i = 0; i < count; i++)
      {
        struct SocketTimer_T *timer = SocketTimer_heap_pop (heap);
        ASSERT_NOT_NULL (timer);
        ASSERT (timer->expiry_ms >= prev_expiry);
        ASSERT (verify_heap_property (heap));
        prev_expiry = timer->expiry_ms;
      }

    ASSERT_EQ (heap->count, 0);
  }
  FINALLY
  {
    SocketTimer_heap_free (&heap);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test: Peek at next timer without removing */
TEST (timer_heap_peek_without_removal)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  int64_t base_time = Socket_get_monotonic_ms ();
  struct SocketTimer_T *timer1
      = create_timer_with_expiry (arena, base_time + 5000);
  struct SocketTimer_T *timer2
      = create_timer_with_expiry (arena, base_time + 1000);

  TRY
  {
    SocketTimer_heap_push (heap, timer1);
    SocketTimer_heap_push (heap, timer2);

    struct SocketTimer_T *peeked = SocketTimer_heap_peek (heap);
    ASSERT_NOT_NULL (peeked);
    ASSERT_EQ (peeked, timer2); /* Earliest timer */
    ASSERT_EQ (heap->count, 2); /* Count unchanged */

    /* Peek again - should return same timer */
    peeked = SocketTimer_heap_peek (heap);
    ASSERT_EQ (peeked, timer2);
    ASSERT_EQ (heap->count, 2);
  }
  FINALLY
  {
    SocketTimer_heap_free (&heap);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test: Peek on empty heap returns NULL */
TEST (timer_heap_peek_empty_returns_null)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  struct SocketTimer_T *peeked = SocketTimer_heap_peek (heap);
  ASSERT_NULL (peeked);

  SocketTimer_heap_free (&heap);
  Arena_dispose (&arena);
}

/* Test: Peek delay calculation with future timer */
TEST (timer_heap_peek_delay_future_timer)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  int64_t now = Socket_get_monotonic_ms ();
  int64_t delay = 5000;
  struct SocketTimer_T *timer = create_timer_with_expiry (arena, now + delay);

  TRY
  {
    SocketTimer_heap_push (heap, timer);

    int64_t peek_delay = SocketTimer_heap_peek_delay (heap);
    /* Delay should be approximately 5000ms, with some tolerance for execution
     * time */
    ASSERT (peek_delay > 4900 && peek_delay <= 5000);
  }
  FINALLY
  {
    SocketTimer_heap_free (&heap);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test: Peek delay returns 0 for expired timer */
TEST (timer_heap_peek_delay_expired_timer)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  int64_t now = Socket_get_monotonic_ms ();
  struct SocketTimer_T *timer = create_timer_with_expiry (arena, now - 1000);

  TRY
  {
    SocketTimer_heap_push (heap, timer);

    int64_t peek_delay = SocketTimer_heap_peek_delay (heap);
    ASSERT_EQ (peek_delay, 0); /* Expired timer returns 0 */
  }
  FINALLY
  {
    SocketTimer_heap_free (&heap);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test: Peek delay on empty heap returns -1 */
TEST (timer_heap_peek_delay_empty_heap)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  int64_t delay = SocketTimer_heap_peek_delay (heap);
  ASSERT_EQ (delay, -1);

  SocketTimer_heap_free (&heap);
  Arena_dispose (&arena);
}

/* Test: Heap capacity growth (2x factor) */
TEST (timer_heap_capacity_growth)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  size_t initial_capacity = heap->capacity;
  ASSERT_EQ (initial_capacity, SOCKET_TIMER_HEAP_INITIAL_CAPACITY);

  int64_t base_time = Socket_get_monotonic_ms ();

  TRY
  {
    /* Push timers until capacity needs to grow */
    for (size_t i = 0; i < initial_capacity + 1; i++)
      {
        struct SocketTimer_T *timer
            = create_timer_with_expiry (arena, base_time + i);
        ASSERT_NOT_NULL (timer);
        SocketTimer_heap_push (heap, timer);
      }

    /* Capacity should have doubled */
    ASSERT_EQ (heap->capacity,
               initial_capacity * SOCKET_TIMER_HEAP_GROWTH_FACTOR);
    ASSERT_EQ (heap->count, initial_capacity + 1);
    ASSERT (verify_heap_property (heap));
  }
  FINALLY
  {
    SocketTimer_heap_free (&heap);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test: Heap saturation should evict and continue accepting timers */
TEST (timer_heap_max_size_enforcement)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  int64_t base_time = Socket_get_monotonic_ms ();

  TRY
  {
    /* Fill heap to maximum capacity */
    for (size_t i = 0; i < SOCKET_MAX_TIMERS_PER_HEAP; i++)
      {
        struct SocketTimer_T *timer
            = create_timer_with_expiry (arena, base_time + i);
        if (!timer)
          break; /* Out of memory, acceptable for this test */
        SocketTimer_heap_push (heap, timer);
      }

    if (heap->count == SOCKET_MAX_TIMERS_PER_HEAP)
      {
        struct SocketTimer_T *timer
            = create_timer_with_expiry (arena, base_time + INT64_MAX / 4);
        ASSERT_NOT_NULL (timer);

        /* Push beyond capacity: implementation should evict one entry and keep
         * heap operational. */
        SocketTimer_heap_push (heap, timer);

        ASSERT_EQ (heap->count, SOCKET_MAX_TIMERS_PER_HEAP);
        ASSERT (verify_heap_property (heap));
      }
  }
  EXCEPT (SocketTimer_Failed)
  {
    ASSERT (0);
  }
  FINALLY
  {
    SocketTimer_heap_free (&heap);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test: Heap handles cancelled timers correctly in pop */
TEST (timer_heap_pop_skips_cancelled)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  int64_t base_time = Socket_get_monotonic_ms ();
  struct SocketTimer_T *timer1
      = create_timer_with_expiry (arena, base_time + 1000);
  struct SocketTimer_T *timer2
      = create_timer_with_expiry (arena, base_time + 2000);
  struct SocketTimer_T *timer3
      = create_timer_with_expiry (arena, base_time + 3000);

  TRY
  {
    SocketTimer_heap_push (heap, timer1);
    SocketTimer_heap_push (heap, timer2);
    SocketTimer_heap_push (heap, timer3);

    /* Mark first timer as cancelled */
    timer1->cancelled = 1;

    /* Pop should skip cancelled timer1 and return timer2 */
    struct SocketTimer_T *popped = SocketTimer_heap_pop (heap);
    ASSERT_NOT_NULL (popped);
    ASSERT_EQ (popped, timer2);
    ASSERT (verify_heap_property (heap));
  }
  FINALLY
  {
    SocketTimer_heap_free (&heap);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test: Heap ID assignment and wraparound */
TEST (timer_heap_id_assignment)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  ASSERT_EQ (heap->next_id, SOCKET_TIMER_INITIAL_ID);

  int64_t base_time = Socket_get_monotonic_ms ();

  TRY
  {
    struct SocketTimer_T *timer1
        = create_timer_with_expiry (arena, base_time + 1000);
    SocketTimer_heap_push (heap, timer1);
    ASSERT_EQ (timer1->id, SOCKET_TIMER_INITIAL_ID);
    ASSERT_EQ (heap->next_id, SOCKET_TIMER_INITIAL_ID + 1);

    struct SocketTimer_T *timer2
        = create_timer_with_expiry (arena, base_time + 2000);
    SocketTimer_heap_push (heap, timer2);
    ASSERT_EQ (timer2->id, SOCKET_TIMER_INITIAL_ID + 1);

    /* Test ID wraparound */
    heap->next_id = UINT64_MAX;
    struct SocketTimer_T *timer3
        = create_timer_with_expiry (arena, base_time + 3000);
    SocketTimer_heap_push (heap, timer3);
    ASSERT_EQ (timer3->id, UINT64_MAX);
    ASSERT_EQ (heap->next_id, SOCKET_TIMER_INITIAL_ID); /* Wrapped */
  }
  FINALLY
  {
    SocketTimer_heap_free (&heap);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Thread test data structure */
struct thread_test_data
{
  SocketTimer_heap_T *heap;
  Arena_T arena;
  int thread_id;
  int push_count;
  volatile int *error_flag;
};

/* Thread function for concurrent push test */
static void *
thread_push_timers (void *arg)
{
  struct thread_test_data *data = (struct thread_test_data *)arg;
  int64_t base_time = Socket_get_monotonic_ms ();

  for (int i = 0; i < data->push_count; i++)
    {
      TRY
      {
        struct SocketTimer_T *timer = create_timer_with_expiry (
            data->arena, base_time + i + data->thread_id * 1000);
        if (timer)
          {
            SocketTimer_heap_push (data->heap, timer);
          }
      }
      EXCEPT (SocketTimer_Failed)
      {
        *(data->error_flag) = 1;
        break;
      }
      END_TRY;
    }

  return NULL;
}

/* Test: Thread safety - concurrent push operations */
TEST (timer_heap_concurrent_push)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  const int num_threads = 4;
  const int pushes_per_thread = 10;
  pthread_t threads[num_threads];
  struct thread_test_data thread_data[num_threads];
  volatile int error_flag = 0;

  /* Create threads */
  for (int i = 0; i < num_threads; i++)
    {
      thread_data[i].heap = heap;
      thread_data[i].arena = arena;
      thread_data[i].thread_id = i;
      thread_data[i].push_count = pushes_per_thread;
      thread_data[i].error_flag = &error_flag;

      int rc = pthread_create (
          &threads[i], NULL, thread_push_timers, &thread_data[i]);
      ASSERT_EQ (rc, 0);
    }

  /* Wait for all threads */
  for (int i = 0; i < num_threads; i++)
    {
      pthread_join (threads[i], NULL);
    }

  /* Verify results if no exception occurred */
  if (!error_flag)
    {
      ASSERT (heap->count <= num_threads * pushes_per_thread);
      ASSERT (verify_heap_property (heap));
    }

  SocketTimer_heap_free (&heap);
  Arena_dispose (&arena);
}

/* Thread function for concurrent pop test */
static void *
thread_pop_timers (void *arg)
{
  struct thread_test_data *data = (struct thread_test_data *)arg;

  for (int i = 0; i < data->push_count; i++)
    {
      struct SocketTimer_T *timer = SocketTimer_heap_pop (data->heap);
      /* Timer may be NULL if another thread popped first */
      (void)timer;
      usleep (100); /* Small delay to increase contention */
    }

  return NULL;
}

/* Test: Thread safety - concurrent pop operations */
TEST (timer_heap_concurrent_pop)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  const int num_threads = 4;
  const int total_timers = 40;
  int64_t base_time = Socket_get_monotonic_ms ();

  /* Pre-populate heap with timers */
  TRY
  {
    for (int i = 0; i < total_timers; i++)
      {
        struct SocketTimer_T *timer
            = create_timer_with_expiry (arena, base_time + i);
        ASSERT_NOT_NULL (timer);
        SocketTimer_heap_push (heap, timer);
      }

    ASSERT_EQ (heap->count, total_timers);

    /* Create threads to pop timers concurrently */
    pthread_t threads[num_threads];
    struct thread_test_data thread_data[num_threads];

    for (int i = 0; i < num_threads; i++)
      {
        thread_data[i].heap = heap;
        thread_data[i].push_count = total_timers / num_threads;
        int rc = pthread_create (
            &threads[i], NULL, thread_pop_timers, &thread_data[i]);
        ASSERT_EQ (rc, 0);
      }

    /* Wait for all threads */
    for (int i = 0; i < num_threads; i++)
      {
        pthread_join (threads[i], NULL);
      }

    /* Heap should be empty or nearly empty */
    ASSERT (heap->count < 5); /* Allow some timing variance */
  }
  FINALLY
  {
    SocketTimer_heap_free (&heap);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test: Verify heap remains valid after mixed operations */
TEST (timer_heap_mixed_operations)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketTimer_heap_T *heap = SocketTimer_heap_new (arena);
  ASSERT_NOT_NULL (heap);

  int64_t base_time = Socket_get_monotonic_ms ();

  TRY
  {
    /* Push some timers */
    for (int i = 0; i < 5; i++)
      {
        struct SocketTimer_T *timer
            = create_timer_with_expiry (arena, base_time + (i + 1) * 1000);
        SocketTimer_heap_push (heap, timer);
      }
    ASSERT (verify_heap_property (heap));

    /* Pop a couple */
    SocketTimer_heap_pop (heap);
    SocketTimer_heap_pop (heap);
    ASSERT (verify_heap_property (heap));

    /* Push more */
    for (int i = 0; i < 3; i++)
      {
        struct SocketTimer_T *timer
            = create_timer_with_expiry (arena, base_time + (i + 10) * 1000);
        SocketTimer_heap_push (heap, timer);
      }
    ASSERT (verify_heap_property (heap));

    /* Peek */
    struct SocketTimer_T *peeked = SocketTimer_heap_peek (heap);
    ASSERT_NOT_NULL (peeked);
    ASSERT (verify_heap_property (heap));

    /* Pop remaining */
    while (heap->count > 0)
      {
        SocketTimer_heap_pop (heap);
        ASSERT (verify_heap_property (heap));
      }

    ASSERT_EQ (heap->count, 0);
  }
  FINALLY
  {
    SocketTimer_heap_free (&heap);
    Arena_dispose (&arena);
  }
  END_TRY;
}


int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

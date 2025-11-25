#ifndef SOCKETTIMER_INTERNAL_INCLUDED
#define SOCKETTIMER_INTERNAL_INCLUDED

/**
 * SocketTimer-internal.h - Internal declarations for SocketTimer module
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This header provides internal declarations shared between SocketTimer
 * implementation files. Not part of the public API.
 */

#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketTimer-private.h"
#include "core/SocketTimer.h"

/* Thread-local error buffer - exported for use by sub-modules */
#ifdef _WIN32
extern __declspec (thread) char sockettimer_error_buf[SOCKET_TIMER_ERROR_BUFSIZE];
extern __declspec (thread) Except_T SocketTimer_DetailedException;
#else
extern __thread char sockettimer_error_buf[SOCKET_TIMER_ERROR_BUFSIZE];
extern __thread Except_T SocketTimer_DetailedException;
#endif

/* Error formatting macros */
#define SOCKETTIMER_ERROR_FMT(fmt, ...)                                       \
  snprintf (sockettimer_error_buf, SOCKET_TIMER_ERROR_BUFSIZE,                \
            fmt " (errno: %d - %s)", ##__VA_ARGS__, errno, strerror (errno))

#define SOCKETTIMER_ERROR_MSG(fmt, ...)                                       \
  snprintf (sockettimer_error_buf, SOCKET_TIMER_ERROR_BUFSIZE, fmt,           \
            ##__VA_ARGS__)

/* Macro to raise timer exception with detailed error message */
#define RAISE_SOCKETTIMER_ERROR(base_exception)                               \
  do                                                                          \
    {                                                                         \
      SocketTimer_DetailedException = (base_exception);                       \
      SocketTimer_DetailedException.reason = sockettimer_error_buf;           \
      RAISE (SocketTimer_DetailedException);                                  \
    }                                                                         \
  while (0)

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * sockettimer_now_ms - Get current monotonic time in milliseconds
 *
 * Returns: Current time in milliseconds since some arbitrary monotonic point
 * Raises: SocketTimer_Failed if clock_gettime fails
 * Thread-safe: Yes (CLOCK_MONOTONIC is thread-safe)
 */
extern int64_t sockettimer_now_ms (void);

/**
 * sockettimer_validate_heap - Validate heap is available from poll
 * @poll: Poll instance
 *
 * Returns: Heap pointer
 * Raises: SocketTimer_Failed if heap not available
 * Thread-safe: Yes
 */
extern SocketTimer_heap_T *sockettimer_validate_heap (SocketPoll_T poll);

/**
 * sockettimer_validate_delay - Validate delay parameter
 * @delay_ms: Delay in milliseconds
 *
 * Raises: SocketTimer_Failed if delay is invalid
 * Thread-safe: Yes
 */
extern void sockettimer_validate_delay (int64_t delay_ms);

/**
 * sockettimer_validate_interval - Validate interval parameter
 * @interval_ms: Interval in milliseconds
 *
 * Raises: SocketTimer_Failed if interval is invalid
 * Thread-safe: Yes
 */
extern void sockettimer_validate_interval (int64_t interval_ms);

/**
 * sockettimer_allocate_timer - Allocate timer structure from arena
 * @arena: Arena to allocate from
 *
 * Returns: Allocated timer structure
 * Raises: SocketTimer_Failed on allocation failure
 * Thread-safe: Yes
 */
extern struct SocketTimer_T *sockettimer_allocate_timer (Arena_T arena);

/**
 * sockettimer_init_oneshot - Initialize a one-shot timer
 * @timer: Timer to initialize
 * @delay_ms: Delay in milliseconds
 * @callback: Callback function
 * @userdata: User data for callback
 *
 * Thread-safe: Yes
 */
extern void sockettimer_init_oneshot (struct SocketTimer_T *timer,
                                      int64_t delay_ms,
                                      SocketTimerCallback callback,
                                      void *userdata);

/**
 * sockettimer_init_repeating - Initialize a repeating timer
 * @timer: Timer to initialize
 * @interval_ms: Interval in milliseconds
 * @callback: Callback function
 * @userdata: User data for callback
 *
 * Thread-safe: Yes
 */
extern void sockettimer_init_repeating (struct SocketTimer_T *timer,
                                        int64_t interval_ms,
                                        SocketTimerCallback callback,
                                        void *userdata);

/* ============================================================================
 * Heap Helper Functions
 * ============================================================================ */

/**
 * sockettimer_heap_parent - Get parent index in heap
 * @index: Current index
 *
 * Returns: Parent index
 */
extern size_t sockettimer_heap_parent (size_t index);

/**
 * sockettimer_heap_left_child - Get left child index in heap
 * @index: Current index
 *
 * Returns: Left child index
 */
extern size_t sockettimer_heap_left_child (size_t index);

/**
 * sockettimer_heap_right_child - Get right child index in heap
 * @index: Current index
 *
 * Returns: Right child index
 */
extern size_t sockettimer_heap_right_child (size_t index);

/**
 * sockettimer_heap_swap - Swap two timers in heap array
 * @timers: Timer array
 * @i: First index
 * @j: Second index
 */
extern void sockettimer_heap_swap (struct SocketTimer_T **timers, size_t i,
                                   size_t j);

/**
 * sockettimer_heap_sift_up - Restore heap property by moving element up
 * @timers: Timer array
 * @index: Starting index
 */
extern void sockettimer_heap_sift_up (struct SocketTimer_T **timers,
                                      size_t index);

/**
 * sockettimer_heap_sift_down - Restore heap property by moving element down
 * @timers: Timer array
 * @count: Number of elements
 * @index: Starting index
 */
extern void sockettimer_heap_sift_down (struct SocketTimer_T **timers,
                                        size_t count, size_t index);

/**
 * sockettimer_heap_resize - Resize heap array to new capacity
 * @heap: Heap to resize
 * @new_capacity: New capacity (must be > current count)
 *
 * Raises: SocketTimer_Failed on allocation failure
 */
extern void sockettimer_heap_resize (SocketTimer_heap_T *heap,
                                     size_t new_capacity);

/**
 * sockettimer_skip_cancelled - Skip cancelled timers at root of heap
 * @heap: Timer heap
 *
 * Thread-safe: No (caller must hold heap->mutex)
 */
extern void sockettimer_skip_cancelled (SocketTimer_heap_T *heap);

/**
 * sockettimer_find_in_heap - Find timer in heap and return its index
 * @heap: Timer heap
 * @timer: Timer to find
 *
 * Returns: Index of timer if found and not cancelled, -1 otherwise
 * Thread-safe: No (caller must hold heap->mutex)
 */
extern ssize_t sockettimer_find_in_heap (SocketTimer_heap_T *heap,
                                         const struct SocketTimer_T *timer);

#endif /* SOCKETTIMER_INTERNAL_INCLUDED */


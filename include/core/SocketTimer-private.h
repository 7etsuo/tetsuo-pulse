#ifndef SOCKETTIMER_PRIVATE_INCLUDED
#define SOCKETTIMER_PRIVATE_INCLUDED

#include "core/Arena.h"
#include "core/SocketTimer.h"
#include <pthread.h>
#include <stdint.h>

/**
 * @file SocketTimer-private.h
 * @brief Internal timer implementation details and heap management.
 *
 * Private header containing internal structures and functions for the SocketTimer
 * module. Not part of the public API - do not include directly from user code.
 *
 * Contains:
 * - Timer heap implementation with binary heap operations
 * - Timer ID generation and management
 * - Internal timer structure definitions
 *
 * @note Thread-safe where noted - heap operations use mutex protection.
 * @see SocketTimer.h for public timer API.
 * @ingroup event_system
 */

/**
 * @brief Internal structure representing a single timer event in the timer subsystem.
 * @ingroup event_system
 *
 * This structure holds all data for a timer, including timing information,
 * callback details, and heap management fields for efficient operations.
 *
 * @note Private implementation detail - users interact via opaque SocketTimer_T handle.
 * @note Allocated and managed by SocketTimer_heap_T.
 * @note Thread-safe access via heap mutex.
 *
 * @var SocketTimer_T::expiry_ms Absolute expiry time in milliseconds using monotonic clock (CLOCK_MONOTONIC).
 * @var SocketTimer_T::interval_ms Repeating interval in milliseconds; 0 for one-shot, >0 for periodic firing.
 * @var SocketTimer_T::callback User-provided callback function invoked upon timer expiry.
 * @var SocketTimer_T::userdata Opaque user data passed to the callback function.
 * @var SocketTimer_T::cancelled Flag indicating lazy cancellation; checked during heap processing.
 * @var SocketTimer_T::id Unique 64-bit identifier for timer uniqueness and debugging.
 * @var SocketTimer_T::heap_index Position in the binary heap's array for efficient operations; SOCKET_TIMER_INVALID_HEAP_INDEX if inactive.
 *
 * @see SocketTimer_heap_T for the containing heap.
 * @see SocketTimer.h for public API.
 */
struct SocketTimer_T
{
  int64_t expiry_ms;            /* Absolute expiry time (monotonic clock) */
  int64_t interval_ms;          /* 0 for one-shot, >0 for repeating */
  SocketTimerCallback callback; /* User callback function */
  void *userdata;               /* User data for callback */
  int cancelled;                /* Lazy deletion flag */
  uint64_t id; /* Unique timer ID (64-bit to prevent wrap-around) */

  size_t heap_index; /* Heap position for fast lookup/cancel,
                        SOCKET_TIMER_INVALID_HEAP_INDEX if not in heap */
};

/**
 * @brief Binary min-heap structure for efficient timer management.
 * @ingroup event_system
 *
 * Manages a collection of SocketTimer_T instances ordered by expiry time.
 * Supports O(log n) push/pop and O(1) peek for next expiry.
 * Uses dynamic array for heap storage and mutex for thread safety.
 *
 * @note Private implementation detail of SocketTimer module.
 * @note Memory allocated from provided Arena_T.
 * @var SocketTimer_heap_T::timers Dynamic array of timer pointers forming the heap.
 * @var SocketTimer_heap_T::count Current number of active timers.
 * @var SocketTimer_heap_T::capacity Allocated size of timers array.
 * @var SocketTimer_heap_T::next_id Sequential ID generator for timers.
 * @var SocketTimer_heap_T::arena Memory arena for timers and internal allocations.
 * @var SocketTimer_heap_T::mutex Mutex for thread-safe operations.
 *
 * @see SocketTimer_T for individual timer structure.
 * @see SocketTimer.h for public timer functions.
 */
struct SocketTimer_heap_T
{
  struct SocketTimer_T **timers; /* Dynamic array of timer pointers (heap) */
  size_t count;                  /* Current number of timers in heap */
  size_t capacity;               /* Allocated capacity of timers array */
  uint64_t
      next_id;   /* Next timer ID to assign (64-bit to prevent wrap-around) */
  Arena_T arena; /* Memory arena for allocations */
  pthread_mutex_t mutex; /* Thread safety mutex */
};

/**
 * @brief Typedef for the internal timer heap structure.
 * @ingroup event_system
 *
 * Provides opaque access to the heap implementation.
 * @see struct SocketTimer_heap_T for detailed fields.
 * @see SocketTimer_heap_new() for creation.
 */
typedef struct SocketTimer_heap_T SocketTimer_heap_T;

/**
 * @brief Sentinel value indicating that a timer is not currently in the heap.
 * @ingroup event_system
 *
 * Used in SocketTimer_T::heap_index to mark timers that are cancelled or not inserted.
 * @see SocketTimer_T::heap_index
 */
#define SOCKET_TIMER_INVALID_HEAP_INDEX ((size_t) - 1)

/**
 * @brief Create a new timer heap.
 * @ingroup event_system
 * @param arena Arena to allocate from (NULL for malloc fallback).
 * @return New heap instance or NULL on error.
 * @throws SocketTimer_Failed if memory allocation fails or mutex initialization fails.
 * @threadsafe No - heap mutex not yet usable.
 * @see SocketTimer_heap_free() for cleanup.
 * @see Arena_T for arena usage details.
 */
SocketTimer_heap_T *SocketTimer_heap_new (Arena_T arena);

/**
 * @brief Free timer heap structure and destroy mutex.
 * @ingroup event_system
 * @param heap Heap to free (may be NULL).
 * @threadsafe No (caller must ensure no concurrent access).
 * @note Frees the heap control structure and destroys the mutex. Timers and timers array must be freed via Arena_dispose(arena). Arena lifetime managed by caller.
 * @see SocketTimer_heap_new() for creation.
 */
void SocketTimer_heap_free (SocketTimer_heap_T **heap);

/**
 * @brief Add timer to heap.
 * @ingroup event_system
 * @param heap Timer heap.
 * @param timer Timer to add (takes ownership).
 * @throws SocketTimer_Failed on allocation failure.
 * @threadsafe Yes - uses heap mutex.
 * @see SocketTimer_heap_pop() for removal.
 */
void SocketTimer_heap_push (SocketTimer_heap_T *heap,
                            struct SocketTimer_T *timer);

/**
 * @brief Remove and return earliest timer.
 * @ingroup event_system
 * @param heap Timer heap.
 * @return Earliest timer or NULL if heap empty.
 * @threadsafe Yes - uses heap mutex.
 * @see SocketTimer_heap_push() for adding timers.
 */
struct SocketTimer_T *SocketTimer_heap_pop (SocketTimer_heap_T *heap);

/**
 * @brief Get earliest timer without removing.
 * @ingroup event_system
 * @param heap Timer heap.
 * @return Earliest timer or NULL if heap empty.
 * @threadsafe Yes - uses heap mutex.
 * @see SocketTimer_heap_pop() for removal.
 */
struct SocketTimer_T *SocketTimer_heap_peek (SocketTimer_heap_T *heap);

/**
 * @brief Get milliseconds until next timer expiry.
 * @ingroup event_system
 * @param heap Timer heap.
 * @return Milliseconds until next timer (>= 0), or -1 if no timers.
 * @threadsafe Yes - uses heap mutex.
 * @see SocketTimer_heap_pop() to fire expired timers.
 */
int64_t SocketTimer_heap_peek_delay (SocketTimer_heap_T *heap);

/**
 * @brief Fire all expired timers and return count.
 * @ingroup event_system
 * @param heap Timer heap.
 * @return Number of timers that fired.
 * @threadsafe Yes - uses heap mutex.
 * @note Callbacks are invoked outside the mutex to prevent deadlocks. Repeating timers are rescheduled after firing.
 * @see SocketTimer_heap_peek_delay() to check for expired timers.
 */
int SocketTimer_process_expired (SocketTimer_heap_T *heap);

/**
 * @brief Mark timer as cancelled (lazy deletion).
 * @ingroup event_system
 * @param heap Timer heap.
 * @param timer Timer to cancel.
 * @return 0 on success, -1 if timer not found.
 * @threadsafe Yes - uses heap mutex.
 * @note O(1) time complexity using maintained heap_index field.
 * @see SocketTimer_heap_push() for adding timers.
 */
int SocketTimer_heap_cancel (SocketTimer_heap_T *heap,
                             struct SocketTimer_T *timer);

/**
 * @brief Get milliseconds until timer expiry.
 * @ingroup event_system
 * @param heap Timer heap.
 * @param timer Timer to query.
 * @return Milliseconds until expiry (>= 0), or -1 if timer not found/cancelled.
 * @threadsafe Yes - uses heap mutex.
 * @note O(1) time complexity using maintained heap_index field.
 * @see SocketTimer_heap_push() for adding timers.
 */
int64_t SocketTimer_heap_remaining (SocketTimer_heap_T *heap,
                                    const struct SocketTimer_T *timer);

#endif /* SOCKETTIMER_PRIVATE_INCLUDED */

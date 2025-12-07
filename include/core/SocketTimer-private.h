#ifndef SOCKETTIMER_PRIVATE_INCLUDED
#define SOCKETTIMER_PRIVATE_INCLUDED

#include "core/Arena.h"
#include "core/SocketTimer.h"
#include <pthread.h>
#include <stdint.h>

/**
 * Private internal functions for SocketTimer module - not public API.
 * Used by SocketPoll integration and timer implementation.
 * Thread-safe where noted.
 */

/* Timer structure - internal definition */
struct SocketTimer_T
{
    int64_t expiry_ms;           /* Absolute expiry time (monotonic clock) */
    int64_t interval_ms;         /* 0 for one-shot, >0 for repeating */
    SocketTimerCallback callback; /* User callback function */
    void *userdata;             /* User data for callback */
    int cancelled;              /* Lazy deletion flag */
    uint64_t id;               /* Unique timer ID (64-bit to prevent wrap-around) */

    size_t heap_index;          /* Heap position for fast lookup/cancel, SOCKET_TIMER_INVALID_HEAP_INDEX if not in heap */
};

/* Heap structure - internal definition */
struct SocketTimer_heap_T
{
    struct SocketTimer_T **timers;  /* Dynamic array of timer pointers (heap) */
    size_t count;                   /* Current number of timers in heap */
    size_t capacity;                /* Allocated capacity of timers array */
    uint64_t next_id;              /* Next timer ID to assign (64-bit to prevent wrap-around) */
    Arena_T arena;                  /* Memory arena for allocations */
    pthread_mutex_t mutex;          /* Thread safety mutex */
};

/* Type alias for heap */
typedef struct SocketTimer_heap_T SocketTimer_heap_T;

/**
 * Invalid heap index value - indicates timer not in heap
 */
#define SOCKET_TIMER_INVALID_HEAP_INDEX ((size_t)-1)

/**
 * SocketTimer_heap_new - Create a new timer heap
 * @arena: Arena to allocate from
 * Returns: New heap instance or NULL on error
 * Thread-safe: No (heap not yet initialized)
 */
SocketTimer_heap_T *SocketTimer_heap_new (Arena_T arena);

/**
 * SocketTimer_heap_free - Free timer heap structure and destroy mutex
 * @heap: Heap to free (may be NULL)
 *
 * Frees the heap control structure and destroys the mutex. Timers and timers
 * array must be freed via Arena_dispose(arena). Arena lifetime managed by caller.
 * Thread-safe: No (caller must ensure no concurrent access)
 */
void SocketTimer_heap_free (SocketTimer_heap_T **heap);

/**
 * SocketTimer_heap_push - Add timer to heap
 * @heap: Timer heap
 * @timer: Timer to add (takes ownership)
 * Raises: SocketTimer_Failed on allocation failure
 * Thread-safe: Yes - uses heap mutex
 */
void SocketTimer_heap_push (SocketTimer_heap_T *heap, struct SocketTimer_T *timer);

/**
 * SocketTimer_heap_pop - Remove and return earliest timer
 * @heap: Timer heap
 * Returns: Earliest timer or NULL if heap empty
 * Thread-safe: Yes - uses heap mutex
 */
struct SocketTimer_T *SocketTimer_heap_pop (SocketTimer_heap_T *heap);

/**
 * SocketTimer_heap_peek - Get earliest timer without removing
 * @heap: Timer heap
 * Returns: Earliest timer or NULL if heap empty
 * Thread-safe: Yes - uses heap mutex
 */
struct SocketTimer_T *SocketTimer_heap_peek (SocketTimer_heap_T *heap);

/**
 * SocketTimer_heap_peek_delay - Get milliseconds until next timer expiry
 * @heap: Timer heap
 * Returns: Milliseconds until next timer (>= 0), or -1 if no timers
 * Thread-safe: Yes - uses heap mutex
 */
int64_t SocketTimer_heap_peek_delay (SocketTimer_heap_T *heap);

/**
 * SocketTimer_process_expired - Fire all expired timers and return count
 * @heap: Timer heap
 * Returns: Number of timers that fired
 * Thread-safe: Yes - uses heap mutex
 * Note: Callbacks are invoked outside the mutex to prevent deadlocks.
 * Repeating timers are rescheduled after firing.
 */
int SocketTimer_process_expired (SocketTimer_heap_T *heap);

/**
 * SocketTimer_heap_cancel - Mark timer as cancelled (lazy deletion)
 * @heap: Timer heap
 * @timer: Timer to cancel
 * Returns: 0 on success, -1 if timer not found
 * Thread-safe: Yes - uses heap mutex
 * Note: O(1) time complexity using maintained heap_index field
 */
int SocketTimer_heap_cancel (SocketTimer_heap_T *heap, struct SocketTimer_T *timer);

/**
 * SocketTimer_heap_remaining - Get milliseconds until timer expiry
 * @heap: Timer heap
 * @timer: Timer to query
 * Returns: Milliseconds until expiry (>= 0), or -1 if timer not found/cancelled
 * Thread-safe: Yes - uses heap mutex
 * Note: O(1) time complexity using maintained heap_index field
 */
int64_t SocketTimer_heap_remaining (SocketTimer_heap_T *heap,
                                   const struct SocketTimer_T *timer);

#endif /* SOCKETTIMER_PRIVATE_INCLUDED */

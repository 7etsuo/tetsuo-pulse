#ifndef SOCKETTIMER_PRIVATE_INCLUDED
#define SOCKETTIMER_PRIVATE_INCLUDED

#include "core/Arena.h"
#include "core/SocketTimer.h"
#include <pthread.h>
#include <stdint.h>

/**
 * @file SocketTimer-private.h
 * @ingroup event_system
 * @brief Internal implementation details for the high-performance SocketTimer
 * module.
 *
 * This private header provides the core structures and functions implementing
 * the timer subsystem's binary min-heap management, timer state tracking, and
 * thread-safe operations. It is **not part of the public API** and should
 * never be included directly in application code. Use only for library
 * maintenance, debugging, or advanced internal customization.
 *
 *  Features
 *
 * - Efficient binary min-heap for O(log n) insert, delete, and minimum
 * operations
 * - Lazy cancellation mechanism for pending timers (marked invalid, removed on
 * pop)
 * - Unique 64-bit timer identifiers to prevent collisions and aid debugging
 * - Mutex-protected thread safety for concurrent access from multiple threads
 * - Arena-based memory allocation for predictable lifecycle management
 * - Monotonic clock integration (CLOCK_MONOTONIC) for reliable timing
 * unaffected by system time changes
 *
 *  Architecture Overview
 *
 * ```
 * ┌──────────────────────────────────────┐
 * │          Public SocketTimer API      │
 * │   SocketTimer_add(), cancel(), etc.  │
 * └────────────────┬─────────────────────┘
 *                  │ Integrates with
 * ┌────────────────▼─────────────────────┐
 * │       Private Heap Management        │
 * │ heap_push(), heap_pop(), process()   │
 * │   Binary heap + mutex protection     │
 * └────────────────┬─────────────────────┘
 *                  │ Depends on
 * ┌────────────────▼─────────────────────┐
 * │         Foundation Layer             │
 * │     Arena_T (memory), pthread mutex  │
 * └──────────────────────────────────────┘
 * ```
 *
 *  Module Relationships
 *
 * - **Depends on**: Foundation modules (@ref foundation) including Arena_T for
 * allocations and pthread for synchronization
 * - **Used internally by**: SocketTimer public functions and SocketPoll_T
 * event loop integration for automatic timer firing
 * - **Provides support for**: Event system (@ref event_system) components
 * requiring precise, scalable timer scheduling
 *
 *  Platform Requirements
 *
 * - POSIX-compliant OS with support for CLOCK_MONOTONIC (Linux, BSD, macOS)
 * - pthreads library for mutex operations (enabled via SOCKET_HAS_PTHREADS)
 * - C11 compiler with _GNU_SOURCE defined for clock_gettime() and related
 * functions
 * - 64-bit integers (int64_t, uint64_t) for timestamps and IDs
 *
 *  Important Notes
 *
 * - All heap operations are thread-safe via internal mutex, but callbacks in
 * process_expired() execute outside the lock to avoid deadlocks
 * - Timers use lazy deletion: cancelled timers are marked but physically
 * removed only when popped from heap
 * - Memory management: Heap and timers allocated from provided Arena_T;
 * dispose arena to free all
 *
 * @warning This private API is unstable and may change between releases
 * without notice. Always use public headers.
 * @warning Do not free individual timers manually; managed by heap and arena.
 *
 * @see SocketTimer.h for the stable public interface
 * @see SocketPoll.h for event loop integration
 * @see docs/ASYNC_IO.md for asynchronous I/O patterns using timers
 * @see docs/ERROR_HANDLING.md for exception handling in timer operations
 */

/**
 * @brief Internal representation of a single scheduled timer event.
 * @ingroup event_system
 *
 * Stores all necessary state for a timer managed by the binary min-heap:
 * timing parameters, user callback and data, cancellation status, unique
 * identifier, and positioning data for efficient heap operations.
 *
 * Instances are allocated from the heap's Arena_T and lifecycle-managed
 * automatically: created on add, potentially rescheduled on repeat fire,
 * marked for lazy deletion on cancel, and freed on pop or arena dispose.
 *
 *  Field Access
 *
 * Fields are private and accessed only under heap mutex protection.
 * Direct manipulation by external code is prohibited and may cause
 * corruption or crashes.
 *
 *  Timing Model
 *
 * - expiry_ms: Absolute future time (ms since monotonic epoch)
 * - interval_ms: Period for repeats; reschedule sets new expiry = current +
 * interval
 * - Delays computed as now_ms + delay_ms for absolute expiry
 *
 *  Callback Execution
 *
 * When expired, callback(userdata) invoked outside mutex (to prevent
 * deadlock). Callback must be fast; no heap operations or long blocks.
 *
 * @threadsafe Partial - modifications and reads protected by heap mutex.
 *                Callback executes with userdata (user-managed safety).
 *
 * @note Use monotonic clock (CLOCK_MONOTONIC) for reliable expiry
 * calculations.
 * @note cancelled=1 marks for skip during process_expired(), removed on pop.
 * @note id generated sequentially; used for logging and duplicate prevention.
 * @note heap_index enables O(1) cancel by direct array access + heapify.
 *
 * @warning Never free timers manually or access fields directly.
 * @warning Callback must not call heap functions (deadlock risk).
 *
 * @complexity Fields support O(log n) heap ops via index maintenance.
 *
 * @see SocketTimer_heap_T The heap managing collections of these timers.
 * @see SocketTimer_add() Public creation (sets expiry, interval=0, callback,
 * userdata).
 * @see SocketTimer_add_repeating() Sets interval >0.
 * @see SocketTimerCallback Callback type constraints.
 * @see docs/TIMEOUTS.md For advanced timing patterns.
 */
struct SocketTimer_T
{
  int64_t expiry_ms;   /**< Absolute expiry time (ms, CLOCK_MONOTONIC). Updated
                          for repeats. */
  int64_t interval_ms; /**< Repeat interval (ms); 0=one-shot, >0=periodic. */
  SocketTimerCallback
      callback;   /**< Function invoked on expiry: callback(userdata). */
  void *userdata; /**< Opaque data passed unchanged to callback. User owns
                     lifetime. */
  int cancelled;  /**< Lazy cancel flag: 1=skip firing/remove on pop, 0=active.
                     Atomic set under mutex. */
  int paused;     /**< Pause flag: 1=timer paused and won't fire, 0=active. */
  int64_t paused_remaining_ms; /**< Time remaining when paused (for resume). */
  uint64_t id;    /**< Unique monotonic ID for debugging/uniqueness. 64-bit
                     prevents wrap in practice. */

  size_t heap_index; /**< Position in heap->timers array. Enables O(1) access
                        for cancel/update. SOCKET_TIMER_INVALID_HEAP_INDEX if
                        not active/in heap. */
};

/**
 * @brief Binary min-heap container for managing multiple SocketTimer_T
 * instances.
 * @ingroup event_system
 *
 * Implements a dynamic array-based binary min-heap (priority queue) ordered
 * by timer expiry time (earliest first). Supports efficient scheduling,
 * expiry checking, and processing in high-performance event loops.
 *
 * Core Operations Complexity:
 * | Operation | Complexity | Description |
 * |-----------|------------|-------------|
 * | push      | O(log n)   | Insert timer, heapify-up from leaf |
 * | pop       | O(log n)   | Extract min, heapify-down from root |
 * | peek      | O(1)       | Access root (next expiry) without remove |
 * | cancel    | O(log n)   | Mark + remove/reheap if active |
 * | resize    | Amortized O(1) | Double capacity when full |
 *
 * Memory & Growth:
 * - Starts with small capacity, doubles on overflow (efficient amortized
 * growth)
 * - All data (heap array, timers) from single Arena_T for batch free
 * - Supports millions of timers practically (memory-limited)
 *
 * Thread Safety & Concurrency:
 * - Full protection via pthread_mutex_t for all state modifications/queries
 * - process_expired() temporarily releases lock during user callbacks
 * - Suitable for multi-threaded environments (e.g., worker threads adding
 * timers)
 *
 * Error Handling:
 * - Functions return error codes or NULL; some raise SocketTimer_Failed via
 * validation
 * - Mutex init failure or arena exhaustion handled gracefully (no leaks)
 *
 * @threadsafe Yes - mutex serializes all access; callbacks executed unlocked.
 *
 * @note Heap is 1-indexed (timers[0] unused as sentinel).
 * @note Lazy cancellation: timers marked invalid but stay until popped
 * (optimizes cancel).
 * @note next_id increments atomically; overflow irrelevant (64-bit huge).
 * @note arena lifetime > heap lifetime; clear only after heap_free().
 *
 * @warning Avoid long-running callbacks in process_expired() (starves other
 * ops).
 * @warning Direct field access corrupts heap invariants; always use API.
 * @warning Capacity growth consumes memory; monitor via count/capacity if
 * needed.
 *
 * @complexity See table above for ops; overall scalable to high loads.
 *
 *  Usage Pattern (Internal)
 *
 * @code{.c}
 * // Typical initialization in SocketPoll or similar
 * Arena_T arena = ...;
 * SocketTimer_heap_T *heap = SocketTimer_heap_new(arena);
 * if (heap) {
 *   // Add timers: heap_push(heap, new_timer);
 *   // In loop: process_expired(heap); or use peek_delay for poll timeout
 *   SocketTimer_heap_free(&heap);
 * }
 * Arena_dispose(&arena);
 * @endcode
 *
 * @see SocketTimer_T Timers stored and managed by this heap.
 * @see SocketTimer_heap_new() Creation and initialization.
 * @see SocketTimer_heap_push() Adding timers.
 * @see SocketTimer_process_expired() Firing expired timers.
 * @see SocketTimer.h Public functions wrapping heap ops.
 * @see docs/ASYNC_IO.md Event loop timer integration.
 * @see docs/ERROR_HANDLING.md Exception details for validation failures.
 */
struct SocketTimer_heap_T
{
  struct SocketTimer_T *
      *timers; /**< Dynamic array of timer pointers (heap structure).
                  1-indexed; reallocated on growth. */

  size_t count; /**< Active timers in heap. Updated on push/pop/cancel. */

  size_t
      capacity; /**< Allocated array size. Doubled when count == capacity. */

  uint64_t
      next_id; /**< Next timer ID generator. Incremented on each new timer. */

  Arena_T arena; /**< Allocation source for timers[], internal buffers, and
                    SocketTimer_T instances. */

  pthread_mutex_t mutex; /**< Synchronization primitive. Locks all operations
                            except during callbacks. */
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
 * Used in SocketTimer_T::heap_index to mark timers that are cancelled or not
 * inserted.
 * @see SocketTimer_T::heap_index
 */
#define SOCKET_TIMER_INVALID_HEAP_INDEX ((size_t) - 1)

/**
 * @brief Allocate and initialize a new timer heap instance.
 * @ingroup event_system
 *
 * Dynamically allocates the heap control structure, initial timers array,
 * and initializes state variables and mutex. All memory from provided arena.
 * Initial heap capacity is small and grows dynamically as needed.
 *
 * Failure modes (return NULL):
 * - Invalid/NULL arena parameter
 * - Arena allocation failure for heap struct or initial timers array
 * - pthread_mutex_init() failure (system resource limits, e.g., too many
 * locks)
 *
 * No exceptions are raised by this function; check return value for success.
 *
 * @param[in] arena Required non-NULL Arena_T for heap allocations.
 *                  No malloc fallback; NULL input returns NULL immediately.
 *
 * @return Allocated and initialized SocketTimer_heap_T * or NULL on any
 * failure.
 *
 * @threadsafe No - initialization is single-threaded; use thread-safe after
 * success.
 *
 *  Basic Usage
 *
 * @code{.c}
 * Arena_T arena = Arena_new();  // Or existing arena
 * SocketTimer_heap_T *heap = SocketTimer_heap_new(arena);
 * if (heap == NULL) {
 *     // Error: log, retry allocation, or fail gracefully
 *     SOCKET_LOG_ERROR_MSG("Failed to create timer heap");
 *     Arena_dispose(&arena);
 *     return NULL;  // Or handle error
 * }
 * // Heap ready: push timers, integrate with poll loop
 * // ...
 * SocketTimer_heap_free(&heap);  // Cleanup structure/mutex
 * Arena_dispose(&arena);         // Free all memory (timers, array)
 * @endcode
 *
 *  Error Handling Pattern
 *
 * @code{.c}
 * TRY {
 *     Arena_T arena = Arena_new();
 *     SocketTimer_heap_T *heap = SocketTimer_heap_new(arena);
 *     // Use heap...
 * } EXCEPT(SocketTimer_Failed) {  // Note: this func doesn't throw, but later
 * ops may
 *     // Handle via validation helpers
 * } FINALLY {
 *     // Cleanup
 * } END_TRY;
 * @endcode
 *
 * @note Mutex initialized with default attributes (fast mutex, not recursive).
 * @note Initial capacity typically 8-16 timers; doubles on resize (amortized
 * efficient).
 * @note After success, all subsequent heap ops are thread-safe.
 *
 * @warning Arena lifetime must exceed heap's: dispose only after heap_free().
 * @warning On failure, no resources leaked (partial allocs cleaned
 * internally).
 * @warning In low-memory, may fail arena allocs; consider larger initial
 * arena.
 *
 * @complexity O(1) - constant time fixed allocations and init.
 *
 * @see SocketTimer_heap_free() Required paired cleanup (mutex destroy).
 * @see Arena_alloc() Underlying allocation mechanism.
 * @see pthread_mutex_init(3) Mutex creation details and errno codes.
 * @see SocketTimer_heap_push() First operation after creation.
 */
SocketTimer_heap_T *SocketTimer_heap_new (Arena_T arena);

/**
 * @brief Finalize and nullify timer heap handle: destroy mutex only.
 * @ingroup event_system
 *
 * Destroys the internal pthread mutex (releasing any system resources)
 * and sets *heap = NULL to invalidate the handle and prevent dangling use.
 *
 * Important**: Does NOT free the heap structure, timers array, or any
 * SocketTimer_T instances - these remain allocated in the original Arena_T.
 * To reclaim memory, caller must subsequently call Arena_dispose(arena)
 * or equivalent after ensuring all timers processed/cancelled.
 *
 * Safe for NULL or already-NULL *heap (no-op).
 *
 * @param[in,out] heap Pointer to heap handle; set to NULL after mutex destroy.
 *
 * @note Call after draining/processing all timers to avoid leaks of pending
 * callbacks.
 * @note Mutex must be unlocked at call time (caller enforce via no concurrent
 * ops).
 * @note No return value; failures in mutex_destroy() (rare, e.g., invalid
 * mutex) ignored silently.
 * @threadsafe No - requires exclusive access; call after stopping threads
 * using heap.
 *
 *  Proper Cleanup Sequence
 *
 * @code{.c}
 * // Before free: optionally drain
 * while (SocketTimer_heap_peek_delay(heap) <= 0) {
 *     SocketTimer_process_expired(heap);
 * }
 * // Cancel any remaining if needed
 * SocketTimer_heap_free(&heap);  // Mutex destroy + nullify
 * // Now safe to free memory
 * Arena_clear(arena);  // Or dispose if end-of-life
 * @endcode
 *
 * @warning Calling with locked mutex leads to undefined behavior (pthread UB).
 * @warning Memory leak if arena not cleared/disposed after this call.
 * @warning Does not wait for or cancel in-flight callbacks (caller
 * responsibility).
 *
 * @complexity O(1) - single mutex destroy operation.
 *
 * @see SocketTimer_heap_new() Creation and arena association.
 * @see Arena_dispose() / Arena_clear() For memory reclamation post-free.
 * @see pthread_mutex_destroy(3) Low-level mutex cleanup and error conditions.
 * @see SocketTimer_process_expired() To handle remaining timers before free.
 * @see SocketTimer_heap_cancel() To invalidate pending timers.
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
 * @note Callbacks are invoked outside the mutex to prevent deadlocks.
 * Repeating timers are rescheduled after firing.
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
 * @return Milliseconds until expiry (>= 0), or -1 if timer not
 * found/cancelled.
 * @threadsafe Yes - uses heap mutex.
 * @note O(1) time complexity using maintained heap_index field.
 * @see SocketTimer_heap_push() for adding timers.
 */
int64_t SocketTimer_heap_remaining (SocketTimer_heap_T *heap,
                                    const struct SocketTimer_T *timer);

#endif /* SOCKETTIMER_PRIVATE_INCLUDED */

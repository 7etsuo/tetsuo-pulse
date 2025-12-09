/**
 * @defgroup foundation Core Foundation Modules
 * @brief Base infrastructure for memory management, exception handling, and
 * core utilities.
 * @{
 * The Foundation group provides the fundamental building blocks used by all
 * other modules in the socket library. Key components include:
 * - Arena (memory): Region-based memory allocation with fast
 * allocation/deallocation
 * - Except (exceptions): Structured exception handling with TRY/EXCEPT/FINALLY
 * - SocketUtil (utilities): Hash functions, error handling, logging
 * - SocketMetrics (metrics): Comprehensive counters, gauges, and histograms
 * for observability and monitoring
 * - SocketConfig (configuration): Global configuration management
 *
 * @see @ref core_io for socket primitives built on foundation.
 * @see @ref Arena_T for memory management
 * @see @ref Except_T for exception handling
 * @see @ref event_system for modules using foundation components
 */

#ifndef ARENA_INCLUDED
#define ARENA_INCLUDED

#include <stddef.h>

/**
 * @file Arena.h
 * @ingroup foundation
 * @brief Arena-based memory allocator for efficient bulk memory management.
 *
 * An arena (also called a memory pool or region) is a memory management
 * technique where allocations are made from a large chunk of memory.
 * All allocations in an arena can be freed at once by disposing the arena.
 *
 * Benefits:
 * - Fast allocation (no per-allocation overhead)
 * - No memory fragmentation within the arena
 * - Simple cleanup - dispose entire arena at once
 * - Thread-safe chunk management with mutex protection
 *
 * Thread Safety:
 * - All operations fully thread-safe with per-arena and global mutex
 * protection
 * - Multiple threads can safely allocate from the same arena concurrently
 * - Each arena has its own mutex protecting allocation state (avail, limit,
 * prev)
 * - Global free chunk cache protected by separate mutex
 * - Safe to use same arena from multiple threads or one arena per thread
 *
 * Usage:
 *   Arena_T arena = Arena_new();
 *   void *ptr = ALLOC(arena, 100);  // Allocate 100 bytes
 *   // ... use memory ...
 *   Arena_clear(arena);      // Clear all allocations but keep arena
 *   // OR
 *   Arena_dispose(&arena);  // Free everything including arena itself
 *
 * @see @ref Arena_T for the opaque arena type.
 * @see @ref Arena_new() for arena creation.
 * @see @ref Arena_dispose() for cleanup.

 */

#include "core/Except.h"

/**
 * @brief Opaque arena type for memory management.
 * @ingroup foundation
 *
 * Arena_T is an opaque pointer to a memory arena structure. Arenas provide
 * fast, thread-safe memory allocation with bulk deallocation. All related
 * objects should use the same arena for their lifecycle management.
 *
 * @see Arena_new() for creation.
 * @see Arena_dispose() for cleanup.

 */
#define T Arena_T
typedef struct T *T;

/**
 * @brief Exception raised when arena allocation fails.
 * @ingroup foundation
 *
 * This exception is raised when:
 * - Memory allocation (malloc) fails
 * - Mutex initialization fails
 * - Arena expansion fails due to system limits
 *
 * @see ERROR_HANDLING.md for exception handling patterns.
 */
extern const Except_T Arena_Failed;

/**
 * @brief Create a new memory arena with initial capacity and thread-safe
 * protection.
 * @ingroup foundation
 *
 * Initializes a new arena allocator. The arena begins with an initial chunk of
 * memory (typically 4KB or system page size) and grows automatically by
 * allocating additional chunks as needed. All allocations are tracked with
 * file and line information for debugging purposes. The arena is fully
 * thread-safe, allowing concurrent allocations from multiple threads.
 *
 * Edge cases:
 * - Returns NULL only if exception handling is disabled; otherwise throws
 * Arena_Failed.
 * - Initial mutex initialization failure (rare, ENOMEM) triggers exception.
 * - Suitable for short-lived objects or request-scoped memory management.
 *
 * @return New arena instance on success.
 *
 * @throws Arena_Failed When underlying malloc or pthread_mutex_init fails.
 *   Common causes: Out of memory (ENOMEM), resource limits (RLIMIT_AS).
 *
 * @threadsafe Yes - creates independent arena with its own mutex protecting
 * allocation state; safe from any thread.
 *
 * ## Usage Example
 *
 * @code{.c}
 * TRY {
 *     Arena_T arena = Arena_new();
 *     // Allocations will use this arena
 *     char *buf = ALLOC(arena, 1024);
 *     // ... use buf ...
 *     // Arena automatically tracks all allocations
 * } EXCEPT(Arena_Failed) {
 *     fprintf(stderr, "Failed to create arena: out of memory\n");
 *     // Handle error - perhaps exit or fallback
 * } FINALLY {
 *     // No need to free individual allocations; dispose will handle
 * } END_TRY;
 * @endcode
 *
 * ## Advanced Usage with Reuse
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * while (running) {
 *     TRY {
 *         // Per-iteration allocations
 *         void *data = CALLOC(arena, 1, sizeof(struct Request));
 *         // ... process request ...
 *     } EXCEPT(Arena_Failed) {
 *         // Handle allocation failure
 *     } END_TRY;
 *     Arena_clear(arena);  // Reset for next iteration
 * }
 * Arena_dispose(&arena);
 * @endcode
 *
 * @note Use arenas to group related allocations (e.g., per-connection buffers,
 * HTTP headers) for efficient bulk deallocation.
 * @warning Avoid long-lived arenas with unbounded growth; monitor usage and
 * clear periodically.
 * @warning Does not support individual free(); all memory freed in bulk via
 * clear() or dispose().
 *
 * @complexity O(1) - single malloc for initial chunk and mutex initialization.
 *
 * @see Arena_dispose() for complete cleanup and memory reclamation.
 * @see Arena_alloc() and ALLOC() for making allocations from the arena.
 * @see Arena_clear() for resetting the arena without disposal.
 * @see docs/ERROR_HANDLING.md for exception handling best practices.
 */
extern T Arena_new (void);

/**
 * @brief Dispose of an arena and all its allocations, freeing underlying
 * memory chunks.
 * @ingroup foundation
 *
 * Releases all memory chunks associated with the arena and destroys the arena
 * structure. The pointer *ap is set to NULL after successful disposal to
 * prevent use-after-free. This is the standard way to clean up an arena after
 * use. All allocations made from this arena become invalid after disposal.
 *
 * Edge cases:
 * - Safe to call on NULL (no-op).
 * - If called concurrently from multiple threads, only one will perform
 * disposal due to mutex.
 * - Recycles freed chunks to global pool for future arenas to reuse (reduces
 * malloc pressure).
 *
 * @param[in,out] ap Pointer to the arena instance (set to NULL on success).
 *
 * @threadsafe Yes - internal mutex ensures atomic disposal; concurrent calls
 * block until complete.
 *
 * ## Basic Usage
 *
 * @code{.c}
 * TRY {
 *     Arena_T arena = Arena_new();
 *     // ... make allocations ...
 *     Arena_dispose(&arena);  // Frees everything, sets arena = NULL
 *     assert(arena == NULL);  // Verify cleanup
 * } EXCEPT(Arena_Failed) {
 *     // Handle creation failure; no dispose needed
 * } END_TRY;
 * @endcode
 *
 * ## Usage in FINALLY Block
 *
 * @code{.c}
 * Arena_T arena = NULL;
 * TRY {
 *     arena = Arena_new();
 *     // ... operations with allocations ...
 * } EXCEPT(Arena_Failed) {
 *     fprintf(stderr, "Arena creation failed\n");
 * } FINALLY {
 *     if (arena != NULL) {
 *         Arena_dispose(&arena);
 *     }
 * } END_TRY;
 * @endcode
 *
 * @note Always pass the address of the arena pointer (&arena) to enable NULL
 * setting and prevent dangling references.
 * @note For reusing the arena across multiple cycles (e.g., request handling
 * loop), prefer Arena_clear().
 * @warning Do not attempt to access the arena or any pointers allocated from
 * it after disposal.
 * @warning Concurrent disposal calls are serialized by mutex, but avoid if
 * possible for performance.
 *
 * @complexity O(c) where c is the number of memory chunks in the arena - each
 * chunk is individually freed.
 *
 * @see Arena_new() for corresponding creation.
 * @see Arena_clear() for resetting allocations without destroying the arena
 * structure.
 * @see docs/ERROR_HANDLING.md for integrating with exception handling.
 */
extern void Arena_dispose (T *ap);

/**
 * @brief Allocate raw memory block from the specified arena.
 * @ingroup foundation
 *
 * Allocates a block of nbytes from the arena's current chunk. If insufficient
 * space remains in the current chunk, a new chunk is allocated automatically.
 * The returned pointer is aligned to the system's maximum alignment
 * requirement (typically 16 bytes). Debug information (file and line) is
 * recorded internally for leak detection and profiling if enabled.
 *
 * Behavior:
 * - Does not initialize memory contents (use memset or Arena_calloc for
 * zeroing).
 * - Fast path if space available in current chunk (no system malloc).
 * - Grows arena by doubling chunk size (up to max) to minimize reallocs.
 * - On failure (arena cannot grow due to system limits), throws Arena_Failed.
 * - Zero-byte allocation returns NULL without error or exception.
 *
 * @param[in] arena Valid non-NULL arena instance.
 * @param[in] nbytes Number of bytes to allocate (>0 for actual allocation).
 * @param[in] file Source file name for debug tracking (typically __FILE__).
 * @param[in] line Source line number for debug tracking (typically __LINE__).
 *
 * @return Pointer to allocated memory, valid until arena clear/dispose; NULL
 * for 0 bytes.
 *
 * @throws Arena_Failed If insufficient space and arena growth fails (e.g.,
 * malloc ENOMEM).
 *
 * @threadsafe Yes - acquires per-arena mutex; low contention for
 * small/frequent allocs.
 *
 * ## Basic Usage via Macro
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * TRY {
 *     void *ptr = ALLOC(arena, 512);  // Macro calls Arena_alloc with
 * __FILE__, __LINE__
 *     // Safe to use ptr
 *     // No individual free needed
 * } EXCEPT(Arena_Failed) {
 *     // OOM handling
 * } END_TRY;
 * Arena_dispose(&arena);
 * @endcode
 *
 * ## Direct Function Call
 *
 * @code{.c}
 * TRY {
 *     // Explicit debug info (rarely needed outside macros)
 *     void *buf = Arena_alloc(arena, 1024, "myfile.c", 123);
 *     // Initialize manually
 *     memset(buf, 0, 1024);  // Or use calloc for auto-zero
 * } EXCEPT(Arena_Failed) {
 *     fprintf(stderr, "Allocation failed\n");
 * } END_TRY;
 * @endcode
 *
 * @note For most cases, use the ALLOC() macro which automatically provides
 * file/line.
 * @note Allocated memory remains valid across Arena_clear() calls? No,
 * cleared.
 * @warning Invalid to call on NULL arena; assumes valid input.
 * @warning Large allocations may cause chunk growth; monitor for performance.
 *
 * @complexity Amortized O(1) - direct from chunk most times; occasional chunk
 * allocation O(1).
 *
 * @see ALLOC(arena, nbytes) macro for convenient usage with auto debug info.
 * @see Arena_calloc() for zero-initialized blocks.
 * @see Arena_new() to create the arena first.
 * @see Arena_clear() and Arena_dispose() for when memory becomes invalid.
 */
extern void *Arena_alloc (T arena, size_t nbytes, const char *file, int line);

/**
 * @brief Allocate and zero-initialize a block of memory elements from the
 * arena.
 * @ingroup foundation
 *
 * Performs allocation similar to Arena_alloc but ensures the entire block is
 * zeroed using memset after allocation. Total size is count * nbytes, with
 * checks for overflow. Ideal for initializing structs, arrays, or any data
 * requiring default zero values. Debug tracking with file/line as standard.
 *
 * Edge cases and behavior:
 * - If count == 0 or nbytes == 0, returns NULL immediately without allocation.
 * - Size computation overflow (e.g., SIZE_MAX crossed) raises Arena_Failed.
 * - Memory zeroed atomically with allocation under mutex protection.
 * - Slower than plain alloc due to memset overhead; use when zero-init is
 * required.
 *
 * @param[in] arena Valid arena instance.
 * @param[in] count Number of elements to zero-allocate.
 * @param[in] nbytes Bytes per element (use sizeof(Type)).
 * @param[in] file Debug file name (__FILE__ via macro).
 * @param[in] line Debug line number (__LINE__ via macro).
 *
 * @return Pointer to zero-filled memory block; NULL if count==0 || nbytes==0.
 *
 * @throws Arena_Failed On allocation failure, size overflow, or arena growth
 * issues.
 *
 * @threadsafe Yes - mutex protected; concurrent safe with serialization.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Zero-init struct array via macro (recommended)
 * TRY {
 *     MyStruct *arr = CALLOC(arena, 20, sizeof(MyStruct));
 *     // All fields in arr[0..19] are zero; safe for C structs
 *     arr[0].id = 1;  // Set specific fields as needed
 * } EXCEPT(Arena_Failed) {
 *     // OOM or overflow
 * } END_TRY;
 * @endcode
 *
 * ## Explicit Call
 *
 * @code{.c}
 * size_t elem_size = sizeof(int);
 * int *ints = Arena_calloc(arena, 1000, elem_size, __FILE__, __LINE__);
 * // ints[0] to ints[999] == 0
 * @endcode
 *
 * @note Prefer CALLOC() macro for automatic debug info injection.
 * @note Ensures C-standard zero-initialization for structs (NULL pointers,
 * zero ints, etc.).
 * @warning memset overhead scales with size; for large blocks, consider alloc
 * + selective init.
 * @warning Verify sizeof() correctness to avoid under/over-allocation bugs.
 *
 * @complexity Amortized O(1) for allocation + O(total_bytes) for memset
 * zeroing.
 *
 * @see CALLOC() macro for convenient zero-allocation with debug info.
 * @see Arena_alloc() for faster non-zeroed allocation.
 * @see sizeof operator for accurate nbytes calculation.
 * @see docs/ERROR_HANDLING.md for handling allocation exceptions.
 */
extern void *Arena_calloc (T arena, size_t count, size_t nbytes,
                           const char *file, int line);

/**
 * @brief Reset the arena by invalidating all current allocations while
 * preserving the arena for reuse.
 * @ingroup foundation
 *
 * Frees all memory chunks allocated within the arena, returning it to a fresh
 * state ready for new allocations. Unlike dispose, the arena object itself
 * (mutex, config) is retained, enabling efficient reuse in loops or repeated
 * operations. Freed chunks are recycled to a global pool to minimize future
 * system allocations.
 *
 * Key behaviors:
 * - All pointers from previous allocations become invalid/dangling.
 * - No exceptions thrown by clear itself; failures in underlying free rare and
 * logged.
 * - Faster than dispose + new for cyclic usage (e.g., per-client session
 * reset).
 * - Maintains thread-safety during clear operation.
 *
 * @param[in] arena Valid non-NULL arena instance to reset.
 *
 * @threadsafe Yes - acquires arena mutex; concurrent operations wait briefly.
 *
 * ## Reuse Pattern Example
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * while (accept_connections) {
 *     Connection_T conn = SocketPool_add(pool, sock);
 *     TRY {
 *         // Connection-specific allocations
 *         SocketBuf_T inbuf = SocketBuf_new(arena, 4096);
 *         SocketHTTP_Headers_T req_headers = SocketHTTP_Headers_new(arena);
 *         // ... process connection ...
 *     } EXCEPT(...) {
 *         // Error handling
 *     } END_TRY;
 *     SocketPool_remove(pool, sock);
 *     Arena_clear(arena);  // Reset for next connection
 * }
 * Arena_dispose(&arena);
 * @endcode
 *
 * ## Simple Reset
 *
 * @code{.c}
 * // No TRY needed as clear doesn't throw
 * Arena_clear(arena);
 * // Immediately safe to allocate again
 * void *fresh = ALLOC(arena, 1024);
 * @endcode
 *
 * @note Optimal for scenarios like HTTP servers resetting per-request state.
 * @note Does not reset arena statistics or debug info; those persist.
 * @warning Update any long-lived pointers/caches after clear to avoid
 * use-after-clear bugs.
 * @warning If arena is empty, clear is near-no-op (just mutex
 * acquire/release).
 *
 * @complexity O(c) where c = number of active chunks; each chunk relinked or
 * freed.
 *
 * @see Arena_dispose() for full destruction when reuse no longer needed.
 * @see Arena_new() for creating arena before reuse cycles.
 * @see ALLOC() for allocations post-clear.
 * @see @ref connection_mgmt for pool integration examples.
 */
extern void Arena_clear (T arena);

/**
 * @brief Convenience macro for Arena_alloc with automatic source location
 * tracking.
 * @ingroup foundation
 *
 * Wraps Arena_alloc(arena, nbytes, __FILE__, __LINE__) to inject
 * compilation-time file and line info for enhanced debugging, leak detection,
 * and profiling. Essential for production code to trace allocation sites
 * without boilerplate.
 *
 * Macro expansion is transparent: no additional runtime cost beyond the
 * function call. Preferred over direct Arena_alloc unless custom location
 * needed.
 *
 * @param[in] arena Arena_T to allocate from.
 * @param[in] nbytes size_t number of bytes.
 *
 * @return void* allocated memory; NULL if nbytes == 0.
 *
 * @throws Arena_Failed Propagated from Arena_alloc on failure.
 *
 * @threadsafe Yes - forwards to thread-safe implementation.
 *
 * ## Standard Usage
 *
 * @code{.c}
 * TRY {
 *     Arena_T arena = Arena_new();
 *     char *buffer = ALLOC(arena, 4096);  // Location tracked automatically
 *     // Use buffer...
 *     // No free(); arena manages
 * } EXCEPT(Arena_Failed) {
 *     // Allocation error
 * } END_TRY;
 * @endcode
 *
 * @note Macro captures exact allocation site for tools like valgrind or custom
 * debuggers.
 * @note Safe in all contexts where Arena_alloc is valid.
 * @warning nbytes == 0 returns NULL harmlessly.
 *
 * @complexity Same as Arena_alloc: amortized O(1).
 *
 * @see Arena_alloc(arena, nbytes, file, line) for manual location override.
 * @see CALLOC(arena, count, nbytes) for zero-initialized variant.
 * @see Arena_new() prerequisite for valid arena.
 */
#define ALLOC(arena, nbytes)                                                  \
  (Arena_alloc ((arena), (nbytes), __FILE__, __LINE__))

/**
 * @brief Convenience macro for zero-initialized multi-element allocation with
 * source tracking.
 * @ingroup foundation
 *
 * Calls Arena_calloc(arena, count, nbytes, __FILE__, __LINE__) to allocate
 * count elements of nbytes each, zero them, and record allocation site
 * automatically. Standard pattern for safe struct/array init in arena-managed
 * memory.
 *
 * Includes overflow protection and atomic zeroing.
 *
 * @param[in] arena Arena_T for allocation.
 * @param[in] count size_t number of elements.
 * @param[in] nbytes size_t bytes per element.
 *
 * @return void* to zeroed block; NULL on zero size.
 *
 * @throws Arena_Failed On underlying failure (alloc, overflow).
 *
 * @threadsafe Yes - via Arena_calloc.
 *
 * ## Common Patterns
 *
 * @code{.c}
 * TRY {
 *     // Zeroed array
 *     double *values = CALLOC(arena, 50, sizeof(double));
 *     // Zeroed single struct
 *     HeaderEntry *header = CALLOC(arena, 1, sizeof(HeaderEntry));
 *     // Fields safe: pointers NULL, numerics 0
 * } EXCEPT(Arena_Failed) {
 *     // Handle
 * } END_TRY;
 * @endcode
 *
 * @note Use sizeof(Type) for nbytes to ensure correctness.
 * @note Equivalent to alloc + memset but with debug info and checks.
 * @warning Large count * nbytes may be slow due to memset; profile if needed.
 *
 * @complexity Amortized O(1) alloc + O(count * nbytes) zeroing.
 *
 * @see Arena_calloc() for direct function with manual file/line.
 * @see ALLOC() for uninitialized faster alloc.
 * @see sizeof for element sizing.
 */
#define CALLOC(arena, count, nbytes)                                          \
  (Arena_calloc ((arena), (count), (nbytes), __FILE__, __LINE__))

#undef T

/** @} */ /* end of foundation group */

#endif

/**
 * @defgroup foundation Core Foundation Modules
 * @brief Base infrastructure for memory management, exception handling, and
 * core utilities.
 *
 * The Foundation group provides the fundamental building blocks used by all
 * other modules in the socket library. Key components include:
 * - Arena (memory): Region-based memory allocation with fast
 * allocation/deallocation
 * - Except (exceptions): Structured exception handling with TRY/EXCEPT/FINALLY
 * - SocketUtil (utilities): Hash functions, error handling, metrics, and
 * logging
 * - SocketConfig (configuration): Global configuration management
 *
 * @see core_io for socket primitives built on foundation modules.
 * @see Arena_T for memory management
 * @see Except_T for exception handling
 * @{
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
 */

#include "core/Except.h"

#define T Arena_T
typedef struct T *T;

/* Arena exception types */
extern const Except_T Arena_Failed;

/**
 * @brief Create a new memory arena.
 * @ingroup foundation
 * @return New arena instance, or NULL on allocation failure.
 * @throws Arena_Failed if malloc fails or mutex initialization fails.
 * @threadsafe Yes
 * @see Arena_dispose() for cleanup.
 * @see ALLOC() macro for convenience.
 */
extern T Arena_new (void);

/**
 * @brief Dispose of an arena and all its allocations.
 * @ingroup foundation
 * @param ap Pointer to arena pointer (will be set to NULL).
 * @threadsafe Yes
 * @see Arena_new() for creation.
 * @see Arena_clear() for selective cleanup.
 */
extern void Arena_dispose (T *ap);

/**
 * @brief Allocate memory from arena.
 * @ingroup foundation
 * @param arena Arena to allocate from.
 * @param nbytes Number of bytes to allocate.
 * @param file Source file (for debugging).
 * @param line Source line (for debugging).
 * @return Pointer to allocated memory, or NULL on failure.
 * @throws Arena_Failed if allocation fails.
 * @threadsafe Yes
 * @note Memory is aligned appropriately for any data type.
 * @see ALLOC() macro for convenience.
 * @see Arena_calloc() for zero-initialized allocation.
 */
extern void *Arena_alloc (T arena, size_t nbytes, const char *file, int line);

/**
 * @brief Allocate and zero-initialize memory from arena.
 * @ingroup foundation
 * @param arena Arena to allocate from.
 * @param count Number of elements.
 * @param nbytes Size of each element.
 * @param file Source file (for debugging).
 * @param line Source line (for debugging).
 * @return Pointer to zeroed memory, or NULL on failure.
 * @throws Arena_Failed if allocation fails.
 * @threadsafe Yes
 * @see CALLOC() macro for convenience.
 * @see Arena_alloc() for non-zeroed allocation.
 */
extern void *Arena_calloc (T arena, size_t count, size_t nbytes,
                           const char *file, int line);

/**
 * @brief Clear all allocations in arena but keep arena active.
 * @ingroup foundation
 * @param arena Arena to clear.
 * @threadsafe Yes
 * @see Arena_dispose() for full cleanup.
 * @see Arena_new() for creation.
 */
extern void Arena_clear (T arena);

/* Allocation macros - automatically pass file/line info */
#define ALLOC(arena, nbytes)                                                  \
  (Arena_alloc ((arena), (nbytes), __FILE__, __LINE__))
#define CALLOC(arena, count, nbytes)                                          \
  (Arena_calloc ((arena), (count), (nbytes), __FILE__, __LINE__))

#undef T

/** @} */ /* end of foundation group */

#endif

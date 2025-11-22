#ifndef ARENA_INCLUDED
#define ARENA_INCLUDED

#include <stddef.h>

/**
 * Arena Memory Allocator
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
 * Thread Safety:
 * - All operations fully thread-safe with per-arena and global mutex
 * protection
 * - Multiple threads can safely allocate from the same arena concurrently
 * - Each arena has its own mutex protecting allocation state (avail, limit,
 * prev)
 * - Global free chunk cache protected by separate mutex
 * - Safe to use same arena from multiple threads or one arena per thread
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
extern Except_T Arena_Failed;

/**
 * Arena_new - Create a new memory arena
 * Returns: New arena instance, or NULL on allocation failure
 * Note: Returns NULL if malloc fails or mutex initialization fails
 * Thread-safe: Yes
 */
extern T Arena_new (void);

/**
 * Arena_dispose - Dispose of an arena and all its allocations
 * @ap: Pointer to arena pointer (will be set to NULL)
 * Frees all memory allocated from this arena.
 * Thread-safe: Yes
 */
extern void Arena_dispose (T *ap);

/**
 * Arena_alloc - Allocate memory from arena
 * @arena: Arena to allocate from
 * @nbytes: Number of bytes to allocate
 * @file: Source file (for debugging)
 * @line: Source line (for debugging)
 * Returns: Pointer to allocated memory, or NULL on failure
 * Thread-safe: Yes
 * Note: Memory is aligned appropriately for any data type
 */
extern void *Arena_alloc (T arena, size_t nbytes, const char *file, int line);

/**
 * Arena_calloc - Allocate and zero memory from arena
 * @arena: Arena to allocate from
 * @count: Number of elements
 * @nbytes: Size of each element
 * @file: Source file (for debugging)
 * @line: Source line (for debugging)
 * Returns: Pointer to zeroed memory, or NULL on failure
 * Thread-safe: Yes
 */
extern void *Arena_calloc (T arena, size_t count, size_t nbytes,
                           const char *file, int line);

/**
 * Arena_clear - Clear all allocations in arena but keep arena active
 * @arena: Arena to clear
 * Frees all memory allocated from this arena but keeps the arena
 * itself active for future allocations.
 * Thread-safe: Yes
 */
extern void Arena_clear (T arena);

/* Allocation macros - automatically pass file/line info */
#define ALLOC(arena, nbytes)                                                  \
  (Arena_alloc ((arena), (nbytes), __FILE__, __LINE__))
#define CALLOC(arena, count, nbytes)                                          \
  (Arena_calloc ((arena), (count), (nbytes), __FILE__, __LINE__))

#undef T
#endif

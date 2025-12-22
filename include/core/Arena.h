/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @defgroup foundation Core Foundation Modules
 * @brief Base infrastructure for memory, exceptions, and utilities.
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
 * Arenas allocate from large chunks and free everything at once.
 *
 * Benefits:
 * - Fast allocation (no per-allocation overhead)
 * - No fragmentation within the arena
 * - Simple cleanup via dispose
 * - Thread-safe with per-arena mutex
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * void *ptr = ALLOC(arena, 100);
 * Arena_dispose(&arena);
 * @endcode
 */

#include "core/Except.h"

/**
 * @brief Opaque arena type.
 */
#define T Arena_T
typedef struct T *T;

/**
 * @brief Exception raised on arena allocation failure.
 */
extern const Except_T Arena_Failed;

/**
 * @brief Create a new memory arena.
 *
 * Returns: New arena instance
 * Raises: Arena_Failed on malloc or mutex init failure
 *
 * @threadsafe Yes
 */
extern T Arena_new (void);

/**
 * @brief Create a new unlocked memory arena for single-threaded use.
 *
 * Returns: New arena instance without mutex protection
 * Raises: Arena_Failed on malloc failure
 *
 * WARNING: Only use when arena is exclusively accessed by one thread
 * (e.g., thread-local storage). Using from multiple threads is undefined.
 *
 * @threadsafe No - arena must only be used by creating thread
 */
extern T Arena_new_unlocked (void);

/**
 * @brief Dispose arena and free all allocations.
 *
 * @param ap  Pointer to arena (set to NULL after)
 *
 * Safe to call on NULL. Recycles chunks to global pool.
 *
 * @threadsafe Yes
 */
extern void Arena_dispose (T *ap);

/**
 * @brief Allocate raw memory from arena.
 *
 * @param arena  Arena instance
 * @param nbytes Bytes to allocate
 * @param file   Source file for debug (__FILE__)
 * @param line   Source line for debug (__LINE__)
 *
 * Returns: Aligned pointer, NULL for 0 bytes
 * Raises: Arena_Failed on growth failure
 *
 * Memory is uninitialized. Use ALLOC() macro for automatic file/line.
 *
 * @threadsafe Yes
 * @complexity Amortized O(1)
 */
extern void *Arena_alloc (T arena, size_t nbytes, const char *file, int line);

/**
 * @brief Allocate zero-initialized memory from arena.
 *
 * @param arena  Arena instance
 * @param count  Number of elements
 * @param nbytes Bytes per element
 * @param file   Source file for debug
 * @param line   Source line for debug
 *
 * Returns: Zero-filled pointer, NULL if count or nbytes is 0
 * Raises: Arena_Failed on failure or size overflow
 *
 * Use CALLOC() macro for automatic file/line.
 *
 * @threadsafe Yes
 * @complexity O(1) alloc + O(n) zeroing
 */
extern void *Arena_calloc (T arena, size_t count, size_t nbytes,
                           const char *file, int line);

/**
 * @brief Reset arena for reuse without destroying it.
 *
 * @param arena  Arena to reset
 *
 * All previous allocations become invalid. Faster than dispose+new
 * for cyclic usage patterns.
 *
 * @threadsafe Yes
 * @complexity O(chunks)
 */
extern void Arena_clear (T arena);

/**
 * @brief Reset arena for reuse without global mutex contention.
 *
 * Unlike Arena_clear(), this keeps one chunk allocated and simply resets
 * the allocation pointer to the beginning. This avoids returning chunks
 * to the global free list (which requires global mutex), making it ideal
 * for high-performance scenarios with thread-local arenas.
 *
 * @param arena  Arena to reset
 *
 * @note Previous allocations become invalid.
 * @note Memory usage stays at one chunk (not freed until Arena_dispose).
 *
 * @threadsafe Yes
 * @complexity O(chunks) for first reset, O(1) for subsequent resets
 */
extern void Arena_reset (T arena);

/**
 * @brief Allocate with automatic source location tracking.
 */
#define ALLOC(arena, nbytes)                                                  \
  (Arena_alloc ((arena), (nbytes), __FILE__, __LINE__))

/**
 * @brief Zero-allocate with automatic source location tracking.
 */
#define CALLOC(arena, count, nbytes)                                          \
  (Arena_calloc ((arena), (count), (nbytes), __FILE__, __LINE__))

#undef T

/** @} */

#endif

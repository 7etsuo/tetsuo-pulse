/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * Arena.c - Arena memory allocator
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * An arena (also called a memory pool or region) is a memory management
 * technique where allocations are made from a large chunk of memory.
 * All allocations in an arena can be freed at once by disposing the arena.
 *
 * Features:
 * - Fast allocation (no per-allocation overhead)
 * - No memory fragmentation within the arena
 * - Simple cleanup - dispose entire arena at once
 * - Thread-safe chunk management with mutex protection
 *
 * Thread Safety:
 * - All operations fully thread-safe with per-arena and global mutex
 * protection
 * - Multiple threads can safely allocate from the same arena concurrently
 * - Each arena has its own mutex protecting allocation state
 * - Global free chunk cache protected by separate mutex
 */

#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketMetrics.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"

#define T Arena_T

/* ==================== Internal Structures ==================== */

/**
 * ChunkHeader - Header for memory chunks in the arena
 *
 * Each chunk stores a linked list pointer and allocation state.
 * chunk_size tracks actual usable size for proper reuse.
 */
struct ChunkHeader
{
  struct ChunkHeader *prev;
  char *avail;
  char *limit;
  size_t chunk_size;
};

/**
 * header - Union for proper memory alignment
 *
 * Ensures all allocations are aligned for any data type.
 */
union header
{
  struct ChunkHeader b;
  /* cppcheck-suppress unusedStructMember */
  union align a;
};

/**
 * Arena structure - Main arena instance
 *
 * Contains allocation state and per-arena mutex for thread safety.
 */
struct T
{
  struct ChunkHeader *prev;
  char *avail;
  char *limit;
  pthread_mutex_t mutex;
};

/* ==================== Chunk Helper Functions ==================== */

/**
 * chunk_total_size - Calculate total size of chunk including header
 * @chunk: Chunk header pointer
 *
 * Returns: Total bytes occupied by chunk (header + usable space)
 * Thread-safe: Yes (const, no side effects)
 */
static inline size_t
chunk_total_size (const struct ChunkHeader *chunk)
{
  return sizeof (union header) + chunk->chunk_size;
}

/**
 * chunk_limit - Calculate end pointer of chunk usable space
 * @chunk: Chunk header pointer
 *
 * Returns: Pointer to end of usable space in chunk
 * Thread-safe: Yes (const, no side effects)
 * Note: Assumes valid chunk with chunk_size set
 */
static inline char *
chunk_limit (const struct ChunkHeader *chunk)
{
  return (char *)chunk + chunk_total_size (chunk);
}

/**
 * arena_link_chunk - Link new chunk into arena's allocation chain
 * @arena: Arena to link chunk into
 * @ptr: Chunk header to link
 * @limit: End pointer of chunk usable space
 *
 * Saves current arena state into chunk header and updates arena to use
 * the new chunk. Used when adding cached or newly allocated chunks.
 * Thread-safe: Must be called with arena->mutex held
 */
static inline void
arena_link_chunk (T arena, struct ChunkHeader *ptr, char *limit)
{
  /* Save current arena state into chunk header */
  ptr->prev = arena->prev;
  ptr->avail = arena->avail;
  ptr->limit = arena->limit;

  /* Update arena to use new chunk */
  arena->avail = (char *)((union header *)ptr + 1);
  arena->limit = limit;
  arena->prev = ptr;
}

/* ==================== Global State ==================== */

/* Arena exception definition */
const Except_T Arena_Failed = { &Arena_Failed, "Arena operation failed" };

/* Thread-local exception using centralized infrastructure */
SOCKET_DECLARE_MODULE_EXCEPTION (Arena);

/* Global free chunk cache for efficient memory reuse */
static struct ChunkHeader *freechunks = NULL;
static int nfree = 0;
static pthread_mutex_t arena_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ==================== Global Memory Limit Tracking ==================== */

/* Atomic counters for global memory tracking */
static _Atomic size_t global_memory_used = 0;
static _Atomic size_t global_memory_limit = 0; /* 0 = unlimited */

void
SocketConfig_set_max_memory (size_t max_bytes)
{
  atomic_store_explicit (&global_memory_limit, max_bytes,
                         memory_order_release);
}

size_t
SocketConfig_get_max_memory (void)
{
  return atomic_load_explicit (&global_memory_limit, memory_order_acquire);
}

size_t
SocketConfig_get_memory_used (void)
{
  return atomic_load_explicit (&global_memory_used, memory_order_acquire);
}

/* Forward declaration for helper used in global_memory_try_alloc */
static int check_alloc_allowed (size_t current, size_t nbytes, size_t limit);

/**
 * global_memory_try_alloc - Try to allocate bytes from global limit
 * @nbytes: Number of bytes to allocate
 *
 * Returns: 1 if allocation allowed, 0 if would exceed limit
 * Thread-safe: Yes (atomic compare-exchange loop for strict enforcement)
 *
 * Security: Uses atomic CAS loop to prevent TOCTOU race conditions where
 * multiple threads could simultaneously pass the limit check and exceed
 * the configured memory limit.
 */
/**
 * global_memory_try_unlimited - Allocate under unlimited policy
 * @nbytes: Bytes to allocate
 *
 * Adds to global used counter using relaxed memory order (no limit check).
 * Returns: Always 1 (success)
 * Thread-safe: Yes (atomic fetch_add relaxed)
 */
static int
global_memory_try_unlimited (size_t nbytes)
{
  atomic_fetch_add_explicit (&global_memory_used, nbytes,
                             memory_order_relaxed);
  return 1;
}

/**
 * global_memory_try_limited - Allocate under limited policy with CAS
 * @limit: Current memory limit
 * @nbytes: Bytes to allocate
 *
 * Uses atomic CAS loop to enforce strict limit without TOCTOU races.
 * Returns: 1 if allocated successfully, 0 if limit exceeded
 * Thread-safe: Yes (atomic CAS acq_rel)
 */
static int
global_memory_try_limited (size_t limit, size_t nbytes)
{
  size_t current
      = atomic_load_explicit (&global_memory_used, memory_order_acquire);
  size_t desired;

  do
    {
      if (!check_alloc_allowed (current, nbytes, limit))
        return 0;

      desired = current + nbytes;
    }
  while (!atomic_compare_exchange_weak_explicit (&global_memory_used, &current,
                                                 desired, memory_order_acq_rel,
                                                 memory_order_acquire));

  return 1;
}

static int
global_memory_try_alloc (size_t nbytes)
{
  size_t limit
      = atomic_load_explicit (&global_memory_limit, memory_order_acquire);

  /* No limit set - always allow */
  if (limit == 0)
    return global_memory_try_unlimited (nbytes);

  return global_memory_try_limited (limit, nbytes);
}

/**
 * global_memory_release - Release bytes back to global pool
 * @nbytes: Number of bytes to release
 *
 * Thread-safe: Yes (atomic subtraction)
 */
static void
global_memory_release (size_t nbytes)
{
  atomic_fetch_sub_explicit (&global_memory_used, nbytes,
                             memory_order_relaxed);
}

/* ==================== Global Memory Helper Functions ==================== */

/**
 * check_alloc_allowed - Check if allocation is allowed under limits
 * @current: Current used memory
 * @nbytes: Bytes to allocate
 * @limit: Global memory limit (0 = unlimited)
 *
 * Performs overflow and limit checks.
 *
 * Returns: 1 if allowed, 0 otherwise
 * Thread-safe: Yes (pure function)
 */
static int
check_alloc_allowed (size_t current, size_t nbytes, size_t limit)
{
  size_t desired;
  if (!SocketSecurity_check_add (current, nbytes, &desired))
    return 0;

  if (limit > 0 && desired > limit)
    return 0;

  return 1;
}

/* ==================== Validation Macros ==================== */

#define ARENA_VALID_PTR_ARITH(ptr, offset, max)                               \
  (((uintptr_t)(ptr) <= UINTPTR_MAX - (offset))                               \
   && ((uintptr_t)(ptr) + (offset) <= (uintptr_t)(max)))

/* ==================== Allocation Helper Functions ==================== */

/**
 * validate_chunk_size - Validate chunk size and calculate total
 * @chunk_size: Usable chunk size (excluding header)
 * @total_out: Output total size including header
 *
 * Returns: ARENA_SUCCESS if valid, ARENA_FAILURE otherwise
 * Thread-safe: Yes
 */
static int
validate_chunk_size (size_t chunk_size, size_t *total_out)
{
  size_t total;

  if (!SocketSecurity_check_add (sizeof (union header), chunk_size, &total))
    {
      SOCKET_ERROR_MSG (
          "Chunk size overflow: sizeof(header)=%zu + chunk_size=%zu",
          sizeof (union header), chunk_size);
      return ARENA_FAILURE;
    }

  if (!SocketSecurity_check_size (total))
    {
      SOCKET_ERROR_MSG ("Chunk size exceeds maximum: %zu (limit=%zu)", total,
                        SocketSecurity_get_max_allocation ());
      return ARENA_FAILURE;
    }

  *total_out = total;
  return ARENA_SUCCESS;
}

/**
 * acquire_global_memory - Check and acquire from global memory limit
 * @total: Total bytes to allocate
 *
 * Attempts to reserve memory from global limit tracker.
 * Updates metrics and sets error on failure.
 *
 * Returns: ARENA_SUCCESS if acquired, ARENA_FAILURE otherwise
 * Thread-safe: Yes (uses atomic operations)
 */
static int
acquire_global_memory (size_t total)
{
  if (!global_memory_try_alloc (total))
    {
      SocketMetrics_counter_inc (SOCKET_CTR_LIMIT_MEMORY_EXCEEDED);
      SOCKET_ERROR_MSG ("Global memory limit exceeded: requested %zu bytes, "
                        "limit %zu, used %zu",
                        total, SocketConfig_get_max_memory (),
                        SocketConfig_get_memory_used ());
      return ARENA_FAILURE;
    }

  return ARENA_SUCCESS;
}

/**
 * allocate_raw_chunk - Allocate raw memory for chunk and validate
 * @total: Total size including header
 *
 * Allocates memory using malloc and performs pointer arithmetic validation.
 * Releases global memory reservation and frees on validation failure.
 *
 * Returns: Validated chunk pointer, or NULL on failure
 * Thread-safe: Yes
 */
static struct ChunkHeader *
allocate_raw_chunk (size_t total)
{
  struct ChunkHeader *ptr = malloc (total);
  if (ptr == NULL)
    {
      global_memory_release (total);
      SOCKET_ERROR_MSG ("Cannot allocate chunk: %zu bytes", total);
      return NULL;
    }

  /* Validate pointer arithmetic won't overflow */
  if (!ARENA_VALID_PTR_ARITH (ptr, total, (void *)UINTPTR_MAX))
    {
      free (ptr);
      global_memory_release (total);
      SOCKET_ERROR_MSG ("Invalid pointer arithmetic for chunk");
      return NULL;
    }

  return ptr;
}

/* ==================== Chunk Cache Operations ==================== */



/**
 * chunk_cache_return - Return chunk to free cache or free it
 * @chunk: Chunk to return
 *
 * Attempts to add chunk to global free cache if under limit.
 * Otherwise frees the chunk and releases global memory reservation.
 * Thread-safe: Yes (uses global arena_mutex)
 */
static void
chunk_cache_return (struct ChunkHeader *chunk)
{
  int added = 0;

  assert (chunk);

  pthread_mutex_lock (&arena_mutex);

  if (nfree < ARENA_MAX_FREE_CHUNKS)
    {
      chunk->prev = freechunks;
      freechunks = chunk;
      nfree++;
      added = 1;
    }

  pthread_mutex_unlock (&arena_mutex);

  if (!added)
    {
      size_t total_bytes = chunk_total_size (chunk);
      free (chunk);
      global_memory_release (total_bytes);
    }
}

/* ==================== Alignment Calculation ==================== */

/**
 * arena_validate_nbytes - Validate input bytes for allocation
 * @nbytes: Bytes to validate
 *
 * Returns: 1 if valid (non-zero and <= max), 0 otherwise
 * Thread-safe: Yes (pure function)
 */


/**
 * arena_align_size - Compute ceiling-aligned allocation size
 * @nbytes: Number of bytes to align
 *
 * Precondition: nbytes validated as non-zero and <= ARENA_MAX_ALLOC_SIZE
 * Returns: Aligned size, or 0 on arithmetic overflow
 * Thread-safe: Yes (pure function)
 */
static size_t
arena_align_size (size_t nbytes)
{
  size_t align = ARENA_ALIGNMENT_SIZE;
  size_t sum;
  size_t units;
  size_t final_size;

  if (!SocketSecurity_check_add (nbytes, align - 1, &sum))
    return 0;

  units = sum / align;

  if (!SocketSecurity_check_multiply (units, align, &final_size))
    return 0;

  return final_size;
}

static size_t
arena_calculate_aligned_size (size_t nbytes)
{
  size_t final_size;

  if (!SocketSecurity_check_size (nbytes))
    return 0;

  final_size = arena_align_size (nbytes);

  /* Defensive check for rounding overflow (possible if align large relative to
   * max) */
  if (!SocketSecurity_check_size (final_size))
    return 0;

  return final_size;
}

/* ==================== Chunk Linking ==================== */



/* ==================== Chunk Allocation ==================== */

/**
 * arena_allocate_new_chunk - Allocate a fresh chunk from system memory
 * @chunk_size: Usable size (excluding header)
 * @ptr_out: Output pointer for chunk header
 * @limit_out: Output pointer for chunk limit
 *
 * Returns: ARENA_SUCCESS on success, ARENA_FAILURE on failure
 * Thread-safe: Yes
 */
static int
arena_allocate_new_chunk (size_t chunk_size, struct ChunkHeader **ptr_out,
                          char **limit_out)
{
  size_t total;
  struct ChunkHeader *ptr;

  if (validate_chunk_size (chunk_size, &total) != ARENA_SUCCESS)
    return ARENA_FAILURE;

  if (acquire_global_memory (total) != ARENA_SUCCESS)
    return ARENA_FAILURE;

  ptr = allocate_raw_chunk (total);
  if (ptr == NULL)
    return ARENA_FAILURE;

  ptr->chunk_size = chunk_size;
  *ptr_out = ptr;
  *limit_out = chunk_limit (ptr);

  return ARENA_SUCCESS;
}

/**
 * arena_get_chunk - Obtain chunk for allocation (reuse or allocate)
 * @arena: Arena needing chunk
 * @min_size: Minimum chunk size required
 *
 * Tries free cache first, then allocates fresh chunk if needed.
 * Returns: ARENA_SUCCESS if chunk obtained, ARENA_FAILURE otherwise
 * Thread-safe: No (must hold arena->mutex, uses global arena_mutex internally)
 */
static int
arena_get_chunk (T arena, size_t min_size)
{
  struct ChunkHeader *ptr;
  char *limit;
  size_t chunk_size;

  /* Try to reuse a cached chunk */
  if (chunk_cache_get (&ptr, &limit) == ARENA_CHUNK_REUSED)
    {
      arena_link_chunk (arena, ptr, limit);
      return ARENA_SUCCESS;
    }

  /* Allocate a new chunk */
  chunk_size = (ARENA_CHUNK_SIZE < min_size) ? min_size : ARENA_CHUNK_SIZE;

  if (arena_allocate_new_chunk (chunk_size, &ptr, &limit) != ARENA_SUCCESS)
    return ARENA_FAILURE;

  arena_link_chunk (arena, ptr, limit);
  return ARENA_SUCCESS;
}

/* ==================== Chunk Cleanup ==================== */

/**
 * arena_release_all_chunks - Release all chunks from arena
 * @arena: Arena to clear
 *
 * Thread-safe: No (must be called with arena->mutex held)
 */
static void
arena_release_all_chunks (T arena)
{
  while (arena->prev != NULL)
    {
      struct ChunkHeader *chunk = arena->prev;
      struct ChunkHeader saved = *chunk;

      arena->prev = saved.prev;
      arena->avail = saved.avail;
      arena->limit = saved.limit;

      chunk_cache_return (chunk);
    }

  /* Verify arena is now empty */
  assert (arena->prev == NULL);
  assert (arena->avail == NULL);
  assert (arena->limit == NULL);
}

/* ==================== Space Allocation ==================== */












/* ==================== Public API ==================== */

/**
 * Arena_new - Create a new arena instance
 *
 * Returns: New arena instance
 * Raises: Arena_Failed if allocation or mutex initialization fails
 * Thread-safe: Yes
 *
 * Creates a new arena allocator with thread-safe allocation support.
 * Memory is managed in chunks; all freed when arena is disposed.
 */
T
Arena_new (void)
{
  T arena;

  arena = malloc (sizeof (*arena));
  if (arena == NULL)
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      ARENA_ENOMEM ": Cannot allocate arena structure");

  if (pthread_mutex_init (&arena->mutex, NULL) != 0)
    {
      free (arena);
      SOCKET_RAISE_MSG (Arena, Arena_Failed,
                        "Failed to initialize arena mutex");
    }

  arena->prev = NULL;
  arena->avail = NULL;
  arena->limit = NULL;

  return arena;
}

/**
 * Arena_dispose - Dispose of an arena and all its allocations
 * @ap: Pointer to arena pointer (will be set to NULL)
 *
 * Frees all memory allocated from this arena including the arena structure
 * itself. After this call, the arena pointer is invalid.
 *
 * Raises: None (void function)
 * Thread-safe: Yes (but arena should not be used concurrently during disposal)
 * Pre-conditions: ap != NULL, *ap != NULL (handles NULL gracefully)
 */
void
Arena_dispose (T *ap)
{
  if (!ap || !*ap)
    return;

  Arena_clear (*ap);
  pthread_mutex_destroy (&(*ap)->mutex);
  free (*ap);
  *ap = NULL;
}

/**
 * Arena_alloc - Allocate memory from arena
 * @arena: Arena to allocate from
 * @nbytes: Number of bytes to allocate
 * @file: Source file name (for debugging)
 * @line: Source line number (for debugging)
 *
 * Returns: Pointer to allocated memory
 * Raises: Arena_Failed if allocation fails due to insufficient space or
 * overflow Thread-safe: Yes Pre-conditions: arena != NULL, nbytes > 0
 *
 * Allocates memory from the arena with proper alignment and overflow
 * protection. Memory remains valid until the arena is cleared or disposed.
 */
void *
Arena_alloc (T arena, size_t nbytes, const char *file, int line)
{
  (void)file; (void)line;
  if (arena == NULL)
    SOCKET_RAISE_MSG (Arena, Arena_Failed, "NULL arena pointer in %s", "Arena_alloc");

  if (nbytes == 0)
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      "Zero size allocation in Arena_alloc");

  size_t aligned_size = arena_calculate_aligned_size (nbytes);
  if (aligned_size == 0)
    SOCKET_RAISE_MSG (
        Arena, Arena_Failed,
        "Invalid allocation size: %zu bytes (overflow or exceeds limit)",
        nbytes);

  pthread_mutex_lock (&arena->mutex);
  while (arena->avail == NULL || arena->limit == NULL
         || (size_t)(arena->limit - arena->avail) < aligned_size)
    {
      /* Try to reuse a cached chunk */
      struct ChunkHeader *ptr;
      char *limit;
      size_t chunk_size;

      /* Inline chunk_cache_get */
      int cache_result = ARENA_CHUNK_NOT_REUSED;
      pthread_mutex_lock (&arena_mutex);

      if ((ptr = freechunks) != NULL)
        {
          freechunks = freechunks->prev;
          nfree--;
          limit = chunk_limit (ptr);
          cache_result = ARENA_CHUNK_REUSED;
        }

      pthread_mutex_unlock (&arena_mutex);

      if (cache_result == ARENA_CHUNK_REUSED)
        {
          arena_link_chunk (arena, ptr, limit);
        }
      else
        {
          /* Allocate a new chunk */
          chunk_size = (ARENA_CHUNK_SIZE < aligned_size) ? aligned_size : ARENA_CHUNK_SIZE;

          if (arena_allocate_new_chunk (chunk_size, &ptr, &limit) != ARENA_SUCCESS)
            SOCKET_RAISE_MSG (Arena, Arena_Failed,
                              "Failed to allocate chunk for %zu bytes (out of memory)",
                              aligned_size);

          arena_link_chunk (arena, ptr, limit);
        }
    }
  void *result = arena->avail;
  arena->avail += aligned_size;
  pthread_mutex_unlock (&arena->mutex);

  return result;
}

/**
 * Arena_calloc - Allocate and zero memory from arena
 * @arena: Arena to allocate from
 * @count: Number of elements
 * @nbytes: Size of each element
 * @file: Source file (for debugging)
 * @line: Source line (for debugging)
 *
 * Returns: Pointer to zeroed memory
 * Raises: Arena_Failed if allocation fails or overflow occurs
 * Thread-safe: Yes
 * Pre-conditions: arena != NULL, count > 0, nbytes > 0
 *
 * Allocates count * nbytes bytes from the arena and initializes to zero.
 * Uses Arena_alloc internally with overflow protection for multiplication.
 */


void *
Arena_calloc (T arena, size_t count, size_t nbytes, const char *file, int line)
{
  (void)file; (void)line;
  if (arena == NULL)
    SOCKET_RAISE_MSG (Arena, Arena_Failed, "NULL arena pointer in %s", "Arena_calloc");
  if (count == 0 || nbytes == 0)
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      "Invalid count (%zu) or nbytes (%zu) in %s", count,
                      nbytes, "Arena_calloc");

  size_t total;
  if (!SocketSecurity_check_multiply (count, nbytes, &total))
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      "calloc overflow: count=%zu, nbytes=%zu in %s", count,
                      nbytes, "Arena_calloc");

  if (!SocketSecurity_check_size (total))
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      "calloc size exceeds maximum: %zu (limit=%zu) in %s",
                      total, SocketSecurity_get_max_allocation (), "Arena_calloc");

  /* Allocate via Arena_alloc (reuses validation and alignment logic) */
  void *ptr = Arena_alloc (arena, count * nbytes, file, line);
  memset (ptr, 0, count * nbytes);

  return ptr;
}

/**
 * Arena_clear - Clear all allocations from arena
 * @arena: Arena to clear
 *
 * Releases all memory chunks back to the free pool without freeing the arena
 * structure. The arena can be reused for new allocations after clearing.
 *
 * Raises: None (void function)
 * Thread-safe: Yes
 * Pre-conditions: arena != NULL (handles NULL gracefully)
 */
void
Arena_clear (T arena)
{
  if (arena == NULL)
    return;

  pthread_mutex_lock (&arena->mutex);
  arena_release_all_chunks (arena);
  pthread_mutex_unlock (&arena->mutex);
}

#undef T

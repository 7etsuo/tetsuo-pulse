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
 * - All operations fully thread-safe with per-arena and global mutex protection
 * - Multiple threads can safely allocate from the same arena concurrently
 * - Each arena has its own mutex protecting allocation state
 * - Global free chunk cache protected by separate mutex
 */

#include <assert.h>
#include <errno.h>
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
  atomic_store_explicit (&global_memory_limit, max_bytes, memory_order_release);
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
static int
global_memory_try_alloc (size_t nbytes)
{
  size_t limit
      = atomic_load_explicit (&global_memory_limit, memory_order_acquire);

  /* No limit set - always allow */
  if (limit == 0)
    {
      atomic_fetch_add_explicit (&global_memory_used, nbytes,
                                 memory_order_relaxed);
      return 1;
    }

  /* Atomic compare-exchange loop for strict limit enforcement */
  size_t current
      = atomic_load_explicit (&global_memory_used, memory_order_acquire);
  size_t desired;

  do
    {
      /* Check for overflow in addition */
      if (current > SIZE_MAX - nbytes)
        return 0;

      /* Check if allocation would exceed limit */
      if (current + nbytes > limit)
        return 0;

      desired = current + nbytes;
    }
  while (!atomic_compare_exchange_weak_explicit (
      &global_memory_used, &current, desired, memory_order_acq_rel,
      memory_order_acquire));

  return 1;
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
  atomic_fetch_sub_explicit (&global_memory_used, nbytes, memory_order_relaxed);
}

/* ==================== Validation Macros ==================== */

#define ARENA_CHECK_OVERFLOW_ADD(a, b) ((a) > SIZE_MAX - (b))
#define ARENA_CHECK_OVERFLOW_MUL(a, b) ((a) != 0 && (b) > SIZE_MAX / (a))
#define ARENA_VALID_PTR_ARITH(ptr, offset, max)                               \
  (((uintptr_t) (ptr) <= UINTPTR_MAX - (offset))                              \
   && ((uintptr_t) (ptr) + (offset) <= (uintptr_t) (max)))

/* ==================== Chunk Cache Operations ==================== */

/**
 * chunk_cache_get - Get chunk from free cache (thread-safe)
 * @ptr_out: Output pointer for chunk header
 * @limit_out: Output pointer for chunk limit
 *
 * Returns: ARENA_CHUNK_REUSED if found, ARENA_CHUNK_NOT_REUSED otherwise
 * Thread-safe: Yes (uses global arena_mutex)
 */
static int
chunk_cache_get (struct ChunkHeader **ptr_out, char **limit_out)
{
  struct ChunkHeader *ptr;
  int result = ARENA_CHUNK_NOT_REUSED;

  pthread_mutex_lock (&arena_mutex);

  if ((ptr = freechunks) != NULL)
    {
      freechunks = freechunks->prev;
      nfree--;
      *ptr_out = ptr;
      *limit_out = (char *)ptr + sizeof (union header) + ptr->chunk_size;
      result = ARENA_CHUNK_REUSED;
    }

  pthread_mutex_unlock (&arena_mutex);
  return result;
}

/**
 * chunk_cache_return - Return chunk to free cache or free it
 * @chunk: Chunk to return
 *
 * Thread-safe: Yes (uses global arena_mutex)
 */
static void
chunk_cache_return (struct ChunkHeader *chunk)
{
  size_t chunk_total_size;
  int added = 0;

  assert (chunk);

  chunk_total_size = sizeof (union header) + chunk->chunk_size;

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
      free (chunk);
      global_memory_release (chunk_total_size);
    }
}

/* ==================== Alignment Calculation ==================== */

/**
 * arena_calculate_aligned_size - Calculate properly aligned allocation size
 * @nbytes: Requested allocation size
 *
 * Returns: Aligned size, or 0 on overflow/invalid size
 * Thread-safe: Yes
 *
 * Performs all alignment and overflow checks in a single function:
 * 1. Validates nbytes is positive and within limits
 * 2. Calculates aligned size with overflow protection
 * 3. Validates final size is within limits
 */
static size_t
arena_calculate_aligned_size (size_t nbytes)
{
  size_t alignment;
  size_t sum;
  size_t aligned_units;
  size_t final_size;

  /* Validate input size */
  if (nbytes == 0 || nbytes > ARENA_MAX_ALLOC_SIZE)
    return 0;

  /* Get alignment (guaranteed non-zero) */
  alignment = ARENA_ALIGNMENT_SIZE;
  if (alignment == 0)
    alignment = 1;

  /* Check for overflow: nbytes + (alignment - 1) */
  if (ARENA_CHECK_OVERFLOW_ADD (nbytes, alignment - 1))
    return 0;

  sum = nbytes + alignment - 1;
  aligned_units = sum / alignment;

  /* Check for overflow: aligned_units * alignment */
  if (ARENA_CHECK_OVERFLOW_MUL (aligned_units, alignment))
    return 0;

  final_size = aligned_units * alignment;

  /* Final validation */
  if (final_size == 0 || final_size > ARENA_MAX_ALLOC_SIZE)
    return 0;

  return final_size;
}

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
  struct ChunkHeader *ptr;
  size_t total_size;

  /* Calculate total size including header */
  if (ARENA_CHECK_OVERFLOW_ADD (sizeof (union header), chunk_size))
    {
      SOCKET_ERROR_MSG ("Chunk size overflow: %zu", chunk_size);
      return ARENA_FAILURE;
    }

  total_size = sizeof (union header) + chunk_size;

  if (total_size > ARENA_MAX_ALLOC_SIZE)
    {
      SOCKET_ERROR_MSG ("Chunk size exceeds maximum: %zu", total_size);
      return ARENA_FAILURE;
    }

  /* Check global memory limit before allocation */
  if (!global_memory_try_alloc (total_size))
    {
      SocketMetrics_counter_inc (SOCKET_CTR_LIMIT_MEMORY_EXCEEDED);
      SOCKET_ERROR_MSG ("Global memory limit exceeded: requested %zu bytes, "
                        "limit %zu, used %zu",
                        total_size, SocketConfig_get_max_memory (),
                        SocketConfig_get_memory_used ());
      return ARENA_FAILURE;
    }

  ptr = malloc (total_size);
  if (ptr == NULL)
    {
      global_memory_release (total_size);
      SOCKET_ERROR_MSG ("Cannot allocate chunk: %zu bytes", total_size);
      return ARENA_FAILURE;
    }

  /* Validate pointer arithmetic won't overflow */
  if (!ARENA_VALID_PTR_ARITH (ptr, total_size, (void *)UINTPTR_MAX))
    {
      free (ptr);
      global_memory_release (total_size);
      SOCKET_ERROR_MSG ("Invalid pointer arithmetic for chunk");
      return ARENA_FAILURE;
    }

  ptr->chunk_size = chunk_size;
  *ptr_out = ptr;
  *limit_out = (char *)ptr + total_size;

  return ARENA_SUCCESS;
}

/**
 * arena_get_chunk - Get a chunk (from cache or allocate new)
 * @arena: Arena to get chunk for
 * @min_size: Minimum size needed
 *
 * Returns: ARENA_SUCCESS on success, ARENA_FAILURE on failure
 * Thread-safe: No (must be called with arena->mutex held)
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
      /* Link reused chunk into arena */
      ptr->prev = arena->prev;
      ptr->avail = arena->avail;
      ptr->limit = arena->limit;

      arena->avail = (char *)((union header *)ptr + 1);
      arena->limit = limit;
      arena->prev = ptr;

      return ARENA_SUCCESS;
    }

  /* Allocate a new chunk */
  chunk_size = (ARENA_CHUNK_SIZE < min_size) ? min_size : ARENA_CHUNK_SIZE;

  if (arena_allocate_new_chunk (chunk_size, &ptr, &limit) != ARENA_SUCCESS)
    return ARENA_FAILURE;

  /* Link new chunk into arena */
  ptr->prev = arena->prev;
  ptr->avail = arena->avail;
  ptr->limit = arena->limit;

  arena->avail = (char *)((union header *)ptr + 1);
  arena->limit = limit;
  arena->prev = ptr;

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
      SOCKET_RAISE_MSG (Arena, Arena_Failed, "Failed to initialize arena mutex");
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
 * Raises: Arena_Failed if allocation fails due to insufficient space or overflow
 * Thread-safe: Yes
 * Pre-conditions: arena != NULL, nbytes > 0
 *
 * Allocates memory from the arena with proper alignment and overflow
 * protection. Memory remains valid until the arena is cleared or disposed.
 */
void *
Arena_alloc (T arena, size_t nbytes, const char *file, int line)
{
  size_t aligned_size;
  void *result;

  /* Suppress unused parameter warnings */
  (void)file;
  (void)line;

  /* Validate input parameters */
  if (arena == NULL)
    SOCKET_RAISE_MSG (Arena, Arena_Failed, "NULL arena pointer in Arena_alloc");

  if (nbytes == 0)
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      "Zero size allocation in Arena_alloc");

  /* Calculate aligned size */
  aligned_size = arena_calculate_aligned_size (nbytes);
  if (aligned_size == 0)
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      "Invalid allocation size: %zu bytes (overflow)", nbytes);

  /* Allocate under mutex protection */
  pthread_mutex_lock (&arena->mutex);

  /* Ensure we have enough space */
  while (arena->avail == NULL || arena->limit == NULL
         || (size_t) (arena->limit - arena->avail) < aligned_size)
    {
      if (arena_get_chunk (arena, aligned_size) != ARENA_SUCCESS)
        {
          pthread_mutex_unlock (&arena->mutex);
          SOCKET_RAISE_MSG (Arena, Arena_Failed,
                            "Failed to allocate chunk for %zu bytes", nbytes);
        }
    }

  result = arena->avail;
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
  void *ptr;
  size_t total;

  /* Validate arena parameter */
  if (arena == NULL)
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      "NULL arena pointer in Arena_calloc");

  /* Validate count and nbytes parameters */
  if (count == 0 || nbytes == 0)
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      "Invalid count (%zu) or nbytes (%zu) in Arena_calloc",
                      count, nbytes);

  /* Check for multiplication overflow */
  if (ARENA_CHECK_OVERFLOW_MUL (count, nbytes))
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      "calloc overflow: count=%zu, nbytes=%zu", count, nbytes);

  total = count * nbytes;

  /* Validate total size */
  if (total > ARENA_MAX_ALLOC_SIZE)
    SOCKET_RAISE_MSG (Arena, Arena_Failed, "calloc size exceeds maximum: %zu",
                      total);

  /* Allocate and zero memory */
  ptr = Arena_alloc (arena, total, file, line);
  memset (ptr, 0, total);

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

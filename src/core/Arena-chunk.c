/**
 * Arena-chunk.c - Private chunk management for Arena allocator
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Handles chunk allocation, reuse, linking, and cleanup for the arena
 * memory allocator. Maintains a global free chunk cache with thread-safe
 * access for efficient memory reuse.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena-private.h"
#include "core/Except.h"
#include "core/SocketError.h"

/* Global free chunk cache */
struct ChunkHeader *freechunks = NULL;
int nfree = 0;
pthread_mutex_t arena_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ==================== Helper Functions ==================== */

/**
 * chunk_calculate_limit - Calculate chunk limit from header and size
 * @ptr: Chunk header pointer
 * @total_size: Total chunk size including header
 * Returns: Pointer to end of chunk
 * Thread-safe: Yes
 */
static char *
chunk_calculate_limit (struct ChunkHeader *ptr, size_t total_size)
{
  return (char *)ptr + total_size;
}

/**
 * chunk_get_from_cache_unlocked - Get chunk from cache (caller holds mutex)
 * @ptr_out: Output pointer for chunk header
 * @limit_out: Output pointer for chunk limit
 * Returns: ARENA_CHUNK_REUSED if found, ARENA_CHUNK_NOT_REUSED otherwise
 * Thread-safe: No (caller must hold arena_mutex)
 */
static int
chunk_get_from_cache_unlocked (struct ChunkHeader **ptr_out, char **limit_out)
{
  struct ChunkHeader *ptr;
  size_t total_size;

  if ((ptr = freechunks) == NULL)
    return ARENA_CHUNK_NOT_REUSED;

  freechunks = freechunks->prev;
  nfree--;
  *ptr_out = ptr;

  total_size = sizeof (union header) + ptr->chunk_size;
  *limit_out = chunk_calculate_limit (ptr, total_size);

  return ARENA_CHUNK_REUSED;
}

/**
 * chunk_add_to_cache_unlocked - Add chunk to cache (caller holds mutex)
 * @chunk: Chunk to add
 * Returns: 1 if added to cache, 0 if cache full
 * Thread-safe: No (caller must hold arena_mutex)
 */
static int
chunk_add_to_cache_unlocked (struct ChunkHeader *chunk)
{
  if (nfree >= ARENA_MAX_FREE_CHUNKS)
    return 0;

  chunk->prev = freechunks;
  freechunks = chunk;
  nfree++;
  return 1;
}

/**
 * chunk_validate_pointer - Validate pointer arithmetic for chunk
 * @ptr: Allocated chunk pointer
 * @total_size: Total size of allocation
 * Returns: 1 if valid, 0 if overflow would occur
 * Thread-safe: Yes
 */
static int
chunk_validate_pointer (struct ChunkHeader *ptr, size_t total_size)
{
  return ARENA_VALID_PTR_ARITH (ptr, total_size, (void *)UINTPTR_MAX);
}

/**
 * chunk_init_metadata - Initialize chunk metadata
 * @ptr: Chunk header to initialize
 * @chunk_size: Usable size (excluding header)
 * Thread-safe: Yes
 */
static void
chunk_init_metadata (struct ChunkHeader *ptr, size_t chunk_size)
{
  ptr->chunk_size = chunk_size;
}

/* ==================== Public Chunk API ==================== */

/**
 * arena_reuse_free_chunk - Try to get a chunk from the free chunk pool
 * @ptr_out: Output pointer for chunk header
 * @limit_out: Output pointer for chunk limit
 *
 * Returns: ARENA_CHUNK_REUSED if chunk was reused,
 *          ARENA_CHUNK_NOT_REUSED otherwise
 * Thread-safe: Yes (uses global arena_mutex)
 *
 * Attempts to retrieve a previously freed chunk from the global cache
 * for reuse, avoiding the overhead of malloc().
 */
int
arena_reuse_free_chunk (struct ChunkHeader **ptr_out, char **limit_out)
{
  int result;

  pthread_mutex_lock (&arena_mutex);
  result = chunk_get_from_cache_unlocked (ptr_out, limit_out);
  pthread_mutex_unlock (&arena_mutex);

  return result;
}

/**
 * arena_calculate_chunk_size - Calculate size for new chunk allocation
 * @min_size: Minimum size required
 *
 * Returns: Chunk size to allocate (at least ARENA_CHUNK_SIZE)
 * Thread-safe: Yes
 *
 * Returns the larger of ARENA_CHUNK_SIZE and min_size to ensure
 * chunks are at least the default size for efficiency.
 */
size_t
arena_calculate_chunk_size (size_t min_size)
{
  return (ARENA_CHUNK_SIZE < min_size) ? min_size : ARENA_CHUNK_SIZE;
}

/**
 * arena_validate_chunk_size - Validate chunk size won't cause overflow
 * @chunk_size: Requested chunk size
 *
 * Returns: Total size including header, or 0 on overflow/invalid
 * Thread-safe: Yes
 *
 * Validates that adding the header size won't overflow and that
 * the total doesn't exceed the maximum allocation size.
 */
size_t
arena_validate_chunk_size (size_t chunk_size)
{
  size_t total_size;

  if (ARENA_CHECK_OVERFLOW_ADD (sizeof (union header), chunk_size)
      == ARENA_VALIDATION_FAILURE)
    return 0;

  total_size = sizeof (union header) + chunk_size;

  if (total_size > ARENA_MAX_ALLOC_SIZE)
    return 0;

  return total_size;
}

/**
 * arena_allocate_new_chunk - Allocate a new chunk from system memory
 * @total_size: Total size including header
 * @ptr_out: Output pointer for chunk header
 * @limit_out: Output pointer for chunk limit
 *
 * Returns: ARENA_SUCCESS on success, ARENA_FAILURE on failure
 * Thread-safe: Yes
 *
 * Allocates a new chunk from the system heap and validates
 * pointer arithmetic to prevent overflow issues.
 */
int
arena_allocate_new_chunk (size_t total_size, struct ChunkHeader **ptr_out,
                          char **limit_out)
{
  struct ChunkHeader *ptr;

  ptr = malloc (total_size);
  if (ptr == NULL)
    {
      ARENA_ERROR_MSG ("Cannot allocate new chunk: %zu bytes", total_size);
      return ARENA_FAILURE;
    }

  if (!chunk_validate_pointer (ptr, total_size))
    {
      free (ptr);
      ARENA_ERROR_MSG ("Invalid pointer arithmetic for chunk allocation");
      return ARENA_FAILURE;
    }

  chunk_init_metadata (ptr, total_size - sizeof (union header));
  *ptr_out = ptr;
  *limit_out = chunk_calculate_limit (ptr, total_size);

  return ARENA_SUCCESS;
}

/**
 * arena_link_chunk - Link a chunk into the arena structure
 * @arena: Arena to link chunk into
 * @ptr: Chunk header to link
 * @limit: Chunk limit pointer
 *
 * Thread-safe: No (must be called with arena->mutex held)
 *
 * Saves current arena state into the chunk header and updates
 * the arena to use the new chunk for allocations.
 */
void
arena_link_chunk (T arena, struct ChunkHeader *ptr, char *limit)
{
  ptr->prev = arena->prev;
  ptr->avail = arena->avail;
  ptr->limit = arena->limit;

  arena->avail = (char *)((union header *)ptr + 1);
  arena->limit = limit;
  arena->prev = ptr;
}

/**
 * arena_try_allocate_fresh_chunk - Try to allocate a fresh chunk
 * @min_size: Minimum size needed
 * @ptr_out: Output pointer for chunk header
 * @limit_out: Output pointer for chunk limit
 *
 * Returns: ARENA_SUCCESS on success, ARENA_FAILURE on failure
 * Thread-safe: Yes
 *
 * Calculates appropriate chunk size, validates it, and allocates
 * a new chunk from system memory.
 */
static int
arena_try_allocate_fresh_chunk (size_t min_size, struct ChunkHeader **ptr_out,
                                char **limit_out)
{
  size_t chunk_size;
  size_t total_size;

  chunk_size = arena_calculate_chunk_size (min_size);
  total_size = arena_validate_chunk_size (chunk_size);

  if (total_size == 0)
    {
      ARENA_ERROR_MSG ("Invalid chunk size calculation: %zu", chunk_size);
      return ARENA_FAILURE;
    }

  return arena_allocate_new_chunk (total_size, ptr_out, limit_out);
}

/**
 * arena_allocate_chunk - Allocate a new chunk for the arena
 * @arena: Arena needing new chunk
 * @min_size: Minimum size needed in chunk
 *
 * Returns: ARENA_SUCCESS on success, ARENA_FAILURE on failure
 * Thread-safe: No (must be called with arena->mutex held)
 *
 * First attempts to reuse a cached chunk, falling back to fresh
 * allocation if the cache is empty.
 */
int
arena_allocate_chunk (T arena, size_t min_size)
{
  struct ChunkHeader *ptr;
  char *limit;

  /* Try cache first */
  if (arena_reuse_free_chunk (&ptr, &limit) == ARENA_CHUNK_REUSED)
    {
      arena_link_chunk (arena, ptr, limit);
      return ARENA_SUCCESS;
    }

  /* Allocate fresh chunk */
  if (arena_try_allocate_fresh_chunk (min_size, &ptr, &limit) != ARENA_SUCCESS)
    return ARENA_FAILURE;

  arena_link_chunk (arena, ptr, limit);
  return ARENA_SUCCESS;
}

/**
 * arena_return_chunk_to_pool - Return chunk to global free pool or free it
 * @chunk: Chunk to return
 *
 * Thread-safe: Yes (uses global arena_mutex)
 *
 * Adds the chunk to the free cache for reuse. If the cache is full,
 * the chunk is freed back to the system.
 */
void
arena_return_chunk_to_pool (struct ChunkHeader *chunk)
{
  int added;

  assert (chunk);

  pthread_mutex_lock (&arena_mutex);
  added = chunk_add_to_cache_unlocked (chunk);
  pthread_mutex_unlock (&arena_mutex);

  if (!added)
    free (chunk);
}

/**
 * arena_process_chunk - Process and remove one chunk from arena
 * @arena: Arena to process chunk from
 *
 * Returns: ARENA_VALIDATION_SUCCESS if chunk was processed,
 *          ARENA_VALIDATION_FAILURE if no more chunks
 * Thread-safe: No (must be called with arena->mutex held)
 *
 * Removes the most recently allocated chunk and restores the
 * arena state to the previous chunk.
 */
int
arena_process_chunk (T arena)
{
  struct ChunkHeader *chunk_to_process;
  struct ChunkHeader saved_state;

  if (arena->prev == NULL)
    return ARENA_VALIDATION_FAILURE;

  chunk_to_process = arena->prev;
  saved_state = *chunk_to_process;

  arena->prev = saved_state.prev;
  arena->avail = saved_state.avail;
  arena->limit = saved_state.limit;

  arena_return_chunk_to_pool (chunk_to_process);
  return ARENA_VALIDATION_SUCCESS;
}

/**
 * arena_clear_all_chunks - Clear all chunks from arena
 * @arena: Arena to clear
 *
 * Thread-safe: No (must be called with arena->mutex held)
 *
 * Iteratively processes and removes all chunks, returning them
 * to the free pool or freeing them.
 */
void
arena_clear_all_chunks (T arena)
{
  while (arena_process_chunk (arena) == ARENA_VALIDATION_SUCCESS)
    ;
}

/**
 * arena_verify_initial_state - Verify arena is in initial empty state
 * @arena: Arena to verify
 *
 * Thread-safe: No (must be called with arena->mutex held)
 *
 * Asserts that the arena has been properly cleared to its initial
 * state with no allocated chunks.
 */
void
arena_verify_initial_state (T arena)
{
  assert (arena->prev == NULL);
  assert (arena->avail == NULL);
  assert (arena->limit == NULL);
}

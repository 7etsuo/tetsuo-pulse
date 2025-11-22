/**
 * Arena-chunk.c - Private chunk management for Arena allocator
 *
 * Handles chunk allocation, reuse, linking, and cleanup.
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
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
#include "core/Except.h"      /* For RAISE if needed */
#include "core/SocketError.h" /* For error handling if needed */

/* Global free chunk cache */
struct ChunkHeader *freechunks = NULL;
int nfree = 0;
pthread_mutex_t arena_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * arena_reuse_free_chunk - Try to get a chunk from the free chunk pool
 * @ptr_out: Output pointer for chunk header
 * @limit_out: Output pointer for chunk limit
 * Returns: ARENA_CHUNK_REUSED if chunk was reused, ARENA_CHUNK_NOT_REUSED
 * otherwise Thread-safe: Yes (uses global arena_mutex)
 */
int
arena_reuse_free_chunk (struct ChunkHeader **ptr_out, char **limit_out)
{
  struct ChunkHeader *ptr;
  size_t total_size;

  pthread_mutex_lock (&arena_mutex);
  if ((ptr = freechunks) != NULL)
    {
      freechunks = freechunks->prev;
      nfree--;
      *ptr_out = ptr;

      /* Use stored chunk_size to recalculate proper limit */
      total_size = sizeof (union header) + ptr->chunk_size;
      *limit_out = (char *)ptr + total_size;

      pthread_mutex_unlock (&arena_mutex);
      return ARENA_CHUNK_REUSED;
    }
  pthread_mutex_unlock (&arena_mutex);
  return ARENA_CHUNK_NOT_REUSED;
}

/**
 * arena_calculate_chunk_size - Calculate size for new chunk allocation
 * @min_size: Minimum size required
 * Returns: Chunk size to allocate
 * Thread-safe: Yes
 */
size_t
arena_calculate_chunk_size (size_t min_size)
{
  size_t chunk_size = ARENA_CHUNK_SIZE;
  return (chunk_size < min_size) ? min_size : chunk_size;
}

/**
 * arena_validate_chunk_size - Validate chunk size won't cause overflow
 * @chunk_size: Requested chunk size
 * Returns: Total size including header, or 0 on overflow
 * Thread-safe: Yes
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
 * Returns: ARENA_SUCCESS on success, ARENA_FAILURE on failure
 * Thread-safe: Yes
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

  if (!ARENA_VALID_PTR_ARITH (ptr, total_size, (void *)UINTPTR_MAX))
    {
      free (ptr);
      ARENA_ERROR_MSG ("Invalid pointer arithmetic for chunk allocation");
      return ARENA_FAILURE;
    }

  /* Store actual chunk size for proper reuse from cache */
  ptr->chunk_size = total_size - sizeof (union header);

  *ptr_out = ptr;
  *limit_out = (char *)ptr + total_size;
  return ARENA_SUCCESS;
}

/**
 * arena_link_chunk - Link a chunk into the arena structure
 * @arena: Arena to link chunk into
 * @ptr: Chunk header to link
 * @limit: Chunk limit pointer
 * Thread-safe: Must be called with arena->mutex held
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
 * arena_allocate_chunk - Allocate a new chunk for the arena
 * @arena: Arena needing new chunk
 * @min_size: Minimum size needed in chunk
 * Returns: ARENA_SUCCESS on success, ARENA_FAILURE on failure
 * Thread-safe: Must be called with arena->mutex held
 */
int
arena_allocate_chunk (T arena, size_t min_size)
{
  struct ChunkHeader *ptr;
  char *limit;
  size_t chunk_size;
  size_t total_size;

  if (arena_reuse_free_chunk (&ptr, &limit) == ARENA_CHUNK_REUSED)
    goto link_chunk;

  chunk_size = arena_calculate_chunk_size (min_size);
  total_size = arena_validate_chunk_size (chunk_size);
  if (total_size == 0)
    {
      ARENA_ERROR_MSG ("Invalid chunk size calculation: %zu", chunk_size);
      return ARENA_FAILURE;
    }

  if (arena_allocate_new_chunk (total_size, &ptr, &limit) != ARENA_SUCCESS)
    return ARENA_FAILURE;

link_chunk:
  arena_link_chunk (arena, ptr, limit);
  return ARENA_SUCCESS;
}

/**
 * arena_return_chunk_to_pool - Return chunk to global free pool or free it
 * @chunk: Chunk to return
 * Thread-safe: Yes (uses global arena_mutex)
 */
void
arena_return_chunk_to_pool (struct ChunkHeader *chunk)
{
  assert (chunk);

  pthread_mutex_lock (&arena_mutex);

  if (nfree < ARENA_MAX_FREE_CHUNKS)
    {
      /* Add to free list for reuse */
      chunk->prev = freechunks;
      freechunks = chunk;
      nfree++;
      pthread_mutex_unlock (&arena_mutex);
    }
  else
    {
      /* Free list is full, free the chunk */
      pthread_mutex_unlock (&arena_mutex);
      free (chunk);
    }
}

/**
 * arena_process_chunk - Process and remove one chunk from arena
 * @arena: Arena to process chunk from
 * Returns: ARENA_VALIDATION_SUCCESS if chunk was processed,
 * ARENA_VALIDATION_FAILURE if no more chunks Thread-safe: Must be called with
 * arena->mutex held
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
 * Thread-safe: Must be called with arena->mutex held
 */
void
arena_clear_all_chunks (T arena)
{
  while (arena_process_chunk (arena) == ARENA_VALIDATION_SUCCESS)
    /* Process all chunks */;
}

/**
 * arena_verify_initial_state - Verify arena is in initial empty state
 * @arena: Arena to verify
 * Thread-safe: Must be called with arena->mutex held
 */
void
arena_verify_initial_state (T arena)
{
  assert (arena->prev == NULL);
  assert (arena->avail == NULL);
  assert (arena->limit == NULL);
}

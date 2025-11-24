/**
 * Arena.c - Arena memory allocator
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This file contains the public API implementation for the Arena allocator.
 * Internal helper functions are delegated to Arena-alloc.c and Arena-chunk.c.
 */

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>

#include "core/Arena-private.h"
#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"

/* Thread-local error buffer - exported for use by Arena-alloc.c/Arena-chunk.c */
#ifdef _WIN32
__declspec (thread) char arena_error_buf[ARENA_ERROR_BUFSIZE];
#else
__thread char arena_error_buf[ARENA_ERROR_BUFSIZE];
#endif

/* Arena exception definition */
const Except_T Arena_Failed = { &Arena_Failed, "Arena operation failed" };

/* Thread-local exception for detailed error messages
 * This is a COPY of the base exception with thread-local reason string.
 * Each thread gets its own exception instance, preventing race conditions
 * when multiple threads raise the same exception type simultaneously. */
#ifdef _WIN32
__declspec (thread) Except_T Arena_DetailedException;
#else
__thread Except_T Arena_DetailedException;
#endif

/* Macros are defined in Arena-private.h to avoid duplication */

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
  T arena = arena_allocate_structure ();
  if (arena == NULL)
    RAISE_ARENA_ERROR (Arena_Failed);

  if (arena_initialize_mutex (arena) != ARENA_SUCCESS)
    {
      free (arena);
      RAISE_ARENA_ERROR (Arena_Failed);
    }

  arena_initialize_state (arena);
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

  /* Suppress unused parameter warnings */
  (void)file;
  (void)line;

  /* Validate input parameters */
  if (arena == NULL)
    {
      ARENA_ERROR_MSG ("NULL arena pointer in Arena_alloc");
      RAISE_ARENA_ERROR (Arena_Failed);
    }
  if (nbytes == 0)
    {
      ARENA_ERROR_MSG ("Zero size allocation in Arena_alloc");
      RAISE_ARENA_ERROR (Arena_Failed);
    }

  /* Prepare aligned allocation size */
  aligned_size = arena_prepare_allocation (nbytes);
  if (aligned_size == 0)
    RAISE_ARENA_ERROR (Arena_Failed);

  /* Execute allocation under mutex protection */
  return arena_execute_allocation (arena, aligned_size, nbytes);
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

  /* Validate input parameters */
  if (arena == NULL)
    {
      ARENA_ERROR_MSG ("NULL arena pointer in Arena_calloc");
      RAISE_ARENA_ERROR (Arena_Failed);
    }
  if (count == 0 || nbytes == 0)
    {
      ARENA_ERROR_MSG ("Invalid count (%zu) or nbytes (%zu) in Arena_calloc",
                       count, nbytes);
      RAISE_ARENA_ERROR (Arena_Failed);
    }

  /* Validate overflow and size limits */
  arena_validate_calloc_overflow (count, nbytes);
  total = count * nbytes;
  arena_validate_calloc_size (total);

  /* Allocate and zero memory */
  ptr = Arena_alloc (arena, total, file, line);
  arena_zero_memory (ptr, total);
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
  arena_clear_all_chunks (arena);
  arena_verify_initial_state (arena);
  pthread_mutex_unlock (&arena->mutex);
}

#undef T

/**
 * Arena.c - Arena memory allocator implementation
 */

#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena-private.h"
#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketError.h"

#include "core/Except.h"

/* Arena-specific configuration constants */

/* Thread-local error buffer */
#ifdef _WIN32
__declspec (thread) char arena_error_buf[ARENA_ERROR_BUFSIZE];
#else
__thread char arena_error_buf[ARENA_ERROR_BUFSIZE];
#endif

/* Arena exception definition */
Except_T Arena_Failed = { "Arena operation failed" };

/* Thread-local exception for detailed error messages
 * This is a COPY of the base exception with thread-local reason string.
 * Each thread gets its own exception instance, preventing race conditions
 * when multiple threads raise the same exception type simultaneously. */
#ifdef _WIN32
__declspec (thread) Except_T Arena_DetailedException;
#else
__thread Except_T Arena_DetailedException;
#endif

/* Error formatting macros */
#define ARENA_ERROR_FMT(fmt, ...)                                             \
  snprintf (arena_error_buf, ARENA_ERROR_BUFSIZE, fmt " (errno: %d - %s)",    \
            ##__VA_ARGS__, errno, Socket_safe_strerror (errno))

#define ARENA_ERROR_MSG(fmt, ...)                                             \
  snprintf (arena_error_buf, ARENA_ERROR_BUFSIZE, fmt, ##__VA_ARGS__)

/* Macro to raise arena exception with detailed error message
 * Creates a thread-local copy of the exception with detailed reason */
#define RAISE_ARENA_ERROR(base_exception)                                     \
  do                                                                          \
    {                                                                         \
      Arena_DetailedException = (base_exception);                             \
      Arena_DetailedException.reason = arena_error_buf;                       \
      RAISE (Arena_DetailedException);                                        \
    }                                                                         \
  while (0)

/* Internal structures and types defined in Arena-private.h */

/* Free chunk cache - defined in Arena-chunk.c */

/* Helper macros for overflow protection */
#define ARENA_CHECK_OVERFLOW_ADD(a, b)                                        \
  (((a) > SIZE_MAX - (b)) ? ARENA_VALIDATION_FAILURE                          \
                          : ARENA_VALIDATION_SUCCESS)
#define ARENA_CHECK_OVERFLOW_MUL(a, b)                                        \
  (((a) != 0 && (b) > SIZE_MAX / (a)) ? ARENA_VALIDATION_FAILURE              \
                                      : ARENA_VALIDATION_SUCCESS)

/* Helper macro for safe pointer arithmetic validation */
#define ARENA_VALID_PTR_ARITH(ptr, offset, max)                               \
  (((uintptr_t)(ptr) <= UINTPTR_MAX - (offset))                               \
   && ((uintptr_t)(ptr) + (offset) <= (uintptr_t)(max)))

/**
 * arena_get_alignment - Get alignment size for memory allocations
 * Returns: Alignment size in bytes (guaranteed to be at least 1)
 * Thread-safe: Yes
 * Calculates the alignment requirement based on the union align structure
 * which ensures proper alignment for all standard C data types.
 */

/* Allocation helper functions implemented in Arena-alloc.c */

/* Allocation helper functions implemented in Arena-alloc.c */

/* Chunk management functions implemented in Arena-chunk.c */

/* Core allocation functions implemented in Arena-alloc.c */

/* Arena structure initialization implemented in Arena-alloc.c */

/**
 * Arena_new - Create a new arena instance
 * Returns: New arena instance, or raises Arena_Failed on error
 * Raises: Arena_Failed if allocation or mutex initialization fails
 * Thread-safe: Yes
 * Creates a new arena allocator with thread-safe allocation support.
 * The arena manages memory in chunks and provides efficient allocation
 * without individual free operations. All memory is freed when the arena
 * is disposed.
 */
T
Arena_new (void)
{
  T arena;

  /* Allocate arena structure */
  arena = arena_allocate_structure ();
  if (arena == NULL)
    RAISE_ARENA_ERROR (Arena_Failed);

  /* Initialize mutex with error checking */
  if (arena_initialize_mutex (arena) != ARENA_SUCCESS)
    {
      free (arena);
      RAISE_ARENA_ERROR (Arena_Failed);
    }

  /* Initialize arena state */
  arena_initialize_state (arena);

  return arena;
}

/**
 * Arena_dispose - Dispose of an arena and all its allocations
 * @ap: Pointer to arena pointer (will be set to NULL)
 * Frees all memory allocated from this arena including the arena structure
 * itself. After this call, the arena pointer is invalid and should not be
 * used. Raises: None (void function) Thread-safe: Yes (but arena should not be
 * used concurrently during disposal) Pre-conditions: ap != NULL, *ap != NULL
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

/* arena_validate_allocation_request implemented in Arena-alloc.c */

/* Allocation space management implemented in Arena-alloc.c */

/* arena_execute_allocation implemented in Arena-alloc.c */

/**
 * Arena_alloc - Allocate memory from arena
 * @arena: Arena to allocate from
 * @nbytes: Number of bytes to allocate
 * @file: Source file name (for debugging)
 * @line: Source line number (for debugging)
 * Returns: Pointer to allocated memory, or raises Arena_Failed on error
 * Raises: Arena_Failed if allocation fails due to insufficient space or
 * overflow Thread-safe: Yes Pre-conditions: arena != NULL, nbytes > 0
 * Allocates memory from the arena with proper alignment and overflow
 * protection. The allocated memory remains valid until the arena is cleared or
 * disposed. No individual free is needed - all memory is managed by the arena
 * lifetime.
 */
void *
Arena_alloc (T arena, size_t nbytes, const char *file, int line)
{
  size_t aligned_size;
  void *result;

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

  /* Validate request parameters */
  if (arena_validate_allocation_request (arena, nbytes) != ARENA_SUCCESS)
    RAISE_ARENA_ERROR (Arena_Failed);

  /* Suppress unused parameter warnings */
  (void)file;
  (void)line;

  /* Prepare allocation */
  aligned_size = arena_prepare_allocation (nbytes);
  if (aligned_size == 0)
    RAISE_ARENA_ERROR (Arena_Failed);

  /* Execute allocation */
  result = arena_execute_allocation (arena, aligned_size, nbytes);

  return result;
}

/* calloc validation functions implemented in Arena-alloc.c */

/* arena_zero_memory implemented in Arena-alloc.c */

/**
 * Arena_calloc - Allocate and zero memory from arena
 * @arena: Arena to allocate from
 * @count: Number of elements
 * @nbytes: Size of each element
 * @file: Source file (for debugging)
 * @line: Source line (for debugging)
 * Returns: Pointer to zeroed memory, or raises Arena_Failed on error
 * Raises: Arena_Failed if allocation fails or overflow occurs
 * Thread-safe: Yes
 * Pre-conditions: arena != NULL, count > 0, nbytes > 0
 * Allocates count * nbytes of memory from the arena and initializes it to
 * zero. Uses Arena_alloc internally with overflow protection for the
 * multiplication.
 */
void *
Arena_calloc (T arena, size_t count, size_t nbytes, const char *file, int line)
{
  void *ptr;
  size_t total;

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

  assert (arena);
  assert (count > 0);
  assert (nbytes > 0);

  arena_validate_calloc_overflow (count, nbytes);
  total = count * nbytes;
  arena_validate_calloc_size (total);

  ptr = Arena_alloc (arena, total, file, line);
  arena_zero_memory (ptr, total);
  return ptr;
}

/* Remaining chunk management functions implemented in Arena-chunk.c */

/**
 * Arena_clear - Clear all allocations from arena
 * @arena: Arena to clear
 * Releases all memory chunks back to the free pool without freeing the arena
 * structure. The arena can be reused for new allocations after clearing.
 * Raises: None (void function)
 * Thread-safe: Yes
 * Pre-conditions: arena != NULL
 */
void
Arena_clear (T arena)
{
  if (arena == NULL)
    {
      ARENA_ERROR_MSG ("NULL arena pointer in Arena_clear");
      return;
    }

  assert (arena);

  pthread_mutex_lock (&arena->mutex);
  arena_clear_all_chunks (arena);
  arena_verify_initial_state (arena);
  pthread_mutex_unlock (&arena->mutex);
}

#undef T

/**
 * Arena-alloc.c - Private allocation logic for Arena allocator
 *
 * Handles size calculation, alignment, overflow validation, and calloc
 * helpers. Part of the Socket Library Following C Interfaces and
 * Implementations patterns
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memset */

#include "core/Arena-private.h"
#include "core/Except.h"
#include "core/SocketError.h" /* For error handling if needed */

/**
 * arena_get_alignment - Get alignment size for memory allocations
 * Returns: Alignment size in bytes (guaranteed to be at least 1)
 * Thread-safe: Yes
 */
size_t
arena_get_alignment (void)
{
  size_t alignment = ARENA_ALIGNMENT_SIZE;
  return (alignment == 0) ? 1 : alignment;
}

/**
 * arena_check_size_overflow - Check if size calculation would overflow
 * @nbytes: Base size
 * @alignment: Alignment requirement
 * Returns: Non-zero if overflow, zero otherwise
 * Thread-safe: Yes
 */
int
arena_check_size_overflow (size_t nbytes, size_t alignment)
{
  return ARENA_CHECK_OVERFLOW_ADD (nbytes, alignment - 1);
}

/**
 * arena_calculate_aligned_bytes - Calculate number of aligned units needed
 * @nbytes: Requested size
 * @alignment: Alignment requirement
 * Returns: Number of aligned units, or 0 on overflow
 * Thread-safe: Yes
 */
size_t
arena_calculate_aligned_bytes (size_t nbytes, size_t alignment)
{
  size_t sum;

  if (arena_check_size_overflow (nbytes, alignment)
      == ARENA_VALIDATION_FAILURE)
    return 0;

  sum = nbytes + alignment - 1;
  return sum / alignment;
}

/**
 * arena_calculate_final_size - Calculate final aligned size
 * @aligned_bytes: Number of aligned units
 * @alignment: Alignment requirement
 * Returns: Final aligned size, or 0 on overflow
 * Thread-safe: Yes
 */
size_t
arena_calculate_final_size (size_t aligned_bytes, size_t alignment)
{
  if (ARENA_CHECK_OVERFLOW_MUL (aligned_bytes, alignment)
      == ARENA_VALIDATION_FAILURE)
    return 0;

  return aligned_bytes * alignment;
}

/**
 * arena_validate_allocation_size - Validate allocation size meets requirements
 * @size: Size to validate
 * Returns: ARENA_SIZE_VALID if size is acceptable, ARENA_SIZE_INVALID
 * otherwise Thread-safe: Yes
 */
int
arena_validate_allocation_size (size_t size)
{
  return (size > 0 && size <= ARENA_MAX_ALLOC_SIZE) ? ARENA_SIZE_VALID
                                                    : ARENA_SIZE_INVALID;
}

/**
 * arena_calculate_aligned_size - Calculate properly aligned allocation size
 * @nbytes: Requested allocation size
 * Returns: Aligned size, or 0 on overflow/underflow/invalid size
 * Thread-safe: Yes
 */
size_t
arena_calculate_aligned_size (size_t nbytes)
{
  size_t alignment;
  size_t aligned_bytes;
  size_t final_size;

  /* Validate input size */
  if (arena_validate_allocation_size (nbytes) == ARENA_SIZE_INVALID)
    return 0;

  /* Get alignment requirement */
  alignment = arena_get_alignment ();

  /* Calculate aligned byte count */
  aligned_bytes = arena_calculate_aligned_bytes (nbytes, alignment);
  if (aligned_bytes == 0)
    return 0;

  /* Calculate final aligned size */
  final_size = arena_calculate_final_size (aligned_bytes, alignment);
  if (final_size == 0)
    return 0;

  /* Final validation of aligned size */
  if (arena_validate_allocation_size (final_size) == ARENA_SIZE_INVALID)
    return 0;

  return final_size;
}

/**
 * arena_prepare_allocation - Prepare allocation by calculating aligned size
 * @nbytes: Number of bytes requested
 * Returns: Aligned size for allocation, or 0 on error
 * Thread-safe: Yes
 */
size_t
arena_prepare_allocation (size_t nbytes)
{
  size_t aligned_size;

  aligned_size = arena_calculate_aligned_size (nbytes);
  if (aligned_size == 0)
    {
      ARENA_ERROR_MSG (
          "Invalid allocation size: %zu bytes (alignment/overflow error)",
          nbytes);
      return 0;
    }

  return aligned_size;
}

/**
 * arena_validate_calloc_overflow - Validate calloc parameters for overflow
 * @count: Number of elements
 * @nbytes: Size of each element
 * Raises: Arena_Failed if overflow detected
 */
void
arena_validate_calloc_overflow (size_t count, size_t nbytes)
{
  if (ARENA_CHECK_OVERFLOW_MUL (count, nbytes) == ARENA_VALIDATION_FAILURE)
    {
      ARENA_ERROR_MSG ("calloc overflow: count=%zu, nbytes=%zu", count,
                       nbytes);
      RAISE_ARENA_ERROR (Arena_Failed);
    }
}

/**
 * arena_validate_calloc_size - Validate calloc total size
 * @total: Total size to validate
 * Raises: Arena_Failed if size exceeds maximum
 */
void
arena_validate_calloc_size (size_t total)
{
  if (total > ARENA_MAX_ALLOC_SIZE)
    {
      ARENA_ERROR_MSG ("calloc size exceeds maximum: %zu", total);
      RAISE_ARENA_ERROR (Arena_Failed);
    }
}

/**
 * arena_zero_memory - Zero allocated memory
 * @ptr: Pointer to memory
 * @total: Size to zero
 */
void
arena_zero_memory (void *ptr, size_t total)
{
  memset (ptr, 0, total);
}

/**
 * arena_has_space - Check if current chunk has enough space
 * @arena: Arena to check
 * @aligned_size: Required aligned size
 * Returns: ARENA_VALIDATION_SUCCESS if space available,
 * ARENA_VALIDATION_FAILURE otherwise Thread-safe: Must be called with
 * arena->mutex held
 */
int
arena_has_space (T arena, size_t aligned_size)
{
  if (arena->avail == NULL || arena->limit == NULL)
    return ARENA_VALIDATION_FAILURE;

  return ((size_t)(arena->limit - arena->avail) >= aligned_size)
             ? ARENA_VALIDATION_SUCCESS
             : ARENA_VALIDATION_FAILURE;
}

/**
 * arena_ensure_space - Ensure arena has enough space for allocation
 * @arena: Arena needing space
 * @aligned_size: Required aligned size
 * Returns: ARENA_SUCCESS on success, ARENA_FAILURE on failure
 * Thread-safe: Must be called with arena->mutex held
 */
int
arena_ensure_space (T arena, size_t aligned_size)
{
  while (arena_has_space (arena, aligned_size) == ARENA_VALIDATION_FAILURE)
    {
      if (arena_allocate_chunk (arena, aligned_size) != ARENA_SUCCESS)
        return ARENA_FAILURE;
    }
  return ARENA_SUCCESS;
}

/**
 * arena_perform_allocation - Perform the actual memory allocation
 * @arena: Arena to allocate from
 * @aligned_size: Aligned size to allocate
 * Returns: Pointer to allocated memory
 * Thread-safe: Must be called with arena->mutex held and validated state
 */
void *
arena_perform_allocation (T arena, size_t aligned_size)
{
  void *result = arena->avail;
  arena->avail += aligned_size;
  return result;
}

/**
 * arena_allocate_structure - Allocate and initialize arena structure
 * Returns: Pointer to allocated arena structure, or NULL on failure
 * Thread-safe: Yes
 */
T
arena_allocate_structure (void)
{
  T arena;

  arena = malloc (sizeof (*arena));
  if (arena == NULL)
    {
      ARENA_ERROR_MSG (ARENA_ENOMEM ": Cannot allocate arena structure");
      return NULL;
    }

  return arena;
}

/**
 * arena_initialize_mutex - Initialize arena mutex
 * @arena: Arena structure to initialize
 * Returns: ARENA_SUCCESS on success, ARENA_FAILURE on failure
 * Thread-safe: Yes
 */
int
arena_initialize_mutex (T arena)
{
  if (pthread_mutex_init (&arena->mutex, NULL) != 0)
    {
      ARENA_ERROR_MSG ("Failed to initialize arena mutex");
      return ARENA_FAILURE;
    }

  return ARENA_SUCCESS;
}

/**
 * arena_initialize_state - Initialize arena state to empty
 * @arena: Arena structure to initialize
 * Thread-safe: Yes
 */
void
arena_initialize_state (T arena)
{
  arena->prev = NULL;
  arena->avail = NULL;
  arena->limit = NULL;
}

/**
 * arena_ensure_allocation_space - Ensure arena has space for allocation
 * @arena: Arena to check
 * @aligned_size: Required aligned size
 * @nbytes: Original requested size (for error messages)
 * Raises: Arena_Failed if space cannot be ensured
 * Thread-safe: Must be called with arena->mutex held
 */
void
arena_ensure_allocation_space (T arena, size_t aligned_size, size_t nbytes)
{
  if (arena_ensure_space (arena, aligned_size) != ARENA_SUCCESS)
    {
      ARENA_ERROR_MSG ("Failed to ensure space for %zu-byte allocation",
                       nbytes);
      RAISE_ARENA_ERROR (Arena_Failed);
    }
}

/**
 * arena_execute_allocation - Execute the allocation under mutex protection
 * @arena: Arena to allocate from
 * @aligned_size: Aligned size to allocate
 * @nbytes: Original requested size (for error messages)
 * Returns: Pointer to allocated memory
 * Thread-safe: Must be called without holding arena mutex
 */
void *
arena_execute_allocation (T arena, size_t aligned_size, size_t nbytes)
{
  void *result = NULL;

  pthread_mutex_lock (&arena->mutex);

  TRY
  {
    arena_ensure_allocation_space (arena, aligned_size, nbytes);
    result = arena_perform_allocation (arena, aligned_size);
    pthread_mutex_unlock (&arena->mutex);
    RETURN result;
  }
  FINALLY
  pthread_mutex_unlock (&arena->mutex);
  END_TRY;

  return NULL;
}

/**
 * arena_validate_allocation_request - Validate allocation request parameters
 * @arena: Arena to allocate from
 * @nbytes: Number of bytes to allocate
 * Returns: ARENA_SUCCESS if valid, ARENA_FAILURE if invalid
 * Thread-safe: Yes
 */
int
arena_validate_allocation_request (T arena, size_t nbytes)
{
  if (arena == NULL || nbytes == 0)
    {
      return ARENA_FAILURE;
    }

  return ARENA_SUCCESS;
}

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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
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
  // cppcheck-suppress unusedStructMember
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

/* ==================== Validation Macros ==================== */

#define ARENA_CHECK_OVERFLOW_ADD(a, b)                                        \
  (((a) > SIZE_MAX - (b)) ? ARENA_VALIDATION_FAILURE                          \
                          : ARENA_VALIDATION_SUCCESS)
#define ARENA_CHECK_OVERFLOW_MUL(a, b)                                        \
  (((a) != 0 && (b) > SIZE_MAX / (a)) ? ARENA_VALIDATION_FAILURE              \
                                      : ARENA_VALIDATION_SUCCESS)
#define ARENA_VALID_PTR_ARITH(ptr, offset, max)                               \
  (((uintptr_t)(ptr) <= UINTPTR_MAX - (offset))                               \
   && ((uintptr_t)(ptr) + (offset) <= (uintptr_t)(max)))

/* ================================================================
 * INPUT VALIDATION HELPERS
 * ================================================================ */

/**
 * arena_validate_arena_param - Validate arena parameter is not NULL
 * @arena: Arena pointer to validate
 * @func_name: Name of calling function for error message
 *
 * Raises: Arena_Failed if arena is NULL
 * Thread-safe: Yes
 */
static void
arena_validate_arena_param (const T arena, const char *func_name)
{
  if (arena == NULL)
    SOCKET_RAISE_MSG (Arena, Arena_Failed, "NULL arena pointer in %s",
                      func_name);
}

/**
 * arena_validate_nbytes_param - Validate nbytes parameter is non-zero
 * @nbytes: Size to validate
 * @func_name: Name of calling function for error message
 *
 * Raises: Arena_Failed if nbytes is zero
 * Thread-safe: Yes
 */
static void
arena_validate_nbytes_param (size_t nbytes, const char *func_name)
{
  if (nbytes == 0)
    SOCKET_RAISE_MSG (Arena, Arena_Failed, "Zero size allocation in %s",
                      func_name);
}

/**
 * arena_validate_calloc_params - Validate calloc count and nbytes
 * @count: Number of elements
 * @nbytes: Size of each element
 *
 * Raises: Arena_Failed if count or nbytes is zero
 * Thread-safe: Yes
 */
static void
arena_validate_calloc_params (size_t count, size_t nbytes)
{
  if (count == 0 || nbytes == 0)
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      "Invalid count (%zu) or nbytes (%zu) in Arena_calloc",
                      count, nbytes);
}

/* ================================================================
 * CHUNK MANAGEMENT - LOW-LEVEL OPERATIONS
 * ================================================================ */

/**
 * chunk_calculate_limit - Calculate chunk limit from header and size
 * @ptr: Chunk header pointer
 * @total_size: Total chunk size including header
 *
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
 *
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
 *
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
 *
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
 *
 * Thread-safe: Yes
 */
static void
chunk_init_metadata (struct ChunkHeader *ptr, size_t chunk_size)
{
  ptr->chunk_size = chunk_size;
}

/* ================================================================
 * CHUNK MANAGEMENT - REUSE AND ALLOCATION
 * ================================================================ */

/**
 * arena_reuse_free_chunk - Try to get a chunk from the free chunk pool
 * @ptr_out: Output pointer for chunk header
 * @limit_out: Output pointer for chunk limit
 *
 * Returns: ARENA_CHUNK_REUSED if chunk was reused,
 *          ARENA_CHUNK_NOT_REUSED otherwise
 * Thread-safe: Yes (uses global arena_mutex)
 */
static int
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
 */
static size_t
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
 */
static size_t
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
 */
static int
arena_allocate_new_chunk (size_t total_size, struct ChunkHeader **ptr_out,
                          char **limit_out)
{
  struct ChunkHeader *ptr;

  ptr = malloc (total_size);
  if (ptr == NULL)
    {
      SOCKET_ERROR_MSG ("Cannot allocate new chunk: %zu bytes", total_size);
      return ARENA_FAILURE;
    }

  if (!chunk_validate_pointer (ptr, total_size))
    {
      free (ptr);
      SOCKET_ERROR_MSG ("Invalid pointer arithmetic for chunk allocation");
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
 */
static void
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
      SOCKET_ERROR_MSG ("Invalid chunk size calculation: %zu", chunk_size);
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
 */
static int
arena_allocate_chunk (T arena, size_t min_size)
{
  struct ChunkHeader *ptr;
  char *limit;

  if (arena_reuse_free_chunk (&ptr, &limit) == ARENA_CHUNK_REUSED)
    {
      arena_link_chunk (arena, ptr, limit);
      return ARENA_SUCCESS;
    }

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
 */
static void
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

/* ================================================================
 * CHUNK MANAGEMENT - CLEANUP OPERATIONS
 * ================================================================ */

/**
 * arena_process_chunk - Process and remove one chunk from arena
 * @arena: Arena to process chunk from
 *
 * Returns: ARENA_VALIDATION_SUCCESS if chunk was processed,
 *          ARENA_VALIDATION_FAILURE if no more chunks
 * Thread-safe: No (must be called with arena->mutex held)
 */
static int
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
 */
static void
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
 */
static void
arena_verify_initial_state (T arena)
{
  assert (arena->prev == NULL);
  assert (arena->avail == NULL);
  assert (arena->limit == NULL);
  (void)arena; /* Suppress unused warning when assertions disabled */
}

/* ================================================================
 * ALIGNMENT CALCULATION HELPERS
 * ================================================================ */

/**
 * arena_get_alignment - Get alignment size for memory allocations
 *
 * Returns: Alignment size in bytes (guaranteed to be at least 1)
 * Thread-safe: Yes
 */
static size_t
arena_get_alignment (void)
{
  size_t alignment = ARENA_ALIGNMENT_SIZE;
  return (alignment == 0) ? 1 : alignment;
}

/**
 * arena_check_size_overflow - Check if size calculation would overflow
 * @nbytes: Base size
 * @alignment: Alignment requirement
 *
 * Returns: Non-zero if overflow, zero otherwise
 * Thread-safe: Yes
 */
static int
arena_check_size_overflow (size_t nbytes, size_t alignment)
{
  return ARENA_CHECK_OVERFLOW_ADD (nbytes, alignment - 1);
}

/**
 * arena_calculate_aligned_bytes - Calculate number of aligned units needed
 * @nbytes: Requested size
 * @alignment: Alignment requirement
 *
 * Returns: Number of aligned units, or 0 on overflow
 * Thread-safe: Yes
 */
static size_t
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
 *
 * Returns: Final aligned size, or 0 on overflow
 * Thread-safe: Yes
 */
static size_t
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
 *
 * Returns: ARENA_SIZE_VALID if size is acceptable, ARENA_SIZE_INVALID otherwise
 * Thread-safe: Yes
 */
static int
arena_validate_allocation_size (size_t size)
{
  return (size > 0 && size <= ARENA_MAX_ALLOC_SIZE) ? ARENA_SIZE_VALID
                                                    : ARENA_SIZE_INVALID;
}

/**
 * arena_calculate_aligned_size - Calculate properly aligned allocation size
 * @nbytes: Requested allocation size
 *
 * Returns: Aligned size, or 0 on overflow/underflow/invalid size
 * Thread-safe: Yes
 */
static size_t
arena_calculate_aligned_size (size_t nbytes)
{
  size_t alignment;
  size_t aligned_bytes;
  size_t final_size;

  if (arena_validate_allocation_size (nbytes) == ARENA_SIZE_INVALID)
    return 0;

  alignment = arena_get_alignment ();

  aligned_bytes = arena_calculate_aligned_bytes (nbytes, alignment);
  if (aligned_bytes == 0)
    return 0;

  final_size = arena_calculate_final_size (aligned_bytes, alignment);
  if (final_size == 0)
    return 0;

  if (arena_validate_allocation_size (final_size) == ARENA_SIZE_INVALID)
    return 0;

  return final_size;
}

/**
 * arena_prepare_allocation - Prepare allocation by calculating aligned size
 * @nbytes: Number of bytes requested
 *
 * Returns: Aligned size for allocation, or 0 on error
 * Thread-safe: Yes
 */
static size_t
arena_prepare_allocation (size_t nbytes)
{
  size_t aligned_size;

  aligned_size = arena_calculate_aligned_size (nbytes);
  if (aligned_size == 0)
    {
      SOCKET_ERROR_MSG (
          "Invalid allocation size: %zu bytes (alignment/overflow error)",
          nbytes);
      return 0;
    }

  return aligned_size;
}

/* ================================================================
 * CALLOC VALIDATION HELPERS
 * ================================================================ */

/**
 * arena_validate_calloc_overflow - Validate calloc parameters for overflow
 * @count: Number of elements
 * @nbytes: Size of each element
 *
 * Raises: Arena_Failed if overflow detected
 * Thread-safe: Yes
 */
static void
arena_validate_calloc_overflow (size_t count, size_t nbytes)
{
  if (ARENA_CHECK_OVERFLOW_MUL (count, nbytes) == ARENA_VALIDATION_FAILURE)
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      "calloc overflow: count=%zu, nbytes=%zu", count, nbytes);
}

/**
 * arena_validate_calloc_size - Validate calloc total size
 * @total: Total size to validate
 *
 * Raises: Arena_Failed if size exceeds maximum
 * Thread-safe: Yes
 */
static void
arena_validate_calloc_size (size_t total)
{
  if (total > ARENA_MAX_ALLOC_SIZE)
    SOCKET_RAISE_MSG (Arena, Arena_Failed, "calloc size exceeds maximum: %zu",
                      total);
}

/**
 * arena_zero_memory - Zero allocated memory
 * @ptr: Pointer to memory
 * @total: Size to zero
 *
 * Thread-safe: Yes
 */
static void
arena_zero_memory (void *ptr, size_t total)
{
  memset (ptr, 0, total);
}

/* ================================================================
 * SPACE MANAGEMENT HELPERS
 * ================================================================ */

/**
 * arena_has_space - Check if current chunk has enough space
 * @arena: Arena to check
 * @aligned_size: Required aligned size
 *
 * Returns: ARENA_VALIDATION_SUCCESS if space available,
 *          ARENA_VALIDATION_FAILURE otherwise
 * Thread-safe: Must be called with arena->mutex held
 */
static int
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
 *
 * Returns: ARENA_SUCCESS on success, ARENA_FAILURE on failure
 * Thread-safe: Must be called with arena->mutex held
 */
static int
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
 *
 * Returns: Pointer to allocated memory
 * Thread-safe: Must be called with arena->mutex held and validated state
 */
static void *
arena_perform_allocation (T arena, size_t aligned_size)
{
  void *result = arena->avail;
  arena->avail += aligned_size;
  return result;
}

/* ================================================================
 * ARENA INITIALIZATION HELPERS
 * ================================================================ */

/**
 * arena_allocate_structure - Allocate and initialize arena structure
 *
 * Returns: Pointer to allocated arena structure, or NULL on failure
 * Thread-safe: Yes
 */
static T
arena_allocate_structure (void)
{
  T arena;

  arena = malloc (sizeof (*arena));
  if (arena == NULL)
    {
      SOCKET_ERROR_MSG (ARENA_ENOMEM ": Cannot allocate arena structure");
      return NULL;
    }

  return arena;
}

/**
 * arena_initialize_mutex - Initialize arena mutex
 * @arena: Arena structure to initialize
 *
 * Returns: ARENA_SUCCESS on success, ARENA_FAILURE on failure
 * Thread-safe: Yes
 */
static int
arena_initialize_mutex (T arena)
{
  if (pthread_mutex_init (&arena->mutex, NULL) != 0)
    {
      SOCKET_ERROR_MSG ("Failed to initialize arena mutex");
      return ARENA_FAILURE;
    }

  return ARENA_SUCCESS;
}

/**
 * arena_initialize_state - Initialize arena state to empty
 * @arena: Arena structure to initialize
 *
 * Thread-safe: Yes
 */
static void
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
 *
 * Raises: Arena_Failed if space cannot be ensured
 * Thread-safe: Must be called with arena->mutex held
 */
static void
arena_ensure_allocation_space (T arena, size_t aligned_size, size_t nbytes)
{
  if (arena_ensure_space (arena, aligned_size) != ARENA_SUCCESS)
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      "Failed to ensure space for %zu-byte allocation", nbytes);
}

/**
 * arena_execute_allocation - Execute the allocation under mutex protection
 * @arena: Arena to allocate from
 * @aligned_size: Aligned size to allocate
 * @nbytes: Original requested size (for error messages)
 *
 * Returns: Pointer to allocated memory, or NULL on failure
 * Raises: Arena_Failed if space cannot be ensured
 * Thread-safe: Yes (acquires arena mutex internally)
 */
static void *
arena_execute_allocation (T arena, size_t aligned_size, size_t nbytes)
{
  /* Pointer must be volatile (not pointed-to value) for longjmp safety */
  void *volatile result = NULL;

  pthread_mutex_lock (&arena->mutex);

  TRY
  {
    arena_ensure_allocation_space (arena, aligned_size, nbytes);
    result = arena_perform_allocation (arena, aligned_size);
  }
  FINALLY
  {
    pthread_mutex_unlock (&arena->mutex);
  }
  END_TRY;

  return (void *)result;
}

/* ================================================================
 * PUBLIC API IMPLEMENTATION
 * ================================================================ */

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
    SOCKET_RAISE_MODULE_ERROR (Arena, Arena_Failed);

  if (arena_initialize_mutex (arena) != ARENA_SUCCESS)
    {
      free (arena);
      SOCKET_RAISE_MODULE_ERROR (Arena, Arena_Failed);
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
  arena_validate_arena_param (arena, "Arena_alloc");
  arena_validate_nbytes_param (nbytes, "Arena_alloc");

  /* Prepare aligned allocation size */
  aligned_size = arena_prepare_allocation (nbytes);
  if (aligned_size == 0)
    SOCKET_RAISE_MODULE_ERROR (Arena, Arena_Failed);

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

  /* Validate arena parameter */
  arena_validate_arena_param (arena, "Arena_calloc");

  /* Validate count and nbytes parameters */
  arena_validate_calloc_params (count, nbytes);

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

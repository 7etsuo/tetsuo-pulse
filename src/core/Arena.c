/**
 * Arena.c - Arena memory allocator implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 */

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/Except.h"

/* Thread-local error buffer */
#ifdef _WIN32
__declspec(thread) char arena_error_buf[ARENA_ERROR_BUFSIZE];
#else
__thread char arena_error_buf[ARENA_ERROR_BUFSIZE];
#endif

/* Arena exception definition */
Except_T Arena_Failed = {"Arena operation failed"};

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec(thread) Except_T Arena_DetailedException;
#else
static __thread Except_T Arena_DetailedException;
#endif

/* Error formatting macros */
#define ARENA_ERROR_FMT(fmt, ...)                                                                                      \
    snprintf(arena_error_buf, ARENA_ERROR_BUFSIZE, fmt " (errno: %d - %s)", ##__VA_ARGS__, errno, strerror(errno))

#define ARENA_ERROR_MSG(fmt, ...) snprintf(arena_error_buf, ARENA_ERROR_BUFSIZE, fmt, ##__VA_ARGS__)

/* Macro to raise arena exception with detailed error message */
#define RAISE_ARENA_ERROR(exception)                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        Arena_DetailedException = (exception);                                                                         \
        Arena_DetailedException.reason = arena_error_buf;                                                              \
        RAISE(Arena_DetailedException);                                                                                \
    } while (0)

#define T Arena_T

/* Chunk header structure - separate from Arena_T to avoid copying mutex */
struct ChunkHeader
{
    struct ChunkHeader *prev;
    char *avail;
    char *limit;
};

/* Main arena structure - includes mutex for thread safety */
struct T
{
    struct ChunkHeader *prev;
    char *avail;
    char *limit;
    pthread_mutex_t mutex; /* Per-arena mutex for thread-safe allocation */
};

/* Alignment union - ensures proper alignment for all data types */
union align {
    int i;
    long l;
    long *lp;
    void *p;
    void (*fp)(void);
    float f;
    double d;
    long double ld;
};

/* Header union - combines chunk metadata with alignment requirements */
union header {
    struct ChunkHeader b;
    union align a;
};

/* Free chunk cache configuration */
static struct ChunkHeader *freechunks = NULL;
static int nfree = 0;
static pthread_mutex_t arena_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Helper macros for overflow protection */
#define ARENA_CHECK_OVERFLOW_ADD(a, b) (((a) > SIZE_MAX - (b)) ? ARENA_VALIDATION_FAILURE : ARENA_VALIDATION_SUCCESS)
#define ARENA_CHECK_OVERFLOW_MUL(a, b) (((a) != 0 && (b) > SIZE_MAX / (a)) ? ARENA_VALIDATION_FAILURE : ARENA_VALIDATION_SUCCESS)

/* Helper macro for safe pointer arithmetic validation */
#define ARENA_VALID_PTR_ARITH(ptr, offset, max)                                                                        \
    (((uintptr_t)(ptr) <= UINTPTR_MAX - (offset)) && ((uintptr_t)(ptr) + (offset) <= (uintptr_t)(max)))

/**
 * arena_get_alignment - Get alignment size for memory allocations
 *
 * Returns: Alignment size in bytes (guaranteed to be at least 1)
 * Thread-safe: Yes
 *
 * Calculates the alignment requirement based on the union align structure
 * which ensures proper alignment for all standard C data types.
 */
static size_t arena_get_alignment(void)
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
static int arena_check_size_overflow(size_t nbytes, size_t alignment)
{
    return ARENA_CHECK_OVERFLOW_ADD(nbytes, alignment - 1);
}

/**
 * arena_calculate_aligned_bytes - Calculate number of aligned units needed
 * @nbytes: Requested size
 * @alignment: Alignment requirement
 *
 * Returns: Number of aligned units, or 0 on overflow
 * Thread-safe: Yes
 */
static size_t arena_calculate_aligned_bytes(size_t nbytes, size_t alignment)
{
    size_t sum;

    if (arena_check_size_overflow(nbytes, alignment))
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
static size_t arena_calculate_final_size(size_t aligned_bytes, size_t alignment)
{
    if (ARENA_CHECK_OVERFLOW_MUL(aligned_bytes, alignment))
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
static int arena_validate_allocation_size(size_t size)
{
    return (size > 0 && size <= ARENA_MAX_ALLOC_SIZE) ?
           ARENA_SIZE_VALID : ARENA_SIZE_INVALID;
}

/**
 * arena_calculate_aligned_size - Calculate properly aligned allocation size
 * @nbytes: Requested allocation size
 *
 * Returns: Aligned size, or 0 on overflow/underflow/invalid size
 * Thread-safe: Yes
 *
 * This function ensures the requested size is properly aligned and doesn't
 * cause integer overflow during size calculations.
 */
static size_t arena_calculate_aligned_size(size_t nbytes)
{
    size_t alignment;
    size_t aligned_bytes;
    size_t final_size;

    /* Validate input size */
    if (arena_validate_allocation_size(nbytes) == ARENA_SIZE_INVALID)
        return 0;

    /* Get alignment requirement */
    alignment = arena_get_alignment();

    /* Calculate aligned byte count */
    aligned_bytes = arena_calculate_aligned_bytes(nbytes, alignment);
    if (aligned_bytes == 0)
        return 0;

    /* Calculate final aligned size */
    final_size = arena_calculate_final_size(aligned_bytes, alignment);
    if (final_size == 0)
        return 0;

    /* Final validation of aligned size */
    if (arena_validate_allocation_size(final_size) == ARENA_SIZE_INVALID)
        return 0;

    return final_size;
}

/**
 * arena_reuse_free_chunk - Try to get a chunk from the free chunk pool
 * @ptr_out: Output pointer for chunk header
 * @limit_out: Output pointer for chunk limit
 *
 * Returns: ARENA_CHUNK_REUSED if chunk was reused, ARENA_CHUNK_NOT_REUSED otherwise
 * Thread-safe: Yes (uses global arena_mutex)
 */
static int arena_reuse_free_chunk(struct ChunkHeader **ptr_out, char **limit_out)
{
    struct ChunkHeader *ptr;

    pthread_mutex_lock(&arena_mutex);
    if ((ptr = freechunks) != NULL)
    {
        freechunks = freechunks->prev;
        nfree--;
        *ptr_out = ptr;
        *limit_out = ptr->limit;
        pthread_mutex_unlock(&arena_mutex);
        return ARENA_CHUNK_REUSED;
    }
    pthread_mutex_unlock(&arena_mutex);
    return ARENA_CHUNK_NOT_REUSED;
}

/**
 * arena_calculate_chunk_size - Calculate size for new chunk allocation
 * @min_size: Minimum size required
 *
 * Returns: Chunk size to allocate
 * Thread-safe: Yes
 */
static size_t arena_calculate_chunk_size(size_t min_size)
{
    size_t chunk_size = ARENA_CHUNK_SIZE;
    return (chunk_size < min_size) ? min_size : chunk_size;
}

/**
 * arena_validate_chunk_size - Validate chunk size won't cause overflow
 * @chunk_size: Requested chunk size
 *
 * Returns: Total size including header, or 0 on overflow
 * Thread-safe: Yes
 */
static size_t arena_validate_chunk_size(size_t chunk_size)
{
    size_t total_size;

    if (ARENA_CHECK_OVERFLOW_ADD(sizeof(union header), chunk_size))
        return 0;

    total_size = sizeof(union header) + chunk_size;

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
static int arena_allocate_new_chunk(size_t total_size, struct ChunkHeader **ptr_out, char **limit_out)
{
    struct ChunkHeader *ptr;

    ptr = malloc(total_size);
    if (ptr == NULL)
    {
        ARENA_ERROR_MSG("Cannot allocate new chunk: %zu bytes", total_size);
        return ARENA_FAILURE;
    }

    if (!ARENA_VALID_PTR_ARITH(ptr, total_size, (void *)UINTPTR_MAX))
    {
        free(ptr);
        ARENA_ERROR_MSG("Invalid pointer arithmetic for chunk allocation");
        return ARENA_FAILURE;
    }

    *ptr_out = ptr;
    *limit_out = (char *)ptr + total_size;
    return ARENA_SUCCESS;
}

/**
 * arena_link_chunk - Link a chunk into the arena structure
 * @arena: Arena to link chunk into
 * @ptr: Chunk header to link
 * @limit: Chunk limit pointer
 *
 * Thread-safe: Must be called with arena->mutex held
 */
static void arena_link_chunk(T arena, struct ChunkHeader *ptr, char *limit)
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
 *
 * Returns: ARENA_SUCCESS on success, ARENA_FAILURE on failure
 * Thread-safe: Must be called with arena->mutex held
 */
static int arena_allocate_chunk(T arena, size_t min_size)
{
    struct ChunkHeader *ptr;
    char *limit;
    size_t chunk_size;
    size_t total_size;

    if (arena_reuse_free_chunk(&ptr, &limit) == ARENA_CHUNK_REUSED)
        goto link_chunk;

    chunk_size = arena_calculate_chunk_size(min_size);
    total_size = arena_validate_chunk_size(chunk_size);
    if (total_size == 0)
    {
        ARENA_ERROR_MSG("Invalid chunk size calculation: %zu", chunk_size);
        return ARENA_FAILURE;
    }

    if (arena_allocate_new_chunk(total_size, &ptr, &limit) != ARENA_SUCCESS)
        return ARENA_FAILURE;

link_chunk:
    arena_link_chunk(arena, ptr, limit);
    return ARENA_SUCCESS;
}

/**
 * arena_has_space - Check if current chunk has enough space
 * @arena: Arena to check
 * @aligned_size: Required aligned size
 *
 * Returns: ARENA_VALIDATION_SUCCESS if space available, ARENA_VALIDATION_FAILURE otherwise
 * Thread-safe: Must be called with arena->mutex held
 */
static int arena_has_space(T arena, size_t aligned_size)
{
    if (arena->avail == NULL || arena->limit == NULL)
        return ARENA_VALIDATION_FAILURE;

    return ((size_t)(arena->limit - arena->avail) >= aligned_size) ?
           ARENA_VALIDATION_SUCCESS : ARENA_VALIDATION_FAILURE;
}

/**
 * arena_ensure_space - Ensure arena has enough space for allocation
 * @arena: Arena needing space
 * @aligned_size: Required aligned size
 *
 * Returns: ARENA_SUCCESS on success, ARENA_FAILURE on failure
 * Thread-safe: Must be called with arena->mutex held
 */
static int arena_ensure_space(T arena, size_t aligned_size)
{
    while (arena_has_space(arena, aligned_size) == ARENA_VALIDATION_FAILURE)
    {
        if (arena_allocate_chunk(arena, aligned_size) != ARENA_SUCCESS)
            return ARENA_FAILURE;
    }
    return ARENA_SUCCESS;
}

/**
 * arena_validate_state - Validate arena state before allocation
 * @arena: Arena to validate
 *
 * Returns: ARENA_VALIDATION_SUCCESS if valid, ARENA_VALIDATION_FAILURE otherwise
 * Thread-safe: Must be called with arena->mutex held
 */
static int arena_validate_state(T arena)
{
    return (arena->limit != NULL && arena->avail != NULL && arena->limit >= arena->avail) ?
           ARENA_VALIDATION_SUCCESS : ARENA_VALIDATION_FAILURE;
}

/**
 * arena_perform_allocation - Perform the actual memory allocation
 * @arena: Arena to allocate from
 * @aligned_size: Aligned size to allocate
 *
 * Returns: Pointer to allocated memory
 * Thread-safe: Must be called with arena->mutex held and validated state
 */
static void *arena_perform_allocation(T arena, size_t aligned_size)
{
    void *result = arena->avail;
    arena->avail += aligned_size;
    return result;
}

/**
 * arena_allocate_structure - Allocate and initialize arena structure
 *
 * Returns: Pointer to allocated arena structure, or NULL on failure
 * Thread-safe: Yes
 */
static T arena_allocate_structure(void)
{
    T arena;

    arena = malloc(sizeof(*arena));
    if (arena == NULL)
    {
        ARENA_ERROR_MSG(ARENA_ENOMEM ": Cannot allocate arena structure");
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
static int arena_initialize_mutex(T arena)
{
    if (pthread_mutex_init(&arena->mutex, NULL) != 0)
    {
        ARENA_ERROR_MSG("Failed to initialize arena mutex");
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
static void arena_initialize_state(T arena)
{
    arena->prev = NULL;
    arena->avail = NULL;
    arena->limit = NULL;
}

/**
 * Arena_new - Create a new arena instance
 *
 * Returns: New arena instance, or raises Arena_Failed on error
 * Raises: Arena_Failed if allocation or mutex initialization fails
 * Thread-safe: Yes
 *
 * Creates a new arena allocator with thread-safe allocation support.
 * The arena manages memory in chunks and provides efficient allocation
 * without individual free operations. All memory is freed when the arena
 * is disposed.
 */
T Arena_new(void)
{
    T arena;

    /* Allocate arena structure */
    arena = arena_allocate_structure();
    if (arena == NULL)
        RAISE_ARENA_ERROR(Arena_Failed);

    /* Initialize mutex with error checking */
    if (arena_initialize_mutex(arena) != ARENA_SUCCESS)
    {
        free(arena);
        RAISE_ARENA_ERROR(Arena_Failed);
    }

    /* Initialize arena state */
    arena_initialize_state(arena);

    return arena;
}

/**
 * Arena_dispose - Dispose of an arena and all its allocations
 * @ap: Pointer to arena pointer (will be set to NULL)
 *
 * Frees all memory allocated from this arena including the arena structure itself.
 * After this call, the arena pointer is invalid and should not be used.
 *
 * Raises: None (void function)
 * Thread-safe: Yes (but arena should not be used concurrently during disposal)
 * Pre-conditions: ap != NULL, *ap != NULL
 */
void Arena_dispose(T *ap)
{
    assert(ap && *ap);

    /* Clear all allocations first */
    Arena_clear(*ap);

    /* Destroy per-arena mutex */
    pthread_mutex_destroy(&(*ap)->mutex);

    /* Free arena structure and nullify pointer */
    free(*ap);
    *ap = NULL;
}

/**
 * arena_validate_allocation_request - Validate allocation request parameters
 * @arena: Arena to allocate from
 * @nbytes: Number of bytes to allocate
 *
 * Returns: ARENA_SUCCESS if valid, ARENA_FAILURE if invalid
 * Thread-safe: Yes
 */
static int arena_validate_allocation_request(T arena, size_t nbytes)
{
    assert(arena);
    assert(nbytes > 0);

    return ARENA_SUCCESS;
}

/**
 * arena_prepare_allocation - Prepare allocation by calculating aligned size
 * @nbytes: Number of bytes requested
 *
 * Returns: Aligned size for allocation, or 0 on error
 * Thread-safe: Yes
 */
static size_t arena_prepare_allocation(size_t nbytes)
{
    size_t aligned_size;

    aligned_size = arena_calculate_aligned_size(nbytes);
    if (aligned_size == 0)
    {
        ARENA_ERROR_MSG("Invalid allocation size: %zu bytes (alignment/overflow error)", nbytes);
        return 0;
    }

    return aligned_size;
}

/**
 * arena_execute_allocation - Execute the allocation under mutex protection
 * @arena: Arena to allocate from
 * @aligned_size: Aligned size to allocate
 * @nbytes: Original requested size (for error messages)
 *
 * Returns: Pointer to allocated memory
 * Thread-safe: Must be called without holding arena mutex
 */
static void *arena_execute_allocation(T arena, size_t aligned_size, size_t nbytes)
{
    void * volatile result;

    pthread_mutex_lock(&arena->mutex);

    TRY {
        if (arena_ensure_space(arena, aligned_size) != ARENA_SUCCESS)
        {
            ARENA_ERROR_MSG("Failed to ensure space for %zu-byte allocation", nbytes);
            RAISE_ARENA_ERROR(Arena_Failed);
        }

        if (arena_validate_state(arena) != ARENA_VALIDATION_SUCCESS)
        {
            ARENA_ERROR_MSG("Arena in invalid state during allocation");
            RAISE_ARENA_ERROR(Arena_Failed);
        }

        result = arena_perform_allocation(arena, aligned_size);
    }
    FINALLY
    pthread_mutex_unlock(&arena->mutex);
    END_TRY;

    return result;
}

/**
 * Arena_alloc - Allocate memory from arena
 * @arena: Arena to allocate from
 * @nbytes: Number of bytes to allocate
 * @file: Source file name (for debugging)
 * @line: Source line number (for debugging)
 *
 * Returns: Pointer to allocated memory, or raises Arena_Failed on error
 * Raises: Arena_Failed if allocation fails due to insufficient space or overflow
 * Thread-safe: Yes
 * Pre-conditions: arena != NULL, nbytes > 0
 *
 * Allocates memory from the arena with proper alignment and overflow protection.
 * The allocated memory remains valid until the arena is cleared or disposed.
 * No individual free is needed - all memory is managed by the arena lifetime.
 */
void *Arena_alloc(T arena, size_t nbytes, const char *file, int line)
{
    size_t aligned_size;
    void *result;

    /* Validate request parameters */
    if (arena_validate_allocation_request(arena, nbytes) != ARENA_SUCCESS)
        RAISE_ARENA_ERROR(Arena_Failed);

    /* Suppress unused parameter warnings */
    (void)file;
    (void)line;

    /* Prepare allocation */
    aligned_size = arena_prepare_allocation(nbytes);
    if (aligned_size == 0)
        RAISE_ARENA_ERROR(Arena_Failed);

    /* Execute allocation */
    result = arena_execute_allocation(arena, aligned_size, nbytes);

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
 * Returns: Pointer to zeroed memory, or raises Arena_Failed on error
 * Raises: Arena_Failed if allocation fails or overflow occurs
 * Thread-safe: Yes
 * Pre-conditions: arena != NULL, count > 0, nbytes > 0
 *
 * Allocates count * nbytes of memory from the arena and initializes it to zero.
 * Uses Arena_alloc internally with overflow protection for the multiplication.
 */
void *Arena_calloc(T arena, size_t count, size_t nbytes, const char *file, int line)
{
    void *ptr;
    size_t total;

    assert(arena);
    assert(count > 0);
    assert(nbytes > 0);

    /* Check for multiplication overflow before calculating total */
    if (ARENA_CHECK_OVERFLOW_MUL(count, nbytes))
    {
        ARENA_ERROR_MSG("calloc overflow: count=%zu, nbytes=%zu", count, nbytes);
        RAISE_ARENA_ERROR(Arena_Failed);
    }

    total = count * nbytes;

    /* Additional sanity check against maximum allocation size */
    if (total > ARENA_MAX_ALLOC_SIZE)
    {
        ARENA_ERROR_MSG("calloc size exceeds maximum: %zu", total);
        RAISE_ARENA_ERROR(Arena_Failed);
    }

    /* Allocate memory */
    ptr = Arena_alloc(arena, total, file, line);
    if (ptr == NULL)
    {
        /* Arena_alloc already raised exception */
        RERAISE;
    }

    /* Zero the allocated memory */
    memset(ptr, 0, total);
    return ptr;
}

/**
 * arena_return_chunk_to_pool - Return chunk to global free pool or free it
 * @chunk: Chunk to return
 *
 * Thread-safe: Yes (uses global arena_mutex)
 */
static void arena_return_chunk_to_pool(struct ChunkHeader *chunk)
{
    assert(chunk);

    pthread_mutex_lock(&arena_mutex);

    if (nfree < ARENA_MAX_FREE_CHUNKS)
    {
        /* Add to free list for reuse */
        chunk->prev = freechunks;
        freechunks = chunk;
        nfree++;
        pthread_mutex_unlock(&arena_mutex);
    }
    else
    {
        /* Free list is full, free the chunk */
        pthread_mutex_unlock(&arena_mutex);
        free(chunk);
    }
}

/**
 * arena_process_chunk - Process and remove one chunk from arena
 * @arena: Arena to process chunk from
 *
 * Returns: ARENA_VALIDATION_SUCCESS if chunk was processed, ARENA_VALIDATION_FAILURE if no more chunks
 * Thread-safe: Must be called with arena->mutex held
 */
static int arena_process_chunk(T arena)
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

    arena_return_chunk_to_pool(chunk_to_process);
    return ARENA_VALIDATION_SUCCESS;
}

/**
 * arena_clear_all_chunks - Clear all chunks from arena
 * @arena: Arena to clear
 *
 * Thread-safe: Must be called with arena->mutex held
 */
static void arena_clear_all_chunks(T arena)
{
    while (arena_process_chunk(arena) == ARENA_VALIDATION_SUCCESS)
        /* Process all chunks */;
}

/**
 * arena_verify_initial_state - Verify arena is in initial empty state
 * @arena: Arena to verify
 *
 * Thread-safe: Must be called with arena->mutex held
 */
static void arena_verify_initial_state(T arena)
{
    assert(arena->prev == NULL);
    assert(arena->avail == NULL);
    assert(arena->limit == NULL);
}

/**
 * Arena_clear - Clear all allocations from arena
 * @arena: Arena to clear
 *
 * Releases all memory chunks back to the free pool without freeing the arena structure.
 * The arena can be reused for new allocations after clearing.
 *
 * Raises: None (void function)
 * Thread-safe: Yes
 * Pre-conditions: arena != NULL
 */
void Arena_clear(T arena)
{
    assert(arena);

    pthread_mutex_lock(&arena->mutex);
    arena_clear_all_chunks(arena);
    arena_verify_initial_state(arena);
    pthread_mutex_unlock(&arena->mutex);
}

#undef T

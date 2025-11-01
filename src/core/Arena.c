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

/* Free chunk cache configuration - defined in SocketConfig.h */

/* Thread-safe free chunk cache for reuse */
static struct ChunkHeader *freechunks = NULL;
static int nfree = 0;
static pthread_mutex_t arena_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Helper macros for overflow protection */
#define ARENA_CHECK_OVERFLOW_ADD(a, b) (((a) > SIZE_MAX - (b)) ? 1 : 0)
#define ARENA_CHECK_OVERFLOW_MUL(a, b) (((a) != 0 && (b) > SIZE_MAX / (a)) ? 1 : 0)

/* Helper macro for safe pointer arithmetic validation */
#define ARENA_VALID_PTR_ARITH(ptr, offset, max)                                                                        \
    (((uintptr_t)(ptr) <= UINTPTR_MAX - (offset)) && ((uintptr_t)(ptr) + (offset) <= (uintptr_t)(max)))

/**
 * arena_new_internal - Internal arena creation with proper error handling
 *
 * Returns: New arena instance, or NULL on allocation failure
 *
 * Thread-safe: Yes (creates per-arena mutex)
 * Error conditions: malloc failure, mutex initialization failure
 */
T Arena_new(void)
{
    T arena;

    /* Allocate arena structure */
    arena = malloc(sizeof(*arena));
    if (arena == NULL)
        return NULL;

    /* Initialize mutex with error checking */
    if (pthread_mutex_init(&arena->mutex, NULL) != 0)
    {
        free(arena);
        return NULL;
    }

    /* Initialize arena state */
    arena->prev = NULL;
    arena->avail = NULL;
    arena->limit = NULL;

    return arena;
}

/**
 * Arena_dispose - Dispose of an arena and all its allocations
 * @ap: Pointer to arena pointer (will be set to NULL)
 *
 * Frees all memory allocated from this arena including the arena structure itself.
 * After this call, the arena pointer is invalid and should not be used.
 *
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
 * arena_get_alignment - Get alignment size for memory allocations
 *
 * Returns: Alignment size (at least 1)
 */
static size_t arena_get_alignment(void)
{
    size_t alignment = sizeof(union align);
    return (alignment == 0) ? 1 : alignment;
}

/**
 * arena_check_size_overflow - Check if size calculation would overflow
 * @nbytes: Base size
 * @alignment: Alignment requirement
 *
 * Returns: Non-zero if overflow, zero otherwise
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
 */
static size_t arena_calculate_final_size(size_t aligned_bytes, size_t alignment)
{
    if (ARENA_CHECK_OVERFLOW_MUL(aligned_bytes, alignment))
        return 0;

    return aligned_bytes * alignment;
}

/**
 * arena_calculate_aligned_size - Calculate properly aligned allocation size
 * @nbytes: Requested allocation size
 *
 * Returns: Aligned size, or 0 on overflow/underflow
 *
 * This function ensures the requested size is properly aligned and doesn't
 * cause integer overflow during size calculations.
 */
static size_t arena_calculate_aligned_size(size_t nbytes)
{
    size_t alignment;
    size_t aligned_bytes;
    size_t final_size;

    alignment = arena_get_alignment();
    aligned_bytes = arena_calculate_aligned_bytes(nbytes, alignment);
    if (aligned_bytes == 0)
        return 0;

    final_size = arena_calculate_final_size(aligned_bytes, alignment);
    if (final_size == 0)
        return 0;

    if (final_size > ARENA_MAX_ALLOC_SIZE)
        return 0;

    return final_size;
}

/**
 * arena_reuse_free_chunk - Try to get a chunk from the free chunk pool
 * @ptr_out: Output pointer for chunk header
 * @limit_out: Output pointer for chunk limit
 *
 * Returns: Non-zero if chunk was reused, zero otherwise
 *
 * Thread-safe: Uses global arena_mutex
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
        return 1;
    }
    pthread_mutex_unlock(&arena_mutex);
    return 0;
}

/**
 * arena_calculate_chunk_size - Calculate size for new chunk allocation
 * @min_size: Minimum size required
 *
 * Returns: Chunk size to allocate
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
 * Returns: 0 on success, -1 on failure
 */
static int arena_allocate_new_chunk(size_t total_size, struct ChunkHeader **ptr_out, char **limit_out)
{
    struct ChunkHeader *ptr;

    ptr = malloc(total_size);
    if (ptr == NULL)
        return -1;

    if (!ARENA_VALID_PTR_ARITH(ptr, total_size, (void *)UINTPTR_MAX))
    {
        free(ptr);
        return -1;
    }

    *ptr_out = ptr;
    *limit_out = (char *)ptr + total_size;
    return 0;
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
 * Returns: 0 on success, -1 on failure
 *
 * Thread-safe: Must be called with arena->mutex held
 */
static int arena_allocate_chunk(T arena, size_t min_size)
{
    struct ChunkHeader *ptr;
    char *limit;
    size_t chunk_size;
    size_t total_size;

    if (arena_reuse_free_chunk(&ptr, &limit))
        goto link_chunk;

    chunk_size = arena_calculate_chunk_size(min_size);
    total_size = arena_validate_chunk_size(chunk_size);
    if (total_size == 0)
        return -1;

    if (arena_allocate_new_chunk(total_size, &ptr, &limit) != 0)
        return -1;

link_chunk:
    arena_link_chunk(arena, ptr, limit);
    return 0;
}

/**
 * arena_has_space - Check if current chunk has enough space
 * @arena: Arena to check
 * @aligned_size: Required aligned size
 *
 * Returns: Non-zero if space available, zero otherwise
 */
static int arena_has_space(T arena, size_t aligned_size)
{
    if (arena->avail == NULL || arena->limit == NULL)
        return 0;

    return (size_t)(arena->limit - arena->avail) >= aligned_size;
}

/**
 * arena_ensure_space - Ensure arena has enough space for allocation
 * @arena: Arena needing space
 * @aligned_size: Required aligned size
 *
 * Returns: 0 on success, -1 on failure
 *
 * Thread-safe: Must be called with arena->mutex held
 */
static int arena_ensure_space(T arena, size_t aligned_size)
{
    while (!arena_has_space(arena, aligned_size))
    {
        if (arena_allocate_chunk(arena, aligned_size) != 0)
            return -1;
    }
    return 0;
}

/**
 * arena_validate_state - Validate arena state before allocation
 * @arena: Arena to validate
 *
 * Returns: Non-zero if valid, zero otherwise
 */
static int arena_validate_state(T arena)
{
    return (arena->limit != NULL && arena->avail != NULL && arena->limit >= arena->avail);
}

/**
 * arena_perform_allocation - Perform the actual memory allocation
 * @arena: Arena to allocate from
 * @aligned_size: Aligned size to allocate
 *
 * Returns: Pointer to allocated memory
 *
 * Thread-safe: Must be called with arena->mutex held and validated state
 */
static void *arena_perform_allocation(T arena, size_t aligned_size)
{
    void *result = arena->avail;
    arena->avail += aligned_size;
    return result;
}

void *Arena_alloc(T arena, size_t nbytes, const char *file, int line)
{
    size_t aligned_size;
    void *result;

    assert(arena);
    assert(nbytes > 0);
    (void)file;
    (void)line;

    aligned_size = arena_calculate_aligned_size(nbytes);
    if (aligned_size == 0)
        return NULL;

    pthread_mutex_lock(&arena->mutex);

    if (arena_ensure_space(arena, aligned_size) != 0)
    {
        pthread_mutex_unlock(&arena->mutex);
        return NULL;
    }

    if (!arena_validate_state(arena))
    {
        pthread_mutex_unlock(&arena->mutex);
        return NULL;
    }

    result = arena_perform_allocation(arena, aligned_size);
    pthread_mutex_unlock(&arena->mutex);

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
 * Returns: Pointer to zeroed memory, or NULL on failure
 *
 * Thread-safe: Yes
 * Pre-conditions: arena != NULL, count > 0, nbytes > 0
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
        return NULL;

    total = count * nbytes;

    /* Additional sanity check against maximum allocation size */
    if (total > ARENA_MAX_ALLOC_SIZE)
        return NULL;

    /* Allocate memory */
    ptr = Arena_alloc(arena, total, file, line);
    if (ptr == NULL)
        return NULL;

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
 * Returns: Non-zero if chunk was processed, zero if no more chunks
 *
 * Thread-safe: Must be called with arena->mutex held
 */
static int arena_process_chunk(T arena)
{
    struct ChunkHeader *chunk_to_process;
    struct ChunkHeader saved_state;

    if (arena->prev == NULL)
        return 0;

    chunk_to_process = arena->prev;
    saved_state = *chunk_to_process;

    arena->prev = saved_state.prev;
    arena->avail = saved_state.avail;
    arena->limit = saved_state.limit;

    arena_return_chunk_to_pool(chunk_to_process);
    return 1;
}

/**
 * arena_clear_all_chunks - Clear all chunks from arena
 * @arena: Arena to clear
 *
 * Thread-safe: Must be called with arena->mutex held
 */
static void arena_clear_all_chunks(T arena)
{
    while (arena_process_chunk(arena))
        /* Process all chunks */;
}

/**
 * arena_verify_initial_state - Verify arena is in initial empty state
 * @arena: Arena to verify
 */
static void arena_verify_initial_state(T arena)
{
    assert(arena->prev == NULL);
    assert(arena->avail == NULL);
    assert(arena->limit == NULL);
}

void Arena_clear(T arena)
{
    assert(arena);

    pthread_mutex_lock(&arena->mutex);
    arena_clear_all_chunks(arena);
    arena_verify_initial_state(arena);
    pthread_mutex_unlock(&arena->mutex);
}

#undef T

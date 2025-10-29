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

#include "Arena.h"
#include "SocketConfig.h"

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

/* Free chunk cache for reuse */
#define MAX_FREE_CHUNKS 10

static struct ChunkHeader *freechunks = NULL;
static int nfree = 0;
static pthread_mutex_t arena_mutex = PTHREAD_MUTEX_INITIALIZER;

T Arena_new(void)
{
    T arena = malloc(sizeof(*arena));
    if (arena == NULL)
        return NULL;

    /* Initialize mutex */
    if (pthread_mutex_init(&arena->mutex, NULL) != 0)
    {
        free(arena);
        return NULL;
    }

    arena->prev = NULL;
    arena->limit = arena->avail = NULL;
    return arena;
}

void Arena_dispose(T *ap)
{
    assert(ap && *ap);
    Arena_clear(*ap);

    /* Destroy mutex */
    pthread_mutex_destroy(&(*ap)->mutex);

    free(*ap);
    *ap = NULL;
}

void *Arena_alloc(T arena, size_t nbytes, const char *file, int line)
{
    void *result;

    assert(arena);
    assert(nbytes > 0);
    (void)file;
    (void)line;

    size_t alignment = sizeof(union align);

    /* Ensure alignment is never zero */
    if (alignment == 0)
        alignment = 1;

    /* Check for overflow */
    if (nbytes > SIZE_MAX - (alignment - 1))
        return NULL;

    /* Calculate aligned size */
    size_t sum = nbytes + alignment - 1;
    size_t aligned_bytes = sum / alignment;

    /* Check multiplication overflow */
    if (aligned_bytes > SIZE_MAX / alignment)
        return NULL;

    nbytes = aligned_bytes * alignment;

    /* Check against maximum allocation size */
    if (nbytes > ARENA_MAX_ALLOC_SIZE)
        return NULL;

    /* Lock arena for thread safety */
    pthread_mutex_lock(&arena->mutex);

    /* Check available space */
    while (arena->avail == NULL || arena->limit == NULL || arena->limit - arena->avail < (ptrdiff_t)nbytes)
    {
        struct ChunkHeader *ptr;
        char *limit;

        pthread_mutex_lock(&arena_mutex);
        if ((ptr = freechunks) != NULL)
        {
            freechunks = freechunks->prev;
            nfree--;
            limit = ptr->limit;
            pthread_mutex_unlock(&arena_mutex);
        }
        else
        {
            pthread_mutex_unlock(&arena_mutex);
            size_t chunk_size = ARENA_CHUNK_SIZE;

            /* Check for overflow */
            if (sizeof(union header) > SIZE_MAX - nbytes)
            {
                pthread_mutex_unlock(&arena->mutex);
                return NULL;
            }

            size_t temp = sizeof(union header) + nbytes;
            if (chunk_size > SIZE_MAX - temp)
            {
                pthread_mutex_unlock(&arena->mutex);
                return NULL;
            }

            size_t m = temp + chunk_size;

            /* Ensure we don't exceed maximum allocation size */
            if (m > ARENA_MAX_ALLOC_SIZE)
            {
                pthread_mutex_unlock(&arena->mutex);
                return NULL;
            }

            /* Check for integer overflow in addition (m < operand means overflow occurred) */
            if (m < temp || m < chunk_size)
            {
                pthread_mutex_unlock(&arena->mutex);
                return NULL;
            }

            ptr = malloc(m);
            if (ptr == NULL)
            {
                pthread_mutex_unlock(&arena->mutex);
                return NULL;
            }

            /* Check pointer arithmetic won't overflow */
            if ((uintptr_t)ptr > UINTPTR_MAX - m)
            {
                free(ptr);
                pthread_mutex_unlock(&arena->mutex);
                return NULL;
            }

            limit = (char *)ptr + m;
        }
        /* Safe to copy chunk fields - ChunkHeader has no mutex to worry about */
        ptr->prev = arena->prev;
        ptr->avail = arena->avail;
        ptr->limit = arena->limit;

        arena->avail = (char *)((union header *)ptr + 1);
        arena->limit = limit;
        arena->prev = ptr;
    }

    /* Validate pointers before arithmetic to prevent underflow */
    if (arena->limit == NULL || arena->avail == NULL || arena->limit < arena->avail)
    {
        pthread_mutex_unlock(&arena->mutex);
        return NULL;
    }

    /* Safe to perform subtraction now */
    if ((size_t)(arena->limit - arena->avail) < nbytes)
    {
        pthread_mutex_unlock(&arena->mutex);
        return NULL;
    }

    arena->avail += nbytes;
    result = arena->avail - nbytes;

    /* Unlock arena before returning */
    pthread_mutex_unlock(&arena->mutex);

    return result;
}

void *Arena_calloc(T arena, size_t count, size_t nbytes, const char *file, int line)
{
    void *ptr;
    assert(arena);
    assert(count > 0);
    assert(nbytes > 0);

    /* Check for multiplication overflow */
    if (count > SIZE_MAX / nbytes)
        return NULL;

    size_t total = count * nbytes;

    /* Additional sanity check */
    if (total > ARENA_MAX_ALLOC_SIZE)
        return NULL;

    ptr = Arena_alloc(arena, total, file, line);
    if (ptr)
        memset(ptr, 0, total);
    return ptr;
}

void Arena_clear(T arena)
{
    assert(arena);

    /* Lock per-arena mutex for thread-safe cleanup */
    pthread_mutex_lock(&arena->mutex);

    /* Protect entire free operation with mutex to prevent race conditions */
    while (arena->prev)
    {
        struct ChunkHeader *prev_chunk;
        struct ChunkHeader *chunk_to_free = NULL;
        /* Save the arena state stored in the chunk header BEFORE modifying it */
        struct ChunkHeader *saved_prev;
        char *saved_avail;
        char *saved_limit;

        /* Save pointer to chunk and the arena state stored within it
         * Note: arena->prev is protected by arena->mutex which we're holding */
        prev_chunk = arena->prev;
        saved_prev = prev_chunk->prev;
        saved_avail = prev_chunk->avail;
        saved_limit = prev_chunk->limit;

        /* Now update the arena state to point to previous chunk */
        arena->prev = saved_prev;
        arena->avail = saved_avail;
        arena->limit = saved_limit;

        /* Now decide what to do with prev_chunk - add to free list or free it
         * This requires the global freechunks mutex */
        pthread_mutex_lock(&arena_mutex);

        if (nfree < MAX_FREE_CHUNKS)
        {
            /* Add to free list - this MODIFIES the chunk fields */
            prev_chunk->prev = freechunks;
            freechunks = prev_chunk;
            nfree++;
            /* Note: limit field is preserved from original allocation, no need to update */
        }
        else
        {
            chunk_to_free = prev_chunk;
        }

        pthread_mutex_unlock(&arena_mutex);

        /* Free outside mutex to avoid holding lock during potentially slow operation */
        if (chunk_to_free)
            free(chunk_to_free);
    }

    /* After freeing all chunks, arena should be in initial state */
    assert(arena->limit == NULL);
    assert(arena->avail == NULL);
    assert(arena->prev == NULL);

    /* Unlock per-arena mutex */
    pthread_mutex_unlock(&arena->mutex);
}

#undef T

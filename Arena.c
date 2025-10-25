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

struct T
{
    T prev;
    char *avail;
    char *limit;
    pthread_mutex_t mutex; /* Per-arena mutex for thread-safe allocation */
};

/* Alignment union - ensures proper alignment for all data types
 * The union contains all fundamental types to determine the strictest
 * alignment requirement across different platforms */
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

/* Header union - combines arena metadata with alignment requirements
 * The union ensures that:
 * 1. Header is properly aligned (via union align member)
 * 2. Memory following header starts at aligned boundary
 * 3. Size of header is rounded up to alignment boundary
 */
union header {
    struct T b;
    union align a;
};

/* Free chunk cache - keeps up to MAX_FREE_CHUNKS chunks for reuse */
#define MAX_FREE_CHUNKS 10

static T freechunks = NULL;
static int nfree = 0;
static pthread_mutex_t arena_mutex = PTHREAD_MUTEX_INITIALIZER;

T Arena_new(void)
{
    T arena = malloc(sizeof(*arena));
    if (arena == NULL)
        return NULL;

    /* Initialize per-arena mutex */
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

    /* Destroy per-arena mutex */
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

    /* Ensure alignment is never zero (defensive programming) */
    if (alignment == 0)
        alignment = 1;

    /* Check for overflow before calculation */
    if (nbytes > SIZE_MAX - (alignment - 1))
        return NULL;

    /* Calculate aligned_bytes safely */
    size_t sum = nbytes + alignment - 1;
    size_t aligned_bytes = sum / alignment;

    /* Check if multiplication would overflow */
    if (aligned_bytes > SIZE_MAX / alignment)
        return NULL;

    nbytes = aligned_bytes * alignment;

    /* Final sanity check against maximum allocation size */
    if (nbytes > ARENA_MAX_ALLOC_SIZE)
        return NULL;

    /* Lock arena for thread-safe allocation */
    pthread_mutex_lock(&arena->mutex);

    /* Use safer pointer subtraction check instead of addition */
    while (arena->avail == NULL || arena->limit == NULL || arena->limit - arena->avail < (ptrdiff_t)nbytes)
    {
        T ptr;
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

            /* Check for overflow before calculation */
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
        /* Copy only the arena fields, NOT the mutex (undefined behavior to copy mutex) */
        ptr->prev = arena->prev;
        ptr->avail = arena->avail;
        ptr->limit = arena->limit;
        /* Note: ptr->mutex field is not used in chunk headers - only prev/avail/limit matter */

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
        T prev_chunk;
        T chunk_to_free = NULL;
        /* Save the arena state stored in the chunk header BEFORE modifying it */
        T saved_prev;
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
        /* Note: arena->mutex remains unchanged - do NOT copy it */

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

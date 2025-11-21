#ifndef ARENA_PRIVATE_INCLUDED
#define ARENA_PRIVATE_INCLUDED

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"  /* For T, types */
#include "core/SocketError.h"  /* For Socket_safe_strerror */

#include "core/SocketConfig.h"  /* For constants */

#define T Arena_T

/* Internal structures */
struct ChunkHeader {
    struct ChunkHeader *prev;
    char *avail;
    char *limit;
    size_t chunk_size; /* Actual size of this chunk (for proper reuse) */
};

union header {
    struct ChunkHeader b;
    union align a;
};

/* Main arena structure - includes mutex for thread safety */
struct T {
    struct ChunkHeader *prev;
    char *avail;
    char *limit;
    pthread_mutex_t mutex; /* Per-arena mutex for thread-safe allocation */
};

/**
 * Private internal functions for Arena module - not part of public API.
 * Used by Arena implementation and sub-modules.
 * Thread-safe where noted.
 */

/* Chunk management private functions */
extern int arena_reuse_free_chunk(struct ChunkHeader **ptr_out, char **limit_out);
extern size_t arena_calculate_chunk_size(size_t min_size);
extern size_t arena_validate_chunk_size(size_t chunk_size);
extern int arena_allocate_new_chunk(size_t total_size, struct ChunkHeader **ptr_out, char **limit_out);
extern void arena_link_chunk(T arena, struct ChunkHeader *ptr, char *limit);
extern int arena_allocate_chunk(T arena, size_t min_size);
extern void arena_return_chunk_to_pool(struct ChunkHeader *chunk);
extern int arena_process_chunk(T arena);
extern void arena_clear_all_chunks(T arena);
extern void arena_verify_initial_state(T arena);

/* Allocation private functions */
extern size_t arena_get_alignment(void);
extern int arena_check_size_overflow(size_t nbytes, size_t alignment);
extern size_t arena_calculate_aligned_bytes(size_t nbytes, size_t alignment);
extern size_t arena_calculate_final_size(size_t aligned_bytes, size_t alignment);
extern int arena_validate_allocation_size(size_t size);
extern size_t arena_calculate_aligned_size(size_t nbytes);
extern size_t arena_prepare_allocation(size_t nbytes);
extern void arena_validate_calloc_overflow(size_t count, size_t nbytes);
extern void arena_validate_calloc_size(size_t total);
extern void arena_zero_memory(void *ptr, size_t total);
extern int arena_has_space(T arena, size_t aligned_size);
extern int arena_ensure_space(T arena, size_t aligned_size);
extern void *arena_perform_allocation(T arena, size_t aligned_size);
extern T arena_allocate_structure(void);
extern int arena_initialize_mutex(T arena);
extern void arena_initialize_state(T arena);
extern void arena_ensure_allocation_space(T arena, size_t aligned_size, size_t nbytes);
extern void *arena_execute_allocation(T arena, size_t aligned_size, size_t nbytes);
extern int arena_validate_allocation_request(T arena, size_t nbytes);

/* Global state */
extern struct ChunkHeader *freechunks;
extern int nfree;
extern pthread_mutex_t arena_mutex;

/* Thread-local error handling globals */
#ifdef _WIN32
extern __declspec(thread) char arena_error_buf[ARENA_ERROR_BUFSIZE];
extern __declspec(thread) Except_T Arena_DetailedException;
#else
extern __thread char arena_error_buf[ARENA_ERROR_BUFSIZE];
extern __thread Except_T Arena_DetailedException;
#endif

/* Overflow and validation macros */
#define ARENA_CHECK_OVERFLOW_ADD(a, b) (((a) > SIZE_MAX - (b)) ? ARENA_VALIDATION_FAILURE : ARENA_VALIDATION_SUCCESS)
#define ARENA_CHECK_OVERFLOW_MUL(a, b) \
    (((a) != 0 && (b) > SIZE_MAX / (a)) ? ARENA_VALIDATION_FAILURE : ARENA_VALIDATION_SUCCESS)
#define ARENA_VALID_PTR_ARITH(ptr, offset, max) \
    (((uintptr_t)(ptr) <= UINTPTR_MAX - (offset)) && ((uintptr_t)(ptr) + (offset) <= (uintptr_t)(max)))

/* Error macros */
#define ARENA_ERROR_MSG(fmt, ...) snprintf(arena_error_buf, ARENA_ERROR_BUFSIZE, fmt, ##__VA_ARGS__)
#define ARENA_ERROR_FMT(fmt, ...) \
    snprintf(arena_error_buf, ARENA_ERROR_BUFSIZE, fmt " (errno: %d - %s)", ##__VA_ARGS__, errno, Socket_safe_strerror(errno))
#define RAISE_ARENA_ERROR(base_exception) \
    do { \
        Arena_DetailedException = (base_exception); \
        Arena_DetailedException.reason = arena_error_buf; \
        RAISE(Arena_DetailedException); \
    } while (0)

#endif /* ARENA_PRIVATE_INCLUDED */

#ifndef ARENA_PRIVATE_INCLUDED
#define ARENA_PRIVATE_INCLUDED

#include "core/Arena.h"  /* For T, types */

#include "core/SocketConfig.h"  /* For constants */

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

#endif /* ARENA_PRIVATE_INCLUDED */

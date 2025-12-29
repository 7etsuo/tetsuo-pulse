/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketMetrics.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"

#define T Arena_T

struct ChunkHeader
{
  struct ChunkHeader *prev;
  char *avail;
  char *limit;
  size_t chunk_size;
};

union header
{
  struct ChunkHeader b;
  /* cppcheck-suppress unusedStructMember */
  union align a;
};

struct T
{
  struct ChunkHeader *prev;
  char *avail;
  char *limit;
  pthread_mutex_t mutex;
  int locked; /* 0 = unlocked (TLS), 1 = locked (normal) */
};

static inline size_t
chunk_total_size (const struct ChunkHeader *chunk)
{
  return sizeof (union header) + chunk->chunk_size;
}

static inline char *
chunk_limit (const struct ChunkHeader *chunk)
{
  return (char *)chunk + chunk_total_size (chunk);
}

/* Link new chunk into arena's allocation chain (must hold arena->mutex) */
static inline void
arena_link_chunk (T arena, struct ChunkHeader *ptr, char *limit)
{

  ptr->prev = arena->prev;
  ptr->avail = arena->avail;
  ptr->limit = arena->limit;

  arena->avail = (char *)((union header *)ptr + 1);
  arena->limit = limit;
  arena->prev = ptr;
}

const Except_T Arena_Failed = { &Arena_Failed, "Arena operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (Arena);

static struct ChunkHeader *freechunks = NULL;
static int nfree = 0;
static pthread_mutex_t arena_mutex = PTHREAD_MUTEX_INITIALIZER;

static _Atomic size_t global_memory_used = 0;
static _Atomic size_t global_memory_limit = 0; /* 0 = unlimited */

void
SocketConfig_set_max_memory (size_t max_bytes)
{
  atomic_store_explicit (&global_memory_limit, max_bytes,
                         memory_order_release);
}

size_t
SocketConfig_get_max_memory (void)
{
  return atomic_load_explicit (&global_memory_limit, memory_order_acquire);
}

size_t
SocketConfig_get_memory_used (void)
{
  return atomic_load_explicit (&global_memory_used, memory_order_acquire);
}

static int check_alloc_allowed (size_t current, size_t nbytes, size_t limit);

static int
global_memory_try_unlimited (size_t nbytes)
{
  atomic_fetch_add_explicit (&global_memory_used, nbytes,
                             memory_order_relaxed);
  return 1;
}

/* Allocate under limited policy with atomic CAS to prevent TOCTOU races */
static int
global_memory_try_limited (size_t limit, size_t nbytes)
{
  size_t current
      = atomic_load_explicit (&global_memory_used, memory_order_acquire);
  size_t desired;

  do
    {
      if (!check_alloc_allowed (current, nbytes, limit))
        return 0;

      desired = current + nbytes;
    }
  while (!atomic_compare_exchange_weak_explicit (&global_memory_used, &current,
                                                 desired, memory_order_acq_rel,
                                                 memory_order_acquire));

  return 1;
}

static int
global_memory_try_alloc (size_t nbytes)
{
  size_t limit
      = atomic_load_explicit (&global_memory_limit, memory_order_acquire);

  if (limit == 0)
    return global_memory_try_unlimited (nbytes);

  return global_memory_try_limited (limit, nbytes);
}

static void
global_memory_release (size_t nbytes)
{
  atomic_fetch_sub_explicit (&global_memory_used, nbytes,
                             memory_order_relaxed);
}

static int
check_alloc_allowed (size_t current, size_t nbytes, size_t limit)
{
  size_t desired;
  if (!SocketSecurity_check_add (current, nbytes, &desired))
    return 0;

  if (limit > 0 && desired > limit)
    return 0;

  return 1;
}

#define ARENA_VALID_PTR_ARITH(ptr, offset, max)                               \
  (((uintptr_t)(ptr) <= UINTPTR_MAX - (offset))                               \
   && ((uintptr_t)(ptr) + (offset) <= (uintptr_t)(max)))

static int
validate_chunk_size (size_t chunk_size, size_t *total_out)
{
  size_t total;

  if (!SocketSecurity_check_add (sizeof (union header), chunk_size, &total))
    {
      SOCKET_ERROR_MSG (
          "Chunk size overflow: sizeof(header)=%zu + chunk_size=%zu",
          sizeof (union header), chunk_size);
      return ARENA_FAILURE;
    }

  if (!SocketSecurity_check_size (total))
    {
      SOCKET_ERROR_MSG ("Chunk size exceeds maximum: %zu (limit=%zu)", total,
                        SocketSecurity_get_max_allocation ());
      return ARENA_FAILURE;
    }

  *total_out = total;
  return ARENA_SUCCESS;
}

static int
acquire_global_memory (size_t total)
{
  if (!global_memory_try_alloc (total))
    {
      SocketMetrics_counter_inc (SOCKET_CTR_LIMIT_MEMORY_EXCEEDED);
      SOCKET_ERROR_MSG ("Global memory limit exceeded: requested %zu bytes, "
                        "limit %zu, used %zu",
                        total, SocketConfig_get_max_memory (),
                        SocketConfig_get_memory_used ());
      return ARENA_FAILURE;
    }

  return ARENA_SUCCESS;
}

static struct ChunkHeader *
allocate_raw_chunk (size_t total)
{
  struct ChunkHeader *ptr = malloc (total);
  if (ptr == NULL)
    {
      global_memory_release (total);
      SOCKET_ERROR_MSG ("Cannot allocate chunk: %zu bytes", total);
      return NULL;
    }

  /* Validate pointer arithmetic won't overflow */
  if (!ARENA_VALID_PTR_ARITH (ptr, total, (void *)UINTPTR_MAX))
    {
      free (ptr);
      global_memory_release (total);
      SOCKET_ERROR_MSG ("Invalid pointer arithmetic for chunk");
      return NULL;
    }

  return ptr;
}

static int
chunk_cache_get (struct ChunkHeader **ptr_out, char **limit_out)
{
  int result = ARENA_CHUNK_NOT_REUSED;

  SOCKET_MUTEX_LOCK_OR_RAISE (&arena_mutex, Arena, Arena_Failed);

  if (freechunks != NULL)
    {
      *ptr_out = freechunks;
      freechunks = freechunks->prev;
      nfree--;
      *limit_out = chunk_limit (*ptr_out);
      result = ARENA_CHUNK_REUSED;
    }

  SOCKET_MUTEX_UNLOCK (&arena_mutex);

  return result;
}

static void
chunk_cache_return (struct ChunkHeader *chunk)
{
  int added = 0;

  assert (chunk);

  SOCKET_MUTEX_LOCK_OR_RAISE (&arena_mutex, Arena, Arena_Failed);

  if (nfree < ARENA_MAX_FREE_CHUNKS)
    {
      chunk->prev = freechunks;
      freechunks = chunk;
      nfree++;
      added = 1;
    }

  SOCKET_MUTEX_UNLOCK (&arena_mutex);

  if (!added)
    {
      size_t total_bytes = chunk_total_size (chunk);
      free (chunk);
      global_memory_release (total_bytes);
    }
}

static size_t
arena_align_size (size_t nbytes)
{
  size_t align = ARENA_ALIGNMENT_SIZE;
  size_t sum;
  size_t units;
  size_t final_size;

  if (!SocketSecurity_check_add (nbytes, align - 1, &sum))
    return 0;

  units = sum / align;

  if (!SocketSecurity_check_multiply (units, align, &final_size))
    return 0;

  return final_size;
}

static size_t
arena_calculate_aligned_size (size_t nbytes)
{
  size_t final_size;

  if (!SocketSecurity_check_size (nbytes))
    return 0;

  final_size = arena_align_size (nbytes);

  /* Defensive check for rounding overflow (possible if align large relative to
   * max) */
  if (!SocketSecurity_check_size (final_size))
    return 0;

  return final_size;
}

static inline int
arena_has_space (const T arena, size_t nbytes)
{
  return arena->avail != NULL && arena->limit != NULL
         && (size_t)(arena->limit - arena->avail) >= nbytes;
}

static int
arena_allocate_new_chunk (size_t chunk_size, struct ChunkHeader **ptr_out,
                          char **limit_out)
{
  size_t total;
  struct ChunkHeader *ptr;

  if (validate_chunk_size (chunk_size, &total) != ARENA_SUCCESS)
    return ARENA_FAILURE;

  if (acquire_global_memory (total) != ARENA_SUCCESS)
    return ARENA_FAILURE;

  ptr = allocate_raw_chunk (total);
  if (ptr == NULL)
    return ARENA_FAILURE;

  ptr->chunk_size = chunk_size;
  *ptr_out = ptr;
  *limit_out = chunk_limit (ptr);

  return ARENA_SUCCESS;
}

/* Must hold arena->mutex */
static int
arena_get_chunk (T arena, size_t min_size)
{
  struct ChunkHeader *ptr;
  char *limit;
  size_t chunk_size;

  if (chunk_cache_get (&ptr, &limit) == ARENA_CHUNK_REUSED)
    {
      arena_link_chunk (arena, ptr, limit);
      return ARENA_SUCCESS;
    }

  chunk_size = (ARENA_CHUNK_SIZE < min_size) ? min_size : ARENA_CHUNK_SIZE;

  if (arena_allocate_new_chunk (chunk_size, &ptr, &limit) != ARENA_SUCCESS)
    return ARENA_FAILURE;

  arena_link_chunk (arena, ptr, limit);
  return ARENA_SUCCESS;
}

/* Must hold arena->mutex if arena->locked */
static int
arena_ensure_space (T arena, size_t aligned_size)
{
  while (!arena_has_space (arena, aligned_size))
    {
      if (arena_get_chunk (arena, aligned_size) != ARENA_SUCCESS)
        return ARENA_FAILURE;
    }
  return ARENA_SUCCESS;
}

/* Must hold arena->mutex */
static void
arena_release_all_chunks (T arena)
{
  while (arena->prev != NULL)
    {
      struct ChunkHeader *chunk = arena->prev;
      struct ChunkHeader saved = *chunk;

      arena->prev = saved.prev;
      arena->avail = saved.avail;
      arena->limit = saved.limit;

      chunk_cache_return (chunk);
    }

  assert (arena->prev == NULL);
  assert (arena->avail == NULL);
  assert (arena->limit == NULL);
}

T
Arena_new (void)
{
  T arena;

  arena = malloc (sizeof (*arena));
  if (arena == NULL)
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      ARENA_ENOMEM ": Cannot allocate arena structure");

  if (pthread_mutex_init (&arena->mutex, NULL) != 0)
    {
      free (arena);
      SOCKET_RAISE_MSG (Arena, Arena_Failed,
                        "Failed to initialize arena mutex");
    }

  arena->prev = NULL;
  arena->avail = NULL;
  arena->limit = NULL;
  arena->locked = 1;

  return arena;
}

T
Arena_new_unlocked (void)
{
  T arena;

  arena = malloc (sizeof (*arena));
  if (arena == NULL)
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      ARENA_ENOMEM ": Cannot allocate arena structure");

  /* No mutex initialization for unlocked arenas */
  arena->prev = NULL;
  arena->avail = NULL;
  arena->limit = NULL;
  arena->locked = 0;

  return arena;
}


void
Arena_dispose (T *ap)
{
  T arena;
  int locked;

  if (!ap || !*ap)
    return;

  /* Save arena pointer and locked flag before clearing, because ap itself
   * may point into memory allocated from this arena (e.g., if ap points to
   * a field within a structure that was arena-allocated). After Arena_clear
   * frees all chunks, dereferencing ap would be use-after-free. */
  arena = *ap;
  locked = arena->locked;

  Arena_clear (arena);
  if (locked)
    pthread_mutex_destroy (&arena->mutex);
  free (arena);
  *ap = NULL;
}

void *
Arena_alloc (T arena, size_t nbytes, const char *file, int line)
{
  void *result;
  size_t aligned_size;

  (void)file;
  (void)line;

  if (arena == NULL)
    SOCKET_RAISE_MSG (Arena, Arena_Failed, "NULL arena pointer");

  if (nbytes == 0)
    SOCKET_RAISE_MSG (Arena, Arena_Failed, "Zero size allocation");

  aligned_size = arena_calculate_aligned_size (nbytes);
  if (aligned_size == 0)
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      "Invalid allocation size: %zu bytes", nbytes);

  if (arena->locked)
    SOCKET_MUTEX_LOCK_OR_RAISE (&arena->mutex, Arena, Arena_Failed);

  if (arena_ensure_space (arena, aligned_size) != ARENA_SUCCESS)
    {
      if (arena->locked)
        SOCKET_MUTEX_UNLOCK (&arena->mutex);
      SOCKET_RAISE_MSG (Arena, Arena_Failed,
                        "Failed to allocate %zu bytes", aligned_size);
    }

  result = arena->avail;
  arena->avail += aligned_size;

  if (arena->locked)
    SOCKET_MUTEX_UNLOCK (&arena->mutex);

  return result;
}

void *
Arena_calloc (T arena, size_t count, size_t nbytes, const char *file, int line)
{
  (void)file;
  (void)line;
  if (arena == NULL)
    SOCKET_RAISE_MSG (Arena, Arena_Failed, "NULL arena pointer in %s",
                      "Arena_calloc");
  if (count == 0 || nbytes == 0)
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      "Invalid count (%zu) or nbytes (%zu) in %s", count,
                      nbytes, "Arena_calloc");

  size_t total;
  if (!SocketSecurity_check_multiply (count, nbytes, &total))
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      "calloc overflow: count=%zu, nbytes=%zu in %s", count,
                      nbytes, "Arena_calloc");

  if (!SocketSecurity_check_size (total))
    SOCKET_RAISE_MSG (Arena, Arena_Failed,
                      "calloc size exceeds maximum: %zu (limit=%zu) in %s",
                      total, SocketSecurity_get_max_allocation (),
                      "Arena_calloc");

  void *ptr = Arena_alloc (arena, total, file, line);
  memset (ptr, 0, total);

  return ptr;
}

void
Arena_clear (T arena)
{
  if (arena == NULL)
    return;

  if (arena->locked)
    SOCKET_MUTEX_LOCK_OR_RAISE (&arena->mutex, Arena, Arena_Failed);
  arena_release_all_chunks (arena);
  if (arena->locked)
    SOCKET_MUTEX_UNLOCK (&arena->mutex);
}

/* Walk the prev chain to find the oldest chunk (where prev == NULL) */
static inline struct ChunkHeader *
arena_find_first_chunk (struct ChunkHeader *chunk)
{
  while (chunk->prev != NULL)
    chunk = chunk->prev;
  return chunk;
}

/* Release all chunks except first_chunk to the global cache */
static inline void
arena_release_extra_chunks (T arena, struct ChunkHeader *first_chunk)
{
  struct ChunkHeader *chunk = arena->prev;

  while (chunk != first_chunk)
    {
      struct ChunkHeader *prev_chunk = chunk->prev;
      chunk_cache_return (chunk);
      chunk = prev_chunk;
    }
}

/* Reset arena state to use a single chunk from the beginning */
static inline void
arena_reset_to_chunk (T arena, struct ChunkHeader *chunk)
{
  arena->prev = chunk;
  arena->avail = (char *)((union header *)chunk + 1);
  arena->limit = chunk_limit (chunk);
}

void
Arena_reset (T arena)
{
  struct ChunkHeader *first_chunk;

  if (arena == NULL)
    return;

  if (arena->locked)
    SOCKET_MUTEX_LOCK_OR_RAISE (&arena->mutex, Arena, Arena_Failed);

  if (arena->prev == NULL)
    {
      if (arena->locked)
        SOCKET_MUTEX_UNLOCK (&arena->mutex);
      return;
    }

  first_chunk = arena_find_first_chunk (arena->prev);
  arena_release_extra_chunks (arena, first_chunk);
  arena_reset_to_chunk (arena, first_chunk);

  if (arena->locked)
    SOCKET_MUTEX_UNLOCK (&arena->mutex);
}

#undef T

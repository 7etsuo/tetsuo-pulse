/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_MUTEXARENA_H
#define SOCKETUTIL_MUTEXARENA_H

/**
 * @file SocketUtil/MutexArena.h
 * @ingroup foundation
 * @brief Mutex + arena allocation pattern for thread-safe modules.
 *
 * Provides standardized patterns for modules that need:
 * - pthread_mutex_t for thread-safe operations
 * - Arena_T for optional arena-based allocation
 * - Exception-safe scoped locking
 *
 * Usage:
 *   struct MyModule_T {
 *     SOCKET_MUTEX_ARENA_FIELDS;
 *     // ... module-specific fields
 *   };
 *
 * @see core/Arena.h for arena memory management
 * @see core/Except.h for exception handling
 */

#include <pthread.h>
#include <stdlib.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketError.h"
#include "core/SocketUtil/Exception.h"

/* ============================================================================
 * MUTEX LOCK/UNLOCK MACROS
 * ============================================================================
 *
 * Standard patterns for mutex operations:
 * - SOCKET_MUTEX_LOCK_OR_RAISE: Lock with error handling via exception
 * - SOCKET_MUTEX_UNLOCK: Unlock (ignores errors per POSIX recommendation)
 * - SOCKET_WITH_MUTEX: Exception-safe scoped locking with TRY/FINALLY
 *
 * Why unlock ignores errors:
 * Per POSIX, pthread_mutex_unlock() errors indicate programming bugs:
 * - EPERM: Calling thread does not own the mutex
 * - EINVAL: Mutex is invalid or uninitialized
 *
 * Raising exceptions in cleanup paths (FINALLY blocks, destructors) causes
 * cascading failures that mask the original error.
 */

/**
 * @brief SOCKET_MUTEX_LOCK_OR_RAISE - Lock mutex with error handling.
 * @param mutex_ptr Pointer to pthread_mutex_t.
 * @param module Module name for exception (e.g., SocketTimer).
 * @param exc Exception to raise (e.g., SocketTimer_Failed).
 *
 * @threadsafe Yes (pthread_mutex_lock is thread-safe)
 */
#define SOCKET_MUTEX_LOCK_OR_RAISE(mutex_ptr, module, exc)   \
  do                                                         \
    {                                                        \
      int _lock_err = pthread_mutex_lock (mutex_ptr);        \
      if (_lock_err != 0)                                    \
        SOCKET_RAISE_MSG (module,                            \
                          exc,                               \
                          "pthread_mutex_lock failed: %s",   \
                          Socket_safe_strerror (_lock_err)); \
    }                                                        \
  while (0)

/**
 * @brief SOCKET_MUTEX_UNLOCK - Unlock mutex (ignores errors).
 * @param mutex_ptr Pointer to pthread_mutex_t.
 *
 * @threadsafe Yes (pthread_mutex_unlock is thread-safe)
 */
#define SOCKET_MUTEX_UNLOCK(mutex_ptr) (void)pthread_mutex_unlock (mutex_ptr)

/**
 * @brief SOCKET_WITH_MUTEX - Execute code block with mutex protection.
 * @param mutex_ptr Pointer to pthread_mutex_t.
 * @param module Module name for exception.
 * @param exc Exception to raise on lock failure.
 * @param code Code block to execute under lock.
 *
 * Exception-safe scoped locking. The mutex is unlocked via FINALLY
 * even if the code block raises an exception.
 *
 * @warning Do not use 'return' inside the code block.
 *
 * @threadsafe Yes
 */
#define SOCKET_WITH_MUTEX(mutex_ptr, module, exc, code)    \
  do                                                       \
    {                                                      \
      SOCKET_MUTEX_LOCK_OR_RAISE (mutex_ptr, module, exc); \
      TRY{ code } FINALLY                                  \
      {                                                    \
        SOCKET_MUTEX_UNLOCK (mutex_ptr);                   \
      }                                                    \
      END_TRY;                                             \
    }                                                      \
  while (0)

/* ============================================================================
 * MUTEX + ARENA ALLOCATION PATTERN
 * ============================================================================
 *
 * Embed SOCKET_MUTEX_ARENA_FIELDS in struct, use SOCKET_MUTEX_ARENA_*() macros.
 *
 * Example usage:
 *   struct MyModule_T {
 *     SOCKET_MUTEX_ARENA_FIELDS;
 *     // ... module-specific fields
 *   };
 *
 *   MyModule_T MyModule_new(Arena_T arena) {
 *     MyModule_T m = arena ? CALLOC(arena, 1, sizeof(*m)) : calloc(1,
 *sizeof(*m));
 *     if (!m) SOCKET_RAISE_MSG(...);
 *     m->arena = arena;
 *     SOCKET_MUTEX_ARENA_INIT(m, MyModule, MyModule_Failed);
 *     return m;
 *   }
 *
 *   void MyModule_free(MyModule_T *m) {
 *     if (!m || !*m) return;
 *     SOCKET_MUTEX_ARENA_DESTROY(*m);
 *     if (!(*m)->arena) free(*m);
 *     *m = NULL;
 *   }
 */

/** Mutex initialization states */
#define SOCKET_MUTEX_UNINITIALIZED 0
#define SOCKET_MUTEX_INITIALIZED 1
#define SOCKET_MUTEX_SHUTDOWN (-1)

/**
 * @brief SOCKET_MUTEX_ARENA_FIELDS - Fields to embed in managed structs.
 *
 * Provides the standard pattern for modules that need:
 * - pthread_mutex_t for thread-safe operations
 * - Arena_T for optional arena-based allocation
 * - Initialization state tracking for safe cleanup
 */
#define SOCKET_MUTEX_ARENA_FIELDS \
  pthread_mutex_t mutex;          \
  Arena_T arena;                  \
  int initialized

/**
 * @brief SOCKET_MUTEX_ARENA_INIT - Initialize mutex and set state.
 * @param obj Pointer to struct containing SOCKET_MUTEX_ARENA_FIELDS.
 * @param module_name Module name for exception.
 * @param exc_var Exception variable to raise on failure.
 *
 * Prerequisites: obj->arena must already be set by caller.
 */
#define SOCKET_MUTEX_ARENA_INIT(obj, module_name, exc_var)         \
  do                                                               \
    {                                                              \
      (obj)->initialized = SOCKET_MUTEX_UNINITIALIZED;             \
      if (pthread_mutex_init (&(obj)->mutex, NULL) != 0)           \
        {                                                          \
          SOCKET_RAISE_MSG (                                       \
              module_name, exc_var, "Failed to initialize mutex"); \
        }                                                          \
      (obj)->initialized = SOCKET_MUTEX_INITIALIZED;               \
    }                                                              \
  while (0)

/**
 * @brief SOCKET_MUTEX_ARENA_DESTROY - Cleanup mutex if initialized.
 * @param obj Pointer to struct containing SOCKET_MUTEX_ARENA_FIELDS.
 *
 * Safe to call multiple times (idempotent).
 */
#define SOCKET_MUTEX_ARENA_DESTROY(obj)                    \
  do                                                       \
    {                                                      \
      if ((obj)->initialized == SOCKET_MUTEX_INITIALIZED)  \
        {                                                  \
          pthread_mutex_destroy (&(obj)->mutex);           \
          (obj)->initialized = SOCKET_MUTEX_UNINITIALIZED; \
        }                                                  \
    }                                                      \
  while (0)

/**
 * @brief SOCKET_MUTEX_ARENA_ALLOC - Allocate from arena or malloc.
 * @param obj Pointer to struct containing SOCKET_MUTEX_ARENA_FIELDS.
 * @param size Bytes to allocate.
 * @return Allocated pointer (uninitialized) or NULL on failure.
 */
#define SOCKET_MUTEX_ARENA_ALLOC(obj, size)                              \
  ((obj)->arena ? Arena_alloc ((obj)->arena, (size), __FILE__, __LINE__) \
                : malloc (size))

/**
 * @brief SOCKET_MUTEX_ARENA_CALLOC - Allocate zeroed memory.
 * @param obj Pointer to struct containing SOCKET_MUTEX_ARENA_FIELDS.
 * @param count Number of elements.
 * @param size Size per element.
 * @return Allocated zeroed pointer or NULL on failure.
 */
#define SOCKET_MUTEX_ARENA_CALLOC(obj, count, size)                       \
  ((obj)->arena                                                           \
       ? Arena_calloc ((obj)->arena, (count), (size), __FILE__, __LINE__) \
       : calloc ((count), (size)))

/**
 * @brief SOCKET_MUTEX_ARENA_FREE - Free if malloc mode (no-op for arena).
 * @param obj Pointer to struct containing SOCKET_MUTEX_ARENA_FIELDS.
 * @param ptr Pointer to free.
 */
#define SOCKET_MUTEX_ARENA_FREE(obj, ptr)        \
  do                                             \
    {                                            \
      if ((obj)->arena == NULL && (ptr) != NULL) \
        {                                        \
          free (ptr);                            \
        }                                        \
    }                                            \
  while (0)

#endif /* SOCKETUTIL_MUTEXARENA_H */

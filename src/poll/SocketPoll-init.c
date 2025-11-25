/**
 * SocketPoll-init.c - Poll initialization helpers
 *
 * This file contains the initialization and allocation functions
 * for the SocketPoll module.
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "core/SocketConfig.h"

#define SOCKET_LOG_COMPONENT "SocketPoll"
#include "core/SocketError.h"
#include "poll/SocketPoll-private.h"
#include "poll/SocketPoll_backend.h"
/* Arena.h, Except.h, SocketTimer-private.h, SocketAsync.h via private header */

#define T SocketPoll_T

/* ==================== Init Failure Macro ==================== */

/**
 * INIT_FAIL - Cleanup and raise exception during init
 * Reduces repeated error handling pattern in init functions.
 */
#define INIT_FAIL(msg)                                                         \
  do                                                                           \
    {                                                                          \
      SOCKET_ERROR_MSG (msg);                                                  \
      cleanup_poll_partial (poll);                                             \
      RAISE_POLL_ERROR (SocketPoll_Failed);                                    \
    }                                                                          \
  while (0)

#define INIT_FAIL_FMT(fmt, ...)                                                \
  do                                                                           \
    {                                                                          \
      SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__);                                   \
      cleanup_poll_partial (poll);                                             \
      RAISE_POLL_ERROR (SocketPoll_Failed);                                    \
    }                                                                          \
  while (0)

/* ==================== Cleanup Helper ==================== */

/**
 * cleanup_poll_partial - Free partially initialized poll structure
 * @poll: Poll instance to clean up
 *
 * Cleans up resources in reverse order of acquisition.
 * Safe to call with NULL members. Exported for use by SocketPoll.c constructor.
 */
void
cleanup_poll_partial (T poll)
{
  if (!poll)
    return;

  if (poll->backend)
    backend_free (poll->backend);

  if (poll->arena)
    Arena_dispose (&poll->arena);

  free (poll);
}

/* ==================== Structure Allocation ==================== */

/**
 * allocate_poll_structure - Allocate poll structure
 * Returns: Allocated poll structure (zero-initialized)
 * Raises: SocketPoll_Failed on allocation failure
 */
T
allocate_poll_structure (void)
{
  T poll = calloc (1, sizeof (*poll));

  if (!poll)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate poll structure");
      RAISE_POLL_ERROR (SocketPoll_Failed); /* No cleanup needed yet */
    }

  return poll;
}

/* ==================== Backend Initialization ==================== */

/**
 * initialize_poll_backend - Initialize poll backend
 * @poll: Poll instance
 * @maxevents: Maximum events
 * Raises: SocketPoll_Failed on failure
 */
void
initialize_poll_backend (T poll, int maxevents)
{
  poll->backend = backend_new (maxevents);

  if (!poll->backend)
    INIT_FAIL_FMT ("Failed to create %s backend", backend_name ());
}

/* ==================== Arena Initialization ==================== */

/**
 * initialize_poll_arena - Initialize poll arena
 * @poll: Poll instance
 * Raises: SocketPoll_Failed on failure
 */
void
initialize_poll_arena (T poll)
{
  poll->arena = Arena_new ();

  if (!poll->arena)
    INIT_FAIL (SOCKET_ENOMEM ": Cannot allocate poll arena");
}

/* ==================== Event Array Allocation ==================== */

/**
 * allocate_poll_event_arrays - Allocate event arrays
 * @poll: Poll instance
 * @maxevents: Maximum events
 * Raises: SocketPoll_Failed on failure
 */
void
allocate_poll_event_arrays (T poll, int maxevents)
{
  size_t array_size;

  if (maxevents <= 0 || maxevents > SOCKET_MAX_POLL_EVENTS)
    INIT_FAIL ("Invalid maxevents value");

  /* Calculate array size with overflow check */
  array_size = (size_t)maxevents * sizeof (*poll->socketevents);
  if (array_size / sizeof (*poll->socketevents) != (size_t)maxevents)
    INIT_FAIL ("Array size overflow");

  poll->socketevents
      = CALLOC (poll->arena, maxevents, sizeof (*poll->socketevents));

  if (!poll->socketevents)
    INIT_FAIL (SOCKET_ENOMEM ": Cannot allocate event arrays");
}

/* ==================== Mutex Initialization ==================== */

/**
 * initialize_poll_mutex - Initialize mutex
 * @poll: Poll instance
 * Raises: SocketPoll_Failed on failure
 */
void
initialize_poll_mutex (T poll)
{
  if (pthread_mutex_init (&poll->mutex, NULL) != 0)
    INIT_FAIL ("Failed to initialize poll mutex");
}

/**
 * initialize_poll_timer_heap - Initialize timer heap
 * @poll: Poll instance
 * Raises: SocketPoll_Failed on allocation failure
 */
void
initialize_poll_timer_heap (T poll)
{
  poll->timer_heap = SocketTimer_heap_new (poll->arena);

  if (!poll->timer_heap)
    INIT_FAIL (SOCKET_ENOMEM ": Cannot allocate timer heap");
}

/**
 * initialize_poll_async - Initialize async context (optional)
 * @poll: Poll instance
 *
 * Async context is optional - graceful degradation if unavailable.
 * Does not raise exceptions on failure.
 */
void
initialize_poll_async (T poll)
{
  /* async starts NULL from calloc; only set if init succeeds */
  TRY
  poll->async = SocketAsync_new (poll->arena);
  EXCEPT (SocketAsync_Failed)
  poll->async = NULL; /* Graceful degradation - async is optional */
  END_TRY;
}

#undef T

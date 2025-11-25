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

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"

#define SOCKET_LOG_COMPONENT "SocketPoll"
#include "core/SocketError.h"
#include "poll/SocketPoll-private.h"
#include "poll/SocketPoll_backend.h"

#include "core/SocketTimer-private.h"
#include "socket/SocketAsync.h"

#define T SocketPoll_T

extern const Except_T SocketPoll_Failed;
extern const Except_T SocketAsync_Failed;

/* ==================== Structure Allocation ==================== */

/**
 * allocate_poll_structure - Allocate poll structure
 * Returns: Allocated poll structure (zero-initialized)
 * Raises: SocketPoll_Failed on allocation failure
 */
T
allocate_poll_structure (void)
{
  T poll = malloc (sizeof (*poll));
  if (poll == NULL)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate poll structure");
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }
  /* Zero-initialize to ensure all fields start in a known state */
  memset (poll, 0, sizeof (*poll));
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
    {
      SOCKET_ERROR_FMT ("Failed to create %s backend", backend_name ());
      free (poll);
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }
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
    {
      backend_free (poll->backend);
      free (poll);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate poll arena");
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }
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

  /* Validate maxevents before allocation */
  if (maxevents <= 0 || maxevents > SOCKET_MAX_POLL_EVENTS)
    {
      backend_free (poll->backend);
      Arena_dispose (&poll->arena);
      free (poll);
      SOCKET_ERROR_MSG ("Invalid maxevents value");
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }

  /* Calculate array size with overflow check */
  array_size = (size_t)maxevents * sizeof (*poll->socketevents);
  if (array_size / sizeof (*poll->socketevents) != (size_t)maxevents)
    {
      backend_free (poll->backend);
      Arena_dispose (&poll->arena);
      free (poll);
      SOCKET_ERROR_MSG ("Array size overflow");
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }

  poll->socketevents
      = CALLOC (poll->arena, maxevents, sizeof (*poll->socketevents));
  if (!poll->socketevents)
    {
      backend_free (poll->backend);
      Arena_dispose (&poll->arena);
      free (poll);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate event arrays");
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }
}

/* ==================== Hash Table Initialization ==================== */

/**
 * initialize_poll_hash_tables - Initialize hash tables to zero
 * @poll: Poll instance
 */
void
initialize_poll_hash_tables (T poll)
{
  memset (poll->socket_data_map, 0, sizeof (poll->socket_data_map));
  memset (poll->fd_to_socket_map, 0, sizeof (poll->fd_to_socket_map));
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
    {
      backend_free (poll->backend);
      Arena_dispose (&poll->arena);
      free (poll);
      SOCKET_ERROR_MSG ("Failed to initialize poll mutex");
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }
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
    {
      backend_free (poll->backend);
      Arena_dispose (&poll->arena);
      free (poll);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate timer heap");
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }
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
  volatile SocketAsync_T volatile_async = NULL;

  poll->async = NULL;

  TRY
  {
    volatile_async = SocketAsync_new (poll->arena);
    poll->async = (SocketAsync_T)volatile_async;
  }
  EXCEPT (SocketAsync_Failed)
  {
    poll->async = NULL;
    volatile_async = NULL;
  }
  END_TRY;
}

#undef T


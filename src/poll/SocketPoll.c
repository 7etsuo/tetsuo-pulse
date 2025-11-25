/**
 * SocketPoll.c - Event polling with backend abstraction
 *
 * PLATFORM: Cross-platform (Linux/BSD/macOS/POSIX)
 * - Linux: epoll backend (best performance)
 * - BSD/macOS: kqueue backend (best performance)
 * - Other POSIX: poll(2) fallback (portable)
 *
 * Backend selection is done at compile-time via CMake.
 * See SocketPoll_backend.h for backend interface details.
 *
 * This file contains the public API implementation.
 * Internal functions are in:
 * - SocketPoll-data.c: Hash table management
 * - SocketPoll-init.c: Initialization helpers
 * - SocketPoll-events.c: Event translation
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "poll/SocketPoll-private.h"
#include "poll/SocketPoll_backend.h"
/* Arena.h, Except.h, Socket.h, SocketAsync.h included via SocketPoll-private.h */

#define SOCKET_LOG_COMPONENT "SocketPoll"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "core/SocketEvents.h"
#include "core/SocketMetrics.h"

/* Include timer private header after struct definition */
#include "core/SocketTimer-private.h"

#define T SocketPoll_T

const Except_T SocketPoll_Failed
    = { &SocketPoll_Failed, "SocketPoll operation failed" };

/* Cleanup helper declared in SocketPoll-init.c and used during construction */
extern void cleanup_poll_partial (T poll);

/* ==================== Constructor ==================== */

T
SocketPoll_new (int maxevents)
{
  volatile T poll = NULL;

  assert (SOCKET_VALID_POLL_EVENTS (maxevents));

  if (maxevents > SOCKET_MAX_POLL_EVENTS)
    maxevents = SOCKET_MAX_POLL_EVENTS;

  TRY
  {
    poll = allocate_poll_structure ();
    initialize_poll_backend (poll, maxevents);
    poll->maxevents = maxevents;
    poll->default_timeout_ms = SOCKET_DEFAULT_POLL_TIMEOUT;
    initialize_poll_arena (poll);
    allocate_poll_event_arrays (poll, maxevents);
    /* Note: Hash tables already zeroed by calloc in allocate_poll_structure */
    initialize_poll_mutex (poll);
    initialize_poll_timer_heap (poll);
    initialize_poll_async (poll);
  }
  EXCEPT (Arena_Failed)
  EXCEPT (SocketPoll_Failed)
  {
    cleanup_poll_partial ((T)poll);
    RAISE_POLL_ERROR (SocketPoll_Failed);
  }
  END_TRY;

  return poll;
}

/* ==================== Destructor ==================== */

void
SocketPoll_free (T *poll)
{
  if (!poll || !*poll)
    return;

  if ((*poll)->backend)
    backend_free ((*poll)->backend);

  if ((*poll)->async)
    SocketAsync_free (&(*poll)->async);

  if ((*poll)->timer_heap)
    SocketTimer_heap_free (&(*poll)->timer_heap);

  pthread_mutex_destroy (&(*poll)->mutex);

  if ((*poll)->arena)
    Arena_dispose (&(*poll)->arena);

  free (*poll);
  *poll = NULL;
}

/* ==================== Add Socket to Poll ==================== */

void
SocketPoll_add (T poll, Socket_T socket, unsigned events, void *data)
{
  int fd;
  unsigned hash;
  SocketData *entry;

  assert (poll);
  assert (socket);

  fd = Socket_fd (socket);
  if (fd < 0)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Adding invalid socket fd=%d to poll; ignoring", fd);
      return;
    }

  Socket_setnonblocking (socket);
  hash = socket_hash (socket);

  pthread_mutex_lock (&poll->mutex);
  TRY
  {
    /* Check for duplicates */
    entry = poll->socket_data_map[hash];
    while (entry)
      {
        if (entry->socket == socket)
          {
            SOCKET_ERROR_MSG ("Socket already in poll set");
            RAISE_POLL_ERROR (SocketPoll_Failed);
          }
        entry = entry->next;
      }

    /* Add to backend */
    if (backend_add (poll->backend, fd, events) < 0)
      {
        if (errno == EEXIST)
          SOCKET_ERROR_FMT ("Socket already in poll set (fd=%d)", fd);
        else
          SOCKET_ERROR_FMT ("Failed to add socket to poll (fd=%d)", fd);
        RAISE_POLL_ERROR (SocketPoll_Failed);
      }

    /* Add to data map */
    TRY
    socket_data_add_unlocked (poll, socket, data);
    EXCEPT (SocketPoll_Failed)
    {
      backend_del (poll->backend, fd);
      RERAISE;
    }
    END_TRY;
  }
  FINALLY
  pthread_mutex_unlock (&poll->mutex);
  END_TRY;
}

/* ==================== Modify Socket Events ==================== */

void
SocketPoll_mod (T poll, Socket_T socket, unsigned events, void *data)
{
  int fd;

  assert (poll);
  assert (socket);

  fd = Socket_fd (socket);

  pthread_mutex_lock (&poll->mutex);
  TRY
  {
    if (backend_mod (poll->backend, fd, events) < 0)
      {
        if (errno == ENOENT)
          SOCKET_ERROR_FMT ("Socket not in poll set (fd=%d)", fd);
        else
          SOCKET_ERROR_FMT ("Failed to modify socket in poll (fd=%d)", fd);
        RAISE_POLL_ERROR (SocketPoll_Failed);
      }

    socket_data_update_unlocked (poll, socket, data);
  }
  FINALLY
  pthread_mutex_unlock (&poll->mutex);
  END_TRY;
}

/* ==================== Remove Socket from Poll ==================== */

void
SocketPoll_del (T poll, Socket_T socket)
{
  int fd;

  assert (poll);
  assert (socket);

  fd = Socket_fd (socket);

  pthread_mutex_lock (&poll->mutex);
  socket_data_remove_unlocked (poll, socket);
  pthread_mutex_unlock (&poll->mutex);

  if (backend_del (poll->backend, fd) < 0 && errno != ENOENT)
    {
      SOCKET_ERROR_FMT ("Failed to remove socket from poll (fd=%d)", fd);
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }
}

/* ==================== Timeout Accessors ==================== */

int
SocketPoll_getdefaulttimeout (T poll)
{
  int current;

  assert (poll);

  pthread_mutex_lock (&poll->mutex);
  current = poll->default_timeout_ms;
  pthread_mutex_unlock (&poll->mutex);

  return current;
}

void
SocketPoll_setdefaulttimeout (T poll, int timeout)
{
  assert (poll);

  if (timeout < -1)
    timeout = 0;

  pthread_mutex_lock (&poll->mutex);
  poll->default_timeout_ms = timeout;
  pthread_mutex_unlock (&poll->mutex);
}

/* ==================== Wait for Events ==================== */

int
SocketPoll_wait (T poll, SocketEvent_T **events, int timeout)
{
  int nfds;

  assert (poll);
  assert (events);

  if (timeout == SOCKET_POLL_TIMEOUT_USE_DEFAULT)
    timeout = poll->default_timeout_ms;

  /* Calculate effective timeout considering timers */
  if (poll->timer_heap)
    {
      int64_t next_timer_ms = SocketTimer_heap_peek_delay (poll->timer_heap);

      if (next_timer_ms >= 0 && (timeout < 0 || next_timer_ms < timeout))
        {
          if (next_timer_ms > SOCKET_MAX_TIMER_TIMEOUT_MS)
            next_timer_ms = SOCKET_MAX_TIMER_TIMEOUT_MS;
          if (next_timer_ms > INT_MAX)
            next_timer_ms = INT_MAX;
          timeout = (int)next_timer_ms;
        }
    }

  /* Process async completions first */
  if (poll->async)
    SocketAsync_process_completions (poll->async, 0);

  /* Wait for events from backend */
  nfds = backend_wait (poll->backend, timeout);
  SocketMetrics_increment (SOCKET_METRIC_POLL_WAKEUPS, 1);

  if (nfds < 0)
    {
      if (errno == EINTR)
        {
          *events = NULL;
          return 0;
        }
      SOCKET_ERROR_FMT ("%s backend wait failed (timeout=%d)", backend_name (),
                        timeout);
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }

  /* Process async completions after wait */
  if (poll->async)
    SocketAsync_process_completions (poll->async, 0);

  /* Process expired timers */
  if (poll->timer_heap)
    SocketTimer_process_expired (poll->timer_heap);

  if (nfds == 0)
    {
      *events = poll->socketevents;
      return 0;
    }

  /* Translate backend events */
  nfds = translate_backend_events_to_socket_events (poll, nfds);

  if (nfds > 0)
    SocketMetrics_increment (SOCKET_METRIC_POLL_EVENTS_DISPATCHED,
                             (unsigned long)nfds);

  SocketEvent_emit_poll_wakeup (nfds, timeout);

#ifdef SOCKET_HAS_TLS
  /* Update poll events for TLS sockets in handshake */
  socketpoll_process_tls_handshakes (poll, nfds);
#endif

  *events = poll->socketevents;
  return nfds;
}

/* ==================== Accessors ==================== */

SocketAsync_T
SocketPoll_get_async (T poll)
{
  assert (poll);
  return poll->async;
}

/**
 * socketpoll_get_timer_heap - Get timer heap from poll (private function)
 * @poll: Poll instance
 * Returns: Timer heap pointer or NULL
 */
SocketTimer_heap_T *
socketpoll_get_timer_heap (T poll)
{
  assert (poll);
  return poll->timer_heap;
}

#undef T

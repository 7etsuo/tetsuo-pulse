/**
 * SocketPoll-events.c - Event translation functions
 *
 * This file contains the event translation logic for converting
 * backend events to SocketEvent_T structures.
 *
 * Thread-safe: Uses mutex for socket data lookups.
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>

#include "core/SocketConfig.h"

#define SOCKET_LOG_COMPONENT "SocketPoll"
#include "core/SocketError.h"
#include "poll/SocketPoll-private.h"
#include "poll/SocketPoll_backend.h"
/* Except.h, Socket.h included via SocketPoll-private.h */

#define T SocketPoll_T

/* ==================== FD to Socket Lookup ==================== */

/**
 * find_socket_by_fd - Find socket by file descriptor
 * @poll: Poll instance
 * @fd: File descriptor to look up
 * Returns: Socket or NULL if not found
 * Thread-safe: No (must be called with poll mutex held)
 *
 * Performs O(1) lookup using the fd_to_socket_map hash table.
 */
Socket_T
find_socket_by_fd (T poll, int fd)
{
  unsigned fd_hash = compute_fd_hash (fd);
  FdSocketEntry *entry = poll->fd_to_socket_map[fd_hash];

  while (entry)
    {
      if (entry->fd == fd)
        return entry->socket;
      entry = entry->next;
    }

  return NULL;
}

/* ==================== Backend Event Retrieval ==================== */

/**
 * get_backend_event - Get event from backend
 * @poll: Poll instance
 * @index: Event index
 * @fd_out: Output file descriptor
 * @events_out: Output event flags
 * Raises: SocketPoll_Failed on backend error
 */
static void
get_backend_event (T poll, int index, int *fd_out, unsigned *events_out)
{
  if (backend_get_event (poll->backend, index, fd_out, events_out) < 0)
    {
      SOCKET_ERROR_MSG ("Failed to get event from backend");
      RAISE_POLL_ERROR (SocketPoll_Failed);
    }
}

/* ==================== Single Event Translation ==================== */

/**
 * translate_single_event - Translate single backend event to SocketEvent_T
 * @poll: Poll instance
 * @index: Backend event index
 * @translated_index: Index in translated events array
 * @max_events: Maximum events (bounds check)
 * Returns: 1 if event was translated, 0 if skipped
 * Raises: SocketPoll_Failed on backend error
 */
static int
translate_single_event (T poll, int index, int translated_index, int max_events)
{
  int fd;
  unsigned event_flags;
  Socket_T socket;
  void *data;
  SocketEvent_T *event;

  /* Bounds check */
  if (translated_index >= max_events)
    return 0;

  get_backend_event (poll, index, &fd, &event_flags);

  pthread_mutex_lock (&poll->mutex);
  socket = find_socket_by_fd (poll, fd);

  if (!socket)
    {
      pthread_mutex_unlock (&poll->mutex);
      return 0;
    }

  data = socket_data_lookup_unlocked (poll, socket);
  pthread_mutex_unlock (&poll->mutex);

  event = &poll->socketevents[translated_index];
  event->socket = socket;
  event->data = data;
  event->events = event_flags;

  return 1;
}

/* ==================== Batch Event Translation ==================== */

/**
 * translate_backend_events_to_socket_events - Convert backend events
 * @poll: Poll instance
 * @nfds: Number of events to process
 * Returns: Number of successfully translated events
 * Raises: SocketPoll_Failed on backend error
 * Thread-safe: Yes (socket_data_lookup handles its own mutex locking)
 *
 * Translates events from the backend-specific format to the
 * standardized SocketEvent_T format used by the public API.
 */
int
translate_backend_events_to_socket_events (T poll, int nfds)
{
  /* volatile to prevent clobbering by setjmp/longjmp in TRY/EXCEPT */
  volatile int translated_count = 0;
  volatile int nfds_local;
  int max_events;
  int i;

  assert (poll);

  if (nfds <= 0 || !poll->socketevents || poll->maxevents <= 0)
    return 0;

  max_events = poll->maxevents;

  /* Copy nfds to volatile local and clamp to max_events */
  nfds_local = (nfds > max_events) ? max_events : nfds;

  TRY
  {
    for (i = 0; i < nfds_local && translated_count < max_events; i++)
      {
        if (translate_single_event (poll, i, translated_count, max_events))
          translated_count++;
      }
  }
  EXCEPT (SocketPoll_Failed)
  {
    /* Exception already handled, return partial results */
  }
  END_TRY;

  return translated_count;
}

#undef T

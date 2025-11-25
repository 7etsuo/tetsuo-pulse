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

#include "core/Except.h"
#include "core/SocketConfig.h"

#define SOCKET_LOG_COMPONENT "SocketPoll"
#include "core/SocketError.h"
#include "poll/SocketPoll-private.h"
#include "poll/SocketPoll_backend.h"
#include "socket/Socket.h"

#define T SocketPoll_T

extern const Except_T SocketPoll_Failed;

/* ==================== FD to Socket Lookup ==================== */

/**
 * find_socket_by_fd - Find socket by file descriptor
 * @poll: Poll instance
 * @fd: File descriptor to look up
 * Returns: Socket or NULL if not found
 * Thread-safe: No (must be called with poll mutex held)
 *
 * Performs O(1) lookup using the fd_to_socket_map hash table.
 * This provides efficient reverse lookup during event processing.
 */
Socket_T
find_socket_by_fd (T poll, int fd)
{
  unsigned fd_hash
      = ((unsigned)fd * HASH_GOLDEN_RATIO) % SOCKET_DATA_HASH_SIZE;
  FdSocketEntry *entry = poll->fd_to_socket_map[fd_hash];

  /* Search the hash bucket for matching FD */
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
 * Returns: 1 if event was translated, 0 if skipped
 * Raises: SocketPoll_Failed on backend error
 */
static int
translate_single_event (T poll, int index, int translated_index)
{
  volatile int fd;
  volatile unsigned event_flags;
  volatile Socket_T socket;
  volatile int max_events;
  void *associated_data;
  Socket_T non_volatile_socket;
  SocketEvent_T *event_ptr;
  SocketEvent_T *array_start;
  SocketEvent_T *array_end;

  if (!poll || index < 0 || translated_index < 0)
    return 0;

  /* Cache maxevents to prevent reading corrupted value */
  max_events = poll->maxevents;
  if (max_events <= 0 || max_events > SOCKET_MAX_POLL_EVENTS)
    return 0;

  if (!poll->socketevents || translated_index >= max_events)
    return 0;

  get_backend_event (poll, index, (int *)&fd, (unsigned *)&event_flags);

  pthread_mutex_lock (&poll->mutex);
  socket = find_socket_by_fd (poll, fd);
  if (!socket)
    {
      pthread_mutex_unlock (&poll->mutex);
      return 0;
    }

  associated_data = socket_data_lookup_unlocked (poll, (Socket_T)socket);
  non_volatile_socket = (Socket_T)socket;
  pthread_mutex_unlock (&poll->mutex);

  /* Use cached maxevents value for bounds checking */
  if (translated_index < 0 || translated_index >= max_events
      || !poll->socketevents)
    return 0;

  /* Validate bounds using pointer arithmetic */
  event_ptr = poll->socketevents + translated_index;
  array_start = poll->socketevents;
  array_end = array_start + max_events;

  /* Additional pointer validation */
  if (event_ptr < array_start || event_ptr >= array_end)
    return 0;

  event_ptr->socket = non_volatile_socket;
  event_ptr->data = associated_data;
  event_ptr->events = event_flags;
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
  volatile int translated_count = 0;
  volatile int i;
  volatile int max_events;
  volatile int volatile_nfds = nfds;

  if (!poll || volatile_nfds < 0 || !poll->socketevents
      || poll->maxevents <= 0)
    return 0;

  /* Cache maxevents value to ensure consistency */
  max_events = poll->maxevents;

  /* Ensure we don't exceed the allocated event array size */
  if (volatile_nfds > max_events)
    volatile_nfds = max_events;

  TRY
  {
    for (i = 0; i < volatile_nfds; i++)
      {
        /* Stop if we've filled the array */
        if (translated_count >= max_events)
          break;

        /* translate_single_event validates bounds internally */
        if (translate_single_event (poll, i, translated_count))
          {
            translated_count++;
          }
      }
  }
  EXCEPT (SocketPoll_Failed)
  {
    /* Handle translation errors - exception already raised */
  }
  END_TRY;

  /* Ensure we never return a count exceeding maxevents */
  if (translated_count > max_events)
    translated_count = max_events;

  return translated_count;
}

#undef T


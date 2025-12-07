/**
 * SocketPoll_epoll.c - epoll backend for Linux
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * PLATFORM: Linux (requires epoll)
 * - Linux kernel 2.6.8+ for full epoll support
 * - Edge-triggered mode via EPOLLET for optimal performance
 * - Best performance on Linux systems
 *
 * Thread-safe: No (caller must synchronize access)
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>

#include "core/SocketConfig.h"
#include "poll/SocketPoll_backend.h"
#include "core/Arena.h"

/* Backend instance structure */
#define T PollBackend_T
typedef struct T *T;
struct T
{
  int epfd;                   /* epoll file descriptor */
  struct epoll_event *events; /* Event array for results */
  int maxevents;              /* Maximum events per wait */
  int last_nev;                 /* Valid events from last backend_wait (0 on error/timeout) */
};
#undef T

/**
 * translate_to_epoll - Convert abstract poll events to epoll events
 * @events: Abstract poll event flags (POLL_READ, POLL_WRITE)
 *
 * Returns: epoll event flags with edge-triggered mode (EPOLLET) enabled.
 *
 * Edge-triggered mode requires the application to drain all available
 * data on each event notification to avoid starvation.
 */
static unsigned
translate_to_epoll (unsigned events)
{
  unsigned epoll_events = 0;

  if (events & POLL_READ)
    epoll_events |= EPOLLIN;

  if (events & POLL_WRITE)
    epoll_events |= EPOLLOUT;

  return epoll_events | EPOLLET;
}

/**
 * translate_from_epoll - Convert epoll events to abstract poll events
 * @epoll_events: epoll event flags from epoll_wait
 *
 * Returns: Abstract poll event flags.
 *
 * Maps EPOLLIN->POLL_READ, EPOLLOUT->POLL_WRITE, EPOLLERR->POLL_ERROR,
 * EPOLLHUP->POLL_HANGUP for portable event handling.
 */
static unsigned
translate_from_epoll (unsigned epoll_events)
{
  unsigned events = 0;

  if (epoll_events & EPOLLIN)
    events |= POLL_READ;

  if (epoll_events & EPOLLOUT)
    events |= POLL_WRITE;

  if (epoll_events & EPOLLERR)
    events |= POLL_ERROR;

  if (epoll_events & EPOLLHUP)
    events |= POLL_HANGUP;

  return events;
}

/**
 * epoll_ctl_helper - Common helper for epoll_ctl add/mod operations
 * @backend: Poll backend instance
 * @fd: File descriptor to add or modify
 * @events: Abstract poll event flags
 * @op: epoll operation (EPOLL_CTL_ADD or EPOLL_CTL_MOD)
 *
 * Returns: 0 on success, -1 on failure (errno set by epoll_ctl).
 *
 * Consolidates common setup logic for backend_add and backend_mod
 * to eliminate code duplication.
 */
static int
epoll_ctl_helper (const PollBackend_T backend, int fd, unsigned events, int op)
{
  struct epoll_event ev = { 0 };

  ev.events = translate_to_epoll (events);
  ev.data.fd = fd;

  return epoll_ctl (backend->epfd, op, fd, &ev) < 0 ? -1 : 0;
}

/**
 * backend_new - Create new epoll backend instance
 * @arena: Arena for allocations (backend struct and events array)
 * @maxevents: Maximum events to return per wait (must be > 0)
 *
 * Returns: New backend instance, or NULL on failure (errno set). On partial
 * failure, allocated memory is left allocated in arena (freed by Arena_dispose).
 *
 * Creates an epoll instance and allocates the event array from arena
 * for storing results from epoll_wait. Uses epoll_create1(0) for
 * close-on-exec behavior.
 */
PollBackend_T
backend_new (Arena_T arena, int maxevents)
{
  PollBackend_T backend;

  assert (arena != NULL);

  VALIDATE_MAXEVENTS (maxevents, struct epoll_event);

  backend = CALLOC (arena, 1, sizeof (*backend));
  if (!backend)
    return NULL;

  backend->epfd = epoll_create1 (0);
  if (backend->epfd < 0)
    {
      return NULL; /* partial allocation leaked to arena dispose */
    }

  backend->events = CALLOC (arena, (size_t)maxevents, sizeof (struct epoll_event));
  if (!backend->events)
    {
      SAFE_CLOSE (backend->epfd);
      return NULL; /* partial allocations leaked to arena dispose */
    }

  backend->maxevents = maxevents;
  backend->last_nev = 0;
  return backend;
}

/**
 * backend_free - Close epoll backend resources
 * @backend: Backend instance (fd closed; memory freed by arena dispose)
 *
 * Closes the epoll file descriptor. Memory allocations (struct, events array)
 * are owned by arena and freed separately by Arena_dispose.
 */
void
backend_free (PollBackend_T backend)
{
  assert (backend);

  SAFE_CLOSE (backend->epfd);
  /* events and backend memory freed by arena dispose */
}

/**
 * backend_add - Add file descriptor to epoll interest set
 * @backend: Poll backend instance
 * @fd: File descriptor to add
 * @events: Abstract poll event flags (POLL_READ, POLL_WRITE)
 *
 * Returns: 0 on success, -1 on failure (errno set).
 *
 * Adds fd with edge-triggered monitoring. Fails if fd is already
 * in the interest set (use backend_mod to change events).
 */
int
backend_add (PollBackend_T backend, int fd, unsigned events)
{
  assert (backend);
  VALIDATE_FD (fd);

  return epoll_ctl_helper (backend, fd, events, EPOLL_CTL_ADD);
}

/**
 * backend_mod - Modify file descriptor events in epoll interest set
 * @backend: Poll backend instance
 * @fd: File descriptor to modify
 * @events: New abstract poll event flags
 *
 * Returns: 0 on success, -1 on failure (errno set).
 *
 * Changes the monitored events for an fd already in the interest set.
 * Fails if fd is not in the interest set (use backend_add first).
 */
int
backend_mod (PollBackend_T backend, int fd, unsigned events)
{
  assert (backend);
  VALIDATE_FD (fd);

  return epoll_ctl_helper (backend, fd, events, EPOLL_CTL_MOD);
}

/**
 * backend_del - Remove file descriptor from epoll interest set
 * @backend: Poll backend instance
 * @fd: File descriptor to remove
 *
 * Returns: 0 on success (including if fd not in set), -1 on error.
 *
 * Silently succeeds if fd is not in the interest set (ENOENT) or
 * is already closed (EBADF) for idempotent removal semantics.
 */
int
backend_del (PollBackend_T backend, int fd)
{
  assert (backend);
  VALIDATE_FD (fd);

  if (epoll_ctl (backend->epfd, EPOLL_CTL_DEL, fd, NULL) < 0)
    {
      /* Silently succeed if fd not in set or already closed */
      if (errno == ENOENT || errno == EBADF)
        return 0;
      return -1;
    }

  return 0;
}

/**
 * backend_wait - Wait for events on the epoll interest set
 * @backend: Poll backend instance (modifies internal events array for output)
 * @timeout_ms: Timeout in milliseconds (-1 for infinite, 0 for non-blocking)
 *
 * Returns: Number of ready events (0 on timeout/interrupt), -1 on error.
 *
 * Blocks until events are ready or timeout expires. Returns 0 if
 * interrupted by signal (EINTR) for seamless signal handling.
 * Thread-safe: No (epoll_wait not thread-safe)
 */
int
backend_wait (PollBackend_T backend, int timeout_ms)
{
  int nev;

  assert (backend);

  nev = epoll_wait (backend->epfd, backend->events, backend->maxevents,
                    timeout_ms);

  if (nev < 0)
    {
      backend->last_nev = 0;
      memset (backend->events, 0, (size_t)backend->maxevents * sizeof (struct epoll_event));
      if (errno == EINTR)
        return 0;
      return -1;
    }

  backend->last_nev = nev;
  if (backend->last_nev == 0)
    {
      memset (backend->events, 0, (size_t)backend->maxevents * sizeof (struct epoll_event));
    }
  return nev;
}

/**
 * backend_get_event - Retrieve event at specified index
 * @backend: Backend instance (const - read-only access to events array)
 * @index: Event index (0 to backend->last_nev - 1 from most recent backend_wait)
 * @fd_out: Output for file descriptor
 * @events_out: Output for abstract poll event flags
 *
 * Returns: 0 on success, -1 if index out of valid range (0 to last_nev-1 or >= maxevents).
 *
 * Retrieves the fd and translated events for a ready event.
 * Must be called after backend_wait returns > 0.
 * Thread-safe: No
 */
int
backend_get_event (const PollBackend_T backend, int index, int *fd_out,
                   unsigned *events_out)
{
  struct epoll_event *ev;

  assert (backend);
  assert (fd_out);
  assert (events_out);

  if (index < 0 || index >= backend->last_nev || index >= backend->maxevents)
    return -1;

  ev = &backend->events[index];
  *fd_out = ev->data.fd;
  *events_out = translate_from_epoll (ev->events);

  return 0;
}

/**
 * backend_name - Get backend name string
 *
 * Returns: Static string "epoll" identifying this backend.
 */
const char *
backend_name (void)
{
  return "epoll";
}

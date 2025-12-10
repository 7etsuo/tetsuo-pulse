/**
 * SocketPoll_kqueue.c - kqueue backend for BSD/macOS
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * PLATFORM: BSD/macOS (requires kqueue)
 * - FreeBSD: Full support (kqueue/kevent)
 * - OpenBSD: Full support
 * - NetBSD: Full support
 * - macOS: Full support
 * - Linux: Not supported (use epoll backend instead)
 *
 * This backend implements the SocketPoll_backend interface using BSD kqueue.
 * It uses EV_CLEAR for edge-triggered mode, matching epoll's EPOLLET behavior.
 *
 * Thread-safe: No (backend instances should not be shared across threads)
 */

/* Platform guard: kqueue is only available on BSD/macOS.
 * On other platforms, this file compiles as an empty translation unit.
 * CMake selects the appropriate backend file for each platform. */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__)         \
    || defined(__OpenBSD__) || defined(__DragonFly__)

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "poll/SocketPoll_backend.h"

/**
 * Backend instance structure
 *
 * Encapsulates kqueue state for event polling operations.
 */
#define T PollBackend_T
struct T
{
  int kq;                /* kqueue file descriptor */
  struct kevent *events; /* Event array for kevent() results */
  int maxevents;         /* Maximum events per wait call */
  int last_nev; /* Valid events from last backend_wait (0 on error/timeout) */
};
#undef T

/**
 * backend_new - Create a new kqueue backend instance
 * @arena: Arena for allocations
 * @maxevents: Maximum number of events to return per wait call
 *
 * Returns: New backend instance, or NULL on failure (errno set)
 *
 * Allocates the backend structure, creates the kqueue fd, and allocates
 * the event array. Cleanup is handled automatically on partial failure.
 */
PollBackend_T
backend_new (Arena_T arena, int maxevents)
{
  PollBackend_T backend;

  assert (arena != NULL);
  assert (maxevents > 0);

  VALIDATE_MAXEVENTS (maxevents, struct kevent);

  backend = CALLOC (arena, 1, sizeof (*backend));
  if (!backend)
    return NULL;

  backend->kq = kqueue ();
  if (backend->kq < 0)
    {
      return NULL; /* partial allocation leaked to arena dispose */
    }

  backend->events = CALLOC (arena, (size_t)maxevents, sizeof (struct kevent));
  if (!backend->events)
    {
      SAFE_CLOSE (backend->kq);
      return NULL; /* partial allocations leaked to arena dispose */
    }

  backend->maxevents = maxevents;
  backend->last_nev = 0;
  return backend;
}

/**
 * backend_free - Close kqueue backend resources
 * @backend: Backend instance (kq closed; memory freed by arena dispose)
 *
 * Closes the kqueue fd. Memory allocations (struct, events array) are
 * owned by arena and freed by Arena_dispose.
 */
void
backend_free (PollBackend_T backend)
{
  assert (backend);

  SAFE_CLOSE (backend->kq);
  /* events and backend memory freed by arena dispose */
}

/**
 * setup_event_filters - Setup kqueue event filters for read/write
 * @backend: Backend instance (must not be NULL)
 * @fd: File descriptor to configure
 * @events: Events to monitor (POLL_READ | POLL_WRITE bitmask)
 * @action: EV_ADD to add filters, EV_DELETE to remove filters
 *
 * Returns: 0 on success, -1 on failure (errno set by kevent)
 *
 * Common helper for add/mod/del operations to eliminate duplicate code.
 * When action is EV_ADD, EV_CLEAR is also set to enable edge-triggered
 * mode, which matches epoll's EPOLLET behavior. This means the caller
 * must drain the socket until EAGAIN before waiting for more events.
 *
 * Up to 2 kevent changes are batched in a single kevent() call for
 * efficiency when both read and write events are requested.
 */
static int
setup_event_filters (PollBackend_T backend, int fd, unsigned events,
                     unsigned short action)
{
  struct kevent ev[2];
  int nev = 0;
  unsigned short flags = action | (action == EV_ADD ? EV_CLEAR : 0);

  if (events & POLL_READ)
    {
      EV_SET (&ev[nev], fd, EVFILT_READ, flags, 0, 0, NULL);
      nev++;
    }

  if (events & POLL_WRITE)
    {
      EV_SET (&ev[nev], fd, EVFILT_WRITE, flags, 0, 0, NULL);
      nev++;
    }

  if (nev == 0)
    return 0; /* No events requested - success */

  if (kevent (backend->kq, ev, nev, NULL, 0, NULL) < 0)
    return -1;

  return 0;
}

/**
 * backend_add - Add a file descriptor to kqueue monitoring
 * @backend: Backend instance (must not be NULL)
 * @fd: File descriptor to add (must be valid)
 * @events: Events to monitor (POLL_READ | POLL_WRITE bitmask)
 *
 * Returns: 0 on success, -1 on failure (errno set)
 *
 * Registers the fd with kqueue for the specified events. Uses EV_CLEAR
 * for edge-triggered mode.
 */
int
backend_add (PollBackend_T backend, int fd, unsigned events)
{
  assert (backend);
  VALIDATE_FD (fd);

  return setup_event_filters (backend, fd, events, EV_ADD);
}

/**
 * backend_mod - Modify events monitored for a file descriptor
 * @backend: Backend instance (must not be NULL)
 * @fd: File descriptor to modify (must be valid)
 * @events: New events to monitor (POLL_READ | POLL_WRITE bitmask)
 *
 * Returns: 0 on success, -1 on failure (errno set)
 *
 * Unlike epoll which has EPOLL_CTL_MOD, kqueue requires deleting existing
 * filters and adding new ones. This function deletes both read and write
 * filters first (silently succeeding if not present), then adds the
 * requested filters.
 */
int
backend_mod (PollBackend_T backend, int fd, unsigned events)
{
  assert (backend);
  VALIDATE_FD (fd);

  /* kqueue doesn't have EPOLL_CTL_MOD equivalent - delete and re-add.
   * Delete both filters first (silently succeeds if not present). */
  (void)setup_event_filters (backend, fd, POLL_READ | POLL_WRITE, EV_DELETE);

  return setup_event_filters (backend, fd, events, EV_ADD);
}

/**
 * backend_del - Remove a file descriptor from kqueue monitoring
 * @backend: Backend instance (must not be NULL)
 * @fd: File descriptor to remove (must be valid)
 *
 * Returns: 0 (always succeeds)
 *
 * Removes both read and write filters for the fd. Errors from kevent()
 * are ignored since the filters may not have been registered (e.g., if
 * only POLL_READ was registered, deleting POLL_WRITE is harmless).
 */
int
backend_del (PollBackend_T backend, int fd)
{
  assert (backend);
  VALIDATE_FD (fd);

  /* Delete both filters - ignore errors (silent success if not present) */
  (void)setup_event_filters (backend, fd, POLL_READ | POLL_WRITE, EV_DELETE);

  return 0;
}

/**
 * backend_wait - Wait for events on monitored file descriptors
 * @backend: Backend instance (const - read-only)
 * @timeout_ms: Timeout in milliseconds (-1 for infinite wait)
 *
 * Returns: Number of events ready (0 on timeout or EINTR), -1 on error
 *
 * Blocks until events are available or timeout expires. Results are
 * stored in the backend's internal event array and can be retrieved
 * via backend_get_event(). EINTR is handled by returning 0, allowing
 * the caller to retry or handle signals.
 * Thread-safe: No (kevent not thread-safe)
 */
int
backend_wait (PollBackend_T backend, int timeout_ms)
{
  struct timespec ts;
  struct timespec *timeout_ptr = NULL;
  int nev;

  assert (backend);

  /* Convert milliseconds to timespec using defined constant */
  if (timeout_ms >= 0)
    {
      ts.tv_sec = timeout_ms / SOCKET_MS_PER_SECOND;
      ts.tv_nsec = (timeout_ms % SOCKET_MS_PER_SECOND) * SOCKET_NS_PER_MS;
      timeout_ptr = &ts;
    }
  /* If timeout_ms is -1, timeout_ptr stays NULL (infinite wait) */

  nev = kevent (backend->kq, NULL, 0, backend->events, backend->maxevents,
                timeout_ptr);

  if (nev < 0)
    {
      backend->last_nev = 0;
      /* kevent was interrupted by signal - return 0 to allow retry */
      if (errno == EINTR)
        return 0;
      return -1;
    }

  backend->last_nev = nev;
  return nev;
}

/**
 * backend_get_event - Retrieve event details from wait results
 * @backend: Backend instance (read-only access to events; last_nev indicates
 * valid range)
 * @index: Event index (0 to backend->last_nev - 1 from most recent
 * backend_wait)
 * @fd_out: Output: file descriptor that triggered the event
 * @events_out: Output: event flags (POLL_READ | POLL_WRITE | POLL_ERROR |
 * POLL_HANGUP)
 *
 * Returns: 0 on success, -1 if index out of valid range (0 to last_nev-1 or >=
 * maxevents)
 *
 * Translates kqueue's kevent structure to the portable POLL_* event flags.
 * kqueue reports each filter (read/write) as a separate event, unlike
 * epoll which can combine them. EV_EOF is mapped to POLL_HANGUP,
 * indicating the peer has closed the connection.
 * Thread-safe: No
 */
int
backend_get_event (const PollBackend_T backend, int index, int *fd_out,
                   unsigned *events_out)
{
  struct kevent *kev;
  unsigned events = 0;

  assert (backend);
  assert (fd_out);
  assert (events_out);

  /* last_nev is always <= maxevents (kevent return bounded by maxevents) */
  if (index < 0 || index >= backend->last_nev)
    return -1;

  kev = &backend->events[index];

  /* Extract file descriptor from kevent ident field */
  *fd_out = (int)kev->ident;

  /* Translate kqueue filter to portable event flags */
  if (kev->filter == EVFILT_READ)
    events |= POLL_READ;

  if (kev->filter == EVFILT_WRITE)
    events |= POLL_WRITE;

  /* Check for error conditions */
  if (kev->flags & EV_ERROR)
    events |= POLL_ERROR;

  if (kev->flags & EV_EOF)
    {
      /* EOF indicates peer closed connection or write-side shutdown */
      events |= POLL_HANGUP;
    }

  *events_out = events;
  return 0;
}

/**
 * backend_name - Get the backend implementation name
 *
 * Returns: Static string "kqueue"
 *
 * Used for logging and debugging to identify which event backend is in use.
 */
const char *
backend_name (void)
{
  return "kqueue";
}

#endif /* BSD/macOS platform guard */

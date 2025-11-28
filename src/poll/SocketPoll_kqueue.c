/**
 * SocketPoll_kqueue.c - kqueue backend for BSD/macOS
 * PLATFORM: BSD/macOS (requires kqueue)
 * - FreeBSD: Full support (kqueue/kevent)
 * - OpenBSD: Full support
 * - NetBSD: Full support
 * - macOS: Full support
 * - Linux: Not supported (use epoll backend instead)
 */

/* Platform guard: kqueue is only available on BSD/macOS.
 * On other platforms, this file compiles as an empty translation unit.
 * CMake selects the appropriate backend file for each platform. */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__)          \
    || defined(__OpenBSD__) || defined(__DragonFly__)

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/SocketConfig.h"
#include "poll/SocketPoll_backend.h"

/* Backend instance structure */
struct PollBackend_T
{
  int kq;                /* kqueue file descriptor */
  struct kevent *events; /* Event array for results */
  int maxevents;         /* Maximum events per wait */
};

PollBackend_T
backend_new (int maxevents)
{
  PollBackend_T backend;

  assert (maxevents > 0);

  backend = calloc (1, sizeof (*backend));
  if (!backend)
    return NULL;

  backend->kq = kqueue ();
  if (backend->kq < 0)
    {
      free (backend);
      return NULL;
    }

  backend->events = calloc (maxevents, sizeof (struct kevent));
  if (!backend->events)
    {
      SAFE_CLOSE (backend->kq);
      free (backend);
      return NULL;
    }

  backend->maxevents = maxevents;
  return backend;
}

void
backend_free (PollBackend_T backend)
{
  assert (backend);

  SAFE_CLOSE (backend->kq);

  if (backend->events)
    free (backend->events);

  free (backend);
}

/**
 * setup_event_filters - Setup kqueue event filters for read/write
 * @backend: Backend instance
 * @fd: File descriptor
 * @events: Events to monitor (POLL_READ | POLL_WRITE)
 * @action: EV_ADD or EV_DELETE
 * Returns: 0 on success, -1 on failure
 *
 * Common helper for add/mod operations to eliminate duplicate code.
 * EV_CLEAR enables edge-triggered mode matching epoll's EPOLLET.
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
    return 0; /* No events - success */

  if (kevent (backend->kq, ev, nev, NULL, 0, NULL) < 0)
    return -1;

  return 0;
}

int
backend_add (PollBackend_T backend, int fd, unsigned events)
{
  assert (backend);
  VALIDATE_FD (fd);

  return setup_event_filters (backend, fd, events, EV_ADD);
}

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

int
backend_del (PollBackend_T backend, int fd)
{
  assert (backend);
  VALIDATE_FD (fd);

  /* Delete both filters - ignore errors (silent success if not present) */
  (void)setup_event_filters (backend, fd, POLL_READ | POLL_WRITE, EV_DELETE);

  return 0;
}

int
backend_wait (PollBackend_T backend, int timeout_ms)
{
  struct timespec ts;
  struct timespec *timeout_ptr = NULL;
  int nev;

  assert (backend);

  /* Convert milliseconds to timespec */
  if (timeout_ms >= 0)
    {
      ts.tv_sec = timeout_ms / 1000;
      ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
      timeout_ptr = &ts;
    }
  /* If timeout_ms is -1, timeout_ptr stays NULL (infinite wait) */

  nev = kevent (backend->kq, NULL, 0, backend->events, backend->maxevents,
                timeout_ptr);

  if (nev < 0)
    {
      /* kevent was interrupted by signal */
      if (errno == EINTR)
        return 0;
      return -1;
    }

  return nev;
}

int
backend_get_event (PollBackend_T backend, int index, int *fd_out,
                   unsigned *events_out)
{
  struct kevent *kev;
  unsigned events = 0;

  assert (backend);
  assert (fd_out);
  assert (events_out);

  if (index < 0 || index >= backend->maxevents)
    return -1;

  kev = &backend->events[index];

  /* Extract file descriptor */
  *fd_out = (int)kev->ident;

  /* Translate kqueue events to our event flags */
  if (kev->filter == EVFILT_READ)
    events |= POLL_READ;

  if (kev->filter == EVFILT_WRITE)
    events |= POLL_WRITE;

  /* Check for error conditions */
  if (kev->flags & EV_ERROR)
    events |= POLL_ERROR;

  if (kev->flags & EV_EOF)
    {
      /* EOF on read or write means hangup */
      events |= POLL_HANGUP;
    }

  *events_out = events;
  return 0;
}

const char *
backend_name (void)
{
  return "kqueue";
}

#endif /* BSD/macOS platform guard */

/**
 * SocketPoll_epoll.c - epoll backend for Linux
 * PLATFORM: Linux (requires epoll)
 * - Linux kernel 2.6.8+ for full epoll support
 * - Edge-triggered mode via EPOLLET
 * - Best performance on Linux
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "poll/SocketPoll_backend.h"

/* Backend instance structure */
struct PollBackend_T
{
  int epfd;                   /* epoll file descriptor */
  struct epoll_event *events; /* Event array for results */
  int maxevents;              /* Maximum events per wait */
};

PollBackend_T
backend_new (int maxevents)
{
  PollBackend_T backend;

  assert (maxevents > 0);

  backend = calloc (1, sizeof (*backend));
  if (!backend)
    return NULL;

  backend->epfd = epoll_create1 (0);
  if (backend->epfd < 0)
    {
      free (backend);
      return NULL;
    }

  backend->events = calloc (maxevents, sizeof (struct epoll_event));
  if (!backend->events)
    {
      close (backend->epfd);
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

  if (backend->epfd >= 0)
    close (backend->epfd);

  if (backend->events)
    free (backend->events);

  free (backend);
}

/* Helper: Translate poll events to epoll events
 * Returns epoll events with edge-triggered mode (EPOLLET) */
static unsigned
translate_to_epoll (unsigned events)
{
  unsigned epoll_events = 0;

  if (events & POLL_READ)
    epoll_events |= EPOLLIN;

  if (events & POLL_WRITE)
    epoll_events |= EPOLLOUT;

  return epoll_events | EPOLLET; /* Edge-triggered mode */
}

/* Helper: Translate epoll events to our event flags */
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

int
backend_add (PollBackend_T backend, int fd, unsigned events)
{
  struct epoll_event ev;

  assert (backend);
  assert (fd >= 0);

  memset (&ev, 0, sizeof (ev));
  ev.events = translate_to_epoll (events);
  ev.data.fd = fd;

  if (epoll_ctl (backend->epfd, EPOLL_CTL_ADD, fd, &ev) < 0)
    return -1;

  return 0;
}

int
backend_mod (PollBackend_T backend, int fd, unsigned events)
{
  struct epoll_event ev;

  assert (backend);
  assert (fd >= 0);

  memset (&ev, 0, sizeof (ev));
  ev.events = translate_to_epoll (events);
  ev.data.fd = fd;

  if (epoll_ctl (backend->epfd, EPOLL_CTL_MOD, fd, &ev) < 0)
    return -1;

  return 0;
}

int
backend_del (PollBackend_T backend, int fd)
{
  assert (backend);
  assert (fd >= 0);

  /* Note: event parameter is ignored in Linux 2.6.9+, but we pass NULL
   * for older kernels compatibility */
  if (epoll_ctl (backend->epfd, EPOLL_CTL_DEL, fd, NULL) < 0)
    {
      /* Silently succeed if fd not in set */
      if (errno == ENOENT || errno == EBADF)
        return 0;
      return -1;
    }

  return 0;
}

int
backend_wait (PollBackend_T backend, int timeout_ms)
{
  int nev;

  assert (backend);

  nev = epoll_wait (backend->epfd, backend->events, backend->maxevents,
                    timeout_ms);

  if (nev < 0)
    {
      /* epoll_wait was interrupted by signal */
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
  struct epoll_event *ev;

  assert (backend);
  assert (fd_out);
  assert (events_out);

  if (index < 0 || index >= backend->maxevents)
    return -1;

  ev = &backend->events[index];

  *fd_out = ev->data.fd;
  *events_out = translate_from_epoll (ev->events);

  return 0;
}

const char *
backend_name (void)
{
  return "epoll";
}

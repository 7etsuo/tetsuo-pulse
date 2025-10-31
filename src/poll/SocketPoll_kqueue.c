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
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "poll/SocketPoll_backend.h"

/* Backend instance structure */
struct PollBackend_T
{
    int kq;                /* kqueue file descriptor */
    struct kevent *events; /* Event array for results */
    int maxevents;         /* Maximum events per wait */
};

PollBackend_T backend_new(int maxevents)
{
    PollBackend_T backend;

    assert(maxevents > 0);

    backend = calloc(1, sizeof(*backend));
    if (!backend)
        return NULL;

    backend->kq = kqueue();
    if (backend->kq < 0)
    {
        free(backend);
        return NULL;
    }

    backend->events = calloc(maxevents, sizeof(struct kevent));
    if (!backend->events)
    {
        close(backend->kq);
        free(backend);
        return NULL;
    }

    backend->maxevents = maxevents;
    return backend;
}

void backend_free(PollBackend_T backend)
{
    assert(backend);

    if (backend->kq >= 0)
        close(backend->kq);

    if (backend->events)
        free(backend->events);

    free(backend);
}

int backend_add(PollBackend_T backend, int fd, unsigned events)
{
    struct kevent ev[2];
    int nev = 0;

    assert(backend);
    assert(fd >= 0);

    /* Add read event if requested
     * EV_ADD: Add event to kqueue
     * EV_CLEAR: Edge-triggered mode (clear after delivery)
     * This matches epoll's EPOLLET behavior */
    if (events & POLL_READ)
    {
        EV_SET(&ev[nev], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
        nev++;
    }

    /* Add write event if requested */
    if (events & POLL_WRITE)
    {
        EV_SET(&ev[nev], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, NULL);
        nev++;
    }

    if (nev == 0)
    {
        /* No events to add - treat as success */
        return 0;
    }

    /* Register events with kqueue */
    if (kevent(backend->kq, ev, nev, NULL, 0, NULL) < 0)
        return -1;

    return 0;
}

int backend_mod(PollBackend_T backend, int fd, unsigned events)
{
    struct kevent ev[4];
    int nev = 0;

    assert(backend);
    assert(fd >= 0);

    /* kqueue doesn't have a "modify" operation like epoll
     * Instead, we delete existing events and add new ones
     * This is safe because EV_DELETE silently succeeds if event doesn't exist
     */

    /* Delete existing read filter */
    EV_SET(&ev[nev], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    nev++;

    /* Delete existing write filter */
    EV_SET(&ev[nev], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    nev++;

    /* Apply deletions (ignore errors - events may not exist) */
    kevent(backend->kq, ev, nev, NULL, 0, NULL);

    /* Now add new events */
    nev = 0;

    if (events & POLL_READ)
    {
        EV_SET(&ev[nev], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
        nev++;
    }

    if (events & POLL_WRITE)
    {
        EV_SET(&ev[nev], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, NULL);
        nev++;
    }

    if (nev == 0)
    {
        /* No events to add - all deleted, treat as success */
        return 0;
    }

    /* Register new events */
    if (kevent(backend->kq, ev, nev, NULL, 0, NULL) < 0)
        return -1;

    return 0;
}

int backend_del(PollBackend_T backend, int fd)
{
    struct kevent ev[2];
    int nev = 0;

    assert(backend);
    assert(fd >= 0);

    /* Delete both read and write filters
     * EV_DELETE silently succeeds if filter doesn't exist */
    EV_SET(&ev[nev], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    nev++;

    EV_SET(&ev[nev], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    nev++;

    /* Apply deletions - ignore errors since we want silent success */
    kevent(backend->kq, ev, nev, NULL, 0, NULL);

    return 0;
}

int backend_wait(PollBackend_T backend, int timeout_ms)
{
    struct timespec ts;
    struct timespec *timeout_ptr = NULL;
    int nev;

    assert(backend);

    /* Convert milliseconds to timespec */
    if (timeout_ms >= 0)
    {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
        timeout_ptr = &ts;
    }
    /* If timeout_ms is -1, timeout_ptr stays NULL (infinite wait) */

    nev = kevent(backend->kq, NULL, 0, backend->events, backend->maxevents, timeout_ptr);

    if (nev < 0)
    {
        /* kevent was interrupted by signal */
        if (errno == EINTR)
            return 0;
        return -1;
    }

    return nev;
}

int backend_get_event(PollBackend_T backend, int index, int *fd_out, unsigned *events_out)
{
    struct kevent *kev;
    unsigned events = 0;

    assert(backend);
    assert(fd_out);
    assert(events_out);

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

const char *backend_name(void)
{
    return "kqueue";
}

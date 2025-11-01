/**
 * SocketPoll_poll.c - poll(2) fallback backend
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * PLATFORM: Any POSIX system (poll is standardized in POSIX.1-2001)
 * - Portable to all POSIX-compliant systems
 * - Performance: O(n) where n = number of file descriptors
 * - Level-triggered only (poll limitation)
 * - Good for < 100 connections or testing
 */

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>

#include "poll/SocketPoll_backend.h"

/* Initial pollfd array size - use configured constant */
#define INITIAL_POLLFDS POLL_INITIAL_FDS

/* Backend instance structure */
struct PollBackend_T
{
    struct pollfd *fds;  /* Array of pollfd structures */
    int *fd_to_index;    /* FD to index mapping (for O(1) lookup) */
    int nfds;            /* Current number of FDs */
    int capacity;        /* Capacity of fds array */
    int maxevents;       /* Maximum events per wait (not strictly enforced) */
    int last_wait_count; /* Number of events from last wait */
    int max_fd;          /* Maximum FD value seen */
};

PollBackend_T backend_new(int maxevents)
{
    PollBackend_T backend;

    assert(maxevents > 0);

    backend = calloc(1, sizeof(*backend));
    if (!backend)
        return NULL;

    backend->capacity = INITIAL_POLLFDS;
    backend->fds = calloc(backend->capacity, sizeof(struct pollfd));
    if (!backend->fds)
    {
        free(backend);
        return NULL;
    }

    /* Allocate FD mapping table - size based on typical FD range */
    backend->max_fd = POLL_INITIAL_FD_MAP_SIZE;
    backend->fd_to_index = calloc(backend->max_fd, sizeof(int));
    if (!backend->fd_to_index)
    {
        free(backend->fds);
        free(backend);
        return NULL;
    }

    /* Initialize mapping to -1 (invalid) */
    for (int i = 0; i < backend->max_fd; i++)
        backend->fd_to_index[i] = -1;

    backend->nfds = 0;
    backend->maxevents = maxevents;
    backend->last_wait_count = 0;

    return backend;
}

void backend_free(PollBackend_T backend)
{
    assert(backend);

    if (backend->fds)
        free(backend->fds);

    if (backend->fd_to_index)
        free(backend->fd_to_index);

    free(backend);
}

/* Helper: Find index of fd in pollfd array */
static int find_fd_index(PollBackend_T backend, int fd)
{
    if (fd < 0 || fd >= backend->max_fd)
        return -1;

    return backend->fd_to_index[fd];
}

/* Helper: Ensure fd mapping table is large enough */
static int ensure_fd_mapping(PollBackend_T backend, int fd)
{
    int new_max, i;
    int *new_mapping;

    if (fd < backend->max_fd)
        return 0;

    /* Expand mapping table */
    new_max = fd + POLL_FD_MAP_EXPAND_INCREMENT;
    new_mapping = calloc(new_max, sizeof(int));
    if (!new_mapping)
        return -1;

    /* Copy old mappings */
    memcpy(new_mapping, backend->fd_to_index, backend->max_fd * sizeof(int));

    /* Initialize new entries to -1 */
    for (i = backend->max_fd; i < new_max; i++)
        new_mapping[i] = -1;

    free(backend->fd_to_index);
    backend->fd_to_index = new_mapping;
    backend->max_fd = new_max;

    return 0;
}

/* Helper: Ensure pollfd array has capacity */
static int ensure_capacity(PollBackend_T backend)
{
    struct pollfd *new_fds;
    int new_capacity;

    if (backend->nfds < backend->capacity)
        return 0;

    /* Double the capacity */
    new_capacity = backend->capacity * 2;
    new_fds = realloc(backend->fds, new_capacity * sizeof(struct pollfd));
    if (!new_fds)
        return -1;

    backend->fds = new_fds;
    backend->capacity = new_capacity;

    return 0;
}

/* Helper: Translate poll events to our event flags */
static unsigned translate_to_poll_events(unsigned events)
{
    unsigned poll_events = 0;

    if (events & POLL_READ)
        poll_events |= POLLIN;

    if (events & POLL_WRITE)
        poll_events |= POLLOUT;

    return poll_events;
}

/* Helper: Translate poll events from poll(2) to our flags */
static unsigned translate_from_poll_events(short revents)
{
    unsigned events = 0;

    if (revents & POLLIN)
        events |= POLL_READ;

    if (revents & POLLOUT)
        events |= POLL_WRITE;

    if (revents & POLLERR)
        events |= POLL_ERROR;

    if (revents & POLLHUP)
        events |= POLL_HANGUP;

    return events;
}

int backend_add(PollBackend_T backend, int fd, unsigned events)
{
    int index;

    assert(backend);
    assert(fd >= 0);

    /* Check if already added */
    if (find_fd_index(backend, fd) >= 0)
    {
        errno = EEXIST;
        return -1;
    }

    /* Ensure capacity */
    if (ensure_capacity(backend) < 0)
        return -1;

    /* Ensure FD mapping table is large enough */
    if (ensure_fd_mapping(backend, fd) < 0)
        return -1;

    /* Add to pollfd array */
    index = backend->nfds;
    backend->fds[index].fd = fd;
    backend->fds[index].events = translate_to_poll_events(events);
    backend->fds[index].revents = 0;

    /* Update mapping */
    backend->fd_to_index[fd] = index;

    backend->nfds++;

    return 0;
}

int backend_mod(PollBackend_T backend, int fd, unsigned events)
{
    int index;

    assert(backend);
    assert(fd >= 0);

    index = find_fd_index(backend, fd);
    if (index < 0)
    {
        errno = ENOENT;
        return -1;
    }

    /* Modify events */
    backend->fds[index].events = translate_to_poll_events(events);
    backend->fds[index].revents = 0;

    return 0;
}

int backend_del(PollBackend_T backend, int fd)
{
    int index, last_index, last_fd;

    assert(backend);
    assert(fd >= 0);

    index = find_fd_index(backend, fd);
    if (index < 0)
    {
        /* Not found - silent success */
        return 0;
    }

    /* Remove from array by swapping with last element */
    last_index = backend->nfds - 1;

    if (index != last_index)
    {
        /* Swap with last element */
        backend->fds[index] = backend->fds[last_index];

        /* Update mapping for moved FD */
        last_fd = backend->fds[index].fd;
        if (last_fd >= 0 && last_fd < backend->max_fd)
            backend->fd_to_index[last_fd] = index;
    }

    /* Clear mapping for removed FD */
    if (fd >= 0 && fd < backend->max_fd)
        backend->fd_to_index[fd] = -1;

    backend->nfds--;

    return 0;
}

int backend_wait(PollBackend_T backend, int timeout_ms)
{
    int result;

    assert(backend);

    if (backend->nfds == 0)
    {
        /* No FDs to poll - simulate timeout */
        if (timeout_ms > 0)
        {
            struct timespec ts;
            ts.tv_sec = timeout_ms / 1000;
            ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
            nanosleep(&ts, NULL);
        }
        return 0;
    }

    result = poll(backend->fds, backend->nfds, timeout_ms);

    if (result < 0)
    {
        /* poll was interrupted by signal */
        if (errno == EINTR)
            return 0;
        return -1;
    }

    backend->last_wait_count = result;
    return result;
}

int backend_get_event(PollBackend_T backend, int index, int *fd_out, unsigned *events_out)
{
    int i, count = 0;

    assert(backend);
    assert(fd_out);
    assert(events_out);

    /* poll returns count of ready FDs, but we need to scan array
     * to find the nth ready FD */
    for (i = 0; i < backend->nfds; i++)
    {
        if (backend->fds[i].revents != 0)
        {
            if (count == index)
            {
                *fd_out = backend->fds[i].fd;
                *events_out = translate_from_poll_events(backend->fds[i].revents);
                return 0;
            }
            count++;
        }
    }

    /* Index out of range */
    return -1;
}

const char *backend_name(void)
{
    return "poll";
}

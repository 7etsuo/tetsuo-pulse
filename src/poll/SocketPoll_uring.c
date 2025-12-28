/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketPoll_uring.c - io_uring backend for Linux
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * PLATFORM: Linux (requires io_uring and liburing)
 * - Linux kernel 5.1+ for basic io_uring support
 * - Linux kernel 5.13+ for multishot poll (IORING_POLL_ADD_MULTI)
 * - Uses IORING_OP_POLL_ADD for fd monitoring
 *
 * Thread-safe: No (caller must synchronize access)
 */

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <liburing.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketUtil.h" /* For socket_util_ms_to_timespec and other utilities */
#include "poll/SocketPoll_backend.h"
#include "socket/Socket.h" /* For Socket_get_monotonic_ms */

/* Ring size for io_uring queue */
#ifndef SOCKET_IO_URING_POLL_ENTRIES
#define SOCKET_IO_URING_POLL_ENTRIES 256
#endif

/* Backend instance structure */
#define T PollBackend_T
typedef struct T *T;

/**
 * Ready event structure for backend_get_event
 */
struct ready_event
{
  int fd;
  unsigned events;
};

struct T
{
  struct io_uring ring;          /* io_uring instance */
  int maxevents;                 /* Maximum events per wait */
  int last_nev;                  /* Valid events from last backend_wait */
  struct ready_event *events;    /* Results array for backend_get_event */
};
#undef T

/**
 * @brief Mapping between portable poll events and io_uring poll flags.
 *
 * io_uring poll uses standard POLLIN/POLLOUT flags.
 */
static const struct
{
  unsigned poll_event;
  unsigned uring_flag;
} poll_to_uring_map[] = {
    { POLL_READ, POLLIN },
    { POLL_WRITE, POLLOUT },
    { 0, 0 }
};

/**
 * @brief Mapping between io_uring poll flags and portable poll events.
 */
static const struct
{
  unsigned uring_flag;
  unsigned poll_flag;
} uring_event_map[] = {
    { POLLIN, POLL_READ },
    { POLLOUT, POLL_WRITE },
    { POLLERR, POLL_ERROR },
    { POLLHUP, POLL_HANGUP },
    { 0, 0 }
};

/**
 * translate_to_uring - Convert abstract poll events to io_uring poll mask
 * @events: Abstract poll event flags (POLL_READ, POLL_WRITE)
 *
 * Returns: poll mask for io_uring POLL_ADD operation.
 */
static unsigned
translate_to_uring (unsigned events)
{
  unsigned uring_events = 0;

  for (size_t i = 0; poll_to_uring_map[i].poll_event != 0; ++i)
    {
      if (events & poll_to_uring_map[i].poll_event)
        uring_events |= poll_to_uring_map[i].uring_flag;
    }

  return uring_events;
}

/**
 * translate_from_uring - Convert io_uring poll result to abstract poll events
 * @uring_events: Poll result from CQE (POLLIN, POLLOUT, etc.)
 *
 * Returns: Abstract poll event flags.
 */
static unsigned
translate_from_uring (unsigned uring_events)
{
  unsigned events = 0;

  for (size_t i = 0; uring_event_map[i].uring_flag != 0; ++i)
    {
      if (uring_events & uring_event_map[i].uring_flag)
        events |= uring_event_map[i].poll_flag;
    }

  return events;
}

/**
 * backend_new - Create new io_uring backend instance
 * @arena: Arena for allocations
 * @maxevents: Maximum events to return per wait (must be > 0)
 *
 * Returns: New backend instance, or NULL on failure (errno set).
 */
PollBackend_T
backend_new (Arena_T arena, int maxevents)
{
  PollBackend_T backend;
  int ret;

  assert (arena != NULL);

  VALIDATE_MAXEVENTS (maxevents, struct ready_event);

  backend = CALLOC (arena, 1, sizeof (*backend));
  if (!backend)
    return NULL;

  ret = io_uring_queue_init (SOCKET_IO_URING_POLL_ENTRIES, &backend->ring, 0);
  if (ret < 0)
    {
      errno = -ret;
      return NULL;
    }

  backend->events
      = CALLOC (arena, (size_t)maxevents, sizeof (struct ready_event));
  if (!backend->events)
    {
      io_uring_queue_exit (&backend->ring);
      return NULL;
    }

  backend->maxevents = maxevents;
  backend->last_nev = 0;
  return backend;
}

/**
 * backend_free - Close io_uring backend resources
 * @backend: Backend instance
 *
 * Exits the io_uring queue. Memory freed by arena dispose.
 */
void
backend_free (PollBackend_T backend)
{
  assert (backend);

  io_uring_queue_exit (&backend->ring);
}

/**
 * @brief Store file descriptor in io_uring SQE user_data field
 * @param sqe SQE to modify
 * @param fd File descriptor to store
 *
 * Centralizes the fd-to-user_data cast pattern used throughout the backend.
 */
static inline void
set_sqe_fd (struct io_uring_sqe *sqe, int fd)
{
  io_uring_sqe_set_data64 (sqe, (uint64_t)(uintptr_t)fd);
}

/**
 * submit_poll_add - Submit a POLL_ADD operation to the ring
 * @backend: Backend instance
 * @fd: File descriptor to monitor
 * @poll_mask: Poll event mask (POLLIN, POLLOUT, etc.)
 *
 * Returns: 0 on success, -1 on failure (errno set).
 *
 * Uses multishot poll (IORING_POLL_ADD_MULTI) if available for persistent
 * monitoring, otherwise falls back to single-shot poll.
 */
static int
submit_poll_add (PollBackend_T backend, int fd, unsigned poll_mask)
{
  struct io_uring_sqe *sqe;
  int ret;

  sqe = io_uring_get_sqe (&backend->ring);
  if (!sqe)
    {
      errno = EAGAIN;
      return -1;
    }

  io_uring_prep_poll_add (sqe, fd, poll_mask);

#ifdef IORING_POLL_ADD_MULTI
  /* Use multishot poll for persistent monitoring (kernel 5.13+) */
  sqe->len |= IORING_POLL_ADD_MULTI;
#endif

  /* Store fd in user_data for retrieval in CQE */
  set_sqe_fd (sqe, fd);

  ret = io_uring_submit (&backend->ring);
  if (ret < 0)
    {
      errno = -ret;
      return -1;
    }

  return 0;
}

/**
 * backend_add - Add file descriptor to io_uring poll set
 * @backend: Poll backend instance
 * @fd: File descriptor to add
 * @events: Abstract poll event flags (POLL_READ, POLL_WRITE)
 *
 * Returns: 0 on success, -1 on failure (errno set).
 */
int
backend_add (PollBackend_T backend, int fd, unsigned events)
{
  unsigned poll_mask;

  assert (backend);
  VALIDATE_FD (fd);

  poll_mask = translate_to_uring (events);
  return submit_poll_add (backend, fd, poll_mask);
}

/**
 * backend_mod - Modify file descriptor events in io_uring poll set
 * @backend: Poll backend instance
 * @fd: File descriptor to modify
 * @events: New abstract poll event flags
 *
 * Returns: 0 on success, -1 on failure (errno set).
 *
 * io_uring requires cancel + re-add for modification.
 */
int
backend_mod (PollBackend_T backend, int fd, unsigned events)
{
  struct io_uring_sqe *sqe;
  struct io_uring_cqe *cqe;
  unsigned poll_mask;
  int ret;

  assert (backend);
  VALIDATE_FD (fd);

  /* Cancel existing poll for this fd */
  sqe = io_uring_get_sqe (&backend->ring);
  if (!sqe)
    {
      errno = EAGAIN;
      return -1;
    }

  io_uring_prep_poll_remove (sqe, (__u64)(uintptr_t)fd);
  set_sqe_fd (sqe, 0); /* Mark as internal operation */

  ret = io_uring_submit (&backend->ring);
  if (ret < 0)
    {
      errno = -ret;
      return -1;
    }

  /* Wait for cancel to complete */
  ret = io_uring_wait_cqe (&backend->ring, &cqe);
  if (ret == 0)
    io_uring_cqe_seen (&backend->ring, cqe);

  /* Re-add with new events */
  poll_mask = translate_to_uring (events);
  return submit_poll_add (backend, fd, poll_mask);
}

/**
 * backend_del - Remove file descriptor from io_uring poll set
 * @backend: Poll backend instance
 * @fd: File descriptor to remove
 *
 * Returns: 0 on success (including if fd not in set), -1 on error.
 */
int
backend_del (PollBackend_T backend, int fd)
{
  struct io_uring_sqe *sqe;
  struct io_uring_cqe *cqe;
  int ret;

  assert (backend);
  VALIDATE_FD (fd);

  sqe = io_uring_get_sqe (&backend->ring);
  if (!sqe)
    return 0; /* Best-effort removal */

  io_uring_prep_poll_remove (sqe, (__u64)(uintptr_t)fd);
  set_sqe_fd (sqe, 0); /* Mark as internal operation */

  ret = io_uring_submit (&backend->ring);
  if (ret < 0)
    {
      /* Silently succeed - fd may not be registered */
      if (-ret == ENOENT || -ret == EBADF)
        return 0;
      errno = -ret;
      return -1;
    }

  /* Non-blocking check for completion */
  if (io_uring_peek_cqe (&backend->ring, &cqe) == 0)
    io_uring_cqe_seen (&backend->ring, cqe);

  return 0;
}

/**
 * calculate_remaining_timeout - Calculate remaining time after EINTR
 * @timeout_ms: Original timeout (-1 infinite, 0 non-blocking, >0 deadline)
 * @deadline_ms: Absolute deadline in milliseconds (0 if infinite)
 * @now_ms: Current monotonic time in milliseconds
 *
 * Returns: Remaining timeout in milliseconds, or -1 for infinite, or 0 if
 * expired.
 *
 * Helper for EINTR retry logic. Calculates how much time is left before
 * the deadline. Returns 0 if deadline has passed (timeout expired).
 */
static int
calculate_remaining_timeout (int timeout_ms, int64_t deadline_ms,
                              int64_t now_ms)
{
  if (timeout_ms == 0)
    return 0; /* Non-blocking */

  if (timeout_ms < 0)
    return -1; /* Infinite */

  /* Positive timeout: check deadline */
  if (now_ms >= deadline_ms)
    return 0; /* Expired */

  return (int)(deadline_ms - now_ms);
}

/**
 * wait_for_cqe - Wait for CQE with timeout and EINTR retry
 * @backend: Backend instance
 * @timeout_ms: Timeout in milliseconds (-1 infinite, 0 non-blocking, >0
 * deadline)
 * @cqe_out: Output for first CQE pointer (if successful)
 *
 * Returns: 0 on success (CQE available), or number of events on timeout (0),
 *          or -1 on error (errno set).
 *
 * Handles EINTR retry with deadline tracking. Returns 0 (timeout) if the
 * deadline expires during retry.
 */
static int
wait_for_cqe (PollBackend_T backend, int timeout_ms,
              struct io_uring_cqe **cqe_out)
{
  struct __kernel_timespec ts;
  struct __kernel_timespec *ts_ptr = NULL;
  int64_t deadline_ms = 0;
  int remaining_ms = timeout_ms;
  int ret;

  /* Calculate deadline for positive timeouts */
  if (timeout_ms > 0)
    deadline_ms = Socket_get_monotonic_ms () + timeout_ms;

  while (1)
    {
      /* Convert timeout to kernel timespec */
      if (remaining_ms >= 0)
        {
          ts = socket_util_ms_to_timespec ((unsigned long)remaining_ms);
          ts_ptr = &ts;
        }
      else
        {
          ts_ptr = NULL; /* Infinite wait */
        }

      /* Wait for at least one CQE */
      ret = io_uring_wait_cqe_timeout (&backend->ring, cqe_out, ts_ptr);

      if (ret == 0)
        return 0; /* Success: CQE available */

      if (ret == -ETIME)
        {
          backend->last_nev = 0;
          return 0; /* Timeout */
        }

      if (ret != -EINTR)
        {
          errno = -ret;
          return HANDLE_POLL_ERROR (backend);
        }

      /* EINTR: Recalculate remaining timeout */
      remaining_ms = calculate_remaining_timeout (
          timeout_ms, deadline_ms, Socket_get_monotonic_ms ());

      if (remaining_ms == 0)
        {
          backend->last_nev = 0;
          return 0; /* Deadline expired during retry */
        }
    }
}

/**
 * process_cqes - Process available CQEs into events array
 * @backend: Backend instance
 *
 * Returns: Number of events processed (may be 0).
 *
 * Translates io_uring CQEs to portable poll events. Handles single-shot
 * poll re-submission when IORING_POLL_ADD_MULTI is not available.
 * Advances the CQ ring after processing.
 */
static int
process_cqes (PollBackend_T backend)
{
  struct io_uring_cqe *cqe;
  unsigned head;
  unsigned consumed = 0;
  int nev = 0;

  io_uring_for_each_cqe (&backend->ring, head, cqe)
  {
    int fd;
    unsigned events_mask;

    /* Stop if we've filled the events array - don't consume this CQE */
    if (nev >= backend->maxevents)
      break;

    consumed++;

    fd = (int)(uintptr_t)cqe->user_data;

    /* Skip internal operations (poll_remove, etc.) */
    if (fd <= 0)
      continue;

    /* Defense-in-depth: validate fd is within reasonable bounds.
     * While io_uring user_data corruption is unlikely under normal operation,
     * this prevents processing invalid fds from corrupted CQEs. Follows the
     * same pattern as kqueue backend (SocketPoll_kqueue.c:331). */
    if ((uintptr_t)fd > (uintptr_t)INT_MAX)
      continue;

    if (cqe->res < 0)
      {
        /* Error on this fd */
        backend->events[nev].fd = fd;
        backend->events[nev].events = POLL_ERROR;
      }
    else
      {
        events_mask = (unsigned)cqe->res;
        backend->events[nev].fd = fd;
        backend->events[nev].events = translate_from_uring (events_mask);
      }

    nev++;

#ifndef IORING_POLL_ADD_MULTI
    /* Single-shot mode: re-submit poll for this fd */
    {
      struct io_uring_sqe *sqe = io_uring_get_sqe (&backend->ring);
      if (sqe)
        {
          unsigned poll_mask = (cqe->res > 0) ? (unsigned)cqe->res : POLLIN;
          io_uring_prep_poll_add (sqe, fd, poll_mask);
          set_sqe_fd (sqe, fd);
        }
    }
#endif
  }

  /* Advance CQ by total consumed CQEs, including skipped internal ops */
  io_uring_cq_advance (&backend->ring, consumed);

#ifndef IORING_POLL_ADD_MULTI
  /* Submit re-added polls */
  if (nev > 0)
    io_uring_submit (&backend->ring);
#endif

  return nev;
}

/**
 * backend_wait - Wait for events on the io_uring poll set
 * @backend: Poll backend instance
 * @timeout_ms: Timeout in milliseconds (-1 for infinite, 0 for non-blocking)
 *
 * Returns: Number of ready events (0 on timeout), -1 on error.
 *
 * Blocks until events are ready or timeout expires. Retries on EINTR.
 */
int
backend_wait (PollBackend_T backend, int timeout_ms)
{
  struct io_uring_cqe *cqe;
  int ret;
  int nev;

  assert (backend);

  /* Wait for CQE with timeout and EINTR handling */
  ret = wait_for_cqe (backend, timeout_ms, &cqe);
  if (ret != 0)
    return ret; /* Error or timeout */

  /* Process available CQEs into events array */
  nev = process_cqes (backend);

  backend->last_nev = nev;
  return nev;
}

/**
 * backend_get_event - Retrieve event at specified index
 * @backend: Backend instance
 * @index: Event index (0 to last_nev - 1)
 * @fd_out: Output for file descriptor
 * @events_out: Output for abstract poll event flags
 *
 * Returns: 0 on success, -1 if index out of valid range.
 */
int
backend_get_event (const PollBackend_T backend, int index, int *fd_out,
                   unsigned *events_out)
{
  assert (backend);

  if (index < 0 || index >= backend->last_nev || index >= backend->maxevents)
    return -1;

  *fd_out = backend->events[index].fd;
  *events_out = backend->events[index].events;
  return 0;
}

/**
 * backend_name - Get human-readable name of this backend
 *
 * Returns: Static string "io_uring" identifying this backend.
 */
const char *
backend_name (void)
{
  return "io_uring";
}

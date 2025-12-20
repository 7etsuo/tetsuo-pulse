/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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
 * - Best suited for < 100 connections or testing/portability
 *
 * IMPLEMENTATION NOTES:
 * - Uses fd_to_index mapping table for O(1) FD lookup via find_fd_index()
 * - Dynamically expands capacity as needed with overflow protection
 * - backend_get_event requires O(n) scan due to poll(2) design limitation
 * - All constants from SocketConfig.h: POLL_INITIAL_FDS,
 *   POLL_INITIAL_FD_MAP_SIZE
 *
 * THREAD SAFETY: Individual backend instances are NOT thread-safe.
 * Each thread should use its own SocketPoll instance.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketSecurity.h"
#include "poll/SocketPoll_backend.h"

/* Sentinel value indicating FD not in poll set */
#define FD_INDEX_INVALID (-1)

/* Backend instance structure */
#define T PollBackend_T
struct T
{
  struct pollfd *fds;  /* Array of pollfd structures */
  int *fd_to_index;    /* FD to index mapping (for O(1) lookup) */
  int nfds;            /* Current number of FDs */
  int capacity;        /* Capacity of fds array */
  int maxevents;       /* Maximum events per wait (not strictly enforced) */
  int last_wait_count; /* Number of events from last wait */
  int last_nev;        /* Valid events from last backend_wait */
  int max_fd;          /* Maximum FD value seen */
  int max_fd_limit;    /* Maximum allowed size for FD mapping to prevent OOM */
};
#undef T

/* ==================== Safe Allocation Helpers ==================== */

/* Inlined into callers to reduce redundancy; uses SocketSecurity_check_multiply directly */

/* safe_realloc_array inlined into callers using SocketSecurity_check_multiply */

/* ==================== Integer Safe Arithmetic Helpers ==================== */

/* safe_int_add and safe_int_double inlined into callers using SocketSecurity_check_add/multiply directly */

/* ==================== Initialization Helpers ==================== */

/**
 * init_fd_mapping_range - Initialize fd_to_index entries to invalid
 * @mapping: FD to index mapping array
 * @start: Starting index (inclusive)
 * @end: Ending index (exclusive)
 */
static void
init_fd_mapping_range (int *mapping, const int start, const int end)
{
  for (int i = start; i < end; i++)
    mapping[i] = FD_INDEX_INVALID;
}

/**
 * allocate_fd_mapping - Allocate and initialize fd_to_index mapping
 * @size: Number of entries to allocate
 *
 * Returns: Allocated mapping or NULL on failure
 */
static int *
allocate_fd_mapping (const int size)
{
  size_t total_bytes;
  if (size <= 0) {
    errno = EINVAL;
    return NULL;
  }
  if (!SocketSecurity_check_multiply((size_t)size, sizeof(int), &total_bytes)) {
    errno = EOVERFLOW;
    return NULL;
  }
  int *mapping = calloc((size_t)size, sizeof(int));
  if (!mapping) {
    return NULL;
  }
  init_fd_mapping_range (mapping, 0, size);
  return mapping;
}

/**
 * compute_max_fd_limit - Calculate maximum FD mapping limit
 *
 * Returns: Safe limit for FD mapping table size
 */
static int
compute_max_fd_limit (int initial_max_fd)
{
  SocketSecurityLimits limits;
  int limit;

  SocketSecurity_get_limits (&limits);
  limit = (int)(limits.max_allocation / sizeof (int));

  if (limit > INT_MAX)
    limit = INT_MAX;

  if (limit < initial_max_fd)
    limit = initial_max_fd;

  return limit;
}

/**
 * init_backend_fds - Allocate and initialize pollfd array
 * @backend: Backend to initialize
 *
 * Returns: 0 on success, -1 on failure
 */
static int
init_backend_fds (PollBackend_T backend)
{
  size_t total_bytes;
  if (backend->capacity <= 0) {
    errno = EINVAL;
    backend->fds = NULL;
    return -1;
  }
  if (!SocketSecurity_check_multiply((size_t)backend->capacity, sizeof(struct pollfd), &total_bytes)) {
    errno = EOVERFLOW;
    backend->fds = NULL;
    return -1;
  }
  backend->fds = calloc((size_t)backend->capacity, sizeof(struct pollfd));
  return backend->fds ? 0 : -1;
}

/**
 * init_backend_fd_mapping - Allocate and initialize FD mapping
 * @backend: Backend to initialize
 *
 * Returns: 0 on success, -1 on failure
 */
static int
init_backend_fd_mapping (PollBackend_T backend)
{
  backend->fd_to_index = allocate_fd_mapping (backend->max_fd);
  return backend->fd_to_index ? 0 : -1;
}

/**
 * init_backend_state - Initialize backend counters and state
 * @backend: Backend to initialize
 * @maxevents: Maximum events per wait
 */
static void
init_backend_state (PollBackend_T backend, int maxevents)
{
  backend->nfds = 0;
  backend->maxevents = maxevents;
  backend->last_nev = 0;
  backend->last_wait_count = 0;
}

PollBackend_T
backend_new (Arena_T arena, const int maxevents)
{
  PollBackend_T backend;

  assert (arena != NULL);
  assert (maxevents > 0);

  backend = CALLOC (arena, 1, sizeof (*backend));
  if (!backend)
    return NULL;

  backend->capacity = POLL_INITIAL_FDS;
  backend->max_fd = POLL_INITIAL_FD_MAP_SIZE;
  backend->max_fd_limit = compute_max_fd_limit (backend->max_fd);

  if (init_backend_fds (backend) < 0)
    return NULL;

  if (init_backend_fd_mapping (backend) < 0)
    {
      free (backend->fds);
      return NULL;
    }

  init_backend_state (backend, maxevents);
  return backend;
}

void
backend_free (PollBackend_T backend)
{
  assert (backend);

  if (backend->fds)
    free (backend->fds);

  if (backend->fd_to_index)
    free (backend->fd_to_index);
}

/* ==================== FD Lookup Helpers ==================== */

/**
 * find_fd_index - Find index of fd in pollfd array
 * @backend: Backend instance
 * @fd: File descriptor to find
 *
 * Returns: Index in fds array, or FD_INDEX_INVALID if not found
 * Complexity: O(1) via fd_to_index mapping
 */
static int
find_fd_index (const PollBackend_T backend, const int fd)
{
  if (fd < 0 || fd >= backend->max_fd)
    return FD_INDEX_INVALID;

  return backend->fd_to_index[fd];
}

/**
 * ensure_fd_mapping - Ensure fd mapping table is large enough
 * @backend: Backend instance
 * @fd: File descriptor that needs to fit
 *
 * Returns: 0 on success, -1 on failure
 */
static int
ensure_fd_mapping (PollBackend_T backend, const int fd)
{
  int new_max;
  int *new_mapping;

  if (fd < backend->max_fd)
    return 0;

  size_t sum;
  if (!SocketSecurity_check_add((size_t)fd, (size_t)POLL_FD_MAP_EXPAND_INCREMENT, &sum) || sum > INT_MAX) {
    errno = EOVERFLOW;
    return -1;
  }
  new_max = (int)sum;

  if (new_max > backend->max_fd_limit)
    {
      errno = ENOMEM;
      return -1;
    }

  size_t total_bytes;
  if (!SocketSecurity_check_multiply((size_t)new_max, sizeof(int), &total_bytes)) {
    errno = EOVERFLOW;
    return -1;
  }
  new_mapping = realloc(backend->fd_to_index, total_bytes);
  if (!new_mapping) {
    return -1;
  }

  init_fd_mapping_range (new_mapping, backend->max_fd, new_max);
  backend->fd_to_index = new_mapping;
  backend->max_fd = new_max;

  return 0;
}

/* ==================== Capacity Management ==================== */

/**
 * ensure_capacity - Ensure pollfd array has capacity for one more FD
 * @backend: Backend instance
 *
 * Returns: 0 on success, -1 on failure
 */
static int
ensure_capacity (PollBackend_T backend)
{
  int new_capacity;
  struct pollfd *new_fds;

  if (backend->nfds < backend->capacity)
    return 0;

  size_t product;
  if (!SocketSecurity_check_multiply((size_t)backend->capacity, 2, &product) || product > INT_MAX) {
    errno = EOVERFLOW;
    return -1;
  }
  new_capacity = (int)product;

  size_t total_bytes;
  if (!SocketSecurity_check_multiply((size_t)new_capacity, sizeof(struct pollfd), &total_bytes)) {
    errno = EOVERFLOW;
    return -1;
  }
  new_fds = realloc(backend->fds, total_bytes);
  if (!new_fds) {
    return -1;
  }

  backend->fds = new_fds;
  backend->capacity = new_capacity;
  return 0;
}

/* ==================== Event Translation ==================== */

/**
 * translate_to_poll_events - Convert SocketPoll events to poll(2) events
 * @events: SocketPoll event flags
 *
 * Returns: poll(2) event mask
 */
static unsigned
translate_to_poll_events (const unsigned events)
{
  unsigned poll_events = 0;

  if (events & POLL_READ)
    poll_events |= POLLIN;

  if (events & POLL_WRITE)
    poll_events |= POLLOUT;

  return poll_events;
}

/**
 * translate_from_poll_events - Convert poll(2) revents to SocketPoll events
 * @revents: poll(2) returned event mask
 *
 * Returns: SocketPoll event flags
 */
static unsigned
translate_from_poll_events (const short revents)
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

/* ==================== Backend Interface Implementation ==================== */

/**
 * add_fd_to_array - Add FD to pollfd array
 * @backend: Backend instance
 * @fd: File descriptor
 * @events: Events to monitor
 *
 * Returns: Index where FD was added
 */
static int
add_fd_to_array (PollBackend_T backend, int fd, unsigned events)
{
  int index = backend->nfds;

  backend->fds[index].fd = fd;
  backend->fds[index].events = translate_to_poll_events (events);
  backend->fds[index].revents = 0;

  return index;
}

/**
 * update_fd_mapping - Update fd_to_index mapping
 * @backend: Backend instance
 * @fd: File descriptor
 * @index: Index in pollfd array
 */
static void
update_fd_mapping (PollBackend_T backend, int fd, int index)
{
  backend->fd_to_index[fd] = index;
}

int
backend_add (PollBackend_T backend, const int fd, const unsigned events)
{
  int index;

  assert (backend);
  VALIDATE_FD (fd);

  if (find_fd_index (backend, fd) != FD_INDEX_INVALID)
    {
      errno = EEXIST;
      return -1;
    }

  if (ensure_capacity (backend) < 0)
    return -1;

  if (ensure_fd_mapping (backend, fd) < 0)
    return -1;

  index = add_fd_to_array (backend, fd, events);
  update_fd_mapping (backend, fd, index);
  backend->nfds++;

  return 0;
}

int
backend_mod (PollBackend_T backend, const int fd, const unsigned events)
{
  int index;

  assert (backend);
  VALIDATE_FD (fd);

  index = find_fd_index (backend, fd);
  if (index < 0)
    {
      errno = ENOENT;
      return -1;
    }

  backend->fds[index].events = translate_to_poll_events (events);
  backend->fds[index].revents = 0;

  return 0;
}

/**
 * swap_remove_from_array - Remove FD by swapping with last element
 * @backend: Backend instance
 * @index: Index to remove
 */
static void
swap_remove_from_array (PollBackend_T backend, int index)
{
  int last_index = backend->nfds - 1;
  int last_fd;

  if (index != last_index)
    {
      backend->fds[index] = backend->fds[last_index];
      last_fd = backend->fds[index].fd;

      if (last_fd >= 0 && last_fd < backend->max_fd)
        backend->fd_to_index[last_fd] = index;
    }
}

/**
 * remove_fd_from_mapping - Clear FD mapping entry
 * @backend: Backend instance
 * @fd: File descriptor
 */
static void
remove_fd_from_mapping (PollBackend_T backend, int fd)
{
  if (fd >= 0 && fd < backend->max_fd)
    backend->fd_to_index[fd] = FD_INDEX_INVALID;
}

int
backend_del (PollBackend_T backend, const int fd)
{
  int index;

  assert (backend);

  if (fd < 0)
    return 0;

  index = find_fd_index (backend, fd);
  if (index == FD_INDEX_INVALID)
    return 0;

  swap_remove_from_array (backend, index);
  remove_fd_from_mapping (backend, fd);
  backend->nfds--;

  return 0;
}

/* ==================== Wait Implementation ==================== */

/**
 * reset_backend_wait_state - Reset backend state after wait completes
 * @backend: Backend instance
 * @nev: Number of valid events (0 on timeout/error/EINTR)
 *
 * Consolidates post-wait state management: sets last_nev and last_wait_count.
 * Note: revents are NOT cleared here - poll() overwrites them on next call,
 * and backend_get_event bounds-checks via last_nev to prevent stale access.
 */
static void
reset_backend_wait_state (PollBackend_T backend, int nev)
{
  backend->last_nev = nev;
  backend->last_wait_count = nev;
}

/**
 * handle_poll_error - Handle poll error result
 * @backend: Backend instance
 *
 * Returns: 0 if EINTR (treat as timeout), -1 for other errors
 */
static int
handle_poll_error (PollBackend_T backend)
{
  reset_backend_wait_state (backend, 0);

  if (errno == EINTR)
    return 0;

  return -1;
}

/**
 * handle_poll_success - Handle successful poll result
 * @backend: Backend instance
 * @result: Number of ready fds from poll()
 *
 * Returns: result
 */
static int
handle_poll_success (PollBackend_T backend, int result)
{
  reset_backend_wait_state (backend, result);
  return result;
}

/**
 * do_sleep_timeout - Sleep for timeout when no FDs registered
 * @timeout_ms: Timeout in milliseconds
 */
static void
do_sleep_timeout (int timeout_ms)
{
  struct timespec ts;

  if (timeout_ms > 0)
    {
      TIMEOUT_MS_TO_TIMESPEC (timeout_ms, &ts);
      nanosleep (&ts, NULL);
    }
}

int
backend_wait (PollBackend_T backend, const int timeout_ms)
{
  int result;

  assert (backend);

  if (backend->nfds == 0)
    {
      do_sleep_timeout (timeout_ms);
      backend->last_nev = 0;
      return 0;
    }

  result = poll (backend->fds, backend->nfds, timeout_ms);

  if (result < 0)
    return handle_poll_error (backend);

  return handle_poll_success (backend, result);
}

/**
 * find_nth_ready_fd - Find the nth FD with events in pollfd array
 * @backend: Backend instance
 * @target_index: Which ready FD to find (0-based)
 * @fd_out: Output - file descriptor
 * @events_out: Output - translated events
 *
 * Returns: 0 on success, -1 if not found
 */
static int
find_nth_ready_fd (const PollBackend_T backend, int target_index, int *fd_out,
                   unsigned *events_out)
{
  int count = 0;

  for (int i = 0; i < backend->nfds; i++)
    {
      if (backend->fds[i].revents != 0)
        {
          if (count == target_index)
            {
              *fd_out = backend->fds[i].fd;
              *events_out = translate_from_poll_events (backend->fds[i].revents);
              return 0;
            }
          count++;
        }
    }

  return -1;
}

int
backend_get_event (const PollBackend_T backend, const int index, int *fd_out,
                   unsigned *events_out)
{
  assert (backend);
  assert (fd_out);
  assert (events_out);

  if (index < 0 || index >= backend->last_nev)
    return -1;

  return find_nth_ready_fd (backend, index, fd_out, events_out);
}

const char *
backend_name (void)
{
  return "poll";
}

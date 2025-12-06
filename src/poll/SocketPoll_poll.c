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
 * - All constants from SocketConfig.h: POLL_INITIAL_FDS, POLL_INITIAL_FD_MAP_SIZE
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

#include "core/SocketConfig.h"
#include "poll/SocketPoll_backend.h"

/* Sentinel value indicating FD not in poll set */
#define FD_INDEX_INVALID (-1)

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

/* ==================== Initialization Helpers ==================== */

/**
 * init_fd_mapping_range - Initialize fd_to_index entries to invalid
 * @mapping: FD to index mapping array (modified in place)
 * @start: Starting index (inclusive)
 * @end: Ending index (exclusive)
 *
 * Sets all entries in [start, end) to FD_INDEX_INVALID.
 * Used during initial allocation and when expanding the mapping table.
 */
static void
init_fd_mapping_range (int *mapping, const int start, const int end)
{
  int i;

  for (i = start; i < end; i++)
    mapping[i] = FD_INDEX_INVALID;
}

/**
 * allocate_fd_mapping - Allocate and initialize fd_to_index mapping
 * @size: Number of entries to allocate
 *
 * Returns: Allocated mapping or NULL on failure (errno set)
 *
 * Initializes all entries to FD_INDEX_INVALID via init_fd_mapping_range().
 */
static int *
allocate_fd_mapping (const int size)
{
  int *mapping;

  mapping = calloc (size, sizeof (int));
  if (mapping)
    init_fd_mapping_range (mapping, 0, size);

  return mapping;
}

PollBackend_T
backend_new (const int maxevents)
{
  PollBackend_T backend;

  assert (maxevents > 0);

  backend = calloc (1, sizeof (*backend));
  if (!backend)
    return NULL;

  backend->capacity = POLL_INITIAL_FDS;
  backend->fds = calloc (backend->capacity, sizeof (struct pollfd));
  if (!backend->fds)
    {
      free (backend);
      return NULL;
    }

  /* Allocate FD mapping table - size based on typical FD range */
  backend->max_fd = POLL_INITIAL_FD_MAP_SIZE;
  backend->fd_to_index = allocate_fd_mapping (backend->max_fd);
  if (!backend->fd_to_index)
    {
      free (backend->fds);
      free (backend);
      return NULL;
    }

  backend->nfds = 0;
  backend->maxevents = maxevents;
  backend->last_wait_count = 0;

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

  free (backend);
}

/* ==================== FD Lookup Helpers ==================== */

/**
 * find_fd_index - Find index of fd in pollfd array
 * @backend: Backend instance (read-only access)
 * @fd: File descriptor to find
 *
 * Returns: Index in fds array, or FD_INDEX_INVALID if not found
 *
 * O(1) lookup using fd_to_index mapping table. This is the key optimization
 * that makes add/mod/del operations efficient despite poll(2)'s O(n) wait.
 */
static int
find_fd_index (const PollBackend_T backend, const int fd)
{
  if (fd < 0 || fd >= backend->max_fd)
    return FD_INDEX_INVALID;

  return backend->fd_to_index[fd];
}

/**
 * ensure_fd_mapping - Ensure fd mapping table is large enough for fd
 * @backend: Backend instance
 * @fd: File descriptor that needs to fit
 *
 * Returns: 0 on success, -1 on failure (sets errno to EOVERFLOW or ENOMEM)
 *
 * Expands the fd_to_index mapping table if needed to accommodate fd.
 * Uses POLL_FD_MAP_EXPAND_INCREMENT from SocketConfig.h to avoid frequent
 * reallocations.
 *
 * Security: Includes overflow checks for both int and size_t calculations
 * to prevent heap corruption from integer overflow.
 */
static int
ensure_fd_mapping (PollBackend_T backend, const int fd)
{
  int new_max;
  int *new_mapping;

  if (fd < backend->max_fd)
    return 0;

  /* Check for integer overflow before expansion */
  if (fd > INT_MAX - POLL_FD_MAP_EXPAND_INCREMENT)
    {
      errno = EOVERFLOW;
      return -1;
    }

  /* Expand mapping table */
  new_max = fd + POLL_FD_MAP_EXPAND_INCREMENT;

  /* Check for size_t overflow before calloc
   * Security: Prevents heap corruption from truncated allocation size */
  if ((size_t)new_max > SIZE_MAX / sizeof (int))
    {
      errno = EOVERFLOW;
      return -1;
    }

  new_mapping = calloc ((size_t)new_max, sizeof (int));
  if (!new_mapping)
    return -1;

  /* Copy old mappings */
  memcpy (new_mapping, backend->fd_to_index,
          (size_t)backend->max_fd * sizeof (int));

  /* Initialize new entries to invalid */
  init_fd_mapping_range (new_mapping, backend->max_fd, new_max);

  free (backend->fd_to_index);
  backend->fd_to_index = new_mapping;
  backend->max_fd = new_max;

  return 0;
}

/* ==================== Capacity Management ==================== */

/**
 * ensure_capacity - Ensure pollfd array has capacity for one more FD
 * @backend: Backend instance
 * Returns: 0 on success, -1 on failure
 *
 * Doubles the capacity of the fds array when full.
 * Includes overflow protection for both capacity and size calculations.
 *
 * Security: Uses explicit multiplication overflow check before realloc
 * to prevent heap corruption from integer overflow.
 */
static int
ensure_capacity (PollBackend_T backend)
{
  struct pollfd *new_fds;
  int new_capacity;
  size_t alloc_size;

  if (backend->nfds < backend->capacity)
    return 0;

  /* Check for int overflow before doubling */
  if (backend->capacity > INT_MAX / 2)
    {
      errno = EOVERFLOW;
      return -1;
    }

  /* Double the capacity */
  new_capacity = backend->capacity * 2;

  /* Check for size_t overflow before realloc
   * Security: Prevents heap corruption from truncated allocation size */
  if ((size_t)new_capacity > SIZE_MAX / sizeof (struct pollfd))
    {
      errno = EOVERFLOW;
      return -1;
    }
  alloc_size = (size_t)new_capacity * sizeof (struct pollfd);

  new_fds = realloc (backend->fds, alloc_size);
  if (!new_fds)
    return -1;

  backend->fds = new_fds;
  backend->capacity = new_capacity;

  return 0;
}

/* ==================== Event Translation ==================== */

/**
 * translate_to_poll_events - Convert SocketPoll events to poll(2) events
 * @events: SocketPoll event flags (POLL_READ | POLL_WRITE)
 *
 * Returns: poll(2) event mask (POLLIN | POLLOUT)
 *
 * Note: poll(2) is level-triggered only, unlike epoll's edge-triggered mode.
 * POLL_ERROR and POLL_HANGUP are always monitored implicitly by poll(2).
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
 * Returns: SocketPoll event flags (POLL_READ | POLL_WRITE | POLL_ERROR | POLL_HANGUP)
 *
 * Maps POLLIN/POLLOUT/POLLERR/POLLHUP to POLL_READ/WRITE/ERROR/HANGUP.
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

int
backend_add (PollBackend_T backend, const int fd, const unsigned events)
{
  int index;

  assert (backend);
  VALIDATE_FD (fd);

  /* Check if already added */
  if (find_fd_index (backend, fd) != FD_INDEX_INVALID)
    {
      errno = EEXIST;
      return -1;
    }

  /* Ensure capacity for new FD */
  if (ensure_capacity (backend) < 0)
    return -1;

  /* Ensure FD mapping table is large enough */
  if (ensure_fd_mapping (backend, fd) < 0)
    return -1;

  /* Add to pollfd array */
  index = backend->nfds;
  backend->fds[index].fd = fd;
  backend->fds[index].events = translate_to_poll_events (events);
  backend->fds[index].revents = 0;

  /* Update mapping for O(1) lookup */
  backend->fd_to_index[fd] = index;

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

  /* Modify events */
  backend->fds[index].events = translate_to_poll_events (events);
  backend->fds[index].revents = 0;

  return 0;
}

int
backend_del (PollBackend_T backend, const int fd)
{
  int index;
  int last_index;
  int last_fd;

  assert (backend);

  /* Invalid FD - silently succeed (already closed) */
  if (fd < 0)
    return 0;

  index = find_fd_index (backend, fd);
  if (index == FD_INDEX_INVALID)
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

  /* Clear mapping for removed FD (fd >= 0 guaranteed by early return) */
  if (fd < backend->max_fd)
    backend->fd_to_index[fd] = FD_INDEX_INVALID;

  backend->nfds--;

  return 0;
}

int
backend_wait (PollBackend_T backend, const int timeout_ms)
{
  int result;

  assert (backend);

  if (backend->nfds == 0)
    {
      /* No FDs to poll - simulate timeout */
      if (timeout_ms > 0)
        {
          struct timespec ts;
          ts.tv_sec = timeout_ms / SOCKET_MS_PER_SECOND;
          ts.tv_nsec = (timeout_ms % SOCKET_MS_PER_SECOND) * SOCKET_NS_PER_MS;
          nanosleep (&ts, NULL);
        }
      return 0;
    }

  result = poll (backend->fds, backend->nfds, timeout_ms);

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

/**
 * backend_get_event - Get event details for index
 * @backend: Backend instance
 * @index: Event index (0 to count-1 from backend_wait)
 * @fd_out: Output - file descriptor with events
 * @events_out: Output - events that occurred (POLL_READ | POLL_WRITE | etc.)
 *
 * Returns: 0 on success, -1 on invalid index
 *
 * NOTE: This function is O(n) where n = nfds because poll(2) returns
 * a count of ready FDs but doesn't provide direct indexing like epoll.
 * We must scan the entire fds array to find the nth ready FD.
 *
 * For high-performance applications, prefer epoll or kqueue backends.
 */
int
backend_get_event (PollBackend_T backend, const int index, int *fd_out,
                   unsigned *events_out)
{
  int i;
  int count;

  assert (backend);
  assert (fd_out);
  assert (events_out);

  /* poll returns count of ready FDs, but we need to scan array
   * to find the nth ready FD - this is O(n) by necessity */
  count = 0;
  for (i = 0; i < backend->nfds; i++)
    {
      if (backend->fds[i].revents != 0)
        {
          if (count == index)
            {
              *fd_out = backend->fds[i].fd;
              *events_out
                  = translate_from_poll_events (backend->fds[i].revents);
              return 0;
            }
          count++;
        }
    }

  /* Index out of range */
  return -1;
}

const char *
backend_name (void)
{
  return "poll";
}

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
#include "core/SocketSecurity.h"
#include "core/Arena.h"
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
  int last_nev;        /* Valid events from last backend_wait (0 on error/timeout) - for consistency with other backends */
  int max_fd;          /* Maximum FD value seen */
  int max_fd_limit;    /* Maximum allowed size for FD mapping to prevent OOM */
};
#undef T

/* ==================== Safe Allocation Helpers ==================== */

/**
 * safe_calc_size - Safely calculate total size for array allocation
 * @num: Number of elements
 * @elem_size: Size of each element
 * @total_out: Output total bytes (only set on success)
 *
 * Returns: 0 on success, -1 on overflow (sets errno to EOVERFLOW)
 * Thread-safe: Yes
 */
static int
safe_calc_size (size_t num, size_t elem_size, size_t *total_out)
{
  size_t total;
  if (num == 0 || elem_size == 0)
    {
      total = 0;
    }
  else
    {
      if (!SocketSecurity_check_multiply (num, elem_size, &total))
        {
          errno = EOVERFLOW;
          return -1;
        }
    }
  if (total_out)
    *total_out = total;
  return 0;
}

/**
 * safe_calloc_array - Safely allocate zeroed array with overflow protection
 * @num: Number of elements
 * @elem_size: Size of each element
 *
 * Returns: Allocated array or NULL on failure (errno set)
 * Thread-safe: Yes
 * Note: Uses safe_calc_size internally
 */
static void *
safe_calloc_array (size_t num, size_t elem_size)
{
  size_t total;
  if (safe_calc_size (num, elem_size, &total) < 0)
    return NULL;
  return calloc (num, elem_size);
}

/**
 * safe_realloc_array - Safely reallocate array with overflow protection
 * @ptr: Pointer to reallocate (NULL ok for initial alloc)
 * @num: New number of elements
 * @elem_size: Size of each element
 *
 * Returns: Reallocated array or NULL on failure (errno set)
 * Thread-safe: Yes
 * Note: Preserves content up to min(old_size, new_size); new area undefined
 * Note: Returns NULL with EINVAL if num is 0 (avoids realloc(ptr, 0) UB)
 */
static void *
safe_realloc_array (void *ptr, size_t num, size_t elem_size)
{
  size_t total;

  /* Reject zero-size allocation to avoid implementation-defined realloc(ptr, 0)
   * behavior. Per POSIX, realloc(ptr, 0) may return NULL or a non-NULL pointer
   * that cannot be dereferenced. We treat this as an error. */
  if (num == 0)
    {
      errno = EINVAL;
      return NULL;
    }

  if (safe_calc_size (num, elem_size, &total) < 0)
    return NULL;
  return realloc (ptr, total);
}

/* ==================== Integer Safe Arithmetic Helpers ==================== */

/**
 * safe_int_add - Safely add two positive integers with overflow check
 * @a: First operand (non-negative)
 * @b: Second operand (positive increment)
 * @result_out: Output result (only set on success)
 *
 * Returns: 0 on success, -1 on overflow (sets errno to EOVERFLOW)
 * Thread-safe: Yes
 * Note: Assumes a >= 0, b > 0 for FD/capacity expansion
 */
static int
safe_int_add (int a, int b, int *result_out)
{
  if (!result_out)
    {
      errno = EINVAL;
      return -1;
    }
  if (a < 0 || b < 0)
    {
      errno = EINVAL;
      return -1;
    }
  size_t sa = (size_t)a;
  size_t sb = (size_t)b;
  size_t res;
  if (!SocketSecurity_check_add (sa, sb, &res))
    {
      errno = EOVERFLOW;
      return -1;
    }
  if (res > (size_t)INT_MAX)
    {
      errno = EOVERFLOW;
      return -1;
    }
  *result_out = (int)res;
  return 0;
}

/**
 * safe_int_double - Safely double a positive integer with overflow check
 * @val: Value to double (positive capacity)
 * @result_out: Output doubled value (only set on success)
 *
 * Returns: 0 on success, -1 on overflow (sets errno to EOVERFLOW)
 * Thread-safe: Yes
 */
static int
safe_int_double (int val, int *result_out)
{
  if (!result_out)
    {
      errno = EINVAL;
      return -1;
    }
  if (val < 0)
    {
      errno = EINVAL;
      return -1;
    }
  size_t sval = (size_t)val;
  size_t res;
  if (!SocketSecurity_check_multiply (sval, 2, &res))
    {
      errno = EOVERFLOW;
      return -1;
    }
  if (res > (size_t)INT_MAX)
    {
      errno = EOVERFLOW;
      return -1;
    }
  *result_out = (int)res;
  return 0;
}
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

  mapping = safe_calloc_array ((size_t)size, sizeof (int));
  if (mapping)
    init_fd_mapping_range (mapping, 0, size);

  return mapping;
}

static int
alloc_and_init_fds (PollBackend_T backend)
{
  backend->fds = safe_calloc_array ((size_t)backend->capacity, sizeof (struct pollfd));
  return backend->fds ? 0 : -1;
}

static int
alloc_and_init_fd_mapping (PollBackend_T backend)
{
  backend->fd_to_index = allocate_fd_mapping (backend->max_fd);
  return backend->fd_to_index ? 0 : -1;
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
  if (alloc_and_init_fds (backend) < 0)
    {
      return NULL; /* arena owns backend */
    }

  /* Allocate FD mapping table - size based on typical FD range */
  backend->max_fd = POLL_INITIAL_FD_MAP_SIZE;

  /* Set maximum FD mapping limit based on security allocation limits */
  SocketSecurityLimits limits;
  SocketSecurity_get_limits (&limits);
  backend->max_fd_limit = (int) (limits.max_allocation / sizeof (int));
  if (backend->max_fd_limit > INT_MAX)
    backend->max_fd_limit = INT_MAX;
  if (backend->max_fd_limit < backend->max_fd)
    backend->max_fd_limit = backend->max_fd;

  if (alloc_and_init_fd_mapping (backend) < 0)
    {
      free (backend->fds); /* stdlib free */
      return NULL; /* arena owns backend */
    }

  backend->nfds = 0;
  backend->maxevents = maxevents;
  backend->last_nev = 0;
  backend->last_wait_count = 0;

  return backend;
}

void
backend_free (PollBackend_T backend)
{
  assert (backend);

  if (backend->fds)
    free (backend->fds); /* Dynamic realloc from heap */

  if (backend->fd_to_index)
    free (backend->fd_to_index); /* Dynamic from heap */

  /* backend struct freed by arena dispose */
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

  if (fd < backend->max_fd)
    return 0;

  if (safe_int_add (fd, POLL_FD_MAP_EXPAND_INCREMENT, &new_max) < 0)
    return -1;

  if (new_max > backend->max_fd_limit)
    {
      errno = ENOMEM;
      return -1;
    }

  int *new_mapping = safe_realloc_array (backend->fd_to_index, (size_t)new_max, sizeof (int));
  if (!new_mapping)
    return -1;

  /* Initialize new entries to invalid (realloc may not zero new area) */
  init_fd_mapping_range (new_mapping, backend->max_fd, new_max);

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
  int new_capacity;

  if (backend->nfds < backend->capacity)
    return 0;

  if (safe_int_double (backend->capacity, &new_capacity) < 0)
    return -1;

  struct pollfd *new_fds = safe_realloc_array (backend->fds, (size_t)new_capacity, sizeof (struct pollfd));
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

static int
add_fd_to_array (PollBackend_T backend, int fd, unsigned events)
{
  int index = backend->nfds;
  backend->fds[index].fd = fd;
  backend->fds[index].events = translate_to_poll_events (events);
  backend->fds[index].revents = 0;
  return index;
}

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

  /* Modify events */
  backend->fds[index].events = translate_to_poll_events (events);
  backend->fds[index].revents = 0;

  return 0;
}

/**
 * swap_remove_from_array - Swap remove FD at index with last element
 * @backend: Backend instance
 * @index: Index to remove
 *
 * Swaps fds[index] with fds[nfds-1], updates mapping for moved FD.
 * Does not update removed FD mapping or decrement nfds.
 * Thread-safe: No
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
 * @fd: File descriptor to remove from mapping
 *
 * Sets fd_to_index[fd] = FD_INDEX_INVALID if in range.
 * Thread-safe: No
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

  /* Invalid FD - silently succeed (already closed) */
  if (fd < 0)
    return 0;

  index = find_fd_index (backend, fd);
  if (index == FD_INDEX_INVALID)
    {
      /* Not found - silent success */
      return 0;
    }

  swap_remove_from_array (backend, index);
  remove_fd_from_mapping (backend, fd);
  backend->nfds--;

  return 0;
}

/**
 * perform_poll_wait - Perform the actual poll(2) system call
 * @backend: Backend instance
 * @timeout_ms: Timeout in ms
 *
 * Handles poll(2) call, EINTR restart simulation, and stores event count.
 * Returns: Number of ready events or -1 on error (non-EINTR)
 * Thread-safe: No
 */
static int
perform_poll_wait (PollBackend_T backend, int timeout_ms)
{
  int result;

  result = poll (backend->fds, backend->nfds, timeout_ms);

  if (result < 0)
    {
      backend->last_nev = 0;
      /* Clear revents to avoid stale data on error/timeout */
      for (int j = 0; j < backend->nfds; j++)
        backend->fds[j].revents = 0;
      /* poll was interrupted by signal - treat as timeout */
      if (errno == EINTR)
        return 0;
      return -1;
    }

  backend->last_nev = result;
  if (backend->last_nev == 0)
    {
      /* Ensure revents cleared on timeout (poll should do this, but explicit) */
      for (int j = 0; j < backend->nfds; j++)
        backend->fds[j].revents = 0;
    }
  backend->last_wait_count = result;
  return result;
}

int
backend_wait (PollBackend_T backend, const int timeout_ms)
{
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
      backend->last_nev = 0;
      return 0;
    }

  return perform_poll_wait (backend, timeout_ms);
}

/**
 * backend_get_event - Get event details for index
 * @backend: Backend instance (checks against last_nev for valid range)
 * @index: Event index (0 to backend->last_nev - 1 from most recent backend_wait)
 * @fd_out: Output - file descriptor with events
 * @events_out: Output - events that occurred (POLL_READ | POLL_WRITE | etc.)
 *
 * Returns: 0 on success, -1 if index out of valid range (0 to last_nev-1)
 *
 * NOTE: This function is O(n) where n = nfds because poll(2) returns
 * a count of ready FDs but doesn't provide direct indexing like epoll.
 * We must scan the entire fds array to find the nth ready FD.
 *
 * For high-performance applications, prefer epoll or kqueue backends.
 */
int
backend_get_event (const PollBackend_T backend, const int index, int *fd_out,
                   unsigned *events_out)
{
  int i;
  int count;

  assert (backend);
  assert (fd_out);
  assert (events_out);

  if (index < 0 || index >= backend->last_nev)
    return -1;

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

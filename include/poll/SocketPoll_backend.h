#ifndef SOCKETPOLL_BACKEND_INCLUDED
#define SOCKETPOLL_BACKEND_INCLUDED

/**
 * SocketPoll Backend Abstraction (Private Interface)
 * This header defines the internal interface that all polling backends
 * must implement. It is not part of the public API.
 * Supported Backends:
 * - epoll (Linux) - High performance, edge-triggered
 * - kqueue (BSD/macOS) - High performance, edge-triggered via EV_CLEAR
 * - poll (POSIX) - Portable fallback, level-triggered
 * Backend Selection:
 * - Compile-time via Makefile based on platform detection
 * - Linux: epoll (best)
 * - BSD/macOS: kqueue (best)
 * - Other POSIX: poll (fallback)
 */

#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "core/Arena.h"

/* Forward declaration of backend-specific poll structure */
typedef struct PollBackend_T *PollBackend_T;

/* Common backend macros for duplication removal */
#ifndef VALIDATE_MAXEVENTS
#define VALIDATE_MAXEVENTS(maxevents, event_type) \
  do { \
    if ((size_t)(maxevents) <= 0) { \
      errno = EINVAL; \
      return NULL; \
    } \
    if ((size_t)(maxevents) > SIZE_MAX / sizeof(event_type)) { \
      errno = EOVERFLOW; \
      return NULL; \
    } \
  } while (0)
#endif

/* ==================== Common Backend Macros ==================== */

/**
 * VALIDATE_FD - Validate file descriptor and return error if invalid
 * Used by all backends to eliminate duplicate fd validation code.
 */
#define VALIDATE_FD(fd)                                                        \
  do                                                                           \
    {                                                                          \
      if ((fd) < 0)                                                            \
        {                                                                      \
          errno = EBADF;                                                       \
          return -1;                                                           \
        }                                                                      \
    }                                                                          \
  while (0)

/**
 * Backend interface - all backends must implement these functions
 */

/**
 * backend_new - Create new backend instance
 * @arena: Arena for memory allocation (backend and events allocated here)
 * @maxevents: Maximum events to return per wait
 * Returns: Backend instance or NULL on failure (arena allocations leaked on partial failure, freed by caller arena dispose)
 */
extern PollBackend_T backend_new (Arena_T arena, int maxevents);

/**
 * backend_free - Close backend resources
 * @backend: Backend instance (fd closed, memory freed by arena dispose)
 * Note: Only closes the backend fd; memory allocations (struct, events array) are owned by arena and freed by Arena_dispose
 */
extern void backend_free (PollBackend_T backend);

/**
 * backend_add - Add socket to poll set
 * @backend: Backend instance
 * @fd: File descriptor to monitor
 * @events: Events to monitor (POLL_READ | POLL_WRITE)
 * Returns: 0 on success, -1 on failure (sets errno)
 */
extern int backend_add (PollBackend_T backend, int fd, unsigned events);

/**
 * backend_mod - Modify monitored events
 * @backend: Backend instance
 * @fd: File descriptor to modify
 * @events: New events to monitor
 * Returns: 0 on success, -1 on failure (sets errno)
 */
extern int backend_mod (PollBackend_T backend, int fd, unsigned events);

/**
 * backend_del - Remove socket from poll set
 * @backend: Backend instance
 * @fd: File descriptor to remove
 * Returns: 0 on success, -1 on failure (sets errno)
 * Note: Should succeed silently if fd not in set
 */
extern int backend_del (PollBackend_T backend, int fd);

/**
 * backend_wait - Wait for events
 * @backend: Backend instance (const - does not modify backend state)
 * @timeout_ms: Timeout in milliseconds (-1 for infinite)
 * Returns: Number of events ready (>= 0), or -1 on error (sets errno)
 * Note: Returns 0 on timeout or EINTR (signal interrupt)
 */
extern int backend_wait (const PollBackend_T backend, int timeout_ms);

/**
 * backend_get_event - Get event details for index
 * @backend: Backend instance (const - read-only access to events array)
 * @index: Event index (0 to count-1 from backend_wait)
 * @fd_out: Output - file descriptor
 * @events_out: Output - events that occurred
 * Returns: 0 on success, -1 on invalid index
 */
extern int backend_get_event (const PollBackend_T backend, int index, int *fd_out,
                              unsigned *events_out);

/**
 * backend_name - Get backend name for debugging
 * Returns: Static string with backend name ("epoll", "kqueue", "poll")
 */
extern const char *backend_name (void);

#endif /* SOCKETPOLL_BACKEND_INCLUDED */

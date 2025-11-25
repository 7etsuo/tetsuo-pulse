/**
 * SocketAsync-backend.c - Asynchronous I/O backend detection and abstraction
 *
 * Provides platform-independent async backend detection and initialization.
 * Abstracts the differences between io_uring (Linux), kqueue (BSD/macOS), and
 * fallback modes for maximum portability.
 *
 * Features:
 * - Automatic backend detection at runtime
 * - Platform-specific backend initialization
 * - Unified async operation submission interface
 * - Fallback to edge-triggered polling when async unavailable
 * - Backend capability reporting
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef SOCKET_HAS_IO_URING
#include <liburing.h>
#include <sys/eventfd.h>
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "socket/Socket.h"
#include "socket/SocketAsync.h"
#include "socket/SocketAsync-private.h"
#define SOCKET_LOG_COMPONENT "SocketAsync"
#include "core/SocketError.h"

#define T SocketAsync_T

/* Forward declarations for backend-specific functions */
#ifdef SOCKET_HAS_IO_URING
static int submit_io_uring_send (T async, struct AsyncRequest *req);
static int submit_io_uring_recv (T async, struct AsyncRequest *req);
static int process_io_uring_completions (T async, int max_completions);
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
static int submit_kqueue_aio (T async, struct AsyncRequest *req);
static int process_kqueue_completions (T async, int timeout_ms,
                                       int max_completions);
#endif

/* ==================== Backend Detection ==================== */

/**
 * detect_async_backend - Detect and initialize platform-specific async backend
 * @async: Async context to initialize
 * Returns: Non-zero if async available, 0 if fallback mode
 */
static int
detect_async_backend (T async)
{
  assert (async);

#ifdef SOCKET_HAS_IO_URING
  /* Try io_uring */
  struct io_uring test_ring;
  if (io_uring_queue_init (32, &test_ring, 0) == 0)
    {
      io_uring_queue_exit (&test_ring);

      /* Allocate ring for this instance */
      async->ring = calloc (1, sizeof (struct io_uring));
      if (!async->ring)
        {
          async->available = 0;
          async->backend_name = "edge-triggered (allocation failed)";
          return 0;
        }

      if (io_uring_queue_init (SOCKET_DEFAULT_IO_URING_ENTRIES, async->ring, 0)
          == 0)
        {
          /* Create eventfd for completion notifications */
          async->io_uring_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
          if (async->io_uring_fd >= 0)
            {
              async->available = 1;
              async->backend_name = "io_uring";
              return 1;
            }
          io_uring_queue_exit (async->ring);
          free (async->ring);
          async->ring = NULL;
        }
      else
        {
          free (async->ring);
          async->ring = NULL;
        }
    }

  /* Fallback to edge-triggered */
  async->available = 0;
  async->backend_name = "edge-triggered (io_uring unavailable)";
  return 0;

#elif defined(__APPLE__) || defined(__FreeBSD__)
  /* Try kqueue (edge-triggered mode - not true AIO but better than poll) */
  async->kqueue_fd = kqueue ();
  if (async->kqueue_fd >= 0)
    {
      async->available = 1;
      async->backend_name = "kqueue (edge-triggered)";
      return 1;
    }

  async->available = 0;
  async->backend_name = "edge-triggered (kqueue unavailable)";
  return 0;

#else
  /* No async support */
  async->available = 0;
  async->backend_name = "edge-triggered (platform not supported)";
  return 0;
#endif
}

/* ==================== Unified Backend Interface ==================== */

/**
 * submit_async_operation - Submit async operation to appropriate backend
 * @async: Async context
 * @req: Request to submit
 * Returns: 0 on success, -1 on failure
 */
int
submit_async_operation (T async, struct AsyncRequest *req)
{
  assert (async);
  assert (req);

#ifdef SOCKET_HAS_IO_URING
  if (async->ring)
    {
      return (req->type == REQ_SEND)
                 ? submit_io_uring_send (async, req)
                 : submit_io_uring_recv (async, req);
    }
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
  if (async->kqueue_fd >= 0)
    {
      return submit_kqueue_aio (async, req);
    }
#endif

  /* No backend available */
  errno = ENOTSUP;
  return -1;
}

/**
 * process_async_completions - Process completions from appropriate backend
 * @async: Async context
 * @timeout_ms: Timeout in milliseconds
 * Returns: Number of completions processed
 */
int
process_async_completions (T async, int timeout_ms __attribute__((unused)))
{
  assert (async);

  if (!async->available)
    return 0;

#ifdef SOCKET_HAS_IO_URING
  if (async->ring)
    {
      /* Check eventfd for completions */
      uint64_t val;
      ssize_t n = read (async->io_uring_fd, &val, sizeof (val));
      if (n > 0)
        {
          /* Process completions */
          return process_io_uring_completions (
              async, SOCKET_MAX_EVENT_BATCH);
        }
      return 0;
    }
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
  if (async->kqueue_fd >= 0)
    {
      /* Process kqueue AIO events */
      return process_kqueue_completions (async, timeout_ms, SOCKET_MAX_EVENT_BATCH);
    }
#endif

  return 0;
}

/* ==================== Backend Initialization ==================== */

void
SocketAsync_initialize_backend (T async)
{
  assert (async);
  detect_async_backend (async);
}

#undef T

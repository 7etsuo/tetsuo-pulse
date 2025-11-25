/**
 * SocketAsync-iouring.c - io_uring asynchronous I/O backend (Linux)
 *
 * Implements high-performance asynchronous I/O operations using Linux io_uring.
 * Provides true kernel-level async I/O with completion ring notifications via
 * eventfd for maximum efficiency and scalability.
 *
 * Features:
 * - True asynchronous send/recv operations
 * - Eventfd-based completion notifications
 * - Kernel-level I/O submission and completion
 * - Efficient batch processing of completions
 * - Platform-specific optimizations for Linux
 */

#ifdef SOCKET_HAS_IO_URING

#include <assert.h>
#include <errno.h>
#include <liburing.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "core/SocketConfig.h"
#include "socket/Socket.h"
#include "socket/SocketAsync.h"
#define SOCKET_LOG_COMPONENT "SocketAsync"
#include "core/SocketError.h"

#define T SocketAsync_T

/* ==================== io_uring Operations ==================== */

/**
 * submit_io_uring_send - Submit send operation via io_uring
 * @async: Async context
 * @req: Request structure
 * Returns: 0 on success, -1 on failure
 */
static int
submit_io_uring_send (T async, struct AsyncRequest *req)
{
  struct io_uring_sqe *sqe;
  int fd = Socket_fd (req->socket);

  assert (async);
  assert (async->ring);
  assert (req);

  sqe = io_uring_get_sqe (async->ring);
  if (!sqe)
    {
      errno = EAGAIN; /* Queue full */
      return -1;
    }

  /* Prepare send operation */
  io_uring_prep_send (sqe, fd, req->send_buf, req->len, 0);

  /* Store request ID in user_data */
  sqe->user_data = (uintptr_t)req->request_id;

  /* Set flags */
  if (req->flags & ASYNC_FLAG_URGENT)
    {
      sqe->flags |= IOSQE_IO_LINK;
    }

  /* Submit */
  int submitted = io_uring_submit (async->ring);
  if (submitted < 0)
    {
      return -1;
    }

  /* Notify via eventfd */
  uint64_t val = 1;
  write (async->io_uring_fd, &val, sizeof (val));

  return 0;
}

/**
 * submit_io_uring_recv - Submit recv operation via io_uring
 * @async: Async context
 * @req: Request structure
 * Returns: 0 on success, -1 on failure
 */
static int
submit_io_uring_recv (T async, struct AsyncRequest *req)
{
  struct io_uring_sqe *sqe;
  int fd = Socket_fd (req->socket);

  assert (async);
  assert (async->ring);
  assert (req);

  sqe = io_uring_get_sqe (async->ring);
  if (!sqe)
    {
      errno = EAGAIN; /* Queue full */
      return -1;
    }

  /* Prepare recv operation */
  io_uring_prep_recv (sqe, fd, req->recv_buf, req->len, 0);

  /* Store request ID in user_data */
  sqe->user_data = (uintptr_t)req->request_id;

  /* Submit */
  int submitted = io_uring_submit (async->ring);
  if (submitted < 0)
    {
      return -1;
    }

  /* Notify via eventfd */
  uint64_t val = 1;
  write (async->io_uring_fd, &val, sizeof (val));

  return 0;
}

/**
 * process_io_uring_completions - Process io_uring completion queue
 * @async: Async context
 * @max_completions: Maximum completions to process
 * Returns: Number of completions processed
 */
static int
process_io_uring_completions (T async, int max_completions)
{
  struct io_uring_cqe *cqe;
  unsigned head;
  int count = 0;

  assert (async);
  assert (async->ring);

  /* Peek at completions without waiting */
  io_uring_for_each_cqe (async->ring, head, cqe)
  {
    if (count >= max_completions)
      break;

    unsigned request_id = (unsigned)(uintptr_t)cqe->user_data;
    ssize_t result = cqe->res;
    int err = (result < 0) ? -result : 0;

    /* Handle completion (defined in SocketAsync.c) */
    handle_completion (async, request_id, result, err);

    count++;
  }

  /* Mark completions as seen */
  io_uring_cq_advance (async->ring, count);

  return count;
}

#endif /* SOCKET_HAS_IO_URING */

#undef T

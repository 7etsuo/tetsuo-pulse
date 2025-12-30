/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */


#include <assert.h>
#include <errno.h>
#include <pthread.h>

#include <string.h>

#include <unistd.h>

#if SOCKET_HAS_IO_URING
#include <liburing.h>
#include <sys/eventfd.h>
#include <sys/uio.h>
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
#include "socket/SocketIO.h"
#define SOCKET_LOG_COMPONENT "SocketAsync"
#include "core/SocketUtil.h"

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#endif

#define T SocketAsync_T

#ifndef SOCKET_IO_URING_TEST_ENTRIES
#define SOCKET_IO_URING_TEST_ENTRIES 32
#endif

#ifndef SOCKET_DEFAULT_IO_URING_ENTRIES
#define SOCKET_DEFAULT_IO_URING_ENTRIES 256
#endif

/* Auto-flush threshold: submit when SQ is this percentage full */
#ifndef SOCKET_IO_URING_FLUSH_THRESHOLD_PCT
#define SOCKET_IO_URING_FLUSH_THRESHOLD_PCT 75
#endif

/* Calculate flush threshold from ring size */
#define SOCKET_IO_URING_FLUSH_THRESHOLD \
  ((SOCKET_DEFAULT_IO_URING_ENTRIES * SOCKET_IO_URING_FLUSH_THRESHOLD_PCT) / 100)

/* Key fields for partial completion and timeout support:
 * - size_t completed in AsyncRequest - tracks bytes transferred so far
 * - int64_t submitted_at in AsyncRequest - submission timestamp for timeout
 * - int64_t deadline_ms in AsyncRequest - per-request deadline (0 = use global)
 * - int64_t request_timeout_ms in SocketAsync_T - global timeout (0 = disabled)
 *
 * See SocketAsync_send_continue(), SocketAsync_recv_continue() for continuation.
 * See SocketAsync_set_timeout(), SocketAsync_expire_stale() for timeout handling.
 */

const Except_T SocketAsync_Failed
    = { &SocketAsync_Failed, "SocketAsync operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketAsync);

#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketAsync, e)
static inline unsigned
request_hash (const unsigned request_id)
{
  return socket_util_hash_uint (request_id, SOCKET_HASH_TABLE_SIZE);
}

/* Request ID 0 is reserved as invalid. When unsigned wraps from
 * UINT_MAX to 0, we skip to 1.
 */
static unsigned
generate_request_id_unlocked (T async)
{
  unsigned id;

  assert (async);

  id = async->next_request_id++;
  /* LCOV_EXCL_START */
  if (id == 0)
    id = async->next_request_id++;
  /* LCOV_EXCL_STOP */

  return id;
}

static struct AsyncRequest *
socket_async_allocate_request (T async)
{
  struct AsyncRequest *volatile req = NULL;

  assert (async);

  TRY { req = CALLOC (async->arena, 1, sizeof (struct AsyncRequest)); }
  EXCEPT (Arena_Failed)
  {
    /* LCOV_EXCL_START */
    SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate async request");
    RAISE_MODULE_ERROR (SocketAsync_Failed);
    /* LCOV_EXCL_STOP */
  }
  END_TRY;

  return (struct AsyncRequest *)req;
}

/* Note: Request is allocated from arena, so no explicit free needed.
 * We clear it securely to prevent use-after-free bugs and ensure
 * sensitive callback data doesn't persist in memory.
 */
static void
socket_async_free_request (T async, struct AsyncRequest *req)
{
  (void)async;
  if (req)
    {
      volatile unsigned char *p = (volatile unsigned char *)req;
      size_t n = sizeof (*req);
      while (n--)
        *p++ = 0;
    }
}

static int find_and_remove_request (T async, unsigned request_id,
                                    struct AsyncRequest **out_req,
                                    SocketAsync_Callback *out_cb,
                                    Socket_T *out_socket,
                                    void **out_user_data);

static void remove_known_request (T async, struct AsyncRequest *req);

static int check_and_expire_stale_requests (T async);
static inline void
accumulate_transfer_progress (struct AsyncRequest *req, ssize_t result)
{
  size_t transferred;

  if (result <= 0)
    return;

  transferred = (size_t)result;
  req->completed += transferred;

  if (req->completed > req->len)
    req->completed = req->len;
}

static void
process_request_completion (T async, struct AsyncRequest *req, ssize_t result, int err)
{
  if (err == 0)
    accumulate_transfer_progress (req, result);

  if (req->cb)
    req->cb (req->socket, result, err, req->user_data);

  socket_async_free_request (async, req);
}

#if SOCKET_HAS_IO_URING
static void
handle_completion (T async, unsigned request_id, ssize_t result, int err)
{
  struct AsyncRequest *req;

  if (!find_and_remove_request (async, request_id, &req, NULL, NULL, NULL))
    return;

  process_request_completion (async, req, result, err);
}
#endif /* SOCKET_HAS_IO_URING */
static struct AsyncRequest *
setup_async_request (T async, Socket_T socket, SocketAsync_Callback cb,
                     void *user_data, enum AsyncRequestType type,
                     const void *send_buf, void *recv_buf, size_t len,
                     SocketAsync_Flags flags)
{
  struct AsyncRequest *req = socket_async_allocate_request (async);

  req->socket = socket;
  req->cb = cb;
  req->user_data = user_data;
  req->type = type;
  req->send_buf = send_buf;
  req->recv_buf = recv_buf;
  req->len = len;
  req->flags = flags;
  req->deadline_ms = 0;

  return req;
}

/* LCOV_EXCL_START */
static void
cleanup_failed_request (T async, struct AsyncRequest *req)
{
  remove_known_request (async, req);
  socket_async_free_request (async, req);
}
/* LCOV_EXCL_STOP */
static struct AsyncRequest *
find_request_unlocked (T async, unsigned request_id)
{
  unsigned hash;
  struct AsyncRequest *req;

  assert (async);

  hash = request_hash (request_id);
  req = async->requests[hash];

  while (req && req->request_id != request_id)
    req = req->next;

  return req;
}

static void
remove_request_unlocked (T async, struct AsyncRequest *req)
{
  unsigned hash;
  struct AsyncRequest **pp;

  if (!req)
    return;

  hash = request_hash (req->request_id);
  pp = &async->requests[hash];

  while (*pp && *pp != req)
    pp = &(*pp)->next;

  if (*pp == req)
    *pp = req->next;
}

static int
find_and_remove_request (T async, unsigned request_id,
                         struct AsyncRequest **out_req,
                         SocketAsync_Callback *out_cb, Socket_T *out_socket,
                         void **out_user_data)
{
  unsigned hash;
  struct AsyncRequest *req;
  struct AsyncRequest **pp;
  int found = 0;

  assert (async);

  *out_req = NULL;
  if (out_cb)
    *out_cb = NULL;
  if (out_socket)
    *out_socket = NULL;
  if (out_user_data)
    *out_user_data = NULL;

  hash = request_hash (request_id);
  pthread_mutex_lock (&async->mutex);
  pp = &async->requests[hash];
  req = *pp;
  while (req && req->request_id != request_id)
    {
      pp = &req->next;
      req = *pp;
    }
  if (req)
    {
      found = 1;
      if (out_cb)
        *out_cb = req->cb;
      if (out_socket)
        *out_socket = req->socket;
      if (out_user_data)
        *out_user_data = req->user_data;
      *out_req = req;
      *pp = req->next;
    }
  pthread_mutex_unlock (&async->mutex);

  return found;
}

static void
remove_known_request (T async, struct AsyncRequest *req)
{
  unsigned hash;
  struct AsyncRequest **pp;

  if (!req || !async)
    return;

  hash = request_hash (req->request_id);
  pthread_mutex_lock (&async->mutex);
  pp = &async->requests[hash];
  while (*pp && *pp != req)
    {
      pp = &(*pp)->next;
    }
  if (*pp == req)
    {
      *pp = req->next;
    }
  pthread_mutex_unlock (&async->mutex);
}

static int submit_async_operation (T async, struct AsyncRequest *req);
static unsigned
submit_and_track_request (T async, struct AsyncRequest *req)
{
  int result;
  unsigned hash;

  pthread_mutex_lock (&async->mutex);

  req->request_id = generate_request_id_unlocked (async);

  hash = request_hash (req->request_id);
  req->next = async->requests[hash];
  async->requests[hash] = req;

  req->completed = 0;
  req->submitted_at = Socket_get_monotonic_ms();

  pthread_mutex_unlock (&async->mutex);

  result = async->available ? submit_async_operation (async, req) : 0;

  /* LCOV_EXCL_START */
  if (result < 0)
    {
      cleanup_failed_request (async, req);
      return 0;
    }
  /* LCOV_EXCL_STOP */

  return req->request_id;
}

#if SOCKET_HAS_IO_URING
/**
 * @brief Flush pending io_uring submissions to kernel.
 * @internal
 * @param async Async context with pending SQEs.
 * @return Number of SQEs submitted, or -1 on error.
 *
 * Submits all pending SQEs in one syscall and resets pending count.
 */
static int
flush_io_uring_unlocked (T async)
{
  int submitted;

  if (!async || !async->ring || async->pending_sqe_count == 0)
    return 0;

  submitted = io_uring_submit (async->ring);
  if (submitted < 0)
    {
      /* Submission failed - pending SQEs are lost */
      async->pending_sqe_count = 0;
      return -1;
    }

  async->pending_sqe_count = 0;
  return submitted;
}

static int
submit_io_uring_op (T async, struct AsyncRequest *req)
{
  struct io_uring_sqe *sqe;
  int fd = Socket_fd (req->socket);
  int submitted;

  assert (async && async->ring && req);

  sqe = io_uring_get_sqe (async->ring);
  if (!sqe)
    {
      /* SQ full - try flushing first */
      if (async->pending_sqe_count > 0)
        {
          flush_io_uring_unlocked (async);
          sqe = io_uring_get_sqe (async->ring);
        }
      if (!sqe)
        {
          errno = EAGAIN;
          return -1;
        }
    }

  if (req->type == REQ_SEND)
    io_uring_prep_send (sqe, fd, req->send_buf, req->len, 0);
  else
    io_uring_prep_recv (sqe, fd, req->recv_buf, req->len, 0);

  sqe->user_data = (uintptr_t)req->request_id;

  if (req->flags & ASYNC_FLAG_URGENT)
    sqe->flags |= IOSQE_IO_LINK;

  /* Check for deferred submission (NOSYNC flag) */
  if (req->flags & ASYNC_FLAG_NOSYNC)
    {
      async->pending_sqe_count++;

      /* Auto-flush if near capacity to prevent SQ overflow */
      if (async->pending_sqe_count >= SOCKET_IO_URING_FLUSH_THRESHOLD)
        {
          submitted = flush_io_uring_unlocked (async);
          if (submitted < 0)
            return -1;
        }
      return 0;
    }

  /* Immediate submission (default behavior) */
  submitted = io_uring_submit (async->ring);
  if (submitted < 0)
    return -1;

  return 0;
}


static int
process_io_uring_completions (T async, int max_completions)
{
  struct io_uring_cqe *cqe;
  unsigned head;
  int count = 0;

  assert (async && async->ring);

  io_uring_for_each_cqe (async->ring, head, cqe)
  {
    if (count >= max_completions)
      break;

    unsigned request_id = (unsigned)(uintptr_t)cqe->user_data;
    ssize_t result = cqe->res;
    int err = (result < 0) ? (int)-result : 0;

    handle_completion (async, request_id, result, err);
    count++;
  }

  io_uring_cq_advance (async->ring, (unsigned)count);

  return count;
}

#endif /* SOCKET_HAS_IO_URING */

#if defined(__APPLE__) || defined(__FreeBSD__)

/* Note: macOS/BSD don't have true AIO like io_uring. This implementation
 * uses edge-triggered kqueue events. The actual I/O is performed when
 * the event fires, then the callback is invoked.
 */
static int
submit_kqueue_aio (T async, struct AsyncRequest *req)
{
  struct kevent kev;
  int fd = Socket_fd (req->socket);
  int16_t filter;

  assert (async && async->kqueue_fd >= 0 && req);

  filter = (req->type == REQ_SEND) ? EVFILT_WRITE : EVFILT_READ;
  EV_SET (&kev, fd, filter, EV_ADD | EV_ENABLE | EV_ONESHOT, 0, 0,
          (void *)(uintptr_t)req->request_id);

  if (kevent (async->kqueue_fd, &kev, 1, NULL, 0, NULL) < 0)
    return -1;

  return 0;
}


static ssize_t
socket_async_perform_io (Socket_T socket, enum AsyncRequestType type,
                         const void *send_buf, void *recv_buf, size_t len,
                         int *err_out)
{
  ssize_t result;
  *err_out = 0;

  TRY
  {
    if (type == REQ_SEND)
      result = socket_send_internal (socket, send_buf, len, MSG_NOSIGNAL);
    else
      result = socket_recv_internal (socket, recv_buf, len, 0);

    if (result == 0)
      {
        *err_out = EAGAIN;
        result = -1;
      }
  }
  EXCEPT (Socket_Closed)
  {
    *err_out = ECONNRESET;
    result = -1;
  }
  EXCEPT (Socket_Failed)
  {
    *err_out = errno ? errno : EPROTO;
    result = -1;
  }
#if SOCKET_HAS_TLS
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    *err_out = EAGAIN;
    result = -1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    *err_out = errno ? errno : EPROTO;
    result = -1;
  }
#endif
  END_TRY;

  return result;
}

static void
kqueue_perform_io (struct AsyncRequest *req, ssize_t *result, int *err)
{
  *result = socket_async_perform_io (req->socket, req->type, req->send_buf,
                                     req->recv_buf, req->len, err);
}

/**
 * kqueue_complete_request - Complete request and invoke callback
 * @async: Async context
 * @req: Request to complete
 *
 * Thread-safe: Yes
 */
static void
kqueue_complete_request (T async, struct AsyncRequest *req)
{
  ssize_t result;
  int err;

  kqueue_perform_io (req, &result, &err);

  process_request_completion (async, req, result, err);
}


static int
process_kqueue_completions (T async, int timeout_ms, int max_completions)
{
  struct kevent events[SOCKET_MAX_EVENT_BATCH];
  struct timespec timeout;
  int n, count = 0;

  assert (async && async->kqueue_fd >= 0);

  if (max_completions > SOCKET_MAX_EVENT_BATCH)
    max_completions = SOCKET_MAX_EVENT_BATCH;

  timeout = socket_util_ms_to_timespec ((unsigned long)timeout_ms);

  n = kevent (async->kqueue_fd, NULL, 0, events, max_completions, &timeout);
  if (n < 0)
    return (errno == EINTR) ? 0 : -1;

  for (int i = 0; i < n; i++)
    {
      unsigned request_id = (unsigned)(uintptr_t)events[i].udata;
      struct AsyncRequest *req;

      if (find_and_remove_request (async, request_id, &req, NULL, NULL, NULL))
        {
          kqueue_complete_request (async, req);
          count++;
        }
    }

  return count;
}

#endif /* __APPLE__ || __FreeBSD__ */


#if SOCKET_HAS_IO_URING
static int
io_uring_register_and_activate (T async, unsigned ring_size, int sqpoll_active,
                                const char *backend_name)
{
  async->io_uring_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (async->io_uring_fd < 0)
    return 0;

  if (io_uring_register_eventfd (async->ring, async->io_uring_fd) != 0)
    {
      close (async->io_uring_fd);
      return 0;
    }

  async->available = 1;
  async->sqpoll_active = sqpoll_active;
  async->ring_size = ring_size;
  async->backend_name = backend_name;
  return 1;
}

static int
try_io_uring_sqpoll (T async, const SocketAsync_Config *config,
                     unsigned ring_size)
{
  struct io_uring_params params;

  memset (&params, 0, sizeof (params));
  params.flags = IORING_SETUP_SQPOLL;
  params.sq_thread_idle = config->sqpoll_idle_ms;

  if (config->sqpoll_cpu >= 0)
    {
      params.flags |= IORING_SETUP_SQ_AFF;
      params.sq_thread_cpu = (unsigned)config->sqpoll_cpu;
    }

  if (io_uring_queue_init_params (ring_size, async->ring, &params) != 0)
    return 0;

  if (io_uring_register_and_activate (async, ring_size, 1, "io_uring (SQPOLL)"))
    return 1;

  io_uring_queue_exit (async->ring);
  return 0;
}

static int
try_io_uring_default (T async, unsigned ring_size)
{
  if (io_uring_queue_init (ring_size, async->ring, 0) != 0)
    {
      async->ring = NULL;
      return 0;
    }

  if (io_uring_register_and_activate (async, ring_size, 0, "io_uring"))
    return 1;

  io_uring_queue_exit (async->ring);
  async->ring = NULL;
  return 0;
}

static int
detect_io_uring_backend (T async, const SocketAsync_Config *config)
{
  struct io_uring test_ring;
  unsigned ring_size;
  int sqpoll_requested;

  ring_size = (config && config->ring_size > 0) ? config->ring_size
                                                 : SOCKET_DEFAULT_IO_URING_ENTRIES;
  sqpoll_requested = config && config->enable_sqpoll;

  /* Test if io_uring is available */
  if (io_uring_queue_init (SOCKET_IO_URING_TEST_ENTRIES, &test_ring, 0) != 0)
    {
      async->available = 0;
      async->backend_name = "unavailable (io_uring unavailable)";
      return 0;
    }
  io_uring_queue_exit (&test_ring);

  /* Allocate ring structure */
  async->ring = CALLOC (async->arena, 1, sizeof (struct io_uring));
  if (!async->ring)
    {
      async->backend_name = "io_uring (allocation failed)";
      return 0;
    }

  /* Try SQPOLL mode first if requested */
  if (sqpoll_requested && try_io_uring_sqpoll (async, config, ring_size))
    return 1;

  /* Fall back to default mode */
  if (try_io_uring_default (async, ring_size))
    return 1;

  async->ring = NULL;
  async->available = 0;
  async->backend_name = "unavailable (io_uring unavailable)";
  return 0;
}
#endif /* SOCKET_HAS_IO_URING */

#if defined(__APPLE__) || defined(__FreeBSD__)
static int
detect_kqueue_backend (T async)
{
  async->kqueue_fd = kqueue ();
  if (async->kqueue_fd >= 0)
    {
      async->available = 1;
      async->backend_name = "kqueue";
      return 1;
    }

  async->available = 0;
  async->backend_name = "unavailable (kqueue unavailable)";
  return 0;
}
#endif /* __APPLE__ || __FreeBSD__ */

static int
detect_async_backend_with_config (T async, const SocketAsync_Config *config)
{
  assert (async);

#if SOCKET_HAS_IO_URING
  return detect_io_uring_backend (async, config);
#elif defined(__APPLE__) || defined(__FreeBSD__)
  (void)config;
  return detect_kqueue_backend (async);
#else
  (void)config;
  async->available = 0;
  async->backend_name = "unavailable (platform not supported)";
  return 0;
#endif
}

/* Backward-compatible wrapper */
static int
detect_async_backend (T async)
{
  return detect_async_backend_with_config (async, NULL);
}

/* LCOV_EXCL_START */
static int
submit_async_operation (T async, struct AsyncRequest *req)
{
  assert (async && req);

#if SOCKET_HAS_IO_URING
  if (async->ring)
    return submit_io_uring_op (async, req);
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
  if (async->kqueue_fd >= 0)
    return submit_kqueue_aio (async, req);
#endif

  (void)async;
  (void)req;
  errno = ENOTSUP;
  return -1;
}
/* LCOV_EXCL_STOP */


static int
process_async_completions_internal (T async,
                                    int timeout_ms __attribute__ ((unused)))
{
  int completed = 0;

  assert (async);

  if (async->available)
    {
#if SOCKET_HAS_IO_URING
      if (async->ring)
        {
          uint64_t val;
          ssize_t n = read (async->io_uring_fd, &val, sizeof (val));
          if (n > 0)
            completed = process_io_uring_completions (async,
                                                      SOCKET_MAX_EVENT_BATCH);
        }
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
      if (async->kqueue_fd >= 0)
        completed = process_kqueue_completions (async, timeout_ms,
                                                SOCKET_MAX_EVENT_BATCH);
#endif
    }

  if (async->request_timeout_ms > 0)
    completed += check_and_expire_stale_requests (async);

  return completed;
}


static unsigned
socket_async_submit (T async, Socket_T socket, enum AsyncRequestType type,
                     const void *send_buf, void *recv_buf, size_t len,
                     SocketAsync_Callback cb, void *user_data,
                     SocketAsync_Flags flags)
{
  struct AsyncRequest *req;
  unsigned request_id;

  if (!async || !socket || !cb || len == 0)
    {
      errno = EINVAL;
      SOCKET_ERROR_FMT ("Invalid parameters: async=%p socket=%p cb=%p len=%zu",
                        (void *)async, (void *)socket, (void *)cb, len);
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }
  if (type == REQ_SEND && !send_buf)
    {
      errno = EINVAL;
      SOCKET_ERROR_MSG ("Send buffer is NULL for send operation");
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }
  if (type == REQ_RECV && !recv_buf)
    {
      errno = EINVAL;
      SOCKET_ERROR_MSG ("Receive buffer is NULL for recv operation");
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }

  TRY { Socket_setnonblocking (socket); }
  EXCEPT (Socket_Failed) { }
  END_TRY;

  req = setup_async_request (async, socket, cb, user_data, type, send_buf,
                             recv_buf, len, flags);

  request_id = submit_and_track_request (async, req);
  if (request_id == 0)
    {
      const char *op = (type == REQ_SEND) ? "send" : "recv";
      SOCKET_ERROR_FMT ("Failed to submit async %s (errno=%d)", op, errno);
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }

  return request_id;
}

T
SocketAsync_new (Arena_T arena)
{
  volatile T async = NULL;

  assert (arena);

  TRY { async = CALLOC (arena, 1, sizeof (*async)); }
  EXCEPT (Arena_Failed)
  {
    /* LCOV_EXCL_START */
    SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate async context");
    RAISE_MODULE_ERROR (SocketAsync_Failed);
    /* LCOV_EXCL_STOP */
  }
  END_TRY;

  ((T)async)->arena = arena;
  ((T)async)->next_request_id = 1;

  if (pthread_mutex_init (&((T)async)->mutex, NULL) != 0)
    {
      /* LCOV_EXCL_START */
      SOCKET_ERROR_MSG ("Failed to initialize async mutex");
      RAISE_MODULE_ERROR (SocketAsync_Failed);
      /* LCOV_EXCL_STOP */
    }

  detect_async_backend ((T)async);

  return (T)async;
}

T
SocketAsync_new_with_config (Arena_T arena, const SocketAsync_Config *config)
{
  volatile T async = NULL;

  assert (arena);

  TRY { async = CALLOC (arena, 1, sizeof (*async)); }
  EXCEPT (Arena_Failed)
  {
    /* LCOV_EXCL_START */
    SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate async context");
    RAISE_MODULE_ERROR (SocketAsync_Failed);
    /* LCOV_EXCL_STOP */
  }
  END_TRY;

  ((T)async)->arena = arena;
  ((T)async)->next_request_id = 1;

  if (pthread_mutex_init (&((T)async)->mutex, NULL) != 0)
    {
      /* LCOV_EXCL_START */
      SOCKET_ERROR_MSG ("Failed to initialize async mutex");
      RAISE_MODULE_ERROR (SocketAsync_Failed);
      /* LCOV_EXCL_STOP */
    }

  detect_async_backend_with_config ((T)async, config);

  return (T)async;
}

int
SocketAsync_is_sqpoll_active (const T async)
{
#if SOCKET_HAS_IO_URING
  if (!async)
    return 0;
  return async->sqpoll_active;
#else
  (void)async;
  return 0;
#endif
}

void
SocketAsync_free (T *async)
{
  if (!async || !*async)
    return;

  pthread_mutex_lock (&(*async)->mutex);
  for (unsigned i = 0; i < SOCKET_HASH_TABLE_SIZE; ++i)
    {
      struct AsyncRequest *req = (*async)->requests[i];
      while (req)
        {
          struct AsyncRequest *next = req->next;
          socket_async_free_request (*async, req);
          req = next;
        }
      (*async)->requests[i] = NULL;
    }
  (*async)->next_request_id = 1;
  pthread_mutex_unlock (&(*async)->mutex);

#if SOCKET_HAS_IO_URING
  if ((*async)->ring)
    {
      /* Unregister buffers if registered */
      if ((*async)->registered_buf_count > 0)
        {
          io_uring_unregister_buffers ((*async)->ring);
          (*async)->registered_buf_count = 0;
          (*async)->registered_bufs = NULL;
        }

      /* Unregister files if registered */
      if ((*async)->registered_fd_count > 0)
        {
          io_uring_unregister_files ((*async)->ring);
          (*async)->registered_fd_count = 0;
          (*async)->registered_fds = NULL;
        }

      if ((*async)->io_uring_fd >= 0)
        {
          io_uring_register_eventfd ((*async)->ring, -1);
          close ((*async)->io_uring_fd);
        }
      io_uring_queue_exit ((*async)->ring);
      (*async)->ring = NULL;
    }
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
  if ((*async)->kqueue_fd >= 0)
    close ((*async)->kqueue_fd);
#endif

  pthread_mutex_destroy (&(*async)->mutex);
  *async = NULL;
}

int
SocketAsync_is_available (const T async)
{
  if (!async)
    return 0;
  return async->available;
}

const char *
SocketAsync_backend_name (const T async)
{
  if (!async)
    return "unavailable";
  return async->backend_name;
}


unsigned
SocketAsync_send (T async, Socket_T socket, const void *buf, size_t len,
                  SocketAsync_Callback cb, void *user_data,
                  SocketAsync_Flags flags)
{
  return socket_async_submit (async, socket, REQ_SEND, buf, NULL, len, cb,
                              user_data, flags);
}


unsigned
SocketAsync_recv (T async, Socket_T socket, void *buf, size_t len,
                  SocketAsync_Callback cb, void *user_data,
                  SocketAsync_Flags flags)
{
  return socket_async_submit (async, socket, REQ_RECV, NULL, buf, len, cb,
                              user_data, flags);
}


int
SocketAsync_cancel (T async, unsigned request_id)
{
  struct AsyncRequest *req;

  if (find_and_remove_request (async, request_id, &req, NULL, NULL, NULL))
    {
      socket_async_free_request (async, req);
      return 0;
    }

  return -1;
}

int
SocketAsync_process_completions (T async, int timeout_ms)
{
  return process_async_completions_internal (async, timeout_ms);
}


int
SocketAsync_submit_batch (T async, SocketAsync_Op *ops, size_t count)
{
  volatile size_t submitted = 0;
  volatile size_t i;
  int use_deferred = 0;

  if (!async || !ops || count == 0)
    return 0;

#if SOCKET_HAS_IO_URING
  /* Use deferred submission for io_uring to batch all SQEs */
  use_deferred = (async->ring != NULL && async->available);
#endif

  for (i = 0; i < count; i++)
    {
      SocketAsync_Op *op = &ops[i];
      volatile SocketAsync_Flags flags = op->flags;
      volatile unsigned req_id = 0;

      /* Add NOSYNC flag for deferred submission on io_uring */
      if (use_deferred)
        flags |= ASYNC_FLAG_NOSYNC;

      TRY
      {
        if (op->is_send)
          {
            req_id = SocketAsync_send (async, op->socket, op->send_buf, op->len,
                                       op->cb, op->user_data, (SocketAsync_Flags)flags);
          }
        else
          {
            req_id = SocketAsync_recv (async, op->socket, op->recv_buf, op->len,
                                       op->cb, op->user_data, (SocketAsync_Flags)flags);
          }
        op->request_id = (unsigned)req_id;
        submitted++;
      }
      EXCEPT (SocketAsync_Failed)
      {
        break;
      }
      END_TRY;
    }

  /* Flush all pending SQEs in one syscall */
  if (use_deferred && submitted > 0)
    SocketAsync_flush (async);

  return (int)submitted;
}


int
SocketAsync_cancel_all (T async)
{
  int cancelled = 0;

  if (!async)
    return 0;

  pthread_mutex_lock (&async->mutex);

  for (unsigned i = 0; i < SOCKET_HASH_TABLE_SIZE; i++)
    {
      struct AsyncRequest *req = async->requests[i];
      while (req)
        {
          struct AsyncRequest *next = req->next;
          socket_async_free_request (async, req);
          cancelled++;
          req = next;
        }
      async->requests[i] = NULL;
    }

  pthread_mutex_unlock (&async->mutex);

  return cancelled;
}

static pthread_mutex_t backend_pref_mutex = PTHREAD_MUTEX_INITIALIZER;
static SocketAsync_Backend preferred_backend = ASYNC_BACKEND_AUTO;


int
SocketAsync_backend_available (SocketAsync_Backend backend)
{
  switch (backend)
    {
    case ASYNC_BACKEND_AUTO:
      return 1;

    case ASYNC_BACKEND_IO_URING:
#if SOCKET_HAS_IO_URING
      {
        struct io_uring test_ring;
        if (io_uring_queue_init (SOCKET_IO_URING_TEST_ENTRIES, &test_ring, 0)
            == 0)
          {
            io_uring_queue_exit (&test_ring);
            return 1;
          }
      }
#endif
      return 0;

    case ASYNC_BACKEND_KQUEUE:
#if defined(__APPLE__) || defined(__FreeBSD__)
      {
        int kq = kqueue ();
        if (kq >= 0)
          {
            close (kq);
            return 1;
          }
      }
#endif
      return 0;

    case ASYNC_BACKEND_POLL:
      return 1;

    case ASYNC_BACKEND_NONE:
      return 1;

    default:
      return 0;
    }
}


int
SocketAsync_set_backend (SocketAsync_Backend backend)
{
  if (!SocketAsync_backend_available (backend))
    return -1;

  pthread_mutex_lock (&backend_pref_mutex);
  preferred_backend = backend;
  pthread_mutex_unlock (&backend_pref_mutex);

  return 0;
}


int
SocketAsync_get_progress (T async, unsigned request_id, size_t *completed,
                          size_t *total)
{
  struct AsyncRequest *req;
  int found = 0;

  if (completed)
    *completed = 0;
  if (total)
    *total = 0;

  if (!async || request_id == 0)
    return 0;

  pthread_mutex_lock (&async->mutex);
  req = find_request_unlocked (async, request_id);
  if (req)
    {
      found = 1;
      if (completed)
        *completed = req->completed;
      if (total)
        *total = req->len;
    }
  pthread_mutex_unlock (&async->mutex);

  return found;
}


static unsigned
socket_async_continue_request (T async, unsigned request_id,
                               enum AsyncRequestType expected_type)
{
  struct AsyncRequest *orig_req;
  struct AsyncRequest *new_req;
  Socket_T socket;
  SocketAsync_Callback cb;
  void *user_data;
  const void *send_buf = NULL;
  void *recv_buf = NULL;
  size_t remaining_len;
  SocketAsync_Flags flags;
  unsigned new_id;

  if (!async || request_id == 0)
    return 0;

  pthread_mutex_lock (&async->mutex);

  orig_req = find_request_unlocked (async, request_id);
  if (!orig_req)
    {
      pthread_mutex_unlock (&async->mutex);
      return 0;
    }

  if (orig_req->type != expected_type)
    {
      pthread_mutex_unlock (&async->mutex);
      return 0;
    }

  if (orig_req->completed >= orig_req->len)
    {
      pthread_mutex_unlock (&async->mutex);
      return 0;
    }

  socket = orig_req->socket;
  cb = orig_req->cb;
  user_data = orig_req->user_data;
  remaining_len = orig_req->len - orig_req->completed;
  flags = orig_req->flags;

  if (expected_type == REQ_SEND)
    send_buf = (const char *)orig_req->send_buf + orig_req->completed;
  else
    recv_buf = (char *)orig_req->recv_buf + orig_req->completed;

  remove_request_unlocked (async, orig_req);

  pthread_mutex_unlock (&async->mutex);

  socket_async_free_request (async, orig_req);

  new_req = setup_async_request (async, socket, cb, user_data, expected_type,
                                 send_buf, recv_buf, remaining_len, flags);

  new_id = submit_and_track_request (async, new_req);
  if (new_id == 0)
    socket_async_free_request (async, new_req);

  return new_id;
}


unsigned
SocketAsync_send_continue (T async, unsigned request_id)
{
  return socket_async_continue_request (async, request_id, REQ_SEND);
}


unsigned
SocketAsync_recv_continue (T async, unsigned request_id)
{
  return socket_async_continue_request (async, request_id, REQ_RECV);
}


void
SocketAsync_set_timeout (T async, int64_t timeout_ms)
{
  if (!async)
    return;

  pthread_mutex_lock (&async->mutex);
  async->request_timeout_ms = (timeout_ms > 0) ? timeout_ms : 0;
  pthread_mutex_unlock (&async->mutex);
}


int64_t
SocketAsync_get_timeout (T async)
{
  int64_t timeout;

  if (!async)
    return 0;

  pthread_mutex_lock (&async->mutex);
  timeout = async->request_timeout_ms;
  pthread_mutex_unlock (&async->mutex);

  return timeout;
}


static int64_t
calculate_request_deadline (const struct AsyncRequest *req,
                             int64_t global_timeout)
{
  if (req->deadline_ms > 0)
    return req->deadline_ms;

  if (global_timeout > 0 && req->submitted_at > 0)
    return req->submitted_at + global_timeout;

  return 0;
}


static struct AsyncRequest *
collect_expired_requests (T async, int64_t now_ms, int64_t global_timeout,
                          int *out_count)
{
  struct AsyncRequest *expired_list = NULL;
  struct AsyncRequest *expired_tail = NULL;
  int expired_count = 0;

  for (unsigned i = 0; i < SOCKET_HASH_TABLE_SIZE; i++)
    {
      struct AsyncRequest **pp = &async->requests[i];

      while (*pp)
        {
          struct AsyncRequest *req = *pp;
          int64_t deadline = calculate_request_deadline (req, global_timeout);

          if (deadline == 0)
            {
              pp = &req->next;
              continue;
            }

          if (now_ms >= deadline)
            {
              *pp = req->next;

              req->next = NULL;
              if (expired_tail)
                expired_tail->next = req;
              else
                expired_list = req;
              expired_tail = req;
              expired_count++;
            }
          else
            {
              pp = &req->next;
            }
        }
    }

  if (out_count)
    *out_count = expired_count;

  return expired_list;
}


static int
invoke_timeout_callbacks (T async, struct AsyncRequest *expired_list)
{
  int count = 0;

  while (expired_list)
    {
      struct AsyncRequest *req = expired_list;
      expired_list = req->next;

      if (req->cb)
        req->cb (req->socket, -1, ETIMEDOUT, req->user_data);

      socket_async_free_request (async, req);
      count++;
    }

  return count;
}


static int
check_and_expire_stale_requests (T async)
{
  int64_t now_ms;
  struct AsyncRequest *expired_list;
  int64_t global_timeout;
  int expired_count;

  if (!async)
    return 0;

  now_ms = Socket_get_monotonic_ms ();

  pthread_mutex_lock (&async->mutex);
  global_timeout = async->request_timeout_ms;
  expired_list = collect_expired_requests (async, now_ms, global_timeout,
                                            &expired_count);
  pthread_mutex_unlock (&async->mutex);

  invoke_timeout_callbacks (async, expired_list);

  return expired_count;
}


int
SocketAsync_expire_stale (T async)
{
  return check_and_expire_stale_requests (async);
}


static unsigned
socket_async_submit_with_timeout (T async, Socket_T socket,
                                  enum AsyncRequestType type,
                                  const void *send_buf, void *recv_buf,
                                  size_t len, SocketAsync_Callback cb,
                                  void *user_data, SocketAsync_Flags flags,
                                  int64_t timeout_ms)
{
  struct AsyncRequest *req;
  unsigned request_id;

  if (!async || !socket || !cb || len == 0)
    {
      errno = EINVAL;
      SOCKET_ERROR_FMT ("Invalid parameters: async=%p socket=%p cb=%p len=%zu",
                        (void *)async, (void *)socket, (void *)cb, len);
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }
  if (type == REQ_SEND && !send_buf)
    {
      errno = EINVAL;
      SOCKET_ERROR_MSG ("Send buffer is NULL for send operation");
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }
  if (type == REQ_RECV && !recv_buf)
    {
      errno = EINVAL;
      SOCKET_ERROR_MSG ("Receive buffer is NULL for recv operation");
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }

  TRY { Socket_setnonblocking (socket); }
  EXCEPT (Socket_Failed) { }
  END_TRY;

  req = setup_async_request (async, socket, cb, user_data, type, send_buf,
                             recv_buf, len, flags);

  if (timeout_ms > 0)
    req->deadline_ms = Socket_get_monotonic_ms () + timeout_ms;

  request_id = submit_and_track_request (async, req);
  if (request_id == 0)
    {
      const char *op = (type == REQ_SEND) ? "send" : "recv";
      SOCKET_ERROR_FMT ("Failed to submit async %s (errno=%d)", op, errno);
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }

  return request_id;
}


unsigned
SocketAsync_send_timeout (T async, Socket_T socket, const void *buf, size_t len,
                          SocketAsync_Callback cb, void *user_data,
                          SocketAsync_Flags flags, int64_t timeout_ms)
{
  return socket_async_submit_with_timeout (async, socket, REQ_SEND, buf, NULL,
                                           len, cb, user_data, flags,
                                           timeout_ms);
}


unsigned
SocketAsync_recv_timeout (T async, Socket_T socket, void *buf, size_t len,
                          SocketAsync_Callback cb, void *user_data,
                          SocketAsync_Flags flags, int64_t timeout_ms)
{
  return socket_async_submit_with_timeout (async, socket, REQ_RECV, NULL, buf,
                                           len, cb, user_data, flags,
                                           timeout_ms);
}


/* ==================== io_uring Availability Check ==================== */

#ifdef __linux__
#include <sys/utsname.h>
#endif

/**
 * Parse kernel version from uname().release string.
 * Returns 1 on success, 0 on failure.
 */
static int
parse_kernel_version (int *major, int *minor, int *patch)
{
#ifdef __linux__
  struct utsname uts;
  if (uname (&uts) != 0)
    return 0;

  /* Parse release string like "5.10.0-generic" or "6.2.15" */
  *major = *minor = *patch = 0;
  if (sscanf (uts.release, "%d.%d.%d", major, minor, patch) >= 2)
    {
      /* Validate kernel version components are reasonable (0-999) */
      if (*major < 0 || *major > 999 ||
          *minor < 0 || *minor > 999 ||
          *patch < 0 || *patch > 999)
        {
          *major = *minor = *patch = 0;
          return 0;
        }
      return 1;
    }

  return 0;
#else
  /* Not Linux - io_uring not available */
  *major = *minor = *patch = 0;
  return 0;
#endif
}

/**
 * Check if kernel version is >= required (major.minor).
 */
static int
kernel_version_at_least (int major, int minor, int req_major, int req_minor)
{
  if (major > req_major)
    return 1;
  if (major == req_major && minor >= req_minor)
    return 1;
  return 0;
}

int
SocketAsync_get_notification_fd (const T async)
{
  if (!async || !async->available)
    return -1;

#if SOCKET_HAS_IO_URING
  if (async->ring && async->io_uring_fd >= 0)
    return async->io_uring_fd;
#endif

  return -1;
}

int
SocketAsync_io_uring_available (SocketAsync_IOUringInfo *info)
{
  static int cached = -1;
  static SocketAsync_IOUringInfo cached_info;

  /* Return cached result if available */
  if (cached >= 0)
    {
      if (info)
        *info = cached_info;
      return cached;
    }

  /* Initialize info structure */
  cached_info.major = 0;
  cached_info.minor = 0;
  cached_info.patch = 0;
  cached_info.supported = 0;
  cached_info.full_support = 0;
  cached_info.compiled = SOCKET_HAS_IO_URING;

  /* Check compile-time support */
  if (!SOCKET_HAS_IO_URING)
    {
      cached = 0;
      if (info)
        *info = cached_info;
      return 0;
    }

  /* Parse kernel version */
  if (!parse_kernel_version (&cached_info.major, &cached_info.minor,
                             &cached_info.patch))
    {
      cached = 0;
      if (info)
        *info = cached_info;
      return 0;
    }

  /* Check kernel version requirements:
   * - 5.1+: Basic io_uring support
   * - 5.6+: Full features (multi-shot, SQPOLL, registered buffers)
   */
  if (kernel_version_at_least (cached_info.major, cached_info.minor, 5, 1))
    cached_info.supported = 1;

  if (kernel_version_at_least (cached_info.major, cached_info.minor, 5, 6))
    cached_info.full_support = 1;

#if SOCKET_HAS_IO_URING
  /* Additional runtime probe: try to create a small ring */
  if (cached_info.supported)
    {
      struct io_uring ring;
      if (io_uring_queue_init (SOCKET_IO_URING_TEST_ENTRIES, &ring, 0) == 0)
        {
          io_uring_queue_exit (&ring);
        }
      else
        {
          /* Ring creation failed - io_uring not usable */
          cached_info.supported = 0;
          cached_info.full_support = 0;
        }
    }
#endif

  cached = cached_info.supported;
  if (info)
    *info = cached_info;
  return cached;
}


int
SocketAsync_flush (T async)
{
#if SOCKET_HAS_IO_URING
  int submitted;

  if (!async || !async->ring)
    return 0;

  pthread_mutex_lock (&async->mutex);
  submitted = flush_io_uring_unlocked (async);
  pthread_mutex_unlock (&async->mutex);

  return submitted;
#else
  (void)async;
  return 0;
#endif
}


unsigned
SocketAsync_pending_count (const T async)
{
#if SOCKET_HAS_IO_URING
  unsigned count;

  if (!async || !async->ring)
    return 0;

  pthread_mutex_lock (&((T)async)->mutex);
  count = async->pending_sqe_count;
  pthread_mutex_unlock (&((T)async)->mutex);

  return count;
#else
  (void)async;
  return 0;
#endif
}


/* ==================== Registered Buffers Implementation ==================== */

int
SocketAsync_register_buffers (T async, void **bufs, size_t *lens, unsigned count)
{
#if SOCKET_HAS_IO_URING
  struct iovec *iovs;
  int ret;

  if (!async || !async->ring || !bufs || !lens || count == 0)
    {
      errno = EINVAL;
      return -1;
    }

  /* Unregister any existing buffers first */
  if (async->registered_buf_count > 0)
    {
      io_uring_unregister_buffers (async->ring);
      async->registered_buf_count = 0;
      async->registered_bufs = NULL;
    }

  /* Allocate iovec array from arena */
  iovs = CALLOC (async->arena, count, sizeof (struct iovec));
  if (!iovs)
    {
      errno = ENOMEM;
      return -1;
    }

  /* Populate iovec array */
  for (unsigned i = 0; i < count; i++)
    {
      iovs[i].iov_base = bufs[i];
      iovs[i].iov_len = lens[i];
    }

  pthread_mutex_lock (&async->mutex);
  ret = io_uring_register_buffers (async->ring, iovs, count);
  if (ret == 0)
    {
      async->registered_bufs = iovs;
      async->registered_buf_count = count;
    }
  pthread_mutex_unlock (&async->mutex);

  if (ret < 0)
    {
      errno = -ret;
      return -1;
    }

  return 0;
#else
  (void)async;
  (void)bufs;
  (void)lens;
  (void)count;
  errno = ENOTSUP;
  return -1;
#endif
}

int
SocketAsync_unregister_buffers (T async)
{
#if SOCKET_HAS_IO_URING
  int ret;

  if (!async || !async->ring)
    {
      errno = EINVAL;
      return -1;
    }

  if (async->registered_buf_count == 0)
    return 0;

  pthread_mutex_lock (&async->mutex);
  ret = io_uring_unregister_buffers (async->ring);
  async->registered_buf_count = 0;
  async->registered_bufs = NULL;
  pthread_mutex_unlock (&async->mutex);

  if (ret < 0)
    {
      errno = -ret;
      return -1;
    }

  return 0;
#else
  (void)async;
  errno = ENOTSUP;
  return -1;
#endif
}

unsigned
SocketAsync_registered_buffer_count (const T async)
{
#if SOCKET_HAS_IO_URING
  if (!async)
    return 0;
  return async->registered_buf_count;
#else
  (void)async;
  return 0;
#endif
}

unsigned
SocketAsync_send_fixed (T async, Socket_T socket, unsigned buf_index,
                        size_t offset, size_t len, SocketAsync_Callback cb,
                        void *user_data, SocketAsync_Flags flags)
{
#if SOCKET_HAS_IO_URING
  struct AsyncRequest *req;
  struct io_uring_sqe *sqe;
  int fd;
  unsigned request_id;
  char *buf_ptr;

  if (!async || !async->ring || !socket || !cb)
    {
      errno = EINVAL;
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }

  if (buf_index >= async->registered_buf_count)
    {
      errno = EINVAL;
      SOCKET_ERROR_FMT ("Buffer index %u out of range (count=%u)", buf_index,
                        async->registered_buf_count);
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }

  /* Check for integer overflow and bounds violation */
  if (offset > async->registered_bufs[buf_index].iov_len
      || len > async->registered_bufs[buf_index].iov_len - offset)
    {
      errno = EINVAL;
      SOCKET_ERROR_MSG ("Offset + len exceeds buffer size");
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }

  fd = Socket_fd (socket);
  buf_ptr = (char *)async->registered_bufs[buf_index].iov_base + offset;

  /* Set up request with fixed buffer flag */
  req = setup_async_request (async, socket, cb, user_data, REQ_SEND, buf_ptr,
                             NULL, len, flags | ASYNC_FLAG_FIXED_BUFFER);

  pthread_mutex_lock (&async->mutex);
  req->request_id = generate_request_id_unlocked (async);

  /* Insert into hash table */
  unsigned hash = request_hash (req->request_id);
  req->next = async->requests[hash];
  async->requests[hash] = req;
  req->submitted_at = Socket_get_monotonic_ms ();

  /* Submit fixed buffer operation */
  sqe = io_uring_get_sqe (async->ring);
  if (!sqe)
    {
      /* Try flushing pending operations */
      if (async->pending_sqe_count > 0)
        flush_io_uring_unlocked (async);
      sqe = io_uring_get_sqe (async->ring);
    }

  if (!sqe)
    {
      remove_request_unlocked (async, req);
      pthread_mutex_unlock (&async->mutex);
      socket_async_free_request (async, req);
      errno = EAGAIN;
      return 0;
    }

  io_uring_prep_write_fixed (sqe, fd, buf_ptr, len, 0, buf_index);
  sqe->user_data = (uintptr_t)req->request_id;

  request_id = req->request_id;

  /* Submit immediately for fixed buffer ops */
  io_uring_submit (async->ring);

  pthread_mutex_unlock (&async->mutex);

  return request_id;
#else
  (void)async;
  (void)socket;
  (void)buf_index;
  (void)offset;
  (void)len;
  (void)cb;
  (void)user_data;
  (void)flags;
  errno = ENOTSUP;
  RAISE_MODULE_ERROR (SocketAsync_Failed);
  return 0;
#endif
}

unsigned
SocketAsync_recv_fixed (T async, Socket_T socket, unsigned buf_index,
                        size_t offset, size_t len, SocketAsync_Callback cb,
                        void *user_data, SocketAsync_Flags flags)
{
#if SOCKET_HAS_IO_URING
  struct AsyncRequest *req;
  struct io_uring_sqe *sqe;
  int fd;
  unsigned request_id;
  char *buf_ptr;

  if (!async || !async->ring || !socket || !cb)
    {
      errno = EINVAL;
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }

  if (buf_index >= async->registered_buf_count)
    {
      errno = EINVAL;
      SOCKET_ERROR_FMT ("Buffer index %u out of range (count=%u)", buf_index,
                        async->registered_buf_count);
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }

  /* Check for integer overflow and bounds violation */
  if (offset > async->registered_bufs[buf_index].iov_len
      || len > async->registered_bufs[buf_index].iov_len - offset)
    {
      errno = EINVAL;
      SOCKET_ERROR_MSG ("Offset + len exceeds buffer size");
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }

  fd = Socket_fd (socket);
  buf_ptr = (char *)async->registered_bufs[buf_index].iov_base + offset;

  /* Set up request with fixed buffer flag */
  req = setup_async_request (async, socket, cb, user_data, REQ_RECV, NULL,
                             buf_ptr, len, flags | ASYNC_FLAG_FIXED_BUFFER);

  pthread_mutex_lock (&async->mutex);
  req->request_id = generate_request_id_unlocked (async);

  /* Insert into hash table */
  unsigned hash = request_hash (req->request_id);
  req->next = async->requests[hash];
  async->requests[hash] = req;
  req->submitted_at = Socket_get_monotonic_ms ();

  /* Submit fixed buffer operation */
  sqe = io_uring_get_sqe (async->ring);
  if (!sqe)
    {
      /* Try flushing pending operations */
      if (async->pending_sqe_count > 0)
        flush_io_uring_unlocked (async);
      sqe = io_uring_get_sqe (async->ring);
    }

  if (!sqe)
    {
      remove_request_unlocked (async, req);
      pthread_mutex_unlock (&async->mutex);
      socket_async_free_request (async, req);
      errno = EAGAIN;
      return 0;
    }

  io_uring_prep_read_fixed (sqe, fd, buf_ptr, len, 0, buf_index);
  sqe->user_data = (uintptr_t)req->request_id;

  request_id = req->request_id;

  /* Submit immediately for fixed buffer ops */
  io_uring_submit (async->ring);

  pthread_mutex_unlock (&async->mutex);

  return request_id;
#else
  (void)async;
  (void)socket;
  (void)buf_index;
  (void)offset;
  (void)len;
  (void)cb;
  (void)user_data;
  (void)flags;
  errno = ENOTSUP;
  RAISE_MODULE_ERROR (SocketAsync_Failed);
  return 0;
#endif
}


/* ==================== Fixed Files Implementation ==================== */

int
SocketAsync_register_files (T async, int *fds, unsigned count)
{
#if SOCKET_HAS_IO_URING
  int *fd_copy;
  int ret;

  if (!async || !async->ring || !fds || count == 0)
    {
      errno = EINVAL;
      return -1;
    }

  /* Unregister any existing files first */
  if (async->registered_fd_count > 0)
    {
      io_uring_unregister_files (async->ring);
      async->registered_fd_count = 0;
      async->registered_fds = NULL;
    }

  /* Allocate fd array copy from arena */
  fd_copy = CALLOC (async->arena, count, sizeof (int));
  if (!fd_copy)
    {
      errno = ENOMEM;
      return -1;
    }

  /* Copy fd array */
  memcpy (fd_copy, fds, count * sizeof (int));

  pthread_mutex_lock (&async->mutex);
  ret = io_uring_register_files (async->ring, fds, count);
  if (ret == 0)
    {
      async->registered_fds = fd_copy;
      async->registered_fd_count = count;
    }
  pthread_mutex_unlock (&async->mutex);

  if (ret < 0)
    {
      errno = -ret;
      return -1;
    }

  return 0;
#else
  (void)async;
  (void)fds;
  (void)count;
  errno = ENOTSUP;
  return -1;
#endif
}

int
SocketAsync_unregister_files (T async)
{
#if SOCKET_HAS_IO_URING
  int ret;

  if (!async || !async->ring)
    {
      errno = EINVAL;
      return -1;
    }

  if (async->registered_fd_count == 0)
    return 0;

  pthread_mutex_lock (&async->mutex);
  ret = io_uring_unregister_files (async->ring);
  async->registered_fd_count = 0;
  async->registered_fds = NULL;
  pthread_mutex_unlock (&async->mutex);

  if (ret < 0)
    {
      errno = -ret;
      return -1;
    }

  return 0;
#else
  (void)async;
  errno = ENOTSUP;
  return -1;
#endif
}

int
SocketAsync_update_registered_fd (T async, unsigned index, int new_fd)
{
#if SOCKET_HAS_IO_URING
  int ret;

  if (!async || !async->ring)
    {
      errno = EINVAL;
      return -1;
    }

  if (index >= async->registered_fd_count)
    {
      errno = EINVAL;
      return -1;
    }

  pthread_mutex_lock (&async->mutex);
  ret = io_uring_register_files_update (async->ring, index, &new_fd, 1);
  if (ret >= 0)
    async->registered_fds[index] = new_fd;
  pthread_mutex_unlock (&async->mutex);

  if (ret < 0)
    {
      errno = -ret;
      return -1;
    }

  return 0;
#else
  (void)async;
  (void)index;
  (void)new_fd;
  errno = ENOTSUP;
  return -1;
#endif
}

int
SocketAsync_get_fixed_fd_index (const T async, int fd)
{
#if SOCKET_HAS_IO_URING
  if (!async || async->registered_fd_count == 0)
    return -1;

  for (unsigned i = 0; i < async->registered_fd_count; i++)
    {
      if (async->registered_fds[i] == fd)
        return (int)i;
    }

  return -1;
#else
  (void)async;
  (void)fd;
  return -1;
#endif
}

unsigned
SocketAsync_registered_file_count (const T async)
{
#if SOCKET_HAS_IO_URING
  if (!async)
    return 0;
  return async->registered_fd_count;
#else
  (void)async;
  return 0;
#endif
}

#undef T

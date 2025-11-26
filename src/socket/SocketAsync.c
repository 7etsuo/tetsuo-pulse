/**
 * SocketAsync.c - Asynchronous I/O core
 *
 * Core asynchronous I/O context management and request tracking for socket
 * operations. Provides the foundation for platform-specific async backends
 * with thread-safe request management and completion handling.
 *
 * Features:
 * - Async context lifecycle management (new/free)
 * - Request ID generation and tracking
 * - Hash table-based request lookup
 * - Completion callback handling
 * - Thread-safe operations
 * - Memory management using Arena allocation
 * - Automatic backend detection (io_uring, kqueue, fallback)
 *
 * Merged from:
 * - SocketAsync.c (core context management)
 * - SocketAsync-request.c (request lifecycle)
 * - SocketAsync-backend.c (backend detection)
 * - SocketAsync-iouring.c (Linux io_uring backend)
 * - SocketAsync-kqueue.c (BSD/macOS kqueue backend)
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
#include "socket/SocketIO.h" /* For TLS-aware I/O functions */
#define SOCKET_LOG_COMPONENT "SocketAsync"
#include "core/SocketUtil.h"

#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLS.h" /* For TLS exception types */
#endif

#define T SocketAsync_T

/* Request type enumeration */
enum AsyncRequestType
{
  REQ_SEND,
  REQ_RECV
};

/* Request tracking structure */
struct AsyncRequest
{
  unsigned request_id;
  Socket_T socket;
  SocketAsync_Callback cb;
  void *user_data;
  enum AsyncRequestType type;
  const void *send_buf; /* For send: data to send */
  void *recv_buf;       /* For recv: user's buffer (must remain valid) */
  size_t len;           /* Original length */
  size_t completed;     /* Bytes completed so far */
  SocketAsync_Flags flags;
  struct AsyncRequest *next; /* Hash table chain */
  time_t submitted_at;       /* For timeout tracking */
};

/* Async context structure */
struct T
{
  Arena_T arena;

  /* Request tracking */
  struct AsyncRequest *requests[SOCKET_HASH_TABLE_SIZE];
  unsigned next_request_id;
  pthread_mutex_t mutex;

  /* Platform-specific async context */
#ifdef SOCKET_HAS_IO_URING
  struct io_uring *ring; /* io_uring ring (if available) */
  int io_uring_fd;       /* Eventfd for completion notifications */
#elif defined(__APPLE__) || defined(__FreeBSD__)
  int kqueue_fd; /* kqueue fd for AIO */
#else
  /* Fallback: edge-triggered polling */
  int fallback_mode;
#endif

  int available; /* Non-zero if async available */
  const char *backend_name;
};

/* Exception */
const Except_T SocketAsync_Failed
    = { &SocketAsync_Failed, "SocketAsync operation failed" };

/* Thread-local exception for detailed error messages */
/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketAsync);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketAsync, e)

/* ==================== Request Management ==================== */
/* Merged from SocketAsync-request.c */

/**
 * request_hash - Hash function for request IDs
 * @request_id: Request ID to hash
 * Returns: Hash value in range [0, SOCKET_HASH_TABLE_SIZE)
 *
 * Uses socket_util_hash_uint() for golden ratio multiplicative hashing.
 */
static unsigned
request_hash (unsigned request_id)
{
  return socket_util_hash_uint (request_id, SOCKET_HASH_TABLE_SIZE);
}

/**
 * generate_request_id - Generate unique request ID
 * @async: Async context
 * Returns: Unique request ID (> 0)
 * Thread-safe: Yes - uses mutex
 */
static unsigned
generate_request_id (T async)
{
  unsigned id;

  assert (async);

  pthread_mutex_lock (&async->mutex);
  id = async->next_request_id++;
  if (id == 0)
    id = async->next_request_id++; /* Skip 0 (invalid) */
  pthread_mutex_unlock (&async->mutex);

  return id;
}

/**
 * socket_async_allocate_request - Allocate async request structure
 * @async: Async context
 * Returns: Allocated request or NULL on allocation failure
 * Raises: SocketAsync_Failed on allocation failure
 */
static struct AsyncRequest *
socket_async_allocate_request (T async)
{
  struct AsyncRequest *volatile volatile_req = NULL;

  assert (async);

  TRY { volatile_req = ALLOC (async->arena, sizeof (struct AsyncRequest)); }
  EXCEPT (Arena_Failed)
  {
    SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate async request");
    RAISE_MODULE_ERROR (SocketAsync_Failed);
  }
  END_TRY;

  memset ((struct AsyncRequest *)volatile_req, 0, sizeof (struct AsyncRequest));
  return (struct AsyncRequest *)volatile_req;
}

/**
 * socket_async_free_request - Free async request structure
 * @async: Async context
 * @req: Request to free
 * Note: Request is allocated from arena, so no explicit free needed
 * but we clear it for safety
 */
static void
socket_async_free_request (T async, struct AsyncRequest *req)
{
  (void)async;
  if (req)
    {
      memset (req, 0, sizeof (*req));
    }
}

/**
 * handle_completion - Handle async operation completion
 * @async: Async context
 * @request_id: Request ID that completed
 * @result: Result (bytes transferred, or negative on error)
 * @err: Error code (0 on success)
 * Thread-safe: Yes - uses mutex for request lookup
 */
static void
handle_completion (T async, unsigned request_id, ssize_t result, int err)
{
  struct AsyncRequest *req;
  unsigned hash = request_hash (request_id);

  assert (async);

  pthread_mutex_lock (&async->mutex);

  /* Find request */
  req = async->requests[hash];
  while (req && req->request_id != request_id)
    {
      req = req->next;
    }

  if (!req)
    {
      pthread_mutex_unlock (&async->mutex);
      return; /* Request not found (already cancelled?) */
    }

  /* Remove from hash table */
  struct AsyncRequest **pp = &async->requests[hash];
  while (*pp != req)
    {
      pp = &(*pp)->next;
    }
  *pp = req->next;

  /* Extract callback and user_data before unlocking */
  SocketAsync_Callback cb = req->cb;
  Socket_T socket = req->socket;
  void *user_data = req->user_data;

  pthread_mutex_unlock (&async->mutex);

  /* Invoke callback */
  if (cb)
    {
      cb (socket, result, err, user_data);
    }

  /* Free request */
  socket_async_free_request (async, req);
}

/**
 * setup_async_request - Initialize async request structure
 * @async: Async context
 * @socket: Socket for operation
 * @cb: Completion callback
 * @user_data: User data for callback
 * @type: Request type (REQ_SEND or REQ_RECV)
 * @send_buf: Buffer for send operations (NULL for recv)
 * @recv_buf: Buffer for recv operations (NULL for send)
 * @len: Buffer length
 * @flags: Operation flags
 * Returns: Initialized request or NULL on allocation failure
 * Thread-safe: No (caller handles allocation)
 */
static struct AsyncRequest *
setup_async_request (T async, Socket_T socket, SocketAsync_Callback cb,
                     void *user_data, enum AsyncRequestType type,
                     const void *send_buf, void *recv_buf, size_t len,
                     SocketAsync_Flags flags)
{
  struct AsyncRequest *req = socket_async_allocate_request (async);
  if (!req)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate async request");
      return NULL;
    }

  req->socket = socket;
  req->cb = cb;
  req->user_data = user_data;
  req->type = type;
  req->send_buf = send_buf;
  req->recv_buf = recv_buf;
  req->len = len;
  req->completed = 0;
  req->flags = flags;
  req->submitted_at = time (NULL);

  return req;
}

/**
 * cleanup_failed_request - Clean up failed request submission
 * @async: Async context
 * @req: Request that failed
 * @hash: Hash value for request ID
 * Thread-safe: Yes (handles mutex locking)
 */
static void
cleanup_failed_request (T async, struct AsyncRequest *req, unsigned hash)
{
  pthread_mutex_lock (&async->mutex);
  struct AsyncRequest **pp = &async->requests[hash];
  while (*pp != req)
    {
      pp = &(*pp)->next;
    }
  *pp = req->next;
  pthread_mutex_unlock (&async->mutex);

  socket_async_free_request (async, req);
}

/* Forward declaration for backend-specific submit */
static int submit_async_operation (T async, struct AsyncRequest *req);

/**
 * submit_and_track_request - Submit request and track in hash table
 * @async: Async context
 * @req: Request to submit and track
 * Returns: Request ID on success, 0 on failure
 * Thread-safe: Yes (handles mutex locking)
 */
static unsigned
submit_and_track_request (T async, struct AsyncRequest *req)
{
  int result;
  unsigned hash;

  pthread_mutex_lock (&async->mutex);

  /* Generate request ID */
  req->request_id = generate_request_id (async);

  /* Insert into hash table */
  hash = request_hash (req->request_id);
  req->next = async->requests[hash];
  async->requests[hash] = req;

  pthread_mutex_unlock (&async->mutex);

  /* Submit to backend */
  result = async->available ? submit_async_operation (async, req) : 0;

  if (result < 0)
    {
      /* Remove from hash table on failure */
      cleanup_failed_request (async, req, hash);
      return 0;
    }

  return req->request_id;
}

/* ==================== io_uring Backend ==================== */
/* Merged from SocketAsync-iouring.c */

#ifdef SOCKET_HAS_IO_URING

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

    /* Handle completion */
    handle_completion (async, request_id, result, err);

    count++;
  }

  /* Mark completions as seen */
  io_uring_cq_advance (async->ring, count);

  return count;
}

#endif /* SOCKET_HAS_IO_URING */

/* ==================== kqueue Backend ==================== */
/* Merged from SocketAsync-kqueue.c */

#if defined(__APPLE__) || defined(__FreeBSD__)

/**
 * submit_kqueue_aio - Submit operation via kqueue (edge-triggered mode)
 * @async: Async context
 * @req: Request structure
 * Returns: 0 on success, -1 on failure
 *
 * Note: macOS/BSD don't have true AIO like io_uring. This implementation
 * uses edge-triggered kqueue events. The actual I/O is performed when
 * the event fires, then the callback is invoked.
 */
static int
submit_kqueue_aio (T async, struct AsyncRequest *req)
{
  struct kevent kev;
  int fd = Socket_fd (req->socket);

  assert (async);
  assert (async->kqueue_fd >= 0);
  assert (req);

  /* Use kqueue to monitor socket for readiness */
  /* For send: monitor POLLOUT */
  /* For recv: monitor POLLIN */
  if (req->type == REQ_SEND)
    {
      EV_SET (&kev, fd, EVFILT_WRITE, EV_ADD | EV_ENABLE | EV_ONESHOT, 0, 0,
              (void *)(uintptr_t)req->request_id);
    }
  else
    {
      EV_SET (&kev, fd, EVFILT_READ, EV_ADD | EV_ENABLE | EV_ONESHOT, 0, 0,
              (void *)(uintptr_t)req->request_id);
    }

  if (kevent (async->kqueue_fd, &kev, 1, NULL, 0, NULL) < 0)
    {
      return -1;
    }

  return 0;
}

/**
 * kqueue_find_request - Find and remove request from hash table
 * @async: Async context
 * @request_id: Request ID to find
 *
 * Returns: Request pointer or NULL if not found
 * Thread-safe: Yes - caller must not hold mutex
 *
 * Note: Removes request from hash table before returning
 */
static struct AsyncRequest *
kqueue_find_request (T async, unsigned request_id)
{
  unsigned hash = request_hash (request_id);
  struct AsyncRequest *req;

  pthread_mutex_lock (&async->mutex);

  req = async->requests[hash];
  while (req && req->request_id != request_id)
    req = req->next;

  if (!req)
    {
      pthread_mutex_unlock (&async->mutex);
      return NULL;
    }

  /* Remove from hash table */
  struct AsyncRequest **pp = &async->requests[hash];
  while (*pp != req)
    pp = &(*pp)->next;
  *pp = req->next;

  pthread_mutex_unlock (&async->mutex);
  return req;
}

/**
 * kqueue_perform_io - Perform I/O operation for kqueue completion
 * @req: Request with operation details
 * @result: Output for bytes transferred
 * @err: Output for error code
 *
 * Thread-safe: Yes (operates on single socket)
 */
static void
kqueue_perform_io (struct AsyncRequest *req, ssize_t *result, int *err)
{
  *result = 0;
  *err = 0;

  TRY
  {
    if (req->type == REQ_SEND)
      {
        *result = socket_send_internal (req->socket, req->send_buf, req->len,
                                        MSG_NOSIGNAL);
        if (*result == 0)
          {
            *err = EAGAIN;
            *result = -1;
          }
      }
    else
      {
        *result = socket_recv_internal (req->socket, req->recv_buf, req->len, 0);
        if (*result == 0)
          {
            *err = EAGAIN;
            *result = -1;
          }
      }
  }
  EXCEPT (Socket_Closed)
  {
    *err = ECONNRESET;
    *result = -1;
  }
  EXCEPT (Socket_Failed)
  {
    *err = errno ? errno : EPROTO;
    *result = -1;
  }
#ifdef SOCKET_HAS_TLS
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    *err = EAGAIN;
    *result = -1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    *err = errno ? errno : EPROTO;
    *result = -1;
  }
#endif
  END_TRY;
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

  if (req->cb)
    req->cb (req->socket, result, err, req->user_data);

  socket_async_free_request (async, req);
}

/**
 * process_kqueue_completions - Process kqueue events and perform I/O
 * @async: Async context
 * @timeout_ms: Timeout in milliseconds
 * @max_completions: Maximum completions to process
 *
 * Returns: Number of completions processed
 * Thread-safe: Yes
 */
static int
process_kqueue_completions (T async, int timeout_ms, int max_completions)
{
  struct kevent events[SOCKET_MAX_EVENT_BATCH];
  struct timespec timeout;
  int n, count = 0;

  assert (async);
  assert (async->kqueue_fd >= 0);

  if (max_completions > SOCKET_MAX_EVENT_BATCH)
    max_completions = SOCKET_MAX_EVENT_BATCH;

  timeout.tv_sec = timeout_ms / SOCKET_MS_PER_SECOND;
  timeout.tv_nsec = (timeout_ms % SOCKET_MS_PER_SECOND) * SOCKET_NS_PER_MS;

  n = kevent (async->kqueue_fd, NULL, 0, events, max_completions, &timeout);
  if (n < 0)
    return (errno == EINTR) ? 0 : -1;

  for (int i = 0; i < n; i++)
    {
      unsigned request_id = (unsigned)(uintptr_t)events[i].udata;
      struct AsyncRequest *req = kqueue_find_request (async, request_id);

      if (req)
        {
          kqueue_complete_request (async, req);
          count++;
        }
    }

  return count;
}

#endif /* __APPLE__ || __FreeBSD__ */

/* ==================== Backend Detection ==================== */
/* Merged from SocketAsync-backend.c */

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

/**
 * submit_async_operation - Submit async operation to appropriate backend
 * @async: Async context
 * @req: Request to submit
 * Returns: 0 on success, -1 on failure
 */
static int
submit_async_operation (T async, struct AsyncRequest *req)
{
  assert (async);
  assert (req);

#ifdef SOCKET_HAS_IO_URING
  if (async->ring)
    {
      return (req->type == REQ_SEND) ? submit_io_uring_send (async, req)
                                     : submit_io_uring_recv (async, req);
    }
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
  if (async->kqueue_fd >= 0)
    {
      return submit_kqueue_aio (async, req);
    }
#endif

  /* No backend available - suppress unused warnings */
  (void)async;
  (void)req;
  errno = ENOTSUP;
  return -1;
}

/**
 * process_async_completions - Process completions from appropriate backend
 * @async: Async context
 * @timeout_ms: Timeout in milliseconds
 * Returns: Number of completions processed
 */
static int
process_async_completions_internal (T async,
                                    int timeout_ms __attribute__ ((unused)))
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
          return process_io_uring_completions (async, SOCKET_MAX_EVENT_BATCH);
        }
      return 0;
    }
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
  if (async->kqueue_fd >= 0)
    {
      /* Process kqueue AIO events */
      return process_kqueue_completions (async, timeout_ms,
                                         SOCKET_MAX_EVENT_BATCH);
    }
#endif

  return 0;
}

/**
 * SocketAsync_initialize_backend - Initialize async backend
 * @async: Async context
 */
static void
SocketAsync_initialize_backend (T async)
{
  assert (async);
  detect_async_backend (async);
}

/* ==================== Public API ==================== */

T
SocketAsync_new (Arena_T arena)
{
  volatile T volatile_async = NULL;

  assert (arena);

  TRY { volatile_async = ALLOC (arena, sizeof (*volatile_async)); }
  EXCEPT (Arena_Failed)
  {
    SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate async context");
    RAISE_MODULE_ERROR (SocketAsync_Failed);
  }
  END_TRY;

  T async = (T)volatile_async;

  memset (async, 0, sizeof (*async));
  async->arena = arena;
  async->next_request_id = 1; /* Start at 1, 0 = invalid */

  if (pthread_mutex_init (&async->mutex, NULL) != 0)
    {
      SOCKET_ERROR_MSG ("Failed to initialize async mutex");
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }

  /* Detect and initialize backend */
  SocketAsync_initialize_backend (async);

  return async;
}

void
SocketAsync_free (T *async)
{
  if (!async || !*async)
    return;

#ifdef SOCKET_HAS_IO_URING
  if ((*async)->ring)
    {
      if ((*async)->io_uring_fd >= 0)
        close ((*async)->io_uring_fd);
      io_uring_queue_exit ((*async)->ring);
      free ((*async)->ring);
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
  struct AsyncRequest *req;
  unsigned request_id;

  assert (async);
  assert (socket);
  assert (buf);
  assert (len > 0);
  assert (cb);

  req = setup_async_request (async, socket, cb, user_data, REQ_SEND, buf, NULL,
                             len, flags);
  if (!req)
    RAISE_MODULE_ERROR (SocketAsync_Failed);

  request_id = submit_and_track_request (async, req);
  if (request_id == 0)
    {
      SOCKET_ERROR_FMT ("Failed to submit async send (errno=%d)", errno);
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }

  return request_id;
}

unsigned
SocketAsync_recv (T async, Socket_T socket, void *buf, size_t len,
                  SocketAsync_Callback cb, void *user_data,
                  SocketAsync_Flags flags)
{
  struct AsyncRequest *req;
  unsigned request_id;

  assert (async);
  assert (socket);
  assert (buf);
  assert (len > 0);
  assert (cb);

  req = setup_async_request (async, socket, cb, user_data, REQ_RECV, NULL, buf,
                             len, flags);
  if (!req)
    RAISE_MODULE_ERROR (SocketAsync_Failed);

  request_id = submit_and_track_request (async, req);
  if (request_id == 0)
    {
      SOCKET_ERROR_FMT ("Failed to submit async recv (errno=%d)", errno);
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }

  return request_id;
}

int
SocketAsync_cancel (T async, unsigned request_id)
{
  struct AsyncRequest *req;
  unsigned hash = request_hash (request_id);
  int cancelled = 0;

  assert (async);

  pthread_mutex_lock (&async->mutex);

  /* Find request */
  req = async->requests[hash];
  while (req && req->request_id != request_id)
    {
      req = req->next;
    }

  if (req)
    {
      /* Remove from hash table */
      struct AsyncRequest **pp = &async->requests[hash];
      while (*pp != req)
        {
          pp = &(*pp)->next;
        }
      *pp = req->next;

      cancelled = 1;
    }

  pthread_mutex_unlock (&async->mutex);

  if (cancelled)
    {
      /* Try to cancel in kernel (best effort) */
      /* Cancellation logic will be in backend files */

      socket_async_free_request (async, req);
      return 0;
    }

  return -1; /* Request not found or already completed */
}

int
SocketAsync_process_completions (T async, int timeout_ms)
{
  return process_async_completions_internal (async, timeout_ms);
}

#undef T

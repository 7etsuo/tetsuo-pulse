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
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>

#include <string.h>

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
#include "socket/SocketIO.h"
#define SOCKET_LOG_COMPONENT "SocketAsync"
#include "core/SocketUtil.h"

#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#endif

#define T SocketAsync_T

/* Test ring entries for io_uring availability check */
#ifndef SOCKET_IO_URING_TEST_ENTRIES
#define SOCKET_IO_URING_TEST_ENTRIES 32
#endif

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
  const void *send_buf;
  void *recv_buf;
  size_t len;
  SocketAsync_Flags flags;
  struct AsyncRequest *next;
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
  struct io_uring *ring;
  int io_uring_fd;
#elif defined(__APPLE__) || defined(__FreeBSD__)
  int kqueue_fd;
#else
  int fallback_mode;
#endif

  int available;
  const char *backend_name;
};

/* Exception */
const Except_T SocketAsync_Failed
    = { &SocketAsync_Failed, "SocketAsync operation failed" };

/* Thread-local exception for detailed error messages */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketAsync);

#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketAsync, e)

/* ==================== Static Helper Functions ==================== */

/**
 * request_hash - Hash function for request IDs
 * @request_id: Request ID to hash
 *
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
 * generate_request_id_unlocked - Generate unique request ID
 * @async: Async context
 *
 * Returns: Unique request ID (> 0)
 * Thread-safe: No - caller must hold async->mutex
 *
 * Note: Request ID 0 is reserved as invalid. When unsigned wraps from
 * UINT_MAX to 0, we skip to 1.
 */
static unsigned
generate_request_id_unlocked (T async)
{
  unsigned id;

  assert (async);

  id = async->next_request_id++;
  /* LCOV_EXCL_START - Wrap from UINT_MAX to 0 is rare */
  if (id == 0)
    id = async->next_request_id++;
  /* LCOV_EXCL_STOP */

  return id;
}




/**
 * socket_async_allocate_request - Allocate async request structure
 * @async: Async context
 *
 * Returns: Allocated and zeroed request
 * Raises: SocketAsync_Failed on allocation failure
 */
static struct AsyncRequest *
socket_async_allocate_request (T async)
{
  struct AsyncRequest *volatile req = NULL;

  assert (async);

  TRY
  {
    req = CALLOC (async->arena, 1, sizeof (struct AsyncRequest));
  }
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

/**
 * socket_async_free_request - Clear async request structure
 * @async: Async context (unused, arena manages memory)
 * @req: Request to clear
 *
 * Note: Request is allocated from arena, so no explicit free needed.
 * We clear it for safety to prevent use-after-free bugs.
 */
static void
socket_async_free_request (T async, struct AsyncRequest *req)
{
  (void)async;
  if (req)
    memset (req, 0, sizeof (*req));
}

static int
find_and_remove_request (T async, unsigned request_id,
                         struct AsyncRequest **out_req,
                         SocketAsync_Callback *out_cb,
                         Socket_T *out_socket,
                         void **out_user_data);

static void
remove_known_request (T async, struct AsyncRequest *req);

/**
 * handle_completion - Handle async operation completion
 * @async: Async context
 * @request_id: Request ID that completed
 * @result: Result (bytes transferred, or negative on error)
 * @err: Error code (0 on success)
 *
 * Thread-safe: Yes - delegates to find_and_remove_request for mutex handling
 */
static void
handle_completion (T async, unsigned request_id, ssize_t result, int err)
{
  struct AsyncRequest *req;
  SocketAsync_Callback cb;
  Socket_T socket;
  void *user_data;

  if (!find_and_remove_request (async, request_id, &req, &cb, &socket, &user_data))
    return;

  if (cb)
    cb (socket, result, err, user_data);

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
 *
 * Returns: Initialized request (never NULL - raises on failure)
 * Raises: SocketAsync_Failed on allocation failure
 */
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

  return req;
}

/**
 * cleanup_failed_request - Clean up failed request submission
 * @async: Async context
 * @req: Request that failed
 *
 * Thread-safe: Yes - delegates to remove_known_request
 *
 * Note: Only reachable when submit_async_operation() returns < 0,
 * which requires async->available = 1 (io_uring/kqueue backend).
 */
/* LCOV_EXCL_START - Only reachable with io_uring/kqueue backend */
static void
cleanup_failed_request (T async, struct AsyncRequest *req)
{
  remove_known_request (async, req);
  socket_async_free_request (async, req);
}
/* LCOV_EXCL_STOP */

/**
 * find_and_remove_request - Find request by ID, remove from hash table, extract info
 * @async: Async context
 * @request_id: ID of request to find and remove
 * @out_req: Output: removed request pointer (always set if found)
 * @out_cb: Output: callback function (set if not NULL and found)
 * @out_socket: Output: socket (set if not NULL and found)
 * @out_user_data: Output: user data (set if not NULL and found)
 *
 * Returns: 1 if found and removed, 0 otherwise
 * Thread-safe: Yes (acquires/releases mutex)
 * 
 * Extracts callback info under lock for safety, minimizes lock hold time.
 * Outputs initialized to NULL/0 if not found or param NULL.
 */
static int
find_and_remove_request (T async, unsigned request_id,
                         struct AsyncRequest **out_req,
                         SocketAsync_Callback *out_cb,
                         Socket_T *out_socket,
                         void **out_user_data)
{
  unsigned hash;
  struct AsyncRequest *req;
  struct AsyncRequest **pp;
  int found = 0;

  assert (async);

  *out_req = NULL;
  if (out_cb) *out_cb = NULL;
  if (out_socket) *out_socket = NULL;
  if (out_user_data) *out_user_data = NULL;

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
      if (out_cb) *out_cb = req->cb;
      if (out_socket) *out_socket = req->socket;
      if (out_user_data) *out_user_data = req->user_data;
      *out_req = req;
      *pp = req->next;
    }
  pthread_mutex_unlock (&async->mutex);

  return found;
}

/**
 * remove_known_request - Remove known request from hash table
 * @async: Async context
 * @req: Request pointer to remove (validated != NULL)
 *
 * Thread-safe: Yes (acquires/releases mutex)
 * 
 * Traverses hash chain to find and unlink the specific req pointer.
 * Safe to call even if req already removed (no-op).
 */
static void
remove_known_request (T async, struct AsyncRequest *req)
{
  unsigned hash;
  struct AsyncRequest **pp;

  if (!req || !async) return;

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

/* Forward declaration for backend-specific submit */
static int submit_async_operation (T async, struct AsyncRequest *req);

/**
 * submit_and_track_request - Submit request and track in hash table
 * @async: Async context
 * @req: Request to submit and track
 *
 * Returns: Request ID on success, 0 on failure
 * Thread-safe: Yes (handles mutex locking)
 */
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

  pthread_mutex_unlock (&async->mutex);

  result = async->available ? submit_async_operation (async, req) : 0;

  /* LCOV_EXCL_START - Only fails with io_uring/kqueue backend */
  if (result < 0)
    {
      cleanup_failed_request (async, req);
      return 0;
    }
  /* LCOV_EXCL_STOP */

  return req->request_id;
}

/* ==================== io_uring Backend ==================== */

#ifdef SOCKET_HAS_IO_URING

/**
 * submit_io_uring_op - Submit operation via io_uring
 * @async: Async context
 * @req: Request structure
 *
 * Returns: 0 on success, -1 on failure
 *
 * Unified submission for both send and recv operations.
 */
static int
submit_io_uring_op (T async, struct AsyncRequest *req)
{
  struct io_uring_sqe *sqe;
  int fd = Socket_fd (req->socket);
  int submitted;
  uint64_t val = 1;

  assert (async && async->ring && req);

  sqe = io_uring_get_sqe (async->ring);
  if (!sqe)
    {
      errno = EAGAIN;
      return -1;
    }

  /* Prepare operation based on type */
  if (req->type == REQ_SEND)
    io_uring_prep_send (sqe, fd, req->send_buf, req->len, 0);
  else
    io_uring_prep_recv (sqe, fd, req->recv_buf, req->len, 0);

  sqe->user_data = (uintptr_t)req->request_id;

  if (req->flags & ASYNC_FLAG_URGENT)
    sqe->flags |= IOSQE_IO_LINK;

  submitted = io_uring_submit (async->ring);
  if (submitted < 0)
    return -1;

  /* Notify via eventfd */
  (void)write (async->io_uring_fd, &val, sizeof (val));

  return 0;
}

/**
 * process_io_uring_completions - Process io_uring completion queue
 * @async: Async context
 * @max_completions: Maximum completions to process
 *
 * Returns: Number of completions processed
 */
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

/* ==================== kqueue Backend ==================== */

#if defined(__APPLE__) || defined(__FreeBSD__)

/**
 * submit_kqueue_aio - Submit operation via kqueue (edge-triggered mode)
 * @async: Async context
 * @req: Request structure
 *
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
  int16_t filter;

  assert (async && async->kqueue_fd >= 0 && req);

  filter = (req->type == REQ_SEND) ? EVFILT_WRITE : EVFILT_READ;
  EV_SET (&kev, fd, filter, EV_ADD | EV_ENABLE | EV_ONESHOT, 0, 0,
          (void *)(uintptr_t)req->request_id);

  if (kevent (async->kqueue_fd, &kev, 1, NULL, 0, NULL) < 0)
    return -1;

  return 0;
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

  assert (async && async->kqueue_fd >= 0);

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

/* ==================== Backend Detection ==================== */

/**
 * detect_async_backend - Detect and initialize platform-specific async backend
 * @async: Async context to initialize
 *
 * Returns: Non-zero if async available, 0 if fallback mode
 */
static int
detect_async_backend (T async)
{
  assert (async);

#ifdef SOCKET_HAS_IO_URING
  /* Try io_uring */
  struct io_uring test_ring;
  if (io_uring_queue_init (SOCKET_IO_URING_TEST_ENTRIES, &test_ring, 0) == 0)
    {
      io_uring_queue_exit (&test_ring);

      async->ring = Arena_calloc (async->arena, 1, sizeof (struct io_uring));
      if (!async->ring)
        {
          async->backend_name = "io_uring (allocation failed)";
          return 0;
        }

      if (io_uring_queue_init (SOCKET_DEFAULT_IO_URING_ENTRIES, async->ring, 0)
          == 0)
        {
          async->io_uring_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
          if (async->io_uring_fd >= 0)
            {
              async->available = 1;
              async->backend_name = "io_uring";
              return 1;
            }
          io_uring_queue_exit (async->ring);
          async->ring = NULL;
        }
      else
        {
          async->ring = NULL;
        }
    }

  async->available = 0;
  async->backend_name = "unavailable (io_uring unavailable)";
  return 0;

#elif defined(__APPLE__) || defined(__FreeBSD__)
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

#else
  async->available = 0;
  async->backend_name = "unavailable (platform not supported)";
  return 0;
#endif
}

/**
 * submit_async_operation - Submit async operation to appropriate backend
 * @async: Async context
 * @req: Request to submit
 *
 * Returns: 0 on success, -1 on failure
 *
 * Note: Only called when async->available = 1 (io_uring/kqueue backend).
 */
/* LCOV_EXCL_START - Only called with io_uring/kqueue backend */
static int
submit_async_operation (T async, struct AsyncRequest *req)
{
  assert (async && req);

#ifdef SOCKET_HAS_IO_URING
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

/**
 * process_async_completions_internal - Process completions from backend
 * @async: Async context
 * @timeout_ms: Timeout in milliseconds
 *
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
      uint64_t val;
      ssize_t n = read (async->io_uring_fd, &val, sizeof (val));
      if (n > 0)
        return process_io_uring_completions (async, SOCKET_MAX_EVENT_BATCH);
      return 0;
    }
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
  if (async->kqueue_fd >= 0)
    return process_kqueue_completions (async, timeout_ms,
                                       SOCKET_MAX_EVENT_BATCH);
#endif

  return 0;
}

/**
 * socket_async_submit - Common submit logic for send/recv requests
 * @async: Async context
 * @socket: Target socket
 * @type: REQ_SEND or REQ_RECV
 * @send_buf: Buffer for send (NULL for recv)
 * @recv_buf: Buffer for recv (NULL for send)
 * @len: Buffer length
 * @cb: Completion callback (required)
 * @user_data: User data for callback
 * @flags: Operation flags
 *
 * Returns: Request ID on success, raises on failure
 * Thread-safe: Yes
 * 
 * Validates parameters, sets up request, tracks in hash, submits to backend.
 * Used by public SocketAsync_send/recv.
 */
static unsigned
socket_async_submit (T async, Socket_T socket, enum AsyncRequestType type,
                     const void *send_buf, void *recv_buf, size_t len,
                     SocketAsync_Callback cb, void *user_data,
                     SocketAsync_Flags flags)
{
  struct AsyncRequest *req;
  unsigned request_id;

  /* Validate parameters */
  if (!async || !socket || !cb || len == 0)
    {
      errno = EINVAL;
      SOCKET_ERROR_MSG ("Invalid parameters for async submit");
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }
  if (type == REQ_SEND && !send_buf)
    {
      errno = EINVAL;
      SOCKET_ERROR_MSG ("Send buffer required for REQ_SEND");
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }
  if (type == REQ_RECV && !recv_buf)
    {
      errno = EINVAL;
      SOCKET_ERROR_MSG ("Recv buffer required for REQ_RECV");
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }

  req = setup_async_request (async, socket, cb, user_data, type,
                             send_buf, recv_buf, len, flags);

  request_id = submit_and_track_request (async, req);
  if (request_id == 0)
    {
      const char *op = (type == REQ_SEND) ? "send" : "recv";
      SOCKET_ERROR_FMT ("Failed to submit async %s (errno=%d)", op, errno);
      RAISE_MODULE_ERROR (SocketAsync_Failed);
    }

  return request_id;
}

/* ==================== Public API ==================== */

T
SocketAsync_new (Arena_T arena)
{
  volatile T async = NULL;

  assert (arena);

  TRY
  {
    async = CALLOC (arena, 1, sizeof (*async));
  }
  EXCEPT (Arena_Failed)
  {
    /* LCOV_EXCL_START */
    SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate async context");
    RAISE_MODULE_ERROR (SocketAsync_Failed);
    /* LCOV_EXCL_STOP */
  }
  END_TRY;

  ((T)async)->arena = arena;
  ((T)async)->next_request_id = 1; /* 0 = invalid */

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

/**
 * SocketAsync_send - Submit asynchronous send operation
 * @async: Async context
 * @socket: Target socket
 * @buf: Data buffer to send
 * @len: Length of data
 * @cb: Completion callback (required)
 * @user_data: User data passed to callback
 * @flags: Operation flags (e.g. ASYNC_FLAG_URGENT)
 *
 * Returns: Unique request ID on success, raises SocketAsync_Failed on error
 * Thread-safe: Yes
 *
 * Submits non-blocking send operation to backend. Callback invoked on completion
 * with bytes sent (or negative error). Use SocketAsync_cancel to cancel pending.
 * Raises if no async backend available or submit fails.
 */
unsigned
SocketAsync_send (T async, Socket_T socket, const void *buf, size_t len,
                  SocketAsync_Callback cb, void *user_data,
                  SocketAsync_Flags flags)
{
  return socket_async_submit (async, socket, REQ_SEND, buf, NULL, len, cb, user_data, flags);
}

/**
 * SocketAsync_recv - Submit asynchronous receive operation
 * @async: Async context
 * @socket: Target socket
 * @buf: Receive buffer
 * @len: Buffer length
 * @cb: Completion callback (required)
 * @user_data: User data passed to callback
 * @flags: Operation flags (e.g. ASYNC_FLAG_URGENT)
 *
 * Returns: Unique request ID on success, raises SocketAsync_Failed on error
 * Thread-safe: Yes
 *
 * Submits non-blocking recv operation to backend. Callback invoked on completion
 * with bytes received (0 for EOF/would block, negative error). 
 * Use SocketAsync_cancel to cancel pending.
 * Raises if no async backend available or submit fails.
 */
unsigned
SocketAsync_recv (T async, Socket_T socket, void *buf, size_t len,
                  SocketAsync_Callback cb, void *user_data,
                  SocketAsync_Flags flags)
{
  return socket_async_submit (async, socket, REQ_RECV, NULL, buf, len, cb, user_data, flags);
}

/**
 * SocketAsync_cancel - Cancel pending async request
 * @async: Async context
 * @request_id: ID of request to cancel
 *
 * Returns: 0 on success (cancelled or not found), -1 on error
 * Thread-safe: Yes - uses find_and_remove_request
 *
 * Removes request from tracking, frees resources. Callback not invoked.
 * Safe to call on completed or non-existent requests (no-op).
 */
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

#undef T

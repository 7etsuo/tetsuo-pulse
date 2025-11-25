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
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "socket/Socket.h"
#include "socket/SocketAsync.h"
#define SOCKET_LOG_COMPONENT "SocketAsync"
#include "core/SocketError.h"

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
#ifdef _WIN32
static __declspec (thread) Except_T SocketAsync_DetailedException;
#else
static __thread Except_T SocketAsync_DetailedException;
#endif

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e)                                                 \
  do                                                                          \
    {                                                                         \
      SocketAsync_DetailedException = (e);                                    \
      SocketAsync_DetailedException.reason = socket_error_buf;               \
      RAISE (SocketAsync_DetailedException);                                  \
    }                                                                         \
  while (0)

/* Forward declarations */
static unsigned generate_request_id (T async);
static struct AsyncRequest *allocate_request (T async);
static void free_request (T async, struct AsyncRequest *req);
static unsigned request_hash (unsigned request_id);
int submit_async_operation (T async, struct AsyncRequest *req);
int process_async_completions (T async, int timeout_ms);
void SocketAsync_initialize_backend (T async);

/* Helper functions for common async request operations */
static struct AsyncRequest *setup_async_request (T async, Socket_T socket,
                                                 SocketAsync_Callback cb, void *user_data,
                                                 enum AsyncRequestType type,
                                                 const void *send_buf, void *recv_buf,
                                                 size_t len, SocketAsync_Flags flags);
static unsigned submit_and_track_request (T async, struct AsyncRequest *req);
static void cleanup_failed_request (T async, struct AsyncRequest *req, unsigned hash);

/* ==================== Request Management ==================== */

/**
 * request_hash - Hash function for request IDs
 * @request_id: Request ID to hash
 * Returns: Hash value in range [0, SOCKET_HASH_TABLE_SIZE)
 */
static unsigned
request_hash (unsigned request_id)
{
  return ((unsigned)request_id * HASH_GOLDEN_RATIO) % SOCKET_HASH_TABLE_SIZE;
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
 * allocate_request - Allocate async request structure
 * @async: Async context
 * Returns: Allocated request or NULL on allocation failure
 * Raises: SocketAsync_Failed on allocation failure
 */
static struct AsyncRequest *
allocate_request (T async)
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

  memset ((struct AsyncRequest *)volatile_req, 0,
          sizeof (struct AsyncRequest));
  return (struct AsyncRequest *)volatile_req;
}

/**
 * free_request - Free async request structure
 * @async: Async context
 * @req: Request to free
 * Note: Request is allocated from arena, so no explicit free needed
 * but we clear it for safety
 */
static void
free_request (T async, struct AsyncRequest *req)
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
static void handle_completion (T async, unsigned request_id, ssize_t result,
                               int err) __attribute__ ((used));
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
  free_request (async, req);
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
setup_async_request (T async, Socket_T socket, SocketAsync_Callback cb, void *user_data,
                     enum AsyncRequestType type,
                     const void *send_buf, void *recv_buf,
                     size_t len, SocketAsync_Flags flags)
{
  struct AsyncRequest *req = allocate_request (async);
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

  free_request (async, req);
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
SocketAsync_is_available (T async)
{
  if (!async)
    return 0;
  return async->available;
}

const char *
SocketAsync_backend_name (T async)
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

  req = setup_async_request (async, socket, cb, user_data, REQ_SEND,
                            buf, NULL, len, flags);
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

  req = setup_async_request (async, socket, cb, user_data, REQ_RECV,
                            NULL, buf, len, flags);
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

      free_request (async, req);
      return 0;
    }

  return -1; /* Request not found or already completed */
}

int
SocketAsync_process_completions (T async, int timeout_ms)
{
  return process_async_completions (async, timeout_ms);
}

#undef T
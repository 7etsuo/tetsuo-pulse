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

/* Forward declarations for request management */
enum AsyncRequestType;
struct AsyncRequest;

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
SOCKET_DECLARE_MODULE_EXCEPTION(SocketAsync);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketAsync, e)

/* Forward declarations */
extern unsigned request_hash (unsigned request_id);
extern unsigned generate_request_id (T async);
extern struct AsyncRequest *allocate_request (T async);
extern void socket_async_free_request (T async, struct AsyncRequest *req);
extern void handle_completion (T async, unsigned request_id, ssize_t result, int err);
extern struct AsyncRequest *setup_async_request (T async, Socket_T socket, SocketAsync_Callback cb, void *user_data,
                                                 enum AsyncRequestType type,
                                                 const void *send_buf, void *recv_buf,
                                                 size_t len, SocketAsync_Flags flags);
extern unsigned submit_and_track_request (T async, struct AsyncRequest *req);
int submit_async_operation (T async, struct AsyncRequest *req);
int process_async_completions (T async, int timeout_ms);
void SocketAsync_initialize_backend (T async);

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

      socket_async_free_request (async, req);
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
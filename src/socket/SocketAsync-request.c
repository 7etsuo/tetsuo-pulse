/**
 * SocketAsync-request.c - Async request management
 *
 * Request lifecycle management, hash table operations, and completion handling
 * for asynchronous socket operations.
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "socket/SocketAsync.h"
#include "core/SocketError.h"

#define T SocketAsync_T

/* Thread-local exception for detailed error messages */
/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketAsyncRequest);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketAsyncRequest, e)

/* Forward declarations */
extern const Except_T SocketAsync_Failed;

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

/* Async context structure (defined here for access to members) */
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

/* Forward declarations for backend functions */
extern int submit_async_operation (T async, struct AsyncRequest *req);

/**
 * request_hash - Hash function for request IDs
 * @request_id: Request ID to hash
 * Returns: Hash value in range [0, SOCKET_HASH_TABLE_SIZE)
 */
unsigned
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
unsigned
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
struct AsyncRequest *
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

  memset ((struct AsyncRequest *)volatile_req, 0,
          sizeof (struct AsyncRequest));
  return (struct AsyncRequest *)volatile_req;
}

/**
 * socket_async_free_request - Free async request structure
 * @async: Async context
 * @req: Request to free
 * Note: Request is allocated from arena, so no explicit free needed
 * but we clear it for safety
 */
void
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
void
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
struct AsyncRequest *
setup_async_request (T async, Socket_T socket, SocketAsync_Callback cb, void *user_data,
                     enum AsyncRequestType type,
                     const void *send_buf, void *recv_buf,
                     size_t len, SocketAsync_Flags flags)
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
void
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

/**
 * submit_and_track_request - Submit request and track in hash table
 * @async: Async context
 * @req: Request to submit and track
 * Returns: Request ID on success, 0 on failure
 * Thread-safe: Yes (handles mutex locking)
 */
unsigned
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

#undef T

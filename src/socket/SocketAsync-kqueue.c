/**
 * SocketAsync-kqueue.c - kqueue asynchronous I/O backend (BSD/macOS)
 *
 * Implements asynchronous I/O operations using BSD/macOS kqueue in edge-triggered
 * mode. While not true kernel AIO like io_uring, provides efficient event-driven
 * I/O with completion callbacks when sockets become ready.
 *
 * Features:
 * - Edge-triggered kqueue event monitoring
 * - Efficient readiness-based I/O
 * - Cross-platform BSD/macOS support
 * - Completion callback on event firing
 * - Timeout support for event waiting
 */

#if defined(__APPLE__) || defined(__FreeBSD__)

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/SocketConfig.h"
#include "socket/Socket.h"
#include "socket/SocketAsync.h"
#include "socket/SocketIO.h" /* For TLS-aware I/O functions */
#define SOCKET_LOG_COMPONENT "SocketAsync"
#include "core/SocketError.h"

#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLS.h" /* For TLS exception types */
#endif

#define T SocketAsync_T

/* ==================== kqueue Operations ==================== */

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
 * process_kqueue_completions - Process kqueue events and perform I/O
 * @async: Async context
 * @timeout_ms: Timeout in milliseconds
 * @max_completions: Maximum completions to process
 * Returns: Number of completions processed
 *
 * Note: This performs the actual I/O operation when the event fires,
 * then invokes the callback with the result.
 */
static int
process_kqueue_completions (T async, int timeout_ms, int max_completions)
{
  struct kevent events[SOCKET_MAX_EVENT_BATCH];
  struct timespec timeout;
  int n;
  int count = 0;

  assert (async);
  assert (async->kqueue_fd >= 0);

  if (max_completions > SOCKET_MAX_EVENT_BATCH)
    max_completions = SOCKET_MAX_EVENT_BATCH;

  timeout.tv_sec = timeout_ms / SOCKET_MS_PER_SECOND;
  timeout.tv_nsec = (timeout_ms % SOCKET_MS_PER_SECOND) * SOCKET_NS_PER_MS;

  n = kevent (async->kqueue_fd, NULL, 0, events, max_completions, &timeout);
  if (n < 0)
    {
      if (errno == EINTR)
        return 0;
      return -1;
    }

  for (int i = 0; i < n; i++)
    {
      unsigned request_id = (unsigned)(uintptr_t)events[i].udata;
      struct AsyncRequest *req;
      unsigned hash = request_hash (request_id);
      ssize_t result = 0;
      int err = 0;

      /* Find request */
      pthread_mutex_lock (&async->mutex);
      req = async->requests[hash];
      while (req && req->request_id != request_id)
        {
          req = req->next;
        }

      if (!req)
        {
          pthread_mutex_unlock (&async->mutex);
          continue; /* Request not found */
        }

      /* Remove from hash table */
      struct AsyncRequest **pp = &async->requests[hash];
      while (*pp != req)
        {
          pp = &(*pp)->next;
        }
      *pp = req->next;

      /* Extract callback and socket before unlocking */
      SocketAsync_Callback cb = req->cb;
      Socket_T socket = req->socket;
      void *user_data = req->user_data;
      enum
      {
        REQ_SEND,
        REQ_RECV
      } type
          = req->type;
      const void *send_buf = req->send_buf;
      void *recv_buf = req->recv_buf;
      size_t len = req->len;

      pthread_mutex_unlock (&async->mutex);

      /* Perform I/O operation using TLS-aware functions */
      /* These functions automatically route through TLS when enabled */
      TRY
      {
        if (type == REQ_SEND)
          {
            result
                = socket_send_internal (socket, send_buf, len, MSG_NOSIGNAL);
            if (result == 0)
              {
                /* Would block (EAGAIN/EWOULDBLOCK) */
                err = EAGAIN;
                result = -1;
              }
            else
              {
                /* Success - result > 0 is bytes sent */
                err = 0;
              }
          }
        else
          {
            result = socket_recv_internal (socket, recv_buf, len, 0);
            if (result == 0)
              {
                /* Would block (EAGAIN/EWOULDBLOCK) */
                /* Note: EOF raises Socket_Closed exception, never returns 0 */
                err = EAGAIN;
                result = -1;
              }
            else
              {
                /* Success - result > 0 is bytes received */
                err = 0;
              }
          }
      }
      EXCEPT (Socket_Closed)
      {
        /* Connection closed (EOF for recv, EPIPE/ECONNRESET for send) */
        err = ECONNRESET;
        result = -1;
      }
      EXCEPT (Socket_Failed)
      {
        /* Socket operation failed - errno should be set by
         * socket_send_internal/recv_internal */
        err = errno;
        if (err == 0)
          err = EPROTO; /* Fallback if errno not set (shouldn't happen) */
        result = -1;
      }
#ifdef SOCKET_HAS_TLS
      EXCEPT (SocketTLS_HandshakeFailed)
      {
        /* TLS handshake not complete - treat as would block */
        err = EAGAIN;
        result = -1;
      }
      EXCEPT (SocketTLS_Failed)
      {
        /* TLS operation failed - errno should be set by
         * socket_handle_ssl_error */
        err = errno;
        if (err == 0)
          err = EPROTO; /* Fallback if errno not set (shouldn't happen) */
        result = -1;
      }
#endif
      END_TRY;

      /* Invoke callback */
      if (cb)
        {
          cb (socket, result, err, user_data);
        }

      /* Free request */
      free_request (async, req);
      count++;
    }

  return count;
}

#endif /* __APPLE__ || __FreeBSD__ */

#undef T

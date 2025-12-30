/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTPClient-async.c
 * @brief Async I/O wrapper functions for HTTP client.
 *
 * Provides synchronous-looking I/O that uses io_uring internally when enabled.
 * Falls back to standard Socket_send/recv if async I/O is unavailable.
 *
 * Thread safety: Functions are thread-safe per client instance.
 */

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "http/SocketHTTPClient-private.h"
#include "socket/SocketAsync.h"

/**
 * @brief Timeout in milliseconds for async completion polling.
 *
 * Small timeout to avoid busy-waiting while processing completions.
 */
#define ASYNC_COMPLETION_POLL_TIMEOUT_MS 1

/**
 * @brief State for blocking async I/O completion.
 *
 * Used to bridge async callbacks to synchronous semantics.
 */
typedef struct AsyncIOState
{
  volatile int completed;     /**< Set to 1 when operation completes */
  volatile ssize_t bytes;     /**< Bytes transferred or -1 on error */
  volatile int error;         /**< errno value if error occurred */
} AsyncIOState;

/**
 * @brief Callback for async send/recv completion.
 *
 * Sets completion state and stores result for blocking wait.
 */
static void
async_io_callback (Socket_T socket, ssize_t bytes, int err, void *user_data)
{
  AsyncIOState *state = (AsyncIOState *)user_data;

  (void)socket; /* Unused in callback */

  if (state == NULL)
    return;

  state->bytes = bytes;
  state->error = err;

  /* Memory barrier before setting completed flag */
  __atomic_store_n (&state->completed, 1, __ATOMIC_RELEASE);
}

/**
 * @brief Wait for async operation to complete with timeout.
 *
 * Spins on completion flag while processing async completions.
 * Uses process_completions with small timeout to avoid busy wait.
 * Returns error if operation exceeds client's configured timeout.
 *
 * @param client HTTP client with async context and timeout config
 * @param state Completion state to wait on
 * @return 0 when completed successfully, -1 on timeout or error
 */
static int
wait_for_completion (SocketHTTPClient_T client, AsyncIOState *state)
{
  int elapsed_ms = 0;
  int timeout_ms;
  int ret;

  assert (client != NULL);
  assert (client->async != NULL);
  assert (state != NULL);

  /* Use client's configured request timeout (default 60 seconds) */
  timeout_ms = client->config.request_timeout_ms;
  if (timeout_ms <= 0)
    timeout_ms = HTTPCLIENT_DEFAULT_REQUEST_TIMEOUT_MS;

  while (!__atomic_load_n (&state->completed, __ATOMIC_ACQUIRE))
    {
      /* Check timeout */
      if (elapsed_ms >= timeout_ms)
        {
          SocketLog_emitf (SOCKET_LOG_WARN, "HTTPClient",
                          "Async operation timed out after %d ms", elapsed_ms);
          errno = ETIMEDOUT;
          return -1;
        }

      /* Process completions with 1ms timeout to avoid busy spin */
      ret = SocketAsync_process_completions (client->async,
                                             ASYNC_COMPLETION_POLL_TIMEOUT_MS);
      if (ret < 0)
        {
          SocketLog_emitf (SOCKET_LOG_ERROR, "HTTPClient",
                          "Failed to process async completions");
          return -1;
        }

      elapsed_ms += ASYNC_COMPLETION_POLL_TIMEOUT_MS;
    }

  return 0;
}

/**
 * @brief Synchronous send fallback when async I/O is unavailable.
 *
 * Performs blocking send using Socket_send with exception handling.
 * Converts Socket_Closed exception to EPIPE errno.
 *
 * @param socket Socket to send on
 * @param data Data buffer to send
 * @param len Length of data
 * @return Bytes sent on success, -1 on error (sets errno)
 */
static ssize_t
sync_send_fallback (Socket_T socket, const void *data, size_t len)
{
  volatile ssize_t sent = 0;

  TRY { sent = Socket_send (socket, data, len); }
  EXCEPT (Socket_Closed)
  {
    errno = EPIPE;
    return -1;
  }
  EXCEPT (Socket_Failed)
  {
    return -1;
  }
  END_TRY;

  return sent;
}

/**
 * @brief Synchronous recv fallback when async I/O is unavailable.
 *
 * Performs blocking recv using Socket_recv with exception handling.
 * Converts Socket_Closed exception to EOF (returns 0).
 *
 * @param socket Socket to receive from
 * @param buf Buffer to receive into
 * @param len Length of buffer
 * @return Bytes received on success, 0 on EOF, -1 on error (sets errno)
 */
static ssize_t
sync_recv_fallback (Socket_T socket, void *buf, size_t len)
{
  volatile ssize_t recvd = 0;

  TRY { recvd = Socket_recv (socket, buf, len); }
  EXCEPT (Socket_Closed)
  {
    recvd = 0; /* EOF - graceful close */
  }
  EXCEPT (Socket_Failed)
  {
    return -1;
  }
  END_TRY;

  return recvd;
}

int
httpclient_async_init (SocketHTTPClient_T client)
{
  volatile int result = -1;

  assert (client != NULL);

  /* Already initialized or not requested */
  if (!client->config.enable_async_io)
    return 0;

  if (client->async != NULL)
    return 0;

  TRY
  {
    client->async = SocketAsync_new (client->arena);
    if (client->async != NULL)
      {
        client->async_available = SocketAsync_is_available (client->async);
        if (client->async_available)
          {
            SocketLog_emitf (SOCKET_LOG_INFO, "HTTPClient",
                             "Async I/O enabled (backend: %s)",
                             SocketAsync_backend_name (client->async));
            result = 0;
          }
        else
          {
            SocketLog_emitf (SOCKET_LOG_DEBUG, "HTTPClient",
                             "Async I/O requested but not available (backend: %s)",
                             SocketAsync_backend_name (client->async));
            /* Keep async context for potential fallback use */
            result = 0;
          }
      }
  }
  EXCEPT (SocketAsync_Failed)
  {
    SocketLog_emitf (SOCKET_LOG_WARN, "HTTPClient",
                     "Failed to initialize async I/O, using sync fallback");
    client->async = NULL;
    client->async_available = 0;
    result = 0; /* Not a fatal error - fallback to sync */
  }
  END_TRY;

  return result;
}

void
httpclient_async_cleanup (SocketHTTPClient_T client)
{
  if (client == NULL)
    return;

  if (client->async != NULL)
    {
      /* Cancel any pending operations */
      SocketAsync_cancel_all (client->async);

      /* Free the async context */
      SocketAsync_free (&client->async);
      client->async = NULL;
      client->async_available = 0;
    }
}

ssize_t
httpclient_io_send (SocketHTTPClient_T client, Socket_T socket,
                    const void *data, size_t len)
{
  AsyncIOState state;
  unsigned req_id;

  /* Validate required inputs */
  if (client == NULL || socket == NULL)
    {
      errno = EINVAL;
      return -1;
    }

  /* NULL data with non-zero length is invalid */
  if (data == NULL && len > 0)
    {
      errno = EINVAL;
      return -1;
    }

  /* Zero-length send is a no-op */
  if (len == 0)
    return 0;

  /* Fast path: use sync I/O if async not available */
  if (!client->async_available || client->async == NULL)
    return sync_send_fallback (socket, data, len);

  /* Initialize completion state */
  memset ((void *)&state, 0, sizeof (state));

  /* Submit async send */
  req_id = SocketAsync_send (client->async, socket, data, len,
                             async_io_callback, (void *)&state,
                             ASYNC_FLAG_NONE);
  if (req_id == 0)
    {
      /* Submission failed - fall back to sync */
      SocketLog_emitf (SOCKET_LOG_DEBUG, "HTTPClient",
                       "Async send submission failed, falling back to sync");
      return sync_send_fallback (socket, data, len);
    }

  /* Wait for completion */
  if (wait_for_completion (client, &state) < 0)
    {
      /* Timeout or processing error - errno already set */
      return -1;
    }

  /* Check for error */
  if (state.error != 0)
    {
      errno = state.error;
      return -1;
    }

  return state.bytes;
}

ssize_t
httpclient_io_recv (SocketHTTPClient_T client, Socket_T socket,
                    void *buf, size_t len)
{
  AsyncIOState state;
  unsigned req_id;

  /* Validate required inputs */
  if (client == NULL || socket == NULL)
    {
      errno = EINVAL;
      return -1;
    }

  /* NULL buffer with non-zero length is invalid */
  if (buf == NULL && len > 0)
    {
      errno = EINVAL;
      return -1;
    }

  /* Zero-length recv is a no-op */
  if (len == 0)
    return 0;

  /* Fast path: use sync I/O if async not available */
  if (!client->async_available || client->async == NULL)
    return sync_recv_fallback (socket, buf, len);

  /* Initialize completion state */
  memset ((void *)&state, 0, sizeof (state));

  /* Submit async recv */
  req_id = SocketAsync_recv (client->async, socket, buf, len,
                             async_io_callback, (void *)&state,
                             ASYNC_FLAG_NONE);
  if (req_id == 0)
    {
      /* Submission failed - fall back to sync */
      SocketLog_emitf (SOCKET_LOG_DEBUG, "HTTPClient",
                       "Async recv submission failed, falling back to sync");
      return sync_recv_fallback (socket, buf, len);
    }

  /* Wait for completion */
  if (wait_for_completion (client, &state) < 0)
    {
      /* Timeout or processing error - errno already set */
      return -1;
    }

  /* Check for error */
  if (state.error != 0)
    {
      if (state.error == ECONNRESET || state.error == EPIPE)
        return 0; /* Treat as EOF */
      errno = state.error;
      return -1;
    }

  return state.bytes;
}

/* =============================================================================
 * Async Request API
 * =============================================================================
 */

/**
 * @brief Create an async HTTP request from a convenience function.
 *
 * Internal helper for SocketHTTPClient_get_async() and _post_async().
 * Allocates async request structure and initializes state.
 *
 * @param client HTTP client
 * @param req Request to execute asynchronously
 * @param callback Completion callback
 * @param userdata User data passed to callback
 * @return Async request handle, or NULL on error
 */
static SocketHTTPClient_AsyncRequest_T
create_async_request (SocketHTTPClient_T client,
                      SocketHTTPClient_Request_T req,
                      SocketHTTPClient_Callback callback, void *userdata)
{
  SocketHTTPClient_AsyncRequest_T async_req;

  if (client == NULL || req == NULL || callback == NULL)
    return NULL;

  /* Allocate async request from client arena */
  async_req = CALLOC (client->arena, 1, sizeof (*async_req));
  if (async_req == NULL)
    return NULL;

  async_req->client = client;
  async_req->request = req;
  async_req->state = ASYNC_STATE_IDLE;
  async_req->error = HTTPCLIENT_OK;
  async_req->conn = NULL;
  async_req->callback = callback;
  async_req->userdata = userdata;
  async_req->next = NULL;

  /* Initialize response arena */
  memset (&async_req->response, 0, sizeof (async_req->response));
  async_req->response.arena = NULL;

  return async_req;
}

SocketHTTPClient_AsyncRequest_T
SocketHTTPClient_get_async (SocketHTTPClient_T client, const char *url,
                            SocketHTTPClient_Callback callback,
                            void *userdata)
{
  SocketHTTPClient_Request_T req;
  SocketHTTPClient_AsyncRequest_T async_req;

  if (client == NULL || url == NULL || callback == NULL)
    return NULL;

  /* Create request */
  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_GET, url);
  if (req == NULL)
    return NULL;

  /* Wrap in async request */
  async_req = create_async_request (client, req, callback, userdata);
  if (async_req == NULL)
    {
      SocketHTTPClient_Request_free (&req);
      return NULL;
    }

  return async_req;
}

SocketHTTPClient_AsyncRequest_T
SocketHTTPClient_post_async (SocketHTTPClient_T client, const char *url,
                             const char *content_type, const void *body,
                             size_t body_len,
                             SocketHTTPClient_Callback callback,
                             void *userdata)
{
  SocketHTTPClient_Request_T req;
  SocketHTTPClient_AsyncRequest_T async_req;

  if (client == NULL || url == NULL || callback == NULL)
    return NULL;

  /* Create request */
  req = SocketHTTPClient_Request_new (client, HTTP_METHOD_POST, url);
  if (req == NULL)
    return NULL;

  /* Set body if provided */
  if (body != NULL && body_len > 0)
    {
      if (SocketHTTPClient_Request_body (req, body, body_len) != 0)
        {
          SocketHTTPClient_Request_free (&req);
          return NULL;
        }
    }

  /* Set Content-Type header if provided with body */
  if (body != NULL && body_len > 0 && content_type != NULL)
    {
      if (SocketHTTPClient_Request_header (req, "Content-Type",
                                           content_type)
          != 0)
        {
          SocketHTTPClient_Request_free (&req);
          return NULL;
        }
    }

  /* Wrap in async request */
  async_req = create_async_request (client, req, callback, userdata);
  if (async_req == NULL)
    {
      SocketHTTPClient_Request_free (&req);
      return NULL;
    }

  return async_req;
}

SocketHTTPClient_AsyncRequest_T
SocketHTTPClient_Request_async (SocketHTTPClient_Request_T req,
                                SocketHTTPClient_Callback callback,
                                void *userdata)
{
  SocketHTTPClient_AsyncRequest_T async_req;

  if (req == NULL || req->client == NULL || callback == NULL)
    return NULL;

  /* Wrap request in async context */
  async_req = create_async_request (req->client, req, callback, userdata);
  return async_req;
}

void
SocketHTTPClient_AsyncRequest_cancel (SocketHTTPClient_AsyncRequest_T req)
{
  if (req == NULL)
    return;

  /* Mark as cancelled if not already complete */
  if (req->state != ASYNC_STATE_COMPLETE
      && req->state != ASYNC_STATE_FAILED)
    {
      req->state = ASYNC_STATE_CANCELLED;
      req->error = HTTPCLIENT_ERROR_CANCELLED;
    }

  /* Note: For a full implementation, we would:
   * - Close any active connection
   * - Remove from pending queue
   * - Invoke callback with cancelled error
   * This stub implementation just marks the state.
   */
}

void
SocketHTTPClient_AsyncRequest_free (SocketHTTPClient_AsyncRequest_T *req)
{
  if (req == NULL || *req == NULL)
    return;

  /* Response arena is managed by the async request, free it if created */
  if ((*req)->response.arena != NULL)
    {
      Arena_dispose (&(*req)->response.arena);
    }

  /* The async request itself is allocated from client arena,
   * so we don't free it here - it will be freed when the client
   * arena is disposed. Just null the pointer. */
  *req = NULL;
}

int
SocketHTTPClient_process (SocketHTTPClient_T client, int timeout_ms)
{
  (void)client;
  (void)timeout_ms;

  /* Stub implementation - no async requests are actually executed yet.
   * A full implementation would:
   * - Poll for connection readiness
   * - Process state machine for pending async requests
   * - Invoke callbacks on completion
   * - Return number of requests processed
   */

  return 0;
}

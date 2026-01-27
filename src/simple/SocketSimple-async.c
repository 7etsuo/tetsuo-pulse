/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-async.c
 * @brief Simple asynchronous I/O operations implementation.
 */

#include "SocketSimple-internal.h"
#include "simple/SocketSimple-async.h"

#include "core/Arena.h"
#include "socket/SocketAsync.h"

/* ============================================================================
 * Internal Structure
 * ============================================================================
 */

/**
 * @brief Linked list node for tracking callback contexts.
 *
 * Enables cleanup of CallbackContext allocations when async operations
 * are cancelled (the normal callback path won't fire to free them).
 */
typedef struct ContextTracker
{
  unsigned request_id;
  struct CallbackContext *ctx;
  struct ContextTracker *next;
} ContextTracker;

struct SocketSimple_Async
{
  Arena_T arena;
  SocketAsync_T async;
  ContextTracker *contexts; /**< Tracked contexts for cancel cleanup */
};

/* ============================================================================
 * Helper: Map Simple flags to core flags
 * ============================================================================
 */

static SocketAsync_Flags
simple_to_core_flags (SocketSimple_AsyncFlags flags)
{
  SocketAsync_Flags core = ASYNC_FLAG_NONE;
  if (flags & SOCKET_SIMPLE_ASYNC_PRIORITY)
    core |= ASYNC_FLAG_URGENT;
  return core;
}

/* ============================================================================
 * Helper: Callback wrapper
 * ============================================================================
 */

/**
 * Wrapper structure to translate between core and simple callbacks.
 * We need this because the core callback receives Socket_T but the
 * simple callback expects SocketSimple_Socket_T.
 */
struct CallbackContext
{
  SocketSimple_AsyncCallback user_cb;
  void *user_data;
  SocketSimple_Socket_T simple_socket;
  struct SocketSimple_Async *async; /**< Back-pointer for tracker removal */
  unsigned request_id;              /**< Request ID for tracker lookup */
};

/* ============================================================================
 * Helper: Context Tracker for Cancellation Cleanup
 * ============================================================================
 */

/**
 * @brief Add a context to the tracker.
 */
static void
context_tracker_add (struct SocketSimple_Async *async,
                     unsigned request_id,
                     struct CallbackContext *ctx)
{
  ContextTracker *entry = calloc (1, sizeof (*entry));
  if (!entry)
    return; /* Best effort - leak is better than crash */

  entry->request_id = request_id;
  entry->ctx = ctx;
  entry->next = async->contexts;
  async->contexts = entry;
}

/**
 * @brief Remove a context from the tracker (does not free the context).
 */
static void
context_tracker_remove (struct SocketSimple_Async *async, unsigned request_id)
{
  ContextTracker **pp = &async->contexts;
  while (*pp)
    {
      if ((*pp)->request_id == request_id)
        {
          ContextTracker *to_free = *pp;
          *pp = to_free->next;
          free (to_free);
          return;
        }
      pp = &(*pp)->next;
    }
}

/**
 * @brief Find and remove a context from the tracker, returning the context.
 */
static struct CallbackContext *
context_tracker_find_and_remove (struct SocketSimple_Async *async,
                                 unsigned request_id)
{
  ContextTracker **pp = &async->contexts;
  while (*pp)
    {
      if ((*pp)->request_id == request_id)
        {
          ContextTracker *entry = *pp;
          struct CallbackContext *ctx = entry->ctx;
          *pp = entry->next;
          free (entry);
          return ctx;
        }
      pp = &(*pp)->next;
    }
  return NULL;
}

/**
 * @brief Free all tracked contexts (for cleanup on cancel_all or destroy).
 */
static void
context_tracker_free_all (struct SocketSimple_Async *async)
{
  ContextTracker *entry = async->contexts;
  while (entry)
    {
      ContextTracker *next = entry->next;
      if (entry->ctx)
        free (entry->ctx);
      free (entry);
      entry = next;
    }
  async->contexts = NULL;
}

static void
core_callback_wrapper (Socket_T socket, ssize_t bytes, int err, void *user_data)
{
  struct CallbackContext *ctx = (struct CallbackContext *)user_data;

  (void)socket; /* We use the simple_socket from context */

  if (ctx)
    {
      /* Remove from tracker before freeing */
      if (ctx->async)
        context_tracker_remove (ctx->async, ctx->request_id);

      if (ctx->user_cb)
        ctx->user_cb (ctx->simple_socket, bytes, err, ctx->user_data);

      /* Free the context after callback */
      free (ctx);
    }
}

/**
 * Get the core Socket_T from a simple handle.
 * Returns NULL if handle is NULL or is UDP (async doesn't support UDP).
 */
static Socket_T
get_core_socket (SocketSimple_Socket_T simple)
{
  if (!simple)
    return NULL;
  /* UDP sockets (dgram) are not supported for async */
  if (simple->is_udp)
    return NULL;
  return simple->socket;
}

/* ============================================================================
 * Async Lifecycle
 * ============================================================================
 */

SocketSimple_Async_T
Socket_simple_async_new (void)
{
  volatile Arena_T arena = NULL;
  volatile SocketAsync_T async = NULL;

  Socket_simple_clear_error ();

  TRY
  {
    arena = Arena_new ();
  }
  EXCEPT (Arena_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_MEMORY,
                      "Failed to create arena for async context");
    return NULL;
  }
  END_TRY;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose ((Arena_T *)&arena);
    simple_set_error (SOCKET_SIMPLE_ERR_ASYNC,
                      "Failed to create async context");
    return NULL;
  }
  END_TRY;

  struct SocketSimple_Async *handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      SocketAsync_free ((SocketAsync_T *)&async);
      Arena_dispose ((Arena_T *)&arena);
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      return NULL;
    }

  handle->arena = arena;
  handle->async = async;

  return handle;
}

void
Socket_simple_async_free (SocketSimple_Async_T *async)
{
  if (!async || !*async)
    return;

  /* Free any remaining tracked callback contexts */
  context_tracker_free_all (*async);

  SocketAsync_free (&(*async)->async);
  Arena_dispose (&(*async)->arena);
  free (*async);
  *async = NULL;
}

/* ============================================================================
 * Async Send/Recv Operations
 * ============================================================================
 */

/**
 * Function pointer types for core async operations.
 */
typedef unsigned (*AsyncOpFunc) (SocketAsync_T async,
                                 Socket_T socket,
                                 void *buf,
                                 size_t len,
                                 SocketAsync_Callback cb,
                                 void *user_data,
                                 SocketAsync_Flags flags);

typedef unsigned (*AsyncOpTimeoutFunc) (SocketAsync_T async,
                                        Socket_T socket,
                                        void *buf,
                                        size_t len,
                                        SocketAsync_Callback cb,
                                        void *user_data,
                                        SocketAsync_Flags flags,
                                        int64_t timeout_ms);

/**
 * Validate async operation parameters.
 *
 * @param async  Simple async context
 * @param socket Simple socket handle
 * @param cb     User callback
 * @return 0 on success, -1 on error (sets error via simple_set_error)
 */
static int
validate_async_params (SocketSimple_Async_T async,
                       SocketSimple_Socket_T socket,
                       SocketSimple_AsyncCallback cb)
{
  if (!async || !async->async)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid async context");
      return -1;
    }

  Socket_T core_socket = get_core_socket (socket);
  if (!core_socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid socket (NULL or UDP not supported)");
      return -1;
    }

  if (!cb)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Callback is required");
      return -1;
    }

  return 0;
}

/**
 * Allocate and initialize callback context for async operations.
 *
 * @param cb            User callback
 * @param user_data     User data for callback
 * @param simple_socket Simple socket handle to pass to callback
 * @return Allocated context on success, NULL on error (sets error)
 */
static struct CallbackContext *
allocate_callback_context (SocketSimple_AsyncCallback cb,
                           void *user_data,
                           SocketSimple_Socket_T simple_socket)
{
  struct CallbackContext *ctx = calloc (1, sizeof (*ctx));
  if (!ctx)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY,
                        "Failed to allocate callback context");
      return NULL;
    }

  ctx->user_cb = cb;
  ctx->user_data = user_data;
  ctx->simple_socket = simple_socket;

  return ctx;
}

/**
 * Submit async operation to core SocketAsync.
 *
 * @param async            Core async context
 * @param core_socket      Core socket handle
 * @param buf              Buffer for operation
 * @param len              Buffer length
 * @param ctx              Callback context (freed on error)
 * @param flags            Simple async flags
 * @param timeout_ms       Timeout in milliseconds (0 = no timeout)
 * @param op_func          Core async function (no timeout)
 * @param op_timeout_func  Core async function (with timeout)
 * @param error_msg        Error message for operation failure
 * @return Request ID on success, 0 on failure (sets error)
 */
static unsigned
submit_async_operation (SocketSimple_Async_T simple_async,
                        SocketAsync_T async,
                        Socket_T core_socket,
                        void *buf,
                        size_t len,
                        struct CallbackContext *ctx,
                        SocketSimple_AsyncFlags flags,
                        int64_t timeout_ms,
                        AsyncOpFunc op_func,
                        AsyncOpTimeoutFunc op_timeout_func,
                        const char *error_msg)
{
  volatile unsigned request_id = 0;

  TRY
  {
    if (timeout_ms > 0)
      {
        request_id = op_timeout_func (async,
                                      core_socket,
                                      buf,
                                      len,
                                      core_callback_wrapper,
                                      ctx,
                                      simple_to_core_flags (flags),
                                      timeout_ms);
      }
    else
      {
        request_id = op_func (async,
                              core_socket,
                              buf,
                              len,
                              core_callback_wrapper,
                              ctx,
                              simple_to_core_flags (flags));
      }
  }
  EXCEPT (SocketAsync_Failed)
  {
    free (ctx);
    simple_set_error (SOCKET_SIMPLE_ERR_ASYNC, error_msg);
    return 0;
  }
  END_TRY;

  /* Track context for cancellation cleanup */
  if (request_id > 0)
    {
      ctx->async = simple_async;
      ctx->request_id = request_id;
      context_tracker_add (simple_async, request_id, ctx);
    }

  return request_id;
}

/**
 * Common implementation for async send/recv operations.
 * Orchestrates validation, context allocation, and operation submission.
 *
 * @param async         Simple async context
 * @param socket        Simple socket handle
 * @param buf           Buffer for operation
 * @param len           Buffer length
 * @param cb            User callback
 * @param user_data     User data for callback
 * @param flags         Simple async flags
 * @param timeout_ms    Timeout in milliseconds (0 = no timeout)
 * @param op_func       Core async function (no timeout)
 * @param op_timeout_func Core async function (with timeout)
 * @param error_msg     Error message for operation failure
 * @return Request ID on success, 0 on failure
 */
static unsigned
async_operation_common (SocketSimple_Async_T async,
                        SocketSimple_Socket_T socket,
                        void *buf,
                        size_t len,
                        SocketSimple_AsyncCallback cb,
                        void *user_data,
                        SocketSimple_AsyncFlags flags,
                        int64_t timeout_ms,
                        AsyncOpFunc op_func,
                        AsyncOpTimeoutFunc op_timeout_func,
                        const char *error_msg)
{
  /* Volatile copy to survive potential longjmp in TRY/EXCEPT */
  SocketSimple_Socket_T volatile safe_socket = socket;

  Socket_simple_clear_error ();

  /* Step 1: Validate parameters */
  if (validate_async_params (async, (SocketSimple_Socket_T)safe_socket, cb)
      != 0)
    return 0;

  /* Step 2: Allocate callback context */
  struct CallbackContext *ctx = allocate_callback_context (
      cb, user_data, (SocketSimple_Socket_T)safe_socket);
  if (!ctx)
    return 0;

  /* Step 3: Submit async operation */
  Socket_T core_socket = get_core_socket ((SocketSimple_Socket_T)safe_socket);
  return submit_async_operation (async,
                                 async->async,
                                 core_socket,
                                 buf,
                                 len,
                                 ctx,
                                 flags,
                                 timeout_ms,
                                 op_func,
                                 op_timeout_func,
                                 error_msg);
}

unsigned
Socket_simple_async_send (SocketSimple_Async_T async,
                          SocketSimple_Socket_T socket,
                          const void *buf,
                          size_t len,
                          SocketSimple_AsyncCallback cb,
                          void *user_data,
                          SocketSimple_AsyncFlags flags)
{
  return Socket_simple_async_send_timeout (
      async, socket, buf, len, cb, user_data, flags, 0);
}

unsigned
Socket_simple_async_recv (SocketSimple_Async_T async,
                          SocketSimple_Socket_T socket,
                          void *buf,
                          size_t len,
                          SocketSimple_AsyncCallback cb,
                          void *user_data,
                          SocketSimple_AsyncFlags flags)
{
  return Socket_simple_async_recv_timeout (
      async, socket, buf, len, cb, user_data, flags, 0);
}

unsigned
Socket_simple_async_send_timeout (SocketSimple_Async_T async,
                                  SocketSimple_Socket_T socket,
                                  const void *buf,
                                  size_t len,
                                  SocketSimple_AsyncCallback cb,
                                  void *user_data,
                                  SocketSimple_AsyncFlags flags,
                                  int64_t timeout_ms)
{
  return async_operation_common (async,
                                 socket,
                                 (void *)buf,
                                 len,
                                 cb,
                                 user_data,
                                 flags,
                                 timeout_ms,
                                 (AsyncOpFunc)SocketAsync_send,
                                 (AsyncOpTimeoutFunc)SocketAsync_send_timeout,
                                 "Failed to submit async send");
}

unsigned
Socket_simple_async_recv_timeout (SocketSimple_Async_T async,
                                  SocketSimple_Socket_T socket,
                                  void *buf,
                                  size_t len,
                                  SocketSimple_AsyncCallback cb,
                                  void *user_data,
                                  SocketSimple_AsyncFlags flags,
                                  int64_t timeout_ms)
{
  return async_operation_common (async,
                                 socket,
                                 buf,
                                 len,
                                 cb,
                                 user_data,
                                 flags,
                                 timeout_ms,
                                 (AsyncOpFunc)SocketAsync_recv,
                                 (AsyncOpTimeoutFunc)SocketAsync_recv_timeout,
                                 "Failed to submit async recv");
}

/* ============================================================================
 * Completion Processing
 * ============================================================================
 */

int
Socket_simple_async_process (SocketSimple_Async_T async, int timeout_ms)
{
  Socket_simple_clear_error ();

  if (!async || !async->async)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid async context");
      return -1;
    }

  return SocketAsync_process_completions (async->async, timeout_ms);
}

/* ============================================================================
 * Request Management
 * ============================================================================
 */

int
Socket_simple_async_cancel (SocketSimple_Async_T async, unsigned request_id)
{
  int result;
  struct CallbackContext *ctx;

  Socket_simple_clear_error ();

  if (!async || !async->async)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid async context");
      return -1;
    }

  result = SocketAsync_cancel (async->async, request_id);

  /* Free the callback context that would otherwise leak since the
   * core callback wrapper won't fire for cancelled operations. */
  ctx = context_tracker_find_and_remove (async, request_id);
  if (ctx)
    free (ctx);

  return result;
}

int
Socket_simple_async_cancel_all (SocketSimple_Async_T async)
{
  int result;

  Socket_simple_clear_error ();

  if (!async || !async->async)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid async context");
      return -1;
    }

  result = SocketAsync_cancel_all (async->async);

  /* Free all tracked callback contexts that would otherwise leak. */
  context_tracker_free_all (async);

  return result;
}

/* ============================================================================
 * Progress and Continuation
 * ============================================================================
 */

int
Socket_simple_async_get_progress (SocketSimple_Async_T async,
                                  unsigned request_id,
                                  size_t *completed,
                                  size_t *total)
{
  if (completed)
    *completed = 0;
  if (total)
    *total = 0;

  Socket_simple_clear_error ();

  if (!async || !async->async)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid async context");
      return 0;
    }

  return SocketAsync_get_progress (async->async, request_id, completed, total);
}

unsigned
Socket_simple_async_send_continue (SocketSimple_Async_T async,
                                   unsigned request_id)
{
  Socket_simple_clear_error ();

  if (!async || !async->async)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid async context");
      return 0;
    }

  return SocketAsync_send_continue (async->async, request_id);
}

unsigned
Socket_simple_async_recv_continue (SocketSimple_Async_T async,
                                   unsigned request_id)
{
  Socket_simple_clear_error ();

  if (!async || !async->async)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid async context");
      return 0;
    }

  return SocketAsync_recv_continue (async->async, request_id);
}

/* ============================================================================
 * Timeout Configuration
 * ============================================================================
 */

void
Socket_simple_async_set_timeout (SocketSimple_Async_T async, int64_t timeout_ms)
{
  if (!async || !async->async)
    return;

  SocketAsync_set_timeout (async->async, timeout_ms);
}

int64_t
Socket_simple_async_get_timeout (SocketSimple_Async_T async)
{
  if (!async || !async->async)
    return 0;

  return SocketAsync_get_timeout (async->async);
}

int
Socket_simple_async_expire_stale (SocketSimple_Async_T async)
{
  Socket_simple_clear_error ();

  if (!async || !async->async)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid async context");
      return 0;
    }

  return SocketAsync_expire_stale (async->async);
}

/* ============================================================================
 * Backend Information
 * ============================================================================
 */

int
Socket_simple_async_is_available (SocketSimple_Async_T async)
{
  if (!async || !async->async)
    return 0;

  return SocketAsync_is_available (async->async);
}

const char *
Socket_simple_async_backend_name (SocketSimple_Async_T async)
{
  if (!async || !async->async)
    return "none";

  return SocketAsync_backend_name (async->async);
}

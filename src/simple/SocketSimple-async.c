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

struct SocketSimple_Async
{
  Arena_T arena;
  SocketAsync_T async;
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
};

static void
core_callback_wrapper (Socket_T socket, ssize_t bytes, int err, void *user_data)
{
  struct CallbackContext *ctx = (struct CallbackContext *)user_data;

  (void)socket; /* We use the simple_socket from context */

  if (ctx && ctx->user_cb)
    ctx->user_cb (ctx->simple_socket, bytes, err, ctx->user_data);

  /* Free the context after callback */
  free (ctx);
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

  TRY { arena = Arena_new (); }
  EXCEPT (Arena_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_MEMORY,
                      "Failed to create arena for async context");
    return NULL;
  }
  END_TRY;

  TRY { async = SocketAsync_new (arena); }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose ((Arena_T *)&arena);
    simple_set_error (SOCKET_SIMPLE_ERR_ASYNC, "Failed to create async context");
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

  SocketAsync_free (&(*async)->async);
  Arena_dispose (&(*async)->arena);
  free (*async);
  *async = NULL;
}

/* ============================================================================
 * Async Send/Recv Operations
 * ============================================================================
 */

unsigned
Socket_simple_async_send (SocketSimple_Async_T async,
                          SocketSimple_Socket_T socket, const void *buf,
                          size_t len, SocketSimple_AsyncCallback cb,
                          void *user_data, SocketSimple_AsyncFlags flags)
{
  return Socket_simple_async_send_timeout (async, socket, buf, len, cb,
                                           user_data, flags, 0);
}

unsigned
Socket_simple_async_recv (SocketSimple_Async_T async,
                          SocketSimple_Socket_T socket, void *buf, size_t len,
                          SocketSimple_AsyncCallback cb, void *user_data,
                          SocketSimple_AsyncFlags flags)
{
  return Socket_simple_async_recv_timeout (async, socket, buf, len, cb,
                                           user_data, flags, 0);
}

unsigned
Socket_simple_async_send_timeout (SocketSimple_Async_T async,
                                  SocketSimple_Socket_T socket, const void *buf,
                                  size_t len, SocketSimple_AsyncCallback cb,
                                  void *user_data, SocketSimple_AsyncFlags flags,
                                  int64_t timeout_ms)
{
  /* Volatile copy to survive potential longjmp in TRY/EXCEPT */
  SocketSimple_Socket_T volatile safe_socket = socket;
  Socket_T core_socket;
  struct CallbackContext *ctx;
  volatile unsigned request_id = 0;

  Socket_simple_clear_error ();

  if (!async || !async->async)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid async context");
      return 0;
    }

  core_socket = get_core_socket ((SocketSimple_Socket_T)safe_socket);
  if (!core_socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid socket (NULL or UDP not supported)");
      return 0;
    }

  if (!cb)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Callback is required");
      return 0;
    }

  /* Allocate callback context */
  ctx = calloc (1, sizeof (*ctx));
  if (!ctx)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY,
                        "Failed to allocate callback context");
      return 0;
    }

  ctx->user_cb = cb;
  ctx->user_data = user_data;
  ctx->simple_socket = (SocketSimple_Socket_T)safe_socket;

  TRY
  {
    if (timeout_ms > 0)
      {
        request_id = SocketAsync_send_timeout (
            async->async, core_socket, buf, len, core_callback_wrapper, ctx,
            simple_to_core_flags (flags), timeout_ms);
      }
    else
      {
        request_id
            = SocketAsync_send (async->async, core_socket, buf, len,
                                core_callback_wrapper, ctx,
                                simple_to_core_flags (flags));
      }
  }
  EXCEPT (SocketAsync_Failed)
  {
    free (ctx);
    simple_set_error (SOCKET_SIMPLE_ERR_ASYNC, "Failed to submit async send");
    return 0;
  }
  END_TRY;

  return request_id;
}

unsigned
Socket_simple_async_recv_timeout (SocketSimple_Async_T async,
                                  SocketSimple_Socket_T socket, void *buf,
                                  size_t len, SocketSimple_AsyncCallback cb,
                                  void *user_data, SocketSimple_AsyncFlags flags,
                                  int64_t timeout_ms)
{
  /* Volatile copy to survive potential longjmp in TRY/EXCEPT */
  SocketSimple_Socket_T volatile safe_socket = socket;
  Socket_T core_socket;
  struct CallbackContext *ctx;
  volatile unsigned request_id = 0;

  Socket_simple_clear_error ();

  if (!async || !async->async)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid async context");
      return 0;
    }

  core_socket = get_core_socket ((SocketSimple_Socket_T)safe_socket);
  if (!core_socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid socket (NULL or UDP not supported)");
      return 0;
    }

  if (!cb)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Callback is required");
      return 0;
    }

  /* Allocate callback context */
  ctx = calloc (1, sizeof (*ctx));
  if (!ctx)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY,
                        "Failed to allocate callback context");
      return 0;
    }

  ctx->user_cb = cb;
  ctx->user_data = user_data;
  ctx->simple_socket = (SocketSimple_Socket_T)safe_socket;

  TRY
  {
    if (timeout_ms > 0)
      {
        request_id = SocketAsync_recv_timeout (
            async->async, core_socket, buf, len, core_callback_wrapper, ctx,
            simple_to_core_flags (flags), timeout_ms);
      }
    else
      {
        request_id
            = SocketAsync_recv (async->async, core_socket, buf, len,
                                core_callback_wrapper, ctx,
                                simple_to_core_flags (flags));
      }
  }
  EXCEPT (SocketAsync_Failed)
  {
    free (ctx);
    simple_set_error (SOCKET_SIMPLE_ERR_ASYNC, "Failed to submit async recv");
    return 0;
  }
  END_TRY;

  return request_id;
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
  Socket_simple_clear_error ();

  if (!async || !async->async)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid async context");
      return -1;
    }

  return SocketAsync_cancel (async->async, request_id);
}

int
Socket_simple_async_cancel_all (SocketSimple_Async_T async)
{
  Socket_simple_clear_error ();

  if (!async || !async->async)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid async context");
      return -1;
    }

  return SocketAsync_cancel_all (async->async);
}

/* ============================================================================
 * Progress and Continuation
 * ============================================================================
 */

int
Socket_simple_async_get_progress (SocketSimple_Async_T async,
                                  unsigned request_id, size_t *completed,
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

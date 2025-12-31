/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_ASYNC_INCLUDED
#define SOCKETSIMPLE_ASYNC_INCLUDED

/**
 * @file SocketSimple-async.h
 * @brief Simple asynchronous I/O operations.
 *
 * Return-code based wrapper for SocketAsync. Provides async send/recv
 * with optional per-request timeouts, progress tracking, and automatic
 * partial transfer continuation.
 *
 * Example:
 * @code
 * // Create async context
 * SocketSimple_Async_T async = Socket_simple_async_new();
 * if (!async) {
 *     fprintf(stderr, "Async error: %s\n", Socket_simple_error());
 *     return 1;
 * }
 *
 * // Set global timeout (optional)
 * Socket_simple_async_set_timeout(async, 30000);  // 30 seconds
 *
 * // Submit async send
 * unsigned req_id = Socket_simple_async_send(async, sock, buf, len,
 *                                             my_callback, user_data, 0);
 * if (req_id == 0) {
 *     fprintf(stderr, "Send error: %s\n", Socket_simple_error());
 * }
 *
 * // Process completions in event loop
 * int completed = Socket_simple_async_process(async, 100);
 *
 * // Cleanup
 * Socket_simple_async_free(&async);
 * @endcode
 */

#include "SocketSimple-tcp.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

  /*============================================================================
   * Opaque Handle Types
   *============================================================================*/

  /**
   * @brief Opaque async context handle.
   */
  typedef struct SocketSimple_Async *SocketSimple_Async_T;

  /*============================================================================
   * Callback Type
   *============================================================================*/

  /**
   * @brief Async completion callback.
   *
   * @param socket Socket that completed operation.
   * @param bytes Bytes transferred (>0), or -1 on error.
   * @param err Error code (0 on success, errno value on failure).
   * @param user_data User-provided context.
   */
  typedef void (*SocketSimple_AsyncCallback) (SocketSimple_Socket_T socket,
                                              ssize_t bytes,
                                              int err,
                                              void *user_data);

  /*============================================================================
   * Flags
   *============================================================================*/

  /**
   * @brief Async operation flags.
   */
  typedef enum
  {
    SOCKET_SIMPLE_ASYNC_NONE = 0x00,    /**< No special flags */
    SOCKET_SIMPLE_ASYNC_PRIORITY = 0x01 /**< High-priority operation */
  } SocketSimple_AsyncFlags;

  /*============================================================================
   * Async Lifecycle
   *============================================================================*/

  /**
   * @brief Create a new async context.
   *
   * @return Async handle on success, NULL on error.
   *
   * Use Socket_simple_error() to get error message on failure.
   */
  extern SocketSimple_Async_T Socket_simple_async_new (void);

  /**
   * @brief Free async context.
   *
   * Cancels all pending operations and releases resources.
   * Sets *async to NULL after freeing.
   *
   * @param async Pointer to async handle.
   */
  extern void Socket_simple_async_free (SocketSimple_Async_T *async);

  /*============================================================================
   * Async Send/Recv Operations
   *============================================================================*/

  /**
   * @brief Submit async send operation.
   *
   * @param async Async context.
   * @param socket Target socket.
   * @param buf Data buffer to send.
   * @param len Length of data.
   * @param cb Completion callback (required).
   * @param user_data User data passed to callback.
   * @param flags Operation flags.
   * @return Request ID (>0) on success, 0 on error.
   *
   * Use Socket_simple_error() to get error message on failure.
   */
  extern unsigned Socket_simple_async_send (SocketSimple_Async_T async,
                                            SocketSimple_Socket_T socket,
                                            const void *buf,
                                            size_t len,
                                            SocketSimple_AsyncCallback cb,
                                            void *user_data,
                                            SocketSimple_AsyncFlags flags);

  /**
   * @brief Submit async recv operation.
   *
   * @param async Async context.
   * @param socket Target socket.
   * @param buf Receive buffer.
   * @param len Buffer length.
   * @param cb Completion callback (required).
   * @param user_data User data passed to callback.
   * @param flags Operation flags.
   * @return Request ID (>0) on success, 0 on error.
   */
  extern unsigned Socket_simple_async_recv (SocketSimple_Async_T async,
                                            SocketSimple_Socket_T socket,
                                            void *buf,
                                            size_t len,
                                            SocketSimple_AsyncCallback cb,
                                            void *user_data,
                                            SocketSimple_AsyncFlags flags);

  /**
   * @brief Submit async send with per-request timeout.
   *
   * @param async Async context.
   * @param socket Target socket.
   * @param buf Data buffer to send.
   * @param len Length of data.
   * @param cb Completion callback (required).
   * @param user_data User data passed to callback.
   * @param flags Operation flags.
   * @param timeout_ms Per-request timeout in milliseconds (0 = use global).
   * @return Request ID (>0) on success, 0 on error.
   */
  extern unsigned
  Socket_simple_async_send_timeout (SocketSimple_Async_T async,
                                    SocketSimple_Socket_T socket,
                                    const void *buf,
                                    size_t len,
                                    SocketSimple_AsyncCallback cb,
                                    void *user_data,
                                    SocketSimple_AsyncFlags flags,
                                    int64_t timeout_ms);

  /**
   * @brief Submit async recv with per-request timeout.
   *
   * @param async Async context.
   * @param socket Target socket.
   * @param buf Receive buffer.
   * @param len Buffer length.
   * @param cb Completion callback (required).
   * @param user_data User data passed to callback.
   * @param flags Operation flags.
   * @param timeout_ms Per-request timeout in milliseconds (0 = use global).
   * @return Request ID (>0) on success, 0 on error.
   */
  extern unsigned
  Socket_simple_async_recv_timeout (SocketSimple_Async_T async,
                                    SocketSimple_Socket_T socket,
                                    void *buf,
                                    size_t len,
                                    SocketSimple_AsyncCallback cb,
                                    void *user_data,
                                    SocketSimple_AsyncFlags flags,
                                    int64_t timeout_ms);

  /*============================================================================
   * Completion Processing
   *============================================================================*/

  /**
   * @brief Process pending async completions.
   *
   * Invokes callbacks for completed operations.
   *
   * @param async Async context.
   * @param timeout_ms Maximum time to wait for completions (0 = non-blocking).
   * @return Number of completions processed, or -1 on error.
   */
  extern int
  Socket_simple_async_process (SocketSimple_Async_T async, int timeout_ms);

  /*============================================================================
   * Request Management
   *============================================================================*/

  /**
   * @brief Cancel a pending async request.
   *
   * @param async Async context.
   * @param request_id ID of request to cancel.
   * @return 0 on success, -1 if request not found.
   */
  extern int
  Socket_simple_async_cancel (SocketSimple_Async_T async, unsigned request_id);

  /**
   * @brief Cancel all pending async requests.
   *
   * @param async Async context.
   * @return Number of requests cancelled.
   */
  extern int Socket_simple_async_cancel_all (SocketSimple_Async_T async);

  /*============================================================================
   * Progress and Continuation
   *============================================================================*/

  /**
   * @brief Query progress of a pending request.
   *
   * @param async Async context.
   * @param request_id ID of request to query.
   * @param completed Output: bytes completed so far.
   * @param total Output: total bytes requested.
   * @return 1 if request found, 0 if not found.
   */
  extern int Socket_simple_async_get_progress (SocketSimple_Async_T async,
                                               unsigned request_id,
                                               size_t *completed,
                                               size_t *total);

  /**
   * @brief Continue a partially completed send operation.
   *
   * Automatically calculates remaining buffer and resubmits.
   *
   * @param async Async context.
   * @param request_id ID of original request.
   * @return New request ID (>0) on success, 0 if request not found or complete.
   */
  extern unsigned Socket_simple_async_send_continue (SocketSimple_Async_T async,
                                                     unsigned request_id);

  /**
   * @brief Continue a partially completed recv operation.
   *
   * @param async Async context.
   * @param request_id ID of original request.
   * @return New request ID (>0) on success, 0 if request not found or complete.
   */
  extern unsigned Socket_simple_async_recv_continue (SocketSimple_Async_T async,
                                                     unsigned request_id);

  /*============================================================================
   * Timeout Configuration
   *============================================================================*/

  /**
   * @brief Set global request timeout.
   *
   * Requests older than this timeout will be cancelled with ETIMEDOUT.
   *
   * @param async Async context.
   * @param timeout_ms Timeout in milliseconds (0 = disable).
   */
  extern void Socket_simple_async_set_timeout (SocketSimple_Async_T async,
                                               int64_t timeout_ms);

  /**
   * @brief Get current global request timeout.
   *
   * @param async Async context.
   * @return Timeout in milliseconds (0 = disabled).
   */
  extern int64_t Socket_simple_async_get_timeout (SocketSimple_Async_T async);

  /**
   * @brief Manually expire stale (timed-out) requests.
   *
   * @param async Async context.
   * @return Number of requests expired.
   */
  extern int Socket_simple_async_expire_stale (SocketSimple_Async_T async);

  /*============================================================================
   * Backend Information
   *============================================================================*/

  /**
   * @brief Check if native async I/O is available.
   *
   * @param async Async context.
   * @return 1 if native backend (io_uring/kqueue) available, 0 if fallback
   * mode.
   */
  extern int Socket_simple_async_is_available (SocketSimple_Async_T async);

  /**
   * @brief Get name of active async backend.
   *
   * @param async Async context.
   * @return Backend name (e.g., "io_uring", "kqueue", "poll").
   */
  extern const char *
  Socket_simple_async_backend_name (SocketSimple_Async_T async);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_ASYNC_INCLUDED */

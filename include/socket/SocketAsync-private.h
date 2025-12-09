#ifndef SOCKETASYNC_PRIVATE_H_INCLUDED
#define SOCKETASYNC_PRIVATE_H_INCLUDED

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "socket/Socket.h"
#include "socket/SocketAsync.h"

/**
 * @file SocketAsync-private.h
 * @brief Private internal definitions for the SocketAsync module.
 *
 * Contains opaque structure definitions for asynchronous I/O context and request tracking.
 * Included only by implementation files (e.g., SocketAsync.c).
 * Not for public use or direct inclusion.
 *
 * @internal
 * @ingroup async_io
 * @{
 *
 * @see SocketAsync.h for public interface.
 * @see docs/ASYNC_IO.md for module overview.
 */

/**
 * @brief Internal structure for tracking asynchronous I/O requests.
 *
 * This structure manages the state of pending async send/recv operations submitted
 * via SocketAsync_send() or SocketAsync_recv().
 *
 * Fields track request metadata, buffers (which must remain valid until completion),
 * progress, and linking for hash table storage.
 *
 * @internal
 * @note Buffers (send_buf, recv_buf) must not be freed or modified until callback invocation.
 * @see SocketAsync_T for the async context that owns these requests.
 * @see SocketAsync_Callback for completion notification.
 * @see docs/ASYNC_IO.md for async operation lifecycle.
 */
struct AsyncRequest
{
  /**
   * @brief Unique request identifier.
   *
   * Assigned sequentially by SocketAsync_new_request_id().
   * Used for cancellation via SocketAsync_cancel() and internal hashing.
   * 0 is invalid.
   */
  unsigned request_id;

  /**
   * @brief Socket associated with this request.
   *
   * The target socket for the I/O operation. Must remain valid until completion.
   * @see Socket_T
   */
  Socket_T socket;

  /**
   * @brief Completion callback function.
   *
   * Invoked upon operation completion or error, from poll context.
   * @see SocketAsync_Callback
   */
  SocketAsync_Callback cb;

  /**
   * @brief User data passed to the callback.
   *
   * Opaque data provided by caller, forwarded unchanged to cb().
   */
  void *user_data;

  /**
   * @brief Type of asynchronous operation.
   *
   * Distinguishes between send and recv requests for backend-specific handling.
   */
  enum AsyncRequestType
  {
    /**
     * @brief Send operation (SocketAsync_send).
     */
    REQ_SEND,
    /**
     * @brief Receive operation (SocketAsync_recv).
     */
    REQ_RECV
  } type;

  /**
   * @brief Input buffer for send operations.
   *
   * Pointer to data to send (REQ_SEND only). Must remain valid and unmodified until callback.
   * @note For zero-copy modes, this may reference file mappings or other kernel-accessible memory.
   */
  const void *send_buf; /* For send: data to send */

  /**
   * @brief Output buffer for recv operations.
   *
   * Buffer to receive data into (REQ_RECV only). Must remain valid until callback invocation.
   * Data is written here by kernel or driver.
   * @warning Do not access or free until callback completes the request.
   */
  void *recv_buf;       /* For recv: user's buffer (must remain valid) */

  /**
   * @brief Original requested transfer length.
   *
   * Total bytes to send/recv as submitted by caller.
   * Used to track partial completions (future support).
   */
  size_t len;           /* Original length */

  /**
   * @brief Operation flags.
   *
   * Controls backend behavior (e.g., zero-copy, priority).
   * @see SocketAsync_Flags
   */
  SocketAsync_Flags flags;

  /**
   * @brief Pointer to next request in hash chain.
   *
   * For collision resolution in requests[] hash table.
   * @see request_hash()
   */
  struct AsyncRequest *next; /* Hash table chain */
};

/**
 * @brief Opaque structure representing the asynchronous I/O context.
 *
 * Manages platform-specific async backend (io_uring, kqueue AIO, or fallback),
 * request tracking hash table, mutex for thread safety, and configuration.
 *
 * @internal
 * @see SocketAsync_new() for creation.
 * @see SocketAsync_free() for destruction.
 * @see SocketPoll_get_async() for integrated poll context.
 */
struct SocketAsync_T
{
  /**
   * @brief Memory arena for internal allocations.
   *
   * Used for allocating AsyncRequest structures and other transient data.
   * Lifetime tied to context; cleared on free().
   * @see Arena_T
   */
  Arena_T arena;

  /**
   * @brief Hash table for fast request lookup by ID.
   *
   * Array of chains for O(1) average-case retrieval of pending requests.
   * Indexed by request_hash(request_id).
   * @see SOCKET_HASH_TABLE_SIZE
   * @see request_hash()
   */
  /* Request tracking */
  struct AsyncRequest *requests[SOCKET_HASH_TABLE_SIZE];

  /**
   * @brief Counter for generating unique request IDs.
   *
   * Incremented atomically under mutex to assign request_id.
   * Wraps around but skips 0.
   */
  unsigned next_request_id;

  /**
   * @brief Mutex protecting request table and ID generation.
   *
   * Ensures thread-safe submission, cancellation, and completion processing.
   * @note Recursive mutex not used; avoid reentrancy in callbacks.
   */
  pthread_mutex_t mutex;

  /**
   * @brief Platform-specific asynchronous I/O backend context.
   *
   * Conditional compilation selects appropriate fields:
   * - Linux io_uring: ring and eventfd for submission/completion queue.
   * - BSD/macOS: kqueue_fd for AIO event monitoring.
   * - Fallback: fallback_mode flag for edge-triggered polling simulation.
   *
   * Initialized in SocketAsync_new(), detecting available backend.
   * @see SocketAsync_is_available()
   * @see SocketAsync_backend_name()
   */
  /* Platform-specific async context */
#ifdef SOCKET_HAS_IO_URING
  /**
   * @brief io_uring instance for kernel async I/O.
   *
   * Submission and completion queue ring for efficient batch operations.
   * Supports zero-copy, multi-shot accepts, and linked requests.
   * @see liburing.h
   */
  struct io_uring *ring; /* io_uring ring (if available) */

  /**
   * @brief Eventfd for io_uring completion notifications.
   *
   * Polled via SocketPoll to detect when to drain completion queue.
   * @see eventfd(2)
   */
  int io_uring_fd;       /* Eventfd for completion notifications */
#elif defined(__APPLE__) || defined(__FreeBSD__)
  /**
   * @brief kqueue file descriptor for AIO events.
   *
   * Monitors AIO completion events from kernel.
   * @see kqueue(2), kevent(2)
   */
  int kqueue_fd; /* kqueue fd for AIO */
#else
  /**
   * @brief Fallback mode flag for non-async platforms.
   *
   * Indicates edge-triggered polling simulation using SocketPoll.
   * Requests are tracked but I/O performed synchronously in process_completions().
   */
  /* Fallback: edge-triggered polling */
  int fallback_mode;
#endif

  /**
   * @brief Availability flag for async backend.
   *
   * Non-zero if platform-optimized async I/O is supported and initialized.
   * Zero indicates fallback to simulated async via polling.
   * @see SocketAsync_is_available()
   */
  int available; /* Non-zero if async available */

  /**
   * @brief String identifier of the active backend.
   *
   * E.g., "io_uring", "kqueue", "edge-triggered". Read-only after init.
   * @see SocketAsync_backend_name()
   */
  const char *backend_name;
};

/** @} */ /* end of async_io private definitions */

/*
 * Note: This private header should be included in SocketAsync.c after public headers
 * to access internal structures. Public headers forward-declare types only.
 */

#endif /* SOCKETASYNC_PRIVATE_H_INCLUDED */

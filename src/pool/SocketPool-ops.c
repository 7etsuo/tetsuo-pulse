/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketPool-ops.c - Pool operations: resize, tuning, accept, async
 *
 * Part of the Socket Library
 *
 * Consolidated from:
 * - Pool resize and capacity management
 * - Pre-warming, buffer configuration, iteration
 * - Batch connection acceptance
 * - Async DNS connection preparation
 * - SYN flood protection integration
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h> /* for sched_yield */
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "core/SocketSecurity.h" /* for SocketSecurity_check_multiply */
#include "dns/SocketDNS.h"
#include "pool/SocketPool-private.h"
#include "socket/SocketCommon.h"
/* SocketUtil.h included via SocketPool-private.h */

/* SOCKET_LOG_COMPONENT defined in SocketPool-private.h */

/**
 * Default batch size for SocketPool_foreach iteration.
 * Balances lock contention vs iteration overhead.
 */
#ifndef SOCKET_POOL_FOREACH_BATCH_SIZE
#define SOCKET_POOL_FOREACH_BATCH_SIZE 100
#endif

#define T SocketPool_T

/* Forward declarations for internal functions used by helpers */
static int consume_rate_and_track_ip (T pool, const char *client_ip);

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * close_socket_safe - Close and remove socket with error handling
 * @pool: Pool instance
 * @socket: Pointer to socket to close (set to NULL on success)
 * @context: Context string for log message (e.g., "Resize", "Cleanup")
 *
 * Thread-safe: Called outside pool lock
 * Handles errors gracefully - logs at DEBUG level and continues.
 *
 * Uses shared socketpool_close_socket_safe() helper from private header.
 */
static void
close_socket_safe (T pool, Socket_T *socket, const char *context)
{
  socketpool_close_socket_safe (pool, socket, context);
}

/**
 * handle_syn_consume_failure - Handle rate/IP consumption failure for SYN
 * @protect: SYN protection instance
 * @client_ip: Client IP address for failure report
 * @client: Pointer to client socket (freed and set to NULL)
 *
 * Thread-safe: Yes
 * Consolidates the repeated pattern of reporting failure and freeing socket.
 */
static void
handle_syn_consume_failure (SocketSYNProtect_T protect, const char *client_ip,
                            Socket_T *client)
{
  SocketSYNProtect_report_failure (protect, client_ip, ECONNREFUSED);
  Socket_free (client);
}

/**
 * try_consume_and_report - Consume rate token, track IP, and report outcome
 * @pool: Pool instance
 * @protect: SYN protection instance
 * @client_ip: Client IP address
 * @report_success: If non-zero, report success to SYN protect on success
 *
 * Returns: 1 on success (rate/IP allowed), 0 on failure (limit exceeded)
 * Thread-safe: Yes - calls thread-safe consume_rate_and_track_ip
 *
 * Consolidates the two-phase check pattern used in SYN protection:
 * 1. Pre-accept: check limits (no token consumption)
 * 2. Post-accept: consume token and track IP (this function)
 */
static int
try_consume_and_report (T pool, SocketSYNProtect_T protect,
                        const char *client_ip, int report_success)
{
  if (!consume_rate_and_track_ip (pool, client_ip))
    {
      SocketSYNProtect_report_failure (protect, client_ip, ECONNREFUSED);
      return 0;
    }

  if (report_success)
    SocketSYNProtect_report_success (protect, client_ip);

  return 1;
}

/* ============================================================================
 * Pool Resize Operations
 * ============================================================================
 */

/**
 * collect_excess_connections - Collect excess active connections for closing
 * @pool: Pool instance
 * @new_maxconns: New maximum capacity
 * @excess_sockets: Output array for excess sockets (pre-allocated)
 *
 * Returns: Number of excess connections found
 * Thread-safe: Call with mutex held
 */
static size_t
collect_excess_connections (T pool, size_t new_maxconns,
                            Socket_T *excess_sockets)
{
  size_t excess_count = 0;
  size_t target;

  if (pool->count <= new_maxconns)
    return 0;

  target = pool->count - new_maxconns;

  for (size_t i = 0; i < pool->maxconns && excess_count < target; i++)
    {
      struct Connection *conn = &pool->connections[i];
      if (conn->active && conn->socket)
        excess_sockets[excess_count++] = conn->socket;
    }

  return excess_count;
}

/**
 * realloc_connections_array - Reallocate connections array
 * @pool: Pool instance
 * @new_maxconns: New size
 *
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Call with mutex held
 *
 * Security: Checks for integer overflow before size calculation to prevent
 * heap buffer overflow from undersized allocation.
 */
static int
realloc_connections_array (T pool, size_t new_maxconns)
{
  struct Connection *new_connections;
  size_t alloc_size;

  /* Security: Check for integer overflow before multiplication */
  if (new_maxconns > SIZE_MAX / sizeof (struct Connection))
    {
      SOCKET_ERROR_MSG ("Overflow in connections array size calculation");
      return -1;
    }

  alloc_size = new_maxconns * sizeof (struct Connection);
  new_connections = realloc (pool->connections, alloc_size);
  if (!new_connections)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot reallocate connections array");
      return -1;
    }

  pool->connections = new_connections;
  return 0;
}

/**
 * rehash_active_connections - Rebuild hash table after array realloc
 * @pool: Pool instance
 * @valid_count: Number of valid slots to scan (min of old/new size)
 *
 * Thread-safe: Call with mutex held
 * Clears hash_table and re-inserts all active connections.
 */
static void
rehash_active_connections (T pool, size_t valid_count)
{
  memset (pool->hash_table, 0,
          sizeof (pool->hash_table[0]) * SOCKET_HASH_SIZE);

  for (size_t i = 0; i < valid_count; i++)
    {
      Connection_T conn = &pool->connections[i];
      if (conn->active && conn->socket)
        insert_into_hash_table (pool, conn, conn->socket);
    }
}

/**
 * rebuild_active_list - Rebuild active list after array realloc
 * @pool: Pool instance
 * @valid_count: Number of valid slots to scan (min of old/new size)
 *
 * Thread-safe: Call with mutex held
 * Clears active list and re-links all active connections.
 * Must be called after rehash_active_connections during resize.
 */
static void
rebuild_active_list (T pool, size_t valid_count)
{
  pool->active_head = NULL;
  pool->active_tail = NULL;

  for (size_t i = 0; i < valid_count; i++)
    {
      Connection_T conn = &pool->connections[i];
      if (conn->active)
        {
          /* Clear stale pointers before re-adding */
          conn->active_prev = NULL;
          conn->active_next = NULL;
          add_to_active_list (pool, conn);
        }
    }
}

/**
 * relink_free_slots - Relink free slots to free_list
 * @pool: Pool instance
 * @maxconns: Limit for scanning (new effective max)
 *
 * Thread-safe: Call with mutex held
 * Scans slots, initializes and links only inactive (free) slots.
 */
static void
relink_free_slots (T pool, size_t maxconns)
{
  pool->free_list = NULL;

  for (size_t i = 0; i < maxconns; i++)
    {
      Connection_T conn = &pool->connections[i];
      if (!conn->active)
        {
          SocketPool_connections_initialize_slot (conn);
          conn->free_next = pool->free_list;
          pool->free_list = conn;
        }
    }
}

/**
 * initialize_new_slots - Initialize newly allocated connection slots
 * @pool: Pool instance
 * @old_maxconns: Old size
 * @new_maxconns: New size
 *
 * Thread-safe: Call with mutex held
 */
static void
initialize_new_slots (T pool, size_t old_maxconns, size_t new_maxconns)
{
  for (size_t i = old_maxconns; i < new_maxconns; i++)
    {
      struct Connection *conn = &pool->connections[i];
      SocketPool_connections_initialize_slot (conn);

      if (SocketPool_connections_alloc_buffers (pool->arena, pool->bufsize,
                                                conn)
          == 0)
        {
          conn->free_next = pool->free_list;
          pool->free_list = conn;
        }
    }
}

/**
 * close_excess_sockets - Close and remove excess sockets
 * @pool: Pool instance
 * @excess_sockets: Array of sockets to close
 * @excess_count: Number of sockets
 *
 * Thread-safe: Called outside lock
 * Handles errors gracefully - logs and continues on failure.
 */
static void
close_excess_sockets (T pool, Socket_T *excess_sockets, size_t excess_count)
{
  /* volatile prevents clobbering when close_socket_safe may use setjmp */
  volatile size_t i;
  for (i = 0; i < excess_count; i++)
    {
      if (excess_sockets[i])
        close_socket_safe (pool, &excess_sockets[i], "Resize");
    }
}

/**
 * allocate_excess_buffer - Allocate buffer for excess sockets
 * @excess_count: Number needed
 *
 * Returns: Allocated buffer or NULL
 */
/* Inlined allocate_excess_buffer into handle_shrink_excess for simplicity */

/**
 * handle_shrink_excess - Handle excess connections when shrinking
 * @pool: Pool instance
 * @new_maxconns: New capacity
 *
 * Thread-safe: Releases and reacquires mutex as needed
 * Raises: SocketPool_Failed on allocation failure
 *
 * Note: Uses actual collected count rather than expected excess_count to handle
 * edge cases where pool->count may be temporarily out of sync with actual
 * active connections (e.g., during concurrent operations or after exceptions).
 */
static void
handle_shrink_excess (T pool, size_t new_maxconns)
{
  size_t excess_count;
  Socket_T *excess_sockets;
  size_t collected;

  excess_count = pool->count > new_maxconns ? (pool->count - new_maxconns) : 0;

  if (excess_count == 0)
    return;

  excess_sockets = calloc (excess_count, sizeof (Socket_T));
  if (!excess_sockets)
    {
      POOL_UNLOCK (pool);
      RAISE_POOL_MSG (SocketPool_Failed,
                      SOCKET_ENOMEM ": Cannot allocate excess buffer");
    }

  collected = collect_excess_connections (pool, new_maxconns, excess_sockets);

  /* Use actual collected count - pool->count may differ from actual active
   * connections in edge cases (e.g., after exceptions during add/remove).
   * Log if mismatch detected for debugging but don't assert. */
  if (collected != excess_count)
    {
      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "Shrink: expected %zu excess, found %zu (count=%zu)",
                       excess_count, collected, pool->count);
    }

  POOL_UNLOCK (pool);
  close_excess_sockets (pool, excess_sockets, collected);
  free (excess_sockets);
  POOL_LOCK (pool);
}

/**
 * SocketPool_resize - Resize pool capacity at runtime
 * @pool: Pool instance
 * @new_maxconns: New maximum connection capacity
 *
 * Raises: SocketPool_Failed on error
 * Thread-safe: Yes - uses internal mutex
 *
 * If a resize callback is set, it is invoked after successful resize.
 */
void
SocketPool_resize (T pool, size_t new_maxconns)
{
  size_t old_maxconns;
  size_t valid_count;
  SocketPool_ResizeCallback cb = NULL;
  void *cb_data = NULL;
  SocketPool_PreResizeCallback pre_cb = NULL;
  void *pre_cb_data = NULL;

  assert (pool);

  new_maxconns = socketpool_enforce_max_connections (new_maxconns);

  POOL_LOCK (pool);

  old_maxconns = pool->maxconns;

  if (new_maxconns == old_maxconns)
    {
      POOL_UNLOCK (pool);
      return;
    }

  /* Capture pre-resize callback info BEFORE any modifications */
  pre_cb = pool->pre_resize_cb;
  pre_cb_data = pool->pre_resize_cb_data;

  /* CRITICAL: Invoke pre-resize callback WITH mutex held so external
   * code can safely clear cached Connection_T pointers before they
   * become invalid due to realloc. The callback must be quick and
   * MUST NOT call SocketPool_add/remove/get (will deadlock). */
  if (pre_cb)
    {
      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "Pool pre-resize notification: %zu -> %zu connections",
                       old_maxconns, new_maxconns);
      pre_cb (pool, old_maxconns, new_maxconns, pre_cb_data);
    }

  if (new_maxconns < old_maxconns)
    handle_shrink_excess (pool, new_maxconns);

  if (realloc_connections_array (pool, new_maxconns) != 0)
    {
      POOL_UNLOCK (pool);
      RAISE_POOL_ERROR (SocketPool_Failed);
    }

  /* Rehash only valid slots: min of old and new size.
   * When growing, new slots are uninitialized until initialize_new_slots.
   * When shrinking, array was truncated to new_maxconns. */
  valid_count
      = old_maxconns < new_maxconns ? old_maxconns : new_maxconns;
  rehash_active_connections (pool, valid_count);
  rebuild_active_list (pool, valid_count);

  if (new_maxconns > old_maxconns)
    initialize_new_slots (pool, old_maxconns, new_maxconns);
  else
    relink_free_slots (pool, new_maxconns);

  pool->maxconns = new_maxconns;

  /* Capture callback info before releasing lock */
  cb = pool->resize_cb;
  cb_data = pool->resize_cb_data;

  POOL_UNLOCK (pool);

  /* Invoke resize callback outside lock to prevent deadlock */
  if (cb)
    {
      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "Pool resized from %zu to %zu connections",
                       old_maxconns, new_maxconns);
      cb (pool, old_maxconns, new_maxconns, cb_data);
    }
}

/* ============================================================================
 * Pool Tuning Operations
 * ============================================================================
 */

/**
 * SocketPool_prewarm - Pre-allocate buffers for percentage of free slots
 * @pool: Pool instance
 * @percentage: Percentage of free slots to pre-warm (0-100)
 *
 * Thread-safe: Yes - uses internal mutex
 */
void
SocketPool_prewarm (T pool, int percentage)
{
  size_t prewarm_count;
  size_t allocated = 0;
  size_t tmp;

  assert (pool);
  assert (percentage >= 0 && percentage <= 100);

  POOL_LOCK (pool);

  if (!SocketSecurity_check_multiply (pool->maxconns, (size_t)percentage, &tmp)
      || tmp / SOCKET_PERCENTAGE_DIVISOR > pool->maxconns - pool->count)
    {
      prewarm_count = 0; /* Safe fallback */
      SOCKET_LOG_WARN_MSG (
          "Prewarm calculation overflow or exceeds available slots; skipping");
    }
  else
    {
      prewarm_count = tmp / SOCKET_PERCENTAGE_DIVISOR;
    }

  /* Safer: iterate by index over the authoritative connections array
   * to avoid following possibly-stale pointers in free_list.
   * This prevents heap-use-after-free if the array is reallocated elsewhere.
   */
  for (size_t i = 0; i < pool->maxconns && allocated < prewarm_count; i++)
    {
      struct Connection *c = &pool->connections[i];
      /* Only prewarm truly free slots (inactive and no buffers allocated) */
      if (!c->active && !c->inbuf && !c->outbuf)
        {
          if (SocketPool_connections_alloc_buffers (pool->arena, pool->bufsize,
                                                    c)
              == 0)
            allocated++;
        }
    }

  POOL_UNLOCK (pool);
}

/**
 * SocketPool_set_bufsize - Set buffer size for future connections
 * @pool: Pool instance
 * @new_bufsize: New buffer size in bytes
 *
 * Thread-safe: Yes - uses internal mutex
 */
void
SocketPool_set_bufsize (T pool, size_t new_bufsize)
{
  assert (pool);

  new_bufsize = socketpool_enforce_buffer_size (new_bufsize);

  POOL_LOCK (pool);
  pool->bufsize = new_bufsize;
  POOL_UNLOCK (pool);
}

/**
 * SocketPool_count - Get active connection count
 * @pool: Pool instance
 *
 * Returns: Number of active connections
 * Thread-safe: Yes - protected by internal mutex
 */
size_t
SocketPool_count (T pool)
{
  size_t count;

  assert (pool);

  POOL_LOCK (pool);
  count = pool->count;
  POOL_UNLOCK (pool);

  return count;
}

/**
 * SocketPool_foreach - Iterate over connections
 * @pool: Pool instance
 * @func: Callback function
 * @arg: User data for callback
 *
 * Calls func for each active connection.
 * Thread-safe: Yes - holds mutex during iteration with periodic yielding
 * Performance: O(active_count) - iterates only active connections via linked list
 * Warning: Callback must not modify pool structure
 *
 * Note: Yields lock every SOCKET_POOL_FOREACH_BATCH_SIZE iterations to
 * reduce contention on large pools.
 */
void
SocketPool_foreach (T pool, void (*func) (Connection_T, void *), void *arg)
{
  Connection_T conn;
  Connection_T next;
  size_t batch_count;

  assert (pool);
  assert (func);

  POOL_LOCK (pool);

  conn = pool->active_head;
  batch_count = 0;

  while (conn)
    {
      /* Cache next pointer before callback (callback might modify state) */
      next = conn->active_next;

      func (conn, arg);
      batch_count++;

      /* Yield lock periodically to reduce contention */
      if (batch_count >= SOCKET_POOL_FOREACH_BATCH_SIZE && next)
        {
          POOL_UNLOCK (pool);
          POOL_LOCK (pool);
          batch_count = 0;
        }

      conn = next;
    }

  POOL_UNLOCK (pool);
}

/**
 * SocketPool_find - Find first connection matching predicate
 * @pool: Pool instance
 * @predicate: Callback that returns non-zero for matching connections
 * @userdata: User data passed to predicate
 *
 * Returns: First matching connection or NULL if none found
 * Thread-safe: Yes - holds mutex during search
 * Complexity: O(active_count) - iterates only active connections via linked list
 */
Connection_T
SocketPool_find (T pool, SocketPool_Predicate predicate, void *userdata)
{
  Connection_T result = NULL;
  Connection_T conn;

  assert (pool);
  assert (predicate);

  POOL_LOCK (pool);

  for (conn = pool->active_head; conn; conn = conn->active_next)
    {
      if (predicate (conn, userdata))
        {
          result = conn;
          break;
        }
    }

  POOL_UNLOCK (pool);
  return result;
}

/**
 * SocketPool_filter - Find all connections matching predicate
 * @pool: Pool instance
 * @predicate: Callback that returns non-zero for matching connections
 * @userdata: User data passed to predicate
 * @results: Array to receive matching connections
 * @max_results: Maximum number of results to return
 *
 * Returns: Number of matching connections found
 * Thread-safe: Yes - holds mutex during search
 * Complexity: O(active_count) - iterates only active connections via linked list
 */
size_t
SocketPool_filter (T pool, SocketPool_Predicate predicate, void *userdata,
                   Connection_T *results, size_t max_results)
{
  size_t found = 0;
  Connection_T conn;

  assert (pool);
  assert (predicate);
  assert (results || max_results == 0);

  if (max_results == 0)
    return 0;

  POOL_LOCK (pool);

  for (conn = pool->active_head; conn && found < max_results;
       conn = conn->active_next)
    {
      if (predicate (conn, userdata))
        results[found++] = conn;
    }

  POOL_UNLOCK (pool);
  return found;
}

/* ============================================================================
 * Batch Accept Operations
 * ============================================================================
 */

/**
 * accept_connection_direct - Accept connection directly using accept4/accept
 * @server_fd: Server socket file descriptor
 *
 * Returns: New file descriptor or -1 on error/would block
 * Thread-safe: Yes - pure system call
 * Note: Uses accept4() with SOCK_CLOEXEC | SOCK_NONBLOCK on Linux,
 * falls back to accept() + fcntl() on other platforms.
 */
static int
accept_connection_direct (int server_fd)
{
  int newfd;
  int flags;

#if SOCKET_HAS_ACCEPT4 && defined(SOCK_NONBLOCK)
  newfd = accept4 (server_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
#elif SOCKET_HAS_ACCEPT4
  newfd = accept4 (server_fd, NULL, NULL, SOCK_CLOEXEC);
#else
  newfd = accept (server_fd, NULL, NULL);
#endif

  if (newfd < 0)
    return -1;

#if !SOCKET_HAS_ACCEPT4 || !defined(SOCK_NONBLOCK)
  if (SocketCommon_setcloexec (newfd, 1) < 0)
    {
      SAFE_CLOSE (newfd);
      return -1;
    }

  flags = fcntl (newfd, F_GETFL, 0);
  if (flags >= 0)
    fcntl (newfd, F_SETFL, flags | O_NONBLOCK);
#else
  (void)flags; /* Suppress unused warning when accept4 is available */
#endif

  return newfd;
}

/**
 * validate_batch_params - Validate batch accept parameters
 * @pool: Pool instance
 * @server: Server socket
 * @max_accepts: Maximum to accept
 * @accepted_capacity: Capacity of accepted array
 * @accepted: Output array
 *
 * Returns: 1 if valid, 0 if invalid
 *//* Inlined validate_batch_params into SocketPool_accept_batch for simplicity */
/**
 * get_available_slots - Get available pool slots
 * @pool: Pool instance
 *
 * Returns: Number of available slots (>= 0)
 * Thread-safe: Yes - uses internal mutex
 *//* Inlined get_available_slots into SocketPool_accept_batch for simplicity */
/**
 * wrap_fd_as_socket - Create Socket_T from file descriptor
 * @newfd: File descriptor to wrap
 *
 * Returns: Socket_T on success, NULL on failure (fd closed on error)
 */
static Socket_T
wrap_fd_as_socket (int newfd)
{
  volatile Socket_T sock = NULL;

  TRY { sock = Socket_new_from_fd (newfd); }
  EXCEPT (Socket_Failed)
  {
    SAFE_CLOSE (newfd);
    return NULL;
  }
  END_TRY;

  return sock;
}

/**
 * try_add_socket_to_pool - Add socket to pool
 * @pool: Pool instance
 * @sock: Socket to add
 *
 * Returns: 1 on success, 0 on failure (socket freed on error)
 */
static int
try_add_socket_to_pool (T pool, Socket_T *sock)
{
  const Connection_T conn = SocketPool_add (pool, *sock);
  if (!conn)
    {
      Socket_free (sock);
      return 0;
    }
  return 1;
}

/**
 * accept_one_connection - Accept and add one connection
 * @pool: Pool instance
 * @server_fd: Server file descriptor
 * @accepted: Output socket pointer
 * @count: Current accepted count (for error messages)
 *
 * Returns: 1 on success, 0 on would-block, -1 on error
 */
static int
accept_one_connection (T pool, int server_fd, Socket_T *accepted, int count)
{
  int newfd;
  Socket_T sock;

  newfd = accept_connection_direct (server_fd);
  if (newfd < 0)
    {
      if (errno != EAGAIN && errno != EWOULDBLOCK)
        SOCKET_ERROR_MSG ("accept() failed (accepted %d so far)", count);
      return 0;
    }

  sock = wrap_fd_as_socket (newfd);
  if (!sock)
    return -1;

  if (!try_add_socket_to_pool (pool, &sock))
    return -1;

  *accepted = sock;
  return 1;
}

/**
 * SocketPool_accept_batch - Accept multiple connections from server socket
 * @pool: Pool instance
 * @server: Server socket to accept from (must be listening and non-blocking)
 * @max_accepts: Maximum number of connections to accept
 *               (1-SOCKET_POOL_MAX_BATCH_ACCEPTS)
 * @accepted_capacity: Capacity of the accepted array (must >= max_accepts)
 * @accepted: Output array of accepted sockets (pre-allocated with given
 * capacity)
 *
 * Returns: Number of connections actually accepted (0 to max_accepts)
 * Raises: SocketPool_Failed on error
 * Thread-safe: Yes - uses internal mutex
 *
 * Accepts up to max_accepts connections from server socket in a single call.
 * Uses accept4() on Linux (SOCK_CLOEXEC | SOCK_NONBLOCK) for efficiency.
 * Falls back to accept() + fcntl() on other platforms.
 * All accepted sockets are automatically added to the pool.
 */
int
SocketPool_accept_batch (T pool, Socket_T server, int max_accepts,
                         size_t accepted_capacity, Socket_T *accepted)
{
  int count = 0;
  int limit;
  int server_fd;
  int result;

  if (!pool || !server || !accepted)
    return 0;

  if (max_accepts <= 0 || max_accepts > SOCKET_POOL_MAX_BATCH_ACCEPTS)
    {
      SOCKET_ERROR_MSG ("Invalid max_accepts %d (must be 1-%d)", max_accepts,
                        SOCKET_POOL_MAX_BATCH_ACCEPTS);
      return 0;
    }

  if ((size_t)max_accepts > accepted_capacity)
    {
      SOCKET_ERROR_MSG ("accepted_capacity %zu too small for max_accepts %d",
                        accepted_capacity, max_accepts);
      return 0;
    }

  POOL_LOCK (pool);
  int available = (int)(pool->maxconns - pool->count);
  POOL_UNLOCK (pool);
  limit = available > 0 ? available : 0;
  if (limit <= 0)
    return 0;

  if (max_accepts < limit)
    limit = max_accepts;

  server_fd = Socket_fd (server);

  for (int i = 0; i < limit; i++)
    {
      result = accept_one_connection (pool, server_fd, &accepted[count], count);
      if (result <= 0)
        break;
      count++;
    }

  return count;
}

/* ============================================================================
 * Async Connection Preparation
 * ============================================================================
 */

/**
 * validate_prepare_params - Validate parameters for prepare_connection
 * @pool: Pool instance
 * @dns: DNS resolver
 * @host: Target hostname
 * @port: Target port
 * @out_socket: Output socket pointer
 * @out_req: Output request pointer
 *
 * Raises: SocketPool_Failed on invalid parameters
 */
static void
validate_prepare_params (T pool, SocketDNS_T dns, const char *host, int port,
                         Socket_T *out_socket, Request_T *out_req)
{
  if (!pool || !dns || !host || !SOCKET_VALID_PORT (port) || !out_socket
      || !out_req)
    RAISE_POOL_MSG (SocketPool_Failed,
                    "Invalid parameters for prepare_connection");
}

/**
 * create_pool_socket - Create and configure socket for pool use
 *
 * Returns: Configured socket
 * Raises: SocketPool_Failed on error
 *
 * Note: Uses AF_INET by default. For IPv6-only connections, the socket
 * family will be updated during Socket_connect_with_addrinfo if the
 * resolved address is IPv6 and the connection attempt requires it.
 */
static Socket_T
create_pool_socket (void)
{
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  if (!socket)
    RAISE_POOL_MSG (SocketPool_Failed, "Failed to create socket for pool");

  Socket_setnonblocking (socket);
  Socket_setreuseaddr (socket);

  return socket;
}

/**
 * apply_pool_timeouts - Apply default timeouts to socket
 * @socket: Socket to configure
 */
static void
apply_pool_timeouts (Socket_T socket)
{
  SocketTimeouts_T timeouts;
  Socket_timeouts_getdefaults (&timeouts);
  Socket_timeouts_set (socket, &timeouts);
}

/**
 * start_async_connect - Start async DNS resolution and connect
 * @dns: DNS resolver
 * @socket: Socket to connect
 * @host: Target hostname
 * @port: Target port
 *
 * Returns: DNS request handle
 * Raises: SocketPool_Failed on error
 */
static Request_T
start_async_connect (SocketDNS_T dns, Socket_T socket, const char *host,
                     int port)
{
  Request_T req = Socket_connect_async (dns, socket, host, port);
  if (!req)
    RAISE_POOL_MSG (SocketPool_Failed, "Failed to start async connect");
  return req;
}

/**
 * SocketPool_prepare_connection - Prepare async connection using DNS
 * @pool: Pool instance (used for configuration)
 * @dns: DNS resolver instance
 * @host: Remote hostname or IP
 * @port: Remote port (1-65535)
 * @out_socket: Output - new Socket_T instance
 * @out_req: Output - SocketDNS_Request_T for monitoring
 *
 * Returns: 0 on success, -1 on error
 * Raises: SocketPool_Failed on error
 * Thread-safe: Yes
 *
 * Creates a new Socket_T, configures with pool defaults, starts async DNS.
 * User must monitor out_req, then call Socket_connect_with_addrinfo() and
 * SocketPool_add() on completion.
 */
int
SocketPool_prepare_connection (T pool, SocketDNS_T dns, const char *host,
                               int port, Socket_T *out_socket,
                               Request_T *out_req)
{
  Socket_T socket = NULL;

  validate_prepare_params (pool, dns, host, port, out_socket, out_req);

  TRY
  {
    socket = create_pool_socket ();
    apply_pool_timeouts (socket);
    *out_req = start_async_connect (dns, socket, host, port);
    *out_socket = socket;
  }
  EXCEPT (Socket_Failed)
  {
    if (socket)
      Socket_free (&socket);
    RERAISE;
  }
  END_TRY;

  return 0;
}

/* ============================================================================
 * Async Connect with Callback
 * ============================================================================
 */

/* AsyncConnectContext structure is defined in SocketPool-private.h */

/**
 * alloc_async_context - Allocate async connect context
 * @pool: Pool instance
 *
 * Returns: New context or NULL on failure
 */
static AsyncConnectContext_T
alloc_async_context (T pool)
{
  return ALLOC (pool->arena, sizeof (struct AsyncConnectContext));
}

/**
 * check_async_limit - Check if async pending limit reached
 * @pool: Pool instance (read-only access)
 *
 * Returns: 1 if under limit, 0 if limit reached
 * Thread-safe: Call with mutex held
 *
 * Security: Prevents resource exhaustion from excessive concurrent
 * async connect operations.
 */
static int
check_async_limit (const SocketPool_T pool)
{
  return pool->async_pending_count < SOCKET_POOL_MAX_ASYNC_PENDING;
}

/**
 * add_async_context - Add context to pool's list
 * @pool: Pool instance
 * @ctx: Context to add
 *
 * Returns: 1 on success, 0 if limit reached
 * Thread-safe: Call with mutex held
 *
 * Security: Enforces SOCKET_POOL_MAX_ASYNC_PENDING limit to prevent
 * resource exhaustion attacks via excessive concurrent connections.
 */
static int
add_async_context (T pool, AsyncConnectContext_T ctx)
{
  if (!check_async_limit (pool))
    return 0;

  ctx->next = pool->async_ctx;
  pool->async_ctx = ctx;
  pool->async_pending_count++;
  return 1;
}

/**
 * remove_async_context - Remove context from pool's list
 * @pool: Pool instance
 * @ctx: Context to remove
 *
 * Thread-safe: Call with mutex held
 */
static void
remove_async_context (T pool, AsyncConnectContext_T ctx)
{
  AsyncConnectContext_T *pp = &pool->async_ctx;
  while (*pp)
    {
      if (*pp == ctx)
        {
          *pp = ctx->next;
          pool->async_pending_count--;
          return;
        }
      pp = &(*pp)->next;
    }
}

/**
 * get_or_create_dns - Get or lazily create pool's DNS resolver
 * @pool: Pool instance
 *
 * Returns: DNS resolver
 * Raises: SocketPool_Failed on error
 * Thread-safe: Call with mutex held
 */
static SocketDNS_T
get_or_create_dns (T pool)
{
  if (!pool->dns)
    {
      TRY { pool->dns = SocketDNS_new (); }
      EXCEPT (SocketDNS_Failed)
      {
        RAISE_POOL_MSG (SocketPool_Failed,
                        "Failed to create DNS resolver for pool");
      }
      END_TRY;
    }
  return pool->dns;
}

/**
 * async_connect_dns_callback - Callback for DNS completion
 * @req: DNS request handle (unused)
 * @result: Resolved address or NULL on error
 * @error: Error code (0 on success)
 * @data: AsyncConnectContext
 */
static void
async_connect_dns_callback (Request_T req, struct addrinfo *result,
                            int error, void *data)
{
  AsyncConnectContext_T ctx = data;
  T pool = ctx->pool;
  volatile Connection_T conn = NULL;
  volatile int callback_error = error;

  /* Copy error parameter to volatile local to prevent clobbering by longjmp */
  (void)error;

  (void)req; /* Unused parameter */

  if (error != 0 || result == NULL)
    {
      /* DNS resolution failed - free the socket that was allocated */
      if (ctx->socket)
        Socket_free (&ctx->socket);
      callback_error = error ? error : EAI_FAIL;
      goto invoke_callback;
    }

  /* Try to connect and add to pool */
  TRY
  {
    Socket_connect_with_addrinfo (ctx->socket, result);
    conn = SocketPool_add (pool, ctx->socket);
    if (!conn)
      {
        callback_error = ENOSPC; /* Pool full */
        Socket_free (&ctx->socket);
      }
  }
  EXCEPT (Socket_Failed)
  {
    callback_error = Socket_geterrno () ? Socket_geterrno () : ECONNREFUSED;
    Socket_free (&ctx->socket);
  }
  END_TRY;

  SocketCommon_free_addrinfo (result);

invoke_callback:
  /* Remove context from list */
  POOL_LOCK (pool);
  remove_async_context (pool, ctx);
  POOL_UNLOCK (pool);

  /* Invoke user callback */
  if (ctx->cb)
    ctx->cb (conn, callback_error, ctx->user_data);
}

/**
 * validate_connect_async_params - Validate connect_async parameters
 * @pool: Pool instance
 * @host: Target hostname
 * @port: Target port
 * @callback: User callback
 *
 * Raises: SocketPool_Failed on invalid parameters
 */
static void
validate_connect_async_params (T pool, const char *host, int port,
                               SocketPool_ConnectCallback callback)
{
  if (!pool || !host || !SOCKET_VALID_PORT (port))
    RAISE_POOL_MSG (SocketPool_Failed, "Invalid parameters for connect_async");
  (void)callback; /* Callback may be NULL for poll-mode */
}

/**
 * SocketPool_connect_async - Create async connection to remote host
 * @pool: Pool instance
 * @host: Remote hostname or IP address
 * @port: Remote port number
 * @callback: Completion callback
 * @data: User data passed to callback
 *
 * Returns: SocketDNS_Request_T for monitoring completion
 * Raises: SocketPool_Failed on invalid params or allocation error
 * Thread-safe: Yes
 *
 * Starts async DNS resolution + connect + pool add. On completion:
 * - Success: callback(conn, 0, data) with Connection_T added to pool
 * - Failure: callback(NULL, error_code, data)
 */
Request_T
SocketPool_connect_async (T pool, const char *host, int port,
                          SocketPool_ConnectCallback callback, void *data)
{
  SocketDNS_T dns;
  volatile Socket_T socket = NULL;
  AsyncConnectContext_T ctx = NULL;
  volatile Request_T req = NULL;

  validate_connect_async_params (pool, host, port, callback);

  POOL_LOCK (pool);

  TRY
  {
    dns = get_or_create_dns (pool);
    ctx = alloc_async_context (pool);
    if (!ctx)
      RAISE_POOL_MSG (SocketPool_Failed,
                      SOCKET_ENOMEM ": Cannot allocate async context");

    socket = create_pool_socket ();
    apply_pool_timeouts (socket);

    /* Initialize context BEFORE DNS resolve - callback may fire immediately
     * for IP addresses that don't need actual DNS lookup (e.g. "127.0.0.1") */
    ctx->pool = pool;
    ctx->socket = socket;
    ctx->cb = callback;
    ctx->user_data = data;
    ctx->next = NULL;

    /* Security: Check async pending limit before starting DNS */
    if (!add_async_context (pool, ctx))
      RAISE_POOL_MSG (SocketPool_Failed,
                      "Async connect limit reached (%d pending)",
                      SOCKET_POOL_MAX_ASYNC_PENDING);

    req = SocketDNS_resolve (dns, host, port, async_connect_dns_callback, ctx);
    if (!req)
      {
        /* Remove context from list since DNS resolve failed */
        remove_async_context (pool, ctx);
        RAISE_POOL_MSG (SocketPool_Failed, "Failed to start DNS resolution");
      }

    /* Store request handle after successful DNS resolve */
    ctx->req = req;
  }
  ELSE
  {
    /* Cleanup on any exception (Socket_Failed or SocketPool_Failed) */
    if (ctx && ctx->socket)
      {
        /* Context was added to list - remove it first */
        remove_async_context (pool, ctx);
        ctx->socket = NULL;
      }
    if (socket)
      Socket_free ((Socket_T *)&socket);
    POOL_UNLOCK (pool);
    RERAISE;
  }
  END_TRY;

  POOL_UNLOCK (pool);
  return req;
}

/* ============================================================================
 * SYN Flood Protection
 * ============================================================================
 */

/**
 * SocketPool_set_syn_protection - Enable SYN flood protection for pool
 * @pool: Pool instance
 * @protect: SYN protection instance (NULL to disable)
 *
 * Thread-safe: Yes
 */
void
SocketPool_set_syn_protection (T pool, SocketSYNProtect_T protect)
{
  assert (pool);

  POOL_LOCK (pool);
  pool->syn_protect = protect;
  POOL_UNLOCK (pool);
}

/**
 * SocketPool_get_syn_protection - Get current SYN protection module
 * @pool: Pool instance
 *
 * Returns: Current SYN protection instance, or NULL if disabled
 * Thread-safe: Yes
 */
SocketSYNProtect_T
SocketPool_get_syn_protection (T pool)
{
  SocketSYNProtect_T protect;

  assert (pool);

  POOL_LOCK (pool);
  protect = pool->syn_protect;
  POOL_UNLOCK (pool);

  return protect;
}

/**
 * apply_syn_throttle - Apply throttle delay if needed
 * @action: SYN protection action
 * @protect: Protection instance (for config)
 *
 * Blocks briefly for throttled connections to slow down attack rate.
 * Uses sched_yield() to minimize CPU waste during delay.
 */
static void
apply_syn_throttle (SocketSYN_Action action, SocketSYNProtect_T protect)
{
  int64_t target;

  if (action != SYN_ACTION_THROTTLE || protect == NULL)
    return;

  /* Apply throttle delay using default config value */
  target = Socket_get_monotonic_ms () + SOCKET_SYN_DEFAULT_THROTTLE_DELAY_MS;
  while (Socket_get_monotonic_ms () < target)
    sched_yield ();
}

/**
 * apply_syn_challenge - Apply TCP_DEFER_ACCEPT for challenged connections
 * @socket: Accepted socket
 * @action: SYN protection action
 * @protect: Protection instance (for config)
 */
static void
apply_syn_challenge (Socket_T socket, SocketSYN_Action action,
                     SocketSYNProtect_T protect)
{
  if (action != SYN_ACTION_CHALLENGE || protect == NULL || socket == NULL)
    return;

  /* Note: TCP_DEFER_ACCEPT is typically set on listening socket, but
   * for per-connection challenge we apply it to accepted socket to
   * ensure data is received before proceeding. This is less effective
   * than listener-level defer but still adds a challenge. */
  TRY { Socket_setdeferaccept (socket, SOCKET_SYN_DEFAULT_DEFER_SEC); }
  ELSE
  {
    /* Ignore failures - best effort protection */
    SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                     "SYN challenge: TCP_DEFER_ACCEPT failed (continuing)");
  }
  END_TRY;
}

/**
 * check_pre_accept_limits - Check rate and pool limits BEFORE accepting
 * @pool: Pool instance
 * @protect_out: Output - SYN protection instance
 *
 * Returns: 1 if accepting is allowed, 0 if rate limited or draining
 * Thread-safe: Yes - acquires pool mutex
 *
 * Security: Checks limits BEFORE accepting to prevent TOCTOU race where
 * connections are accepted then immediately closed, wasting resources.
 *
 * This is Phase 1 of the two-phase rate check pattern:
 * - Phase 1 (this function): Pre-accept check - does NOT consume token
 * - Phase 2 (consume_rate_and_track_ip): Post-accept consume token + track IP
 *
 * @see consume_rate_and_track_ip() for Phase 2
 */
static int
check_pre_accept_limits (T pool, SocketSYNProtect_T *protect_out)
{
  int accepting;
  int rate_ok;

  POOL_LOCK (pool);

  /* Capture SYN protect instance */
  if (protect_out)
    *protect_out = pool->syn_protect;

  /* Check pool state first */
  accepting = (atomic_load_explicit (&pool->state, memory_order_acquire)
               == POOL_STATE_RUNNING);
  if (!accepting)
    {
      POOL_UNLOCK (pool);
      return 0;
    }

  /* Check rate limit (does NOT consume token - just checks availability) */
  rate_ok = (!pool->conn_limiter
             || SocketRateLimit_available (pool->conn_limiter) > 0);

  POOL_UNLOCK (pool);

  return rate_ok;
}

/**
 * consume_rate_and_track_ip - Consume rate token and track IP after accept
 * @pool: Pool instance
 * @client_ip: Client IP address
 *
 * Returns: 1 if successful, 0 if rate/IP limit exceeded
 * Thread-safe: Yes - acquires pool mutex
 *
 * This is Phase 2 of the two-phase rate check pattern:
 * - Phase 1 (check_pre_accept_limits): Pre-accept check - does NOT consume
 * token
 * - Phase 2 (this function): Post-accept consume token + track IP
 *
 * @see check_pre_accept_limits() for Phase 1
 */
static int
consume_rate_and_track_ip (T pool, const char *client_ip)
{
  int rate_ok;
  int ip_ok;

  POOL_LOCK (pool);

  /* Consume rate token */
  rate_ok = (!pool->conn_limiter
             || SocketRateLimit_try_acquire (pool->conn_limiter, 1));

  if (!rate_ok)
    {
      POOL_UNLOCK (pool);
      return 0;
    }

  /* Check and track IP */
  if (pool->ip_tracker && client_ip && client_ip[0] != '\0')
    {
      ip_ok = SocketIPTracker_track (pool->ip_tracker, client_ip);
      if (!ip_ok)
        {
          POOL_UNLOCK (pool);
          return 0;
        }
    }

  POOL_UNLOCK (pool);
  return 1;
}

/**
 * SocketPool_accept_protected - Accept with full SYN flood protection
 * @pool: Pool instance
 * @server: Server socket (listening, non-blocking)
 * @action_out: Output - action taken (optional, may be NULL)
 *
 * Returns: New socket if allowed, NULL if blocked/would block
 * Raises: SocketPool_Failed on actual errors
 * Thread-safe: Yes
 *
 * Security: Checks rate limits BEFORE accepting to prevent resource exhaustion
 * from accepting connections that will be immediately rejected. This prevents
 * TOCTOU race conditions where attackers could exhaust server resources.
 *
 * Flow:
 * 1. Check rate limits and pool state (pre-accept check - Phase 1)
 * 2. Accept connection
 * 3. Check SYN protection for the specific client IP
 * 4. Consume rate token and track IP (post-accept confirmation - Phase 2)
 * 5. Apply throttle/challenge actions as needed
 */
Socket_T
SocketPool_accept_protected (T pool, Socket_T server,
                             SocketSYN_Action *action_out)
{
  Socket_T client = NULL;
  SocketSYNProtect_T protect = NULL;
  SocketSYN_Action action = SYN_ACTION_ALLOW;
  const char *client_ip = NULL;

  assert (pool);
  assert (server);

  /* Security: Check rate limits BEFORE accepting to prevent TOCTOU race.
   * This ensures we don't accept connections that will be immediately
   * rejected, preventing resource exhaustion attacks. */
  if (!check_pre_accept_limits (pool, &protect))
    {
      if (action_out)
        *action_out = SYN_ACTION_THROTTLE;
      return NULL;
    }

  /* If no SYN protection, fall back to rate-limited accept */
  if (protect == NULL)
    {
      if (action_out)
        *action_out = SYN_ACTION_ALLOW;
      return SocketPool_accept_limited (pool, server);
    }

  /* Now accept the connection - rate limits already checked.
   * Any Socket_Failed exception will propagate naturally. */
  client = Socket_accept (server);

  if (client == NULL)
    {
      /* Would block - not an error */
      if (action_out)
        *action_out = SYN_ACTION_ALLOW;
      return NULL;
    }

  /* Get client IP for SYN protection check */
  client_ip = Socket_getpeeraddr (client);

  /* Check with SYN protection module */
  action = SocketSYNProtect_check (protect, client_ip, NULL);

  if (action_out)
    *action_out = action;

  /* Handle action */
  switch (action)
    {
    case SYN_ACTION_ALLOW:
      if (!try_consume_and_report (pool, protect, client_ip, 1))
        {
          handle_syn_consume_failure (protect, client_ip, &client);
          return NULL;
        }
      break;

    case SYN_ACTION_THROTTLE:
      /* Apply throttle delay, then allow */
      apply_syn_throttle (action, protect);
      if (!try_consume_and_report (pool, protect, client_ip, 1))
        {
          handle_syn_consume_failure (protect, client_ip, &client);
          return NULL;
        }
      break;

    case SYN_ACTION_CHALLENGE:
      /* Apply TCP_DEFER_ACCEPT challenge */
      apply_syn_challenge (client, action, protect);
      if (!try_consume_and_report (pool, protect, client_ip, 0))
        {
          handle_syn_consume_failure (protect, client_ip, &client);
          return NULL;
        }
      /* Report success only after challenge - caller should verify data
       * received */
      break;

    case SYN_ACTION_BLOCK:
      /* Reject connection immediately */
      handle_syn_consume_failure (protect, client_ip, &client);
      return NULL;
    }

  return client;
}

#undef T

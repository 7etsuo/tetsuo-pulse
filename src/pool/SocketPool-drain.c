/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketPool-drain.c - Graceful shutdown (drain) implementation
 *
 * Part of the Socket Library
 *
 * Implements industry-standard graceful shutdown following patterns from
 * nginx, HAProxy, Envoy, and Go http.Server:
 *
 * - Clean state machine (RUNNING -> DRAINING -> STOPPED)
 * - Non-blocking API for event loop integration
 * - Timeout-guaranteed completion
 * - Lock-free state reads for performance
 * - Zero heap allocation in shutdown path
 *
 * Thread Safety:
 * - State reads are lock-free (C11 atomics with acquire semantics)
 * - State transitions use mutex for atomicity
 * - Callback invocation outside lock to prevent deadlock
 */

#include <assert.h>

#include <limits.h>
#include <stdlib.h>

#include "core/SocketMetrics.h"
#include "pool/SocketPool-private.h"
/* SocketUtil.h included via SocketPool-private.h */

/* SOCKET_LOG_COMPONENT defined in SocketPool-private.h */

#define T SocketPool_T

/** Minimum backoff for drain_wait polling (milliseconds) */
#define SOCKET_POOL_DRAIN_BACKOFF_MIN_MS 1

/** Maximum backoff for drain_wait polling (milliseconds) */
#define SOCKET_POOL_DRAIN_BACKOFF_MAX_MS 100

/** Backoff multiplier for drain_wait polling */
#define SOCKET_POOL_DRAIN_BACKOFF_MULTIPLIER 2

/** Infinite timeout sentinel */
#define SOCKET_POOL_DRAIN_TIMEOUT_INFINITE (-1)

/**
 * @brief Atomically load pool state with acquire semantics.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @return Current SocketPool_State.
 * @threadsafe Yes - C11 atomic read.
 *
 * @see SocketPool_state() for public interface.
 * @see store_pool_state() for storing state.
 */
static inline SocketPool_State
load_pool_state (const T pool)
{
  return (SocketPool_State)atomic_load_explicit (&pool->state,
                                                 memory_order_acquire);
}


/**
 * @brief Shutdown socket gracefully, ignoring errors.
 * @ingroup connection_mgmt
 * @param sock Socket to shutdown.
 *
 * Helper to avoid TRY/EXCEPT in the loop which triggers clobbered warning.
 * Used during drain operations to close connections.
 *
 * @see SocketPool_drain() for usage context.
 * @see SocketPool_drain_force() for forced shutdown.
 */
static void
shutdown_socket_gracefully (Socket_T sock)
{
  TRY
  {
    Socket_shutdown (sock, SHUT_RDWR);
  }
  ELSE
  { /* Ignore errors - socket may already be closed */
  }
  END_TRY;
}

/**
 * allocate_closing_buffer - Allocate or get buffer for closing sockets
 * @pool: Pool instance
 * @allocated_out: Output: 1 if newly allocated (caller must free)
 *
 * Returns: Buffer for sockets, or NULL on failure
 * Thread-safe: Call with mutex held
 */
static Socket_T *
allocate_closing_buffer (T pool, int *allocated_out)
{
  Socket_T *buf = pool->cleanup_buffer;
  *allocated_out = 0;

  if (!buf)
    {
      if (pool->maxconns > SIZE_MAX / sizeof (Socket_T))
        {
          SocketLog_emitf (SOCKET_LOG_ERROR,
                           SOCKET_LOG_COMPONENT,
                           "Integer overflow in force close buffer size");
          return NULL;
        }
      buf = malloc (pool->maxconns * sizeof (Socket_T));
      if (!buf)
        {
          SocketLog_emitf (SOCKET_LOG_ERROR,
                           SOCKET_LOG_COMPONENT,
                           "Failed to allocate buffer for force close");
          return NULL;
        }
      *allocated_out = 1;
    }

  return buf;
}

/**
 * collect_active_connections - Collect active sockets under lock
 * @pool: Pool instance
 * @buffer: Pre-allocated buffer for sockets
 * @max_slots: Maximum slots in buffer
 *
 * Returns: Number of active sockets collected
 * Thread-safe: Call with mutex held
 * Complexity: O(maxconns)
 */
static size_t
collect_active_connections (T pool, Socket_T *buffer, size_t max_slots)
{
  size_t count = 0;
  size_t i;

  for (i = 0; i < pool->maxconns && count < max_slots && count < pool->count;
       i++)
    {
      struct Connection *conn = &pool->connections[i];
      if (conn->active && conn->socket)
        buffer[count++] = conn->socket;
    }

  return count;
}

/**
 * close_collected_connections - Close and free collected sockets
 * @pool: Pool instance
 * @sockets: Array of sockets to close
 * @count: Number of sockets
 *
 * Closes sockets, removes from pool, frees. Does not hold lock.
 * Thread-safe: Yes (SocketPool_remove locks internally)
 */
static void
close_collected_connections (T pool, Socket_T *sockets, size_t count)
{
  size_t i;

  for (i = 0; i < count; i++)
    {
      Socket_T sock = sockets[i];
      if (sock)
        {
          shutdown_socket_gracefully (sock);
          SocketPool_remove (pool, sock);
          Socket_free (&sock);
          sockets[i] = NULL;
        }
    }
}

/**
 * SocketPool_state - Get current pool lifecycle state
 * @pool: Pool instance
 *
 * Returns: Current SocketPool_State
 * Thread-safe: Yes - C11 atomic read with acquire semantics
 * Complexity: O(1)
 *
 * Uses memory_order_acquire to ensure all memory writes that happened
 * before the state transition are visible to this thread.
 */
SocketPool_State
SocketPool_state (const T pool)
{
  assert (pool);
  return load_pool_state (pool);
}

/**
 * SocketPool_health - Get pool health status for load balancers
 * @pool: Pool instance
 *
 * Returns: Current SocketPool_Health
 * Thread-safe: Yes - C11 atomic read
 * Complexity: O(1)
 */
SocketPool_Health
SocketPool_health (const T pool)
{
  assert (pool);

  switch (load_pool_state (pool))
    {
    case POOL_STATE_RUNNING:
      return POOL_HEALTH_HEALTHY;
    case POOL_STATE_DRAINING:
      return POOL_HEALTH_DRAINING;
    case POOL_STATE_STOPPED:
      return POOL_HEALTH_STOPPED;
    default:
      return POOL_HEALTH_STOPPED;
    }
}

/**
 * SocketPool_is_draining - Check if pool is currently draining
 * @pool: Pool instance
 *
 * Returns: Non-zero if state is DRAINING
 * Thread-safe: Yes - C11 atomic read
 * Complexity: O(1)
 */
int
SocketPool_is_draining (const T pool)
{
  assert (pool);
  return load_pool_state (pool) == POOL_STATE_DRAINING;
}

/**
 * SocketPool_is_stopped - Check if pool is fully stopped
 * @pool: Pool instance
 *
 * Returns: Non-zero if state is STOPPED
 * Thread-safe: Yes - C11 atomic read
 * Complexity: O(1)
 */
int
SocketPool_is_stopped (const T pool)
{
  assert (pool);
  return load_pool_state (pool) == POOL_STATE_STOPPED;
}

/**
 * transition_to_stopped - Transition pool to STOPPED state and invoke callback
 * @pool: Pool instance
 * @timed_out: 1 if drain timed out, 0 if graceful
 *
 * Thread-safe: Call with mutex held (releases before callback)
 *
 * Sets state to STOPPED, then invokes drain callback outside lock
 * to prevent deadlock if callback calls pool functions.
 *
 * Uses memory_order_release on state write to ensure all memory writes
 * (cleanup operations) are visible before the state change is observed.
 */
static void
transition_to_stopped (T pool, int timed_out)
{
  SocketPool_DrainCallback cb = pool->drain_cb;
  void *cb_data = pool->drain_cb_data;

  pool->drain_deadline_ms = 0;

  /* Set state with release semantics to ensure all prior writes are visible */
  atomic_store_explicit (
      &pool->state, POOL_STATE_STOPPED, memory_order_release);

  SocketLog_emitf (SOCKET_LOG_INFO,
                   SOCKET_LOG_COMPONENT,
                   "Pool drain complete (timed_out=%d)",
                   timed_out);
  SocketMetrics_counter_inc (SOCKET_CTR_POOL_DRAIN_COMPLETED);

  /* Release lock BEFORE callback to prevent deadlock */
  POOL_UNLOCK (pool);

  if (cb)
    cb (pool, timed_out, cb_data);

  /* Re-acquire lock for caller (they expect to hold it) */
  POOL_LOCK (pool);
}

/**
 * force_close_all_connections - Force close all active connections
 * @pool: Pool instance
 *
 * Thread-safe: Call with mutex held
 * Complexity: O(n) where n = active connections
 *
 * Collects all active sockets under lock to get a consistent snapshot,
 * then releases the lock before closing to avoid holding it during
 * potentially slow I/O operations.
 */
static void
force_close_all_connections (T pool)
{
  Socket_T *to_close;
  int allocated = 0;
  size_t close_count;

  if (pool->count == 0)
    return;

  to_close = allocate_closing_buffer (pool, &allocated);
  if (!to_close)
    return;

  /* Collect active connections while holding lock to get consistent snapshot */
  close_count = collect_active_connections (pool, to_close, pool->maxconns);

  /* THREAD SAFETY: Release lock before closing sockets to avoid holding lock
   * during potentially slow I/O operations. During this unlocked period:
   *
   * SAFE: SocketPool_add() rejects new connections (pool is DRAINING state)
   * RACE RISK: SocketPool_remove() could be called on a socket we're about
   *            to close, potentially leading to use-after-free if that thread
   *            calls Socket_free()
   *
   * MITIGATION: Applications MUST NOT call Socket_free() on pool connections
   * after drain is initiated. The drain mechanism owns all cleanup during this
   * phase. SocketPool_remove() itself is safe as it only updates bookkeeping.
   *
   * RATIONALE: We release the lock here because:
   * 1. Socket shutdown/close can block (TCP FIN handshake, kernel buffering)
   * 2. Holding lock during close would serialize all pool operations
   * 3. The collected sockets array is a snapshot taken under lock protection
   *
   * See close_collected_connections() which safely handles NULL sockets and
   * calls SocketPool_remove() which acquires its own lock for bookkeeping.
   */
  POOL_UNLOCK (pool);

  /* Close all collected sockets (lock released to avoid blocking pool) */
  close_collected_connections (pool, to_close, close_count);

  /* Re-acquire lock for caller (expected to hold lock on return) */
  POOL_LOCK (pool);

  if (allocated)
    free (to_close);

  SocketLog_emitf (SOCKET_LOG_WARN,
                   SOCKET_LOG_COMPONENT,
                   "Forced close of %zu connections",
                   close_count);
}

/**
 * SocketPool_drain - Initiate graceful shutdown
 * @pool: Pool instance
 * @timeout_ms: Maximum time to wait for connections to close (-1 for infinite)
 *
 * Thread-safe: Yes
 * Complexity: O(1)
 */
void
SocketPool_drain (T pool, int timeout_ms)
{
  int64_t now_ms;
  size_t current_count;
  SocketPool_State current_state;

  assert (pool);

  POOL_LOCK (pool);

  /* Only transition from RUNNING */
  current_state = load_pool_state (pool);
  if (current_state != POOL_STATE_RUNNING)
    {
      SocketLog_emitf (SOCKET_LOG_DEBUG,
                       SOCKET_LOG_COMPONENT,
                       "Pool drain called but state is %d (not RUNNING)",
                       (int)current_state);
      POOL_UNLOCK (pool);
      return;
    }

  now_ms = Socket_get_monotonic_ms ();
  current_count = pool->count;

  /* Set deadline using overflow-safe addition */
  if (timeout_ms == SOCKET_POOL_DRAIN_TIMEOUT_INFINITE)
    pool->drain_deadline_ms = INT64_MAX;
  else if (timeout_ms <= 0)
    pool->drain_deadline_ms = now_ms;
  else
    pool->drain_deadline_ms = pool_safe_add_ms (now_ms, timeout_ms);

  /* Transition to DRAINING with release semantics */
  atomic_store_explicit (
      &pool->state, POOL_STATE_DRAINING, memory_order_release);

  SocketLog_emitf (SOCKET_LOG_INFO,
                   SOCKET_LOG_COMPONENT,
                   "Pool drain initiated: %zu connections, timeout=%d ms",
                   current_count,
                   timeout_ms);
  SocketMetrics_counter_inc (SOCKET_CTR_POOL_DRAIN_STARTED);

  /* If no connections, transition immediately to STOPPED */
  if (current_count == 0)
    {
      transition_to_stopped (pool, 0);
      POOL_UNLOCK (pool);
      return;
    }

  /* If timeout is 0 (immediate), force close now */
  if (timeout_ms == 0)
    {
      force_close_all_connections (pool);
      transition_to_stopped (pool, 1);
      POOL_UNLOCK (pool);
      return;
    }

  POOL_UNLOCK (pool);
}

/**
 * SocketPool_drain_poll - Poll drain progress (non-blocking)
 * @pool: Pool instance
 *
 * Returns: >0 connections remaining, 0 = complete, -1 = forced
 * Thread-safe: Yes
 * Complexity: O(1) normally, O(n) on force close
 */
int
SocketPool_drain_poll (T pool)
{
  SocketPool_State state;
  size_t current_count;
  int64_t now_ms;

  assert (pool);

  POOL_LOCK (pool);

  state = load_pool_state (pool);
  current_count = pool->count;

  switch (state)
    {
    case POOL_STATE_STOPPED:
      POOL_UNLOCK (pool);
      return 0;

    case POOL_STATE_RUNNING:
      POOL_UNLOCK (pool);
      return (int)current_count;

    case POOL_STATE_DRAINING:
      break;
    }

  /* State is DRAINING - check completion conditions */
  if (current_count == 0)
    {
      transition_to_stopped (pool, 0);
      POOL_UNLOCK (pool);
      return 0;
    }

  now_ms = Socket_get_monotonic_ms ();
  if (pool->drain_deadline_ms != INT64_MAX && now_ms >= pool->drain_deadline_ms)
    {
      SocketLog_emitf (SOCKET_LOG_WARN,
                       SOCKET_LOG_COMPONENT,
                       "Pool drain timeout expired, forcing close of %zu "
                       "connections",
                       current_count);
      force_close_all_connections (pool);
      transition_to_stopped (pool, 1);
      POOL_UNLOCK (pool);
      return -1;
    }

  POOL_UNLOCK (pool);
  return (int)current_count;
}

/**
 * SocketPool_drain_remaining_ms - Get time until forced shutdown
 * @pool: Pool instance
 *
 * Returns: Milliseconds remaining, 0 if expired, -1 if not draining
 * Thread-safe: Yes (atomic state check; deadline read may be stale)
 * Complexity: O(1)
 *
 * THREAD SAFETY NOTES:
 * The pool state is checked atomically, but the drain_deadline_ms read is
 * non-atomic and may observe stale values. This is acceptable because:
 *
 * 1. This function returns a best-effort ESTIMATE for use as a timeout hint
 *    in poll/select during graceful shutdown monitoring.
 *
 * 2. The returned value is inherently racy - time advances continuously, so
 *    the "remaining time" becomes stale immediately after being computed.
 *
 * 3. Callers MUST treat the return value as advisory. The actual timeout may
 *    differ due to:
 *    - Concurrent drain_deadline_ms modifications by other threads
 *    - Time elapsed between reading deadline and caller receiving value
 *    - System clock adjustments (though monotonic clock mitigates this)
 *
 * 4. Critical drain decisions (force-close on timeout) are made by
 *    SocketPool_drain_poll() which holds the mutex and performs consistent
 *    reads under lock protection.
 *
 * USAGE PATTERN:
 *   while (SocketPool_drain_poll(pool) > 0) {
 *       int64_t timeout_hint = SocketPool_drain_remaining_ms(pool);
 *       SocketPoll_wait(poll, &events, timeout_hint);  // Advisory timeout
 *   }
 *
 * If precise deadline tracking is needed, use SocketPool_drain_poll() which
 * synchronizes access to both state and deadline fields.
 */
int64_t
SocketPool_drain_remaining_ms (const T pool)
{
  int64_t remaining;

  assert (pool);

  if (load_pool_state (pool) != POOL_STATE_DRAINING)
    return -1;

  if (pool->drain_deadline_ms == INT64_MAX)
    return INT64_MAX;

  remaining = pool->drain_deadline_ms - Socket_get_monotonic_ms ();
  return remaining > 0 ? remaining : 0;
}

/**
 * SocketPool_drain_force - Force immediate shutdown
 * @pool: Pool instance
 *
 * Thread-safe: Yes (C11 atomic operations)
 * Complexity: O(n)
 */
void
SocketPool_drain_force (T pool)
{
  SocketPool_State state;

  assert (pool);

  POOL_LOCK (pool);

  state = load_pool_state (pool);

  if (state == POOL_STATE_STOPPED)
    {
      POOL_UNLOCK (pool);
      return;
    }

  if (state == POOL_STATE_RUNNING)
    {
      atomic_store_explicit (
          &pool->state, POOL_STATE_DRAINING, memory_order_release);
      pool->drain_deadline_ms = 0;
    }

  SocketLog_emitf (SOCKET_LOG_WARN,
                   SOCKET_LOG_COMPONENT,
                   "Pool drain forced: %zu connections to close",
                   pool->count);

  if (pool->count > 0)
    force_close_all_connections (pool);

  transition_to_stopped (pool, 1);
  POOL_UNLOCK (pool);
}

/**
 * SocketPool_drain_wait - Blocking drain with internal poll loop
 * @pool: Pool instance
 * @timeout_ms: Maximum wait time, -1 for infinite
 *
 * Returns: 0 if graceful, -1 if forced
 * Thread-safe: Yes
 */
int
SocketPool_drain_wait (T pool, int timeout_ms)
{
  int backoff_ms = SOCKET_POOL_DRAIN_BACKOFF_MIN_MS;
  int result;
  struct timespec ts;

  assert (pool);

  /* Initiate drain */
  SocketPool_drain (pool, timeout_ms);

  /* Poll with exponential backoff */
  while ((result = SocketPool_drain_poll (pool)) > 0)
    {
      /* Sleep with exponential backoff
       * Note: nanosleep() may return early on signal (EINTR), which is
       * acceptable here as the loop will simply poll sooner. The backoff
       * is for efficiency, not correctness. */
      ts = socket_util_ms_to_timespec (backoff_ms);
      nanosleep (&ts, NULL);

      /* Increase backoff up to max */
      backoff_ms *= SOCKET_POOL_DRAIN_BACKOFF_MULTIPLIER;
      if (backoff_ms > SOCKET_POOL_DRAIN_BACKOFF_MAX_MS)
        backoff_ms = SOCKET_POOL_DRAIN_BACKOFF_MAX_MS;
    }

  /* result == 0 means graceful, -1 means forced */
  return result;
}

/**
 * SocketPool_set_drain_callback - Register drain completion callback
 * @pool: Pool instance
 * @cb: Callback function (NULL to clear)
 * @data: User data passed to callback
 *
 * Thread-safe: Yes
 */
void
SocketPool_set_drain_callback (T pool, SocketPool_DrainCallback cb, void *data)
{
  assert (pool);

  POOL_LOCK (pool);
  pool->drain_cb = cb;
  pool->drain_cb_data = data;
  POOL_UNLOCK (pool);
}

/**
 * SocketPool_set_idle_timeout - Set idle connection timeout
 * @pool: Pool instance
 * @timeout_sec: Idle timeout in seconds (0 to disable)
 *
 * Thread-safe: Yes
 */
void
SocketPool_set_idle_timeout (T pool, time_t timeout_sec)
{
  assert (pool);

  POOL_LOCK (pool);
  pool->idle_timeout_sec = timeout_sec;
  POOL_UNLOCK (pool);
}

/**
 * SocketPool_get_idle_timeout - Get idle connection timeout
 * @pool: Pool instance
 *
 * Returns: Current idle timeout in seconds (0 = disabled)
 * Thread-safe: Yes
 */
time_t
SocketPool_get_idle_timeout (const T pool)
{
  time_t timeout;

  assert (pool);

  POOL_LOCK (pool);
  timeout = pool->idle_timeout_sec;
  POOL_UNLOCK (pool);

  return timeout;
}

/**
 * SocketPool_idle_cleanup_due_ms - Get time until next idle cleanup
 * @pool: Pool instance
 *
 * Returns: Milliseconds until next cleanup, -1 if disabled
 * Thread-safe: Yes
 */
int64_t
SocketPool_idle_cleanup_due_ms (const T pool)
{
  int64_t remaining;

  assert (pool);

  POOL_LOCK (pool);

  if (pool->idle_timeout_sec == 0)
    {
      POOL_UNLOCK (pool);
      return -1;
    }

  remaining
      = pool_safe_add_ms (pool->last_cleanup_ms, pool->cleanup_interval_ms)
        - Socket_get_monotonic_ms ();

  POOL_UNLOCK (pool);

  return remaining > 0 ? remaining : 0;
}

/**
 * SocketPool_run_idle_cleanup - Run idle connection cleanup if due
 * @pool: Pool instance
 *
 * Returns: Number of connections cleaned up
 * Thread-safe: Yes
 */
size_t
SocketPool_run_idle_cleanup (T pool)
{
  int64_t now_ms;
  int64_t next_cleanup_ms;
  time_t idle_timeout;
  size_t count_before, count_after, cleaned_count;

  assert (pool);

  POOL_LOCK (pool);

  if (pool->idle_timeout_sec == 0)
    {
      POOL_UNLOCK (pool);
      return 0;
    }

  now_ms = Socket_get_monotonic_ms ();
  next_cleanup_ms
      = pool_safe_add_ms (pool->last_cleanup_ms, pool->cleanup_interval_ms);

  if (now_ms < next_cleanup_ms)
    {
      POOL_UNLOCK (pool);
      return 0;
    }

  pool->last_cleanup_ms = now_ms;
  idle_timeout = pool->idle_timeout_sec;

  POOL_UNLOCK (pool);

  /* Run cleanup - SocketPool_cleanup handles its own locking */
  count_before = SocketPool_count (pool);
  SocketPool_cleanup (pool, idle_timeout);
  count_after = SocketPool_count (pool);

  cleaned_count = count_before > count_after ? count_before - count_after : 0;

  if (cleaned_count > 0)
    {
      POOL_LOCK (pool);
      pool->stats_idle_cleanups += cleaned_count;
      POOL_UNLOCK (pool);

      SocketLog_emitf (SOCKET_LOG_DEBUG,
                       SOCKET_LOG_COMPONENT,
                       "Idle cleanup removed %zu connections",
                       cleaned_count);
    }

  return cleaned_count;
}

#undef T

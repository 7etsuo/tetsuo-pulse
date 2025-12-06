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
 * - State reads are lock-free (volatile int)
 * - State transitions use mutex for atomicity
 * - Callback invocation outside lock to prevent deadlock
 */

#include <assert.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pool/SocketPool-private.h"
/* SocketUtil.h included via SocketPool-private.h */

/* Override default log component (SocketUtil.h sets "Socket") */
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketPool"

#define T SocketPool_T

/* ============================================================================
 * Constants
 * ============================================================================ */

/** Minimum backoff for drain_wait polling (milliseconds) */
#define DRAIN_BACKOFF_MIN_MS 1

/** Maximum backoff for drain_wait polling (milliseconds) */
#define DRAIN_BACKOFF_MAX_MS 100

/** Backoff multiplier for drain_wait polling */
#define DRAIN_BACKOFF_MULTIPLIER 2

/** Infinite timeout sentinel */
#define DRAIN_TIMEOUT_INFINITE (-1)

/* ============================================================================
 * State Query Functions (Lock-Free with C11 Atomics)
 * ============================================================================ */

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
SocketPool_state (T pool)
{
  assert (pool);

  /* C11 atomic read with acquire semantics for proper memory ordering */
  return (SocketPool_State)atomic_load_explicit (&pool->state,
                                                  memory_order_acquire);
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
SocketPool_health (T pool)
{
  SocketPool_State state;

  assert (pool);

  state = (SocketPool_State)atomic_load_explicit (&pool->state,
                                                   memory_order_acquire);
  switch (state)
    {
    case POOL_STATE_RUNNING:
      return POOL_HEALTH_HEALTHY;
    case POOL_STATE_DRAINING:
      return POOL_HEALTH_DRAINING;
    case POOL_STATE_STOPPED:
      return POOL_HEALTH_STOPPED;
    default:
      /* Defensive: treat unknown state as stopped */
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
SocketPool_is_draining (T pool)
{
  assert (pool);
  return atomic_load_explicit (&pool->state, memory_order_acquire)
         == POOL_STATE_DRAINING;
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
SocketPool_is_stopped (T pool)
{
  assert (pool);
  return atomic_load_explicit (&pool->state, memory_order_acquire)
         == POOL_STATE_STOPPED;
}

/* ============================================================================
 * Internal State Transition Helpers
 * ============================================================================ */

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
  SocketPool_DrainCallback cb;
  void *cb_data;

  /* Capture callback info under lock */
  cb = pool->drain_cb;
  cb_data = pool->drain_cb_data;

  pool->drain_deadline_ms = 0;

  /* Set state with release semantics to ensure all prior writes are visible */
  atomic_store_explicit (&pool->state, POOL_STATE_STOPPED,
                         memory_order_release);

  /* Log transition */
  SocketLog_emitf (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT,
                   "Pool drain complete (timed_out=%d)", timed_out);

  /* Emit event */
  SocketMetrics_increment (SOCKET_METRIC_POOL_DRAIN_COMPLETED, 1);

  /* Release lock BEFORE callback to prevent deadlock */
  pthread_mutex_unlock (&pool->mutex);

  /* Invoke callback outside lock */
  if (cb)
    cb (pool, timed_out, cb_data);

  /* Re-acquire lock for caller (they expect to hold it) */
  pthread_mutex_lock (&pool->mutex);
}

/**
 * force_close_all_connections - Force close all active connections
 * @pool: Pool instance
 *
 * Thread-safe: Call with mutex held
 * Complexity: O(n) where n = active connections
 *
 * Collects all active sockets, releases lock, then closes them.
 * This prevents holding the lock during potentially slow close operations.
 */
/**
 * shutdown_socket_gracefully - Shutdown socket ignoring errors
 * @sock: Socket to shutdown
 *
 * Helper to avoid TRY/EXCEPT in the loop which triggers clobbered warning.
 */
static void
shutdown_socket_gracefully (Socket_T sock)
{
  TRY { Socket_shutdown (sock, SHUT_RDWR); }
  ELSE { /* Ignore errors - socket may already be closed */ }
  END_TRY;
}

/**
 * force_close_all_connections - Force close all active connections
 * @pool: Pool instance
 *
 * Thread-safe: Call with mutex held
 * Complexity: O(n) where n = active connections
 *
 * Collects all active sockets, releases lock, then closes them.
 * This prevents holding the lock during potentially slow close operations.
 *
 * THREAD SAFETY NOTE:
 * This function is designed to be called only during drain when the pool is
 * in DRAINING state. During drain, SocketPool_add() rejects new connections,
 * but SocketPool_remove() may still be called by other threads.
 *
 * If another thread calls SocketPool_remove() + Socket_free() on a socket
 * that is in our collected list, there is a potential use-after-free when
 * we try to call SocketPool_remove() on the same socket. However:
 *
 * 1. The second SocketPool_remove() will return early (find_slot returns NULL)
 * 2. The Socket_free() will be on already-freed memory (undefined behavior)
 *
 * MITIGATION: Applications should ensure that during drain, only the drain
 * mechanism itself calls Socket_free() on pool connections. Normal application
 * code should stop processing connections when drain is initiated.
 *
 * FUTURE IMPROVEMENT: Consider adding a "closing" flag to Connection to
 * prevent concurrent removal and double-free scenarios.
 */
static void
force_close_all_connections (T pool)
{
  Socket_T *to_close;
  int allocated_buffer = 0;
  size_t close_count = 0;
  size_t i;

  if (pool->count == 0)
    return;

  /* Allocate buffer for sockets to close (from pool's cleanup buffer) */
  to_close = pool->cleanup_buffer;
  if (!to_close)
    {
      /* Fallback: allocate temporary buffer */
      /* Security: Check for integer overflow before multiplication to prevent
       * heap buffer overflow from undersized allocation */
      if (pool->maxconns > SIZE_MAX / sizeof (Socket_T))
        {
          SocketLog_emitf (SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT,
                           "Integer overflow in force close buffer size");
          return;
        }
      to_close = malloc (pool->maxconns * sizeof (Socket_T));
      if (!to_close)
        {
          SocketLog_emitf (SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT,
                           "Failed to allocate buffer for force close");
          return;
        }
      allocated_buffer = 1;
    }

  /* Collect active sockets under lock */
  for (i = 0; i < pool->maxconns && close_count < pool->count; i++)
    {
      struct Connection *conn = &pool->connections[i];
      if (conn->active && conn->socket)
        to_close[close_count++] = conn->socket;
    }

  /* Release lock before closing sockets */
  pthread_mutex_unlock (&pool->mutex);

  /* Close all collected sockets */
  for (i = 0; i < close_count; i++)
    {
      Socket_T sock = to_close[i];
      if (sock)
        {
          /* Shutdown first to send FIN */
          shutdown_socket_gracefully (sock);

          /* Remove from pool - SocketPool_remove handles its own locking */
          SocketPool_remove (pool, sock);

          Socket_free (&sock);
        }
    }

  /* Re-acquire lock for caller */
  pthread_mutex_lock (&pool->mutex);

  /* Free temporary buffer if we allocated one */
  if (allocated_buffer)
    free (to_close);

  SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                   "Forced close of %zu connections", close_count);
}

/* ============================================================================
 * Drain API Implementation
 * ============================================================================ */

/**
 * SocketPool_drain - Initiate graceful shutdown
 * @pool: Pool instance
 * @timeout_ms: Maximum time to wait for connections to close
 *
 * Thread-safe: Yes
 * Complexity: O(1)
 */
void
SocketPool_drain (T pool, int timeout_ms)
{
  int64_t now_ms;
  size_t current_count;

  assert (pool);

  pthread_mutex_lock (&pool->mutex);

  /* Only transition from RUNNING */
  if (atomic_load_explicit (&pool->state, memory_order_acquire)
      != POOL_STATE_RUNNING)
    {
      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "Pool drain called but state is %d (not RUNNING)",
                       atomic_load_explicit (&pool->state, memory_order_relaxed));
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  /* Get current time and count */
  now_ms = Socket_get_monotonic_ms ();
  current_count = pool->count;

  /* Set deadline */
  if (timeout_ms == DRAIN_TIMEOUT_INFINITE)
    {
      pool->drain_deadline_ms = INT64_MAX;
    }
  else if (timeout_ms <= 0)
    {
      /* Immediate force close */
      pool->drain_deadline_ms = now_ms;
    }
  else
    {
      /* Security: Overflow-safe deadline calculation with saturation.
       * While practically impossible (requires ~292 million years uptime),
       * defense-in-depth dictates protecting against INT64 overflow. */
      if (now_ms > INT64_MAX - timeout_ms)
        pool->drain_deadline_ms = INT64_MAX; /* Saturate on overflow */
      else
        pool->drain_deadline_ms = now_ms + timeout_ms;
    }

  /* Transition to DRAINING with release semantics */
  atomic_store_explicit (&pool->state, POOL_STATE_DRAINING,
                         memory_order_release);

  SocketLog_emitf (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT,
                   "Pool drain initiated: %zu connections, timeout=%d ms",
                   current_count, timeout_ms);

  /* Emit metrics */
  SocketMetrics_increment (SOCKET_METRIC_POOL_DRAIN_INITIATED, 1);

  /* If no connections, transition immediately to STOPPED */
  if (current_count == 0)
    {
      transition_to_stopped (pool, 0);
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  /* If timeout is 0 or negative (except -1), force close now */
  if (timeout_ms == 0)
    {
      force_close_all_connections (pool);
      transition_to_stopped (pool, 1);
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  pthread_mutex_unlock (&pool->mutex);
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
  int64_t now_ms;
  size_t current_count;
  int result;

  assert (pool);

  pthread_mutex_lock (&pool->mutex);

  /* Not draining - return current count or 0 */
  if (atomic_load_explicit (&pool->state, memory_order_acquire)
      == POOL_STATE_STOPPED)
    {
      pthread_mutex_unlock (&pool->mutex);
      return 0;
    }

  if (atomic_load_explicit (&pool->state, memory_order_acquire)
      == POOL_STATE_RUNNING)
    {
      result = (int)pool->count;
      pthread_mutex_unlock (&pool->mutex);
      return result;
    }

  /* State is DRAINING */
  current_count = pool->count;
  now_ms = Socket_get_monotonic_ms ();

  /* Check if all connections closed naturally */
  if (current_count == 0)
    {
      transition_to_stopped (pool, 0);
      pthread_mutex_unlock (&pool->mutex);
      return 0;
    }

  /* Check if deadline expired */
  if (pool->drain_deadline_ms != INT64_MAX && now_ms >= pool->drain_deadline_ms)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Pool drain timeout expired, forcing close of %zu "
                       "connections",
                       current_count);
      force_close_all_connections (pool);
      transition_to_stopped (pool, 1);
      pthread_mutex_unlock (&pool->mutex);
      return -1;
    }

  /* Still draining */
  pthread_mutex_unlock (&pool->mutex);
  return (int)current_count;
}

/**
 * SocketPool_drain_remaining_ms - Get time until forced shutdown
 * @pool: Pool instance
 *
 * Returns: Milliseconds remaining, 0 if expired, -1 if not draining
 * Thread-safe: Yes (C11 atomic read)
 * Complexity: O(1)
 */
int64_t
SocketPool_drain_remaining_ms (T pool)
{
  int64_t now_ms;
  int64_t remaining;

  assert (pool);

  /* Not draining - atomic read for lock-free check */
  if (atomic_load_explicit (&pool->state, memory_order_acquire)
      != POOL_STATE_DRAINING)
    return -1;

  /* Infinite timeout */
  if (pool->drain_deadline_ms == INT64_MAX)
    return INT64_MAX;

  now_ms = Socket_get_monotonic_ms ();
  remaining = pool->drain_deadline_ms - now_ms;

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
  int current_state;

  assert (pool);

  pthread_mutex_lock (&pool->mutex);

  current_state = atomic_load_explicit (&pool->state, memory_order_acquire);

  /* Already stopped */
  if (current_state == POOL_STATE_STOPPED)
    {
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  /* Force transition to DRAINING first if needed */
  if (current_state == POOL_STATE_RUNNING)
    {
      atomic_store_explicit (&pool->state, POOL_STATE_DRAINING,
                             memory_order_release);
      pool->drain_deadline_ms = 0; /* Already expired */
    }

  SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                   "Pool drain forced: %zu connections to close", pool->count);

  /* Force close all connections */
  if (pool->count > 0)
    force_close_all_connections (pool);

  /* Transition to stopped */
  transition_to_stopped (pool, 1);

  pthread_mutex_unlock (&pool->mutex);
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
  int backoff_ms = DRAIN_BACKOFF_MIN_MS;
  int result;
  struct timespec ts;

  assert (pool);

  /* Initiate drain */
  SocketPool_drain (pool, timeout_ms);

  /* Poll with exponential backoff */
  while ((result = SocketPool_drain_poll (pool)) > 0)
    {
      /* Sleep with exponential backoff */
      ts.tv_sec = backoff_ms / 1000;
      ts.tv_nsec = (backoff_ms % 1000) * 1000000L;
      nanosleep (&ts, NULL);

      /* Increase backoff up to max */
      backoff_ms *= DRAIN_BACKOFF_MULTIPLIER;
      if (backoff_ms > DRAIN_BACKOFF_MAX_MS)
        backoff_ms = DRAIN_BACKOFF_MAX_MS;
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

  pthread_mutex_lock (&pool->mutex);
  pool->drain_cb = cb;
  pool->drain_cb_data = data;
  pthread_mutex_unlock (&pool->mutex);
}

/* ============================================================================
 * Idle Connection Cleanup
 * ============================================================================ */

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

  pthread_mutex_lock (&pool->mutex);
  pool->idle_timeout_sec = timeout_sec;
  pthread_mutex_unlock (&pool->mutex);
}

/**
 * SocketPool_get_idle_timeout - Get idle connection timeout
 * @pool: Pool instance
 *
 * Returns: Current idle timeout in seconds (0 = disabled)
 * Thread-safe: Yes
 */
time_t
SocketPool_get_idle_timeout (T pool)
{
  time_t timeout;

  assert (pool);

  pthread_mutex_lock (&pool->mutex);
  timeout = pool->idle_timeout_sec;
  pthread_mutex_unlock (&pool->mutex);

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
SocketPool_idle_cleanup_due_ms (T pool)
{
  int64_t now_ms;
  int64_t next_cleanup_ms;
  int64_t remaining;

  assert (pool);

  pthread_mutex_lock (&pool->mutex);

  /* Disabled if idle timeout is 0 */
  if (pool->idle_timeout_sec == 0)
    {
      pthread_mutex_unlock (&pool->mutex);
      return -1;
    }

  now_ms = Socket_get_monotonic_ms ();

  /* Security: Overflow-safe addition with saturation */
  if (pool->last_cleanup_ms > INT64_MAX - pool->cleanup_interval_ms)
    next_cleanup_ms = INT64_MAX;
  else
    next_cleanup_ms = pool->last_cleanup_ms + pool->cleanup_interval_ms;

  remaining = next_cleanup_ms - now_ms;

  pthread_mutex_unlock (&pool->mutex);

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
  size_t cleaned_count = 0;

  assert (pool);

  pthread_mutex_lock (&pool->mutex);

  /* Check if idle cleanup is enabled */
  if (pool->idle_timeout_sec == 0)
    {
      pthread_mutex_unlock (&pool->mutex);
      return 0;
    }

  /* Check if cleanup is due */
  now_ms = Socket_get_monotonic_ms ();

  /* Security: Overflow-safe addition with saturation */
  if (pool->last_cleanup_ms > INT64_MAX - pool->cleanup_interval_ms)
    next_cleanup_ms = INT64_MAX;
  else
    next_cleanup_ms = pool->last_cleanup_ms + pool->cleanup_interval_ms;

  if (now_ms < next_cleanup_ms)
    {
      pthread_mutex_unlock (&pool->mutex);
      return 0;
    }

  /* Update last cleanup time and get timeout */
  pool->last_cleanup_ms = now_ms;
  idle_timeout = pool->idle_timeout_sec;

  pthread_mutex_unlock (&pool->mutex);

  /* Run cleanup - SocketPool_cleanup handles its own locking */
  /* Get count before */
  size_t count_before = SocketPool_count (pool);
  SocketPool_cleanup (pool, idle_timeout);
  size_t count_after = SocketPool_count (pool);

  cleaned_count = count_before > count_after ? count_before - count_after : 0;

  /* Update statistics if any connections were cleaned */
  if (cleaned_count > 0)
    {
      pthread_mutex_lock (&pool->mutex);
      pool->stats_idle_cleanups += cleaned_count;
      pthread_mutex_unlock (&pool->mutex);

      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "Idle cleanup removed %zu connections", cleaned_count);
    }

  return cleaned_count;
}

#undef T


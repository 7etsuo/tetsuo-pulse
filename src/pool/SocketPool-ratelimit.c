/**
 * SocketPool-ratelimit.c - Rate Limiting Implementation for SocketPool
 *
 * Part of the Socket Library
 *
 * Implements connection rate limiting and per-IP connection limits:
 * - Connection rate limiting using token bucket algorithm
 * - Per-IP connection limits using hash table tracking
 * - Integration with SocketPool_add() and SocketPool_remove()
 *
 * Thread Safety:
 * - All functions acquire pool mutex for rate limiting operations
 * - Rate limiter and IP tracker have their own internal mutexes
 */

#include <assert.h>
#include <limits.h>
#include "core/SocketSecurity.h"

#include "core/SocketIPTracker.h"
#include "core/SocketRateLimit.h"
#include "pool/SocketPool-private.h"
/* SocketUtil.h included via SocketPool-private.h */

/* Override default log component (SocketUtil.h sets "Socket") */
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketPool"

#define T SocketPool_T

/* Common mutex operations to reduce code duplication */
#define POOL_LOCK(p)   do { pthread_mutex_lock (&(p)->mutex); } while (0)
#define POOL_UNLOCK(p) do { pthread_mutex_unlock (&(p)->mutex); } while (0)

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */

/** Tokens consumed per connection attempt for rate limiting */
#define RATELIMIT_TOKENS_PER_ACCEPT 1

/* ============================================================================
 * Static Helper Functions - IP Address Validation
 * ============================================================================ */

/**
 * is_valid_ip_for_tracking - Check if IP is valid for tracking
 * @ip: IP address string (may be NULL)
 *
 * Returns: 1 if IP is valid (non-NULL and non-empty), 0 otherwise
 *
 * Centralizes the IP validation pattern used throughout this module.
 */
static int
is_valid_ip_for_tracking (const char *ip)
{
  return ip != NULL && ip[0] != '\0';
}

/* ============================================================================
 * Static Helper Functions - Generic IP Tracker Operations
 * ============================================================================ */

/**
 * locked_ip_op_void - Perform void operation on IP tracker under lock
 * @pool: Connection pool
 * @ip: IP address
 * @op: Operation to perform if tracker exists and IP valid
 *
 * Performs the operation atomically under pool mutex.
 * Skips if IP invalid or no tracker.
 * Thread-safe: Yes
 */
static void
locked_ip_op_void (T pool, const char *ip, void (*op)(SocketIPTracker_T, const char *))
{
  if (!is_valid_ip_for_tracking (ip))
    return;

  POOL_LOCK (pool);
  if (pool->ip_tracker)
    op (pool->ip_tracker, ip);
  POOL_UNLOCK (pool);
}

/**
 * locked_ip_op_int - Perform int-returning operation on IP tracker under lock
 * @pool: Connection pool
 * @ip: IP address
 * @op: Operation to perform if tracker exists and IP valid
 * @no_tracker_retval: Return value if no tracker or invalid IP
 *                     (typically 1 for "success/noop" ops like track,
 *                      0 for query ops like count)
 *
 * Returns: Operation result or no_tracker_retval
 * Thread-safe: Yes
 */
static int
locked_ip_op_int (T pool, const char *ip, int (*op)(SocketIPTracker_T, const char *), int no_tracker_retval)
{
  if (!is_valid_ip_for_tracking (ip))
    return no_tracker_retval;

  POOL_LOCK (pool);
  int res = no_tracker_retval;
  if (pool->ip_tracker)
    res = op (pool->ip_tracker, ip);
  POOL_UNLOCK (pool);
  return res;
}

/* ============================================================================
 * Static Helper Functions - Rate Limiter Management
 * ============================================================================ */





/**
 * configure_rate_limiter - Configure rate limiter (create or reconfigure)
 * @pool: Connection pool (must hold mutex)
 * @rate: Connections per second
 * @burst: Burst capacity
 *
 * Returns: 1 on success, 0 on failure
 */
static int
configure_rate_limiter (T pool, size_t rate, size_t burst)
{
  if (pool->conn_limiter)
    {
      SocketRateLimit_configure (pool->conn_limiter, rate, burst);
      return 1;
    }

  TRY
    pool->conn_limiter = SocketRateLimit_new (pool->arena, rate, burst);
  EXCEPT (SocketRateLimit_Failed)
    return 0;
  END_TRY;

  return 1;
}



/* ============================================================================
 * Static Helper Functions - IP Tracker Management
 * ============================================================================ */





/**
 * configure_ip_tracker - Configure IP tracker (create or reconfigure)
 * @pool: Connection pool (must hold mutex)
 * @max_conns: Maximum connections per IP
 *
 * Returns: 1 on success, 0 on failure
 */
static int
configure_ip_tracker (T pool, int max_conns)
{
  if (pool->ip_tracker)
    {
      SocketIPTracker_setmax (pool->ip_tracker, max_conns);
      return 1;
    }

  TRY
    pool->ip_tracker = SocketIPTracker_new (pool->arena, max_conns);
  EXCEPT (SocketIPTracker_Failed)
    return 0;
  END_TRY;

  return 1;
}

/* ============================================================================
 * Static Helper Functions - Rate Limit Checks
 * ============================================================================ */











/* ============================================================================
 * Static Helper Functions - Accept Operations
 * ============================================================================ */





/* ============================================================================
 * Connection Rate Limiting - Public API
 * ============================================================================ */

/**
 * SocketPool_setconnrate - Set connection rate limit
 * @pool: Connection pool
 * @conns_per_sec: Connections per second (0 or negative to disable)
 * @burst: Burst capacity (defaults to rate if <= 0)
 *
 * Thread-safe: Yes - acquires pool mutex
 */
void
SocketPool_setconnrate (T pool, int conns_per_sec, int burst)
{
  int config_ok;

  assert (pool);

  /* Disable if rate is zero or negative */
  if (conns_per_sec <= 0)
    {
      POOL_LOCK (pool);
      pool->conn_limiter = NULL;
      POOL_UNLOCK (pool);
      return;
    }

  int safe_burst = (burst <= 0) ? conns_per_sec : burst;

  /* Validate parameters to prevent resource exhaustion */
  size_t max_burst_check;
  if (conns_per_sec > 1000000 ||
      !SocketSecurity_check_multiply((size_t)conns_per_sec, 100, &max_burst_check) ||
      (size_t)safe_burst > max_burst_check ||
      safe_burst <= 0) {
    RAISE_POOL_MSG (SocketPool_Failed, "Invalid connection rate: rate=%d burst=%d (max 1M/sec, burst <=100x rate)", conns_per_sec, safe_burst);
  }

  POOL_LOCK (pool);
  config_ok = configure_rate_limiter (pool, (size_t)conns_per_sec,
                                      (size_t)safe_burst);
  POOL_UNLOCK (pool);

  if (!config_ok)
    RAISE_POOL_MSG (SocketPool_Failed, "Failed to create connection rate limiter");
}

/**
 * SocketPool_getconnrate - Get connection rate limit
 * @pool: Connection pool
 *
 * Returns: Connections per second rate, or 0 if disabled
 * Thread-safe: Yes - acquires pool mutex
 */
int
SocketPool_getconnrate (T pool)
{
  assert (pool);

  POOL_LOCK (pool);
  size_t raw_rate = pool->conn_limiter ? SocketRateLimit_get_rate (pool->conn_limiter) : 0;
  int rate = (raw_rate > (size_t)INT_MAX) ? INT_MAX : (int)raw_rate;
  POOL_UNLOCK (pool);

  return rate;
}

/* ============================================================================
 * Per-IP Connection Limiting - Public API
 * ============================================================================ */

/**
 * SocketPool_setmaxperip - Set maximum connections per IP
 * @pool: Connection pool
 * @max_conns: Maximum connections per IP (0 or negative to disable)
 *
 * Thread-safe: Yes - acquires pool mutex
 */
void
SocketPool_setmaxperip (T pool, int max_conns)
{
  int config_ok;

  assert (pool);

  /* Disable if max is zero or negative */
  if (max_conns <= 0)
    {
      POOL_LOCK (pool);
      pool->ip_tracker = NULL;
      POOL_UNLOCK (pool);
      return;
    }

  /* Validate parameters to prevent resource exhaustion */
  if (max_conns < 1 || max_conns > 10000) {
    RAISE_POOL_MSG (SocketPool_Failed, "Invalid max per IP: %d (range 1-10000)", max_conns);
  }

  POOL_LOCK (pool);
  config_ok = configure_ip_tracker (pool, max_conns);
  POOL_UNLOCK (pool);

  if (!config_ok)
    RAISE_POOL_MSG (SocketPool_Failed, "Failed to create IP tracker");
}

/**
 * SocketPool_getmaxperip - Get maximum connections per IP
 * @pool: Connection pool
 *
 * Returns: Maximum connections per IP, or 0 if disabled
 * Thread-safe: Yes - acquires pool mutex
 */
int
SocketPool_getmaxperip (T pool)
{
  assert (pool);

  POOL_LOCK (pool);
  int max = pool->ip_tracker ? SocketIPTracker_getmax (pool->ip_tracker) : 0;
  POOL_UNLOCK (pool);

  return max;
}

/* ============================================================================
 * Rate Limit Checking - Public API
 * ============================================================================ */

/**
 * SocketPool_accept_allowed - Check if accepting is allowed
 * @pool: Connection pool
 * @client_ip: Client IP address (may be NULL)
 *
 * Returns: 1 if allowed, 0 if draining/stopped, rate limited, or IP limit reached
 * Thread-safe: Yes - acquires pool mutex
 *
 * Does NOT consume rate tokens - use for pre-check only.
 * Returns 0 immediately if pool is draining or stopped.
 */
int
SocketPool_accept_allowed (T pool, const char *client_ip)
{
  assert (pool);

  POOL_LOCK (pool);

  /* Reject if draining or stopped */
  if (atomic_load_explicit (&pool->state, memory_order_acquire) != POOL_STATE_RUNNING)
    {
      POOL_UNLOCK (pool);
      return 0;
    }

  int allowed = (!pool->conn_limiter
                || SocketRateLimit_available (pool->conn_limiter) > 0)
            && (!pool->ip_tracker
                || !is_valid_ip_for_tracking (client_ip)
                || (SocketIPTracker_count (pool->ip_tracker, client_ip) < SocketIPTracker_getmax (pool->ip_tracker)));
  POOL_UNLOCK (pool);

  return allowed;
}

/**
 * check_pool_accepting - Check if pool is accepting connections (with mutex)
 * @pool: Connection pool
 *
 * Returns: 1 if accepting, 0 if draining or stopped
 * Thread-safe: Yes - acquires pool mutex
 */
static int
check_pool_accepting (T pool)
{
  POOL_LOCK (pool);
  int accepting = atomic_load_explicit (&pool->state, memory_order_acquire)
         == POOL_STATE_RUNNING;
  POOL_UNLOCK (pool);

  return accepting;
}

/**
 * SocketPool_accept_limited - Rate-limited accept
 * @pool: Connection pool
 * @server: Server socket to accept from
 *
 * Returns: Accepted socket, or NULL if draining/stopped, rate limited, or accept failed
 * Thread-safe: Yes - acquires pool mutex for rate checks
 *
 * Returns NULL immediately if pool is draining or stopped.
 * Consumes a rate token before attempting accept. If accept fails,
 * the token is NOT refunded (prevents DoS via rapid accept failures).
 *
 * Note: If per-IP limiting is enabled (via SocketPool_setmaxperip > 0),
 * this function automatically tracks the client IP after successful Socket_accept.
 * If the subsequent SocketPool_add(pool, client) fails (e.g., pool full or state
 * changed to draining), the caller MUST call:
 *   - SocketPool_release_ip(pool, Socket_getpeeraddr(client)) to decrement the IP count
 *   - Socket_free(&client) to close the socket and prevent FD/memory leaks.
 * Failure to do so leads to permanent per-IP connection bans and resource exhaustion
 * (DoS vulnerability). See examples and SocketPool.h for proper error handling.
 */
Socket_T
SocketPool_accept_limited (T pool, Socket_T server)
{
  Socket_T client;
  const char *client_ip;

  assert (pool);
  assert (server);

  /* Reject if draining or stopped */
  if (!check_pool_accepting (pool))
    return NULL;

  /* Check and consume rate token */
  {
    POOL_LOCK (pool);
    int rate_ok = !pool->conn_limiter || SocketRateLimit_try_acquire (pool->conn_limiter, RATELIMIT_TOKENS_PER_ACCEPT);
    POOL_UNLOCK (pool);
    if (!rate_ok)
      return NULL;
  }

  /* Accept the connection */
  client = Socket_accept (server);
  if (!client)
    return NULL;

  /* Check per-IP limit and track */
  client_ip = Socket_getpeeraddr (client);

  if (!locked_ip_op_int (pool, client_ip, SocketIPTracker_track, 1))
    {
      Socket_free (&client);
      return NULL;
    }

  return client;
}

/* ============================================================================
 * Manual IP Tracking - Public API
 * ============================================================================ */
/**
 * SocketPool_track_ip - Manually track IP for per-IP limiting
 * @pool: Connection pool
 * @ip: IP address to track (NULL or empty always allowed)
 *
 * Returns: 1 if tracked successfully, 0 if IP limit reached
 * Thread-safe: Yes - acquires pool mutex
 */
int
SocketPool_track_ip (T pool, const char *ip)
{
  assert (pool);

  return locked_ip_op_int (pool, ip, SocketIPTracker_track, 1);
}

/**
 * SocketPool_release_ip - Release tracked IP when connection closes
 * @pool: Connection pool
 * @ip: IP address to release (NULL or empty is no-op)
 *
 * Thread-safe: Yes - acquires pool mutex
 */
void
SocketPool_release_ip (T pool, const char *ip)
{
  assert (pool);

  locked_ip_op_void (pool, ip, SocketIPTracker_release);
}


/**
 * SocketPool_ip_count - Get connection count for IP
 * @pool: Connection pool
 * @ip: IP address to query (NULL or empty returns 0)
 *
 * Returns: Current connection count for the IP
 * Thread-safe: Yes - acquires pool mutex
 */
int
SocketPool_ip_count (T pool, const char *ip)
{
  assert (pool);

  return locked_ip_op_int (pool, ip, SocketIPTracker_count, 0);
}

#undef T

/**
 * SocketPool-ratelimit.c - Rate Limiting Implementation for SocketPool
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
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

#include "pool/SocketPool-private.h"
#include "core/SocketIPTracker.h"
#include "core/SocketRateLimit.h"
#include <assert.h>
#include <errno.h>
#include <string.h>

#define T SocketPool_T

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */

/** Tokens consumed per connection attempt for rate limiting */
#define RATELIMIT_TOKENS_PER_ACCEPT 1

/* ============================================================================
 * Static Helper Functions - Rate Limiter Management
 * ============================================================================ */

/**
 * disable_rate_limiter_unlocked - Disable connection rate limiting
 * @pool: Connection pool (must hold mutex)
 *
 * Clears the rate limiter pointer. Arena-allocated, no explicit free needed.
 */
static void
disable_rate_limiter_unlocked (T pool)
{
  pool->conn_limiter = NULL;
}

/**
 * create_rate_limiter_unlocked - Create new rate limiter
 * @pool: Connection pool (must hold mutex)
 * @rate: Connections per second
 * @burst: Burst capacity
 *
 * Returns: 1 on success, 0 on failure (raises exception)
 */
static int
create_rate_limiter_unlocked (T pool, size_t rate, size_t burst)
{
  TRY
    pool->conn_limiter
        = SocketRateLimit_new (pool->arena, rate, burst);
  EXCEPT (SocketRateLimit_Failed)
    return 0;
  END_TRY;

  return 1;
}

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

  return create_rate_limiter_unlocked (pool, rate, burst);
}

/* ============================================================================
 * Static Helper Functions - IP Tracker Management
 * ============================================================================ */

/**
 * disable_ip_tracker_unlocked - Disable per-IP connection limiting
 * @pool: Connection pool (must hold mutex)
 *
 * Clears the IP tracker pointer. Arena-allocated, no explicit free needed.
 */
static void
disable_ip_tracker_unlocked (T pool)
{
  pool->ip_tracker = NULL;
}

/**
 * create_ip_tracker_unlocked - Create new IP tracker
 * @pool: Connection pool (must hold mutex)
 * @max_conns: Maximum connections per IP
 *
 * Returns: 1 on success, 0 on failure (raises exception)
 */
static int
create_ip_tracker_unlocked (T pool, int max_conns)
{
  TRY
    pool->ip_tracker = SocketIPTracker_new (pool->arena, max_conns);
  EXCEPT (SocketIPTracker_Failed)
    return 0;
  END_TRY;

  return 1;
}

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

  return create_ip_tracker_unlocked (pool, max_conns);
}

/* ============================================================================
 * Static Helper Functions - Rate Limit Checks
 * ============================================================================ */

/**
 * check_rate_limit_unlocked - Check if connection rate allows new connection
 * @pool: Connection pool (must hold mutex)
 *
 * Returns: 1 if allowed, 0 if rate limited
 *
 * Does NOT consume a token - use for checking only.
 */
static int
check_rate_limit_unlocked (const T pool)
{
  if (!pool->conn_limiter)
    return 1;

  return SocketRateLimit_available (pool->conn_limiter) > 0;
}

/**
 * check_ip_limit_unlocked - Check if IP has room for more connections
 * @pool: Connection pool (must hold mutex)
 * @client_ip: Client IP address (NULL or empty allowed)
 *
 * Returns: 1 if allowed, 0 if IP limit reached
 */
static int
check_ip_limit_unlocked (const T pool, const char *client_ip)
{
  int count, max;

  if (!pool->ip_tracker)
    return 1;

  if (!client_ip || !client_ip[0])
    return 1;

  count = SocketIPTracker_count (pool->ip_tracker, client_ip);
  max = SocketIPTracker_getmax (pool->ip_tracker);

  return (max <= 0) || (count < max);
}

/**
 * consume_rate_token_unlocked - Consume a rate limit token
 * @pool: Connection pool (must hold mutex)
 *
 * Returns: 1 if token consumed, 0 if rate limited
 */
static int
consume_rate_token_unlocked (T pool)
{
  if (!pool->conn_limiter)
    return 1;

  return SocketRateLimit_try_acquire (pool->conn_limiter,
                                      RATELIMIT_TOKENS_PER_ACCEPT);
}

/**
 * track_client_ip_unlocked - Track client IP for per-IP limiting
 * @pool: Connection pool (must hold mutex)
 * @client_ip: Client IP address
 *
 * Returns: 1 if tracked successfully, 0 if IP limit reached
 */
static int
track_client_ip_unlocked (T pool, const char *client_ip)
{
  if (!pool->ip_tracker)
    return 1;

  if (!client_ip || !client_ip[0])
    return 1;

  return SocketIPTracker_track (pool->ip_tracker, client_ip);
}

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
  int safe_burst = burst;
  int safe_rate = conns_per_sec;

  assert (pool);

  pthread_mutex_lock (&pool->mutex);

  if (safe_rate <= 0)
    {
      disable_rate_limiter_unlocked (pool);
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  if (safe_burst <= 0)
    safe_burst = safe_rate;

  if (!configure_rate_limiter (pool, (size_t)safe_rate, (size_t)safe_burst))
    {
      pthread_mutex_unlock (&pool->mutex);
      SOCKET_ERROR_MSG ("Failed to create connection rate limiter");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }

  pthread_mutex_unlock (&pool->mutex);
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
  int rate;

  assert (pool);

  pthread_mutex_lock (&pool->mutex);
  rate = pool->conn_limiter
             ? (int)SocketRateLimit_get_rate (pool->conn_limiter)
             : 0;
  pthread_mutex_unlock (&pool->mutex);

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
  assert (pool);

  pthread_mutex_lock (&pool->mutex);

  if (max_conns <= 0)
    {
      disable_ip_tracker_unlocked (pool);
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  if (!configure_ip_tracker (pool, max_conns))
    {
      pthread_mutex_unlock (&pool->mutex);
      SOCKET_ERROR_MSG ("Failed to create IP tracker");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }

  pthread_mutex_unlock (&pool->mutex);
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
  int max;

  assert (pool);

  pthread_mutex_lock (&pool->mutex);
  max = pool->ip_tracker ? SocketIPTracker_getmax (pool->ip_tracker) : 0;
  pthread_mutex_unlock (&pool->mutex);

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
 * Returns: 1 if allowed, 0 if rate limited or IP limit reached
 * Thread-safe: Yes - acquires pool mutex
 *
 * Does NOT consume rate tokens - use for pre-check only.
 */
int
SocketPool_accept_allowed (T pool, const char *client_ip)
{
  int allowed;

  assert (pool);

  pthread_mutex_lock (&pool->mutex);

  allowed = check_rate_limit_unlocked (pool)
            && check_ip_limit_unlocked (pool, client_ip);

  pthread_mutex_unlock (&pool->mutex);

  return allowed;
}

/**
 * SocketPool_accept_limited - Rate-limited accept
 * @pool: Connection pool
 * @server: Server socket to accept from
 *
 * Returns: Accepted socket, or NULL if rate limited or accept failed
 * Thread-safe: Yes - acquires pool mutex for rate checks
 *
 * Consumes a rate token before attempting accept. If accept fails,
 * the token is NOT refunded (prevents DoS via rapid accept failures).
 */
Socket_T
SocketPool_accept_limited (T pool, Socket_T server)
{
  Socket_T client;
  const char *client_ip;
  int rate_ok;

  assert (pool);
  assert (server);

  /* Check and consume rate token */
  pthread_mutex_lock (&pool->mutex);
  rate_ok = consume_rate_token_unlocked (pool);
  pthread_mutex_unlock (&pool->mutex);

  if (!rate_ok)
    return NULL;

  /* Accept the connection */
  client = Socket_accept (server);
  if (!client)
    return NULL;

  /* Check per-IP limit and track */
  client_ip = Socket_getpeeraddr (client);

  pthread_mutex_lock (&pool->mutex);

  if (!track_client_ip_unlocked (pool, client_ip))
    {
      pthread_mutex_unlock (&pool->mutex);
      Socket_free (&client);
      return NULL;
    }

  pthread_mutex_unlock (&pool->mutex);

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
  int result;

  assert (pool);

  if (!ip || !ip[0])
    return 1;

  pthread_mutex_lock (&pool->mutex);
  result = track_client_ip_unlocked (pool, ip);
  pthread_mutex_unlock (&pool->mutex);

  return result;
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

  if (!ip || !ip[0])
    return;

  pthread_mutex_lock (&pool->mutex);

  if (pool->ip_tracker)
    SocketIPTracker_release (pool->ip_tracker, ip);

  pthread_mutex_unlock (&pool->mutex);
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
  int count = 0;

  assert (pool);

  if (!ip || !ip[0])
    return 0;

  pthread_mutex_lock (&pool->mutex);

  if (pool->ip_tracker)
    count = SocketIPTracker_count (pool->ip_tracker, ip);

  pthread_mutex_unlock (&pool->mutex);

  return count;
}

#undef T

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
 * Connection Rate Limiting
 * ============================================================================ */

/**
 * SocketPool_setconnrate - Set connection rate limit
 */
void
SocketPool_setconnrate (T pool, int conns_per_sec, int burst)
{
  volatile int safe_burst;
  volatile int safe_rate;
  
  assert (pool);

  /* Save parameters before TRY block to prevent clobbering */
  safe_rate = conns_per_sec;
  safe_burst = burst;

  pthread_mutex_lock (&pool->mutex);

  if (safe_rate <= 0)
    {
      /* Disable rate limiting */
      if (pool->conn_limiter)
        {
          /* Arena-allocated, just set to NULL */
          pool->conn_limiter = NULL;
        }
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  /* Default burst to rate if not specified */
  if (safe_burst <= 0)
    {
      safe_burst = safe_rate;
    }

  if (pool->conn_limiter)
    {
      /* Reconfigure existing limiter */
      SocketRateLimit_configure (pool->conn_limiter, (size_t)safe_rate,
                                 (size_t)safe_burst);
    }
  else
    {
      /* Create new limiter using pool's arena */
      TRY
        pool->conn_limiter = SocketRateLimit_new (pool->arena,
                                                  (size_t)safe_rate,
                                                  (size_t)safe_burst);
      EXCEPT (SocketRateLimit_Failed)
        pthread_mutex_unlock (&pool->mutex);
        SOCKET_ERROR_MSG ("Failed to create connection rate limiter");
        RAISE_POOL_ERROR (SocketPool_Failed);
      END_TRY;
    }

  pthread_mutex_unlock (&pool->mutex);
}

/**
 * SocketPool_getconnrate - Get connection rate limit
 */
int
SocketPool_getconnrate (T pool)
{
  int rate;

  assert (pool);

  pthread_mutex_lock (&pool->mutex);

  if (pool->conn_limiter)
    {
      rate = (int)SocketRateLimit_get_rate (pool->conn_limiter);
    }
  else
    {
      rate = 0; /* Disabled */
    }

  pthread_mutex_unlock (&pool->mutex);
  return rate;
}

/* ============================================================================
 * Per-IP Connection Limiting
 * ============================================================================ */

/**
 * SocketPool_setmaxperip - Set maximum connections per IP
 */
void
SocketPool_setmaxperip (T pool, int max_conns)
{
  assert (pool);

  pthread_mutex_lock (&pool->mutex);

  if (max_conns <= 0)
    {
      /* Disable per-IP limiting */
      if (pool->ip_tracker)
        {
          /* Arena-allocated, just set to NULL */
          pool->ip_tracker = NULL;
        }
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  if (pool->ip_tracker)
    {
      /* Reconfigure existing tracker */
      SocketIPTracker_setmax (pool->ip_tracker, max_conns);
    }
  else
    {
      /* Create new tracker using pool's arena */
      TRY
        pool->ip_tracker = SocketIPTracker_new (pool->arena, max_conns);
      EXCEPT (SocketIPTracker_Failed)
        pthread_mutex_unlock (&pool->mutex);
        SOCKET_ERROR_MSG ("Failed to create IP tracker");
        RAISE_POOL_ERROR (SocketPool_Failed);
      END_TRY;
    }

  pthread_mutex_unlock (&pool->mutex);
}

/**
 * SocketPool_getmaxperip - Get maximum connections per IP
 */
int
SocketPool_getmaxperip (T pool)
{
  int max;

  assert (pool);

  pthread_mutex_lock (&pool->mutex);

  if (pool->ip_tracker)
    {
      max = SocketIPTracker_getmax (pool->ip_tracker);
    }
  else
    {
      max = 0; /* Disabled */
    }

  pthread_mutex_unlock (&pool->mutex);
  return max;
}

/* ============================================================================
 * Rate Limit Checking
 * ============================================================================ */

/**
 * SocketPool_accept_allowed - Check if accepting is allowed
 */
int
SocketPool_accept_allowed (T pool, const char *client_ip)
{
  int allowed = 1;

  assert (pool);

  pthread_mutex_lock (&pool->mutex);

  /* Check connection rate limit (without consuming) */
  if (pool->conn_limiter)
    {
      if (SocketRateLimit_available (pool->conn_limiter) == 0)
        {
          allowed = 0;
        }
    }

  /* Check per-IP limit */
  if (allowed && pool->ip_tracker && client_ip && client_ip[0])
    {
      int count = SocketIPTracker_count (pool->ip_tracker, client_ip);
      int max = SocketIPTracker_getmax (pool->ip_tracker);
      if (max > 0 && count >= max)
        {
          allowed = 0;
        }
    }

  pthread_mutex_unlock (&pool->mutex);
  return allowed;
}

/**
 * SocketPool_accept_limited - Rate-limited accept
 */
Socket_T
SocketPool_accept_limited (T pool, Socket_T server)
{
  Socket_T client;
  const char *client_ip;
  int rate_ok = 1;
  int ip_ok = 1;

  assert (pool);
  assert (server);

  /* First, check rate limit (consumes token if available) */
  pthread_mutex_lock (&pool->mutex);

  if (pool->conn_limiter)
    {
      if (!SocketRateLimit_try_acquire (pool->conn_limiter, 1))
        {
          rate_ok = 0;
        }
    }

  pthread_mutex_unlock (&pool->mutex);

  if (!rate_ok)
    {
      return NULL; /* Rate limited */
    }

  /* Accept the connection */
  client = Socket_accept (server);
  if (!client)
    {
      /* Would block or error - refund the rate token if we consumed one */
      /* Actually, don't refund - the rate limit should apply to attempts,
       * not just successes. This prevents DoS via rapid accept failures. */
      return NULL;
    }

  /* Check per-IP limit */
  client_ip = Socket_getpeeraddr (client);

  pthread_mutex_lock (&pool->mutex);

  if (pool->ip_tracker && client_ip && client_ip[0])
    {
      if (!SocketIPTracker_track (pool->ip_tracker, client_ip))
        {
          ip_ok = 0;
        }
    }

  pthread_mutex_unlock (&pool->mutex);

  if (!ip_ok)
    {
      /* IP limit reached - close and reject */
      Socket_free (&client);
      return NULL;
    }

  return client;
}

/* ============================================================================
 * Manual IP Tracking
 * ============================================================================ */

/**
 * SocketPool_track_ip - Manually track IP for per-IP limiting
 */
int
SocketPool_track_ip (T pool, const char *ip)
{
  int result = 1;

  assert (pool);

  if (!ip || !ip[0])
    {
      return 1; /* Always allow empty IP */
    }

  pthread_mutex_lock (&pool->mutex);

  if (pool->ip_tracker)
    {
      result = SocketIPTracker_track (pool->ip_tracker, ip);
    }

  pthread_mutex_unlock (&pool->mutex);
  return result;
}

/**
 * SocketPool_release_ip - Release tracked IP when connection closes
 */
void
SocketPool_release_ip (T pool, const char *ip)
{
  assert (pool);

  if (!ip || !ip[0])
    {
      return;
    }

  pthread_mutex_lock (&pool->mutex);

  if (pool->ip_tracker)
    {
      SocketIPTracker_release (pool->ip_tracker, ip);
    }

  pthread_mutex_unlock (&pool->mutex);
}

/**
 * SocketPool_ip_count - Get connection count for IP
 */
int
SocketPool_ip_count (T pool, const char *ip)
{
  int count = 0;

  assert (pool);

  if (!ip || !ip[0])
    {
      return 0;
    }

  pthread_mutex_lock (&pool->mutex);

  if (pool->ip_tracker)
    {
      count = SocketIPTracker_count (pool->ip_tracker, ip);
    }

  pthread_mutex_unlock (&pool->mutex);
  return count;
}

#undef T


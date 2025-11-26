/**
 * test_ratelimit.c - Rate Limiting Module Tests
 *
 * Part of the Socket Library Test Suite
 *
 * Tests for:
 * - SocketRateLimit: Token bucket algorithm
 * - SocketIPTracker: Per-IP connection tracking
 * - SocketPool rate limiting integration
 * - Socket bandwidth limiting
 */

#include <assert.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketIPTracker.h"
#include "core/SocketRateLimit.h"
#include "pool/SocketPool.h"
#include "socket/Socket.h"
#include "test/Test.h"

/* ============================================================================
 * SocketRateLimit Tests
 * ============================================================================ */

/* Test rate limiter creation with arena */
TEST (ratelimit_create_with_arena)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;

  ASSERT_NOT_NULL (arena);

  TRY
    limiter = SocketRateLimit_new (arena, 100, 50);
    ASSERT_NOT_NULL (limiter);
    ASSERT_EQ (100, SocketRateLimit_get_rate (limiter));
    ASSERT_EQ (50, SocketRateLimit_get_bucket_size (limiter));
  EXCEPT (SocketRateLimit_Failed)
    Arena_dispose (&arena);
    ASSERT (0); /* Should not reach here */
  END_TRY;

  Arena_dispose (&arena);
}

/* Test rate limiter creation with malloc */
TEST (ratelimit_create_with_malloc)
{
  SocketRateLimit_T limiter = NULL;

  TRY
    limiter = SocketRateLimit_new (NULL, 100, 50);
    ASSERT_NOT_NULL (limiter);
    SocketRateLimit_free (&limiter);
    ASSERT_NULL (limiter);
  EXCEPT (SocketRateLimit_Failed)
    ASSERT (0); /* Should not reach here */
  END_TRY;
}

/* Test token acquisition */
TEST (ratelimit_acquire_tokens)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;
  int acquired;

  TRY
    /* Create limiter: 100 tokens/sec, bucket of 10 */
    limiter = SocketRateLimit_new (arena, 100, 10);

    /* Initial bucket should be full (10 tokens) */
    ASSERT_EQ (10, SocketRateLimit_available (limiter));

    /* Acquire all tokens */
    acquired = SocketRateLimit_try_acquire (limiter, 10);
    ASSERT_EQ (1, acquired);
    ASSERT_EQ (0, SocketRateLimit_available (limiter));

    /* Try to acquire more - should fail */
    acquired = SocketRateLimit_try_acquire (limiter, 1);
    ASSERT_EQ (0, acquired);
  EXCEPT (SocketRateLimit_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test token refill over time */
TEST (ratelimit_refill_over_time)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;
  size_t available;

  TRY
    /* Create limiter: 1000 tokens/sec, bucket of 100 */
    limiter = SocketRateLimit_new (arena, 1000, 100);

    /* Drain the bucket */
    SocketRateLimit_try_acquire (limiter, 100);
    ASSERT_EQ (0, SocketRateLimit_available (limiter));

    /* Wait for refill (50ms should give ~50 tokens) */
    usleep (50000);

    available = SocketRateLimit_available (limiter);
    /* Allow some tolerance for timing */
    ASSERT (available >= 30 && available <= 70);
  EXCEPT (SocketRateLimit_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test wait time calculation */
TEST (ratelimit_wait_time_calculation)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;
  int64_t wait_ms;

  TRY
    /* Create limiter: 100 tokens/sec, bucket of 10 */
    limiter = SocketRateLimit_new (arena, 100, 10);

    /* With full bucket, wait time should be 0 */
    wait_ms = SocketRateLimit_wait_time_ms (limiter, 5);
    ASSERT_EQ (0, wait_ms);

    /* Drain bucket */
    SocketRateLimit_try_acquire (limiter, 10);

    /* Need 5 tokens at 100/sec = 50ms wait */
    wait_ms = SocketRateLimit_wait_time_ms (limiter, 5);
    ASSERT (wait_ms >= 40 && wait_ms <= 60);

    /* Impossible request (more than bucket size) */
    wait_ms = SocketRateLimit_wait_time_ms (limiter, 20);
    ASSERT_EQ (-1, wait_ms);
  EXCEPT (SocketRateLimit_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test runtime reconfiguration */
TEST (ratelimit_reconfigure)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;

  TRY
    limiter = SocketRateLimit_new (arena, 100, 50);

    /* Reconfigure */
    SocketRateLimit_configure (limiter, 200, 100);
    ASSERT_EQ (200, SocketRateLimit_get_rate (limiter));
    ASSERT_EQ (100, SocketRateLimit_get_bucket_size (limiter));

    /* Partial reconfigure (0 keeps current) */
    SocketRateLimit_configure (limiter, 0, 150);
    ASSERT_EQ (200, SocketRateLimit_get_rate (limiter));
    ASSERT_EQ (150, SocketRateLimit_get_bucket_size (limiter));
  EXCEPT (SocketRateLimit_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test bucket reset */
TEST (ratelimit_reset)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;

  TRY
    limiter = SocketRateLimit_new (arena, 100, 50);

    /* Drain bucket */
    SocketRateLimit_try_acquire (limiter, 50);
    ASSERT_EQ (0, SocketRateLimit_available (limiter));

    /* Reset */
    SocketRateLimit_reset (limiter);
    ASSERT_EQ (50, SocketRateLimit_available (limiter));
  EXCEPT (SocketRateLimit_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test zero tokens acquisition */
TEST (ratelimit_zero_tokens)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;
  int acquired;

  TRY
    limiter = SocketRateLimit_new (arena, 100, 10);

    /* Zero tokens always succeeds */
    acquired = SocketRateLimit_try_acquire (limiter, 0);
    ASSERT_EQ (1, acquired);

    /* Drain bucket */
    SocketRateLimit_try_acquire (limiter, 10);

    /* Zero still succeeds when empty */
    acquired = SocketRateLimit_try_acquire (limiter, 0);
    ASSERT_EQ (1, acquired);
  EXCEPT (SocketRateLimit_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* ============================================================================
 * SocketIPTracker Tests
 * ============================================================================ */

/* Test IP tracker creation */
TEST (iptracker_create)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;

  TRY
    tracker = SocketIPTracker_new (arena, 10);
    ASSERT_NOT_NULL (tracker);
    ASSERT_EQ (10, SocketIPTracker_getmax (tracker));
    ASSERT_EQ (0, SocketIPTracker_total (tracker));
    ASSERT_EQ (0, SocketIPTracker_unique_ips (tracker));
  EXCEPT (SocketIPTracker_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test IP tracking */
TEST (iptracker_track_connections)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;
  int result;

  TRY
    tracker = SocketIPTracker_new (arena, 3);

    /* Track first connection */
    result = SocketIPTracker_track (tracker, "192.168.1.1");
    ASSERT_EQ (1, result);
    ASSERT_EQ (1, SocketIPTracker_count (tracker, "192.168.1.1"));

    /* Track second connection from same IP */
    result = SocketIPTracker_track (tracker, "192.168.1.1");
    ASSERT_EQ (1, result);
    ASSERT_EQ (2, SocketIPTracker_count (tracker, "192.168.1.1"));

    /* Track third connection */
    result = SocketIPTracker_track (tracker, "192.168.1.1");
    ASSERT_EQ (1, result);
    ASSERT_EQ (3, SocketIPTracker_count (tracker, "192.168.1.1"));

    /* Fourth should be rejected (limit is 3) */
    result = SocketIPTracker_track (tracker, "192.168.1.1");
    ASSERT_EQ (0, result);
    ASSERT_EQ (3, SocketIPTracker_count (tracker, "192.168.1.1"));

    /* Different IP should be allowed */
    result = SocketIPTracker_track (tracker, "192.168.1.2");
    ASSERT_EQ (1, result);
    ASSERT_EQ (2, SocketIPTracker_unique_ips (tracker));
  EXCEPT (SocketIPTracker_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test IP release */
TEST (iptracker_release_connections)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;
  int result;

  TRY
    tracker = SocketIPTracker_new (arena, 2);

    /* Fill to limit */
    SocketIPTracker_track (tracker, "10.0.0.1");
    SocketIPTracker_track (tracker, "10.0.0.1");
    result = SocketIPTracker_track (tracker, "10.0.0.1");
    ASSERT_EQ (0, result);

    /* Release one */
    SocketIPTracker_release (tracker, "10.0.0.1");
    ASSERT_EQ (1, SocketIPTracker_count (tracker, "10.0.0.1"));

    /* Can now track again */
    result = SocketIPTracker_track (tracker, "10.0.0.1");
    ASSERT_EQ (1, result);

    /* Release all - entry should be removed */
    SocketIPTracker_release (tracker, "10.0.0.1");
    SocketIPTracker_release (tracker, "10.0.0.1");
    ASSERT_EQ (0, SocketIPTracker_count (tracker, "10.0.0.1"));
    ASSERT_EQ (0, SocketIPTracker_unique_ips (tracker));
  EXCEPT (SocketIPTracker_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test unlimited mode (max=0) */
TEST (iptracker_unlimited_mode)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;
  int i;
  int result;

  TRY
    tracker = SocketIPTracker_new (arena, 0); /* Unlimited */

    /* Should allow many connections */
    for (i = 0; i < 100; i++)
      {
        result = SocketIPTracker_track (tracker, "unlimited.test");
        ASSERT_EQ (1, result);
      }
    ASSERT_EQ (100, SocketIPTracker_count (tracker, "unlimited.test"));
  EXCEPT (SocketIPTracker_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test clearing all entries */
TEST (iptracker_clear_all)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;

  TRY
    tracker = SocketIPTracker_new (arena, 10);

    /* Add some entries */
    SocketIPTracker_track (tracker, "1.1.1.1");
    SocketIPTracker_track (tracker, "2.2.2.2");
    SocketIPTracker_track (tracker, "3.3.3.3");
    ASSERT_EQ (3, SocketIPTracker_unique_ips (tracker));

    /* Clear */
    SocketIPTracker_clear (tracker);
    ASSERT_EQ (0, SocketIPTracker_unique_ips (tracker));
    ASSERT_EQ (0, SocketIPTracker_total (tracker));
  EXCEPT (SocketIPTracker_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test IPv6 address handling */
TEST (iptracker_ipv6_addresses)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;
  int result;

  TRY
    tracker = SocketIPTracker_new (arena, 5);

    /* Track IPv6 addresses */
    result = SocketIPTracker_track (tracker, "::1");
    ASSERT_EQ (1, result);

    result = SocketIPTracker_track (tracker, "2001:db8::1");
    ASSERT_EQ (1, result);

    result = SocketIPTracker_track (tracker, "fe80::1%eth0");
    ASSERT_EQ (1, result);

    ASSERT_EQ (3, SocketIPTracker_unique_ips (tracker));
  EXCEPT (SocketIPTracker_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test setmax changes limit */
TEST (iptracker_setmax)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;
  int result;

  TRY
    tracker = SocketIPTracker_new (arena, 5);
    ASSERT_EQ (5, SocketIPTracker_getmax (tracker));

    SocketIPTracker_setmax (tracker, 10);
    ASSERT_EQ (10, SocketIPTracker_getmax (tracker));

    /* Add 6 connections - should work now */
    for (int i = 0; i < 6; i++)
      {
        result = SocketIPTracker_track (tracker, "test.ip");
      }
    ASSERT_EQ (6, SocketIPTracker_count (tracker, "test.ip"));

    /* Set limit below current count - existing stay but new rejected */
    SocketIPTracker_setmax (tracker, 2);
    result = SocketIPTracker_track (tracker, "test.ip");
    ASSERT_EQ (0, result); /* Rejected */
    ASSERT_EQ (6, SocketIPTracker_count (tracker, "test.ip")); /* Count unchanged */
  EXCEPT (SocketIPTracker_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* ============================================================================
 * SocketPool Rate Limiting Tests
 * ============================================================================ */

/* Test connection rate limiting in pool */
TEST (pool_connection_rate_limit)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool;

  TRY
    pool = SocketPool_new (arena, 100, 4096);

    /* Initially no rate limit */
    ASSERT_EQ (0, SocketPool_getconnrate (pool));

    /* Set rate limit */
    SocketPool_setconnrate (pool, 10, 5);
    ASSERT_EQ (10, SocketPool_getconnrate (pool));

    /* Disable rate limit */
    SocketPool_setconnrate (pool, 0, 0);
    ASSERT_EQ (0, SocketPool_getconnrate (pool));
  EXCEPT (SocketPool_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test per-IP limiting in pool */
TEST (pool_per_ip_limit)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool;

  TRY
    pool = SocketPool_new (arena, 100, 4096);

    /* Initially no per-IP limit */
    ASSERT_EQ (0, SocketPool_getmaxperip (pool));

    /* Set per-IP limit */
    SocketPool_setmaxperip (pool, 5);
    ASSERT_EQ (5, SocketPool_getmaxperip (pool));

    /* Disable per-IP limit */
    SocketPool_setmaxperip (pool, 0);
    ASSERT_EQ (0, SocketPool_getmaxperip (pool));
  EXCEPT (SocketPool_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test manual IP tracking in pool */
TEST (pool_manual_ip_tracking)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool;
  int result;

  TRY
    pool = SocketPool_new (arena, 100, 4096);
    SocketPool_setmaxperip (pool, 2);

    /* Track IPs manually */
    result = SocketPool_track_ip (pool, "192.168.1.100");
    ASSERT_EQ (1, result);
    ASSERT_EQ (1, SocketPool_ip_count (pool, "192.168.1.100"));

    result = SocketPool_track_ip (pool, "192.168.1.100");
    ASSERT_EQ (1, result);

    result = SocketPool_track_ip (pool, "192.168.1.100");
    ASSERT_EQ (0, result); /* Rejected (limit 2) */

    /* Release */
    SocketPool_release_ip (pool, "192.168.1.100");
    ASSERT_EQ (1, SocketPool_ip_count (pool, "192.168.1.100"));

    /* Can track again */
    result = SocketPool_track_ip (pool, "192.168.1.100");
    ASSERT_EQ (1, result);
  EXCEPT (SocketPool_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test accept_allowed check */
TEST (pool_accept_allowed_check)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool;
  int allowed;

  TRY
    pool = SocketPool_new (arena, 100, 4096);

    /* No limits - always allowed */
    allowed = SocketPool_accept_allowed (pool, "10.0.0.1");
    ASSERT_EQ (1, allowed);

    /* Set per-IP limit */
    SocketPool_setmaxperip (pool, 1);
    SocketPool_track_ip (pool, "10.0.0.1");

    /* Now at limit */
    allowed = SocketPool_accept_allowed (pool, "10.0.0.1");
    ASSERT_EQ (0, allowed);

    /* Different IP still allowed */
    allowed = SocketPool_accept_allowed (pool, "10.0.0.2");
    ASSERT_EQ (1, allowed);
  EXCEPT (SocketPool_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* ============================================================================
 * Socket Bandwidth Limiting Tests
 * ============================================================================ */

/* Test socket bandwidth limiting API */
TEST (socket_bandwidth_api)
{
  Socket_T sock;

  TRY
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (sock);

    /* Initially no bandwidth limit */
    ASSERT_EQ (0, Socket_getbandwidth (sock));

    /* Set bandwidth limit */
    Socket_setbandwidth (sock, 10240); /* 10 KB/s */
    ASSERT_EQ (10240, Socket_getbandwidth (sock));

    /* Disable bandwidth limit */
    Socket_setbandwidth (sock, 0);
    ASSERT_EQ (0, Socket_getbandwidth (sock));

    Socket_free (&sock);
  EXCEPT (Socket_Failed)
    ASSERT (0);
  END_TRY;
}

/* ============================================================================
 * Thread Safety Tests
 * ============================================================================ */

/* Thread test data for rate limiter */
static SocketRateLimit_T thread_test_limiter;
static int thread_acquired_count;
static pthread_mutex_t thread_test_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Thread function for rate limiter test */
static void *
thread_acquire_tokens (void *arg)
{
  int i;
  int local_count = 0;
  (void)arg;

  for (i = 0; i < 100; i++)
    {
      if (SocketRateLimit_try_acquire (thread_test_limiter, 1))
        {
          local_count++;
        }
      usleep (1000); /* 1ms between attempts */
    }

  pthread_mutex_lock (&thread_test_mutex);
  thread_acquired_count += local_count;
  pthread_mutex_unlock (&thread_test_mutex);

  return NULL;
}

/* Test rate limiter thread safety */
TEST (ratelimit_thread_safety)
{
  Arena_T arena = Arena_new ();
  pthread_t threads[4];
  int i;

  TRY
    /* Create limiter: 500 tokens/sec, bucket of 50 */
    thread_test_limiter = SocketRateLimit_new (arena, 500, 50);
    thread_acquired_count = 0;

    /* Start 4 threads competing for tokens */
    for (i = 0; i < 4; i++)
      {
        pthread_create (&threads[i], NULL, thread_acquire_tokens, NULL);
      }

    /* Wait for all threads */
    for (i = 0; i < 4; i++)
      {
        pthread_join (threads[i], NULL);
      }

    /* Should have acquired some tokens (exact count varies) */
    ASSERT (thread_acquired_count > 0);
    /* Should not exceed what's possible (~500/sec for 400ms = ~200 + 50 burst) */
    ASSERT (thread_acquired_count <= 300);
  EXCEPT (SocketRateLimit_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* IP tracker thread test data */
static SocketIPTracker_T thread_test_tracker;
static int thread_track_success;
static int thread_track_fail;

/* Thread function for IP tracker test */
static void *
thread_track_ip (void *arg)
{
  int i;
  int local_success = 0;
  int local_fail = 0;
  (void)arg;

  for (i = 0; i < 50; i++)
    {
      if (SocketIPTracker_track (thread_test_tracker, "shared.ip"))
        {
          local_success++;
          usleep (500);
          SocketIPTracker_release (thread_test_tracker, "shared.ip");
        }
      else
        {
          local_fail++;
        }
      usleep (100);
    }

  pthread_mutex_lock (&thread_test_mutex);
  thread_track_success += local_success;
  thread_track_fail += local_fail;
  pthread_mutex_unlock (&thread_test_mutex);

  return NULL;
}

/* Test IP tracker thread safety */
TEST (iptracker_thread_safety)
{
  Arena_T arena = Arena_new ();
  pthread_t threads[4];
  int i;

  TRY
    /* Create tracker with limit of 2 per IP */
    thread_test_tracker = SocketIPTracker_new (arena, 2);
    thread_track_success = 0;
    thread_track_fail = 0;

    /* Start 4 threads competing for IP slots */
    for (i = 0; i < 4; i++)
      {
        pthread_create (&threads[i], NULL, thread_track_ip, NULL);
      }

    /* Wait for all threads */
    for (i = 0; i < 4; i++)
      {
        pthread_join (threads[i], NULL);
      }

    /* Should have some successes and some failures */
    ASSERT (thread_track_success > 0);
    ASSERT (thread_track_fail > 0);

    /* Final count should be 0 (all released) */
    ASSERT_EQ (0, SocketIPTracker_count (thread_test_tracker, "shared.ip"));
  EXCEPT (SocketIPTracker_Failed)
    Arena_dispose (&arena);
    ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test Suite Entry Point
 * ============================================================================ */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

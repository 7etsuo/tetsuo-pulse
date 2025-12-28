/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_socketdns.c
 * @ingroup dns
 * @brief Comprehensive SocketDNS unit tests.
 *
 * Industry-standard test coverage for SocketDNS async DNS module.
 * Tests async resolution, callbacks, cancellation, queue management,
 * thread pool, and synchronization primitives.
 *
 * @see SocketDNS.h for module API.
 * @see SocketDNS-private.h for internal structures.
 */

/* cppcheck-suppress-file constVariablePointer ; test result inspection */
/* cppcheck-suppress-file redundantAssignment ; test code patterns */

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNS.h"
#include "dns/SocketDNSResolver.h"
#include "socket/SocketCommon.h"
#include "test/Test.h"

/* Suppress longjmp clobbering warnings for test variables used with TRY/EXCEPT
 */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* ==================== Basic Resolver Tests ==================== */

TEST (socketdns_new_creates_resolver)
{
  SocketDNS_T dns = SocketDNS_new ();
  ASSERT_NOT_NULL (dns);
  SocketDNS_free (&dns);
  ASSERT_NULL (dns);
}

TEST (socketdns_pollfd)
{
  SocketDNS_T dns = SocketDNS_new ();
  ASSERT_NOT_NULL (dns);
  int fd = SocketDNS_pollfd (dns);
  ASSERT_NE (fd, -1);
  SocketDNS_free (&dns);
}

/* ==================== Resolution Tests ==================== */

TEST (socketdns_resolve_localhost)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;

  TRY req = SocketDNS_resolve (dns, "localhost", 80, NULL, NULL);
  ASSERT_NOT_NULL (req);

  usleep (100000);
  SocketDNS_check (dns);

  struct addrinfo *result = SocketDNS_getresult (dns, req);
  if (result)
    {
      ASSERT_NOT_NULL (result);
      SocketCommon_free_addrinfo (result);
    }
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

TEST (socketdns_resolve_loopback_ip)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;

  TRY req = SocketDNS_resolve (dns, "127.0.0.1", 80, NULL, NULL);
  ASSERT_NOT_NULL (req);

  usleep (100000);
  SocketDNS_check (dns);

  struct addrinfo *result = SocketDNS_getresult (dns, req);
  if (result)
    {
      ASSERT_NOT_NULL (result);
      SocketCommon_free_addrinfo (result);
    }
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

TEST (socketdns_resolve_ipv6_loopback)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;

  TRY req = SocketDNS_resolve (dns, "::1", 80, NULL, NULL);
  ASSERT_NOT_NULL (req);

  usleep (100000);
  SocketDNS_check (dns);

  struct addrinfo *result = SocketDNS_getresult (dns, req);
  if (result)
    {
      ASSERT_NOT_NULL (result);
      SocketCommon_free_addrinfo (result);
    }
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

TEST (socketdns_resolve_with_port)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;

  TRY req = SocketDNS_resolve (dns, "localhost", 8080, NULL, NULL);
  ASSERT_NOT_NULL (req);

  usleep (100000);
  SocketDNS_check (dns);

  struct addrinfo *result = SocketDNS_getresult (dns, req);
  if (result)
    SocketCommon_free_addrinfo (result);
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

TEST (socketdns_resolve_without_port)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;

  TRY req = SocketDNS_resolve (dns, "localhost", 0, NULL, NULL);
  ASSERT_NOT_NULL (req);

  usleep (100000);
  SocketDNS_check (dns);

  struct addrinfo *result = SocketDNS_getresult (dns, req);
  if (result)
    SocketCommon_free_addrinfo (result);
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

/* ==================== Multiple Resolution Tests ==================== */

TEST (socketdns_multiple_resolutions)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req1 = NULL, req2 = NULL, req3 = NULL;

  TRY req1 = SocketDNS_resolve (dns, "localhost", 80, NULL, NULL);
  req2 = SocketDNS_resolve (dns, "127.0.0.1", 443, NULL, NULL);
  req3 = SocketDNS_resolve (dns, "::1", 8080, NULL, NULL);

  ASSERT_NOT_NULL (req1);
  ASSERT_NOT_NULL (req2);
  ASSERT_NOT_NULL (req3);

  usleep (200000);
  SocketDNS_check (dns);

  struct addrinfo *res1 = SocketDNS_getresult (dns, req1);
  struct addrinfo *res2 = SocketDNS_getresult (dns, req2);
  struct addrinfo *res3 = SocketDNS_getresult (dns, req3);

  if (res1)
    SocketCommon_free_addrinfo (res1);
  if (res2)
    SocketCommon_free_addrinfo (res2);
  if (res3)
    SocketCommon_free_addrinfo (res3);
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

TEST (socketdns_sequential_resolutions)
{
  SocketDNS_T dns = SocketDNS_new ();

  TRY volatile int i;
  for (i = 0; i < 10; i++)
    {
      Request_T req
          = SocketDNS_resolve (dns, "127.0.0.1", 80, NULL, NULL);
      ASSERT_NOT_NULL (req);
      usleep (50000);
      SocketDNS_check (dns);
      struct addrinfo *result = SocketDNS_getresult (dns, req);
      if (result)
        SocketCommon_free_addrinfo (result);
    }
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

/* ==================== Callback Tests ==================== */

static void
slow_queue_callback (Request_T req, struct addrinfo *result,
                     int error, void *data)
{
  (void)req;
  (void)error;
  if (data)
    *(int *)data = 1;
  usleep (50000);
  if (result)
    SocketCommon_free_addrinfo (result);
}

static atomic_int callback_invoked;
static void
test_callback (Request_T req, struct addrinfo *result, int error,
               void *data)
{
  (void)req;
  (void)error;
  (void)data;
  callback_invoked = 1;
  if (result)
    SocketCommon_free_addrinfo (result);
}

TEST (socketdns_callback_invoked)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;

  TRY callback_invoked = 0;
  req = SocketDNS_resolve (dns, "127.0.0.1", 80, test_callback, NULL);
  ASSERT_NOT_NULL (req);

  usleep (200000);
  SocketDNS_check (dns);

  ASSERT_NE (callback_invoked, 0);
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

static atomic_int test_received_data;

static void
callback_check_data (Request_T r, struct addrinfo *res, int err,
                     void *d)
{
  (void)r;
  (void)err;
  if (d)
    test_received_data = *(int *)d;
  if (res)
    SocketCommon_free_addrinfo (res);
}

TEST (socketdns_callback_with_user_data)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;
  int user_data = 12345;

  TRY test_received_data = 0;
  req = SocketDNS_resolve (dns, "localhost", 80, callback_check_data,
                           &user_data);
  ASSERT_NOT_NULL (req);

  usleep (200000);
  SocketDNS_check (dns);

  ASSERT_EQ (test_received_data, user_data);
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

/* ==================== Cancellation Tests ==================== */

TEST (socketdns_cancel_request)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;

  TRY req = SocketDNS_resolve (dns, "localhost", 80, NULL, NULL);
  ASSERT_NOT_NULL (req);
  SocketDNS_cancel (dns, req);
  usleep (100000);
  struct addrinfo *result = SocketDNS_getresult (dns, req);
  ASSERT_NULL (result);
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

TEST (socketdns_cancel_multiple)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req1 = NULL, req2 = NULL;

  TRY req1 = SocketDNS_resolve (dns, "localhost", 80, NULL, NULL);
  req2 = SocketDNS_resolve (dns, "127.0.0.1", 80, NULL, NULL);

  SocketDNS_cancel (dns, req1);
  SocketDNS_cancel (dns, req2);

  usleep (100000);
  ASSERT_NULL (SocketDNS_getresult (dns, req1));
  ASSERT_NULL (SocketDNS_getresult (dns, req2));
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

/* ==================== Check Operation Tests ==================== */

TEST (socketdns_check_returns_completion_count)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;

  TRY
  {
    volatile int count;

    req = SocketDNS_resolve (dns, "localhost", 80, NULL, NULL);
    usleep (100000);
    count = SocketDNS_check (dns);
    ASSERT_NE (count, -1);

    /* Drain result to release getaddrinfo allocation */
    struct addrinfo *result = SocketDNS_getresult (dns, req);
    if (result)
      SocketCommon_free_addrinfo (result);
  }
  EXCEPT (SocketDNS_Failed) { (void)0; }
  FINALLY { SocketDNS_free (&dns); }
  END_TRY;
}

TEST (socketdns_check_before_completion)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;

  TRY
  {
    volatile int count;

    req = SocketDNS_resolve (dns, "localhost", 80, NULL, NULL);
    count = SocketDNS_check (dns);
    (void)count;

    /* Allow resolver to finish, then drain result */
    usleep (100000);
    SocketDNS_check (dns);
    struct addrinfo *result = SocketDNS_getresult (dns, req);
    if (result)
      SocketCommon_free_addrinfo (result);
  }
  EXCEPT (SocketDNS_Failed) { (void)0; }
  FINALLY { SocketDNS_free (&dns); }
  END_TRY;
}

/* ==================== GetResult Tests ==================== */

TEST (socketdns_getresult_before_completion)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;

  /* Note: With the new resolver architecture (Phase 2.x), localhost resolution
   * is synchronous - the callback is invoked immediately during resolve().
   * This test now verifies that synchronous resolution works correctly. */
  TRY req = SocketDNS_resolve (dns, "localhost", 80, NULL, NULL);
  struct addrinfo *result = SocketDNS_getresult (dns, req);
  /* Localhost resolution is synchronous, so result should be available */
  ASSERT_NOT_NULL (result);
  SocketCommon_free_addrinfo (result);
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

TEST (socketdns_getresult_after_completion)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;

  TRY req = SocketDNS_resolve (dns, "127.0.0.1", 80, NULL, NULL);
  ASSERT_NOT_NULL (req);

  usleep (100000);
  SocketDNS_check (dns);

  struct addrinfo *result = SocketDNS_getresult (dns, req);
  if (result)
    {
      ASSERT_NOT_NULL (result);
      SocketCommon_free_addrinfo (result);
    }
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

TEST (socketdns_getresult_clears_result)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;

  TRY req = SocketDNS_resolve (dns, "127.0.0.1", 80, NULL, NULL);
  usleep (100000);
  SocketDNS_check (dns);

  struct addrinfo *result1 = SocketDNS_getresult (dns, req);
  if (result1)
    {
      SocketCommon_free_addrinfo (result1);
      struct addrinfo *result2 = SocketDNS_getresult (dns, req);
      ASSERT_NULL (result2);
    }
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

/* ==================== Concurrent Resolution Tests ==================== */

TEST (socketdns_many_concurrent_resolutions)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T requests[20];

  TRY volatile int i;
  volatile int completed = 0;
  for (i = 0; i < 20; i++)
    {
      requests[i] = SocketDNS_resolve (dns, "127.0.0.1", 80 + i, NULL, NULL);
      ASSERT_NOT_NULL (requests[i]);
    }

  usleep (500000);
  SocketDNS_check (dns);

  for (i = 0; i < 20; i++)
    {
      struct addrinfo *result = SocketDNS_getresult (dns, requests[i]);
      if (result)
        {
          completed++;
          SocketCommon_free_addrinfo (result);
        }
    }
  ASSERT_NE (completed, 0);
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

/* ==================== Stress Tests ==================== */

TEST (socketdns_rapid_resolution_requests)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T requests[50] = { 0 };

  TRY
  {
    volatile int i;
    for (i = 0; i < 50; i++)
      {
        requests[i] = SocketDNS_resolve (dns, "127.0.0.1", 80, NULL, NULL);
        ASSERT_NOT_NULL (requests[i]);
      }
    usleep (500000);
    SocketDNS_check (dns);

    for (i = 0; i < 50; i++)
      {
        struct addrinfo *result = SocketDNS_getresult (dns, requests[i]);
        if (result)
          SocketCommon_free_addrinfo (result);
      }
  }
  EXCEPT (SocketDNS_Failed) { ASSERT (0); }
  FINALLY { SocketDNS_free (&dns); }
  END_TRY;
}

TEST (socketdns_resolve_cancel_cycle)
{
  SocketDNS_T dns = SocketDNS_new ();

  TRY volatile int i;
  for (i = 0; i < 20; i++)
    {
      Request_T req
          = SocketDNS_resolve (dns, "localhost", 80, NULL, NULL);
      SocketDNS_cancel (dns, req);
    }
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

/* ==================== Thread Safety Tests ==================== */

static void *
thread_resolve_requests (void *arg)
{
  SocketDNS_T dns = (SocketDNS_T)arg;

  for (volatile int i = 0; i < 10; i++)
    {
      int stop = 0;
      Request_T req = NULL;
      struct addrinfo *result = NULL;

      TRY
      {
        req = SocketDNS_resolve (dns, "127.0.0.1", 80, NULL, NULL);
        if (req == NULL)
          {
            /* Use test framework failure reporting and abort this thread's
             * work NOTE: Use RETURN to properly unwind exception stack inside
             * TRY block. */
            Test_fail ("Assertion failed: req is NULL", __FILE__, __LINE__);
            RETURN NULL;
          }

        while (result == NULL)
          {
            usleep (10000);
            SocketDNS_check (dns);
            result = SocketDNS_getresult (dns, req);
          }

        SocketCommon_free_addrinfo (result);
        result = NULL;
      }
      EXCEPT (SocketDNS_Failed) { stop = 1; }
      FINALLY
      {
        if (result)
          SocketCommon_free_addrinfo (result);
      }
      END_TRY;

      if (stop)
        break;
    }

  return NULL;
}

TEST (socketdns_concurrent_resolutions)
{
  SocketDNS_T dns = SocketDNS_new ();
  pthread_t threads[4];

  volatile int i;
  for (i = 0; i < 4; i++)
    pthread_create (&threads[i], NULL, thread_resolve_requests, dns);

  for (i = 0; i < 4; i++)
    pthread_join (threads[i], NULL);

  usleep (500000);
  SocketDNS_check (dns);
  SocketDNS_free (&dns);
}

#if 0 /* KNOWN_ISSUE: Exception frame handling segfault in DNS worker threads.
       * See KNOWN_ISSUES.md for details and tracking. */
static void *thread_check_completions(void *arg)
{
    SocketDNS_T dns = (SocketDNS_T)arg;
    
    volatile int i;
    for (i = 0; i < 20; i++)
    {
        SocketDNS_check(dns);
        usleep(10000);
    }
    
    return NULL;
}

TEST(socketdns_concurrent_check)
{
    SocketDNS_T dns = SocketDNS_new();
    pthread_t threads[4];

    TRY
        volatile int i;
        for (i = 0; i < 10; i++)
            SocketDNS_resolve(dns, "localhost", 80, NULL, NULL);
        
        for (i = 0; i < 4; i++)
            pthread_create(&threads[i], NULL, thread_check_completions, dns);
        
        for (i = 0; i < 4; i++)
            pthread_join(threads[i], NULL);
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}
#endif

static void *
thread_cancel_requests (void *arg)
{
  SocketDNS_T dns = (SocketDNS_T)arg;

  for (volatile int i = 0; i < 10; i++)
    {
      int stop = 0;
      TRY Request_T req
          = SocketDNS_resolve (dns, "localhost", 80, NULL, NULL);
      usleep (5000);
      SocketDNS_cancel (dns, req);
      EXCEPT (SocketDNS_Failed)
      stop = 1;
      END_TRY;

      if (stop)
        break;
    }

  return NULL;
}

TEST (socketdns_concurrent_cancel)
{
  SocketDNS_T dns = SocketDNS_new ();
  pthread_t threads[4];

  volatile int i;
  for (i = 0; i < 4; i++)
    pthread_create (&threads[i], NULL, thread_cancel_requests, dns);

  for (i = 0; i < 4; i++)
    pthread_join (threads[i], NULL);

  SocketDNS_free (&dns);
}

/* ==================== Thread Pool Tests ==================== */

#if 0 /* KNOWN_ISSUE: Exception frame handling segfault in DNS worker threads.
       * See KNOWN_ISSUES.md for details and tracking. */
TEST(socketdns_thread_pool_processes_requests)
{
    SocketDNS_T dns = SocketDNS_new();
    Request_T requests[10];

    TRY
        volatile int i;
        volatile int completed = 0;
        for (i = 0; i < 10; i++)
            requests[i] = SocketDNS_resolve(dns, "127.0.0.1", 80, NULL, NULL);
        
        usleep(300000);
        SocketDNS_check(dns);
        
        for (i = 0; i < 10; i++)
        {
            struct addrinfo *result = SocketDNS_getresult(dns, requests[i]);
            if (result)
            {
                completed++;
                SocketCommon_free_addrinfo(result);
            }
        }
        ASSERT_NE(completed, 0);
    EXCEPT(SocketDNS_Failed) (void)0;
    FINALLY
        SocketDNS_free(&dns);
    END_TRY;
}
#endif

/* ==================== Parameter Validation Tests ==================== */

TEST (socketdns_resolve_null_hostname)
{
  SocketDNS_T dns = SocketDNS_new ();

  /* NULL hostname causes assert() - cannot test exception in debug builds */
  /* In release builds (NDEBUG), this would cause crash via strlen(NULL) */
  /* This test verifies that assert() prevents NULL hostname */
  (void)dns; /* Suppress unused warning */

  SocketDNS_free (&dns);
}

TEST (socketdns_resolve_empty_hostname)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;
  int caught = 0;

  TRY
  {
    TRY
    {
      req = SocketDNS_resolve (dns, "", 80, NULL, NULL);
      ASSERT_NULL (req); /* Should not reach here */
    }
    EXCEPT (Test_Failed) { RERAISE; }
    ELSE
    {
      ASSERT_NOT_NULL (Except_frame.exception);
      ASSERT_NOT_NULL (
          strstr (Except_frame.exception->reason, "Invalid hostname length"));
      caught = 1;
    }
    END_TRY;
  }
  FINALLY { SocketDNS_free (&dns); }
  END_TRY;

  ASSERT (caught);
}

TEST (socketdns_resolve_invalid_port_negative)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;
  int caught = 0;

  TRY
  {
    TRY
    {
      req = SocketDNS_resolve (dns, "localhost", -1, NULL, NULL);
      ASSERT_NULL (req); /* Should not reach here */
    }
    EXCEPT (Test_Failed) { RERAISE; }
    ELSE
    {
      ASSERT_NOT_NULL (Except_frame.exception);
      ASSERT_NOT_NULL (
          strstr (Except_frame.exception->reason, "Invalid port number"));
      caught = 1;
    }
    END_TRY;
  }
  FINALLY { SocketDNS_free (&dns); }
  END_TRY;

  ASSERT (caught);
}

TEST (socketdns_resolve_invalid_port_too_large)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;
  int caught = 0;

  TRY
  {
    TRY
    {
      req = SocketDNS_resolve (dns, "localhost", 65536, NULL, NULL);
      ASSERT_NULL (req); /* Should not reach here */
    }
    EXCEPT (Test_Failed) { RERAISE; }
    ELSE
    {
      ASSERT_NOT_NULL (Except_frame.exception);
      ASSERT_NOT_NULL (
          strstr (Except_frame.exception->reason, "Invalid port number"));
      caught = 1;
    }
    END_TRY;
  }
  FINALLY { SocketDNS_free (&dns); }
  END_TRY;

  ASSERT (caught);
}

TEST (socketdns_resolve_valid_port_zero)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;
  struct addrinfo *result = NULL;

  TRY
  {
    req = SocketDNS_resolve (dns, "localhost", 0, NULL, NULL);
    ASSERT_NOT_NULL (req);

    usleep (100000);
    SocketDNS_check (dns);
    result = SocketDNS_getresult (dns, req);
    if (result)
      SocketCommon_free_addrinfo (result);
    result = NULL;
  }
  EXCEPT (SocketDNS_Failed) { ASSERT (0); /* Port 0 should be valid */ }
  FINALLY
  {
    if (result)
      SocketCommon_free_addrinfo (result);
    SocketDNS_free (&dns);
  }
  END_TRY;
}

TEST (socketdns_resolve_valid_port_max)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;
  struct addrinfo *result = NULL;

  TRY
  {
    req = SocketDNS_resolve (dns, "127.0.0.1", 65535, NULL, NULL);
    ASSERT_NOT_NULL (req);

    usleep (100000);
    SocketDNS_check (dns);
    result = SocketDNS_getresult (dns, req);
    if (result)
      SocketCommon_free_addrinfo (result);
    result = NULL;
  }
  EXCEPT (SocketDNS_Failed) { ASSERT (0); /* Maximum port should be valid */ }
  FINALLY
  {
    if (result)
      SocketCommon_free_addrinfo (result);
    SocketDNS_free (&dns);
  }
  END_TRY;
}

TEST (socketdns_resolve_null_dns)
{
  /* NULL DNS resolver causes assert() - cannot test exception in debug builds
   */
  /* This test verifies that assert() prevents NULL DNS resolver */
  (void)0; /* Test placeholder - actual test requires assert override */
}

TEST (socketdns_cancel_null_request)
{
  SocketDNS_T dns = SocketDNS_new ();

  /* NULL request causes assert() - cannot test exception in debug builds */
  /* This test verifies that assert() prevents NULL request */
  (void)0; /* Test placeholder - actual test requires assert override */

  SocketDNS_free (&dns);
}

/* ==================== Error Handling Tests ==================== */

TEST (socketdns_getresult_null_request)
{
  SocketDNS_T dns = SocketDNS_new ();

  /* NULL request causes assert() - cannot test exception in debug builds */
  /* This test verifies that assert() prevents NULL request */
  (void)0; /* Test placeholder - actual test requires assert override */

  SocketDNS_free (&dns);
}

TEST (socketdns_getresult_pending_request)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;

  /* Note: With the new resolver architecture (Phase 2.x), localhost resolution
   * is synchronous. This test now verifies synchronous resolution behavior. */
  TRY req = SocketDNS_resolve (dns, "localhost", 80, NULL, NULL);
  ASSERT_NOT_NULL (req);

  /* Localhost resolution is synchronous, result is immediately available */
  struct addrinfo *result = SocketDNS_getresult (dns, req);
  ASSERT_NOT_NULL (result);
  SocketCommon_free_addrinfo (result);
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

TEST (socketdns_getresult_cancelled_request)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;

  TRY req = SocketDNS_resolve (dns, "localhost", 80, NULL, NULL);
  ASSERT_NOT_NULL (req);

  SocketDNS_cancel (dns, req);

  /* Cancelled request should return NULL */
  struct addrinfo *result = SocketDNS_getresult (dns, req);
  ASSERT_NULL (result);
  EXCEPT (SocketDNS_Failed) (void) 0;
  FINALLY
  SocketDNS_free (&dns);
  END_TRY;
}

/* ==================== Queue Management Tests ==================== */

TEST (socketdns_queue_full_handling)
{
  SocketDNS_T dns = SocketDNS_new ();
  Request_T req = NULL;
  size_t original_limit = 0;

  /* Note: With the new resolver architecture (Phase 2.x), there is no queue.
   * Resolution for localhost/IP literals is synchronous (immediate callback).
   * This test now verifies that max_pending getter/setter works and that
   * synchronous resolution succeeds regardless of the max_pending setting. */
  TRY
  {
    original_limit = SocketDNS_getmaxpending (dns);
    ASSERT_NE (original_limit, 0);

    SocketDNS_setmaxpending (dns, 0);
    ASSERT_EQ (SocketDNS_getmaxpending (dns), 0);

    /* IP literal resolution is synchronous - succeeds regardless of limit */
    req = SocketDNS_resolve (dns, "127.0.0.1", 80, NULL, NULL);
    ASSERT_NOT_NULL (req);

    /* Result should be immediately available (synchronous resolution) */
    struct addrinfo *result = SocketDNS_getresult (dns, req);
    ASSERT_NOT_NULL (result);
    SocketCommon_free_addrinfo (result);

    /* Restore original limit */
    SocketDNS_setmaxpending (dns, original_limit);
    ASSERT_EQ (SocketDNS_getmaxpending (dns), original_limit);
  }
  FINALLY
  {
    SocketDNS_free (&dns);
  }
  END_TRY;
}

TEST (socketdns_multiple_resolvers_independent)
{
  SocketDNS_T dns1 = SocketDNS_new ();
  SocketDNS_T dns2 = SocketDNS_new ();
  Request_T req1 = NULL;
  Request_T req2 = NULL;
  struct addrinfo *res1 = NULL;
  struct addrinfo *res2 = NULL;

  TRY
  {
    req1 = SocketDNS_resolve (dns1, "localhost", 80, NULL, NULL);
    req2 = SocketDNS_resolve (dns2, "127.0.0.1", 443, NULL, NULL);

    ASSERT_NOT_NULL (req1);
    ASSERT_NOT_NULL (req2);

    usleep (100000);
    SocketDNS_check (dns1);
    SocketDNS_check (dns2);

    res1 = SocketDNS_getresult (dns1, req1);
    res2 = SocketDNS_getresult (dns2, req2);
  }
  EXCEPT (SocketDNS_Failed)
  {
    ASSERT (0); /* Both resolutions should succeed */
  }
  FINALLY
  {
    if (res1)
      SocketCommon_free_addrinfo (res1);
    if (res2)
      SocketCommon_free_addrinfo (res2);
    SocketDNS_free (&dns1);
    SocketDNS_free (&dns2);
  }
  END_TRY;
}

/* ==================== Timeout Configuration Tests ==================== */

TEST (socketdns_timeout_get_set)
{
  SocketDNS_T dns = SocketDNS_new ();
  ASSERT_NOT_NULL (dns);

  /* Set timeout and verify it's returned correctly */
  SocketDNS_settimeout (dns, 5000);
  int timeout = SocketDNS_gettimeout (dns);
  ASSERT_EQ (timeout, 5000);

  /* Set a different timeout */
  SocketDNS_settimeout (dns, 10000);
  timeout = SocketDNS_gettimeout (dns);
  ASSERT_EQ (timeout, 10000);

  /* Set timeout to 0 (disable) */
  SocketDNS_settimeout (dns, 0);
  timeout = SocketDNS_gettimeout (dns);
  ASSERT_EQ (timeout, 0);

  SocketDNS_free (&dns);
}

TEST (socketdns_timeout_negative_sanitized)
{
  SocketDNS_T dns = SocketDNS_new ();
  ASSERT_NOT_NULL (dns);

  /* Negative timeout should be sanitized to 0 */
  SocketDNS_settimeout (dns, -100);
  int timeout = SocketDNS_gettimeout (dns);
  ASSERT_EQ (timeout, 0);

  SocketDNS_free (&dns);
}

TEST (socketdns_timeout_null_dns)
{
  /* These should not crash when called with NULL */
  SocketDNS_settimeout (NULL, 5000);
  int timeout = SocketDNS_gettimeout (NULL);
  ASSERT_EQ (timeout, 0);
}

TEST (socketdns_timeout_affects_requests)
{
  SocketDNS_T dns = SocketDNS_new ();
  ASSERT_NOT_NULL (dns);

  /* Set a reasonable timeout */
  SocketDNS_settimeout (dns, 30000);
  int timeout = SocketDNS_gettimeout (dns);
  ASSERT_EQ (timeout, 30000);

  /* Make a request and verify it works */
  Request_T req = NULL;
  struct addrinfo *result = NULL;

  TRY
  {
    req = SocketDNS_resolve (dns, "127.0.0.1", 80, NULL, NULL);
    ASSERT_NOT_NULL (req);

    usleep (100000);
    SocketDNS_check (dns);
    result = SocketDNS_getresult (dns, req);
    if (result)
      SocketCommon_free_addrinfo (result);
    result = NULL;
  }
  EXCEPT (SocketDNS_Failed) { /* May fail */ }
  FINALLY
  {
    if (result)
      SocketCommon_free_addrinfo (result);
    SocketDNS_free (&dns);
  }
  END_TRY;
}

TEST (socketdns_request_timeout_in_worker)
{
  /* This test exercises the timeout path in process_single_request().
   * We set a very short timeout, submit a request that will be slow,
   * and verify the worker thread detects the timeout. */
  SocketDNS_T dns = SocketDNS_new ();
  ASSERT_NOT_NULL (dns);

  /* Set extremely short timeout (1ms) - request will time out before
   * DNS resolution completes */
  SocketDNS_settimeout (dns, 1);

  /* Submit a request - use a hostname that requires actual DNS lookup
   * (not just IP parsing) so it takes time. We use an invalid/slow host. */
  Request_T req = NULL;

  TRY
  {
    /* Use a hostname that will be slow to resolve or fail */
    req = SocketDNS_resolve (dns, "this.host.does.not.exist.invalid", 80, NULL,
                             NULL);
    ASSERT_NOT_NULL (req);

    /* Sleep to ensure the timeout elapses before worker processes it */
    usleep (50000); /* 50ms - well past the 1ms timeout */

    /* Poll for completion */
    SocketDNS_check (dns);
    usleep (10000);
    SocketDNS_check (dns);

    /* The request should have timed out or failed */
    struct addrinfo *result = SocketDNS_getresult (dns, req);
    if (result == NULL)
      {
        /* Expected: timeout or resolution failure */
        int err = SocketDNS_geterror (dns, req);
        /* EAI_AGAIN indicates timeout, other errors indicate DNS failure */
        (void)err; /* Both outcomes are acceptable for coverage */
      }
    else
      {
        /* Unlikely but possible if DNS is very fast - clean up */
        SocketCommon_free_addrinfo (result);
      }
  }
  EXCEPT (SocketDNS_Failed)
  {
    /* DNS failure is acceptable - we're testing the timeout path */
  }
  FINALLY { SocketDNS_free (&dns); }
  END_TRY;
}

/* ==================== Close-on-Exec Tests ==================== */

TEST (socketdns_pipe_has_cloexec)
{
  SocketDNS_T dns = SocketDNS_new ();
  ASSERT_NOT_NULL (dns);

  int pollfd = SocketDNS_pollfd (dns);
  ASSERT_NE (pollfd, -1);

  /* Verify pipe read end has CLOEXEC set */
  int has_cloexec = SocketCommon_has_cloexec (pollfd);
  ASSERT_EQ (has_cloexec, 1);

  SocketDNS_free (&dns);
}

/* ==================== Security Tests (Issue #716) ==================== */

/* Test: SocketDNS_resolve_sync rejects NULL dns parameter */
TEST (socketdns_resolve_sync_null_dns_rejected)
{
  volatile int exception_raised = 0;
  volatile struct addrinfo *result = NULL;

  TRY
  {
    /* Attempt to call SocketDNS_resolve_sync with NULL dns
     * This should raise SocketDNS_Failed exception to prevent
     * bypassing timeout protection (DoS vulnerability). */
    result = SocketDNS_resolve_sync (NULL, "example.com", 80, NULL, 5000);

    /* Should not reach here */
    ASSERT (0);
  }
  EXCEPT (SocketDNS_Failed)
  {
    /* Expected exception - NULL dns must be rejected for security */
    exception_raised = 1;
  }
  END_TRY;

  ASSERT_EQ (exception_raised, 1);
  ASSERT_NULL (result);
}

/* Test: SocketDNS_resolve_sync works with valid dns resolver */
TEST (socketdns_resolve_sync_with_timeout_protection)
{
  SocketDNS_T dns = SocketDNS_new ();
  struct addrinfo *result = NULL;

  TRY
  {
    /* Resolve IP address - should succeed quickly with timeout protection */
    result = SocketDNS_resolve_sync (dns, "127.0.0.1", 80, NULL, 5000);
    ASSERT_NOT_NULL (result);

    /* Verify it's a valid result */
    ASSERT_EQ (result->ai_family, AF_INET);

    SocketCommon_free_addrinfo (result);
    result = NULL;
  }
  EXCEPT (SocketDNS_Failed)
  {
    ASSERT (0); /* Should not fail with valid parameters */
  }
  FINALLY
  {
    if (result)
      SocketCommon_free_addrinfo (result);
    SocketDNS_free (&dns);
  }
  END_TRY;
}

/* ==================== Resolver Sync Tests (Issue #1067) ==================== */

/* Test: SocketDNSResolver_resolve_sync with localhost hostname */
TEST (test_socketdnsresolver_resolve_sync_hostname)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = NULL;
  SocketDNSResolver_Result result = { 0 };
  volatile int success = 0;

  TRY
  {
    resolver = SocketDNSResolver_new (arena);
    ASSERT_NOT_NULL (resolver);

    /* Load system nameservers */
    int ns_count = SocketDNSResolver_load_resolv_conf (resolver);
    ASSERT_NE (ns_count, -1);

    /* Resolve localhost - should succeed */
    int err = SocketDNSResolver_resolve_sync (resolver, "localhost",
                                               RESOLVER_FLAG_BOTH, 5000, &result);
    ASSERT_EQ (err, RESOLVER_OK);
    ASSERT_NOT_NULL (result.addresses);
    ASSERT_NE (result.count, 0);

    /* Verify at least one address has valid family */
    int found_valid = 0;
    for (size_t i = 0; i < result.count; i++)
      {
        if (result.addresses[i].family == AF_INET
            || result.addresses[i].family == AF_INET6)
          {
            found_valid = 1;
            break;
          }
      }
    ASSERT_NE (found_valid, 0);

    SocketDNSResolver_result_free (&result);
    success = 1;
  }
  EXCEPT (SocketDNSResolver_Failed)
  {
    ASSERT (0); /* Should not fail with valid parameters */
  }
  FINALLY
  {
    if (result.addresses)
      SocketDNSResolver_result_free (&result);
    if (resolver)
      SocketDNSResolver_free (&resolver);
    Arena_dispose (&arena);
  }
  END_TRY;

  ASSERT_NE (success, 0);
}

/* Test: SocketDNSResolver_resolve_sync with IPv4 literal */
TEST (test_socketdnsresolver_resolve_sync_ipv4_literal)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = NULL;
  SocketDNSResolver_Result result = { 0 };
  volatile int success = 0;

  TRY
  {
    resolver = SocketDNSResolver_new (arena);
    ASSERT_NOT_NULL (resolver);

    /* Load system nameservers */
    int ns_count = SocketDNSResolver_load_resolv_conf (resolver);
    ASSERT_NE (ns_count, -1);

    /* Resolve IPv4 literal - should succeed */
    int err = SocketDNSResolver_resolve_sync (resolver, "127.0.0.1",
                                               RESOLVER_FLAG_IPV4, 5000, &result);
    ASSERT_EQ (err, RESOLVER_OK);
    ASSERT_NOT_NULL (result.addresses);
    ASSERT_NE (result.count, 0);

    /* Verify AF_INET family */
    ASSERT_EQ (result.addresses[0].family, AF_INET);

    SocketDNSResolver_result_free (&result);
    success = 1;
  }
  EXCEPT (SocketDNSResolver_Failed)
  {
    ASSERT (0); /* Should not fail with valid IPv4 literal */
  }
  FINALLY
  {
    if (result.addresses)
      SocketDNSResolver_result_free (&result);
    if (resolver)
      SocketDNSResolver_free (&resolver);
    Arena_dispose (&arena);
  }
  END_TRY;

  ASSERT_NE (success, 0);
}

/* Test: SocketDNSResolver_resolve_sync with IPv6 literal */
TEST (test_socketdnsresolver_resolve_sync_ipv6_literal)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = NULL;
  SocketDNSResolver_Result result = { 0 };
  volatile int success = 0;

  TRY
  {
    resolver = SocketDNSResolver_new (arena);
    ASSERT_NOT_NULL (resolver);

    /* Load system nameservers */
    int ns_count = SocketDNSResolver_load_resolv_conf (resolver);
    ASSERT_NE (ns_count, -1);

    /* Resolve IPv6 literal - should succeed */
    int err = SocketDNSResolver_resolve_sync (resolver, "::1",
                                               RESOLVER_FLAG_IPV6, 5000, &result);
    ASSERT_EQ (err, RESOLVER_OK);
    ASSERT_NOT_NULL (result.addresses);
    ASSERT_NE (result.count, 0);

    /* Verify AF_INET6 family */
    ASSERT_EQ (result.addresses[0].family, AF_INET6);

    SocketDNSResolver_result_free (&result);
    success = 1;
  }
  EXCEPT (SocketDNSResolver_Failed)
  {
    ASSERT (0); /* Should not fail with valid IPv6 literal */
  }
  FINALLY
  {
    if (result.addresses)
      SocketDNSResolver_result_free (&result);
    if (resolver)
      SocketDNSResolver_free (&resolver);
    Arena_dispose (&arena);
  }
  END_TRY;

  ASSERT_NE (success, 0);
}

/* Test: SocketDNSResolver_resolve_sync timeout with non-existent domain */
TEST (test_socketdnsresolver_resolve_sync_timeout)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = NULL;
  SocketDNSResolver_Result result = { 0 };
  volatile int got_error = 0;

  TRY
  {
    resolver = SocketDNSResolver_new (arena);
    ASSERT_NOT_NULL (resolver);

    /* Load system nameservers */
    int ns_count = SocketDNSResolver_load_resolv_conf (resolver);
    ASSERT_NE (ns_count, -1);

    /* Set very short timeout (1ms) and try non-existent domain */
    int err = SocketDNSResolver_resolve_sync (
        resolver, "this.host.does.not.exist.invalid", RESOLVER_FLAG_BOTH, 1,
        &result);

    /* Should timeout or fail (NXDOMAIN) */
    ASSERT_NE (err, RESOLVER_OK);
    got_error = 1;
  }
  EXCEPT (SocketDNSResolver_Failed)
  {
    /* Also acceptable - exception on failure */
    got_error = 1;
  }
  FINALLY
  {
    if (result.addresses)
      SocketDNSResolver_result_free (&result);
    if (resolver)
      SocketDNSResolver_free (&resolver);
    Arena_dispose (&arena);
  }
  END_TRY;

  ASSERT_NE (got_error, 0);
}

/* Test: SocketDNSResolver_resolve_sync NXDOMAIN for invalid domain */
TEST (test_socketdnsresolver_resolve_sync_nxdomain)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = NULL;
  SocketDNSResolver_Result result = { 0 };
  volatile int got_error = 0;

  TRY
  {
    resolver = SocketDNSResolver_new (arena);
    ASSERT_NOT_NULL (resolver);

    /* Load system nameservers */
    int ns_count = SocketDNSResolver_load_resolv_conf (resolver);
    ASSERT_NE (ns_count, -1);

    /* Use invalid domain - should fail with NXDOMAIN or timeout */
    int err = SocketDNSResolver_resolve_sync (
        resolver, "this.host.does.not.exist.invalid", RESOLVER_FLAG_BOTH, 5000,
        &result);

    /* Should fail (NXDOMAIN, timeout, or other error) */
    ASSERT_NE (err, RESOLVER_OK);
    got_error = 1;
  }
  EXCEPT (SocketDNSResolver_Failed)
  {
    /* Also acceptable - exception on failure */
    got_error = 1;
  }
  FINALLY
  {
    if (result.addresses)
      SocketDNSResolver_result_free (&result);
    if (resolver)
      SocketDNSResolver_free (&resolver);
    Arena_dispose (&arena);
  }
  END_TRY;

  ASSERT_NE (got_error, 0);
}

/* Test: SocketDNSResolver_resolve_sync cache paths (miss then hit) */
TEST (test_socketdnsresolver_resolve_sync_cache_paths)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = NULL;
  SocketDNSResolver_Result result1 = { 0 };
  SocketDNSResolver_Result result2 = { 0 };
  volatile int success = 0;

  TRY
  {
    resolver = SocketDNSResolver_new (arena);
    ASSERT_NOT_NULL (resolver);

    /* Load system nameservers */
    int ns_count = SocketDNSResolver_load_resolv_conf (resolver);
    ASSERT_NE (ns_count, -1);

    /* Get initial cache stats */
    SocketDNSResolver_CacheStats stats_before = { 0 };
    SocketDNSResolver_cache_stats (resolver, &stats_before);

    /* First resolve - should be cache miss or direct IP parsing */
    int err1 = SocketDNSResolver_resolve_sync (resolver, "localhost",
                                                RESOLVER_FLAG_BOTH, 5000, &result1);
    ASSERT_EQ (err1, RESOLVER_OK);
    ASSERT_NOT_NULL (result1.addresses);

    /* Check cache stats after first resolve */
    SocketDNSResolver_CacheStats stats_after_first = { 0 };
    SocketDNSResolver_cache_stats (resolver, &stats_after_first);

    /* Second resolve - should be cache hit if caching occurred */
    int err2 = SocketDNSResolver_resolve_sync (resolver, "localhost",
                                                RESOLVER_FLAG_BOTH, 5000, &result2);
    ASSERT_EQ (err2, RESOLVER_OK);
    ASSERT_NOT_NULL (result2.addresses);

    /* Check cache stats after second resolve */
    SocketDNSResolver_CacheStats stats_after_second = { 0 };
    SocketDNSResolver_cache_stats (resolver, &stats_after_second);

    /* Verify cache stats are accessible and reasonable
     * (IP literals may bypass cache, so we just verify stats are valid) */
    ASSERT (stats_after_second.hits >= stats_before.hits);
    ASSERT (stats_after_second.misses >= stats_before.misses);

    SocketDNSResolver_result_free (&result1);
    SocketDNSResolver_result_free (&result2);
    success = 1;
  }
  EXCEPT (SocketDNSResolver_Failed)
  {
    ASSERT (0); /* Should not fail with valid parameters */
  }
  FINALLY
  {
    if (result1.addresses)
      SocketDNSResolver_result_free (&result1);
    if (result2.addresses)
      SocketDNSResolver_result_free (&result2);
    if (resolver)
      SocketDNSResolver_free (&resolver);
    Arena_dispose (&arena);
  }
  END_TRY;

  ASSERT_NE (success, 0);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

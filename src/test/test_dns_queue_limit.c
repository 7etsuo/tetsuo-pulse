/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_dns_queue_limit.c
 * @brief Unit tests for DNS queue limit enforcement.
 */

#include "dns/SocketDNS.h"
#include "socket/SocketCommon.h"
#include "test/Test.h"

#include <stdio.h>
#include <string.h>

/* Test: Queue limit is enforced */
TEST (dns_queue_limit_enforced)
{
  SocketDNS_T dns = NULL;
  SocketDNS_Request_T *requests[10];
  size_t i;
  volatile int exception_caught = 0;

  TRY
  {
    dns = SocketDNS_new ();
    ASSERT_NOT_NULL (dns);

    /* Set a very low queue limit for testing */
    SocketDNS_setmaxpending (dns, 5);
    ASSERT_EQ (SocketDNS_getmaxpending (dns), 5);

    /* Fill the queue to capacity */
    for (i = 0; i < 5; i++)
      {
        requests[i] = SocketDNS_resolve (dns, "example.com", 80, NULL, NULL);
        ASSERT_NOT_NULL (requests[i]);
      }

    /* Next request should fail with queue full exception */
    TRY
    {
      requests[5] = SocketDNS_resolve (dns, "example.com", 80, NULL, NULL);
      /* Should not reach here */
      Test_fail ("Expected SocketDNS_Failed exception for queue full",
                 __FILE__,
                 __LINE__);
    }
    EXCEPT (SocketDNS_Failed)
    {
      exception_caught = 1;
    }
    END_TRY;

    ASSERT_EQ (exception_caught, 1);
  }
  FINALLY
  {
    if (dns)
      {
        SocketDNS_free (&dns);
      }
  }
  END_TRY;
}

/* Test: Completed requests don't count toward limit */
TEST (dns_queue_limit_excludes_completed)
{
  SocketDNS_T dns = NULL;
  SocketDNS_Request_T *req1, *req2, *req3;
  struct addrinfo *result;

  TRY
  {
    dns = SocketDNS_new ();
    ASSERT_NOT_NULL (dns);

    /* Set queue limit */
    SocketDNS_setmaxpending (dns, 2);

    /* Resolve IP addresses - these complete immediately */
    req1 = SocketDNS_resolve (dns, "127.0.0.1", 80, NULL, NULL);
    ASSERT_NOT_NULL (req1);

    req2 = SocketDNS_resolve (dns, "127.0.0.2", 80, NULL, NULL);
    ASSERT_NOT_NULL (req2);

    /* Since IP addresses resolve immediately (REQ_COMPLETE state),
     * they shouldn't count toward the pending limit.
     * We should be able to resolve more. */
    req3 = SocketDNS_resolve (dns, "127.0.0.3", 80, NULL, NULL);
    ASSERT_NOT_NULL (req3);

    /* Retrieve all results to clean up.
     * Must use SocketCommon_free_addrinfo, not freeaddrinfo, because
     * the library allocates ai_addr separately with calloc. */
    result = SocketDNS_getresult (dns, req1);
    if (result)
      {
        SocketCommon_free_addrinfo (result);
      }
    result = SocketDNS_getresult (dns, req2);
    if (result)
      {
        SocketCommon_free_addrinfo (result);
      }
    result = SocketDNS_getresult (dns, req3);
    if (result)
      {
        SocketCommon_free_addrinfo (result);
      }
  }
  FINALLY
  {
    if (dns)
      {
        SocketDNS_free (&dns);
      }
  }
  END_TRY;
}

/* Test: Zero max_pending allows no pending requests */
TEST (dns_queue_limit_zero)
{
  SocketDNS_T dns = NULL;
  volatile int exception_caught = 0;

  TRY
  {
    dns = SocketDNS_new ();
    ASSERT_NOT_NULL (dns);

    /* Set max_pending to 0 */
    SocketDNS_setmaxpending (dns, 0);
    ASSERT_EQ (SocketDNS_getmaxpending (dns), 0);

    /* Hostname resolution should fail when queue is full (0 capacity).
     * Note: IP literals resolve synchronously and won't count toward pending.
     */
    TRY
    {
      SocketDNS_resolve (dns, "example.com", 80, NULL, NULL);
      Test_fail ("Expected SocketDNS_Failed exception with max_pending=0",
                 __FILE__,
                 __LINE__);
    }
    EXCEPT (SocketDNS_Failed)
    {
      exception_caught = 1;
    }
    END_TRY;

    ASSERT_EQ (exception_caught, 1);
  }
  FINALLY
  {
    if (dns)
      {
        SocketDNS_free (&dns);
      }
  }
  END_TRY;
}

/* Test: Default max_pending is reasonable */
TEST (dns_queue_limit_default)
{
  SocketDNS_T dns = NULL;

  TRY
  {
    dns = SocketDNS_new ();
    ASSERT_NOT_NULL (dns);

    /* Default should be SOCKET_DNS_MAX_PENDING (1000) */
    size_t max = SocketDNS_getmaxpending (dns);
    ASSERT (max > 0);
    /* Don't hardcode the exact value, but verify it's reasonable */
    ASSERT (max >= 100);
  }
  FINALLY
  {
    if (dns)
      {
        SocketDNS_free (&dns);
      }
  }
  END_TRY;
}

/* Main function - run all tests */
int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_dns_mutex_macros.c - DNS mutex macro exception safety tests
 * Tests for exception-safe mutex-protected field access macros in SocketDNS.
 * Verifies that mutexes are properly unlocked even when exceptions are raised.
 */

#include <pthread.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNS-private.h"
#include "test/Test.h"

/* Suppress longjmp clobbering warnings for test variables used with TRY/EXCEPT
 */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Test exception type */
static const Except_T TestException = { &TestException, "Test exception" };

/* Helper to create a minimal DNS resolver structure for testing */
static struct SocketDNS_T *
create_test_dns_resolver (Arena_T arena)
{
  struct SocketDNS_T *dns;

  dns = Arena_alloc (arena, sizeof (*dns), __FILE__, __LINE__);
  memset (dns, 0, sizeof (*dns));

  /* Initialize only the mutex - we don't need a fully functional resolver */
  pthread_mutex_init (&dns->mutex, NULL);

  /* Set some test values */
  dns->request_timeout_ms = 5000;
  dns->max_pending = 100;
  dns->prefer_ipv6 = 1;

  return dns;
}

/* Helper to cleanup DNS resolver */
static void
cleanup_test_dns_resolver (struct SocketDNS_T *dns)
{
  if (dns)
    {
      pthread_mutex_destroy (&dns->mutex);
    }
}

/* Test DNS_LOCKED_INT_GETTER normal operation */
TEST (dns_mutex_int_getter_normal)
{
  Arena_T arena = Arena_new ();
  struct SocketDNS_T *dns = NULL;
  int timeout = 0;

  TRY
  {
    dns = create_test_dns_resolver (arena);
    timeout = DNS_LOCKED_INT_GETTER (dns, request_timeout_ms);
    ASSERT_EQ (timeout, 5000);
  }
  FINALLY
  {
    if (dns)
      cleanup_test_dns_resolver (dns);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test DNS_LOCKED_SIZE_GETTER normal operation */
TEST (dns_mutex_size_getter_normal)
{
  Arena_T arena = Arena_new ();
  struct SocketDNS_T *dns = NULL;
  size_t max_pending = 0;

  TRY
  {
    dns = create_test_dns_resolver (arena);
    max_pending = DNS_LOCKED_SIZE_GETTER (dns, max_pending);
    ASSERT_EQ (max_pending, 100);
  }
  FINALLY
  {
    if (dns)
      cleanup_test_dns_resolver (dns);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test DNS_LOCKED_INT_SETTER normal operation */
TEST (dns_mutex_int_setter_normal)
{
  Arena_T arena = Arena_new ();
  struct SocketDNS_T *dns = NULL;

  TRY
  {
    dns = create_test_dns_resolver (arena);
    DNS_LOCKED_INT_SETTER (dns, request_timeout_ms, 10000);

    /* Verify the value was set */
    pthread_mutex_lock (&dns->mutex);
    ASSERT_EQ (dns->request_timeout_ms, 10000);
    pthread_mutex_unlock (&dns->mutex);
  }
  FINALLY
  {
    if (dns)
      cleanup_test_dns_resolver (dns);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test that DNS_LOCKED_INT_GETTER is exception-safe (mutex unlocked on
 * exception) */
TEST (dns_mutex_int_getter_exception_safe)
{
  Arena_T arena = Arena_new ();
  struct SocketDNS_T *dns = NULL;
  volatile int exception_caught = 0;

  TRY
  {
    dns = create_test_dns_resolver (arena);

    /* This should unlock the mutex even though we raise an exception inside */
    TRY
    {
      int timeout = DNS_LOCKED_INT_GETTER (dns, request_timeout_ms);
      (void)timeout; /* Avoid unused warning */

      /* Raise exception after getting value but inside the TRY block */
      RAISE (TestException);
    }
    EXCEPT (TestException) { exception_caught = 1; }
    END_TRY;

    /* Verify we caught the exception */
    ASSERT_EQ (exception_caught, 1);

    /* Verify mutex is not locked by trying to lock it with trylock.
     * If the mutex is still locked (deadlock), trylock will fail. */
    int lock_result = pthread_mutex_trylock (&dns->mutex);
    ASSERT_EQ (lock_result, 0); /* 0 = successfully locked */

    if (lock_result == 0)
      {
        pthread_mutex_unlock (&dns->mutex);
      }
  }
  FINALLY
  {
    if (dns)
      cleanup_test_dns_resolver (dns);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test that DNS_LOCKED_SIZE_GETTER is exception-safe */
TEST (dns_mutex_size_getter_exception_safe)
{
  Arena_T arena = Arena_new ();
  struct SocketDNS_T *dns = NULL;
  volatile int exception_caught = 0;

  TRY
  {
    dns = create_test_dns_resolver (arena);

    TRY
    {
      size_t max = DNS_LOCKED_SIZE_GETTER (dns, max_pending);
      (void)max;

      RAISE (TestException);
    }
    EXCEPT (TestException) { exception_caught = 1; }
    END_TRY;

    ASSERT_EQ (exception_caught, 1);

    /* Verify mutex is unlocked */
    int lock_result = pthread_mutex_trylock (&dns->mutex);
    ASSERT_EQ (lock_result, 0);

    if (lock_result == 0)
      {
        pthread_mutex_unlock (&dns->mutex);
      }
  }
  FINALLY
  {
    if (dns)
      cleanup_test_dns_resolver (dns);
    Arena_dispose (&arena);
  }
  END_TRY;
}

/* Test that DNS_LOCKED_INT_SETTER is exception-safe */
TEST (dns_mutex_int_setter_exception_safe)
{
  Arena_T arena = Arena_new ();
  struct SocketDNS_T *dns = NULL;
  volatile int exception_caught = 0;

  TRY
  {
    dns = create_test_dns_resolver (arena);

    TRY
    {
      DNS_LOCKED_INT_SETTER (dns, request_timeout_ms, 20000);

      /* Raise exception after setter */
      RAISE (TestException);
    }
    EXCEPT (TestException) { exception_caught = 1; }
    END_TRY;

    ASSERT_EQ (exception_caught, 1);

    /* Verify mutex is unlocked */
    int lock_result = pthread_mutex_trylock (&dns->mutex);
    ASSERT_EQ (lock_result, 0);

    if (lock_result == 0)
      {
        /* Also verify the value was set despite the exception */
        ASSERT_EQ (dns->request_timeout_ms, 20000);
        pthread_mutex_unlock (&dns->mutex);
      }
  }
  FINALLY
  {
    if (dns)
      cleanup_test_dns_resolver (dns);
    Arena_dispose (&arena);
  }
  END_TRY;
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

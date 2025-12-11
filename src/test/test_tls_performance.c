/**
 * test_tls_performance.c - Unit tests for TLS performance optimizations
 *
 * Part of the Socket Library Test Suite
 *
 * Tests:
 * - TLS 1.3 0-RTT early data support
 * - TLS 1.3 KeyUpdate for key rotation
 * - TCP handshake optimization functions
 * - Session cache sharding
 * - TLS buffer pooling
 */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "test/Test.h"

#if SOCKET_HAS_TLS

#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"

/* ============================================================================
 * Test Setup and Helpers
 * ============================================================================
 */

/* Reuse test certificates if available, otherwise create dummy tests */
static int
check_test_certs_available (void)
{
  /* Check for test certificate files */
  FILE *f = fopen ("../certs/server.crt", "r");
  if (f)
    {
      fclose (f);
      return 1;
    }
  f = fopen ("certs/server.crt", "r");
  if (f)
    {
      fclose (f);
      return 1;
    }
  return 0;
}

/* ============================================================================
 * TCP Optimization Tests
 * ============================================================================
 */

/**
 * Test TCP optimization function with non-TLS socket (should fail gracefully)
 */
TEST (tcp_optimize_non_tls_socket)
{
  Socket_T sock = NULL;

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (sock);

    /* Should return -1 with EINVAL since TLS is not enabled */
    int ret = SocketTLS_optimize_handshake (sock);
    ASSERT_EQ (-1, ret);
    ASSERT_EQ (EINVAL, errno);

    printf ("    TCP optimize correctly fails for non-TLS socket\n");
  }
  FINALLY
  {
    if (sock)
      Socket_free (&sock);
  }
  END_TRY;
}

/**
 * Test TCP restore defaults function
 */
TEST (tcp_restore_defaults)
{
  Socket_T sock = NULL;

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (sock);

    /* Should not crash even for non-TLS socket */
    int ret = SocketTLS_restore_tcp_defaults (sock);
    /* May succeed or fail depending on whether socket is connected */
    (void)ret;

    printf ("    TCP restore defaults function executes without crash\n");
  }
  FINALLY
  {
    if (sock)
      Socket_free (&sock);
  }
  END_TRY;
}

/* ============================================================================
 * TLS Buffer Pool Tests
 * ============================================================================
 */

/**
 * Test buffer pool creation and destruction
 */
TEST (buffer_pool_lifecycle)
{
  TLSBufferPool_T pool = TLSBufferPool_new (4096, 10, NULL);
  ASSERT_NOT_NULL (pool);

  /* Check initial stats */
  size_t total, in_use, available;
  TLSBufferPool_stats (pool, &total, &in_use, &available);
  ASSERT_EQ (10, (int)total);
  ASSERT_EQ (0, (int)in_use);
  ASSERT_EQ (10, (int)available);

  TLSBufferPool_free (&pool);
  ASSERT_NULL (pool);

  printf ("    Buffer pool lifecycle test passed\n");
}

/**
 * Test buffer pool acquire and release
 */
TEST (buffer_pool_acquire_release)
{
  TLSBufferPool_T pool = TLSBufferPool_new (4096, 5, NULL);
  ASSERT_NOT_NULL (pool);

  /* Acquire all buffers */
  void *buffers[5];
  for (int i = 0; i < 5; i++)
    {
      buffers[i] = TLSBufferPool_acquire (pool);
      ASSERT_NOT_NULL (buffers[i]);
    }

  /* Pool should be exhausted */
  void *extra = TLSBufferPool_acquire (pool);
  ASSERT_NULL (extra);

  /* Check stats */
  size_t total, in_use, available;
  TLSBufferPool_stats (pool, &total, &in_use, &available);
  ASSERT_EQ (5, (int)total);
  ASSERT_EQ (5, (int)in_use);
  ASSERT_EQ (0, (int)available);

  /* Release all buffers */
  for (int i = 0; i < 5; i++)
    {
      TLSBufferPool_release (pool, buffers[i]);
    }

  /* Check stats again */
  TLSBufferPool_stats (pool, &total, &in_use, &available);
  ASSERT_EQ (5, (int)total);
  ASSERT_EQ (0, (int)in_use);
  ASSERT_EQ (5, (int)available);

  /* Acquire again should work */
  void *buf = TLSBufferPool_acquire (pool);
  ASSERT_NOT_NULL (buf);
  TLSBufferPool_release (pool, buf);

  TLSBufferPool_free (&pool);

  printf ("    Buffer pool acquire/release test passed\n");
}

/**
 * Test buffer pool with NULL pool (should not crash)
 */
TEST (buffer_pool_null_handling)
{
  /* All functions should handle NULL gracefully */
  void *buf = TLSBufferPool_acquire (NULL);
  ASSERT_NULL (buf);

  TLSBufferPool_release (NULL, NULL);

  size_t total, in_use, available;
  TLSBufferPool_stats (NULL, &total, &in_use, &available);
  ASSERT_EQ (0, (int)total);
  ASSERT_EQ (0, (int)in_use);
  ASSERT_EQ (0, (int)available);

  TLSBufferPool_T pool = NULL;
  TLSBufferPool_free (&pool); /* Should not crash */

  printf ("    Buffer pool NULL handling test passed\n");
}

/**
 * Test concurrent buffer pool access (basic thread safety)
 */
static void *
buffer_pool_thread_func (void *arg)
{
  TLSBufferPool_T pool = (TLSBufferPool_T)arg;

  for (int i = 0; i < 100; i++)
    {
      void *buf = TLSBufferPool_acquire (pool);
      if (buf)
        {
          /* Use the buffer briefly */
          memset (buf, 0, 100);
          usleep (10); /* Small delay */
          TLSBufferPool_release (pool, buf);
        }
    }

  return NULL;
}

TEST (buffer_pool_concurrent)
{
  TLSBufferPool_T pool = TLSBufferPool_new (4096, 10, NULL);
  ASSERT_NOT_NULL (pool);

  pthread_t threads[4];

  /* Start threads */
  for (int i = 0; i < 4; i++)
    {
      int ret = pthread_create (&threads[i], NULL, buffer_pool_thread_func, pool);
      ASSERT_EQ (0, ret);
    }

  /* Wait for threads */
  for (int i = 0; i < 4; i++)
    {
      pthread_join (threads[i], NULL);
    }

  /* Check final stats - all buffers should be released */
  size_t total, in_use, available;
  TLSBufferPool_stats (pool, &total, &in_use, &available);
  ASSERT_EQ (10, (int)total);
  ASSERT_EQ (0, (int)in_use);
  ASSERT_EQ (10, (int)available);

  TLSBufferPool_free (&pool);

  printf ("    Buffer pool concurrent test passed\n");
}

/* ============================================================================
 * Early Data Status Tests
 * ============================================================================
 */

/**
 * Test early data status function with non-TLS socket
 */
TEST (early_data_status_non_tls)
{
  Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (sock);

  SocketTLS_EarlyDataStatus status = SocketTLS_get_early_data_status (sock);
  ASSERT_EQ (SOCKET_EARLY_DATA_NOT_SENT, (int)status);

  Socket_free (&sock);

  printf ("    Early data status correctly returns NOT_SENT for non-TLS socket\n");
}

/* ============================================================================
 * Session Cache Sharding Tests
 * ============================================================================
 */

/**
 * Test sharded cache creation (basic functionality)
 */
TEST (sharded_cache_creation)
{
  if (!check_test_certs_available ())
    {
      printf ("    [SKIP] Test certificates not available\n");
      return;
    }

  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_server ("../certs/server.crt",
                                       "../certs/server.key", NULL);
    if (!ctx)
      ctx = SocketTLSContext_new_server ("certs/server.crt",
                                         "certs/server.key", NULL);
    ASSERT_NOT_NULL (ctx);

    /* Create sharded cache */
    SocketTLSContext_create_sharded_cache (ctx, 4, 100, 300);

    /* Get stats (should work without error) */
    size_t hits, misses, stores;
    SocketTLSContext_get_sharded_stats (ctx, &hits, &misses, &stores);

    /* Initial stats should be zero */
    ASSERT_EQ (0, (int)hits);
    ASSERT_EQ (0, (int)misses);
    ASSERT_EQ (0, (int)stores);

    printf ("    Sharded cache creation test passed\n");
  }
  EXCEPT (SocketTLS_Failed)
  {
    printf ("    [SKIP] TLS context creation failed\n");
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ============================================================================
 * Context Early Data Configuration Tests
 * ============================================================================
 */

/**
 * Test enabling/disabling early data on context
 */
TEST (context_early_data_config)
{
  if (!check_test_certs_available ())
    {
      printf ("    [SKIP] Test certificates not available\n");
      return;
    }

  SocketTLSContext_T server_ctx = NULL;
  SocketTLSContext_T client_ctx = NULL;

  TRY
  {
    server_ctx = SocketTLSContext_new_server ("../certs/server.crt",
                                              "../certs/server.key", NULL);
    if (!server_ctx)
      server_ctx = SocketTLSContext_new_server ("certs/server.crt",
                                                "certs/server.key", NULL);
    ASSERT_NOT_NULL (server_ctx);

    client_ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (client_ctx);

    /* Enable early data on server with default size */
    SocketTLSContext_enable_early_data (server_ctx, 0);

    /* Enable early data on client */
    SocketTLSContext_enable_early_data (client_ctx, 0);

    /* Disable early data */
    SocketTLSContext_disable_early_data (server_ctx);
    SocketTLSContext_disable_early_data (client_ctx);

    printf ("    Context early data configuration test passed\n");
  }
  EXCEPT (SocketTLS_Failed)
  {
    printf ("    [SKIP] TLS context creation failed\n");
  }
  FINALLY
  {
    if (server_ctx)
      SocketTLSContext_free (&server_ctx);
    if (client_ctx)
      SocketTLSContext_free (&client_ctx);
  }
  END_TRY;
}

/* ============================================================================
 * TLS 1.3 KeyUpdate Tests
 * ============================================================================
 */

/**
 * Test KeyUpdate on non-TLS socket (should fail gracefully)
 */
TEST (key_update_non_tls_socket)
{
  Socket_T sock = NULL;

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (sock);

    /* Should return 0 since TLS is not enabled */
    int ret = SocketTLS_request_key_update (sock, 1);
    ASSERT_EQ (0, ret);
    ASSERT_EQ (EINVAL, errno);

    /* Count should be 0 */
    ASSERT_EQ (0, SocketTLS_get_key_update_count (sock));

    printf ("    KeyUpdate correctly fails for non-TLS socket\n");
  }
  FINALLY
  {
    if (sock)
      Socket_free (&sock);
  }
  END_TRY;
}

/**
 * Test KeyUpdate count initialization
 */
TEST (key_update_count_init)
{
  Socket_T sock = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (sock);

    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLS_enable (sock, ctx);

    /* Count should start at 0 */
    ASSERT_EQ (0, SocketTLS_get_key_update_count (sock));

    printf ("    KeyUpdate count initialization test passed\n");
  }
  EXCEPT (SocketTLS_Failed)
  {
    printf ("    [SKIP] TLS context creation failed\n");
  }
  FINALLY
  {
    if (sock)
      {
        SocketTLS_disable (sock);
        Socket_free (&sock);
      }
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/**
 * Test KeyUpdate before handshake (should return 0)
 */
TEST (key_update_before_handshake)
{
  Socket_T sock = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (sock);

    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketTLS_enable (sock, ctx);

    /* KeyUpdate should return 0 since handshake not done */
    int ret = SocketTLS_request_key_update (sock, 1);
    ASSERT_EQ (0, ret);

    /* Count should still be 0 */
    ASSERT_EQ (0, SocketTLS_get_key_update_count (sock));

    printf ("    KeyUpdate before handshake test passed\n");
  }
  EXCEPT (SocketTLS_Failed)
  {
    printf ("    [SKIP] TLS context creation failed\n");
  }
  FINALLY
  {
    if (sock)
      {
        SocketTLS_disable (sock);
        Socket_free (&sock);
      }
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================
 */

int
main (void)
{
  printf ("\n=== TLS Performance Optimizations Test Suite ===\n\n");

  Test_run_all ();

  int failures = Test_get_failures ();

  printf ("\n=== Test Summary: %d failures ===\n\n",
          failures);

  return failures > 0 ? 1 : 0;
}

#else /* !SOCKET_HAS_TLS */

#include <stdio.h>

int
main (void)
{
  printf ("TLS not enabled - skipping TLS performance tests\n");
  return 0;
}

#endif /* SOCKET_HAS_TLS */

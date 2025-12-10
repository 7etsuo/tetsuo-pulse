/**
 * test_tls_crl_integration.c - CRL Management Integration Tests
 *
 * Tests CRL auto-refresh functionality in realistic scenarios including
 * timing, concurrent access, and long-running operation simulation.
 */

#include "core/Arena.h"
#include "core/SocketUtil.h"
#include "test/Test.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if SOCKET_HAS_TLS

#include "tls/SocketTLSConfig.h"

/* Integration test callback data */
typedef struct
{
  pthread_mutex_t lock;
  int success_count;
  int failure_count;
  int total_calls;
  time_t last_refresh_time;
} integration_callback_data_t;

/* Integration test callback */
static void
integration_crl_callback (SocketTLSContext_T ctx, const char *path, int success,
                          void *user_data)
{
  integration_callback_data_t *data = (integration_callback_data_t *)user_data;

  pthread_mutex_lock (&data->lock);

  data->total_calls++;
  if (success)
    data->success_count++;
  else
    data->failure_count++;

  data->last_refresh_time = time (NULL);

  printf ("CRL Integration: Refresh %s for %s (total: %d, success: %d, fail: %d)\n",
          success ? "SUCCESS" : "FAILED", path, data->total_calls,
          data->success_count, data->failure_count);

  pthread_mutex_unlock (&data->lock);

  (void)ctx; /* Unused */
}

/* Simulate long-running application with periodic CRL refresh */
static char *
test_crl_long_running_simulation (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file[] = "/tmp/test_crl_long_XXXXXX";
  int fd;
  integration_callback_data_t callback_data = {0};

  /* Initialize callback data */
  pthread_mutex_init (&callback_data.lock, NULL);

  TRY
  {
    /* Create TLS context */
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    /* Create CRL file */
    fd = mkstemp (temp_file);
    TEST_ASSERT (fd != -1);
    close (fd);

    /* Write a minimal valid CRL */
    FILE *f = fopen (temp_file, "w");
    TEST_ASSERT (f != NULL);
    fprintf (f, "-----BEGIN X509 CRL-----\n");
    fprintf (f, "MIIBvjCBowIJAKZ7ZL0FgZpZMA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNVBAMMCWxv\n");
    fprintf (f, "Y2FsaG9zdBcNMjUwMTIwMTIwMDAwWhcNMjUwMTIxMTIwMDAwWjArMCkCCQCmd2S9\n");
    fprintf (f, "BYGaWTALBgNVHRQEBAICEAIwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBBQUA\n");
    fprintf (f, "A4GBAMnG9Z6Z3F8kJvQK8t6rFg2aX8QzJcFkJzZbQK8t6rFg2aX8QzJcFkJzZbQ\n");
    fprintf (f, "-----END X509 CRL-----\n");
    fclose (f);

    /* Configure auto-refresh with short interval for testing */
    SocketTLSContext_set_crl_auto_refresh (ctx, temp_file, 2, /* 2 seconds */
                                           integration_crl_callback, &callback_data);

    /* Simulate application event loop for 10 seconds */
    time_t start_time = time (NULL);
    int iterations = 0;

    while (time (NULL) - start_time < 10)
      {
        /* Check for CRL refresh */
        SocketTLSContext_crl_check_refresh (ctx);

        /* Simulate other work */
        usleep (500000); /* 500ms */
        iterations++;

        /* Periodic status check */
        if (iterations % 10 == 0)
          {
            pthread_mutex_lock (&callback_data.lock);
            printf ("Integration Status: %d iterations, %d refreshes\n",
                    iterations, callback_data.total_calls);
            pthread_mutex_unlock (&callback_data.lock);
          }
      }

    /* Verify that refreshes occurred */
    pthread_mutex_lock (&callback_data.lock);
    TEST_ASSERT (callback_data.total_calls >= 3); /* At least 3 refreshes in 10s */
    TEST_ASSERT (callback_data.success_count >= 3);
    TEST_ASSERT (callback_data.failure_count == 0);
    pthread_mutex_unlock (&callback_data.lock);

    unlink (temp_file);
    SocketTLSContext_free (&ctx);
    pthread_mutex_destroy (&callback_data.lock);
  }
  EXCEPT (SocketTLS_Failed)
  {
    unlink (temp_file);
    if (ctx)
      SocketTLSContext_free (&ctx);
    pthread_mutex_destroy (&callback_data.lock);
    TEST_FAIL ("CRL long-running simulation failed");
  }
  END_TRY;

  return NULL;
}

/* Test CRL refresh timing accuracy */
static char *
test_crl_refresh_timing (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file[] = "/tmp/test_crl_timing_XXXXXX";
  int fd;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    fd = mkstemp (temp_file);
    TEST_ASSERT (fd != -1);
    close (fd);

    /* Create minimal CRL */
    FILE *f = fopen (temp_file, "w");
    TEST_ASSERT (f != NULL);
    fprintf (f, "-----BEGIN X509 CRL-----\n");
    fprintf (f, "MIIBvjCBowIJAKZ7ZL0FgZpZMA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNVBAMMCWxv\n");
    fprintf (f, "Y2FsaG9zdBcNMjUwMTIwMTIwMDAwWhcNMjUwMTIxMTIwMDAwWjArMCkCCQCmd2S9\n");
    fprintf (f, "BYGaWTALBgNVHRQEBAICEAIwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBBQUA\n");
    fprintf (f, "A4GBAMnG9Z6Z3F8kJvQK8t6rFg2aX8QzJcFkJzZbQK8t6rFg2aX8QzJcFkJzZbQ\n");
    fprintf (f, "-----END X509 CRL-----\n");
    fclose (f);

    /* Configure 3-second refresh interval */
    SocketTLSContext_set_crl_auto_refresh (ctx, temp_file, 3, NULL, NULL);

    /* Check initial timing */
    long initial_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    TEST_ASSERT (initial_ms > 0 && initial_ms <= 3000);

    /* Wait 1 second and check timing decreased */
    usleep (1000000); /* 1 second */
    long after_1s_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    TEST_ASSERT (after_1s_ms > 0 && after_1s_ms < initial_ms);

    /* Wait another 1 second */
    usleep (1000000); /* 1 second */
    long after_2s_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    TEST_ASSERT (after_2s_ms > 0 && after_2s_ms < after_1s_ms);

    /* Force a refresh */
    int refreshed = SocketTLSContext_crl_check_refresh (ctx);
    TEST_ASSERT (refreshed == 1);

    /* Check timing reset */
    long after_refresh_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    TEST_ASSERT (after_refresh_ms > 0 && after_refresh_ms <= 3000);

    unlink (temp_file);
    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    unlink (temp_file);
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("CRL refresh timing test failed");
  }
  END_TRY;

  return NULL;
}

/* Test CRL refresh with file updates */
static char *
test_crl_file_update_refresh (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file[] = "/tmp/test_crl_update_XXXXXX";
  int fd;
  integration_callback_data_t callback_data = {0};

  /* Initialize callback data */
  pthread_mutex_init (&callback_data.lock, NULL);

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    fd = mkstemp (temp_file);
    TEST_ASSERT (fd != -1);
    close (fd);

    /* Create initial CRL */
    FILE *f = fopen (temp_file, "w");
    TEST_ASSERT (f != NULL);
    fprintf (f, "-----BEGIN X509 CRL-----\n");
    fprintf (f, "MIIBvjCBowIJAKZ7ZL0FgZpZMA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNVBAMMCWxv\n");
    fprintf (f, "Y2FsaG9zdBcNMjUwMTIwMTIwMDAwWhcNMjUwMTIxMTIwMDAwWjArMCkCCQCmd2S9\n");
    fprintf (f, "BYGaWTALBgNVHRQEBAICEAIwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBBQUA\n");
    fprintf (f, "A4GBAMnG9Z6Z3F8kJvQK8t6rFg2aX8QzJcFkJzZbQK8t6rFg2aX8QzJcFkJzZbQ\n");
    fprintf (f, "-----END X509 CRL-----\n");
    fclose (f);

    /* Configure auto-refresh with 1-second interval */
    SocketTLSContext_set_crl_auto_refresh (ctx, temp_file, 1,
                                           integration_crl_callback, &callback_data);

    /* Wait for initial refresh */
    sleep (2);
    SocketTLSContext_crl_check_refresh (ctx);

    /* Update the CRL file with different content */
    f = fopen (temp_file, "w");
    TEST_ASSERT (f != NULL);
    fprintf (f, "-----BEGIN X509 CRL-----\n");
    fprintf (f, "MIIBvjCBowIJAKZ7ZL0FgZpZMA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNVBAMMCWxv\n");
    fprintf (f, "Y2FsaG9zdBcNMjUwMTIwMTMwMDAwWhcNMjUwMTIxMTMwMDAwWjArMCkCCQCmd2S9\n");
    fprintf (f, "BYGaWTALBgNVHRQEBAICEAIwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBBQUA\n");
    fprintf (f, "A4GBAMnG9Z6Z3F8kJvQK8t6rFg2aX8QzJcFkJzZbQK8t6rFg2aX8QzJcFkJzZbQ\n");
    fprintf (f, "-----END X509 CRL-----\n");
    fclose (f);

    /* Wait and trigger another refresh */
    sleep (2);
    SocketTLSContext_crl_check_refresh (ctx);

    /* Verify refreshes occurred */
    pthread_mutex_lock (&callback_data.lock);
    TEST_ASSERT (callback_data.total_calls >= 2);
    TEST_ASSERT (callback_data.success_count >= 2);
    pthread_mutex_unlock (&callback_data.lock);

    unlink (temp_file);
    SocketTLSContext_free (&ctx);
    pthread_mutex_destroy (&callback_data.lock);
  }
  EXCEPT (SocketTLS_Failed)
  {
    unlink (temp_file);
    if (ctx)
      SocketTLSContext_free (&ctx);
    pthread_mutex_destroy (&callback_data.lock);
    TEST_FAIL ("CRL file update refresh test failed");
  }
  END_TRY;

  return NULL;
}

/* Test concurrent CRL refresh operations */
static void *
concurrent_refresh_thread (void *arg)
{
  SocketTLSContext_T ctx = (SocketTLSContext_T)arg;

  /* Perform refresh checks */
  for (int i = 0; i < 10; i++)
    {
      SocketTLSContext_crl_check_refresh (ctx);
      usleep (100000); /* 100ms */
    }

  return NULL;
}

static char *
test_concurrent_crl_refresh (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file[] = "/tmp/test_crl_concurrent_XXXXXX";
  int fd;
  pthread_t threads[3];

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    fd = mkstemp (temp_file);
    TEST_ASSERT (fd != -1);
    close (fd);

    /* Create CRL file */
    FILE *f = fopen (temp_file, "w");
    TEST_ASSERT (f != NULL);
    fprintf (f, "-----BEGIN X509 CRL-----\n");
    fprintf (f, "MIIBvjCBowIJAKZ7ZL0FgZpZMA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNVBAMMCWxv\n");
    fprintf (f, "Y2FsaG9zdBcNMjUwMTIwMTIwMDAwWhcNMjUwMTIxMTIwMDAwWjArMCkCCQCmd2S9\n");
    fprintf (f, "BYGaWTALBgNVHRQEBAICEAIwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBBQUA\n");
    fprintf (f, "A4GBAMnG9Z6Z3F8kJvQK8t6rFg2aX8QzJcFkJzZbQK8t6rFg2aX8QzJcFkJzZbQ\n");
    fprintf (f, "-----END X509 CRL-----\n");
    fclose (f);

    /* Configure auto-refresh */
    SocketTLSContext_set_crl_auto_refresh (ctx, temp_file, 1, NULL, NULL);

    /* Create concurrent threads performing refresh checks */
    for (int i = 0; i < 3; i++)
      {
        int ret = pthread_create (&threads[i], NULL, concurrent_refresh_thread, ctx);
        TEST_ASSERT (ret == 0);
      }

    /* Wait for all threads to complete */
    for (int i = 0; i < 3; i++)
      {
        pthread_join (threads[i], NULL);
      }

    unlink (temp_file);
    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    unlink (temp_file);
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("Concurrent CRL refresh test failed");
  }
  END_TRY;

  return NULL;
}

/* Test CRL refresh with missing file */
static char *
test_crl_refresh_missing_file (void)
{
  SocketTLSContext_T ctx = NULL;
  integration_callback_data_t callback_data = {0};

  /* Initialize callback data */
  pthread_mutex_init (&callback_data.lock, NULL);

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    /* Configure auto-refresh with non-existent file */
    SocketTLSContext_set_crl_auto_refresh (ctx, "/nonexistent/crl.pem", 1,
                                           integration_crl_callback, &callback_data);

    /* Trigger refresh */
    int refreshed = SocketTLSContext_crl_check_refresh (ctx);
    TEST_ASSERT (refreshed == 1);

    /* Check that callback was called with failure */
    pthread_mutex_lock (&callback_data.lock);
    TEST_ASSERT (callback_data.total_calls == 1);
    TEST_ASSERT (callback_data.failure_count == 1);
    TEST_ASSERT (callback_data.success_count == 0);
    pthread_mutex_unlock (&callback_data.lock);

    SocketTLSContext_free (&ctx);
    pthread_mutex_destroy (&callback_data.lock);
  }
  EXCEPT (SocketTLS_Failed)
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    pthread_mutex_destroy (&callback_data.lock);
    TEST_FAIL ("CRL refresh missing file test failed");
  }
  END_TRY;

  return NULL;
}

/* Main integration test runner */
char *
run_tls_crl_integration_tests (void)
{
  TEST_RUN (test_crl_long_running_simulation);
  TEST_RUN (test_crl_refresh_timing);
  TEST_RUN (test_crl_file_update_refresh);
  TEST_RUN (test_concurrent_crl_refresh);
  TEST_RUN (test_crl_refresh_missing_file);

  return NULL;
}

#endif /* SOCKET_HAS_TLS */
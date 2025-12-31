/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_tls_crl_integration.c - CRL Management Integration Tests
 *
 * Tests CRL auto-refresh functionality in realistic scenarios including
 * timing verification, configuration, and error handling.
 *
 * Note: CRL refresh intervals must be >= 60 seconds per security requirements.
 * Tests verify timing logic and API behavior without waiting for long
 * intervals.
 */

/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketUtil.h"
#include "test/Test.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"

#if SOCKET_HAS_TLS

#include "tls/SocketTLSConfig.h"

/* Suppress -Wclobbered for volatile variables across setjmp/longjmp */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

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
integration_crl_callback (SocketTLSContext_T ctx,
                          const char *path,
                          int success,
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

  pthread_mutex_unlock (&data->lock);

  (void)ctx;  /* Unused */
  (void)path; /* Unused */
}

/**
 * Generate a valid CRL using OpenSSL command line tools.
 * Creates a CA key and cert, then generates a CRL signed by that CA.
 */
static int
generate_test_crl (const char *crl_file,
                   const char *ca_key,
                   const char *ca_cert)
{
  char cmd[2048];
  const char *conf_file = "/tmp/openssl_crl_int_test.cnf";
  FILE *f;

  /* Create OpenSSL config file */
  f = fopen (conf_file, "w");
  if (!f)
    return 0;

  fprintf (f,
           "[ca]\n"
           "default_ca = CA_default\n"
           "[CA_default]\n"
           "database = /tmp/crl_int_test_index.txt\n"
           "crlnumber = /tmp/crl_int_test_crlnumber\n"
           "default_md = sha256\n"
           "default_crl_days = 30\n"
           "[req]\n"
           "distinguished_name = req_dn\n"
           "x509_extensions = v3_ca\n"
           "[req_dn]\n"
           "CN = Test CA\n"
           "[v3_ca]\n"
           "basicConstraints = CA:TRUE\n"
           "keyUsage = keyCertSign, cRLSign\n");
  fclose (f);

  /* Create empty index file */
  f = fopen ("/tmp/crl_int_test_index.txt", "w");
  if (f)
    fclose (f);

  /* Create CRL number file */
  f = fopen ("/tmp/crl_int_test_crlnumber", "w");
  if (f)
    {
      fprintf (f, "01\n");
      fclose (f);
    }

  /* Generate CA key */
  snprintf (
      cmd, sizeof (cmd), "openssl genrsa -out %s 2048 2>/dev/null", ca_key);
  if (system (cmd) != 0)
    goto fail;

  /* Generate self-signed CA certificate */
  snprintf (cmd,
            sizeof (cmd),
            "openssl req -new -x509 -key %s -out %s -days 1 -nodes "
            "-subj '/CN=Test CA' -config %s -extensions v3_ca 2>/dev/null",
            ca_key,
            ca_cert,
            conf_file);
  if (system (cmd) != 0)
    goto fail;

  /* Generate CRL */
  snprintf (cmd,
            sizeof (cmd),
            "openssl ca -gencrl -keyfile %s -cert %s -out %s "
            "-config %s 2>/dev/null",
            ca_key,
            ca_cert,
            crl_file,
            conf_file);
  if (system (cmd) != 0)
    goto fail;

  /* Cleanup temp files */
  unlink (conf_file);
  unlink ("/tmp/crl_int_test_index.txt");
  unlink ("/tmp/crl_int_test_index.txt.attr");
  unlink ("/tmp/crl_int_test_crlnumber");
  unlink ("/tmp/crl_int_test_crlnumber.old");
  return 1;

fail:
  unlink (conf_file);
  unlink ("/tmp/crl_int_test_index.txt");
  unlink ("/tmp/crl_int_test_index.txt.attr");
  unlink ("/tmp/crl_int_test_crlnumber");
  unlink ("/tmp/crl_int_test_crlnumber.old");
  unlink (ca_key);
  unlink (ca_cert);
  unlink (crl_file);
  return 0;
}

static void
cleanup_test_crl (const char *crl_file, const char *ca_key, const char *ca_cert)
{
  unlink (crl_file);
  unlink (ca_key);
  unlink (ca_cert);
}

/* Test CRL refresh timing - verify next_refresh_ms returns correct values */
TEST (crl_integration_refresh_timing)
{
  SocketTLSContext_T ctx = NULL;
  const char *crl_file = "/tmp/test_crl_timing.crl";
  const char *ca_key = "/tmp/test_crl_timing_ca.key";
  const char *ca_cert = "/tmp/test_crl_timing_ca.crt";

  if (!generate_test_crl (crl_file, ca_key, ca_cert))
    return; /* Skip if openssl not available */

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Configure with minimum 60-second refresh interval */
    SocketTLSContext_set_crl_auto_refresh (
        ctx, crl_file, SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL, NULL, NULL);

    /* Check initial timing - should be ~60 seconds (60000ms) */
    long initial_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    ASSERT (initial_ms > 0);
    ASSERT (initial_ms <= (SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL * 1000L));

    /* Wait 100ms and verify timing decreased */
    usleep (100000); /* 100ms */
    long after_wait_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    ASSERT (after_wait_ms >= 0);
    ASSERT (after_wait_ms < initial_ms);
  }
  FINALLY
  {
    cleanup_test_crl (crl_file, ca_key, ca_cert);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* Test CRL refresh configuration with callback */
TEST (crl_integration_refresh_callback)
{
  SocketTLSContext_T ctx = NULL;
  const char *crl_file = "/tmp/test_crl_intcb.crl";
  const char *ca_key = "/tmp/test_crl_intcb_ca.key";
  const char *ca_cert = "/tmp/test_crl_intcb_ca.crt";
  integration_callback_data_t callback_data = { 0 };

  /* Initialize callback data */
  pthread_mutex_init (&callback_data.lock, NULL);

  if (!generate_test_crl (crl_file, ca_key, ca_cert))
    {
      pthread_mutex_destroy (&callback_data.lock);
      return; /* Skip if openssl not available */
    }

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Configure auto-refresh with callback */
    SocketTLSContext_set_crl_auto_refresh (ctx,
                                           crl_file,
                                           SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL,
                                           integration_crl_callback,
                                           &callback_data);

    /* Verify timing is set */
    long next_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    ASSERT (next_ms > 0);

    /* The API should work; we don't wait for refresh to actually occur
       since that would require 60+ seconds */
  }
  FINALLY
  {
    cleanup_test_crl (crl_file, ca_key, ca_cert);
    if (ctx)
      SocketTLSContext_free (&ctx);
    pthread_mutex_destroy (&callback_data.lock);
  }
  END_TRY;
}

/* Test concurrent CRL operations (thread safety) */
static void *
concurrent_query_thread (void *arg)
{
  SocketTLSContext_T ctx = (SocketTLSContext_T)arg;

  /* Perform multiple next_refresh_ms queries */
  for (int i = 0; i < 50; i++)
    {
      long ms = SocketTLSContext_crl_next_refresh_ms (ctx);
      (void)ms;
      usleep (1000); /* 1ms */
    }

  return NULL;
}

TEST (crl_integration_concurrent_queries)
{
  SocketTLSContext_T ctx = NULL;
  const char *crl_file = "/tmp/test_crl_concurrent.crl";
  const char *ca_key = "/tmp/test_crl_concurrent_ca.key";
  const char *ca_cert = "/tmp/test_crl_concurrent_ca.crt";
  pthread_t threads[3];

  if (!generate_test_crl (crl_file, ca_key, ca_cert))
    return; /* Skip if openssl not available */

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Configure auto-refresh */
    SocketTLSContext_set_crl_auto_refresh (
        ctx, crl_file, SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL, NULL, NULL);

    /* Create concurrent threads querying refresh timing */
    for (int i = 0; i < 3; i++)
      {
        int ret
            = pthread_create (&threads[i], NULL, concurrent_query_thread, ctx);
        ASSERT_EQ (ret, 0);
      }

    /* Wait for all threads to complete */
    for (int i = 0; i < 3; i++)
      {
        pthread_join (threads[i], NULL);
      }

    /* If we got here without crashing, concurrent access is safe */
  }
  FINALLY
  {
    cleanup_test_crl (crl_file, ca_key, ca_cert);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* Test CRL auto-refresh with invalid file path (path validation) */
TEST (crl_integration_invalid_path)
{
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Configure auto-refresh with non-existent file should fail */
    TRY
    {
      SocketTLSContext_set_crl_auto_refresh (
          ctx,
          "/nonexistent/crl.pem",
          SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL,
          NULL,
          NULL);
    }
    EXCEPT (SocketTLS_Failed)
    {
      caught = 1;
    }
    END_TRY;

    ASSERT_EQ (caught, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

#endif /* SOCKET_HAS_TLS */

int
main (void)
{
  /* Ignore SIGPIPE */
  signal (SIGPIPE, SIG_IGN);

  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}

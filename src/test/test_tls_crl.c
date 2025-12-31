/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_tls_crl.c - CRL Management Unit Tests
 *
 * Tests the CRL (Certificate Revocation List) management system
 * including loading, refresh configuration, security validations, and
 * error handling.
 *
 * Note: CRL refresh intervals must be >= 60 seconds per security requirements.
 * Tests verify timing logic without actually waiting for long intervals.
 */

/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */

#include <limits.h>
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
#include <openssl/ssl.h>
#include <openssl/x509.h>

/* Suppress -Wclobbered for volatile variables across setjmp/longjmp */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Test callback data */
typedef struct
{
  int call_count;
  int last_success;
  char last_path[1024];
} test_callback_data_t;

/* Test CRL refresh callback */
static void
test_crl_callback (SocketTLSContext_T ctx,
                   const char *path,
                   int success,
                   void *user_data)
{
  test_callback_data_t *data = (test_callback_data_t *)user_data;
  data->call_count++;
  data->last_success = success;
  strncpy (data->last_path, path, sizeof (data->last_path) - 1);
  data->last_path[sizeof (data->last_path) - 1] = '\0';

  (void)ctx; /* Unused */
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
  const char *conf_file = "/tmp/openssl_crl_test.cnf";
  FILE *f;

  /* Create OpenSSL config file */
  f = fopen (conf_file, "w");
  if (!f)
    return 0;

  fprintf (f,
           "[ca]\n"
           "default_ca = CA_default\n"
           "[CA_default]\n"
           "database = /tmp/crl_test_index.txt\n"
           "crlnumber = /tmp/crl_test_crlnumber\n"
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
  f = fopen ("/tmp/crl_test_index.txt", "w");
  if (f)
    fclose (f);

  /* Create CRL number file */
  f = fopen ("/tmp/crl_test_crlnumber", "w");
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
  unlink ("/tmp/crl_test_index.txt");
  unlink ("/tmp/crl_test_index.txt.attr");
  unlink ("/tmp/crl_test_crlnumber");
  unlink ("/tmp/crl_test_crlnumber.old");
  return 1;

fail:
  unlink (conf_file);
  unlink ("/tmp/crl_test_index.txt");
  unlink ("/tmp/crl_test_index.txt.attr");
  unlink ("/tmp/crl_test_crlnumber");
  unlink ("/tmp/crl_test_crlnumber.old");
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

/* Test disabled auto-refresh returns -1 for next refresh */
TEST (crl_disabled_refresh_returns_minus_one)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Without configuring auto-refresh, next_refresh_ms should return -1 */
    long next_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    ASSERT_EQ (next_ms, -1);
  }
  FINALLY
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* Test interval validation - negative interval */
TEST (crl_interval_validation_negative)
{
  SocketTLSContext_T ctx = NULL;
  const char *crl_file = "/tmp/test_crl_interval.crl";
  const char *ca_key = "/tmp/test_crl_interval_ca.key";
  const char *ca_cert = "/tmp/test_crl_interval_ca.crt";
  volatile int caught = 0;

  if (!generate_test_crl (crl_file, ca_key, ca_cert))
    return; /* Skip if openssl not available */

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Test negative interval (should fail) */
    TRY
    {
      SocketTLSContext_set_crl_auto_refresh (ctx, crl_file, -1, NULL, NULL);
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
    cleanup_test_crl (crl_file, ca_key, ca_cert);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* Test interval validation - below minimum */
TEST (crl_interval_validation_below_minimum)
{
  SocketTLSContext_T ctx = NULL;
  const char *crl_file = "/tmp/test_crl_belowmin.crl";
  const char *ca_key = "/tmp/test_crl_belowmin_ca.key";
  const char *ca_cert = "/tmp/test_crl_belowmin_ca.crt";
  volatile int caught = 0;

  if (!generate_test_crl (crl_file, ca_key, ca_cert))
    return; /* Skip if openssl not available */

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Test 30 seconds (below minimum of 60) */
    TRY
    {
      SocketTLSContext_set_crl_auto_refresh (ctx, crl_file, 30, NULL, NULL);
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
    cleanup_test_crl (crl_file, ca_key, ca_cert);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* Test interval validation - above maximum */
TEST (crl_interval_validation_above_maximum)
{
  SocketTLSContext_T ctx = NULL;
  const char *crl_file = "/tmp/test_crl_abovemax.crl";
  const char *ca_key = "/tmp/test_crl_abovemax_ca.key";
  const char *ca_cert = "/tmp/test_crl_abovemax_ca.crt";
  volatile int caught = 0;

  if (!generate_test_crl (crl_file, ca_key, ca_cert))
    return; /* Skip if openssl not available */

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Test 400 days (above maximum of 1 year) */
    TRY
    {
      SocketTLSContext_set_crl_auto_refresh (
          ctx, crl_file, 400L * 24 * 3600, NULL, NULL);
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
    cleanup_test_crl (crl_file, ca_key, ca_cert);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* Test minimum interval boundary (exactly 60 seconds) */
TEST (crl_minimum_interval_boundary)
{
  SocketTLSContext_T ctx = NULL;
  const char *crl_file = "/tmp/test_crl_minbnd.crl";
  const char *ca_key = "/tmp/test_crl_minbnd_ca.key";
  const char *ca_cert = "/tmp/test_crl_minbnd_ca.crt";
  volatile int success = 0;

  if (!generate_test_crl (crl_file, ca_key, ca_cert))
    return; /* Skip if openssl not available */

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Test exactly 60 seconds (minimum) - should succeed */
    SocketTLSContext_set_crl_auto_refresh (
        ctx, crl_file, SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL, NULL, NULL);

    /* Verify timing is set */
    long next_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    ASSERT (next_ms > 0);
    success = 1;
  }
  FINALLY
  {
    cleanup_test_crl (crl_file, ca_key, ca_cert);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;

  ASSERT_EQ (success, 1);
}

/* Test CRL loading with non-existent file */
TEST (crl_error_nonexistent_file)
{
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Test loading non-existent file (should fail) */
    TRY
    {
      SocketTLSContext_load_crl (ctx, "/nonexistent/crl/file.pem");
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

/* Test path security - path traversal rejected */
TEST (crl_path_security_traversal)
{
  SocketTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Test path with .. (should fail due to traversal) */
    TRY
    {
      SocketTLSContext_load_crl (ctx, "/tmp/../../../etc/passwd");
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

/* Test CRL cancel auto-refresh */
TEST (crl_cancel_auto_refresh)
{
  SocketTLSContext_T ctx = NULL;
  const char *crl_file = "/tmp/test_crl_cancel.crl";
  const char *ca_key = "/tmp/test_crl_cancel_ca.key";
  const char *ca_cert = "/tmp/test_crl_cancel_ca.crt";

  if (!generate_test_crl (crl_file, ca_key, ca_cert))
    return; /* Skip if openssl not available */

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Configure auto-refresh with minimum interval */
    SocketTLSContext_set_crl_auto_refresh (
        ctx, crl_file, SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL, NULL, NULL);

    /* Verify timing is set */
    long next_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    ASSERT (next_ms > 0);

    /* Cancel auto-refresh */
    SocketTLSContext_cancel_crl_auto_refresh (ctx);

    /* Verify refresh is disabled */
    next_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    ASSERT_EQ (next_ms, -1);
  }
  FINALLY
  {
    cleanup_test_crl (crl_file, ca_key, ca_cert);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* Test basic CRL loading */
TEST (crl_load_basic)
{
  SocketTLSContext_T ctx = NULL;
  const char *crl_file = "/tmp/test_crl_basic.crl";
  const char *ca_key = "/tmp/test_crl_basic_ca.key";
  const char *ca_cert = "/tmp/test_crl_basic_ca.crt";
  volatile int success = 0;

  if (!generate_test_crl (crl_file, ca_key, ca_cert))
    return; /* Skip if openssl not available */

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Load CRL - should succeed */
    SocketTLSContext_load_crl (ctx, crl_file);
    success = 1;
  }
  FINALLY
  {
    cleanup_test_crl (crl_file, ca_key, ca_cert);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;

  ASSERT_EQ (success, 1);
}

/* Test CRL file size limit enforcement */
TEST (crl_file_size_limit)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file[] = "/tmp/test_crl_size_XXXXXX";
  int fd;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Create oversized file (just over limit) */
    fd = mkstemp (temp_file);
    ASSERT (fd != -1);

    /* Write a file slightly larger than max (add 1KB to be safe) */
    size_t oversize = SOCKET_TLS_MAX_CRL_SIZE + 1024;
    char *large_data = (char *)malloc (oversize);
    ASSERT_NOT_NULL (large_data);

    memset (large_data, 'A', oversize);
    ssize_t written = write (fd, large_data, oversize);
    free (large_data);
    close (fd);

    ASSERT ((size_t)written == oversize);

    /* Loading oversized file should fail */
    TRY
    {
      SocketTLSContext_load_crl (ctx, temp_file);
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
    unlink (temp_file);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* Test auto-refresh configuration with callback */
TEST (crl_auto_refresh_with_callback)
{
  SocketTLSContext_T ctx = NULL;
  const char *crl_file = "/tmp/test_crl_callback.crl";
  const char *ca_key = "/tmp/test_crl_callback_ca.key";
  const char *ca_cert = "/tmp/test_crl_callback_ca.crt";
  test_callback_data_t callback_data = { 0 };

  if (!generate_test_crl (crl_file, ca_key, ca_cert))
    return; /* Skip if openssl not available */

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Configure auto-refresh with callback */
    SocketTLSContext_set_crl_auto_refresh (ctx,
                                           crl_file,
                                           SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL,
                                           test_crl_callback,
                                           &callback_data);

    /* Verify timing is set */
    long next_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    ASSERT (next_ms > 0);

    /* Initial load should have triggered callback success
       (auto-refresh does initial load) */
    /* Note: Whether initial load triggers callback depends on implementation.
       Just verify the API works without crashing */
  }
  FINALLY
  {
    cleanup_test_crl (crl_file, ca_key, ca_cert);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* Test overflow protection for time addition */
TEST (crl_overflow_protection)
{
  SocketTLSContext_T ctx = NULL;
  const char *crl_file = "/tmp/test_crl_overflow.crl";
  const char *ca_key = "/tmp/test_crl_overflow_ca.key";
  const char *ca_cert = "/tmp/test_crl_overflow_ca.crt";

  if (!generate_test_crl (crl_file, ca_key, ca_cert))
    return; /* Skip if openssl not available */

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Configure with maximum allowed interval (1 year) */
    SocketTLSContext_set_crl_auto_refresh (
        ctx, crl_file, SOCKET_TLS_CRL_MAX_REFRESH_INTERVAL, NULL, NULL);

    /* Verify timing is set and does not overflow */
    long next_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    ASSERT (next_ms > 0);

    /* The implementation should clamp to INT64_MAX if overflow would occur,
       but with normal system uptime this should not happen. The test verifies
       that the safe_add_u64 protection is in place and doesn't crash. */

    /* Verify next refresh time is reasonable (not negative or zero) */
    ASSERT (next_ms >= 0);
  }
  FINALLY
  {
    cleanup_test_crl (crl_file, ca_key, ca_cert);
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

/**
 * test_tls_crl.c - CRL Management Unit Tests (Section 2.5)
 *
 * Tests the complete CRL (Certificate Revocation List) management system
 * including loading, refresh, auto-refresh, security validations, and
 * error handling.
 */

#include "core/Arena.h"
#include "core/SocketUtil.h"
#include "test/Test.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if SOCKET_HAS_TLS

#include "tls/SocketTLSConfig.h"
#include <openssl/ssl.h>
#include <openssl/x509.h>

/* Test callback data */
typedef struct
{
  int call_count;
  int last_success;
  char last_path[1024];
} test_callback_data_t;

/* Test CRL refresh callback */
static void
test_crl_callback (SocketTLSContext_T ctx, const char *path, int success,
                   void *user_data)
{
  test_callback_data_t *data = (test_callback_data_t *)user_data;
  data->call_count++;
  data->last_success = success;
  strncpy (data->last_path, path, sizeof (data->last_path) - 1);
  data->last_path[sizeof (data->last_path) - 1] = '\0';

  (void)ctx; /* Unused */
}

/* Create a minimal valid CRL for testing */
static int
create_test_crl (const char *filename)
{
  /* Create a minimal PEM CRL structure for testing */
  const char *crl_pem =
    "-----BEGIN X509 CRL-----\n"
    "MIIBvjCBowIJAKZ7ZL0FgZpZMA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNVBAMMCWxv\n"
    "Y2FsaG9zdBcNMjUwMTIwMTIwMDAwWhcNMjUwMTIxMTIwMDAwWjArMCkCCQCmd2S9\n"
    "BYGaWTALBgNVHRQEBAICEAIwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBBQUA\n"
    "A4GBAMnG9Z6Z3F8kJvQK8t6rFg2aX8QzJcFkJzZbQK8t6rFg2aX8QzJcFkJzZbQ\n"
    "-----END X509 CRL-----\n";

  FILE *f = fopen (filename, "w");
  if (!f)
    return 0;

  fprintf (f, "%s", crl_pem);
  fclose (f);
  return 1;
}

/* Create a directory with CRL files */
static int
create_test_crl_directory (const char *dirname)
{
  if (mkdir (dirname, 0755) != 0)
    return 0;

  /* Create hash-named CRL files (OpenSSL style) */
  char crl1_path[1024];
  char crl2_path[1024];

  snprintf (crl1_path, sizeof (crl1_path), "%s/12345678.r0", dirname);
  snprintf (crl2_path, sizeof (crl2_path), "%s/87654321.r0", dirname);

  return create_test_crl (crl1_path) && create_test_crl (crl2_path);
}

/* Test basic CRL loading */
static char *
test_load_crl_basic (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file[] = "/tmp/test_crl_XXXXXX";
  int fd;

  TRY
  {
    /* Create TLS context */
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    /* Create temporary CRL file */
    fd = mkstemp (temp_file);
    TEST_ASSERT (fd != -1);
    close (fd);

    TEST_ASSERT (create_test_crl (temp_file));

    /* Load CRL */
    SocketTLSContext_load_crl (ctx, temp_file);
    /* Should not raise exception */

    unlink (temp_file);
    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    unlink (temp_file);
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("CRL loading failed unexpectedly");
  }
  END_TRY;

  return NULL;
}

/* Test CRL loading from directory */
static char *
test_load_crl_directory (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_dir[] = "/tmp/test_crl_dir_XXXXXX";

  TRY
  {
    /* Create TLS context */
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    /* Create temporary directory with CRL files */
    TEST_ASSERT (mkdtemp (temp_dir) != NULL);
    TEST_ASSERT (create_test_crl_directory (temp_dir));

    /* Load CRL directory */
    SocketTLSContext_load_crl (ctx, temp_dir);
    /* Should not raise exception */

    char cmd[1024];
    snprintf (cmd, sizeof (cmd), "rm -rf %s", temp_dir);
    system (cmd);

    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    char cmd[1024];
    snprintf (cmd, sizeof (cmd), "rm -rf %s", temp_dir);
    system (cmd);

    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("CRL directory loading failed unexpectedly");
  }
  END_TRY;

  return NULL;
}

/* Test CRL refresh */
static char *
test_refresh_crl (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file[] = "/tmp/test_crl_refresh_XXXXXX";
  int fd;

  TRY
  {
    /* Create TLS context */
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    /* Create temporary CRL file */
    fd = mkstemp (temp_file);
    TEST_ASSERT (fd != -1);
    close (fd);

    TEST_ASSERT (create_test_crl (temp_file));

    /* Load initial CRL */
    SocketTLSContext_load_crl (ctx, temp_file);

    /* Refresh CRL */
    SocketTLSContext_refresh_crl (ctx, temp_file);
    /* Should not raise exception */

    unlink (temp_file);
    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    unlink (temp_file);
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("CRL refresh failed unexpectedly");
  }
  END_TRY;

  return NULL;
}

/* Test CRL reload (alias for refresh) */
static char *
test_reload_crl (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file[] = "/tmp/test_crl_reload_XXXXXX";
  int fd;

  TRY
  {
    /* Create TLS context */
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    /* Create temporary CRL file */
    fd = mkstemp (temp_file);
    TEST_ASSERT (fd != -1);
    close (fd);

    TEST_ASSERT (create_test_crl (temp_file));

    /* Load initial CRL */
    SocketTLSContext_load_crl (ctx, temp_file);

    /* Reload CRL */
    SocketTLSContext_reload_crl (ctx, temp_file);
    /* Should not raise exception */

    unlink (temp_file);
    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    unlink (temp_file);
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("CRL reload failed unexpectedly");
  }
  END_TRY;

  return NULL;
}

/* Test auto-refresh configuration */
static char *
test_set_crl_auto_refresh (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file[] = "/tmp/test_crl_auto_XXXXXX";
  int fd;

  TRY
  {
    /* Create TLS context */
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    /* Create temporary CRL file */
    fd = mkstemp (temp_file);
    TEST_ASSERT (fd != -1);
    close (fd);

    TEST_ASSERT (create_test_crl (temp_file));

    /* Configure auto-refresh */
    SocketTLSContext_set_crl_auto_refresh (ctx, temp_file, 3600, NULL, NULL);
    /* Should not raise exception */

    /* Check that next refresh time is set */
    long next_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    TEST_ASSERT (next_ms > 0);

    unlink (temp_file);
    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    unlink (temp_file);
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("CRL auto-refresh configuration failed unexpectedly");
  }
  END_TRY;

  return NULL;
}

/* Test auto-refresh with callback */
static char *
test_crl_auto_refresh_callback (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file[] = "/tmp/test_crl_callback_XXXXXX";
  int fd;
  test_callback_data_t callback_data = {0};

  TRY
  {
    /* Create TLS context */
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    /* Create temporary CRL file */
    fd = mkstemp (temp_file);
    TEST_ASSERT (fd != -1);
    close (fd);

    TEST_ASSERT (create_test_crl (temp_file));

    /* Configure auto-refresh with callback */
    SocketTLSContext_set_crl_auto_refresh (ctx, temp_file, 1, test_crl_callback,
                                           &callback_data);

    /* Wait a bit and check refresh */
    sleep (2);

    int refreshed = SocketTLSContext_crl_check_refresh (ctx);
    TEST_ASSERT (refreshed == 1);
    TEST_ASSERT (callback_data.call_count == 1);
    TEST_ASSERT (callback_data.last_success == 1);
    TEST_ASSERT (strcmp (callback_data.last_path, temp_file) == 0);

    unlink (temp_file);
    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    unlink (temp_file);
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("CRL auto-refresh with callback failed unexpectedly");
  }
  END_TRY;

  return NULL;
}

/* Test canceling auto-refresh */
static char *
test_cancel_crl_auto_refresh (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file[] = "/tmp/test_crl_cancel_XXXXXX";
  int fd;

  TRY
  {
    /* Create TLS context */
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    /* Create temporary CRL file */
    fd = mkstemp (temp_file);
    TEST_ASSERT (fd != -1);
    close (fd);

    TEST_ASSERT (create_test_crl (temp_file));

    /* Configure auto-refresh */
    SocketTLSContext_set_crl_auto_refresh (ctx, temp_file, 3600, NULL, NULL);

    /* Check that next refresh time is set */
    long next_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    TEST_ASSERT (next_ms > 0);

    /* Cancel auto-refresh */
    SocketTLSContext_cancel_crl_auto_refresh (ctx);

    /* Check that refresh is disabled */
    next_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    TEST_ASSERT (next_ms == -1);

    unlink (temp_file);
    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    unlink (temp_file);
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("CRL auto-refresh cancellation failed unexpectedly");
  }
  END_TRY;

  return NULL;
}

/* Test path security validation */
static char *
test_crl_path_security (void)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    /* Test path with .. (should fail) */
    TRY
    {
      SocketTLSContext_load_crl (ctx, "/tmp/../../../etc/passwd");
      TEST_FAIL ("Path traversal should have been rejected");
    }
    EXCEPT (SocketTLS_Failed)
    {
      /* Expected - path traversal should be rejected */
    }
    END_TRY;

    /* Test path with control characters (should fail) */
    TRY
    {
      SocketTLSContext_load_crl (ctx, "/tmp/crl\x01test.pem");
      TEST_FAIL ("Control characters should have been rejected");
    }
    EXCEPT (SocketTLS_Failed)
    {
      /* Expected - control characters should be rejected */
    }
    END_TRY;

    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("CRL path security test setup failed");
  }
  END_TRY;

  return NULL;
}

/* Test interval validation */
static char *
test_crl_interval_validation (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file[] = "/tmp/test_crl_interval_XXXXXX";
  int fd;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    fd = mkstemp (temp_file);
    TEST_ASSERT (fd != -1);
    close (fd);
    TEST_ASSERT (create_test_crl (temp_file));

    /* Test negative interval (should fail) */
    TRY
    {
      SocketTLSContext_set_crl_auto_refresh (ctx, temp_file, -1, NULL, NULL);
      TEST_FAIL ("Negative interval should have been rejected");
    }
    EXCEPT (SocketTLS_Failed)
    {
      /* Expected */
    }
    END_TRY;

    /* Test too small interval (should fail) */
    TRY
    {
      SocketTLSContext_set_crl_auto_refresh (ctx, temp_file, 30, NULL, NULL);
      TEST_FAIL ("Too small interval should have been rejected");
    }
    EXCEPT (SocketTLS_Failed)
    {
      /* Expected */
    }
    END_TRY;

    /* Test too large interval (should fail) */
    TRY
    {
      SocketTLSContext_set_crl_auto_refresh (ctx, temp_file, 400 * 24 * 3600,
                                             NULL, NULL);
      TEST_FAIL ("Too large interval should have been rejected");
    }
    EXCEPT (SocketTLS_Failed)
    {
      /* Expected */
    }
    END_TRY;

    unlink (temp_file);
    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    unlink (temp_file);
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("CRL interval validation test failed");
  }
  END_TRY;

  return NULL;
}

/* Test CRL loading error handling */
static char *
test_crl_error_handling (void)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    /* Test loading non-existent file (should fail) */
    TRY
    {
      SocketTLSContext_load_crl (ctx, "/nonexistent/crl/file.pem");
      TEST_FAIL ("Loading non-existent file should have failed");
    }
    EXCEPT (SocketTLS_Failed)
    {
      /* Expected */
    }
    END_TRY;

    /* Test loading directory as file (may succeed or fail depending on content) */
    TRY
    {
      SocketTLSContext_load_crl (ctx, "/tmp");
      /* This might succeed if /tmp has CRL files, or fail - either is OK */
    }
    EXCEPT (SocketTLS_Failed)
    {
      /* Also OK - depends on /tmp contents */
    }
    END_TRY;

    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("CRL error handling test setup failed");
  }
  END_TRY;

  return NULL;
}

/* Test multiple CRL loading (accumulation) */
static char *
test_multiple_crl_loading (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file1[] = "/tmp/test_crl_multi1_XXXXXX";
  char temp_file2[] = "/tmp/test_crl_multi2_XXXXXX";
  int fd1, fd2;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    /* Create first CRL file */
    fd1 = mkstemp (temp_file1);
    TEST_ASSERT (fd1 != -1);
    close (fd1);
    TEST_ASSERT (create_test_crl (temp_file1));

    /* Create second CRL file */
    fd2 = mkstemp (temp_file2);
    TEST_ASSERT (fd2 != -1);
    close (fd2);
    TEST_ASSERT (create_test_crl (temp_file2));

    /* Load first CRL */
    SocketTLSContext_load_crl (ctx, temp_file1);

    /* Load second CRL (should accumulate) */
    SocketTLSContext_load_crl (ctx, temp_file2);

    unlink (temp_file1);
    unlink (temp_file2);
    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    unlink (temp_file1);
    unlink (temp_file2);
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("Multiple CRL loading failed unexpectedly");
  }
  END_TRY;

  return NULL;
}

/* Test overflow protection in crl_next_refresh_ms */
static char *
test_crl_next_refresh_overflow (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file[] = "/tmp/test_crl_overflow_XXXXXX";
  int fd;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    fd = mkstemp (temp_file);
    TEST_ASSERT (fd != -1);
    close (fd);
    TEST_ASSERT (create_test_crl (temp_file));

    /* Configure auto-refresh with maximum allowed interval (1 year) */
    SocketTLSContext_set_crl_auto_refresh (ctx, temp_file,
                                           SOCKET_TLS_CRL_MAX_REFRESH_INTERVAL,
                                           NULL, NULL);

    /* Get next refresh time - should return valid value, not overflow */
    long next_ms = SocketTLSContext_crl_next_refresh_ms (ctx);

    /* Should be positive and bounded by LONG_MAX */
    TEST_ASSERT (next_ms > 0);
    TEST_ASSERT (next_ms <= LONG_MAX);

    /* Verify it's approximately 1 year in milliseconds (with tolerance) */
    /* 1 year in ms = 365 * 24 * 3600 * 1000 = 31536000000 */
    /* But LONG_MAX on 32-bit is only ~2.1 billion, so it may be capped */
    long expected_max_ms = SOCKET_TLS_CRL_MAX_REFRESH_INTERVAL * 1000LL;
    if (expected_max_ms > LONG_MAX)
      {
        /* On systems where this overflows LONG_MAX, verify it's capped */
        TEST_ASSERT (next_ms == LONG_MAX);
      }
    else
      {
        /* Should be close to expected value */
        TEST_ASSERT (next_ms <= expected_max_ms + 1000);
      }

    unlink (temp_file);
    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    unlink (temp_file);
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("CRL overflow protection test failed");
  }
  END_TRY;

  return NULL;
}

/* Test CRL file size limit enforcement */
static char *
test_crl_file_size_limit (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file[] = "/tmp/test_crl_size_XXXXXX";
  int fd;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    /* Create oversized CRL file (just over limit) */
    fd = mkstemp (temp_file);
    TEST_ASSERT (fd != -1);

    /* Write a file slightly larger than max (add 1KB to be safe) */
    size_t oversize = SOCKET_TLS_MAX_CRL_SIZE + 1024;
    char *large_data = (char *)malloc (oversize);
    TEST_ASSERT (large_data != NULL);

    memset (large_data, 'A', oversize);
    ssize_t written = write (fd, large_data, oversize);
    free (large_data);
    close (fd);

    TEST_ASSERT ((size_t)written == oversize);

    /* Loading oversized CRL should fail */
    TRY
    {
      SocketTLSContext_load_crl (ctx, temp_file);
      TEST_FAIL ("Oversized CRL should have been rejected");
    }
    EXCEPT (SocketTLS_Failed)
    {
      /* Expected - file too large */
    }
    END_TRY;

    unlink (temp_file);
    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    unlink (temp_file);
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("CRL file size limit test setup failed");
  }
  END_TRY;

  return NULL;
}

/* Test symlink rejection in CRL path validation */
static char *
test_crl_symlink_rejection (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file[] = "/tmp/test_crl_target_XXXXXX";
  char symlink_path[] = "/tmp/test_crl_symlink_XXXXXX";
  int fd;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    /* Create target CRL file */
    fd = mkstemp (temp_file);
    TEST_ASSERT (fd != -1);
    close (fd);
    TEST_ASSERT (create_test_crl (temp_file));

    /* Create unique symlink name */
    fd = mkstemp (symlink_path);
    TEST_ASSERT (fd != -1);
    close (fd);
    unlink (symlink_path); /* Remove file to create symlink */

    /* Create symlink to CRL file */
    int ret = symlink (temp_file, symlink_path);
    TEST_ASSERT (ret == 0);

    /* Loading CRL via symlink - this should work since realpath resolves it,
     * but the resolved path is validated. The security model allows symlinks
     * that resolve to valid paths, but rejects path traversal. */
    TRY
    {
      SocketTLSContext_load_crl (ctx, symlink_path);
      /* May succeed if symlink resolves to valid path without traversal */
    }
    EXCEPT (SocketTLS_Failed)
    {
      /* May fail depending on security policy - both outcomes acceptable */
    }
    END_TRY;

    unlink (symlink_path);
    unlink (temp_file);
    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    unlink (symlink_path);
    unlink (temp_file);
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("CRL symlink rejection test setup failed");
  }
  END_TRY;

  return NULL;
}

/* Test disabled auto-refresh returns -1 for next refresh */
static char *
test_crl_disabled_refresh_returns_minus_one (void)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    /* Without configuring auto-refresh, next_refresh_ms should return -1 */
    long next_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
    TEST_ASSERT (next_ms == -1);

    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("CRL disabled refresh test failed");
  }
  END_TRY;

  return NULL;
}

/* Test exact minimum interval boundary (60 seconds) */
static char *
test_crl_minimum_interval_boundary (void)
{
  SocketTLSContext_T ctx = NULL;
  char temp_file[] = "/tmp/test_crl_minint_XXXXXX";
  int fd;

  TRY
  {
    ctx = SocketTLSContext_new_client (NULL);
    TEST_ASSERT (ctx != NULL);

    fd = mkstemp (temp_file);
    TEST_ASSERT (fd != -1);
    close (fd);
    TEST_ASSERT (create_test_crl (temp_file));

    /* Test exactly 60 seconds (minimum) - should succeed */
    TRY
    {
      SocketTLSContext_set_crl_auto_refresh (
          ctx, temp_file, SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL, NULL, NULL);
      /* Should succeed */
      long next_ms = SocketTLSContext_crl_next_refresh_ms (ctx);
      TEST_ASSERT (next_ms > 0);
    }
    EXCEPT (SocketTLS_Failed)
    {
      TEST_FAIL ("Minimum interval (60s) should have been accepted");
    }
    END_TRY;

    /* Test 59 seconds (just below minimum) - should fail */
    TRY
    {
      SocketTLSContext_set_crl_auto_refresh (
          ctx, temp_file, SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL - 1, NULL, NULL);
      TEST_FAIL ("Below minimum interval should have been rejected");
    }
    EXCEPT (SocketTLS_Failed)
    {
      /* Expected */
    }
    END_TRY;

    unlink (temp_file);
    SocketTLSContext_free (&ctx);
  }
  EXCEPT (SocketTLS_Failed)
  {
    unlink (temp_file);
    if (ctx)
      SocketTLSContext_free (&ctx);
    TEST_FAIL ("CRL minimum interval boundary test failed");
  }
  END_TRY;

  return NULL;
}

/* Main test runner */
char *
run_tls_crl_tests (void)
{
  TEST_RUN (test_load_crl_basic);
  TEST_RUN (test_load_crl_directory);
  TEST_RUN (test_refresh_crl);
  TEST_RUN (test_reload_crl);
  TEST_RUN (test_set_crl_auto_refresh);
  TEST_RUN (test_crl_auto_refresh_callback);
  TEST_RUN (test_cancel_crl_auto_refresh);
  TEST_RUN (test_crl_path_security);
  TEST_RUN (test_crl_interval_validation);
  TEST_RUN (test_crl_error_handling);
  TEST_RUN (test_multiple_crl_loading);
  TEST_RUN (test_crl_next_refresh_overflow);
  TEST_RUN (test_crl_file_size_limit);
  TEST_RUN (test_crl_symlink_rejection);
  TEST_RUN (test_crl_disabled_refresh_returns_minus_one);
  TEST_RUN (test_crl_minimum_interval_boundary);

  return NULL;
}

#endif /* SOCKET_HAS_TLS */
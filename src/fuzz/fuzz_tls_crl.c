/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_tls_crl.c - Fuzzer for TLS CRL Management (Section 2.5)
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketTLSContext_load_crl() - CRL loading from files/directories
 * - SocketTLSContext_refresh_crl() - CRL refresh operations
 * - SocketTLSContext_reload_crl() - CRL reload operations
 * - SocketTLSContext_set_crl_auto_refresh() - Auto-refresh configuration
 * - SocketTLSContext_crl_check_refresh() - Refresh scheduling/checking
 * - validate_crl_path_security() - Path security validation
 * - validate_crl_interval() - Interval validation
 *
 * Security Focus:
 * - Path traversal prevention (.. sequences)
 * - Control character injection
 * - Memory exhaustion via large CRL files
 * - Race conditions in auto-refresh
 * - Invalid CRL file formats
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON -DENABLE_TLS=ON && make
 * fuzz_tls_crl Run:   ./fuzz_tls_crl corpus/tls_crl/ -fork=16 -max_len=65536
 */

#if SOCKET_HAS_TLS

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/Except.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

/* Operation codes for CRL fuzzing */
enum CrlOp
{
  CRL_OP_LOAD_FILE = 0,
  CRL_OP_LOAD_DIR,
  CRL_OP_REFRESH,
  CRL_OP_RELOAD,
  CRL_OP_SET_AUTO_REFRESH,
  CRL_OP_CANCEL_AUTO_REFRESH,
  CRL_OP_CHECK_REFRESH,
  CRL_OP_GET_NEXT_REFRESH,
  CRL_OP_LOAD_MULTIPLE,
  CRL_OP_LOAD_OVERSIZED,
  CRL_OP_LOAD_SYMLINK,
  CRL_OP_INTERVAL_BOUNDARY,
  CRL_OP_COUNT
};

/* Mock CRL refresh callback for testing */
static void
mock_crl_callback (SocketTLSContext_T ctx,
                   const char *path,
                   int success,
                   void *user_data)
{
  (void)ctx;
  (void)path;
  (void)success;
  (void)user_data;
  /* Callback does nothing - just for fuzzing coverage */
}

/* Create temporary CRL file with fuzzer data */
static char *
create_temp_crl_file (const uint8_t *data, size_t size)
{
  char template[] = "/tmp/fuzz_crl_XXXXXX";
  int fd = mkstemp (template);
  if (fd == -1)
    return NULL;

  /* Write fuzzer data as CRL content */
  ssize_t written = write (fd, data, size);
  close (fd);

  if (written != (ssize_t)size)
    {
      unlink (template);
      return NULL;
    }

  return strdup (template);
}

/* Create temporary directory with CRL files */
static char *
create_temp_crl_dir (const uint8_t *data, size_t size)
{
  char template[] = "/tmp/fuzz_crl_dir_XXXXXX";
  char *dir_path = mkdtemp (template);
  if (!dir_path)
    return NULL;

  /* Create multiple CRL files with different data slices */
  size_t num_files = (size / 100) + 1; /* At least 1 file */
  if (num_files > 10)
    num_files = 10; /* Limit to prevent too many files */

  for (size_t i = 0; i < num_files; i++)
    {
      char filename[256];
      snprintf (filename, sizeof (filename), "%s/crl_%zu.pem", dir_path, i);

      FILE *f = fopen (filename, "wb");
      if (f)
        {
          size_t start = (i * size) / num_files;
          size_t end = ((i + 1) * size) / num_files;
          if (end > size)
            end = size;

          fwrite (data + start, 1, end - start, f);
          fclose (f);
        }
    }

  return strdup (dir_path);
}

/* Clean up temporary files/directories */
static void
cleanup_temp_path (char *path)
{
  if (!path)
    return;

  /* Try to remove as file first, then as directory */
  if (unlink (path) != 0)
    {
      /* If unlink failed, try removing as directory */
      char cmd[1024];
      snprintf (cmd, sizeof (cmd), "rm -rf '%s'", path);
      system (cmd);
    }

  free (path);
}

/* Fuzz CRL operations on a TLS context */
static void
fuzz_crl_operations (SocketTLSContext_T ctx, const uint8_t *data, size_t size)
{
  if (size < 1)
    return;

  uint8_t op = data[0] % CRL_OP_COUNT;
  const uint8_t *op_data = data + 1;
  size_t op_size = size - 1;

  /* Must be volatile since modified in TRY block and used in FINALLY after
   * potential longjmp */
  char *volatile temp_path = NULL;

  TRY
  {
    switch (op)
      {
      case CRL_OP_LOAD_FILE:
        if (op_size > 0)
          {
            temp_path = create_temp_crl_file (op_data, op_size);
            if (temp_path)
              {
                SocketTLSContext_load_crl (ctx, temp_path);
              }
          }
        break;

      case CRL_OP_LOAD_DIR:
        if (op_size > 0)
          {
            temp_path = create_temp_crl_dir (op_data, op_size);
            if (temp_path)
              {
                SocketTLSContext_load_crl (ctx, temp_path);
              }
          }
        break;

      case CRL_OP_REFRESH:
        if (op_size > 0)
          {
            temp_path = create_temp_crl_file (op_data, op_size);
            if (temp_path)
              {
                SocketTLSContext_refresh_crl (ctx, temp_path);
              }
          }
        break;

      case CRL_OP_RELOAD:
        if (op_size > 0)
          {
            temp_path = create_temp_crl_file (op_data, op_size);
            if (temp_path)
              {
                SocketTLSContext_reload_crl (ctx, temp_path);
              }
          }
        break;

      case CRL_OP_SET_AUTO_REFRESH:
        if (op_size >= sizeof (long))
          {
            long interval = *(const long *)op_data;
            temp_path = create_temp_crl_file (op_data + sizeof (long),
                                              op_size - sizeof (long));
            if (temp_path)
              {
                SocketTLSContext_set_crl_auto_refresh (
                    ctx, temp_path, interval, mock_crl_callback, NULL);
              }
          }
        break;

      case CRL_OP_CANCEL_AUTO_REFRESH:
        SocketTLSContext_cancel_crl_auto_refresh (ctx);
        break;

      case CRL_OP_CHECK_REFRESH:
        SocketTLSContext_crl_check_refresh (ctx);
        break;

      case CRL_OP_GET_NEXT_REFRESH:
        SocketTLSContext_crl_next_refresh_ms (ctx);
        break;

      case CRL_OP_LOAD_MULTIPLE:
        /* Load multiple CRLs to test accumulation */
        for (size_t i = 0; i < 3 && op_size > 10; i++)
          {
            size_t chunk_size = op_size / (3 - i);
            temp_path = create_temp_crl_file (op_data, chunk_size);
            if (temp_path)
              {
                SocketTLSContext_load_crl (ctx, temp_path);
                cleanup_temp_path ((char *)temp_path);
                temp_path = NULL;
              }
            op_data += chunk_size;
            op_size -= chunk_size;
          }
        break;

      case CRL_OP_LOAD_OVERSIZED:
        /* Test file size limit enforcement - should fail gracefully */
        {
          char template[] = "/tmp/fuzz_crl_big_XXXXXX";
          int fd = mkstemp (template);
          if (fd != -1)
            {
              /* Write just over the limit to test rejection */
              size_t oversize = SOCKET_TLS_MAX_CRL_SIZE + 1;
              void *zeros = calloc (1, 4096); /* Write in chunks */
              if (zeros)
                {
                  for (size_t written = 0;
                       written < oversize
                       && written < SOCKET_TLS_MAX_CRL_SIZE + 4096;
                       written += 4096)
                    {
                      write (fd, zeros, 4096);
                    }
                  free (zeros);
                }
              close (fd);
              temp_path = strdup (template);
              if (temp_path)
                {
                  SocketTLSContext_load_crl (ctx, temp_path);
                }
            }
        }
        break;

      case CRL_OP_LOAD_SYMLINK:
        /* Test symlink handling - create symlink to CRL file */
        if (op_size > 0)
          {
            char target[] = "/tmp/fuzz_crl_target_XXXXXX";
            char link_path[] = "/tmp/fuzz_crl_link_XXXXXX";
            int fd = mkstemp (target);
            if (fd != -1)
              {
                write (fd, op_data, op_size);
                close (fd);

                int ld = mkstemp (link_path);
                if (ld != -1)
                  {
                    close (ld);
                    unlink (link_path);
                    if (symlink (target, link_path) == 0)
                      {
                        SocketTLSContext_load_crl (ctx, link_path);
                        unlink (link_path);
                      }
                  }
                unlink (target);
              }
          }
        break;

      case CRL_OP_INTERVAL_BOUNDARY:
        /* Test interval boundary conditions */
        if (op_size >= 1)
          {
            temp_path = create_temp_crl_file (op_data, op_size);
            if (temp_path)
              {
                /* Test various interval values */
                long intervals[] = { 0,
                                     -1,
                                     59,
                                     60,
                                     61,
                                     3600,
                                     SOCKET_TLS_CRL_MAX_REFRESH_INTERVAL,
                                     SOCKET_TLS_CRL_MAX_REFRESH_INTERVAL + 1,
                                     LONG_MAX };
                size_t idx
                    = op_data[0] % (sizeof (intervals) / sizeof (intervals[0]));
                SocketTLSContext_set_crl_auto_refresh (
                    ctx, temp_path, intervals[idx], mock_crl_callback, NULL);
              }
          }
        break;
      }
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected - CRL operations may fail with fuzzer data */
  }
  FINALLY
  {
    /* Guarantee cleanup regardless of exception path.
     * Cast away volatile since cleanup_temp_path doesn't modify the pointer
     * value in a way that matters for control flow. */
    cleanup_temp_path ((char *)temp_path);
  }
  END_TRY;
}

/* Main fuzzing entry point */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  /* Initialize OpenSSL if not already done */
  SSL_library_init ();
  SSL_load_error_strings ();
  ERR_load_crypto_strings ();

  /* Create TLS context for fuzzing */
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    /* Try client context first */
    ctx = SocketTLSContext_new_client (NULL);

    if (!ctx)
      {
        /* Fallback to custom config context */
        SocketTLSConfig_T config;
        SocketTLS_config_defaults (&config);
        ctx = SocketTLSContext_new (&config);
      }

    if (ctx)
      {
        /* Run CRL fuzzing operations */
        fuzz_crl_operations (ctx, data, size);

        /* Clean shutdown */
        SocketTLSContext_free (&ctx);
      }
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Context creation may fail - that's OK for fuzzing */
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;

  /* Clean up OpenSSL errors */
  ERR_clear_error ();

  return 0;
}

#endif /* SOCKET_HAS_TLS */
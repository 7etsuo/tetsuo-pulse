/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_tls_error.c - Fuzzer for OpenSSL Error Formatting (Section 7.2)
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - ssl_format_openssl_error_to_buf() - OpenSSL error formatting
 * - ctx_raise_openssl_error() - Error raising with OpenSSL details
 * - ERR_get_error() / ERR_error_string_n() usage patterns
 * - ERR_clear_error() proper cleanup
 * - Buffer size handling (SOCKET_SSL_OPENSSL_ERRSTR_BUFSIZE = 256)
 *
 * Security Focus:
 * - Buffer overflow prevention
 * - Error queue exhaustion
 * - Thread-local storage handling
 * - Format string safety
 * - Memory safety with edge case buffer sizes
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON -DENABLE_TLS=ON && make fuzz_tls_error
 * Run:   ./fuzz_tls_error corpus/tls_error/ -fork=16 -max_len=4096
 */

#if SOCKET_HAS_TLS

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tls/SocketSSL-internal.h"
#include "tls/SocketTLSConfig.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

/* Operation codes for error formatting fuzzing */
enum ErrorOp
{
  ERR_OP_FORMAT_NORMAL = 0,
  ERR_OP_FORMAT_NULL_CONTEXT,
  ERR_OP_FORMAT_EMPTY_CONTEXT,
  ERR_OP_FORMAT_SMALL_BUF,
  ERR_OP_FORMAT_ZERO_BUF,
  ERR_OP_FORMAT_NULL_BUF,
  ERR_OP_FORMAT_LARGE_CONTEXT,
  ERR_OP_PUSH_MULTIPLE_ERRORS,
  ERR_OP_NO_ERROR_QUEUED,
  ERR_OP_VERIFY_BUFFER_SIZE,
  ERR_OP_CLEAR_ERROR_CHECK,
  ERR_OP_COUNT
};

/* Push a synthetic OpenSSL error to the queue */
static void
push_synthetic_error (void)
{
  /* Push a synthetic SSL error to the queue using OpenSSL functions.
   * ERR_put_error is deprecated in OpenSSL 3.0 but still works.
   * We use ERR_raise_data for OpenSSL 3.0+ compatibility. */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  ERR_raise_data (ERR_LIB_SSL, SSL_R_CERTIFICATE_VERIFY_FAILED,
                  "synthetic fuzz error");
#else
  ERR_put_error (ERR_LIB_SSL, SSL_F_SSL_CTX_USE_CERTIFICATE,
                 SSL_R_CERTIFICATE_VERIFY_FAILED, __FILE__, __LINE__);
#endif
}

/* Push multiple errors to test queue handling */
static void
push_multiple_errors (int count)
{
  for (int i = 0; i < count && i < 20; i++)
    {
      push_synthetic_error ();
    }
}

/* Compile-time verification of buffer size constants */
static_assert (SOCKET_SSL_OPENSSL_ERRSTR_BUFSIZE == 256,
               "SOCKET_SSL_OPENSSL_ERRSTR_BUFSIZE must be 256");
static_assert (SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE == 256,
               "SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE must be 256");

/* Verify buffer size constant is correct at runtime */
static void
verify_buffer_size_constant (void)
{
  /* Verify buffer is sufficient for typical OpenSSL error strings.
   * OpenSSL error format: error:[hex]:[lib]:[func]:[reason]
   * Typical length: ~80-120 characters
   * Maximum observed: ~200 characters */
  char test_buf[SOCKET_SSL_OPENSSL_ERRSTR_BUFSIZE];
  push_synthetic_error ();
  unsigned long err = ERR_get_error ();
  if (err != 0)
    {
      ERR_error_string_n (err, test_buf, sizeof (test_buf));
      /* Verify string is null-terminated and within bounds */
      assert (strlen (test_buf) < sizeof (test_buf));
    }
  ERR_clear_error ();
}

/* Test ssl_format_openssl_error_to_buf with normal parameters */
static void
fuzz_format_normal (const uint8_t *data, size_t size)
{
  if (size == 0 || size > 256)
    return;

  /* Create null-terminated context string from fuzzer input */
  char *context = malloc (size + 1);
  if (!context)
    return;
  memcpy (context, data, size);
  context[size] = '\0';

  /* Test with error queued */
  push_synthetic_error ();
  char buf[512];
  ssl_format_openssl_error_to_buf (context, buf, sizeof (buf));

  /* Verify output is null-terminated */
  assert (strlen (buf) < sizeof (buf));

  /* Verify error queue was cleared */
  assert (ERR_peek_error () == 0);

  free (context);
}

/* Test with NULL context */
static void
fuzz_format_null_context (void)
{
  push_synthetic_error ();
  char buf[256];
  ssl_format_openssl_error_to_buf (NULL, buf, sizeof (buf));

  /* Should still produce valid output */
  assert (strlen (buf) < sizeof (buf));
  assert (ERR_peek_error () == 0);
}

/* Test with empty context */
static void
fuzz_format_empty_context (void)
{
  push_synthetic_error ();
  char buf[256];
  ssl_format_openssl_error_to_buf ("", buf, sizeof (buf));

  assert (strlen (buf) < sizeof (buf));
  assert (ERR_peek_error () == 0);
}

/* Test with small buffer sizes */
static void
fuzz_format_small_buf (const uint8_t *data, size_t size)
{
  if (size == 0)
    return;

  /* Use first byte to determine buffer size (1-255) */
  size_t buf_size = (data[0] % 254) + 1;
  char *buf = malloc (buf_size);
  if (!buf)
    return;

  push_synthetic_error ();
  ssl_format_openssl_error_to_buf ("test context", buf, buf_size);

  /* Verify output is null-terminated and within bounds */
  if (buf_size > 0)
    {
      assert (strlen (buf) < buf_size);
    }
  assert (ERR_peek_error () == 0);

  free (buf);
}

/* Test with zero buffer size */
static void
fuzz_format_zero_buf (void)
{
  push_synthetic_error ();
  char buf[1] = { 'X' };

  /* Zero size should not write to buffer */
  ssl_format_openssl_error_to_buf ("test", buf, 0);

  /* Buffer should be unchanged */
  assert (buf[0] == 'X');
  /* Error queue should still be cleared */
  assert (ERR_peek_error () == 0);
}

/* Test with NULL buffer */
static void
fuzz_format_null_buf (void)
{
  push_synthetic_error ();

  /* NULL buffer should not crash */
  ssl_format_openssl_error_to_buf ("test", NULL, 256);

  /* Error queue should be cleared even with NULL buffer */
  assert (ERR_peek_error () == 0);
}

/* Test with large context string */
static void
fuzz_format_large_context (const uint8_t *data, size_t size)
{
  if (size < 2)
    return;

  /* Create large context string (up to 4KB) */
  size_t context_len = ((data[0] << 8) | data[1]) % 4096;
  if (context_len == 0)
    context_len = 1;

  char *context = malloc (context_len + 1);
  if (!context)
    return;

  /* Fill with pattern from fuzzer data */
  for (size_t i = 0; i < context_len; i++)
    {
      context[i] = (data[(i + 2) % size] % 95) + 32; /* Printable ASCII */
    }
  context[context_len] = '\0';

  push_synthetic_error ();
  char buf[512];
  ssl_format_openssl_error_to_buf (context, buf, sizeof (buf));

  /* Verify truncation happened correctly */
  assert (strlen (buf) < sizeof (buf));
  assert (ERR_peek_error () == 0);

  free (context);
}

/* Test multiple errors in queue */
static void
fuzz_push_multiple_errors (const uint8_t *data, size_t size)
{
  if (size == 0)
    return;

  /* Push multiple errors based on first byte */
  int count = (data[0] % 10) + 1;
  push_multiple_errors (count);

  char buf[512];
  ssl_format_openssl_error_to_buf ("multiple errors", buf, sizeof (buf));

  /* Only first error should be formatted, but all should be cleared */
  assert (strlen (buf) < sizeof (buf));
  assert (ERR_peek_error () == 0);
}

/* Test with no error in queue */
static void
fuzz_no_error_queued (void)
{
  /* Ensure queue is empty */
  ERR_clear_error ();

  char buf[256];
  ssl_format_openssl_error_to_buf ("no error test", buf, sizeof (buf));

  /* Should produce "Unknown error" message */
  assert (strlen (buf) < sizeof (buf));
  assert (strstr (buf, "no error test") != NULL);
  assert (ERR_peek_error () == 0);
}

/* Test error clear verification */
static void
fuzz_clear_error_check (void)
{
  /* Push many errors */
  for (int i = 0; i < 50; i++)
    {
      push_synthetic_error ();
    }

  /* Verify errors are queued */
  assert (ERR_peek_error () != 0);

  char buf[256];
  ssl_format_openssl_error_to_buf ("clear test", buf, sizeof (buf));

  /* ALL errors should be cleared, not just the first */
  assert (ERR_peek_error () == 0);
}

/* Main fuzzer entry point */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size == 0)
    return 0;

  /* Use first byte to select operation */
  enum ErrorOp op = data[0] % ERR_OP_COUNT;
  const uint8_t *remaining = data + 1;
  size_t remaining_size = size - 1;

  switch (op)
    {
    case ERR_OP_FORMAT_NORMAL:
      fuzz_format_normal (remaining, remaining_size);
      break;

    case ERR_OP_FORMAT_NULL_CONTEXT:
      fuzz_format_null_context ();
      break;

    case ERR_OP_FORMAT_EMPTY_CONTEXT:
      fuzz_format_empty_context ();
      break;

    case ERR_OP_FORMAT_SMALL_BUF:
      fuzz_format_small_buf (remaining, remaining_size);
      break;

    case ERR_OP_FORMAT_ZERO_BUF:
      fuzz_format_zero_buf ();
      break;

    case ERR_OP_FORMAT_NULL_BUF:
      fuzz_format_null_buf ();
      break;

    case ERR_OP_FORMAT_LARGE_CONTEXT:
      fuzz_format_large_context (remaining, remaining_size);
      break;

    case ERR_OP_PUSH_MULTIPLE_ERRORS:
      fuzz_push_multiple_errors (remaining, remaining_size);
      break;

    case ERR_OP_NO_ERROR_QUEUED:
      fuzz_no_error_queued ();
      break;

    case ERR_OP_VERIFY_BUFFER_SIZE:
      verify_buffer_size_constant ();
      break;

    case ERR_OP_CLEAR_ERROR_CHECK:
      fuzz_clear_error_check ();
      break;

    default:
      break;
    }

  /* Always ensure error queue is clean at end */
  ERR_clear_error ();
  return 0;
}

#else /* !SOCKET_HAS_TLS */

/* Stub when TLS is disabled */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0;
}

#endif /* SOCKET_HAS_TLS */

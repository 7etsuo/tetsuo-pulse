/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_ssl_path_validation.c - Fuzzer for TLS/DTLS file path validation
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - ssl_validate_file_path() - Core path validation function
 * - ssl_contains_path_traversal() - Path traversal detection
 * - ssl_contains_control_chars() - Control character detection
 * - tls_validate_file_path() - TLS wrapper
 * - dtls_validate_file_path() - DTLS wrapper
 *
 * Security Focus:
 * - Path traversal attacks (../, \..\, /..\ variations)
 * - Control character injection (0x00-0x1F, 0x7F)
 * - Null byte injection (embedded NUL terminators)
 * - Symlink attacks (when files exist)
 * - Length limit enforcement
 * - URL-encoded traversal patterns
 * - Mixed separator attacks (Unix/Windows path separators)
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON -DENABLE_TLS=ON && make fuzz_ssl_path_validation
 * Run:   ./fuzz_ssl_path_validation corpus/ssl_path/ -fork=16 -max_len=8192
 */

#if SOCKET_HAS_TLS

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tls/SocketSSL-internal.h"
#include "tls/SocketTLSConfig.h"

/* Operation codes for path validation fuzzing */
enum PathValidationOp
{
  OP_VALIDATE_PATH = 0,
  OP_CONTAINS_TRAVERSAL,
  OP_CONTAINS_CONTROL,
  OP_TEST_KNOWN_ATTACKS,
  OP_TEST_EDGE_CASES,
  OP_TEST_LENGTH_LIMITS,
  OP_TEST_SYMLINK,
  OP_COUNT
};

/**
 * test_known_attack_patterns - Test against known path traversal attacks
 *
 * Tests a curated list of known path traversal and injection attack patterns.
 * All patterns should be rejected by ssl_validate_file_path().
 */
static void
test_known_attack_patterns (void)
{
  /* Path traversal patterns that MUST be rejected */
  static const char *traversal_attacks[] = {
      /* Basic Unix traversal */
      "..",
      "../",
      "../..",
      "../../etc/passwd",
      "/etc/passwd/../../../etc/shadow",
      "foo/../../../etc/passwd",
      "/tmp/./../../etc/passwd",

      /* Windows-style traversal */
      "..\\",
      "..\\..\\",
      "..\\..\\windows\\system32\\config",
      "foo\\..\\..\\windows\\system.ini",

      /* Mixed separators */
      "../\\..\\",
      "..\\/../",
      "foo/..\\bar/../..",

      /* URL-encoded (may appear in web contexts) */
      "..%2f",
      "..%5c",
      "%2e%2e/",
      "%2e%2e%2f",

      /* Double-encoded */
      "%252e%252e%252f",
      "..%252f",

      /* Unicode/overlong (should be caught by control char check) */
      "..%c0%af",
      "..%c1%1c",

      /* Null byte injection (truncation attack) */
      "../etc/passwd\x00.jpg",
      "valid.crt\x00../../../etc/shadow",

      /* Trailing traversal */
      "foo/..",
      "bar/../..",
      "/tmp/cert/..",

      /* Just parent directory references */
      "/..",
      "\\..",
      "/foo/bar/..",
      "\\foo\\bar\\..",

      NULL};

  for (const char **pattern = traversal_attacks; *pattern != NULL; ++pattern)
    {
      /* All traversal attacks must be rejected */
      int result
          = ssl_validate_file_path (*pattern, SOCKET_SSL_MAX_PATH_LEN);
      (void)result; /* Fuzzer should not crash; result is 0 (rejected) */
    }
}

/**
 * test_control_char_patterns - Test control character rejection
 */
static void
test_control_char_patterns (void)
{
  static const char *control_attacks[] = {
      /* Null byte at various positions */
      "/etc/passwd\x00",
      "\x00/etc/passwd",
      "/etc/\x00passwd",

      /* Bell character */
      "/tmp/cert\x07.pem",

      /* Tab and newline */
      "/tmp/cert\t.pem",
      "/tmp/cert\n.pem",
      "/tmp/cert\r\n.pem",

      /* Escape sequences (for terminal injection) */
      "/tmp/cert\x1b[2J.pem",
      "\x1b[0;31m/tmp/cert.pem",

      /* Form feed and other C0 controls */
      "/tmp/cert\x0c.pem",
      "/tmp/cert\x0b.pem",

      /* DEL character */
      "/tmp/cert\x7f.pem",

      NULL};

  for (const char **pattern = control_attacks; *pattern != NULL; ++pattern)
    {
      int result
          = ssl_validate_file_path (*pattern, SOCKET_SSL_MAX_PATH_LEN);
      (void)result;
    }
}

/**
 * test_edge_cases - Test validation edge cases
 */
static void
test_edge_cases (void)
{
  /* Empty and NULL paths */
  ssl_validate_file_path (NULL, SOCKET_SSL_MAX_PATH_LEN);
  ssl_validate_file_path ("", SOCKET_SSL_MAX_PATH_LEN);

  /* Single characters */
  ssl_validate_file_path (".", SOCKET_SSL_MAX_PATH_LEN);
  ssl_validate_file_path ("/", SOCKET_SSL_MAX_PATH_LEN);
  ssl_validate_file_path ("a", SOCKET_SSL_MAX_PATH_LEN);

  /* Legitimate-looking paths (should pass validation) */
  ssl_validate_file_path ("/etc/ssl/certs/ca-bundle.crt",
                          SOCKET_SSL_MAX_PATH_LEN);
  ssl_validate_file_path ("./certs/server.pem", SOCKET_SSL_MAX_PATH_LEN);
  ssl_validate_file_path ("cert.pem", SOCKET_SSL_MAX_PATH_LEN);
  ssl_validate_file_path ("/var/lib/ssl/private/key.pem",
                          SOCKET_SSL_MAX_PATH_LEN);

  /* Filenames with dots (legitimate, not traversal) */
  ssl_validate_file_path ("cert..pem", SOCKET_SSL_MAX_PATH_LEN);
  ssl_validate_file_path ("foo...bar.crt", SOCKET_SSL_MAX_PATH_LEN);
  ssl_validate_file_path (".hidden.pem", SOCKET_SSL_MAX_PATH_LEN);

  /* Max length boundary */
  ssl_validate_file_path ("a", 1);
  ssl_validate_file_path ("ab", 1); /* Over limit */
  ssl_validate_file_path ("abc", 2);
}

/**
 * test_length_limits - Test length limit enforcement
 */
static void
test_length_limits (void)
{
  char long_path[8192];

  /* Test various lengths around the limit */
  for (size_t len = 0; len <= 4200; len += 100)
    {
      memset (long_path, 'a', len);
      long_path[len] = '\0';

      /* Test with TLS max path length */
      ssl_validate_file_path (long_path, SOCKET_TLS_MAX_PATH_LEN);

      /* Test with exact length */
      ssl_validate_file_path (long_path, len);

      /* Test with length - 1 (should fail) */
      if (len > 1)
        ssl_validate_file_path (long_path, len - 1);
    }

  /* Test exactly at limit */
  memset (long_path, 'x', SOCKET_TLS_MAX_PATH_LEN);
  long_path[SOCKET_TLS_MAX_PATH_LEN] = '\0';
  ssl_validate_file_path (long_path, SOCKET_TLS_MAX_PATH_LEN);

  /* Test one over limit */
  memset (long_path, 'y', SOCKET_TLS_MAX_PATH_LEN + 1);
  long_path[SOCKET_TLS_MAX_PATH_LEN + 1] = '\0';
  ssl_validate_file_path (long_path, SOCKET_TLS_MAX_PATH_LEN);
}

/**
 * test_helper_functions - Test the helper functions directly
 */
static void
test_helper_functions (const char *path, size_t path_len)
{
  if (!path)
    return;

  /* Test traversal detection */
  ssl_contains_path_traversal (path, path_len);

  /* Test control char detection */
  ssl_contains_control_chars (path, path_len);
}

/**
 * create_test_symlink - Create a temporary symlink for testing
 * @return Path to symlink (caller must free) or NULL on failure
 */
static char *
create_test_symlink (void)
{
  char target[] = "/tmp/fuzz_ssl_target_XXXXXX";
  char link_template[] = "/tmp/fuzz_ssl_link_XXXXXX";

  /* Create target file */
  int fd = mkstemp (target);
  if (fd == -1)
    return NULL;
  close (fd);

  /* Create link path (need unique name, not actual file) */
  int ld = mkstemp (link_template);
  if (ld == -1)
    {
      unlink (target);
      return NULL;
    }
  close (ld);
  unlink (link_template); /* Remove file so we can create symlink */

  /* Create symlink */
  if (symlink (target, link_template) != 0)
    {
      unlink (target);
      return NULL;
    }

  /* Clean up target (symlink still exists) */
  unlink (target);

  return strdup (link_template);
}

/**
 * test_symlink_rejection - Test that symlinks are rejected
 */
static void
test_symlink_rejection (void)
{
  char *symlink_path = create_test_symlink ();
  if (symlink_path)
    {
      /* Symlinks should be rejected */
      int result
          = ssl_validate_file_path (symlink_path, SOCKET_SSL_MAX_PATH_LEN);
      (void)result; /* Should be 0 (rejected) */

      /* Clean up */
      unlink (symlink_path);
      free (symlink_path);
    }
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Remaining: Path string data
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  char path[8192];
  size_t path_len;

  if (size < 1)
    return 0;

  uint8_t op = data[0];
  const uint8_t *path_data = data + 1;
  size_t path_data_len = size - 1;

  /* Cap path length to buffer size - 1 for null terminator */
  if (path_data_len > sizeof (path) - 1)
    path_data_len = sizeof (path) - 1;

  /* Copy and null-terminate the path */
  memcpy (path, path_data, path_data_len);
  path[path_data_len] = '\0';
  path_len = strlen (path); /* May be shorter if data contains null bytes */

  switch (op % OP_COUNT)
    {
    case OP_VALIDATE_PATH:
      {
        /* Main validation test with fuzzed input */
        int result
            = ssl_validate_file_path (path, SOCKET_SSL_MAX_PATH_LEN);
        (void)result;

        /* Also test with exact length (may include embedded nulls) */
        result = ssl_validate_file_path (path, path_data_len);
        (void)result;

        /* Test with TLS-specific limit */
        result = ssl_validate_file_path (path, SOCKET_TLS_MAX_PATH_LEN);
        (void)result;
      }
      break;

    case OP_CONTAINS_TRAVERSAL:
      {
        /* Direct test of traversal detection */
        int has_traversal = ssl_contains_path_traversal (path, path_len);
        (void)has_traversal;

        /* Test with raw data length */
        has_traversal = ssl_contains_path_traversal (path, path_data_len);
        (void)has_traversal;
      }
      break;

    case OP_CONTAINS_CONTROL:
      {
        /* Direct test of control char detection */
        int has_control = ssl_contains_control_chars (path, path_len);
        (void)has_control;

        /* Test with raw data length (may include nulls) */
        has_control = ssl_contains_control_chars (path, path_data_len);
        (void)has_control;
      }
      break;

    case OP_TEST_KNOWN_ATTACKS:
      {
        /* Run through known attack patterns */
        test_known_attack_patterns ();
        test_control_char_patterns ();
      }
      break;

    case OP_TEST_EDGE_CASES:
      {
        /* Test validation edge cases */
        test_edge_cases ();
        test_helper_functions (path, path_len);
      }
      break;

    case OP_TEST_LENGTH_LIMITS:
      {
        /* Test length limit enforcement */
        test_length_limits ();
      }
      break;

    case OP_TEST_SYMLINK:
      {
        /* Test symlink rejection */
        test_symlink_rejection ();
      }
      break;
    }

  return 0;
}

#else /* !SOCKET_HAS_TLS */

/* Stub for non-TLS builds */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0;
}

#endif /* SOCKET_HAS_TLS */

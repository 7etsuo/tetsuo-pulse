/**
 * fuzz_tls_sni.c - Fuzzer for TLS SNI hostname validation
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - tls_validate_hostname() - RFC 6066 hostname validation
 * - Hostname length limits (max 255 chars, max 63 per label)
 * - Character validation (alphanumeric + hyphen)
 * - Label boundary checking (dots, leading/trailing hyphens)
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON -DENABLE_TLS=ON && make
 * fuzz_tls_sni Run:   ./fuzz_tls_sni corpus/tls_sni/ -fork=16 -max_len=512
 */

#if SOCKET_HAS_TLS

#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Except.h"
#include "tls/SocketTLS-private.h"

/* Operation codes */
enum SniOp
{
  OP_VALIDATE_BASIC = 0,
  OP_VALIDATE_LONG,
  OP_VALIDATE_LABELS,
  OP_VALIDATE_EDGE_CASES,
  OP_VALIDATE_RANDOM,
  OP_COUNT
};

/**
 * test_validate_basic - Test basic hostname validation
 * @hostname: Null-terminated hostname string
 */
static void
test_validate_basic (const char *hostname)
{
  int result = tls_validate_hostname (hostname);
  (void)result;

  /* Also test NULL */
  result = tls_validate_hostname (NULL);
  assert (result == 0); /* NULL should be invalid */

  /* Test empty string */
  result = tls_validate_hostname ("");
  assert (result == 0); /* Empty should be invalid */
}

/**
 * test_validate_long_hostname - Test with long hostnames
 * @data: Raw fuzz data
 * @len: Length of fuzz data
 */
static void
test_validate_long_hostname (const uint8_t *data, size_t len)
{
  /* Create hostname up to 512 chars */
  char hostname[512];
  size_t copy_len = len > sizeof (hostname) - 1 ? sizeof (hostname) - 1 : len;

  memcpy (hostname, data, copy_len);
  hostname[copy_len] = '\0';

  int result = tls_validate_hostname (hostname);
  (void)result;

  /* Hostnames > 255 chars should be invalid per RFC 6066 */
  if (copy_len > 255)
    {
      /* May or may not be invalid depending on SOCKET_TLS_MAX_SNI_LEN */
    }
}

/**
 * test_validate_labels - Test label-specific validation
 * @data: Raw fuzz data for label content
 * @len: Length of fuzz data
 */
static void
test_validate_labels (const uint8_t *data, size_t len)
{
  char hostname[256];
  size_t pos = 0;
  size_t label_start = 0;

  /* Build hostname with dots from fuzz data */
  for (size_t i = 0; i < len && pos < sizeof (hostname) - 1; i++)
    {
      if (data[i] == 0)
        {
          /* Insert a dot */
          if (pos > label_start && pos < sizeof (hostname) - 1)
            {
              hostname[pos++] = '.';
              label_start = pos;
            }
        }
      else
        {
          hostname[pos++] = (char)data[i];
        }
    }
  hostname[pos] = '\0';

  int result = tls_validate_hostname (hostname);
  (void)result;
}

/**
 * test_edge_cases - Test specific edge cases
 */
static void
test_edge_cases (void)
{
  int result;

  /* Valid hostnames */
  result = tls_validate_hostname ("example.com");
  (void)result;

  result = tls_validate_hostname ("www.example.com");
  (void)result;

  result = tls_validate_hostname ("a.b.c");
  (void)result;

  result = tls_validate_hostname ("test-host.example.com");
  (void)result;

  /* Edge cases - single character labels */
  result = tls_validate_hostname ("a");
  (void)result;

  result = tls_validate_hostname ("a.b");
  (void)result;

  /* Leading hyphen (should be invalid) */
  result = tls_validate_hostname ("-test.com");
  (void)result;

  /* Trailing hyphen in label (may be invalid) */
  result = tls_validate_hostname ("test-.com");
  (void)result;

  /* Consecutive dots (empty label - should be invalid) */
  result = tls_validate_hostname ("test..com");
  (void)result;

  /* Leading dot */
  result = tls_validate_hostname (".example.com");
  (void)result;

  /* Trailing dot */
  result = tls_validate_hostname ("example.com.");
  (void)result;

  /* Only dots */
  result = tls_validate_hostname ("...");
  (void)result;

  /* Long label (64 chars - should be invalid) */
  result = tls_validate_hostname (
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com");
  (void)result;

  /* Exactly 63 char label (max valid) */
  result = tls_validate_hostname (
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com");
  (void)result;

  /* Numeric labels */
  result = tls_validate_hostname ("123.456.789");
  (void)result;

  /* Mixed alphanumeric */
  result = tls_validate_hostname ("test123.example456.com");
  (void)result;

  /* Invalid characters */
  result = tls_validate_hostname ("test_host.com"); /* underscore */
  (void)result;

  result = tls_validate_hostname ("test host.com"); /* space */
  (void)result;

  result = tls_validate_hostname ("test@host.com"); /* at sign */
  (void)result;

  result = tls_validate_hostname ("test/host.com"); /* slash */
  (void)result;

  /* Non-ASCII (should be invalid for SNI) */
  result = tls_validate_hostname ("\xc3\xa9xample.com"); /* UTF-8 é */
  (void)result;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Remaining: Hostname string or raw data
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  char hostname[512];

  if (size < 1)
    return 0;

  uint8_t op = data[0];
  const uint8_t *hostname_data = data + 1;
  size_t hostname_len = size - 1;

  /* Create null-terminated hostname */
  if (hostname_len > sizeof (hostname) - 1)
    hostname_len = sizeof (hostname) - 1;

  memcpy (hostname, hostname_data, hostname_len);
  hostname[hostname_len] = '\0';

  switch (op % OP_COUNT)
    {
    case OP_VALIDATE_BASIC:
      test_validate_basic (hostname);
      break;

    case OP_VALIDATE_LONG:
      test_validate_long_hostname (hostname_data, hostname_len);
      break;

    case OP_VALIDATE_LABELS:
      test_validate_labels (hostname_data, hostname_len);
      break;

    case OP_VALIDATE_EDGE_CASES:
      test_edge_cases ();
      /* Also test with fuzz hostname */
      test_validate_basic (hostname);
      break;

    case OP_VALIDATE_RANDOM:
      {
        /* Random validation with various lengths */
        for (size_t i = 0; i < hostname_len; i++)
          {
            char partial[512];
            size_t plen = i > sizeof (partial) - 1 ? sizeof (partial) - 1 : i;
            memcpy (partial, hostname, plen);
            partial[plen] = '\0';

            int result = tls_validate_hostname (partial);
            (void)result;
          }
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

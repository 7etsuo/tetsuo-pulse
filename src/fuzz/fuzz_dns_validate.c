/**
 * fuzz_dns_validate.c - libFuzzer harness for DNS hostname validation
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Hostname label validation (RFC 1123 compliance)
 * - IP address detection (IPv4/IPv6)
 * - Hostname length checks
 * - Label length and character validation
 * - Edge cases: empty labels, consecutive dots, invalid characters
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_dns_validate
 * Run:   ./fuzz_dns_validate corpus/dns/ -fork=16 -max_len=512
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Except.h"
#include "dns/SocketDNS.h"
#include "dns/SocketDNS-private.h"

/* Maximum hostname length per RFC 1035 */
#define MAX_HOSTNAME_LEN 253

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 * @data: Fuzz input data
 * @size: Size of fuzz input
 *
 * Returns: 0 (required by libFuzzer)
 *
 * Tests DNS hostname validation with arbitrary string input.
 * None of these functions should ever crash regardless of input.
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size == 0)
    return 0;

  /* Cap at max hostname length + some margin for testing */
  size_t str_len = size > (MAX_HOSTNAME_LEN + 10) ? (MAX_HOSTNAME_LEN + 10) : size;

  /* Create null-terminated string from fuzz input */
  char hostname[MAX_HOSTNAME_LEN + 16];
  memcpy (hostname, data, str_len);
  hostname[str_len] = '\0';

  /* Test is_ip_address - should never crash */
  bool is_ip = is_ip_address (hostname);
  (void)is_ip;

  /* Test with NULL - should handle gracefully */
  is_ip = is_ip_address (NULL);
  (void)is_ip;

  /* Test validate_hostname_label with length output */
  size_t label_len = 0;
  int valid = validate_hostname_label (hostname, &label_len);
  (void)valid;
  (void)label_len;

  /* Test with NULL length output */
  valid = validate_hostname_label (hostname, NULL);
  (void)valid;

  /* Test validate_hostname */
  valid = validate_hostname (hostname);
  (void)valid;

  /* Test validate_resolve_params with various combinations */
  TRY
  {
    /* Valid port range */
    if (size >= 2)
      {
        int port = ((int)data[0] << 8) | data[1];
        /* Only test valid port range to avoid expected exceptions */
        if (port > 0 && port <= 65535)
          {
            validate_resolve_params (hostname, port);
          }
      }
  }
  EXCEPT (SocketDNS_Failed)
  {
    /* Expected for invalid hostnames */
  }
  END_TRY;

  /* Test with NULL hostname (should be allowed for wildcard bind) */
  TRY
  {
    validate_resolve_params (NULL, 8080);
  }
  EXCEPT (SocketDNS_Failed)
  {
    /* May or may not raise depending on implementation */
  }
  END_TRY;

  /* Test edge cases with specific patterns */

  /* Empty string */
  valid = validate_hostname ("");
  (void)valid;

  /* Single dot */
  valid = validate_hostname (".");
  (void)valid;

  /* Multiple consecutive dots */
  valid = validate_hostname ("..");
  (void)valid;
  valid = validate_hostname ("...");
  (void)valid;

  /* Leading/trailing dots */
  if (str_len > 2)
    {
      char test[MAX_HOSTNAME_LEN + 16];

      /* Leading dot */
      test[0] = '.';
      memcpy (test + 1, hostname, str_len - 1);
      test[str_len] = '\0';
      valid = validate_hostname (test);
      (void)valid;

      /* Trailing dot */
      memcpy (test, hostname, str_len - 1);
      test[str_len - 1] = '.';
      test[str_len] = '\0';
      valid = validate_hostname (test);
      (void)valid;
    }

  /* Test with very long label (should be rejected) */
  char long_label[128];
  memset (long_label, 'a', 100);
  long_label[100] = '\0';
  valid = validate_hostname (long_label);
  (void)valid;

  /* Test with exactly max label length (63 chars) */
  memset (long_label, 'a', 63);
  long_label[63] = '\0';
  valid = validate_hostname (long_label);
  (void)valid;

  /* Test with max+1 label length (64 chars - should fail) */
  memset (long_label, 'a', 64);
  long_label[64] = '\0';
  valid = validate_hostname (long_label);
  (void)valid;

  return 0;
}


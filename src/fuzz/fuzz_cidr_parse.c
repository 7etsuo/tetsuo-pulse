/**
 * fuzz_cidr_parse.c - Fuzzer for CIDR Notation Parsing
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketCommon_cidr_match() - Main CIDR matching function
 * - Internal: socketcommon_parse_cidr(), cidr_parse_prefix()
 * - Internal: cidr_parse_ipv4(), cidr_parse_ipv6()
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_cidr_parse
 * Run:   ./fuzz_cidr_parse corpus/cidr_parse/ -fork=16 -max_len=512
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "socket/SocketCommon.h"

/* Operation codes */
enum CidrOp
{
  CIDR_MATCH_IPV4 = 0,
  CIDR_MATCH_IPV6,
  CIDR_MATCH_MIXED,
  CIDR_PARSE_IP_ONLY,
  CIDR_OP_COUNT
};

/* Maximum string lengths */
#define MAX_IP_STR_LEN 64
#define MAX_CIDR_STR_LEN 64

/**
 * extract_string - Extract null-terminated string from fuzz data
 * @data: Source data
 * @size: Available data size
 * @buf: Output buffer
 * @buf_size: Output buffer size
 *
 * Returns: Number of bytes consumed (including null terminator or limit)
 */
static size_t
extract_string (const uint8_t *data, size_t size, char *buf, size_t buf_size)
{
  size_t i;
  size_t max_len = (size < buf_size - 1) ? size : buf_size - 1;

  for (i = 0; i < max_len; i++)
    {
      if (data[i] == '\0')
        {
          buf[i] = '\0';
          return i + 1;
        }
      buf[i] = (char)data[i];
    }

  buf[i] = '\0';
  return i;
}

/**
 * fuzz_cidr_match_ipv4 - Test CIDR matching with IPv4 bias
 * @data: Fuzz input
 * @size: Input size
 */
static void
fuzz_cidr_match_ipv4 (const uint8_t *data, size_t size)
{
  char ip_str[MAX_IP_STR_LEN];
  char cidr_str[MAX_CIDR_STR_LEN];

  size_t consumed = extract_string (data, size, ip_str, sizeof (ip_str));
  if (consumed >= size)
    return;

  extract_string (data + consumed, size - consumed, cidr_str,
                  sizeof (cidr_str));

  /* Call the CIDR matching function */
  (void)SocketCommon_cidr_match (ip_str, cidr_str);
}

/**
 * fuzz_cidr_match_ipv6 - Test CIDR matching with IPv6 bias
 * @data: Fuzz input
 * @size: Input size
 *
 * Prepends ":" to encourage IPv6-like parsing
 */
static void
fuzz_cidr_match_ipv6 (const uint8_t *data, size_t size)
{
  char ip_str[MAX_IP_STR_LEN];
  char cidr_str[MAX_CIDR_STR_LEN];

  size_t consumed = extract_string (data, size, ip_str, sizeof (ip_str));
  if (consumed >= size)
    return;

  extract_string (data + consumed, size - consumed, cidr_str,
                  sizeof (cidr_str));

  /* Test as-is for IPv6 addresses */
  (void)SocketCommon_cidr_match (ip_str, cidr_str);

  /* Also test with :: prefix if room */
  if (strlen (ip_str) < MAX_IP_STR_LEN - 3)
    {
      char ipv6_str[MAX_IP_STR_LEN];
      snprintf (ipv6_str, sizeof (ipv6_str), "::%s", ip_str);
      (void)SocketCommon_cidr_match (ipv6_str, cidr_str);
    }
}

/**
 * fuzz_cidr_match_mixed - Test CIDR matching with mixed inputs
 * @data: Fuzz input
 * @size: Input size
 *
 * Tests various combinations to trigger edge cases
 */
static void
fuzz_cidr_match_mixed (const uint8_t *data, size_t size)
{
  char ip_str[MAX_IP_STR_LEN];
  char cidr_str[MAX_CIDR_STR_LEN];

  size_t consumed = extract_string (data, size, ip_str, sizeof (ip_str));
  if (consumed >= size)
    return;

  extract_string (data + consumed, size - consumed, cidr_str,
                  sizeof (cidr_str));

  /* Test original combination */
  (void)SocketCommon_cidr_match (ip_str, cidr_str);

  /* Test with swapped arguments (should fail gracefully) */
  (void)SocketCommon_cidr_match (cidr_str, ip_str);

  /* Test IP matching against itself as CIDR /32 or /128 */
  if (strlen (ip_str) < MAX_CIDR_STR_LEN)
    {
      char self_cidr[MAX_CIDR_STR_LEN + 8];
      /* Try as /32 (IPv4) */
      snprintf (self_cidr, sizeof (self_cidr), "%s/32", ip_str);
      (void)SocketCommon_cidr_match (ip_str, self_cidr);

      /* Try as /128 (IPv6) */
      snprintf (self_cidr, sizeof (self_cidr), "%s/128", ip_str);
      (void)SocketCommon_cidr_match (ip_str, self_cidr);
    }
}

/**
 * fuzz_parse_ip_only - Test IP address parsing
 * @data: Fuzz input
 * @size: Input size
 */
static void
fuzz_parse_ip_only (const uint8_t *data, size_t size)
{
  char ip_str[MAX_IP_STR_LEN];

  extract_string (data, size, ip_str, sizeof (ip_str));

  int family;
  (void)SocketCommon_parse_ip (ip_str, &family);
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Bytes 1-N: Null-terminated IP string
 * - Bytes N+1-M: Null-terminated CIDR string
 *
 * Tests CIDR parsing and matching.
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 3)
    return 0;

  uint8_t op = data[0];
  const uint8_t *str_data = data + 1;
  size_t str_size = size - 1;

  switch (op % CIDR_OP_COUNT)
    {
    case CIDR_MATCH_IPV4:
      fuzz_cidr_match_ipv4 (str_data, str_size);
      break;

    case CIDR_MATCH_IPV6:
      fuzz_cidr_match_ipv6 (str_data, str_size);
      break;

    case CIDR_MATCH_MIXED:
      fuzz_cidr_match_mixed (str_data, str_size);
      break;

    case CIDR_PARSE_IP_ONLY:
      fuzz_parse_ip_only (str_data, str_size);
      break;
    }

  return 0;
}


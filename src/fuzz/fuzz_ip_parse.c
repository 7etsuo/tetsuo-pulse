/**
 * fuzz_ip_parse.c - libFuzzer harness for IP address parsing
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketCommon_parse_ip() with arbitrary strings
 * - IPv4/IPv6 address validation edge cases
 * - Buffer handling in address parsing
 * - Port validation functions
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_ip_parse
 * Run:   ./fuzz_ip_parse corpus/ip_parse/ -fork=16 -max_len=512
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Except.h"
#include "socket/SocketCommon.h"

/* Maximum string length to process */
#define MAX_IP_STRING 256

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 * @data: Fuzz input data
 * @size: Size of fuzz input
 *
 * Returns: 0 (required by libFuzzer)
 *
 * Tests IP parsing with arbitrary string input.
 * The parser should never crash regardless of input.
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size == 0)
    return 0;

  /* Cap string length */
  size_t str_len = size > MAX_IP_STRING ? MAX_IP_STRING : size;

  /* Create null-terminated string from fuzz input */
  char ip_str[MAX_IP_STRING + 1];
  memcpy (ip_str, data, str_len);
  ip_str[str_len] = '\0';

  /* Test SocketCommon_parse_ip with family output */
  int family = 0;
  int result = SocketCommon_parse_ip (ip_str, &family);
  (void)result;
  (void)family;

  /* Test with NULL family pointer - should not crash */
  result = SocketCommon_parse_ip (ip_str, NULL);
  (void)result;

  /* Test port validation if we have enough bytes */
  if (size >= 4)
    {
      /* Interpret bytes as port number (signed to test negatives) */
      int32_t port = (int32_t)(((uint32_t)data[0]) | ((uint32_t)data[1] << 8)
                               | ((uint32_t)data[2] << 16)
                               | ((uint32_t)data[3] << 24));

      /* Test port validation - should handle any int value safely */
      TRY
      {
        /* This may raise exception for invalid ports - that's OK */
        SocketCommon_validate_port (port, SocketCommon_Failed);
      }
      EXCEPT (SocketCommon_Failed)
      {
        /* Expected for invalid ports */
      }
      END_TRY;
    }

  /* Test host validation */
  TRY
  {
    SocketCommon_validate_host_not_null (ip_str, SocketCommon_Failed);
  }
  EXCEPT (SocketCommon_Failed)
  {
    /* Should not happen for non-NULL string */
  }
  END_TRY;

  /* Test NULL host validation */
  TRY
  {
    SocketCommon_validate_host_not_null (NULL, SocketCommon_Failed);
  }
  EXCEPT (SocketCommon_Failed)
  {
    /* Expected - NULL host is invalid */
  }
  END_TRY;

  /* Test wildcard normalization */
  const char *normalized = SocketCommon_normalize_wildcard_host (ip_str);
  (void)normalized;

  /* Test known wildcard patterns */
  (void)SocketCommon_normalize_wildcard_host ("0.0.0.0");
  (void)SocketCommon_normalize_wildcard_host ("::");
  (void)SocketCommon_normalize_wildcard_host (NULL);

  return 0;
}


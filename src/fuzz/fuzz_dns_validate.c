/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dns_validate.c - libFuzzer harness for DNS hostname validation
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Hostname validation via public API
 * - IP address detection (IPv4/IPv6)
 * - DNS parameter validation
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_dns_validate
 * Run:   ./fuzz_dns_validate corpus/dns/ -fork=16 -max_len=512
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Except.h"
#include "dns/SocketDNS-private.h"
#include "dns/SocketDNS.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

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
  size_t str_len
      = size > (MAX_HOSTNAME_LEN + 10) ? (MAX_HOSTNAME_LEN + 10) : size;

  /* Create null-terminated string from fuzz input */
  char hostname[MAX_HOSTNAME_LEN + 16];
  memcpy (hostname, data, str_len);
  hostname[str_len] = '\0';

  /* Test socketcommon_is_ip_address - should never crash */
  bool is_ip = socketcommon_is_ip_address (hostname);
  (void)is_ip;

  /* Test with NULL - should handle gracefully */
  is_ip = socketcommon_is_ip_address (NULL);
  (void)is_ip;

  /* Test SocketCommon_validate_hostname via exception handling */
  TRY { SocketCommon_validate_hostname (hostname, SocketDNS_Failed); }
  EXCEPT (SocketDNS_Failed) { /* Expected for invalid hostnames */ }
  END_TRY;

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
  EXCEPT (SocketDNS_Failed) { /* Expected for invalid hostnames */ }
  END_TRY;

  /* Test with NULL hostname (should be allowed for wildcard bind) */
  TRY { validate_resolve_params (NULL, 8080); }
  EXCEPT (SocketDNS_Failed)
  {
    /* May or may not raise depending on implementation */
  }
  END_TRY;

  /* Test SocketCommon_parse_ip - should not crash on arbitrary input */
  int family = 0;
  int result = SocketCommon_parse_ip (hostname, &family);
  (void)result;
  (void)family;

  /* Test with NULL */
  result = SocketCommon_parse_ip (NULL, &family);
  (void)result;

  /* Test with NULL family output */
  result = SocketCommon_parse_ip (hostname, NULL);
  (void)result;

  return 0;
}

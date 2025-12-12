/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dns_inj.c - libFuzzer for DNS Hostname Injection/Validation
 *
 * Fuzzes DNS hostname validation for injection, spoofing attempts.
 * Inputs: Malformed hostnames (long, invalid chars, traversal, injection).
 *
 * Performance Optimization:
 * - Does NOT perform actual DNS resolution (too slow for fuzzing)
 * - Tests hostname validation logic only
 * - No arena/DNS object allocation per invocation
 *
 * Targets:
 * - Hostname format bypass (length >255, invalid labels)
 * - Injection characters (null bytes, control chars)
 * - Path traversal attempts in hostnames
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_dns_inj
 * ./fuzz_dns_inj corpus/dns_inj/ -fork=16 -max_len=1024
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <netdb.h>

#include "core/Except.h"
#include "dns/SocketDNS.h"
#include "dns/SocketDNS-private.h"
#include "socket/SocketCommon.h"
#include "socket/SocketCommon-private.h"

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 1)
    return 0;

  /* Fuzz hostname from data - no actual DNS resolution */
  char hostname[256];
  size_t host_len = (size > 255) ? 255 : size;
  memcpy (hostname, data, host_len);
  hostname[host_len] = '\0';

  /* Test hostname validation - this is fast and doesn't do network I/O */
  TRY { SocketCommon_validate_hostname (hostname, SocketDNS_Failed); }
  EXCEPT (SocketDNS_Failed) { /* Expected on invalid hosts */ }
  END_TRY;

  /* Test IP address detection */
  bool is_ip = socketcommon_is_ip_address (hostname);
  (void)is_ip;

  /* Test IP parsing */
  int family = 0;
  int result = SocketCommon_parse_ip (hostname, &family);
  (void)result;
  (void)family;

  /* Test validate_resolve_params with various ports */
  TRY
  {
    if (size >= 2)
      {
        int port = ((int)data[0] << 8) | data[1];
        if (port > 0 && port <= 65535)
          validate_resolve_params (hostname, port);
      }
  }
  EXCEPT (SocketDNS_Failed) { /* Expected for invalid hostnames */ }
  END_TRY;

  return 0;
}

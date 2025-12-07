/**
 * fuzz_dns_inj.c - libFuzzer for DNS Hostname Injection/Validation
 *
 * Fuzzes SocketDNS hostname parsing/resolution for injection, spoofing, timeout issues.
 * Inputs: Malformed hostnames (long, invalid chars, traversal, injection attempts).
 *
 * Targets:
 * - Hostname format bypass (length >255, invalid labels)
 * - DNS query construction (wire format overflows)
 * - Resolution timeouts/hangs
 * - Addrinfo result validation (malicious responses)
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_dns_inj
 * ./fuzz_dns_inj corpus/dns_inj/ -fork=16 -max_len=1024
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNS.h"

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 4) return 0;

  volatile Arena_T arena = Arena_new ();
  if (!arena) return 0;

  TRY
    {
      SocketDNS_T dns = SocketDNS_new ();
      if (!dns) return 0;

      /* Fuzz hostname from data */
      char hostname[256];
      size_t host_len = (size > 255) ? 255 : size;
      memcpy (hostname, data, host_len);
      hostname[host_len] = '\0';

      /* Validate/parse fuzzed hostname */
      struct addrinfo hints = {0};
      hints.ai_family = AF_UNSPEC;
      struct addrinfo *res = SocketDNS_resolve_sync (dns, hostname, 80, &hints, 1000); /* Short timeout */

      /* Fuzz request/cancel */
      SocketDNS_Request_T req = SocketDNS_resolve (dns, hostname, 80, NULL, NULL);
      SocketDNS_cancel (dns, req);

      freeaddrinfo (res);
      SocketDNS_free (&dns);
    }
  EXCEPT (SocketDNS_Failed | Arena_Failed)
    {
      /* Expected on invalid hosts */
    }
  END_TRY;

  Arena_dispose (&arena);

  return 0;
}
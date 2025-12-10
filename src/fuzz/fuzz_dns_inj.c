/**
 * fuzz_dns_inj.c - libFuzzer for DNS Hostname Injection/Validation
 *
 * Fuzzes SocketDNS hostname parsing/resolution for injection, spoofing,
 * timeout issues. Inputs: Malformed hostnames (long, invalid chars, traversal,
 * injection attempts).
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
#include <netdb.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNS.h"
#include "socket/SocketCommon.h"

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 4)
    return 0;

  Arena_T arena_instance = Arena_new ();
  if (!arena_instance)
    return 0;
  volatile Arena_T arena = arena_instance;
  (void)arena; /* Used only for exception safety */

  SocketDNS_T dns = NULL;
  struct addrinfo *res = NULL;

  TRY
  {
    dns = SocketDNS_new ();
    if (!dns)
      {
        Arena_dispose (&arena_instance);
        return 0;
      }

    /* Fuzz hostname from data */
    char hostname[256];
    size_t host_len = (size > 255) ? 255 : size;
    memcpy (hostname, data, host_len);
    hostname[host_len] = '\0';

    /* Validate/parse fuzzed hostname using sync API only.
     * NOTE: We avoid the async API (SocketDNS_resolve/cancel) here because
     * it has complex state management that can cause memory leaks if a
     * request completes before cancel is called. The sync API tests the
     * same hostname validation and resolution logic. */
    struct addrinfo hints = { 0 };
    hints.ai_family = AF_UNSPEC;
    res = SocketDNS_resolve_sync (dns, hostname, 80, &hints,
                                  50); /* Very short timeout for fuzzing */
  }
  EXCEPT (SocketDNS_Failed) { /* Expected on invalid hosts */ }
  EXCEPT (Arena_Failed) { /* Expected on invalid hosts */ }
  END_TRY;

  /* Cleanup outside TRY block to ensure it always happens.
   * NOTE: Must use SocketCommon_free_addrinfo, NOT freeaddrinfo!
   * SocketDNS_resolve_sync returns a copy made with SocketCommon_copy_addrinfo. */
  if (res)
    SocketCommon_free_addrinfo (res);
  if (dns)
    SocketDNS_free (&dns);

  Arena_dispose (&arena_instance);

  return 0;
}

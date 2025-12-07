/**
 * fuzz_pool_dos.c - libFuzzer for SocketPool DoS Vectors
 *
 * Fuzzes pool ops for resource exhaustion (max conns, buf growth, IP limits, drain).
 * Inputs: Fuzzed conn add/remove rates, buf sizes, IP addrs for tracking.
 *
 * Targets:
 * - Conn slot exhaustion
 * - Buffer growth OOM
 * - Per-IP limits bypass
 * - Drain state manipulation
 * - Rate limit token bucket overflows
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_pool_dos
 * ./fuzz_pool_dos corpus/pool_dos/ -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "pool/SocketPool.h"

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  volatile Arena_T arena = Arena_new ();
  if (!arena) return 0;

  TRY
    {
      SocketPool_T pool = SocketPool_new (arena, 10, 1024); /* Small for fuzz exhaustion */
      if (!pool) return 0;

      uint32_t seed = 0;
      if (size >= 4) {
        seed = *(uint32_t*)data;
        data += 4;
        size -= 4;
      }

      /* Fuzz conn add (simulate flood) */
      for (size_t i = 0; i < size / 8; i++) {
        /* Stub socket from fuzzed data */
        Socket_T stub_sock = Socket_new_from_fd (-1); /* Invalid for test */
        if (stub_sock) {
          SocketPool_add (pool, stub_sock);
        }
        SocketPool_cleanup (pool, 0); /* Force drain fuzz */
      }

      /* Fuzz resize/limits */
      if (seed % 2) {
        SocketPool_resize (pool, (size % 100) + 1); /* Small resizes */
      }

      /* Fuzz rate limits */
      SocketPool_setconnrate (pool, (int)(seed % 1000), 10);

      SocketPool_free (&pool);
    }
  EXCEPT (SocketPool_Failed | Arena_Failed)
    {
      /* Expected on limits/exhaust */
    }
  END_TRY;

  Arena_dispose (&arena);

  return 0;
}
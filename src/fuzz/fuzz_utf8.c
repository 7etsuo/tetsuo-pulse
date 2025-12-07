/**
 * fuzz_utf8.c - libFuzzer for SocketUTF8 Validation
 *
 * Fuzzes UTF8 decoder for security issues (overlong, surrogates, invalid sequences).
 * Used in WS text frames, HTTP headers.
 *
 * Inputs: Fuzzed byte sequences for incremental update/finish.
 *
 * Targets:
 * - Overlong encodings (bypass filters)
 * - Surrogate pairs in UTF8 (encoding confusion)
 * - Truncated multi-byte seq
 * - State machine corruption
 * - Resource exhaustion from long invalid seq
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_utf8
 * ./fuzz_utf8 corpus/utf8/ -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketUTF8.h"

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena_instance = Arena_new ();
  if (!arena_instance) return 0;
  volatile Arena_T arena = arena_instance;
  (void)arena;  /* Used only for exception safety */

  TRY
    {
      SocketUTF8_State state;
      SocketUTF8_init (&state);

      /* Incremental update with fuzzed bytes in chunks */
      size_t i = 0;
      while (i < size) {
        size_t chunk = (size - i > 16) ? 16 : size - i; /* Small chunks for state fuzz */
        SocketUTF8_Result res = SocketUTF8_update (&state, data + i, chunk);
        (void)res; /* Coverage on invalid */
        i += chunk;

        /* Random finish to check incomplete */
        if (i % 5 == 0) {
          SocketUTF8_finish (&state);
          SocketUTF8_init (&state); /* Reset for multi-message fuzz */
        }
      }

      SocketUTF8_finish (&state); /* Final check */
    }
  EXCEPT (SocketUTF8_Failed)
    {
      /* Expected; validates rejection */
    }
  END_TRY;

  Arena_dispose (&arena_instance);

  return 0;
}
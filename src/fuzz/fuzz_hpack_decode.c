/**
 * fuzz_hpack_decode.c - Fuzzing harness for HPACK header block decoding
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Tests HPACK decoder robustness against malformed input.
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHPACK.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * LibFuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketHPACK_Decoder_T decoder = NULL;
  SocketHPACK_Header headers[64];
  size_t header_count;

  /* Skip empty input */
  if (size == 0)
    return 0;

  TRY
  {
    arena = Arena_new ();
    if (arena == NULL)
      goto cleanup;

    /* Create decoder with default config */
    decoder = SocketHPACK_Decoder_new (NULL, arena);
    if (decoder == NULL)
      goto cleanup;

    /* Try to decode the fuzzed input */
    SocketHPACK_Decoder_decode (decoder, data, size, headers, 64, &header_count,
                                arena);

    /* Success or expected error - both are fine */
  }
  EXCEPT (SocketHPACK_Error)
  {
    /* Expected for malformed input */
  }
  FINALLY
  {
  cleanup:
    if (decoder)
      SocketHPACK_Decoder_free (&decoder);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;

  return 0;
}


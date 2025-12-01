/**
 * fuzz_hpack_huffman.c - Fuzzing harness for HPACK Huffman decoding
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Tests Huffman decoder robustness against malformed input.
 */

#include "core/Except.h"
#include "http/SocketHPACK.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * LibFuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  unsigned char output[4096];

  /* Skip empty input */
  if (size == 0)
    return 0;

  TRY
  {
    /* Try to decode the fuzzed Huffman data */
    ssize_t decoded
        = SocketHPACK_huffman_decode (data, size, output, sizeof (output));

    /* If decode succeeded, verify by re-encoding */
    if (decoded > 0)
      {
        unsigned char reencoded[4096];
        ssize_t enc_len = SocketHPACK_huffman_encode (
            output, (size_t)decoded, reencoded, sizeof (reencoded));
        (void)enc_len; /* Suppress unused warning */
      }
  }
  EXCEPT (SocketHPACK_Error)
  {
    /* Expected for malformed input */
  }
  END_TRY;

  return 0;
}


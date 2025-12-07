/**
 * fuzz_hpack.c - libFuzzer for HPACK Header Compression (RFC 7541)
 *
 * Fuzzes SocketHPACK for decompression bombs, table manipulation, integer coding issues.
 *
 * Inputs: Fuzzed HPACK encoded headers (dynamic table updates, Huffman, indices).
 *
 * Targets:
 * - HPACK bomb (excessive expansion)
 * - Invalid integer prefixes/overflow
 * - Huffman decoding attacks (padding, truncated)
 * - Table eviction/size change abuse
 * - Header field validation (name/value bounds)
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_hpack
 * ./fuzz_hpack corpus/hpack/ -fork=16 -max_len=32768
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHPACK.h"

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 1) return 0;

  volatile Arena_T arena = Arena_new ();
  if (!arena) return 0;

  TRY
    {
      SocketHPACK_Decoder_T decoder;
      SocketHPACK_Decoder_init (&decoder, arena, SOCKETHPACK_DEFAULT_MAX_TABLE_SIZE);

      /* Incremental decode fuzzed HPACK data */
      size_t consumed = 0;
      SocketHPACK_Result res = SocketHPACK_Decoder_decode (&decoder, data, size, &consumed);

      /* Loop for multi-block */
      while (res == HPACK_CONTINUE && consumed < size)
        {
          res = SocketHPACK_Decoder_decode (&decoder, data + consumed, size - consumed, &consumed);
        }

      /* Access decoded headers to trigger full processing */
      size_t num_headers;
      const SocketHPACK_Header *headers = SocketHPACK_Decoder_get_headers (&decoder, &num_headers);
      (void)headers; (void)num_headers; /* Fuzz coverage */

      /* Fuzz table size change */
      if (size > 4) {
        uint32_t new_size = *(uint32_t*)data % SOCKETHPACK_MAX_TABLE_SIZE;
        SocketHPACK_Decoder_set_max_table_size (&decoder, new_size);
      }

      SocketHPACK_Decoder_reset (&decoder);
    }
  EXCEPT (SocketHPACK_Failed | Arena_Failed)
    {
      /* Expected on malformed; good for crash detection */
    }
  END_TRY;

  Arena_dispose (&arena);

  return 0;
}
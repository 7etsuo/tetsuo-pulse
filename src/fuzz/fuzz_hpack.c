/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_hpack.c - libFuzzer for HPACK Header Compression (RFC 7541)
 *
 * Fuzzes SocketHPACK for decompression bombs, table manipulation, integer
 * coding issues.
 *
 * Inputs: Fuzzed HPACK encoded headers (dynamic table updates, Huffman,
 * indices).
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

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHPACK.h"

#define MAX_HEADERS 64

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 1)
    return 0;

  Arena_T arena_instance = Arena_new ();
  if (!arena_instance)
    return 0;
  volatile Arena_T arena = arena_instance;
  (void)arena; /* Used only for exception safety */

  TRY
  {
    /* Create decoder with default config */
    SocketHPACK_DecoderConfig cfg;
    SocketHPACK_decoder_config_defaults (&cfg);
    SocketHPACK_Decoder_T decoder
        = SocketHPACK_Decoder_new (&cfg, arena_instance);

    /* Decode fuzzed HPACK data */
    SocketHPACK_Header headers[MAX_HEADERS];
    size_t header_count = 0;
    SocketHPACK_Result res = SocketHPACK_Decoder_decode (decoder,
                                                         data,
                                                         size,
                                                         headers,
                                                         MAX_HEADERS,
                                                         &header_count,
                                                         arena_instance);

    /* Access decoded headers to trigger full processing */
    (void)res;
    for (size_t i = 0; i < header_count; i++)
      {
        (void)headers[i].name;
        (void)headers[i].value;
      }

    /* Fuzz table size change */
    if (size > 4)
      {
        uint32_t new_size = *(uint32_t *)data % SOCKETHPACK_MAX_TABLE_SIZE;
        SocketHPACK_Decoder_set_table_size (decoder, new_size);
      }

    SocketHPACK_Decoder_free (&decoder);
  }
  EXCEPT (SocketHPACK_Error)
  {
    /* Expected on malformed; good for crash detection */
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on malformed; good for crash detection */
  }
  END_TRY;

  Arena_dispose (&arena_instance);

  return 0;
}

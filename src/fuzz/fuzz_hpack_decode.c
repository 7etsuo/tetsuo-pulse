/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_hpack_decode.c - Fuzzing harness for HPACK header block decoding
 *
 * Part of the Socket Library
 *
 * Performance Optimization:
 * - Uses static arena with Arena_clear() for reuse
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

/* Static arena for reuse */
static Arena_T g_arena = NULL;

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void)argc;
  (void)argv;
  g_arena = Arena_new ();
  return 0;
}

/**
 * LibFuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketHPACK_Decoder_T decoder = NULL;
  SocketHPACK_Header headers[32];
  size_t header_count;

  /* Skip empty input */
  if (size == 0)
    return 0;

  /* Skip if arena init failed */
  if (!g_arena)
    return 0;

  /* Clear arena for reuse */
  Arena_clear (g_arena);

  TRY
  {
    /* Create decoder for this decode */
    decoder = SocketHPACK_Decoder_new (NULL, g_arena);
    if (decoder)
      {
        /* Try to decode the fuzzed input */
        SocketHPACK_Decoder_decode (
            decoder, data, size, headers, 32, &header_count, g_arena);
        SocketHPACK_Decoder_free (&decoder);
      }
  }
  EXCEPT (SocketHPACK_Error)
  { /* Expected for malformed input */
  }
  END_TRY;

  return 0;
}

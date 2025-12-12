/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_http2_headers.c - HTTP/2 HPACK Header Fuzzer
 *
 * Part of the Socket Library
 * Fuzzes HPACK encoding/decoding in HTTP/2 context.
 *
 * Performance Optimization:
 * - Uses static arena with Arena_clear() to avoid repeated allocations
 * - Creates new decoder per invocation (HPACK has state that can't be reset)
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHPACK.h"
#include <stdint.h>
#include <string.h>

/* Static arena for reuse */
static Arena_T g_arena = NULL;

/**
 * LLVMFuzzerInitialize - One-time setup for fuzzer
 */
int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void)argc;
  (void)argv;
  g_arena = Arena_new ();
  return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketHPACK_Decoder_T decoder = NULL;
  SocketHPACK_Header headers[64];
  size_t header_count = 0;

  if (size == 0)
    return 0;

  /* Check arena is initialized */
  if (!g_arena)
    {
      g_arena = Arena_new ();
      if (!g_arena)
        return 0;
    }

  /* Clear arena for reuse */
  Arena_clear (g_arena);

  TRY
  {
    /* Create decoder with limits */
    SocketHPACK_DecoderConfig config;
    SocketHPACK_decoder_config_defaults (&config);
    config.max_header_size = 4096;
    config.max_header_list_size = 16384;

    decoder = SocketHPACK_Decoder_new (&config, g_arena);
    if (!decoder)
      return 0;

    /* Try to decode the fuzz input as a header block */
    SocketHPACK_Result result = SocketHPACK_Decoder_decode (
        decoder, data, size, headers, 64, &header_count, g_arena);

    /* Result is informational - all results are valid */
    (void)result;

    /* Cleanup decoder */
    SocketHPACK_Decoder_free (&decoder);
  }
  EXCEPT (SocketHPACK_Error) { /* Expected for malformed input */ }
  EXCEPT (Arena_Failed) { /* Memory exhaustion */ }
  END_TRY;

  return 0;
}

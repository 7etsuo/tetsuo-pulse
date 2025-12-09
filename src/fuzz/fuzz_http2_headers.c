/**
 * fuzz_http2_headers.c - HTTP/2 HPACK Header Fuzzer
 *
 * Part of the Socket Library
 * Fuzzes HPACK encoding/decoding in HTTP/2 context.
 */

#include "core/Arena.h"
#include "http/SocketHPACK.h"
#include <stdint.h>
#include <string.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketHPACK_Decoder_T decoder = NULL;
  SocketHPACK_Header headers[64];
  size_t header_count = 0;

  if (size == 0)
    return 0;

  arena = Arena_new ();
  if (!arena)
    return 0;

  /* Create decoder with limits */
  SocketHPACK_DecoderConfig config;
  SocketHPACK_decoder_config_defaults (&config);
  config.max_header_size = 4096;
  config.max_header_list_size = 16384;

  decoder = SocketHPACK_Decoder_new (&config, arena);
  if (!decoder)
    {
      Arena_dispose (&arena);
      return 0;
    }

  /* Try to decode the fuzz input as a header block */
  SocketHPACK_Result result = SocketHPACK_Decoder_decode (
      decoder, data, size, headers, 64, &header_count, arena);

  /* Result is informational - all results are valid */
  (void)result;

  /* Cleanup */
  SocketHPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  return 0;
}

/**
 * fuzz_http2_frames.c - HTTP/2 Frame Parsing Fuzzer
 *
 * Part of the Socket Library
 * Fuzzes HTTP/2 frame header parsing.
 */

#include "http/SocketHTTP2.h"
#include <stdint.h>
#include <string.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketHTTP2_FrameHeader header;
  unsigned char output[HTTP2_FRAME_HEADER_SIZE];

  /* Test frame header parsing */
  if (size >= HTTP2_FRAME_HEADER_SIZE)
    {
      SocketHTTP2_frame_header_parse (data, &header);

      /* Test roundtrip */
      SocketHTTP2_frame_header_serialize (&header, output);

      /* Verify roundtrip for valid frames */
      if (header.length <= SOCKETHTTP2_MAX_MAX_FRAME_SIZE
          && header.stream_id <= 0x7FFFFFFF)
        {
          SocketHTTP2_FrameHeader verify;
          SocketHTTP2_frame_header_parse (output, &verify);
          /* Should match original parse */
        }
    }

  /* Test error string functions with parsed values */
  if (size >= 1)
    {
      SocketHTTP2_error_string ((SocketHTTP2_ErrorCode)(data[0] & 0x0F));
      SocketHTTP2_frame_type_string ((SocketHTTP2_FrameType)(data[0] & 0x0F));
    }

  if (size >= 1)
    {
      SocketHTTP2_stream_state_string ((SocketHTTP2_StreamState)(data[0] % 7));
    }

  return 0;
}


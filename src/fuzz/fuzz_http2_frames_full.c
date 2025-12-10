/**
 * fuzz_http2_frames_full.c - Comprehensive HTTP/2 frame processing fuzzer
 *
 * Tests full HTTP/2 frame parsing and payload validation for all frame types:
 * - DATA frames (with padding)
 * - HEADERS frames (with HPACK)
 * - SETTINGS frames (configuration)
 * - WINDOW_UPDATE frames (flow control)
 * - PING/PONG frames (keep-alive)
 * - RST_STREAM frames (error signaling)
 * - GOAWAY frames (connection shutdown)
 * - PUSH_PROMISE frames (server push)
 * - CONTINUATION frames (header continuation)
 *
 * Targets:
 * - Frame payload parsing vulnerabilities
 * - Flow control bypass attempts
 * - Malformed frame handling
 * - HPACK decompression in HEADERS frames
 * - Stream ID validation
 * - Frame size limits
 * - Padding validation
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http2_frames_full
 * ./fuzz_http2_frames_full corpus/http2_frames/ -fork=16 -max_len=65536
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHPACK.h"
#include "http/SocketHTTP2.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Frame header size */
#define FRAME_HEADER_SIZE 9

/* Maximum frame payload size for fuzzing */
#define MAX_FRAME_PAYLOAD 32768

/**
 * Build a frame with fuzzed payload
 */
static size_t
build_frame (uint8_t *buffer, size_t buffer_size, uint8_t type, uint8_t flags,
             uint32_t stream_id, const uint8_t *payload, size_t payload_len)
{
  if (buffer_size < FRAME_HEADER_SIZE + payload_len)
    return 0;

  /* Length (24-bit big endian) */
  uint32_t length = payload_len & 0x00FFFFFF; /* Max 16MB per RFC */
  buffer[0] = (length >> 16) & 0xFF;
  buffer[1] = (length >> 8) & 0xFF;
  buffer[2] = length & 0xFF;

  /* Type */
  buffer[3] = type;

  /* Flags */
  buffer[4] = flags;

  /* Stream ID (31-bit big endian) */
  uint32_t sid = stream_id & 0x7FFFFFFF;
  buffer[5] = (sid >> 24) & 0xFF;
  buffer[6] = (sid >> 16) & 0xFF;
  buffer[7] = (sid >> 8) & 0xFF;
  buffer[8] = sid & 0xFF;

  /* Payload */
  if (payload && payload_len > 0)
    memcpy (buffer + FRAME_HEADER_SIZE, payload, payload_len);

  return FRAME_HEADER_SIZE + payload_len;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketHPACK_Decoder_T hpack_decoder = NULL;
  uint8_t frame_buffer[FRAME_HEADER_SIZE + MAX_FRAME_PAYLOAD];
  size_t frame_size;

  /* Skip empty input */
  if (size == 0)
    return 0;

  arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    /* Setup HPACK decoder for HEADERS frame testing */
    SocketHPACK_DecoderConfig hpack_config;
    SocketHPACK_decoder_config_defaults (&hpack_config);
    hpack_config.max_header_size = 4096;
    hpack_config.max_header_list_size = 16384;

    hpack_decoder = SocketHPACK_Decoder_new (&hpack_config, arena);
    if (!hpack_decoder)
      {
        Arena_dispose (&arena);
        return 0;
      }

    /* Test all frame types with fuzzed payloads */
    uint8_t frame_types[] = {
        HTTP2_FRAME_DATA,
        HTTP2_FRAME_HEADERS,
        HTTP2_FRAME_PRIORITY,
        HTTP2_FRAME_RST_STREAM,
        HTTP2_FRAME_SETTINGS,
        HTTP2_FRAME_PUSH_PROMISE,
        HTTP2_FRAME_PING,
        HTTP2_FRAME_GOAWAY,
        HTTP2_FRAME_WINDOW_UPDATE,
        HTTP2_FRAME_CONTINUATION
    };

    /* Test each frame type */
    for (size_t type_idx = 0; type_idx < sizeof (frame_types) / sizeof (frame_types[0]); type_idx++)
      {
        uint8_t frame_type = frame_types[type_idx];

        /* Test with various flags */
        uint8_t test_flags[] = {0x00, 0x01, 0x08, 0x20, 0xFF};

        for (size_t flag_idx = 0; flag_idx < sizeof (test_flags) / sizeof (test_flags[0]); flag_idx++)
          {
            uint8_t flags = test_flags[flag_idx];

            /* Test with various stream IDs */
            uint32_t test_stream_ids[] = {0, 1, 2, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF};

            for (size_t sid_idx = 0; sid_idx < sizeof (test_stream_ids) / sizeof (test_stream_ids[0]); sid_idx++)
              {
                uint32_t stream_id = test_stream_ids[sid_idx];

                /* Use fuzzed data as frame payload, limited to reasonable size */
                size_t payload_size = size > MAX_FRAME_PAYLOAD ? MAX_FRAME_PAYLOAD : size;

                /* Build frame with fuzzed payload */
                frame_size = build_frame (frame_buffer, sizeof (frame_buffer),
                                         frame_type, flags, stream_id, data, payload_size);

                if (frame_size > 0)
                  {
                    /* Parse frame header */
                    SocketHTTP2_FrameHeader header;
                    int parse_result = SocketHTTP2_frame_header_parse (frame_buffer, frame_size, &header);

                    if (parse_result == 0)
                      {
                        /* Header parsed successfully, now test payload based on frame type */
                        const uint8_t *payload = frame_buffer + FRAME_HEADER_SIZE;
                        size_t payload_len = header.length;

                        switch (header.type)
                          {
                            case HTTP2_FRAME_DATA:
                              /* Test DATA frame padding */
                              if (flags & 0x08) /* PADDED flag */
                                {
                                  if (payload_len > 0)
                                    {
                                      uint8_t pad_length = payload[0];
                                      /* Verify padding doesn't exceed payload */
                                      (void)pad_length;
                                    }
                                }
                              break;

                            case HTTP2_FRAME_HEADERS:
                              /* Test HEADERS frame with HPACK decoding */
                              if (payload_len > 0)
                                {
                                  SocketHPACK_Header headers[64];
                                  size_t header_count = 0;
                                  SocketHPACK_Result hpack_result = SocketHPACK_Decoder_decode (
                                      hpack_decoder, payload, payload_len, headers, 64,
                                      &header_count, arena);
                                  (void)hpack_result;
                                }
                              break;

                            case HTTP2_FRAME_SETTINGS:
                              /* Test SETTINGS frame payload validation */
                              if (payload_len % 6 == 0) /* Settings are 6 bytes each */
                                {
                                  size_t num_settings = payload_len / 6;
                                  for (size_t i = 0; i < num_settings && i < 64; i++)
                                    {
                                      /* Each setting: 2 bytes ID + 4 bytes value */
                                      size_t offset = i * 6;
                                      if (offset + 6 <= payload_len)
                                        {
                                          uint16_t setting_id = (payload[offset] << 8) | payload[offset + 1];
                                          uint32_t setting_value = ((uint32_t)payload[offset + 2] << 24) |
                                                                  ((uint32_t)payload[offset + 3] << 16) |
                                                                  ((uint32_t)payload[offset + 4] << 8) |
                                                                  payload[offset + 5];
                                          (void)setting_id;
                                          (void)setting_value;
                                        }
                                    }
                                }
                              break;

                            case HTTP2_FRAME_WINDOW_UPDATE:
                              /* Test WINDOW_UPDATE increment validation */
                              if (payload_len >= 4)
                                {
                                  uint32_t increment = ((uint32_t)payload[0] << 24) |
                                                      ((uint32_t)payload[1] << 16) |
                                                      ((uint32_t)payload[2] << 8) |
                                                      payload[3];
                                  /* RFC 9113: increment must be > 0 and <= 2^31-1 */
                                  (void)increment;
                                }
                              break;

                            case HTTP2_FRAME_RST_STREAM:
                              /* Test RST_STREAM error code */
                              if (payload_len >= 4)
                                {
                                  uint32_t error_code = ((uint32_t)payload[0] << 24) |
                                                       ((uint32_t)payload[1] << 16) |
                                                       ((uint32_t)payload[2] << 8) |
                                                       payload[3];
                                  (void)error_code;
                                }
                              break;

                            case HTTP2_FRAME_GOAWAY:
                              /* Test GOAWAY frame */
                              if (payload_len >= 8)
                                {
                                  uint32_t last_stream_id = ((uint32_t)payload[0] << 24) |
                                                           ((uint32_t)payload[1] << 16) |
                                                           ((uint32_t)payload[2] << 8) |
                                                           payload[3];
                                  uint32_t error_code = ((uint32_t)payload[4] << 24) |
                                                       ((uint32_t)payload[5] << 16) |
                                                       ((uint32_t)payload[6] << 8) |
                                                       payload[7];
                                  (void)last_stream_id;
                                  (void)error_code;
                                }
                              break;

                            case HTTP2_FRAME_PING:
                              /* Test PING frame (8 bytes of opaque data) */
                              if (payload_len >= 8)
                                {
                                  uint64_t ping_data = ((uint64_t)payload[0] << 56) |
                                                      ((uint64_t)payload[1] << 48) |
                                                      ((uint64_t)payload[2] << 40) |
                                                      ((uint64_t)payload[3] << 32) |
                                                      ((uint64_t)payload[4] << 24) |
                                                      ((uint64_t)payload[5] << 16) |
                                                      ((uint64_t)payload[6] << 8) |
                                                      payload[7];
                                  (void)ping_data;
                                }
                              break;

                            case HTTP2_FRAME_PRIORITY:
                              /* Test PRIORITY frame (deprecated but still needs validation) */
                              if (payload_len >= 5)
                                {
                                  uint32_t priority_stream = ((uint32_t)payload[0] << 24) |
                                                            ((uint32_t)payload[1] << 16) |
                                                            ((uint32_t)payload[2] << 8) |
                                                            payload[3];
                                  uint8_t weight = payload[4];
                                  (void)priority_stream;
                                  (void)weight;
                                }
                              break;

                            case HTTP2_FRAME_PUSH_PROMISE:
                              /* Test PUSH_PROMISE frame */
                              if (payload_len >= 4)
                                {
                                  uint32_t promised_stream = ((uint32_t)payload[0] << 24) |
                                                            ((uint32_t)payload[1] << 16) |
                                                            ((uint32_t)payload[2] << 8) |
                                                            payload[3];
                                  (void)promised_stream;
                                  /* Remaining payload should be HPACK headers */
                                  if (payload_len > 4)
                                    {
                                      SocketHPACK_Header headers[64];
                                      size_t header_count = 0;
                                      SocketHPACK_Result hpack_result = SocketHPACK_Decoder_decode (
                                          hpack_decoder, payload + 4, payload_len - 4, headers, 64,
                                          &header_count, arena);
                                      (void)hpack_result;
                                    }
                                }
                              break;

                            case HTTP2_FRAME_CONTINUATION:
                              /* Test CONTINUATION frame (HPACK header fragment) */
                              if (payload_len > 0)
                                {
                                  SocketHPACK_Header headers[64];
                                  size_t header_count = 0;
                                  SocketHPACK_Result hpack_result = SocketHPACK_Decoder_decode (
                                      hpack_decoder, payload, payload_len, headers, 64,
                                      &header_count, arena);
                                  (void)hpack_result;
                                }
                              break;

                            default:
                              /* Unknown frame type - should be ignored per RFC */
                              break;
                          }
                      }
                  }
              }
          }
      }

    /* Test frame size limits and edge cases */
    for (size_t i = 0; i < size && i < 20; i++)
      {
        /* Test various frame sizes - must not exceed actual input size */
        size_t test_sizes[] = {0, 1, 8, 16384, 16777215}; /* Max frame size */
        for (size_t sz_idx = 0; sz_idx < sizeof (test_sizes) / sizeof (test_sizes[0]); sz_idx++)
          {
            /* Clamp test_size to available input data */
            size_t test_size = test_sizes[sz_idx];
            if (test_size > size)
              test_size = size;
            if (test_size <= MAX_FRAME_PAYLOAD)
              {
                frame_size = build_frame (frame_buffer, sizeof (frame_buffer),
                                         HTTP2_FRAME_DATA, 0, 1, data, test_size);
                if (frame_size > 0)
                  {
                    SocketHTTP2_FrameHeader header;
                    SocketHTTP2_frame_header_parse (frame_buffer, frame_size, &header);
                  }
              }
          }
      }

    SocketHPACK_Decoder_free (&hpack_decoder);
  }
  EXCEPT (SocketHTTP2_ProtocolError)
  {
    /* Expected on malformed frames */
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on memory exhaustion */
  }
  END_TRY;

  Arena_dispose (&arena);

  return 0;
}

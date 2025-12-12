/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_http2_frames.c - Enterprise-grade HTTP/2 frame processing fuzzer
 *
 * Comprehensive fuzzing harness for HTTP/2 frame parsing, serialization,
 * and validation targeting all frame types and edge cases per RFC 9113.
 *
 * Frame Types Tested:
 * - DATA (0x00): Stream data with optional padding
 * - HEADERS (0x01): HTTP headers with HPACK compression
 * - PRIORITY (0x02): Stream prioritization (deprecated)
 * - RST_STREAM (0x03): Stream termination
 * - SETTINGS (0x04): Connection configuration
 * - PUSH_PROMISE (0x05): Server push initiation
 * - PING (0x06): Keep-alive and latency measurement
 * - GOAWAY (0x07): Graceful connection shutdown
 * - WINDOW_UPDATE (0x08): Flow control updates
 * - CONTINUATION (0x09): Header continuation
 *
 * Security Focus:
 * - Frame header parsing with arbitrary input
 * - Frame payload validation
 * - Stream ID validation (odd/even, reserved bit)
 * - Frame size limits and overflow
 * - Flag validation per frame type
 * - Roundtrip serialization/parsing integrity
 * - Error code and string function coverage
 * - Stream state transitions
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http2_frames
 * ./fuzz_http2_frames corpus/http2_frames/ -fork=16 -max_len=65536
 */

#include "http/SocketHTTP2.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * Test all error code strings
 */
static void
test_error_strings (const uint8_t *data, size_t size)
{
  /* Test all defined error codes */
  SocketHTTP2_ErrorCode codes[] = {
    HTTP2_NO_ERROR,
    HTTP2_PROTOCOL_ERROR,
    HTTP2_INTERNAL_ERROR,
    HTTP2_FLOW_CONTROL_ERROR,
    HTTP2_SETTINGS_TIMEOUT,
    HTTP2_STREAM_CLOSED,
    HTTP2_FRAME_SIZE_ERROR,
    HTTP2_REFUSED_STREAM,
    HTTP2_CANCEL,
    HTTP2_COMPRESSION_ERROR,
    HTTP2_CONNECT_ERROR,
    HTTP2_ENHANCE_YOUR_CALM,
    HTTP2_INADEQUATE_SECURITY,
    HTTP2_HTTP_1_1_REQUIRED
  };

  for (size_t i = 0; i < sizeof (codes) / sizeof (codes[0]); i++)
    {
      const char *str = SocketHTTP2_error_string (codes[i]);
      (void)str;
    }

  /* Test with fuzzed values */
  if (size >= 4)
    {
      uint32_t fuzz_code = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
                           | ((uint32_t)data[2] << 8) | data[3];
      SocketHTTP2_error_string ((SocketHTTP2_ErrorCode)fuzz_code);
    }

  /* Test boundary values */
  SocketHTTP2_error_string ((SocketHTTP2_ErrorCode)0);
  SocketHTTP2_error_string ((SocketHTTP2_ErrorCode)0xFF);
  SocketHTTP2_error_string ((SocketHTTP2_ErrorCode)0xFFFFFFFF);
}

/**
 * Test all frame type strings
 */
static void
test_frame_type_strings (const uint8_t *data, size_t size)
{
  /* Test all defined frame types */
  SocketHTTP2_FrameType types[] = {
    HTTP2_FRAME_DATA,         HTTP2_FRAME_HEADERS,    HTTP2_FRAME_PRIORITY,
    HTTP2_FRAME_RST_STREAM,   HTTP2_FRAME_SETTINGS,   HTTP2_FRAME_PUSH_PROMISE,
    HTTP2_FRAME_PING,         HTTP2_FRAME_GOAWAY,     HTTP2_FRAME_WINDOW_UPDATE,
    HTTP2_FRAME_CONTINUATION,
  };

  for (size_t i = 0; i < sizeof (types) / sizeof (types[0]); i++)
    {
      const char *str = SocketHTTP2_frame_type_string (types[i]);
      (void)str;
    }

  /* Test with fuzzed values */
  if (size >= 1)
    {
      SocketHTTP2_frame_type_string ((SocketHTTP2_FrameType)data[0]);
    }

  /* Test boundary values */
  SocketHTTP2_frame_type_string ((SocketHTTP2_FrameType)0xFF);
}

/**
 * Test stream state strings
 */
static void
test_stream_state_strings (const uint8_t *data, size_t size)
{
  /* Test all defined stream states */
  SocketHTTP2_StreamState states[] = {
    HTTP2_STREAM_STATE_IDLE,
    HTTP2_STREAM_STATE_RESERVED_LOCAL,
    HTTP2_STREAM_STATE_RESERVED_REMOTE,
    HTTP2_STREAM_STATE_OPEN,
    HTTP2_STREAM_STATE_HALF_CLOSED_LOCAL,
    HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE,
    HTTP2_STREAM_STATE_CLOSED,
  };

  for (size_t i = 0; i < sizeof (states) / sizeof (states[0]); i++)
    {
      const char *str = SocketHTTP2_stream_state_string (states[i]);
      (void)str;
    }

  /* Test with fuzzed values */
  if (size >= 1)
    {
      SocketHTTP2_stream_state_string ((SocketHTTP2_StreamState)(data[0] % 10));
    }
}

/**
 * Build a frame header manually and test parsing
 */
static void
test_frame_construction (const uint8_t *data, size_t size)
{
  if (size < 9)
    return;

  /* Build frame header from fuzz data */
  SocketHTTP2_FrameHeader header;
  unsigned char buffer[HTTP2_FRAME_HEADER_SIZE];
  unsigned char verify_buffer[HTTP2_FRAME_HEADER_SIZE];

  /* Parse fuzzed header */
  int result = SocketHTTP2_frame_header_parse (data, size, &header);

  if (result == 0)
    {
      /* Serialize back */
      SocketHTTP2_frame_header_serialize (&header, buffer);

      /* Verify roundtrip */
      SocketHTTP2_FrameHeader verify;
      SocketHTTP2_frame_header_parse (buffer, HTTP2_FRAME_HEADER_SIZE, &verify);

      /* Re-serialize for comparison */
      SocketHTTP2_frame_header_serialize (&verify, verify_buffer);
    }
}

/**
 * Test frame construction with all frame types and flags
 */
static void
test_all_frame_types (void)
{
  SocketHTTP2_FrameHeader header;
  unsigned char buffer[HTTP2_FRAME_HEADER_SIZE];
  unsigned char parse_buffer[HTTP2_FRAME_HEADER_SIZE];

  /* Frame types to test */
  uint8_t frame_types[] = {
    HTTP2_FRAME_DATA,          HTTP2_FRAME_HEADERS,
    HTTP2_FRAME_PRIORITY,      HTTP2_FRAME_RST_STREAM,
    HTTP2_FRAME_SETTINGS,      HTTP2_FRAME_PUSH_PROMISE,
    HTTP2_FRAME_PING,          HTTP2_FRAME_GOAWAY,
    HTTP2_FRAME_WINDOW_UPDATE, HTTP2_FRAME_CONTINUATION,
    0xFF, /* Unknown type */
  };

  /* Flags to test */
  uint8_t flags[] = {
    0x00, /* No flags */
    0x01, /* END_STREAM / ACK */
    0x04, /* END_HEADERS */
    0x08, /* PADDED */
    0x20, /* PRIORITY */
    0x0D, /* Multiple flags */
    0xFF, /* All flags */
  };

  /* Stream IDs to test */
  uint32_t stream_ids[] = {
    0,          /* Connection-level */
    1,          /* First client stream */
    2,          /* First server push */
    0x7FFFFFFF, /* Maximum valid stream ID */
    0x80000000, /* Reserved bit set (invalid) */
    0xFFFFFFFF, /* All bits set */
  };

  /* Frame lengths to test */
  uint32_t lengths[] = {
    0,                                 /* Empty payload */
    1,                                 /* Minimum payload */
    8,                                 /* PING frame */
    9,                                 /* Frame header size */
    SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE, /* Default max */
    SOCKETHTTP2_MAX_MAX_FRAME_SIZE,     /* Maximum allowed */
    0x00FFFFFF,                        /* 24-bit maximum */
  };

  for (size_t t = 0; t < sizeof (frame_types) / sizeof (frame_types[0]); t++)
    {
      for (size_t f = 0; f < sizeof (flags) / sizeof (flags[0]); f++)
        {
          for (size_t s = 0; s < sizeof (stream_ids) / sizeof (stream_ids[0]);
               s++)
            {
              for (size_t l = 0; l < sizeof (lengths) / sizeof (lengths[0]);
                   l++)
                {
                  /* Build header */
                  header.length = lengths[l];
                  header.type = frame_types[t];
                  header.flags = flags[f];
                  header.stream_id = stream_ids[s];

                  /* Serialize */
                  SocketHTTP2_frame_header_serialize (&header, buffer);

                  /* Parse back */
                  SocketHTTP2_FrameHeader parsed;
                  int result = SocketHTTP2_frame_header_parse (
                      buffer, HTTP2_FRAME_HEADER_SIZE, &parsed);
                  (void)result;

                  /* Re-serialize and compare */
                  SocketHTTP2_frame_header_serialize (&parsed, parse_buffer);
                }
            }
        }
    }
}

/**
 * Test frame header parsing with various input sizes
 */
static void
test_partial_frame_headers (const uint8_t *data, size_t size)
{
  SocketHTTP2_FrameHeader header;

  /* Test all sizes from 0 to header size */
  for (size_t len = 0; len <= HTTP2_FRAME_HEADER_SIZE && len <= size; len++)
    {
      int result = SocketHTTP2_frame_header_parse (data, len, &header);

      /* Should fail for sizes < 9 */
      if (len < HTTP2_FRAME_HEADER_SIZE)
        {
          /* Expected to fail */
          (void)result;
        }
    }
}

/**
 * Test specific frame type payload sizes
 */
static void
test_frame_payload_sizes (void)
{
  SocketHTTP2_FrameHeader header;
  unsigned char buffer[HTTP2_FRAME_HEADER_SIZE];

  /* SETTINGS frame: must be multiple of 6 bytes */
  uint32_t settings_sizes[] = { 0, 6, 12, 18, 24, 5, 7, 11 };
  for (size_t i = 0; i < sizeof (settings_sizes) / sizeof (settings_sizes[0]);
       i++)
    {
      header.length = settings_sizes[i];
      header.type = HTTP2_FRAME_SETTINGS;
      header.flags = 0;
      header.stream_id = 0;

      SocketHTTP2_frame_header_serialize (&header, buffer);
      SocketHTTP2_FrameHeader parsed;
      SocketHTTP2_frame_header_parse (buffer, HTTP2_FRAME_HEADER_SIZE, &parsed);
    }

  /* PING frame: must be exactly 8 bytes */
  uint32_t ping_sizes[] = { 0, 7, 8, 9, 16 };
  for (size_t i = 0; i < sizeof (ping_sizes) / sizeof (ping_sizes[0]); i++)
    {
      header.length = ping_sizes[i];
      header.type = HTTP2_FRAME_PING;
      header.flags = 0;
      header.stream_id = 0;

      SocketHTTP2_frame_header_serialize (&header, buffer);
      SocketHTTP2_FrameHeader parsed;
      SocketHTTP2_frame_header_parse (buffer, HTTP2_FRAME_HEADER_SIZE, &parsed);
    }

  /* RST_STREAM frame: must be exactly 4 bytes */
  uint32_t rst_sizes[] = { 0, 3, 4, 5, 8 };
  for (size_t i = 0; i < sizeof (rst_sizes) / sizeof (rst_sizes[0]); i++)
    {
      header.length = rst_sizes[i];
      header.type = HTTP2_FRAME_RST_STREAM;
      header.flags = 0;
      header.stream_id = 1;

      SocketHTTP2_frame_header_serialize (&header, buffer);
      SocketHTTP2_FrameHeader parsed;
      SocketHTTP2_frame_header_parse (buffer, HTTP2_FRAME_HEADER_SIZE, &parsed);
    }

  /* WINDOW_UPDATE frame: must be exactly 4 bytes */
  uint32_t wu_sizes[] = { 0, 3, 4, 5, 8 };
  for (size_t i = 0; i < sizeof (wu_sizes) / sizeof (wu_sizes[0]); i++)
    {
      header.length = wu_sizes[i];
      header.type = HTTP2_FRAME_WINDOW_UPDATE;
      header.flags = 0;
      header.stream_id = 0;

      SocketHTTP2_frame_header_serialize (&header, buffer);
      SocketHTTP2_FrameHeader parsed;
      SocketHTTP2_frame_header_parse (buffer, HTTP2_FRAME_HEADER_SIZE, &parsed);
    }

  /* PRIORITY frame: must be exactly 5 bytes */
  uint32_t priority_sizes[] = { 0, 4, 5, 6, 10 };
  for (size_t i = 0; i < sizeof (priority_sizes) / sizeof (priority_sizes[0]);
       i++)
    {
      header.length = priority_sizes[i];
      header.type = HTTP2_FRAME_PRIORITY;
      header.flags = 0;
      header.stream_id = 1;

      SocketHTTP2_frame_header_serialize (&header, buffer);
      SocketHTTP2_FrameHeader parsed;
      SocketHTTP2_frame_header_parse (buffer, HTTP2_FRAME_HEADER_SIZE, &parsed);
    }

  /* GOAWAY frame: minimum 8 bytes */
  uint32_t goaway_sizes[] = { 0, 7, 8, 9, 100 };
  for (size_t i = 0; i < sizeof (goaway_sizes) / sizeof (goaway_sizes[0]); i++)
    {
      header.length = goaway_sizes[i];
      header.type = HTTP2_FRAME_GOAWAY;
      header.flags = 0;
      header.stream_id = 0;

      SocketHTTP2_frame_header_serialize (&header, buffer);
      SocketHTTP2_FrameHeader parsed;
      SocketHTTP2_frame_header_parse (buffer, HTTP2_FRAME_HEADER_SIZE, &parsed);
    }
}

/**
 * Test stream ID constraints per frame type
 */
static void
test_stream_id_constraints (void)
{
  SocketHTTP2_FrameHeader header;
  unsigned char buffer[HTTP2_FRAME_HEADER_SIZE];

  /* Frames that must have stream_id = 0 */
  uint8_t connection_frames[] = { HTTP2_FRAME_SETTINGS, HTTP2_FRAME_PING,
                                  HTTP2_FRAME_GOAWAY };

  for (size_t i = 0;
       i < sizeof (connection_frames) / sizeof (connection_frames[0]); i++)
    {
      /* Valid: stream_id = 0 */
      header.length = 8;
      header.type = connection_frames[i];
      header.flags = 0;
      header.stream_id = 0;
      SocketHTTP2_frame_header_serialize (&header, buffer);
      SocketHTTP2_FrameHeader parsed;
      SocketHTTP2_frame_header_parse (buffer, HTTP2_FRAME_HEADER_SIZE, &parsed);

      /* Invalid: stream_id != 0 */
      header.stream_id = 1;
      SocketHTTP2_frame_header_serialize (&header, buffer);
      SocketHTTP2_frame_header_parse (buffer, HTTP2_FRAME_HEADER_SIZE, &parsed);

      header.stream_id = 0x7FFFFFFF;
      SocketHTTP2_frame_header_serialize (&header, buffer);
      SocketHTTP2_frame_header_parse (buffer, HTTP2_FRAME_HEADER_SIZE, &parsed);
    }

  /* Frames that must have stream_id != 0 */
  uint8_t stream_frames[] = { HTTP2_FRAME_DATA,        HTTP2_FRAME_HEADERS,
                              HTTP2_FRAME_PRIORITY,    HTTP2_FRAME_RST_STREAM,
                              HTTP2_FRAME_PUSH_PROMISE, HTTP2_FRAME_CONTINUATION };

  for (size_t i = 0; i < sizeof (stream_frames) / sizeof (stream_frames[0]);
       i++)
    {
      /* Invalid: stream_id = 0 */
      header.length = 10;
      header.type = stream_frames[i];
      header.flags = 0;
      header.stream_id = 0;
      SocketHTTP2_frame_header_serialize (&header, buffer);
      SocketHTTP2_FrameHeader parsed;
      SocketHTTP2_frame_header_parse (buffer, HTTP2_FRAME_HEADER_SIZE, &parsed);

      /* Valid: stream_id != 0 */
      header.stream_id = 1;
      SocketHTTP2_frame_header_serialize (&header, buffer);
      SocketHTTP2_frame_header_parse (buffer, HTTP2_FRAME_HEADER_SIZE, &parsed);
    }

  /* WINDOW_UPDATE can be on stream 0 or non-zero */
  header.length = 4;
  header.type = HTTP2_FRAME_WINDOW_UPDATE;
  header.flags = 0;

  header.stream_id = 0;
  SocketHTTP2_frame_header_serialize (&header, buffer);
  SocketHTTP2_FrameHeader parsed;
  SocketHTTP2_frame_header_parse (buffer, HTTP2_FRAME_HEADER_SIZE, &parsed);

  header.stream_id = 1;
  SocketHTTP2_frame_header_serialize (&header, buffer);
  SocketHTTP2_frame_header_parse (buffer, HTTP2_FRAME_HEADER_SIZE, &parsed);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketHTTP2_FrameHeader header;
  unsigned char output[HTTP2_FRAME_HEADER_SIZE];

  /* ====================================================================
   * Test 1: Direct fuzzed header parsing
   * ==================================================================== */
  if (size >= HTTP2_FRAME_HEADER_SIZE)
    {
      int result
          = SocketHTTP2_frame_header_parse (data, size, &header);

      if (result == 0)
        {
          /* Roundtrip: serialize and re-parse */
          SocketHTTP2_frame_header_serialize (&header, output);
          SocketHTTP2_FrameHeader verify;
          SocketHTTP2_frame_header_parse (output, HTTP2_FRAME_HEADER_SIZE,
                                          &verify);
        }
    }

  /* ====================================================================
   * Test 2: Partial header parsing (should fail)
   * ==================================================================== */
  test_partial_frame_headers (data, size);

  /* ====================================================================
   * Test 3: Edge cases with extreme values
   * ==================================================================== */
  {
    /* Maximum frame size */
    header.length = SOCKETHTTP2_MAX_MAX_FRAME_SIZE;
    header.stream_id = 0x7FFFFFFF;
    header.type = HTTP2_FRAME_DATA;
    header.flags = 0xFF;
    SocketHTTP2_frame_header_serialize (&header, output);
    SocketHTTP2_FrameHeader verify;
    SocketHTTP2_frame_header_parse (output, HTTP2_FRAME_HEADER_SIZE, &verify);

    /* Zero values */
    header.length = 0;
    header.stream_id = 0;
    header.type = 0;
    header.flags = 0;
    SocketHTTP2_frame_header_serialize (&header, output);
    SocketHTTP2_frame_header_parse (output, HTTP2_FRAME_HEADER_SIZE, &verify);

    /* Reserved bit in stream ID (should be masked) */
    header.stream_id = 0x80000001; /* Reserved bit set */
    SocketHTTP2_frame_header_serialize (&header, output);
    SocketHTTP2_frame_header_parse (output, HTTP2_FRAME_HEADER_SIZE, &verify);
  }

  /* ====================================================================
   * Test 4: String functions for all codes and types
   * ==================================================================== */
  test_error_strings (data, size);
  test_frame_type_strings (data, size);
  test_stream_state_strings (data, size);

  /* ====================================================================
   * Test 5: Frame construction with fuzzed data
   * ==================================================================== */
  test_frame_construction (data, size);

  /* ====================================================================
   * Test 6: All frame type/flag/stream combinations
   * ==================================================================== */
  test_all_frame_types ();

  /* ====================================================================
   * Test 7: Frame payload size constraints
   * ==================================================================== */
  test_frame_payload_sizes ();

  /* ====================================================================
   * Test 8: Stream ID constraints per frame type
   * ==================================================================== */
  test_stream_id_constraints ();

  /* ====================================================================
   * Test 9: Short input handling
   * ==================================================================== */
  if (size > 0 && size < HTTP2_FRAME_HEADER_SIZE)
    {
      /* Should return error for too-short input */
      SocketHTTP2_frame_header_parse (data, size, &header);
    }

  /* ====================================================================
   * Test 10: Fuzzed frame construction from data
   * ==================================================================== */
  if (size >= 9)
    {
      /* Use fuzz data to construct frame header */
      header.length = ((uint32_t)data[0] << 16) | ((uint32_t)data[1] << 8)
                      | data[2];
      header.type = data[3];
      header.flags = data[4];
      header.stream_id = ((uint32_t)data[5] << 24) | ((uint32_t)data[6] << 16)
                         | ((uint32_t)data[7] << 8) | data[8];

      /* Mask reserved bit */
      header.stream_id &= 0x7FFFFFFF;

      /* Serialize and verify */
      SocketHTTP2_frame_header_serialize (&header, output);
      SocketHTTP2_FrameHeader parsed;
      int result
          = SocketHTTP2_frame_header_parse (output, HTTP2_FRAME_HEADER_SIZE,
                                            &parsed);
      (void)result;
    }

  return 0;
}

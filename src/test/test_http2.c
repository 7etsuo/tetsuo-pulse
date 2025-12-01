/**
 * test_http2.c - HTTP/2 Protocol Tests
 *
 * Part of the Socket Library
 * Comprehensive tests for HTTP/2 implementation (RFC 9113)
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHPACK.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Test Utilities
 * ============================================================================ */

static int tests_run = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond, msg)                                                 \
  do                                                                           \
    {                                                                          \
      if (!(cond))                                                             \
        {                                                                      \
          fprintf (stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__);   \
          return 0;                                                            \
        }                                                                      \
    }                                                                          \
  while (0)

#define TEST_BEGIN(name)                                                       \
  do                                                                           \
    {                                                                          \
      tests_run++;                                                             \
      printf ("  Testing %s... ", #name);                                      \
      fflush (stdout);                                                         \
    }                                                                          \
  while (0)

#define TEST_PASS()                                                            \
  do                                                                           \
    {                                                                          \
      tests_passed++;                                                          \
      printf ("PASSED\n");                                                     \
      return 1;                                                                \
    }                                                                          \
  while (0)

/* ============================================================================
 * Frame Header Tests
 * ============================================================================ */

static int
test_frame_header_parse (void)
{
  TEST_BEGIN (frame_header_parse);

  SocketHTTP2_FrameHeader header;
  unsigned char data[9];

  /* Test case 1: Simple DATA frame */
  /* Length: 100 (0x000064), Type: DATA (0), Flags: END_STREAM (0x01), Stream:
   * 1 */
  data[0] = 0x00;
  data[1] = 0x00;
  data[2] = 0x64; /* Length = 100 */
  data[3] = 0x00; /* Type = DATA */
  data[4] = 0x01; /* Flags = END_STREAM */
  data[5] = 0x00;
  data[6] = 0x00;
  data[7] = 0x00;
  data[8] = 0x01; /* Stream ID = 1 */

  TEST_ASSERT (SocketHTTP2_frame_header_parse (data, &header) == 0,
               "Parse should succeed");
  TEST_ASSERT (header.length == 100, "Length should be 100");
  TEST_ASSERT (header.type == HTTP2_FRAME_DATA, "Type should be DATA");
  TEST_ASSERT (header.flags == HTTP2_FLAG_END_STREAM,
               "Flags should be END_STREAM");
  TEST_ASSERT (header.stream_id == 1, "Stream ID should be 1");

  /* Test case 2: SETTINGS frame */
  data[0] = 0x00;
  data[1] = 0x00;
  data[2] = 0x12; /* Length = 18 (3 settings) */
  data[3] = 0x04; /* Type = SETTINGS */
  data[4] = 0x00; /* Flags = 0 */
  data[5] = 0x00;
  data[6] = 0x00;
  data[7] = 0x00;
  data[8] = 0x00; /* Stream ID = 0 */

  TEST_ASSERT (SocketHTTP2_frame_header_parse (data, &header) == 0,
               "Parse should succeed");
  TEST_ASSERT (header.length == 18, "Length should be 18");
  TEST_ASSERT (header.type == HTTP2_FRAME_SETTINGS, "Type should be SETTINGS");
  TEST_ASSERT (header.flags == 0, "Flags should be 0");
  TEST_ASSERT (header.stream_id == 0, "Stream ID should be 0");

  /* Test case 3: Large frame */
  data[0] = 0x00;
  data[1] = 0x40;
  data[2] = 0x00; /* Length = 16384 (max default) */
  data[3] = 0x00; /* Type = DATA */
  data[4] = 0x00; /* Flags = 0 */
  data[5] = 0x00;
  data[6] = 0x00;
  data[7] = 0x00;
  data[8] = 0x03; /* Stream ID = 3 */

  TEST_ASSERT (SocketHTTP2_frame_header_parse (data, &header) == 0,
               "Parse should succeed");
  TEST_ASSERT (header.length == 16384, "Length should be 16384");
  TEST_ASSERT (header.stream_id == 3, "Stream ID should be 3");

  TEST_PASS ();
}

static int
test_frame_header_serialize (void)
{
  TEST_BEGIN (frame_header_serialize);

  SocketHTTP2_FrameHeader header;
  unsigned char data[9];

  /* Test serialization */
  header.length = 256;
  header.type = HTTP2_FRAME_HEADERS;
  header.flags = HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_END_STREAM;
  header.stream_id = 5;

  SocketHTTP2_frame_header_serialize (&header, data);

  TEST_ASSERT (data[0] == 0x00, "Length byte 0");
  TEST_ASSERT (data[1] == 0x01, "Length byte 1");
  TEST_ASSERT (data[2] == 0x00, "Length byte 2");
  TEST_ASSERT (data[3] == HTTP2_FRAME_HEADERS, "Type byte");
  TEST_ASSERT (data[4] == (HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_END_STREAM),
               "Flags byte");
  TEST_ASSERT (data[5] == 0x00, "Stream ID byte 0");
  TEST_ASSERT (data[6] == 0x00, "Stream ID byte 1");
  TEST_ASSERT (data[7] == 0x00, "Stream ID byte 2");
  TEST_ASSERT (data[8] == 0x05, "Stream ID byte 3");

  TEST_PASS ();
}

static int
test_frame_header_roundtrip (void)
{
  TEST_BEGIN (frame_header_roundtrip);

  SocketHTTP2_FrameHeader original, parsed;
  unsigned char data[9];

  /* Various frame types */
  SocketHTTP2_FrameType types[]
      = { HTTP2_FRAME_DATA,     HTTP2_FRAME_HEADERS,
          HTTP2_FRAME_SETTINGS, HTTP2_FRAME_PING,
          HTTP2_FRAME_GOAWAY,   HTTP2_FRAME_WINDOW_UPDATE };

  for (size_t i = 0; i < sizeof (types) / sizeof (types[0]); i++)
    {
      original.length = 1000 + (uint32_t)i * 100;
      original.type = types[i];
      original.flags = (uint8_t)(i * 2);
      original.stream_id = (types[i] == HTTP2_FRAME_SETTINGS
                            || types[i] == HTTP2_FRAME_PING
                            || types[i] == HTTP2_FRAME_GOAWAY)
                               ? 0
                               : (uint32_t)(i + 1);

      SocketHTTP2_frame_header_serialize (&original, data);
      SocketHTTP2_frame_header_parse (data, &parsed);

      TEST_ASSERT (parsed.length == original.length, "Length roundtrip");
      TEST_ASSERT (parsed.type == original.type, "Type roundtrip");
      TEST_ASSERT (parsed.flags == original.flags, "Flags roundtrip");
      TEST_ASSERT (parsed.stream_id == original.stream_id,
                   "Stream ID roundtrip");
    }

  TEST_PASS ();
}

/* ============================================================================
 * Error Code Tests
 * ============================================================================ */

static int
test_error_strings (void)
{
  TEST_BEGIN (error_strings);

  TEST_ASSERT (strcmp (SocketHTTP2_error_string (HTTP2_NO_ERROR), "NO_ERROR")
                   == 0,
               "NO_ERROR string");
  TEST_ASSERT (strcmp (SocketHTTP2_error_string (HTTP2_PROTOCOL_ERROR),
                       "PROTOCOL_ERROR")
                   == 0,
               "PROTOCOL_ERROR string");
  TEST_ASSERT (strcmp (SocketHTTP2_error_string (HTTP2_FLOW_CONTROL_ERROR),
                       "FLOW_CONTROL_ERROR")
                   == 0,
               "FLOW_CONTROL_ERROR string");
  TEST_ASSERT (strcmp (SocketHTTP2_error_string (HTTP2_COMPRESSION_ERROR),
                       "COMPRESSION_ERROR")
                   == 0,
               "COMPRESSION_ERROR string");

  TEST_PASS ();
}

static int
test_frame_type_strings (void)
{
  TEST_BEGIN (frame_type_strings);

  TEST_ASSERT (
      strcmp (SocketHTTP2_frame_type_string (HTTP2_FRAME_DATA), "DATA") == 0,
      "DATA string");
  TEST_ASSERT (strcmp (SocketHTTP2_frame_type_string (HTTP2_FRAME_HEADERS),
                       "HEADERS")
                   == 0,
               "HEADERS string");
  TEST_ASSERT (strcmp (SocketHTTP2_frame_type_string (HTTP2_FRAME_SETTINGS),
                       "SETTINGS")
                   == 0,
               "SETTINGS string");
  TEST_ASSERT (
      strcmp (SocketHTTP2_frame_type_string (HTTP2_FRAME_GOAWAY), "GOAWAY")
          == 0,
      "GOAWAY string");

  TEST_PASS ();
}

static int
test_stream_state_strings (void)
{
  TEST_BEGIN (stream_state_strings);

  TEST_ASSERT (
      strcmp (SocketHTTP2_stream_state_string (HTTP2_STREAM_STATE_IDLE), "idle")
          == 0,
      "idle string");
  TEST_ASSERT (
      strcmp (SocketHTTP2_stream_state_string (HTTP2_STREAM_STATE_OPEN), "open")
          == 0,
      "open string");
  TEST_ASSERT (strcmp (SocketHTTP2_stream_state_string (HTTP2_STREAM_STATE_CLOSED),
                       "closed")
                   == 0,
               "closed string");

  TEST_PASS ();
}

/* ============================================================================
 * Configuration Tests
 * ============================================================================ */

static int
test_config_defaults_client (void)
{
  TEST_BEGIN (config_defaults_client);

  SocketHTTP2_Config config;
  SocketHTTP2_config_defaults (&config, HTTP2_ROLE_CLIENT);

  TEST_ASSERT (config.role == HTTP2_ROLE_CLIENT, "Role should be client");
  TEST_ASSERT (config.header_table_size == SOCKETHTTP2_DEFAULT_HEADER_TABLE_SIZE,
               "Default header table size");
  TEST_ASSERT (config.enable_push == 0,
               "Client should not enable push by default");
  TEST_ASSERT (config.max_concurrent_streams
                   == SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS,
               "Default max concurrent streams");
  TEST_ASSERT (config.initial_window_size
                   == SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE,
               "Default initial window size");
  TEST_ASSERT (config.max_frame_size == SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE,
               "Default max frame size");

  TEST_PASS ();
}

static int
test_config_defaults_server (void)
{
  TEST_BEGIN (config_defaults_server);

  SocketHTTP2_Config config;
  SocketHTTP2_config_defaults (&config, HTTP2_ROLE_SERVER);

  TEST_ASSERT (config.role == HTTP2_ROLE_SERVER, "Role should be server");
  TEST_ASSERT (config.enable_push == SOCKETHTTP2_DEFAULT_ENABLE_PUSH,
               "Server should enable push by default");

  TEST_PASS ();
}

/* ============================================================================
 * Constants Validation Tests
 * ============================================================================ */

static int
test_constants (void)
{
  TEST_BEGIN (constants);

  /* Verify RFC 9113 constants */
  TEST_ASSERT (HTTP2_FRAME_HEADER_SIZE == 9, "Frame header size should be 9");
  TEST_ASSERT (HTTP2_PREFACE_SIZE == 24, "Preface size should be 24");

  /* Verify default settings match RFC */
  TEST_ASSERT (SOCKETHTTP2_DEFAULT_HEADER_TABLE_SIZE == 4096,
               "Default header table size");
  TEST_ASSERT (SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE == 65535,
               "Default initial window");
  TEST_ASSERT (SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE == 16384,
               "Default max frame");
  TEST_ASSERT (SOCKETHTTP2_MAX_MAX_FRAME_SIZE == 16777215,
               "Max max frame (2^24-1)");

  TEST_PASS ();
}

/* ============================================================================
 * Frame Type Enumeration Tests
 * ============================================================================ */

static int
test_frame_types (void)
{
  TEST_BEGIN (frame_types);

  /* Verify frame type values match RFC 9113 */
  TEST_ASSERT (HTTP2_FRAME_DATA == 0x0, "DATA = 0x0");
  TEST_ASSERT (HTTP2_FRAME_HEADERS == 0x1, "HEADERS = 0x1");
  TEST_ASSERT (HTTP2_FRAME_PRIORITY == 0x2, "PRIORITY = 0x2");
  TEST_ASSERT (HTTP2_FRAME_RST_STREAM == 0x3, "RST_STREAM = 0x3");
  TEST_ASSERT (HTTP2_FRAME_SETTINGS == 0x4, "SETTINGS = 0x4");
  TEST_ASSERT (HTTP2_FRAME_PUSH_PROMISE == 0x5, "PUSH_PROMISE = 0x5");
  TEST_ASSERT (HTTP2_FRAME_PING == 0x6, "PING = 0x6");
  TEST_ASSERT (HTTP2_FRAME_GOAWAY == 0x7, "GOAWAY = 0x7");
  TEST_ASSERT (HTTP2_FRAME_WINDOW_UPDATE == 0x8, "WINDOW_UPDATE = 0x8");
  TEST_ASSERT (HTTP2_FRAME_CONTINUATION == 0x9, "CONTINUATION = 0x9");

  TEST_PASS ();
}

/* ============================================================================
 * Frame Flags Tests
 * ============================================================================ */

static int
test_frame_flags (void)
{
  TEST_BEGIN (frame_flags);

  /* Verify flag values */
  TEST_ASSERT (HTTP2_FLAG_END_STREAM == 0x01, "END_STREAM = 0x01");
  TEST_ASSERT (HTTP2_FLAG_END_HEADERS == 0x04, "END_HEADERS = 0x04");
  TEST_ASSERT (HTTP2_FLAG_PADDED == 0x08, "PADDED = 0x08");
  TEST_ASSERT (HTTP2_FLAG_PRIORITY == 0x20, "PRIORITY = 0x20");
  TEST_ASSERT (HTTP2_FLAG_ACK == 0x01, "ACK = 0x01");

  /* Test flag combinations */
  uint8_t headers_flags = HTTP2_FLAG_END_STREAM | HTTP2_FLAG_END_HEADERS;
  TEST_ASSERT (headers_flags == 0x05, "Combined flags");

  TEST_PASS ();
}

/* ============================================================================
 * Error Code Tests
 * ============================================================================ */

static int
test_error_codes (void)
{
  TEST_BEGIN (error_codes);

  /* Verify error code values match RFC 9113 */
  TEST_ASSERT (HTTP2_NO_ERROR == 0x0, "NO_ERROR = 0x0");
  TEST_ASSERT (HTTP2_PROTOCOL_ERROR == 0x1, "PROTOCOL_ERROR = 0x1");
  TEST_ASSERT (HTTP2_INTERNAL_ERROR == 0x2, "INTERNAL_ERROR = 0x2");
  TEST_ASSERT (HTTP2_FLOW_CONTROL_ERROR == 0x3, "FLOW_CONTROL_ERROR = 0x3");
  TEST_ASSERT (HTTP2_SETTINGS_TIMEOUT == 0x4, "SETTINGS_TIMEOUT = 0x4");
  TEST_ASSERT (HTTP2_STREAM_CLOSED == 0x5, "STREAM_CLOSED = 0x5");
  TEST_ASSERT (HTTP2_FRAME_SIZE_ERROR == 0x6, "FRAME_SIZE_ERROR = 0x6");
  TEST_ASSERT (HTTP2_REFUSED_STREAM == 0x7, "REFUSED_STREAM = 0x7");
  TEST_ASSERT (HTTP2_CANCEL == 0x8, "CANCEL = 0x8");
  TEST_ASSERT (HTTP2_COMPRESSION_ERROR == 0x9, "COMPRESSION_ERROR = 0x9");
  TEST_ASSERT (HTTP2_CONNECT_ERROR == 0xa, "CONNECT_ERROR = 0xa");
  TEST_ASSERT (HTTP2_ENHANCE_YOUR_CALM == 0xb, "ENHANCE_YOUR_CALM = 0xb");
  TEST_ASSERT (HTTP2_INADEQUATE_SECURITY == 0xc, "INADEQUATE_SECURITY = 0xc");
  TEST_ASSERT (HTTP2_HTTP_1_1_REQUIRED == 0xd, "HTTP_1_1_REQUIRED = 0xd");

  TEST_PASS ();
}

/* ============================================================================
 * Settings ID Tests
 * ============================================================================ */

static int
test_settings_ids (void)
{
  TEST_BEGIN (settings_ids);

  /* Verify settings IDs match RFC 9113 */
  TEST_ASSERT (HTTP2_SETTINGS_HEADER_TABLE_SIZE == 0x1,
               "HEADER_TABLE_SIZE = 0x1");
  TEST_ASSERT (HTTP2_SETTINGS_ENABLE_PUSH == 0x2, "ENABLE_PUSH = 0x2");
  TEST_ASSERT (HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS == 0x3,
               "MAX_CONCURRENT_STREAMS = 0x3");
  TEST_ASSERT (HTTP2_SETTINGS_INITIAL_WINDOW_SIZE == 0x4,
               "INITIAL_WINDOW_SIZE = 0x4");
  TEST_ASSERT (HTTP2_SETTINGS_MAX_FRAME_SIZE == 0x5, "MAX_FRAME_SIZE = 0x5");
  TEST_ASSERT (HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE == 0x6,
               "MAX_HEADER_LIST_SIZE = 0x6");

  TEST_PASS ();
}

/* ============================================================================
 * Stream State Tests
 * ============================================================================ */

static int
test_stream_states (void)
{
  TEST_BEGIN (stream_states);

  /* Verify all 7 stream states exist */
  TEST_ASSERT (HTTP2_STREAM_STATE_IDLE == 0, "IDLE = 0");
  TEST_ASSERT (HTTP2_STREAM_STATE_RESERVED_LOCAL == 1, "RESERVED_LOCAL = 1");
  TEST_ASSERT (HTTP2_STREAM_STATE_RESERVED_REMOTE == 2, "RESERVED_REMOTE = 2");
  TEST_ASSERT (HTTP2_STREAM_STATE_OPEN == 3, "OPEN = 3");
  TEST_ASSERT (HTTP2_STREAM_STATE_HALF_CLOSED_LOCAL == 4,
               "HALF_CLOSED_LOCAL = 4");
  TEST_ASSERT (HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE == 5,
               "HALF_CLOSED_REMOTE = 5");
  TEST_ASSERT (HTTP2_STREAM_STATE_CLOSED == 6, "CLOSED = 6");

  TEST_PASS ();
}

/* ============================================================================
 * Event Type Tests
 * ============================================================================ */

static int
test_event_types (void)
{
  TEST_BEGIN (event_types);

  /* Stream events */
  TEST_ASSERT (HTTP2_EVENT_STREAM_START == 1, "STREAM_START");
  TEST_ASSERT (HTTP2_EVENT_HEADERS_RECEIVED == 2, "HEADERS_RECEIVED");
  TEST_ASSERT (HTTP2_EVENT_DATA_RECEIVED == 3, "DATA_RECEIVED");
  TEST_ASSERT (HTTP2_EVENT_TRAILERS_RECEIVED == 4, "TRAILERS_RECEIVED");
  TEST_ASSERT (HTTP2_EVENT_STREAM_END == 5, "STREAM_END");
  TEST_ASSERT (HTTP2_EVENT_STREAM_RESET == 6, "STREAM_RESET");
  TEST_ASSERT (HTTP2_EVENT_PUSH_PROMISE == 7, "PUSH_PROMISE");
  TEST_ASSERT (HTTP2_EVENT_WINDOW_UPDATE == 8, "WINDOW_UPDATE");

  /* Connection events */
  TEST_ASSERT (HTTP2_EVENT_SETTINGS_ACK == 20, "SETTINGS_ACK");
  TEST_ASSERT (HTTP2_EVENT_PING_ACK == 21, "PING_ACK");
  TEST_ASSERT (HTTP2_EVENT_GOAWAY_RECEIVED == 22, "GOAWAY_RECEIVED");
  TEST_ASSERT (HTTP2_EVENT_CONNECTION_ERROR == 23, "CONNECTION_ERROR");

  TEST_PASS ();
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */

int
main (void)
{
  printf ("HTTP/2 Protocol Tests\n");
  printf ("=====================\n\n");

  /* Frame header tests */
  printf ("Frame Header Tests:\n");
  test_frame_header_parse ();
  test_frame_header_serialize ();
  test_frame_header_roundtrip ();
  printf ("\n");

  /* String conversion tests */
  printf ("String Conversion Tests:\n");
  test_error_strings ();
  test_frame_type_strings ();
  test_stream_state_strings ();
  printf ("\n");

  /* Configuration tests */
  printf ("Configuration Tests:\n");
  test_config_defaults_client ();
  test_config_defaults_server ();
  printf ("\n");

  /* Protocol constant tests */
  printf ("Protocol Constant Tests:\n");
  test_constants ();
  test_frame_types ();
  test_frame_flags ();
  test_error_codes ();
  test_settings_ids ();
  test_stream_states ();
  test_event_types ();
  printf ("\n");

  /* Summary */
  printf ("=====================\n");
  printf ("Tests: %d passed, %d failed, %d total\n", tests_passed,
          tests_run - tests_passed, tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}

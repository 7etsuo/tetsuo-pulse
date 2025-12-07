/**
 * test_websocket.c - WebSocket Protocol Tests (RFC 6455)
 *
 * Comprehensive unit tests for the WebSocket implementation.
 * Tests frame parsing, handshake, masking, and message handling.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"  /* For SOCKET_HAS_TLS */
#include "core/SocketCrypto.h"
#include "core/SocketUTF8.h"
#include "socket/SocketWS.h"
#include "socket/SocketWS-private.h"
#include "test/Test.h"

/* Suppress unused variable warnings in Release builds (NDEBUG defined)
 * where assert() is compiled out */
#define TEST_UNUSED(x) ((void)(x))

/* ============================================================================
 * Test Counters
 * ============================================================================ */

static int tests_run = 0;
static int tests_passed = 0;

#define TEST_START(name)                                                       \
  do                                                                           \
    {                                                                          \
      printf ("  Testing %s...", name);                                        \
      fflush (stdout);                                                         \
      tests_run++;                                                             \
    }                                                                          \
  while (0)

#define TEST_PASS()                                                            \
  do                                                                           \
    {                                                                          \
      printf (" PASSED\n");                                                    \
      tests_passed++;                                                          \
    }                                                                          \
  while (0)

#define TEST_FAIL(msg)                                                         \
  do                                                                           \
    {                                                                          \
      printf (" FAILED: %s\n", msg);                                           \
    }                                                                          \
  while (0)

/* ============================================================================
 * Test: Configuration Defaults
 * ============================================================================ */

static void
test_config_defaults (void)
{
  SocketWS_Config config;

  TEST_START ("config_defaults");

  SocketWS_config_defaults (&config);

  assert (config.role == WS_ROLE_CLIENT);
  assert (config.max_frame_size == SOCKETWS_MAX_FRAME_SIZE);
  assert (config.max_message_size == SOCKETWS_MAX_MESSAGE_SIZE);
  assert (config.max_fragments == SOCKETWS_MAX_FRAGMENTS);
  assert (config.validate_utf8 == 1);
  assert (config.enable_permessage_deflate == 0);
  assert (config.deflate_max_window_bits == SOCKETWS_DEFAULT_DEFLATE_WINDOW_BITS);
  assert (config.ping_interval_ms == SOCKETWS_DEFAULT_PING_INTERVAL_MS);
  assert (config.ping_timeout_ms == SOCKETWS_DEFAULT_PING_TIMEOUT_MS);

  TEST_PASS ();
}

/* ============================================================================
 * Test: XOR Masking
 * ============================================================================ */

static void
test_masking_simple (void)
{
  unsigned char data[] = "Hello, WebSocket!";
  unsigned char original[32];
  unsigned char mask[4] = { 0x37, 0xFA, 0x21, 0x3D };
  size_t len = strlen ((char *)data);

  TEST_START ("masking_simple");

  /* Save original */
  memcpy (original, data, len);

  /* Apply mask */
  ws_mask_payload (data, len, mask);

  /* Verify data changed */
  assert (memcmp (data, original, len) != 0);

  /* Apply mask again (should restore) */
  ws_mask_payload (data, len, mask);

  /* Verify restored */
  assert (memcmp (data, original, len) == 0);

  TEST_PASS ();
}

static void
test_masking_aligned (void)
{
  /* Test with 8-byte aligned buffer for optimized path */
  unsigned char data[64];
  unsigned char original[64];
  unsigned char mask[4] = { 0xAB, 0xCD, 0xEF, 0x12 };
  size_t len = sizeof (data);

  TEST_START ("masking_aligned");

  /* Fill with pattern */
  for (size_t i = 0; i < len; i++)
    data[i] = (unsigned char)i;
  memcpy (original, data, len);

  /* Apply mask */
  ws_mask_payload (data, len, mask);

  /* Apply again */
  ws_mask_payload (data, len, mask);

  /* Verify restored */
  assert (memcmp (data, original, len) == 0);

  TEST_PASS ();
}

static void
test_masking_with_offset (void)
{
  unsigned char data[16];
  unsigned char mask[4] = { 0x11, 0x22, 0x33, 0x44 };
  size_t offset;

  TEST_START ("masking_with_offset");

  memset (data, 0, sizeof (data));

  /* Apply masking in chunks */
  offset = 0;
  offset = ws_mask_payload_offset (data, 5, mask, offset);
  assert (offset == 1);

  offset = ws_mask_payload_offset (data + 5, 5, mask, offset);
  assert (offset == 2);

  offset = ws_mask_payload_offset (data + 10, 6, mask, offset);
  assert (offset == 0);

  TEST_PASS ();
}

/* ============================================================================
 * Test: Frame Header Building
 * ============================================================================ */

static void
test_frame_header_small (void)
{
  unsigned char header[SOCKETWS_MAX_HEADER_SIZE];
  size_t len;

  TEST_START ("frame_header_small");

  /* Small payload (7-bit length) */
  len = ws_frame_build_header (header, 1, WS_OPCODE_TEXT, 0, NULL, 100);

  assert (len == 2);
  assert ((header[0] & 0x80) != 0); /* FIN */
  assert ((header[0] & 0x0F) == WS_OPCODE_TEXT);
  assert ((header[1] & 0x80) == 0); /* Not masked */
  assert ((header[1] & 0x7F) == 100);
  TEST_UNUSED (len);

  TEST_PASS ();
}

static void
test_frame_header_medium (void)
{
  unsigned char header[SOCKETWS_MAX_HEADER_SIZE];
  size_t len;

  TEST_START ("frame_header_medium");

  /* Medium payload (16-bit length) */
  len = ws_frame_build_header (header, 1, WS_OPCODE_BINARY, 0, NULL, 1000);

  assert (len == 4);
  assert ((header[1] & 0x7F) == 126);
  assert (header[2] == (1000 >> 8));
  assert (header[3] == (1000 & 0xFF));
  TEST_UNUSED (len);

  TEST_PASS ();
}

static void
test_frame_header_large (void)
{
  unsigned char header[SOCKETWS_MAX_HEADER_SIZE];
  size_t len;
  uint64_t payload_len = 100000;

  TEST_START ("frame_header_large");

  /* Large payload (64-bit length) */
  len = ws_frame_build_header (header, 1, WS_OPCODE_BINARY, 0, NULL, payload_len);

  assert (len == 10);
  assert ((header[1] & 0x7F) == 127);
  TEST_UNUSED (len);

  TEST_PASS ();
}

static void
test_frame_header_masked (void)
{
  unsigned char header[SOCKETWS_MAX_HEADER_SIZE];
  unsigned char mask[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
  size_t len;

  TEST_START ("frame_header_masked");

  /* Masked frame */
  len = ws_frame_build_header (header, 1, WS_OPCODE_TEXT, 1, mask, 50);

  assert (len == 6); /* 2 base + 4 mask */
  assert ((header[1] & 0x80) != 0); /* Masked */
  assert (memcmp (header + 2, mask, 4) == 0);
  TEST_UNUSED (len);

  TEST_PASS ();
}

/* ============================================================================
 * Test: Frame Header Parsing
 * ============================================================================ */

static void
test_frame_parse_simple (void)
{
  SocketWS_FrameParse frame;
  unsigned char data[] = { 0x81, 0x05, 'H', 'e', 'l', 'l', 'o' };
  size_t consumed;
  SocketWS_Error err;

  TEST_START ("frame_parse_simple");

  ws_frame_reset (&frame);
  err = ws_frame_parse_header (&frame, data, sizeof (data), &consumed);

  assert (err == WS_OK);
  assert (consumed == 2);
  assert (frame.fin == 1);
  assert (frame.opcode == WS_OPCODE_TEXT);
  assert (frame.masked == 0);
  assert (frame.payload_len == 5);
  TEST_UNUSED (err);

  TEST_PASS ();
}

static void
test_frame_parse_masked (void)
{
  SocketWS_FrameParse frame;
  unsigned char data[]
      = { 0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D, 0x7F, 0x9F, 0x4D, 0x51, 0x58 };
  size_t consumed;
  SocketWS_Error err;

  TEST_START ("frame_parse_masked");

  ws_frame_reset (&frame);
  err = ws_frame_parse_header (&frame, data, sizeof (data), &consumed);

  assert (err == WS_OK);
  assert (consumed == 6); /* 2 header + 4 mask */
  assert (frame.masked == 1);
  assert (frame.payload_len == 5);
  assert (frame.mask_key[0] == 0x37);
  assert (frame.mask_key[1] == 0xFA);
  assert (frame.mask_key[2] == 0x21);
  assert (frame.mask_key[3] == 0x3D);
  TEST_UNUSED (err);

  TEST_PASS ();
}

static void
test_frame_parse_extended16 (void)
{
  SocketWS_FrameParse frame;
  unsigned char data[] = { 0x82, 0x7E, 0x01, 0x00 }; /* 256 bytes */
  size_t consumed;
  SocketWS_Error err;

  TEST_START ("frame_parse_extended16");

  ws_frame_reset (&frame);
  err = ws_frame_parse_header (&frame, data, sizeof (data), &consumed);

  assert (err == WS_OK);
  assert (consumed == 4);
  assert (frame.payload_len == 256);
  TEST_UNUSED (err);

  TEST_PASS ();
}

static void
test_frame_parse_extended64 (void)
{
  SocketWS_FrameParse frame;
  unsigned char data[] = { 0x82, 0x7F, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x01, 0x00, 0x00 }; /* 65536 bytes */
  size_t consumed;
  SocketWS_Error err;

  TEST_START ("frame_parse_extended64");

  ws_frame_reset (&frame);
  err = ws_frame_parse_header (&frame, data, sizeof (data), &consumed);

  assert (err == WS_OK);
  assert (consumed == 10);
  assert (frame.payload_len == 65536);
  TEST_UNUSED (err);

  TEST_PASS ();
}

static void
test_frame_parse_control (void)
{
  SocketWS_FrameParse frame;
  unsigned char ping[] = { 0x89, 0x00 }; /* PING, no payload */
  unsigned char pong[] = { 0x8A, 0x00 }; /* PONG, no payload */
  unsigned char close[] = { 0x88, 0x02, 0x03, 0xE8 }; /* CLOSE 1000 */
  size_t consumed;
  SocketWS_Error err;

  TEST_START ("frame_parse_control");

  /* PING */
  ws_frame_reset (&frame);
  err = ws_frame_parse_header (&frame, ping, sizeof (ping), &consumed);
  assert (err == WS_OK);
  assert (frame.opcode == WS_OPCODE_PING);
  assert (frame.fin == 1);

  /* PONG */
  ws_frame_reset (&frame);
  err = ws_frame_parse_header (&frame, pong, sizeof (pong), &consumed);
  assert (err == WS_OK);
  assert (frame.opcode == WS_OPCODE_PONG);

  /* CLOSE */
  ws_frame_reset (&frame);
  err = ws_frame_parse_header (&frame, close, sizeof (close), &consumed);
  assert (err == WS_OK);
  assert (frame.opcode == WS_OPCODE_CLOSE);
  assert (frame.payload_len == 2);
  TEST_UNUSED (err);

  TEST_PASS ();
}

static void
test_frame_parse_incremental (void)
{
  SocketWS_FrameParse frame;
  unsigned char data1[] = { 0x81 }; /* Just first byte */
  unsigned char data2[] = { 0x05 }; /* Second byte */
  size_t consumed;
  SocketWS_Error err;

  TEST_START ("frame_parse_incremental");

  ws_frame_reset (&frame);

  /* First byte only */
  err = ws_frame_parse_header (&frame, data1, 1, &consumed);
  assert (err == WS_ERROR_WOULD_BLOCK);
  assert (consumed == 1);

  /* Second byte */
  err = ws_frame_parse_header (&frame, data2, 1, &consumed);
  assert (err == WS_OK);
  assert (consumed == 1);
  assert (frame.payload_len == 5);
  TEST_UNUSED (err);

  TEST_PASS ();
}

/* ============================================================================
 * Test: Protocol Validation
 * ============================================================================ */

static void
test_frame_parse_invalid_opcode (void)
{
  SocketWS_FrameParse frame;
  unsigned char data[] = { 0x83, 0x00 }; /* Invalid opcode 3 */
  size_t consumed;
  SocketWS_Error err;

  TEST_START ("frame_parse_invalid_opcode");

  ws_frame_reset (&frame);
  err = ws_frame_parse_header (&frame, data, sizeof (data), &consumed);

  assert (err == WS_ERROR_PROTOCOL);
  TEST_UNUSED (err);

  TEST_PASS ();
}

static void
test_frame_parse_fragmented_control (void)
{
  SocketWS_FrameParse frame;
  unsigned char data[] = { 0x09, 0x00 }; /* PING without FIN */
  size_t consumed;
  SocketWS_Error err;

  TEST_START ("frame_parse_fragmented_control");

  ws_frame_reset (&frame);
  err = ws_frame_parse_header (&frame, data, sizeof (data), &consumed);

  /* Control frames must not be fragmented */
  assert (err == WS_ERROR_PROTOCOL);
  TEST_UNUSED (err);

  TEST_PASS ();
}

static void
test_frame_parse_control_too_large (void)
{
  SocketWS_FrameParse frame;
  unsigned char data[] = { 0x89, 0x7E, 0x00, 0x80 }; /* PING with 128 bytes */
  size_t consumed;
  SocketWS_Error err;

  TEST_START ("frame_parse_control_too_large");

  ws_frame_reset (&frame);
  err = ws_frame_parse_header (&frame, data, sizeof (data), &consumed);

  /* Control frame payload max 125 bytes */
  assert (err == WS_ERROR_PROTOCOL);
  TEST_UNUSED (err);

  TEST_PASS ();
}

/* ============================================================================
 * Test: Opcode Validation Helpers
 * ============================================================================ */

static void
test_opcode_helpers (void)
{
  TEST_START ("opcode_helpers");

  /* Control opcodes */
  assert (ws_is_control_opcode (WS_OPCODE_CLOSE) == 1);
  assert (ws_is_control_opcode (WS_OPCODE_PING) == 1);
  assert (ws_is_control_opcode (WS_OPCODE_PONG) == 1);
  assert (ws_is_control_opcode (WS_OPCODE_TEXT) == 0);
  assert (ws_is_control_opcode (WS_OPCODE_BINARY) == 0);

  /* Data opcodes */
  assert (ws_is_data_opcode (WS_OPCODE_TEXT) == 1);
  assert (ws_is_data_opcode (WS_OPCODE_BINARY) == 1);
  assert (ws_is_data_opcode (WS_OPCODE_CONTINUATION) == 0);
  assert (ws_is_data_opcode (WS_OPCODE_CLOSE) == 0);

  /* Valid opcodes */
  assert (ws_is_valid_opcode (WS_OPCODE_CONTINUATION) == 1);
  assert (ws_is_valid_opcode (WS_OPCODE_TEXT) == 1);
  assert (ws_is_valid_opcode (WS_OPCODE_BINARY) == 1);
  assert (ws_is_valid_opcode (WS_OPCODE_CLOSE) == 1);
  assert (ws_is_valid_opcode (WS_OPCODE_PING) == 1);
  assert (ws_is_valid_opcode (WS_OPCODE_PONG) == 1);
  assert (ws_is_valid_opcode ((SocketWS_Opcode)0x03) == 0); /* Reserved */
  assert (ws_is_valid_opcode ((SocketWS_Opcode)0x0B) == 0); /* Reserved */

  TEST_PASS ();
}

/* ============================================================================
 * Test: Close Code Validation
 * ============================================================================ */

static void
test_close_code_validation (void)
{
  TEST_START ("close_code_validation");

  /* Valid codes */
  assert (ws_is_valid_close_code (WS_CLOSE_NORMAL) == 1);
  assert (ws_is_valid_close_code (WS_CLOSE_GOING_AWAY) == 1);
  assert (ws_is_valid_close_code (WS_CLOSE_PROTOCOL_ERROR) == 1);
  assert (ws_is_valid_close_code (WS_CLOSE_UNSUPPORTED_DATA) == 1);
  assert (ws_is_valid_close_code (WS_CLOSE_INVALID_PAYLOAD) == 1);
  assert (ws_is_valid_close_code (WS_CLOSE_POLICY_VIOLATION) == 1);
  assert (ws_is_valid_close_code (WS_CLOSE_MESSAGE_TOO_BIG) == 1);
  assert (ws_is_valid_close_code (WS_CLOSE_MANDATORY_EXT) == 1);
  assert (ws_is_valid_close_code (WS_CLOSE_INTERNAL_ERROR) == 1);
  assert (ws_is_valid_close_code (3000) == 1); /* Private use */
  assert (ws_is_valid_close_code (4999) == 1); /* Private use */

  /* Invalid codes */
  assert (ws_is_valid_close_code (0) == 0);
  assert (ws_is_valid_close_code (999) == 0);
  assert (ws_is_valid_close_code (1004) == 0); /* Reserved */
  assert (ws_is_valid_close_code (WS_CLOSE_NO_STATUS) == 0);
  assert (ws_is_valid_close_code (WS_CLOSE_ABNORMAL) == 0);
  assert (ws_is_valid_close_code (WS_CLOSE_TLS_HANDSHAKE) == 0);
  assert (ws_is_valid_close_code (5000) == 0);

  TEST_PASS ();
}

/* ============================================================================
 * Test: Error Strings
 * ============================================================================ */

static void
test_error_strings (void)
{
  TEST_START ("error_strings");

  assert (strcmp (SocketWS_error_string (WS_OK), "OK") == 0);
  assert (strcmp (SocketWS_error_string (WS_ERROR), "General error") == 0);
  assert (strcmp (SocketWS_error_string (WS_ERROR_HANDSHAKE), "Handshake failed")
          == 0);
  assert (strcmp (SocketWS_error_string (WS_ERROR_PROTOCOL), "Protocol error")
          == 0);
  assert (strcmp (SocketWS_error_string (WS_ERROR_INVALID_UTF8), "Invalid UTF-8")
          == 0);
  assert (SocketWS_error_string ((SocketWS_Error)999) != NULL);

  TEST_PASS ();
}

/* ============================================================================
 * Test: WebSocket Key Generation (using SocketCrypto)
 * ============================================================================ */

static void
test_websocket_key_generation (void)
{
  char key1[SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE];
  char key2[SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE];
  int result;

  TEST_START ("websocket_key_generation");

  /* Generate two keys */
  result = SocketCrypto_websocket_key (key1);
  assert (result == 0);
  assert (strlen (key1) == 24);

  result = SocketCrypto_websocket_key (key2);
  assert (result == 0);
  assert (strlen (key2) == 24);

  /* Keys should be different (random) */
  assert (strcmp (key1, key2) != 0);
  TEST_UNUSED (result);

  TEST_PASS ();
}

/* ============================================================================
 * Test: WebSocket Accept Computation (using SocketCrypto)
 * ============================================================================ */

#if SOCKET_HAS_TLS
static void
test_websocket_accept_computation (void)
{
  /* RFC 6455 test vector */
  const char *key = "dGhlIHNhbXBsZSBub25jZQ==";
  const char *expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
  char accept[SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE];
  int result;

  TEST_START ("websocket_accept_computation");

  result = SocketCrypto_websocket_accept (key, accept);
  assert (result == 0);
  assert (strcmp (accept, expected) == 0);
  TEST_UNUSED (result);

  TEST_PASS ();
}
#endif /* SOCKET_HAS_TLS */

/* ============================================================================
 * Tests: WebSocket Compression (permessage-deflate)
 * ============================================================================ */

#ifdef SOCKETWS_HAS_DEFLATE

static void
test_ws_compression_roundtrip (void)
{
  (void)SocketWS_DetailedException; /* Suppress unused module exception warning */
  TEST_START ("ws_compression_roundtrip");

  Arena_T arena = Arena_new ();

  // Minimal ws setup for test
  SocketWS_T ws = CALLOC (arena, 1, sizeof (struct SocketWS));
  ws->arena = arena;
  ws->role = WS_ROLE_CLIENT;
  ws->config.max_message_size = 1 << 20; // 1MB limit
  ws->handshake.client_max_window_bits = 10;
  ws->handshake.server_max_window_bits = 10;
  ws->config.enable_permessage_deflate = 1;

  // Init compression
  int init_ret = ws_compression_init (ws);
  assert (init_ret == 0);

  // Test data
  const char *test_str = "Hello, WebSocket compression test!";
  size_t test_len = strlen (test_str);
  unsigned char *compressed = NULL;
  size_t comp_len = 0;
  unsigned char *decompressed = NULL;
  size_t decomp_len = 0;

  // Compress
  int comp_ret = ws_compress_message (ws, (const unsigned char *)test_str, test_len, &compressed, &comp_len);
  assert (comp_ret == 0);
  assert (comp_len > 0);
  assert (comp_len < test_len * 2); // Reasonable compression or slight expansion

  // Decompress
  int decomp_ret = ws_decompress_message (ws, compressed, comp_len, &decompressed, &decomp_len);
  assert (decomp_ret == 0);
  assert (decomp_len == test_len);
  assert (memcmp (decompressed, test_str, test_len) == 0);

  // Cleanup
  ws_compression_free (ws);

  Arena_dispose (&arena);

  TEST_PASS ();
}

static void
test_ws_compression_errors (void)
{
  TEST_START ("ws_compression_errors");

  Arena_T arena = Arena_new ();

  SocketWS_T ws = CALLOC (arena, 1, sizeof (struct SocketWS));
  ws->arena = arena;
  ws->role = WS_ROLE_CLIENT;
  ws->config.max_message_size = 1024; // Small limit for test
  ws->config.enable_permessage_deflate = 1;

  // Invalid window bits
  ws->handshake.client_max_window_bits = 20; // Invalid >15
  int init_ret = ws_compression_init (ws);
  assert (init_ret == -1); // Should error on validation

  // Reset for other test
  ws_compression_free (ws);
  memset (ws, 0, sizeof (struct SocketWS)); // Reset
  ws->arena = arena;
  ws->role = WS_ROLE_CLIENT;
  ws->handshake.client_max_window_bits = 10; // Valid
  ws->handshake.server_max_window_bits = 10;
  init_ret = ws_compression_init (ws);
  assert (init_ret == 0);

  // Test size exceed (mock large input)
  size_t large_input = ws->config.max_message_size * 10;
  unsigned char *large_comp = NULL;
  size_t large_comp_len = 0;
  int large_ret = ws_compress_message (ws, (const unsigned char *)"", large_input, &large_comp, &large_comp_len); // Large avail_in
  assert (large_ret == -1); // Expect failure due to size checks during growth
  // Note: Verifies overflow/ size limit enforcement
  ws_compression_free (ws);

  Arena_dispose (&arena);

  TEST_PASS ();
}

#endif /* SOCKETWS_HAS_DEFLATE */

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */

int
main (void)
{
  printf ("=== WebSocket Tests ===\n\n");

  printf ("Configuration:\n");
  test_config_defaults ();

  printf ("\nXOR Masking:\n");
  test_masking_simple ();
  test_masking_aligned ();
  test_masking_with_offset ();

  printf ("\nFrame Header Building:\n");
  test_frame_header_small ();
  test_frame_header_medium ();
  test_frame_header_large ();
  test_frame_header_masked ();

  printf ("\nFrame Header Parsing:\n");
  test_frame_parse_simple ();
  test_frame_parse_masked ();
  test_frame_parse_extended16 ();
  test_frame_parse_extended64 ();
  test_frame_parse_control ();
  test_frame_parse_incremental ();

  printf ("\nProtocol Validation:\n");
  test_frame_parse_invalid_opcode ();
  test_frame_parse_fragmented_control ();
  test_frame_parse_control_too_large ();
  test_opcode_helpers ();
  test_close_code_validation ();

  printf ("\nError Handling:\n");
  test_error_strings ();

  printf ("\nCryptographic Helpers:\n");
  test_websocket_key_generation ();
#if SOCKET_HAS_TLS
  test_websocket_accept_computation ();
#else
  printf ("  [SKIPPED] websocket_accept_computation (requires TLS)\n");
#endif

#ifdef SOCKETWS_HAS_DEFLATE
  printf ("\nCompression (permessage-deflate):\n");
  test_ws_compression_roundtrip ();
  test_ws_compression_errors ();
#else
  printf ("  [SKIPPED] Compression tests (requires zlib/SOCKETWS_HAS_DEFLATE)\n");
#endif

  printf ("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}


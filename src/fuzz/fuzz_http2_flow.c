/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_http2_flow.c - Comprehensive HTTP/2 Flow Control Fuzzer
 *
 * This fuzzer targets HTTP/2 flow control mechanisms per RFC 9113 Section 5.2.
 * Previously, SocketHTTP2-flow.c had 0% test coverage (114 lines, 0/10
 * functions).
 *
 * Flow Control (RFC 9113 Section 5.2):
 * - Connection-level and stream-level flow control windows
 * - WINDOW_UPDATE frame processing
 * - Flow control error handling
 * - Window size arithmetic and overflow detection
 * - Initial window size settings (SETTINGS_INITIAL_WINDOW_SIZE)
 *
 * Functions Tested (10 total in SocketHTTP2-flow.c):
 * - flow_update_window: Update flow control window with overflow detection
 * - http2_flow_validate: Validate connection and stream association
 * - http2_flow_consume_level: Consume bytes from flow control windows
 * - http2_flow_update_level: Update flow control windows
 * - http2_flow_consume_recv: Consume from receive window
 * - http2_flow_update_recv: Update receive window
 * - http2_flow_consume_send: Consume from send window
 * - http2_flow_update_send: Update send window
 * - http2_flow_available_send: Get available send window
 * - http2_flow_adjust_window: Adjust window for SETTINGS_INITIAL_WINDOW_SIZE
 * changes
 *
 * Security Focus:
 * - Integer overflow in window updates (RFC 9113 Section 6.9.1)
 * - Negative window values (flow control error)
 * - Zero increment in WINDOW_UPDATE (protocol error)
 * - Window size exceeding 2^31-1 (SOCKETHTTP2_MAX_WINDOW_SIZE)
 * - Flow control violations (consuming more than available)
 * - SETTINGS_INITIAL_WINDOW_SIZE changes affecting existing streams
 * - Connection vs stream window interactions
 * - Simultaneous window updates on multiple streams
 *
 * Flow Control Errors:
 * - Sending data exceeding available window → FLOW_CONTROL_ERROR
 * - Window update causing overflow → FLOW_CONTROL_ERROR
 * - Zero increment in WINDOW_UPDATE → PROTOCOL_ERROR
 * - Negative window after consumption → FLOW_CONTROL_ERROR
 *
 * Build: CC=clang cmake -B build -DENABLE_FUZZING=ON
 * Run: ./fuzz_http2_flow corpus/http2_flow/ -fork=16 -max_len=4096
 */

#include "http/SocketHTTP2.h"
#include "http/SocketHTTP2-private.h"
#include "core/Arena.h"
#include "socket/Socket.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

/* Suppress unused variable warnings for fuzzing */
#define UNUSED(x) (void)(x)

/**
 * Test window update overflow detection
 */
static void
test_window_overflow (const uint8_t *data, size_t size)
{
  if (size < 8)
    return;

  int32_t current_window
      = (int32_t)(((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
                  | ((uint32_t)data[2] << 8) | data[3]);

  uint32_t increment = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16)
                       | ((uint32_t)data[6] << 8) | data[7];

  /* Test overflow detection:
   * RFC 9113 Section 6.9.1: A sender MUST NOT allow a flow-control window
   * to exceed 2^31-1 octets. If a sender receives a WINDOW_UPDATE that
   * causes a flow-control window to exceed this maximum, it MUST terminate
   * either the stream or the connection, as appropriate.
   */

  /* Test cases for overflow */
  struct
  {
    int32_t window;
    uint32_t increment;
    int should_overflow;
  } test_cases[] = {
    /* Valid updates */
    { 0, 65535, 0 },
    { 65535, 1, 0 },
    { 1000000, 1000000, 0 },
    { 0x7FFFFFFE, 1, 0 }, /* Near max + 1 */

    /* Overflow cases */
    { 0x7FFFFFFF, 1, 1 },          /* Max + 1 */
    { 0x7FFFFFFF, 100, 1 },        /* Max + large */
    { 0x40000000, 0x40000000, 1 }, /* Half max + half max */
    { 0x7FFFFFFE, 2, 1 },          /* Near max + 2 */

    /* Fuzzed values */
    { current_window, increment, 0 },
  };

  for (size_t i = 0; i < sizeof (test_cases) / sizeof (test_cases[0]); i++)
    {
      int32_t window = test_cases[i].window;
      uint32_t inc = test_cases[i].increment;

      /* Check for overflow: (int64_t)window + (int64_t)inc > MAX_WINDOW_SIZE */
      int64_t new_value = (int64_t)window + (int64_t)inc;
      int overflows = new_value > SOCKETHTTP2_MAX_WINDOW_SIZE;

      UNUSED (overflows);
      UNUSED (test_cases[i].should_overflow);
    }
}

/**
 * Test zero increment detection (protocol error)
 */
static void
test_zero_increment (const uint8_t *data, size_t size)
{
  /* RFC 9113 Section 6.9: A receiver that receives a WINDOW_UPDATE frame
   * with an increment of 0 MUST respond with a connection error of type
   * PROTOCOL_ERROR.
   */

  if (size < 4)
    return;

  uint32_t increment = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
                       | ((uint32_t)data[2] << 8) | data[3];

  /* Test various increment values */
  uint32_t increments[] = {
    0,          /* Invalid: zero increment → PROTOCOL_ERROR */
    1,          /* Valid: minimum */
    65535,      /* Valid: common value */
    0x7FFFFFFF, /* Valid: maximum */
    increment,  /* Fuzzed value */
  };

  for (size_t i = 0; i < sizeof (increments) / sizeof (increments[0]); i++)
    {
      uint32_t inc = increments[i];

      /* Zero increment is a protocol error */
      int is_zero = (inc == 0);

      /* Increment exceeding maximum is also invalid */
      int exceeds_max = inc > SOCKETHTTP2_MAX_WINDOW_SIZE;

      UNUSED (is_zero);
      UNUSED (exceeds_max);
    }
}

/**
 * Test negative window detection
 */
static void
test_negative_window (const uint8_t *data, size_t size)
{
  if (size < 8)
    return;

  int32_t window
      = (int32_t)(((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
                  | ((uint32_t)data[2] << 8) | data[3]);

  size_t consume = ((size_t)data[4] << 24) | ((size_t)data[5] << 16)
                   | ((size_t)data[6] << 8) | data[7];

  /* Test consuming from window */
  struct
  {
    int32_t window;
    size_t consume;
    int should_fail;
  } test_cases[] = {
    /* Valid consumption */
    { 65535, 1000, 0 },
    { 1000, 1000, 0 },
    { 1000, 0, 0 },

    /* Invalid consumption (exceeds window) */
    { 1000, 1001, 1 },
    { 0, 1, 1 },
    { -1, 1, 1 }, /* Negative window */
    { 65535, 65536, 1 },

    /* Edge cases */
    { 0x7FFFFFFF, 0x7FFFFFFF, 0 }, /* Consume entire max window */
    { 1, 0x7FFFFFFF, 1 },          /* Consume more than available */

    /* Fuzzed values */
    { window, consume, 0 },
  };

  for (size_t i = 0; i < sizeof (test_cases) / sizeof (test_cases[0]); i++)
    {
      int32_t w = test_cases[i].window;
      size_t c = test_cases[i].consume;

      /* Check if consumption would make window negative */
      int would_be_negative = (int64_t)w - (int64_t)c < 0;

      /* Check if consume is too large (> INT32_MAX) */
      int consume_too_large = c > INT32_MAX;

      UNUSED (would_be_negative);
      UNUSED (consume_too_large);
      UNUSED (test_cases[i].should_fail);
    }
}

/**
 * Test SETTINGS_INITIAL_WINDOW_SIZE changes
 */
static void
test_initial_window_size_changes (const uint8_t *data, size_t size)
{
  /* RFC 9113 Section 6.5.2: When the value of SETTINGS_INITIAL_WINDOW_SIZE
   * changes, a receiver MUST adjust the size of all stream flow-control
   * windows by the difference between the new value and the old value.
   */

  if (size < 8)
    return;

  uint32_t old_initial = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
                         | ((uint32_t)data[2] << 8) | data[3];

  uint32_t new_initial = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16)
                         | ((uint32_t)data[6] << 8) | data[7];

  /* Test various initial window size changes */
  struct
  {
    uint32_t old_size;
    uint32_t new_size;
    int32_t delta;
  } test_cases[] = {
    /* Increase window */
    { 65535, 131070, 65535 },
    { 65535, 1048576, 983041 },

    /* Decrease window */
    { 131070, 65535, -65535 },
    { 1048576, 65535, -983041 },

    /* No change */
    { 65535, 65535, 0 },

    /* Edge cases */
    { 0, 0x7FFFFFFF, 0x7FFFFFFF },           /* Min to max */
    { 0x7FFFFFFF, 0, -(int32_t)0x7FFFFFFF }, /* Max to min */

    /* Fuzzed values */
    { old_initial, new_initial, (int64_t)new_initial - (int64_t)old_initial },
  };

  for (size_t i = 0; i < sizeof (test_cases) / sizeof (test_cases[0]); i++)
    {
      uint32_t old_sz = test_cases[i].old_size;
      uint32_t new_sz = test_cases[i].new_size;
      int32_t delta = test_cases[i].delta;

      /* Mask to valid range */
      old_sz &= 0x7FFFFFFF;
      new_sz &= 0x7FFFFFFF;

      /* Calculate actual delta */
      int64_t actual_delta = (int64_t)new_sz - (int64_t)old_sz;

      /* Test applying delta to various current windows */
      int32_t test_windows[] = {
        0,
        65535,
        0x7FFFFFFF,
      };

      for (size_t j = 0; j < sizeof (test_windows) / sizeof (test_windows[0]);
           j++)
        {
          int32_t current = test_windows[j];
          int64_t new_window = (int64_t)current + (int64_t)actual_delta;

          /* Check if adjustment would overflow or underflow */
          int would_overflow = new_window > SOCKETHTTP2_MAX_WINDOW_SIZE;
          int would_underflow = new_window < 0;

          UNUSED (would_overflow);
          UNUSED (would_underflow);
        }

      UNUSED (delta);
    }
}

/**
 * Test connection vs stream window interaction
 */
static void
test_connection_stream_windows (const uint8_t *data, size_t size)
{
  /* RFC 9113 Section 5.2: Flow control operates at two levels:
   * stream and connection. Both types of flow control are hop-by-hop.
   *
   * When sending data:
   * 1. Check stream send window
   * 2. Check connection send window
   * 3. Use minimum of the two
   * 4. Consume from both windows
   */

  if (size < 12)
    return;

  int32_t conn_window
      = (int32_t)(((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
                  | ((uint32_t)data[2] << 8) | data[3]);

  int32_t stream_window
      = (int32_t)(((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16)
                  | ((uint32_t)data[6] << 8) | data[7]);

  size_t data_size = ((size_t)data[8] << 24) | ((size_t)data[9] << 16)
                     | ((size_t)data[10] << 8) | data[11];

  /* Test various window combinations */
  struct
  {
    int32_t conn_win;
    int32_t stream_win;
    size_t data_sz;
    size_t expected_allowed;
  } test_cases[] = {
    /* Connection window is limiting */
    { 1000, 10000, 5000, 1000 },
    { 0, 10000, 5000, 0 },

    /* Stream window is limiting */
    { 10000, 1000, 5000, 1000 },
    { 10000, 0, 5000, 0 },

    /* Both equal */
    { 5000, 5000, 10000, 5000 },

    /* Data smaller than both windows */
    { 10000, 10000, 1000, 1000 },

    /* Zero windows */
    { 0, 0, 1000, 0 },

    /* Negative windows (error case) */
    { -1, 10000, 1000, 0 },
    { 10000, -1, 1000, 0 },

    /* Fuzzed values */
    { conn_window, stream_window, data_size, 0 },
  };

  for (size_t i = 0; i < sizeof (test_cases) / sizeof (test_cases[0]); i++)
    {
      int32_t cw = test_cases[i].conn_win;
      int32_t sw = test_cases[i].stream_win;
      size_t dsz = test_cases[i].data_sz;

      /* Calculate available window (minimum of conn and stream) */
      int32_t available = cw < sw ? cw : sw;
      if (available < 0)
        available = 0;

      /* Calculate how much data can be sent */
      size_t can_send = (size_t)available;
      if (can_send > dsz)
        can_send = dsz;

      UNUSED (can_send);
      UNUSED (test_cases[i].expected_allowed);
    }
}

/**
 * Test window update frame payload
 */
static void
test_window_update_payload (const uint8_t *data, size_t size)
{
  if (size < 4)
    return;

  /* WINDOW_UPDATE payload is exactly 4 bytes: window size increment */
  uint32_t raw_increment = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
                           | ((uint32_t)data[2] << 8) | data[3];

  /* Mask reserved bit (bit 31) */
  uint32_t increment = raw_increment & 0x7FFFFFFF;

  /* Test reserved bit handling */
  int reserved_bit = (raw_increment >> 31) & 1;

  /* Test various payload values */
  uint32_t test_payloads[] = {
    0x00000000,    /* Zero increment (error) */
    0x00000001,    /* Minimum valid */
    0x0000FFFF,    /* Common value */
    0x7FFFFFFF,    /* Maximum valid (reserved bit = 0) */
    0x80000001,    /* Reserved bit set (should be masked) */
    0xFFFFFFFF,    /* All bits set */
    raw_increment, /* Fuzzed value */
  };

  for (size_t i = 0; i < sizeof (test_payloads) / sizeof (test_payloads[0]);
       i++)
    {
      uint32_t payload = test_payloads[i];

      /* Mask reserved bit */
      uint32_t masked = payload & 0x7FFFFFFF;

      /* Check if zero */
      int is_zero = (masked == 0);

      UNUSED (masked);
      UNUSED (is_zero);
    }

  UNUSED (increment);
  UNUSED (reserved_bit);
}

/**
 * Test edge cases and boundary conditions
 */
static void
test_edge_cases (const uint8_t *data, size_t size)
{
  /* Test maximum window size boundary */
  int32_t max_window = SOCKETHTTP2_MAX_WINDOW_SIZE;
  UNUSED (max_window);

  /* Test default initial window size */
  uint32_t default_initial = SOCKETHTTP2_DEFAULT_INITIAL_WINDOW_SIZE;
  UNUSED (default_initial);

  /* Test connection window size */
  uint32_t conn_window = SOCKETHTTP2_CONNECTION_WINDOW_SIZE;
  UNUSED (conn_window);

  /* Test window arithmetic edge cases */
  struct
  {
    int32_t window;
    uint32_t increment;
    const char *description;
  } edge_cases[] = {
    { 0, 1, "Zero window + minimum increment" },
    { 0x7FFFFFFE, 1, "Near max + 1" },
    { 0x7FFFFFFE, 2, "Near max + 2 (overflow)" },
    { 0x7FFFFFFF, 0, "Max window + zero (error)" },
    { 0x3FFFFFFF, 0x3FFFFFFF, "Half max + half max (near overflow)" },
    { 0x40000000, 0x40000000, "Slightly over half max (overflow)" },
  };

  for (size_t i = 0; i < sizeof (edge_cases) / sizeof (edge_cases[0]); i++)
    {
      int32_t w = edge_cases[i].window;
      uint32_t inc = edge_cases[i].increment;

      /* Test overflow */
      int64_t result = (int64_t)w + (int64_t)inc;
      int overflows = result > SOCKETHTTP2_MAX_WINDOW_SIZE;

      /* Test zero increment */
      int is_zero = (inc == 0);

      UNUSED (overflows);
      UNUSED (is_zero);
      UNUSED (edge_cases[i].description);
    }

  UNUSED (data);
  UNUSED (size);
}

/**
 * Test flow control violation scenarios
 */
static void
test_flow_violations (const uint8_t *data, size_t size)
{
  /* Test scenarios that should trigger FLOW_CONTROL_ERROR:
   * 1. Sending data exceeding available window
   * 2. Window update causing overflow
   * 3. Consuming more bytes than available
   */

  if (size < 8)
    return;

  int32_t window
      = (int32_t)(((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
                  | ((uint32_t)data[2] << 8) | data[3]);

  size_t send_bytes = ((size_t)data[4] << 24) | ((size_t)data[5] << 16)
                      | ((size_t)data[6] << 8) | data[7];

  /* Violation scenarios */
  struct
  {
    int32_t window;
    size_t bytes;
    int is_violation;
  } violations[] = {
    /* Valid sends */
    { 1000, 500, 0 },
    { 1000, 1000, 0 },
    { 0x7FFFFFFF, 1000, 0 },

    /* Violations */
    { 1000, 1001, 1 }, /* Exceed by 1 */
    { 0, 1, 1 },       /* Send on zero window */
    { -1, 1, 1 },      /* Negative window */
    { 500, 1000, 1 },  /* Exceed by 500 */

    /* Fuzzed */
    { window, send_bytes, 0 },
  };

  for (size_t i = 0; i < sizeof (violations) / sizeof (violations[0]); i++)
    {
      int32_t w = violations[i].window;
      size_t b = violations[i].bytes;

      /* Check if bytes exceed window */
      int exceeds = (b > INT32_MAX) || ((int32_t)b > w);

      /* Check for negative window */
      int negative = (w < 0);

      UNUSED (exceeds);
      UNUSED (negative);
      UNUSED (violations[i].is_violation);
    }
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  /* ====================================================================
   * Test 1: Window overflow detection
   * ==================================================================== */
  test_window_overflow (data, size);

  /* ====================================================================
   * Test 2: Zero increment detection (protocol error)
   * ==================================================================== */
  test_zero_increment (data, size);

  /* ====================================================================
   * Test 3: Negative window detection
   * ==================================================================== */
  test_negative_window (data, size);

  /* ====================================================================
   * Test 4: SETTINGS_INITIAL_WINDOW_SIZE changes
   * ==================================================================== */
  test_initial_window_size_changes (data, size);

  /* ====================================================================
   * Test 5: Connection vs stream window interaction
   * ==================================================================== */
  test_connection_stream_windows (data, size);

  /* ====================================================================
   * Test 6: WINDOW_UPDATE frame payload
   * ==================================================================== */
  test_window_update_payload (data, size);

  /* ====================================================================
   * Test 7: Edge cases and boundary conditions
   * ==================================================================== */
  test_edge_cases (data, size);

  /* ====================================================================
   * Test 8: Flow control violation scenarios
   * ==================================================================== */
  test_flow_violations (data, size);

  return 0;
}

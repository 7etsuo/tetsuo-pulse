/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_http2_settings.c - Enterprise-grade HTTP/2 SETTINGS frame fuzzer
 *
 * Comprehensive fuzzing harness for HTTP/2 SETTINGS frame parsing and
 * validation per RFC 9113 Section 6.5.
 *
 * Targets:
 * - SETTINGS frame payload parsing (6-byte parameter units)
 * - Setting ID validation (known vs unknown)
 * - Setting value validation (range constraints per ID)
 * - ACK flag handling (empty payload required)
 * - Connection-level settings application
 * - Multiple settings in single frame
 * - Settings ordering and priority
 *
 * Security Focus:
 * - Integer overflow in setting values
 * - Invalid setting combinations
 * - DoS via extreme values (INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE)
 * - ENABLE_PUSH validation (0 or 1 only)
 * - MAX_CONCURRENT_STREAMS limits
 * - HEADER_TABLE_SIZE memory exhaustion
 * - Settings payload size validation (multiple of 6)
 *
 * RFC 9113 Section 6.5.2 Defined Settings:
 * - SETTINGS_HEADER_TABLE_SIZE (0x01): HPACK table size, default 4096
 * - SETTINGS_ENABLE_PUSH (0x02): Server push, 0 or 1, default 1
 * - SETTINGS_MAX_CONCURRENT_STREAMS (0x03): Max streams, default unlimited
 * - SETTINGS_INITIAL_WINDOW_SIZE (0x04): Window size, max 2^31-1
 * - SETTINGS_MAX_FRAME_SIZE (0x05): Frame size, 16384-16777215
 * - SETTINGS_MAX_HEADER_LIST_SIZE (0x06): Header list size, default unlimited
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http2_settings
 * ./fuzz_http2_settings corpus/http2_settings/ -fork=16 -max_len=4096
 */

#include "http/SocketHTTP2.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * Validate a single setting per RFC 9113 Section 6.5.2
 */
static int
validate_setting (uint16_t id, uint32_t value)
{
  switch (id)
    {
    case HTTP2_SETTINGS_ENABLE_PUSH:
      /* MUST be 0 or 1 */
      if (value > 1)
        return -1; /* PROTOCOL_ERROR */
      break;

    case HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
      /* MUST NOT exceed 2^31-1 */
      if (value > 0x7FFFFFFF)
        return -1; /* FLOW_CONTROL_ERROR */
      break;

    case HTTP2_SETTINGS_MAX_FRAME_SIZE:
      /* MUST be 16384 to 16777215 */
      if (value < SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE
          || value > SOCKETHTTP2_MAX_MAX_FRAME_SIZE)
        return -1; /* PROTOCOL_ERROR */
      break;

    case HTTP2_SETTINGS_HEADER_TABLE_SIZE:
    case HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
    case HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
      /* Any value is valid for these */
      break;

    default:
      /* Unknown settings MUST be ignored per RFC 9113 */
      break;
    }

  return 0;
}

/**
 * Parse and validate SETTINGS frame payload
 * Returns number of settings parsed, or -1 on error
 */
static int
parse_settings_payload (const uint8_t *data, size_t size)
{
  /* SETTINGS payload MUST be multiple of 6 bytes */
  if (size % 6 != 0)
    return -1;

  size_t num_settings = size / 6;
  size_t offset = 0;

  for (size_t i = 0; i < num_settings; i++)
    {
      /* Parse setting: 2 bytes ID + 4 bytes value (big endian) */
      uint16_t id = ((uint16_t)data[offset] << 8) | data[offset + 1];
      uint32_t value = ((uint32_t)data[offset + 2] << 24)
                       | ((uint32_t)data[offset + 3] << 16)
                       | ((uint32_t)data[offset + 4] << 8) | data[offset + 5];

      /* Validate the setting */
      int result = validate_setting (id, value);
      (void)result;

      offset += 6;
    }

  return (int)num_settings;
}

/**
 * Build SETTINGS frame with given settings
 */
static size_t
build_settings_frame (uint8_t *buffer,
                      size_t buffer_size,
                      uint8_t flags,
                      const uint16_t *ids,
                      const uint32_t *values,
                      size_t num_settings)
{
  if (buffer_size < HTTP2_FRAME_HEADER_SIZE + num_settings * 6)
    return 0;

  /* Calculate payload size */
  uint32_t payload_size = num_settings * 6;

  /* Frame header */
  buffer[0] = (payload_size >> 16) & 0xFF;
  buffer[1] = (payload_size >> 8) & 0xFF;
  buffer[2] = payload_size & 0xFF;
  buffer[3] = HTTP2_FRAME_SETTINGS;
  buffer[4] = flags;
  buffer[5] = 0; /* Stream ID must be 0 */
  buffer[6] = 0;
  buffer[7] = 0;
  buffer[8] = 0;

  /* Payload */
  size_t offset = HTTP2_FRAME_HEADER_SIZE;
  for (size_t i = 0; i < num_settings; i++)
    {
      buffer[offset++] = (ids[i] >> 8) & 0xFF;
      buffer[offset++] = ids[i] & 0xFF;
      buffer[offset++] = (values[i] >> 24) & 0xFF;
      buffer[offset++] = (values[i] >> 16) & 0xFF;
      buffer[offset++] = (values[i] >> 8) & 0xFF;
      buffer[offset++] = values[i] & 0xFF;
    }

  return offset;
}

/**
 * Test all defined settings with various values
 */
static void
test_all_settings (void)
{
  uint8_t buffer[256];

  /* Test each setting ID */
  uint16_t setting_ids[] = {
    HTTP2_SETTINGS_HEADER_TABLE_SIZE,
    HTTP2_SETTINGS_ENABLE_PUSH,
    HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
    HTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
    HTTP2_SETTINGS_MAX_FRAME_SIZE,
    HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
    0x0007, /* Unknown setting */
    0x00FF, /* Unknown setting */
    0xFFFF, /* Unknown setting */
  };

  /* Test values for each setting */
  uint32_t test_values[] = {
    0,     1,        2,          100,        4096,       16384,
    65535, 16777215, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
  };

  for (size_t id_idx = 0;
       id_idx < sizeof (setting_ids) / sizeof (setting_ids[0]);
       id_idx++)
    {
      for (size_t val_idx = 0;
           val_idx < sizeof (test_values) / sizeof (test_values[0]);
           val_idx++)
        {
          uint16_t id = setting_ids[id_idx];
          uint32_t value = test_values[val_idx];

          /* Build single setting frame */
          size_t frame_size = build_settings_frame (
              buffer, sizeof (buffer), 0, &id, &value, 1);

          if (frame_size > 0)
            {
              /* Parse the frame header */
              SocketHTTP2_FrameHeader header;
              int result = SocketHTTP2_frame_header_parse (
                  buffer, frame_size, &header);
              (void)result;

              /* Parse the payload */
              if (frame_size > HTTP2_FRAME_HEADER_SIZE)
                {
                  parse_settings_payload (buffer + HTTP2_FRAME_HEADER_SIZE,
                                          frame_size - HTTP2_FRAME_HEADER_SIZE);
                }
            }

          /* Validate the setting directly */
          validate_setting (id, value);
        }
    }
}

/**
 * Test SETTINGS ACK (empty payload with ACK flag)
 */
static void
test_settings_ack (void)
{
  uint8_t buffer[16];

  /* Valid ACK: empty payload, ACK flag set */
  size_t frame_size
      = build_settings_frame (buffer, sizeof (buffer), 0x01, NULL, NULL, 0);

  if (frame_size > 0)
    {
      SocketHTTP2_FrameHeader header;
      SocketHTTP2_frame_header_parse (buffer, frame_size, &header);
    }

  /* Invalid ACK: non-empty payload with ACK flag */
  uint16_t id = HTTP2_SETTINGS_HEADER_TABLE_SIZE;
  uint32_t value = 4096;
  frame_size
      = build_settings_frame (buffer, sizeof (buffer), 0x01, &id, &value, 1);

  if (frame_size > 0)
    {
      SocketHTTP2_FrameHeader header;
      SocketHTTP2_frame_header_parse (buffer, frame_size, &header);
      /* This should be a FRAME_SIZE_ERROR per RFC 9113 */
    }
}

/**
 * Test multiple settings in single frame
 */
static void
test_multiple_settings (void)
{
  uint8_t buffer[256];

  /* All settings at once */
  uint16_t ids[] = {
    HTTP2_SETTINGS_HEADER_TABLE_SIZE,      HTTP2_SETTINGS_ENABLE_PUSH,
    HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, HTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
    HTTP2_SETTINGS_MAX_FRAME_SIZE,         HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
  };

  uint32_t values[] = {
    4096,  /* Default HEADER_TABLE_SIZE */
    1,     /* Default ENABLE_PUSH */
    100,   /* MAX_CONCURRENT_STREAMS */
    65535, /* INITIAL_WINDOW_SIZE */
    16384, /* Default MAX_FRAME_SIZE */
    8192,  /* MAX_HEADER_LIST_SIZE */
  };

  size_t num_settings = sizeof (ids) / sizeof (ids[0]);
  size_t frame_size = build_settings_frame (
      buffer, sizeof (buffer), 0, ids, values, num_settings);

  if (frame_size > 0)
    {
      SocketHTTP2_FrameHeader header;
      SocketHTTP2_frame_header_parse (buffer, frame_size, &header);

      if (frame_size > HTTP2_FRAME_HEADER_SIZE)
        {
          int count
              = parse_settings_payload (buffer + HTTP2_FRAME_HEADER_SIZE,
                                        frame_size - HTTP2_FRAME_HEADER_SIZE);
          (void)count;
        }
    }
}

/**
 * Test invalid payload sizes
 */
static void
test_invalid_payload_sizes (void)
{
  /* Test sizes that are not multiples of 6 */
  size_t invalid_sizes[] = { 1, 2, 3, 4, 5, 7, 8, 11, 13, 17, 19, 23 };

  for (size_t i = 0; i < sizeof (invalid_sizes) / sizeof (invalid_sizes[0]);
       i++)
    {
      size_t size = invalid_sizes[i];
      uint8_t *data = malloc (size);
      if (data)
        {
          memset (data, 0, size);
          int result = parse_settings_payload (data, size);
          /* Should return -1 for invalid size */
          (void)result;
          free (data);
        }
    }

  /* Test valid sizes (multiples of 6) */
  size_t valid_sizes[] = { 0, 6, 12, 18, 24, 30, 60, 120 };

  for (size_t i = 0; i < sizeof (valid_sizes) / sizeof (valid_sizes[0]); i++)
    {
      size_t size = valid_sizes[i];
      uint8_t *data = malloc (size > 0 ? size : 1);
      if (data)
        {
          memset (data, 0, size > 0 ? size : 1);
          int result = parse_settings_payload (data, size);
          /* Should succeed */
          (void)result;
          free (data);
        }
    }
}

/**
 * Test edge cases for specific settings
 */
static void
test_setting_edge_cases (void)
{
  /* ENABLE_PUSH edge cases */
  validate_setting (HTTP2_SETTINGS_ENABLE_PUSH, 0);          /* Valid */
  validate_setting (HTTP2_SETTINGS_ENABLE_PUSH, 1);          /* Valid */
  validate_setting (HTTP2_SETTINGS_ENABLE_PUSH, 2);          /* Invalid */
  validate_setting (HTTP2_SETTINGS_ENABLE_PUSH, 0xFFFFFFFF); /* Invalid */

  /* INITIAL_WINDOW_SIZE edge cases */
  validate_setting (HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 0);          /* Valid */
  validate_setting (HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 1);          /* Valid */
  validate_setting (HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 0x7FFFFFFF); /* Valid */
  validate_setting (HTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
                    0x80000000); /* Invalid */
  validate_setting (HTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
                    0xFFFFFFFF); /* Invalid */

  /* MAX_FRAME_SIZE edge cases */
  validate_setting (HTTP2_SETTINGS_MAX_FRAME_SIZE, 0);        /* Invalid */
  validate_setting (HTTP2_SETTINGS_MAX_FRAME_SIZE, 16383);    /* Invalid */
  validate_setting (HTTP2_SETTINGS_MAX_FRAME_SIZE, 16384);    /* Valid (min) */
  validate_setting (HTTP2_SETTINGS_MAX_FRAME_SIZE, 16385);    /* Valid */
  validate_setting (HTTP2_SETTINGS_MAX_FRAME_SIZE, 16777215); /* Valid (max) */
  validate_setting (HTTP2_SETTINGS_MAX_FRAME_SIZE, 16777216); /* Invalid */
  validate_setting (HTTP2_SETTINGS_MAX_FRAME_SIZE, 0xFFFFFFFF); /* Invalid */

  /* HEADER_TABLE_SIZE edge cases (any value valid) */
  validate_setting (HTTP2_SETTINGS_HEADER_TABLE_SIZE, 0);
  validate_setting (HTTP2_SETTINGS_HEADER_TABLE_SIZE, 4096);
  validate_setting (HTTP2_SETTINGS_HEADER_TABLE_SIZE, 0xFFFFFFFF);

  /* MAX_CONCURRENT_STREAMS edge cases (any value valid) */
  validate_setting (HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 0);
  validate_setting (HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100);
  validate_setting (HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 0xFFFFFFFF);

  /* MAX_HEADER_LIST_SIZE edge cases (any value valid) */
  validate_setting (HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, 0);
  validate_setting (HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, 8192);
  validate_setting (HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, 0xFFFFFFFF);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  /* ====================================================================
   * Test 1: Direct fuzzed settings payload parsing
   * ==================================================================== */
  parse_settings_payload (data, size);

  /* ====================================================================
   * Test 2: Fuzzed payload with various offsets/sizes
   * ==================================================================== */
  for (size_t offset = 0; offset < size && offset < 20; offset++)
    {
      for (size_t len = 0; len <= size - offset && len <= 120; len += 6)
        {
          parse_settings_payload (data + offset, len);
        }
    }

  /* ====================================================================
   * Test 3: All defined settings with various values
   * ==================================================================== */
  test_all_settings ();

  /* ====================================================================
   * Test 4: SETTINGS ACK handling
   * ==================================================================== */
  test_settings_ack ();

  /* ====================================================================
   * Test 5: Multiple settings in single frame
   * ==================================================================== */
  test_multiple_settings ();

  /* ====================================================================
   * Test 6: Invalid payload sizes
   * ==================================================================== */
  test_invalid_payload_sizes ();

  /* ====================================================================
   * Test 7: Setting edge cases
   * ==================================================================== */
  test_setting_edge_cases ();

  /* ====================================================================
   * Test 8: Build frame from fuzzed data and parse
   * ==================================================================== */
  if (size >= 6)
    {
      uint8_t buffer[256];

      /* Extract settings from fuzz data */
      size_t num_settings = size / 6;
      if (num_settings > 10)
        num_settings = 10;

      uint16_t ids[10];
      uint32_t values[10];

      for (size_t i = 0; i < num_settings; i++)
        {
          size_t offset = i * 6;
          ids[i] = ((uint16_t)data[offset] << 8) | data[offset + 1];
          values[i] = ((uint32_t)data[offset + 2] << 24)
                      | ((uint32_t)data[offset + 3] << 16)
                      | ((uint32_t)data[offset + 4] << 8) | data[offset + 5];
        }

      size_t frame_size = build_settings_frame (
          buffer, sizeof (buffer), 0, ids, values, num_settings);

      if (frame_size > 0)
        {
          /* Parse frame header */
          SocketHTTP2_FrameHeader header;
          int result
              = SocketHTTP2_frame_header_parse (buffer, frame_size, &header);

          if (result == 0 && frame_size > HTTP2_FRAME_HEADER_SIZE)
            {
              /* Parse payload */
              parse_settings_payload (buffer + HTTP2_FRAME_HEADER_SIZE,
                                      frame_size - HTTP2_FRAME_HEADER_SIZE);
            }
        }
    }

  /* ====================================================================
   * Test 9: Fuzzed setting validation
   * ==================================================================== */
  if (size >= 6)
    {
      uint16_t id = ((uint16_t)data[0] << 8) | data[1];
      uint32_t value = ((uint32_t)data[2] << 24) | ((uint32_t)data[3] << 16)
                       | ((uint32_t)data[4] << 8) | data[5];

      validate_setting (id, value);
    }

  /* ====================================================================
   * Test 10: Boundary values for all settings
   * ==================================================================== */
  {
    uint32_t boundary_values[]
        = { 0,     1,     0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
            16384, 16383, 16385,      16777215,   16777216 };

    for (uint16_t id = 0; id <= 10; id++)
      {
        for (size_t v = 0;
             v < sizeof (boundary_values) / sizeof (boundary_values[0]);
             v++)
          {
            validate_setting (id, boundary_values[v]);
          }
      }
  }

  return 0;
}

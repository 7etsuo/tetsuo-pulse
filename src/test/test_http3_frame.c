/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_http3_frame.c
 * @brief Unit tests for HTTP/3 frame parser/serializer (RFC 9114 Section 7).
 */

#include <string.h>

#include "http/SocketHTTP3-constants.h"
#include "http/SocketHTTP3-frame.h"
#include "quic/SocketQUICVarInt.h"
#include "test/Test.h"

TEST (h3_frame_header_roundtrip_data)
{
  uint8_t buf[16];
  int written = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_DATA, 100, buf, sizeof (buf));
  ASSERT (written > 0);

  SocketHTTP3_FrameHeader header;
  size_t consumed;
  SocketHTTP3_ParseResult res = SocketHTTP3_Frame_parse_header (
      buf, (size_t)written, &header, &consumed);
  ASSERT_EQ (HTTP3_PARSE_OK, res);
  ASSERT_EQ (HTTP3_FRAME_DATA, header.type);
  ASSERT_EQ (100ULL, header.length);
  ASSERT_EQ ((size_t)written, consumed);
}

TEST (h3_frame_header_roundtrip_headers)
{
  uint8_t buf[16];
  int written = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_HEADERS, 256, buf, sizeof (buf));
  ASSERT (written > 0);

  SocketHTTP3_FrameHeader header;
  size_t consumed;
  SocketHTTP3_ParseResult res = SocketHTTP3_Frame_parse_header (
      buf, (size_t)written, &header, &consumed);
  ASSERT_EQ (HTTP3_PARSE_OK, res);
  ASSERT_EQ (HTTP3_FRAME_HEADERS, header.type);
  ASSERT_EQ (256ULL, header.length);
}

TEST (h3_frame_header_roundtrip_settings)
{
  uint8_t buf[16];
  int written = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_SETTINGS, 0, buf, sizeof (buf));
  ASSERT (written > 0);

  SocketHTTP3_FrameHeader header;
  size_t consumed;
  SocketHTTP3_ParseResult res = SocketHTTP3_Frame_parse_header (
      buf, (size_t)written, &header, &consumed);
  ASSERT_EQ (HTTP3_PARSE_OK, res);
  ASSERT_EQ (HTTP3_FRAME_SETTINGS, header.type);
  ASSERT_EQ (0ULL, header.length);
}

TEST (h3_frame_header_roundtrip_goaway)
{
  uint8_t buf[16];
  int written = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_GOAWAY, 8, buf, sizeof (buf));
  ASSERT (written > 0);

  SocketHTTP3_FrameHeader header;
  size_t consumed;
  SocketHTTP3_ParseResult res = SocketHTTP3_Frame_parse_header (
      buf, (size_t)written, &header, &consumed);
  ASSERT_EQ (HTTP3_PARSE_OK, res);
  ASSERT_EQ (HTTP3_FRAME_GOAWAY, header.type);
  ASSERT_EQ (8ULL, header.length);
}

TEST (h3_frame_header_roundtrip_max_push_id)
{
  uint8_t buf[16];
  int written = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_MAX_PUSH_ID, 4, buf, sizeof (buf));
  ASSERT (written > 0);

  SocketHTTP3_FrameHeader header;
  size_t consumed;
  SocketHTTP3_ParseResult res = SocketHTTP3_Frame_parse_header (
      buf, (size_t)written, &header, &consumed);
  ASSERT_EQ (HTTP3_PARSE_OK, res);
  ASSERT_EQ (HTTP3_FRAME_MAX_PUSH_ID, header.type);
}

TEST (h3_frame_header_roundtrip_cancel_push)
{
  uint8_t buf[16];
  int written = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_CANCEL_PUSH, 2, buf, sizeof (buf));
  ASSERT (written > 0);

  SocketHTTP3_FrameHeader header;
  size_t consumed;
  SocketHTTP3_ParseResult res = SocketHTTP3_Frame_parse_header (
      buf, (size_t)written, &header, &consumed);
  ASSERT_EQ (HTTP3_PARSE_OK, res);
  ASSERT_EQ (HTTP3_FRAME_CANCEL_PUSH, header.type);
}

TEST (h3_frame_header_roundtrip_push_promise)
{
  uint8_t buf[16];
  int written = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_PUSH_PROMISE, 1024, buf, sizeof (buf));
  ASSERT (written > 0);

  SocketHTTP3_FrameHeader header;
  size_t consumed;
  SocketHTTP3_ParseResult res = SocketHTTP3_Frame_parse_header (
      buf, (size_t)written, &header, &consumed);
  ASSERT_EQ (HTTP3_PARSE_OK, res);
  ASSERT_EQ (HTTP3_FRAME_PUSH_PROMISE, header.type);
  ASSERT_EQ (1024ULL, header.length);
}

TEST (h3_frame_header_boundary_1byte)
{
  /* Type 0 (1-byte varint), length 63 (1-byte varint max) */
  uint8_t buf[16];
  int written = SocketHTTP3_Frame_write_header (0, 63, buf, sizeof (buf));
  ASSERT_EQ (2, written);

  SocketHTTP3_FrameHeader header;
  size_t consumed;
  SocketHTTP3_ParseResult res = SocketHTTP3_Frame_parse_header (
      buf, (size_t)written, &header, &consumed);
  ASSERT_EQ (HTTP3_PARSE_OK, res);
  ASSERT_EQ (0ULL, header.type);
  ASSERT_EQ (63ULL, header.length);
}

TEST (h3_frame_header_boundary_2byte)
{
  /* Length 16383 (2-byte varint max) */
  uint8_t buf[16];
  int written = SocketHTTP3_Frame_write_header (0, 16383, buf, sizeof (buf));
  ASSERT (written > 0);

  SocketHTTP3_FrameHeader header;
  size_t consumed;
  SocketHTTP3_ParseResult res = SocketHTTP3_Frame_parse_header (
      buf, (size_t)written, &header, &consumed);
  ASSERT_EQ (HTTP3_PARSE_OK, res);
  ASSERT_EQ (16383ULL, header.length);
}

TEST (h3_frame_header_boundary_4byte)
{
  /* Length 1073741823 (4-byte varint max) */
  uint8_t buf[16];
  int written
      = SocketHTTP3_Frame_write_header (0, 1073741823ULL, buf, sizeof (buf));
  ASSERT (written > 0);

  SocketHTTP3_FrameHeader header;
  size_t consumed;
  SocketHTTP3_ParseResult res = SocketHTTP3_Frame_parse_header (
      buf, (size_t)written, &header, &consumed);
  ASSERT_EQ (HTTP3_PARSE_OK, res);
  ASSERT_EQ (1073741823ULL, header.length);
}

TEST (h3_frame_header_boundary_8byte)
{
  /* Length requiring 8-byte varint */
  uint64_t big_val = 1073741824ULL;
  uint8_t buf[16];
  int written = SocketHTTP3_Frame_write_header (0, big_val, buf, sizeof (buf));
  ASSERT (written > 0);

  SocketHTTP3_FrameHeader header;
  size_t consumed;
  SocketHTTP3_ParseResult res = SocketHTTP3_Frame_parse_header (
      buf, (size_t)written, &header, &consumed);
  ASSERT_EQ (HTTP3_PARSE_OK, res);
  ASSERT_EQ (big_val, header.length);
}

TEST (h3_frame_header_incomplete_empty)
{
  SocketHTTP3_FrameHeader header;
  size_t consumed;
  SocketHTTP3_ParseResult res
      = SocketHTTP3_Frame_parse_header (NULL, 0, &header, &consumed);
  ASSERT_EQ (HTTP3_PARSE_INCOMPLETE, res);
}

TEST (h3_frame_header_incomplete_type_only)
{
  /* Encode just the type, no length */
  uint8_t buf[1] = { 0x04 }; /* SETTINGS type = 0x04 */
  SocketHTTP3_FrameHeader header;
  size_t consumed;
  SocketHTTP3_ParseResult res
      = SocketHTTP3_Frame_parse_header (buf, 1, &header, &consumed);
  ASSERT_EQ (HTTP3_PARSE_INCOMPLETE, res);
}

TEST (h3_settings_init_defaults)
{
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  ASSERT_EQ (UINT64_MAX, settings.max_field_section_size);
  ASSERT_EQ (0ULL, settings.qpack_max_table_capacity);
  ASSERT_EQ (0ULL, settings.qpack_blocked_streams);
}

TEST (h3_settings_parse_known_params)
{
  /* Encode: QPACK_MAX_TABLE_CAPACITY=4096, MAX_FIELD_SECTION_SIZE=8192,
   * QPACK_BLOCKED_STREAMS=100 */
  uint8_t buf[48];
  size_t pos = 0;

  encode_varint_field (
      H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, buf, &pos, sizeof (buf));
  encode_varint_field (4096, buf, &pos, sizeof (buf));
  encode_varint_field (
      H3_SETTINGS_MAX_FIELD_SECTION_SIZE, buf, &pos, sizeof (buf));
  encode_varint_field (8192, buf, &pos, sizeof (buf));
  encode_varint_field (
      H3_SETTINGS_QPACK_BLOCKED_STREAMS, buf, &pos, sizeof (buf));
  encode_varint_field (100, buf, &pos, sizeof (buf));

  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  int ret = SocketHTTP3_Settings_parse (buf, pos, &settings);
  ASSERT_EQ (0, ret);
  ASSERT_EQ (4096ULL, settings.qpack_max_table_capacity);
  ASSERT_EQ (8192ULL, settings.max_field_section_size);
  ASSERT_EQ (100ULL, settings.qpack_blocked_streams);
}

TEST (h3_settings_parse_unknown_params)
{
  /* Unknown setting ID 0xFF with value 42 — should be silently ignored */
  uint8_t buf[16];
  size_t pos = 0;

  encode_varint_field (0xFF, buf, &pos, sizeof (buf));
  encode_varint_field (42, buf, &pos, sizeof (buf));

  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  int ret = SocketHTTP3_Settings_parse (buf, pos, &settings);
  ASSERT_EQ (0, ret);
  /* Settings should remain at defaults */
  ASSERT_EQ (UINT64_MAX, settings.max_field_section_size);
  ASSERT_EQ (0ULL, settings.qpack_max_table_capacity);
  ASSERT_EQ (0ULL, settings.qpack_blocked_streams);
}

TEST (h3_settings_parse_grease_params)
{
  /* GREASE setting 0x21 (0x1f*0 + 0x21) with value 999 — silently ignored */
  uint8_t buf[16];
  size_t pos = 0;

  encode_varint_field (0x21, buf, &pos, sizeof (buf));
  encode_varint_field (999, buf, &pos, sizeof (buf));

  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  int ret = SocketHTTP3_Settings_parse (buf, pos, &settings);
  ASSERT_EQ (0, ret);
  ASSERT_EQ (UINT64_MAX, settings.max_field_section_size);
}

TEST (h3_settings_parse_duplicate_id)
{
  /* Duplicate QPACK_MAX_TABLE_CAPACITY → H3_SETTINGS_ERROR */
  uint8_t buf[32];
  size_t pos = 0;

  encode_varint_field (
      H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, buf, &pos, sizeof (buf));
  encode_varint_field (100, buf, &pos, sizeof (buf));
  encode_varint_field (
      H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, buf, &pos, sizeof (buf));
  encode_varint_field (200, buf, &pos, sizeof (buf));

  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  int ret = SocketHTTP3_Settings_parse (buf, pos, &settings);
  ASSERT_EQ (-(int)H3_SETTINGS_ERROR, ret);
}

TEST (h3_settings_parse_duplicate_unknown_id)
{
  /* Duplicate unknown ID 0xAA → H3_SETTINGS_ERROR */
  uint8_t buf[32];
  size_t pos = 0;

  encode_varint_field (0xAA, buf, &pos, sizeof (buf));
  encode_varint_field (1, buf, &pos, sizeof (buf));
  encode_varint_field (0xAA, buf, &pos, sizeof (buf));
  encode_varint_field (2, buf, &pos, sizeof (buf));

  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  int ret = SocketHTTP3_Settings_parse (buf, pos, &settings);
  ASSERT_EQ (-(int)H3_SETTINGS_ERROR, ret);
}

TEST (h3_settings_parse_reserved_h2_id)
{
  /* Reserved HTTP/2 setting 0x02 (ENABLE_PUSH) → H3_SETTINGS_ERROR */
  uint8_t buf[16];
  size_t pos = 0;

  encode_varint_field (0x02, buf, &pos, sizeof (buf));
  encode_varint_field (1, buf, &pos, sizeof (buf));

  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  int ret = SocketHTTP3_Settings_parse (buf, pos, &settings);
  ASSERT_EQ (-(int)H3_SETTINGS_ERROR, ret);
}

TEST (h3_settings_parse_reserved_h2_ids_all)
{
  /* All reserved HTTP/2 settings (0x02-0x05) must be rejected */
  for (uint64_t id = 0x02; id <= 0x05; id++)
    {
      uint8_t buf[16];
      size_t pos = 0;
      encode_varint_field (id, buf, &pos, sizeof (buf));
      encode_varint_field (0, buf, &pos, sizeof (buf));

      SocketHTTP3_Settings settings;
      SocketHTTP3_Settings_init (&settings);
      int ret = SocketHTTP3_Settings_parse (buf, pos, &settings);
      ASSERT_EQ (-(int)H3_SETTINGS_ERROR, ret);
    }
}

TEST (h3_settings_roundtrip)
{
  SocketHTTP3_Settings orig;
  SocketHTTP3_Settings_init (&orig);
  orig.qpack_max_table_capacity = 4096;
  orig.max_field_section_size = 16384;
  orig.qpack_blocked_streams = 128;

  uint8_t buf[HTTP3_SETTINGS_MAX_WRITE_SIZE];
  int written = SocketHTTP3_Settings_write (&orig, buf, sizeof (buf));
  ASSERT (written > 0);

  SocketHTTP3_Settings parsed;
  SocketHTTP3_Settings_init (&parsed);
  int ret = SocketHTTP3_Settings_parse (buf, (size_t)written, &parsed);
  ASSERT_EQ (0, ret);
  ASSERT_EQ (orig.qpack_max_table_capacity, parsed.qpack_max_table_capacity);
  ASSERT_EQ (orig.max_field_section_size, parsed.max_field_section_size);
  ASSERT_EQ (orig.qpack_blocked_streams, parsed.qpack_blocked_streams);
}

TEST (h3_settings_write_defaults_empty)
{
  /* Default settings should produce zero bytes (nothing to write) */
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);

  uint8_t buf[48];
  int written = SocketHTTP3_Settings_write (&settings, buf, sizeof (buf));
  ASSERT_EQ (0, written);
}

TEST (h3_goaway_roundtrip)
{
  uint8_t buf[8];
  int written = SocketHTTP3_Goaway_write (42, buf, sizeof (buf));
  ASSERT (written > 0);

  uint64_t id;
  int ret = SocketHTTP3_Goaway_parse (buf, (size_t)written, &id);
  ASSERT_EQ (0, ret);
  ASSERT_EQ (42ULL, id);
}

TEST (h3_goaway_roundtrip_large)
{
  uint64_t big_id = 1073741824ULL;
  uint8_t buf[8];
  int written = SocketHTTP3_Goaway_write (big_id, buf, sizeof (buf));
  ASSERT (written > 0);

  uint64_t id;
  int ret = SocketHTTP3_Goaway_parse (buf, (size_t)written, &id);
  ASSERT_EQ (0, ret);
  ASSERT_EQ (big_id, id);
}

TEST (h3_max_push_id_roundtrip)
{
  uint8_t buf[8];
  int written = SocketHTTP3_MaxPushId_write (7, buf, sizeof (buf));
  ASSERT (written > 0);

  uint64_t id;
  int ret = SocketHTTP3_MaxPushId_parse (buf, (size_t)written, &id);
  ASSERT_EQ (0, ret);
  ASSERT_EQ (7ULL, id);
}

TEST (h3_cancel_push_roundtrip)
{
  uint8_t buf[8];
  int written = SocketHTTP3_CancelPush_write (99, buf, sizeof (buf));
  ASSERT (written > 0);

  uint64_t push_id;
  int ret = SocketHTTP3_CancelPush_parse (buf, (size_t)written, &push_id);
  ASSERT_EQ (0, ret);
  ASSERT_EQ (99ULL, push_id);
}

TEST (h3_push_promise_parse_id)
{
  /* Simulate: push_id=5, followed by 10 bytes of encoded field section */
  uint8_t buf[16];
  size_t pos = 0;
  encode_varint_field (5, buf, &pos, sizeof (buf));
  /* Fill remaining with dummy field section data */
  memset (buf + pos, 0xAB, 10);
  size_t total = pos + 10;

  uint64_t push_id;
  size_t payload_offset;
  int ret = SocketHTTP3_PushPromise_parse_id (
      buf, total, &push_id, &payload_offset);
  ASSERT_EQ (0, ret);
  ASSERT_EQ (5ULL, push_id);
  ASSERT_EQ (pos, payload_offset);
  /* Verify remaining bytes are the field section */
  ASSERT_EQ ((unsigned char)0xAB, buf[payload_offset]);
}

TEST (h3_push_promise_parse_id_incomplete)
{
  uint64_t push_id;
  size_t payload_offset;
  int ret
      = SocketHTTP3_PushPromise_parse_id (NULL, 0, &push_id, &payload_offset);
  ASSERT_EQ (1, ret);
}

TEST (h3_validate_data_on_request)
{
  ASSERT_EQ (
      0ULL,
      SocketHTTP3_Frame_validate (HTTP3_FRAME_DATA, HTTP3_STREAM_REQUEST, 0));
}

TEST (h3_validate_data_on_push)
{
  ASSERT_EQ (
      0ULL,
      SocketHTTP3_Frame_validate (HTTP3_FRAME_DATA, HTTP3_STREAM_PUSH, 0));
}

TEST (h3_validate_data_on_control)
{
  ASSERT_EQ (
      H3_FRAME_UNEXPECTED,
      SocketHTTP3_Frame_validate (HTTP3_FRAME_DATA, HTTP3_STREAM_CONTROL, 0));
}

TEST (h3_validate_headers_on_request)
{
  ASSERT_EQ (0ULL,
             SocketHTTP3_Frame_validate (
                 HTTP3_FRAME_HEADERS, HTTP3_STREAM_REQUEST, 0));
}

TEST (h3_validate_headers_on_control)
{
  ASSERT_EQ (H3_FRAME_UNEXPECTED,
             SocketHTTP3_Frame_validate (
                 HTTP3_FRAME_HEADERS, HTTP3_STREAM_CONTROL, 0));
}

TEST (h3_validate_settings_on_control)
{
  ASSERT_EQ (0ULL,
             SocketHTTP3_Frame_validate (
                 HTTP3_FRAME_SETTINGS, HTTP3_STREAM_CONTROL, 1));
}

TEST (h3_validate_settings_on_request)
{
  ASSERT_EQ (H3_FRAME_UNEXPECTED,
             SocketHTTP3_Frame_validate (
                 HTTP3_FRAME_SETTINGS, HTTP3_STREAM_REQUEST, 0));
}

TEST (h3_validate_goaway_on_control)
{
  ASSERT_EQ (
      0ULL,
      SocketHTTP3_Frame_validate (HTTP3_FRAME_GOAWAY, HTTP3_STREAM_CONTROL, 0));
}

TEST (h3_validate_goaway_on_request)
{
  ASSERT_EQ (
      H3_FRAME_UNEXPECTED,
      SocketHTTP3_Frame_validate (HTTP3_FRAME_GOAWAY, HTTP3_STREAM_REQUEST, 0));
}

TEST (h3_validate_max_push_id_on_control)
{
  ASSERT_EQ (0ULL,
             SocketHTTP3_Frame_validate (
                 HTTP3_FRAME_MAX_PUSH_ID, HTTP3_STREAM_CONTROL, 0));
}

TEST (h3_validate_max_push_id_on_push)
{
  ASSERT_EQ (H3_FRAME_UNEXPECTED,
             SocketHTTP3_Frame_validate (
                 HTTP3_FRAME_MAX_PUSH_ID, HTTP3_STREAM_PUSH, 0));
}

TEST (h3_validate_cancel_push_on_control)
{
  ASSERT_EQ (0ULL,
             SocketHTTP3_Frame_validate (
                 HTTP3_FRAME_CANCEL_PUSH, HTTP3_STREAM_CONTROL, 0));
}

TEST (h3_validate_cancel_push_on_request)
{
  ASSERT_EQ (H3_FRAME_UNEXPECTED,
             SocketHTTP3_Frame_validate (
                 HTTP3_FRAME_CANCEL_PUSH, HTTP3_STREAM_REQUEST, 0));
}

TEST (h3_validate_push_promise_on_request)
{
  ASSERT_EQ (0ULL,
             SocketHTTP3_Frame_validate (
                 HTTP3_FRAME_PUSH_PROMISE, HTTP3_STREAM_REQUEST, 0));
}

TEST (h3_validate_push_promise_on_control)
{
  ASSERT_EQ (H3_FRAME_UNEXPECTED,
             SocketHTTP3_Frame_validate (
                 HTTP3_FRAME_PUSH_PROMISE, HTTP3_STREAM_CONTROL, 0));
}

TEST (h3_validate_push_promise_on_push)
{
  ASSERT_EQ (H3_FRAME_UNEXPECTED,
             SocketHTTP3_Frame_validate (
                 HTTP3_FRAME_PUSH_PROMISE, HTTP3_STREAM_PUSH, 0));
}

TEST (h3_validate_reserved_h2_frames)
{
  uint64_t reserved[] = { 0x02, 0x06, 0x08, 0x09 };
  for (size_t i = 0; i < sizeof (reserved) / sizeof (reserved[0]); i++)
    {
      ASSERT_EQ (
          H3_FRAME_UNEXPECTED,
          SocketHTTP3_Frame_validate (reserved[i], HTTP3_STREAM_REQUEST, 0));
      ASSERT_EQ (
          H3_FRAME_UNEXPECTED,
          SocketHTTP3_Frame_validate (reserved[i], HTTP3_STREAM_CONTROL, 0));
      ASSERT_EQ (
          H3_FRAME_UNEXPECTED,
          SocketHTTP3_Frame_validate (reserved[i], HTTP3_STREAM_PUSH, 0));
    }
}

TEST (h3_validate_grease_frames_allowed)
{
  /* GREASE values: 0x21, 0x40, 0x5f */
  ASSERT_EQ (0ULL, SocketHTTP3_Frame_validate (0x21, HTTP3_STREAM_REQUEST, 0));
  ASSERT_EQ (0ULL, SocketHTTP3_Frame_validate (0x40, HTTP3_STREAM_CONTROL, 0));
  ASSERT_EQ (0ULL, SocketHTTP3_Frame_validate (0x5f, HTTP3_STREAM_PUSH, 0));
}

TEST (h3_zero_length_data_valid)
{
  uint8_t buf[16];
  int written
      = SocketHTTP3_Frame_write_header (HTTP3_FRAME_DATA, 0, buf, sizeof (buf));
  ASSERT (written > 0);

  SocketHTTP3_FrameHeader header;
  size_t consumed;
  SocketHTTP3_ParseResult res = SocketHTTP3_Frame_parse_header (
      buf, (size_t)written, &header, &consumed);
  ASSERT_EQ (HTTP3_PARSE_OK, res);
  ASSERT_EQ (HTTP3_FRAME_DATA, header.type);
  ASSERT_EQ (0ULL, header.length);
}

TEST (h3_validate_first_frame_settings_ok)
{
  /* SETTINGS as first frame on control stream: allowed */
  ASSERT_EQ (0ULL,
             SocketHTTP3_Frame_validate (
                 HTTP3_FRAME_SETTINGS, HTTP3_STREAM_CONTROL, 1));
}

TEST (h3_validate_first_frame_not_settings)
{
  /* DATA as first frame on control stream: H3_MISSING_SETTINGS */
  ASSERT_EQ (
      H3_MISSING_SETTINGS,
      SocketHTTP3_Frame_validate (HTTP3_FRAME_DATA, HTTP3_STREAM_CONTROL, 1));
}

TEST (h3_validate_first_frame_goaway_missing_settings)
{
  /* GOAWAY as first frame on control stream: H3_MISSING_SETTINGS */
  ASSERT_EQ (
      H3_MISSING_SETTINGS,
      SocketHTTP3_Frame_validate (HTTP3_FRAME_GOAWAY, HTTP3_STREAM_CONTROL, 1));
}

TEST (h3_write_header_buffer_too_small)
{
  uint8_t buf[1]; /* Too small for type + length */
  int written = SocketHTTP3_Frame_write_header (
      HTTP3_FRAME_DATA, 100, buf, sizeof (buf));
  ASSERT_EQ (-1, written);
}

TEST (h3_goaway_write_buffer_too_small)
{
  uint8_t buf[0];
  int written = SocketHTTP3_Goaway_write (42, buf, 0);
  ASSERT_EQ (-1, written);
}

TEST (h3_settings_write_buffer_too_small)
{
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  settings.qpack_max_table_capacity = 4096;

  uint8_t buf[1]; /* Too small */
  int written = SocketHTTP3_Settings_write (&settings, buf, sizeof (buf));
  ASSERT_EQ (-1, written);
}

TEST (h3_goaway_parse_incomplete)
{
  uint64_t id;
  int ret = SocketHTTP3_Goaway_parse (NULL, 0, &id);
  ASSERT_EQ (1, ret);
}

TEST (h3_max_push_id_parse_incomplete)
{
  uint64_t id;
  int ret = SocketHTTP3_MaxPushId_parse (NULL, 0, &id);
  ASSERT_EQ (1, ret);
}

TEST (h3_cancel_push_parse_incomplete)
{
  uint64_t push_id;
  int ret = SocketHTTP3_CancelPush_parse (NULL, 0, &push_id);
  ASSERT_EQ (1, ret);
}

TEST (h3_settings_parse_empty)
{
  SocketHTTP3_Settings settings;
  SocketHTTP3_Settings_init (&settings);
  int ret = SocketHTTP3_Settings_parse (NULL, 0, &settings);
  ASSERT_EQ (0, ret);
  /* All defaults preserved */
  ASSERT_EQ (UINT64_MAX, settings.max_field_section_size);
  ASSERT_EQ (0ULL, settings.qpack_max_table_capacity);
  ASSERT_EQ (0ULL, settings.qpack_blocked_streams);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

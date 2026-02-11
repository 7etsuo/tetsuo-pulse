/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP3-frame.c
 * @brief HTTP/3 frame parser/serializer implementation (RFC 9114 Section 7).
 */

#include "http/SocketHTTP3-frame.h"
#include "http/SocketHTTP3-constants.h"
#include "quic/SocketQUICVarInt.h"

#include <string.h>

/* Maximum number of unique setting IDs we track for duplicate detection.
 * SETTINGS frames are small; 64 is generous. */
#define MAX_SETTINGS_IDS 64

/* ============================================================================
 * Frame Header Parse/Write
 * ============================================================================
 */

SocketHTTP3_ParseResult
SocketHTTP3_Frame_parse_header (const uint8_t *buf,
                                size_t buflen,
                                SocketHTTP3_FrameHeader *header,
                                size_t *consumed)
{
  if (buflen == 0)
    return HTTP3_PARSE_INCOMPLETE;

  uint64_t type_val;
  size_t type_consumed;
  SocketQUICVarInt_Result res;

  res = SocketQUICVarInt_decode (buf, buflen, &type_val, &type_consumed);
  if (res == QUIC_VARINT_INCOMPLETE)
    return HTTP3_PARSE_INCOMPLETE;
  if (res != QUIC_VARINT_OK)
    return HTTP3_PARSE_ERROR;

  uint64_t len_val;
  size_t len_consumed;
  res = SocketQUICVarInt_decode (
      buf + type_consumed, buflen - type_consumed, &len_val, &len_consumed);
  if (res == QUIC_VARINT_INCOMPLETE)
    return HTTP3_PARSE_INCOMPLETE;
  if (res != QUIC_VARINT_OK)
    return HTTP3_PARSE_ERROR;

  header->type = type_val;
  header->length = len_val;
  *consumed = type_consumed + len_consumed;
  return HTTP3_PARSE_OK;
}

int
SocketHTTP3_Frame_write_header (uint64_t type,
                                uint64_t length,
                                uint8_t *buf,
                                size_t buflen)
{
  size_t type_size = SocketQUICVarInt_size (type);
  size_t len_size = SocketQUICVarInt_size (length);

  if (type_size == 0 || len_size == 0)
    return -1;

  if (type_size + len_size > buflen)
    return -1;

  size_t pos = 0;
  if (!encode_varint_field (type, buf, &pos, buflen))
    return -1;
  if (!encode_varint_field (length, buf, &pos, buflen))
    return -1;

  return (int)pos;
}

/* ============================================================================
 * SETTINGS (RFC 9114 Section 7.2.4)
 * ============================================================================
 */

void
SocketHTTP3_Settings_init (SocketHTTP3_Settings *settings)
{
  settings->max_field_section_size = UINT64_MAX;
  settings->qpack_max_table_capacity = 0;
  settings->qpack_blocked_streams = 0;
}

int
SocketHTTP3_Settings_parse (const uint8_t *buf,
                            size_t len,
                            SocketHTTP3_Settings *settings)
{
  size_t offset = 0;
  uint64_t seen_ids[MAX_SETTINGS_IDS];
  size_t seen_count = 0;

  while (offset < len)
    {
      uint64_t id, value;
      size_t id_consumed, val_consumed;
      SocketQUICVarInt_Result res;

      res = SocketQUICVarInt_decode (
          buf + offset, len - offset, &id, &id_consumed);
      if (res == QUIC_VARINT_INCOMPLETE)
        return 1;
      if (res != QUIC_VARINT_OK)
        return -(int)H3_SETTINGS_ERROR;

      offset += id_consumed;

      res = SocketQUICVarInt_decode (
          buf + offset, len - offset, &value, &val_consumed);
      if (res == QUIC_VARINT_INCOMPLETE)
        return 1;
      if (res != QUIC_VARINT_OK)
        return -(int)H3_SETTINGS_ERROR;

      offset += val_consumed;

      /* Reserved HTTP/2 settings (0x02-0x05) → H3_SETTINGS_ERROR */
      if (HTTP3_IS_RESERVED_H2_SETTING (id))
        return -(int)H3_SETTINGS_ERROR;

      /* Duplicate detection for ALL identifiers */
      for (size_t i = 0; i < seen_count; i++)
        {
          if (seen_ids[i] == id)
            return -(int)H3_SETTINGS_ERROR;
        }
      if (seen_count < MAX_SETTINGS_IDS)
        seen_ids[seen_count++] = id;
      else
        return -(int)H3_SETTINGS_ERROR; /* too many settings to track */

      /* GREASE values: silently ignore (RFC 9114 §7.2.4.1) */
      if (H3_IS_GREASE (id))
        continue;

      /* Apply known settings */
      switch (id)
        {
        case H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY:
          settings->qpack_max_table_capacity = value;
          break;
        case H3_SETTINGS_MAX_FIELD_SECTION_SIZE:
          settings->max_field_section_size = value;
          break;
        case H3_SETTINGS_QPACK_BLOCKED_STREAMS:
          settings->qpack_blocked_streams = value;
          break;
        default:
          /* Unknown non-GREASE identifiers: silently ignore */
          break;
        }
    }

  return 0;
}

int
SocketHTTP3_Settings_write (const SocketHTTP3_Settings *settings,
                            uint8_t *buf,
                            size_t buflen)
{
  size_t pos = 0;

  /* Only write non-default settings to minimize wire size */
  if (settings->qpack_max_table_capacity != 0)
    {
      if (!encode_varint_field (
              H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, buf, &pos, buflen))
        return -1;
      if (!encode_varint_field (
              settings->qpack_max_table_capacity, buf, &pos, buflen))
        return -1;
    }

  if (settings->max_field_section_size != UINT64_MAX)
    {
      if (!encode_varint_field (
              H3_SETTINGS_MAX_FIELD_SECTION_SIZE, buf, &pos, buflen))
        return -1;
      if (!encode_varint_field (
              settings->max_field_section_size, buf, &pos, buflen))
        return -1;
    }

  if (settings->qpack_blocked_streams != 0)
    {
      if (!encode_varint_field (
              H3_SETTINGS_QPACK_BLOCKED_STREAMS, buf, &pos, buflen))
        return -1;
      if (!encode_varint_field (
              settings->qpack_blocked_streams, buf, &pos, buflen))
        return -1;
    }

  return (int)pos;
}

/* ============================================================================
 * Single-Varint Helpers
 * ============================================================================
 */

static int
parse_single_varint (const uint8_t *buf, size_t len, uint64_t *value)
{
  if (len == 0)
    return 1;

  size_t consumed;
  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (buf, len, value, &consumed);

  if (res == QUIC_VARINT_INCOMPLETE)
    return 1;
  if (res != QUIC_VARINT_OK)
    return -1;

  return 0;
}

static int
write_single_varint (uint64_t value, uint8_t *buf, size_t buflen)
{
  size_t written = SocketQUICVarInt_encode (value, buf, buflen);
  if (written == 0)
    return -1;
  return (int)written;
}

/* ============================================================================
 * GOAWAY (RFC 9114 Section 7.2.6)
 * ============================================================================
 */

int
SocketHTTP3_Goaway_parse (const uint8_t *buf, size_t len, uint64_t *id)
{
  return parse_single_varint (buf, len, id);
}

int
SocketHTTP3_Goaway_write (uint64_t id, uint8_t *buf, size_t buflen)
{
  return write_single_varint (id, buf, buflen);
}

/* ============================================================================
 * MAX_PUSH_ID (RFC 9114 Section 7.2.7)
 * ============================================================================
 */

int
SocketHTTP3_MaxPushId_parse (const uint8_t *buf, size_t len, uint64_t *id)
{
  return parse_single_varint (buf, len, id);
}

int
SocketHTTP3_MaxPushId_write (uint64_t id, uint8_t *buf, size_t buflen)
{
  return write_single_varint (id, buf, buflen);
}

/* ============================================================================
 * CANCEL_PUSH (RFC 9114 Section 7.2.3)
 * ============================================================================
 */

int
SocketHTTP3_CancelPush_parse (const uint8_t *buf, size_t len, uint64_t *push_id)
{
  return parse_single_varint (buf, len, push_id);
}

int
SocketHTTP3_CancelPush_write (uint64_t push_id, uint8_t *buf, size_t buflen)
{
  return write_single_varint (push_id, buf, buflen);
}

/* ============================================================================
 * PUSH_PROMISE (RFC 9114 Section 7.2.5)
 * ============================================================================
 */

int
SocketHTTP3_PushPromise_parse_id (const uint8_t *buf,
                                  size_t len,
                                  uint64_t *push_id,
                                  size_t *payload_offset)
{
  if (len == 0)
    return 1;

  size_t consumed;
  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (buf, len, push_id, &consumed);

  if (res == QUIC_VARINT_INCOMPLETE)
    return 1;
  if (res != QUIC_VARINT_OK)
    return -1;

  *payload_offset = consumed;
  return 0;
}

/* ============================================================================
 * Frame Validation (RFC 9114 Section 7.2)
 * ============================================================================
 */

uint64_t
SocketHTTP3_Frame_validate (uint64_t frame_type,
                            SocketHTTP3_StreamContext stream_type,
                            int is_first_frame)
{
  /* Reserved HTTP/2 frame types → always rejected */
  if (HTTP3_IS_RESERVED_H2_FRAME (frame_type))
    return H3_FRAME_UNEXPECTED;

  /* First frame on control stream MUST be SETTINGS (RFC 9114 §6.2.1) */
  if (stream_type == HTTP3_STREAM_CONTROL && is_first_frame
      && frame_type != HTTP3_FRAME_SETTINGS)
    return H3_MISSING_SETTINGS;

  /* GREASE and unknown frame types → always allowed (must be ignored) */
  if (H3_IS_GREASE (frame_type))
    return 0;

  switch (frame_type)
    {
    case HTTP3_FRAME_DATA:
    case HTTP3_FRAME_HEADERS:
      /* DATA and HEADERS: request and push streams only */
      if (stream_type == HTTP3_STREAM_CONTROL)
        return H3_FRAME_UNEXPECTED;
      return 0;

    case HTTP3_FRAME_CANCEL_PUSH:
    case HTTP3_FRAME_SETTINGS:
    case HTTP3_FRAME_GOAWAY:
    case HTTP3_FRAME_MAX_PUSH_ID:
      /* Control-stream-only frames */
      if (stream_type != HTTP3_STREAM_CONTROL)
        return H3_FRAME_UNEXPECTED;
      return 0;

    case HTTP3_FRAME_PUSH_PROMISE:
      /* PUSH_PROMISE: request stream only */
      if (stream_type != HTTP3_STREAM_REQUEST)
        return H3_FRAME_UNEXPECTED;
      return 0;

    default:
      /* Unknown non-GREASE frames: allowed (must be ignored) */
      return 0;
    }
}

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICFrame-flow.c
 * @brief QUIC Flow Control Frame Encoding (RFC 9000 Sections 19.9-19.14).
 *
 * Implements encoding for:
 * - MAX_DATA (0x10) - Connection-level flow control limit
 * - MAX_STREAM_DATA (0x11) - Stream-level flow control limit
 * - MAX_STREAMS (0x12-0x13) - Stream limit
 * - DATA_BLOCKED (0x14) - Connection-level flow control blocking
 * - STREAM_DATA_BLOCKED (0x15) - Stream-level flow control blocking
 * - STREAMS_BLOCKED (0x16-0x17) - Stream limit blocking
 */

#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICVarInt.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ============================================================================
 * Common Helper Function
 * ============================================================================
 *
 * This helper eliminates 90%+ code duplication across the 6 flow control
 * frame encoding functions. Each function follows the identical pattern:
 * 1. Validate output buffer
 * 2. Calculate varint sizes for all fields
 * 3. Validate field sizes (detect overflow)
 * 4. Check output buffer capacity
 * 5. Encode frame type byte
 * 6. Encode variable number of varint fields
 */

/**
 * @brief Generic flow control frame encoder.
 *
 * Encodes a flow control frame with 1-2 varint fields following the frame type.
 * All 6 flow control frames (MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS,
 * DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED) share this structure.
 *
 * @param frame_type QUIC frame type (0x10-0x17).
 * @param field1     First varint field value.
 * @param field2     Second varint field value (ignored if field_count == 1).
 * @param field_count Number of fields to encode (1 or 2).
 * @param out        Output buffer for encoded frame.
 * @param out_size   Size of output buffer in bytes.
 *
 * @return Number of bytes written on success, 0 on error.
 *
 * @note This function performs all validation checks that were previously
 *       duplicated across the 6 individual encoding functions.
 */
static size_t
encode_flow_control_frame (uint8_t frame_type, uint64_t field1,
                           uint64_t field2, size_t field_count, uint8_t *out,
                           size_t out_size)
{
  if (!out)
    return 0;

  /* Calculate required size: type (1 byte) + field(s) (varint) */
  size_t type_len = 1;
  size_t field1_len = SocketQUICVarInt_size (field1);

  if (field1_len == 0)
    return 0; /* field1 exceeds varint maximum */

  size_t total_len = type_len + field1_len;

  /* Handle second field if present */
  size_t field2_len = 0;
  if (field_count == 2)
    {
      field2_len = SocketQUICVarInt_size (field2);
      if (field2_len == 0)
        return 0; /* field2 exceeds varint maximum */
      total_len += field2_len;
    }

  if (out_size < total_len)
    return 0; /* Buffer too small */

  size_t pos = 0;

  /* Encode frame type */
  out[pos++] = frame_type;

  /* Encode first field */
  if (!encode_varint_field (field1, out, &pos, out_size))
    return 0;

  /* Encode second field if present */
  if (field_count == 2)
    {
      if (!encode_varint_field (field2, out, &pos, out_size))
        return 0;
    }

  return pos;
}

/* ============================================================================
 * MAX_DATA Frame Encoding (RFC 9000 Section 19.9)
 * ============================================================================
 *
 * Format:
 *   Type (0x10)
 *   Maximum Data (varint)
 */

size_t
SocketQUICFrame_encode_max_data (uint64_t max_data, uint8_t *out,
                                  size_t out_size)
{
  return encode_flow_control_frame (QUIC_FRAME_MAX_DATA, max_data, 0, 1, out,
                                    out_size);
}

/* ============================================================================
 * MAX_STREAM_DATA Frame Encoding (RFC 9000 Section 19.10)
 * ============================================================================
 *
 * Format:
 *   Type (0x11)
 *   Stream ID (varint)
 *   Maximum Stream Data (varint)
 */

size_t
SocketQUICFrame_encode_max_stream_data (uint64_t stream_id, uint64_t max_data,
                                         uint8_t *out, size_t out_size)
{
  return encode_flow_control_frame (QUIC_FRAME_MAX_STREAM_DATA, stream_id,
                                    max_data, 2, out, out_size);
}

/* ============================================================================
 * MAX_STREAMS Frame Encoding (RFC 9000 Section 19.11)
 * ============================================================================
 *
 * Format:
 *   Type (0x12 for bidirectional, 0x13 for unidirectional)
 *   Maximum Streams (varint)
 */

size_t
SocketQUICFrame_encode_max_streams (int bidirectional, uint64_t max_streams,
                                     uint8_t *out, size_t out_size)
{
  uint8_t frame_type = bidirectional ? QUIC_FRAME_MAX_STREAMS_BIDI
                                     : QUIC_FRAME_MAX_STREAMS_UNI;
  return encode_flow_control_frame (frame_type, max_streams, 0, 1, out,
                                    out_size);
}

/* ============================================================================
 * DATA_BLOCKED Frame Encoding (RFC 9000 Section 19.12)
 * ============================================================================
 */

/**
 * @brief Encode a DATA_BLOCKED frame.
 *
 * DATA_BLOCKED Frame {
 *   Type (i) = 0x14,
 *   Maximum Data (i)
 * }
 *
 * @param max_data Connection-level data limit that is blocking.
 * @param out Output buffer for encoded frame.
 * @param out_size Size of output buffer in bytes.
 *
 * @return Number of bytes written on success, 0 on error.
 *
 * @note Requires buffer of at least 1 + varint_size(max_data) bytes.
 */
size_t
SocketQUICFrame_encode_data_blocked (uint64_t max_data, uint8_t *out,
                                      size_t out_size)
{
  return encode_flow_control_frame (QUIC_FRAME_DATA_BLOCKED, max_data, 0, 1,
                                    out, out_size);
}

/* ============================================================================
 * STREAM_DATA_BLOCKED Frame Encoding (RFC 9000 Section 19.13)
 * ============================================================================
 */

/**
 * @brief Encode a STREAM_DATA_BLOCKED frame.
 *
 * STREAM_DATA_BLOCKED Frame {
 *   Type (i) = 0x15,
 *   Stream ID (i),
 *   Maximum Stream Data (i)
 * }
 *
 * @param stream_id Stream ID that is blocked.
 * @param max_data Stream-level data limit that is blocking.
 * @param out Output buffer for encoded frame.
 * @param out_size Size of output buffer in bytes.
 *
 * @return Number of bytes written on success, 0 on error.
 *
 * @note Requires buffer of at least 1 + varint_size(stream_id) +
 *       varint_size(max_data) bytes.
 */
size_t
SocketQUICFrame_encode_stream_data_blocked (uint64_t stream_id,
                                             uint64_t max_data, uint8_t *out,
                                             size_t out_size)
{
  return encode_flow_control_frame (QUIC_FRAME_STREAM_DATA_BLOCKED, stream_id,
                                    max_data, 2, out, out_size);
}

/* ============================================================================
 * STREAMS_BLOCKED Frame Encoding (RFC 9000 Section 19.14)
 * ============================================================================
 */

/**
 * @brief Encode a STREAMS_BLOCKED frame.
 *
 * STREAMS_BLOCKED Frame {
 *   Type (i) = 0x16..0x17,
 *   Maximum Streams (i)
 * }
 *
 * Type 0x16: Bidirectional streams blocked
 * Type 0x17: Unidirectional streams blocked
 *
 * @param bidirectional 1 for bidirectional (0x16), 0 for unidirectional (0x17).
 * @param max_streams Maximum stream limit that is blocking.
 * @param out Output buffer for encoded frame.
 * @param out_size Size of output buffer in bytes.
 *
 * @return Number of bytes written on success, 0 on error.
 *
 * @note Requires buffer of at least 1 + varint_size(max_streams) bytes.
 */
size_t
SocketQUICFrame_encode_streams_blocked (int bidirectional, uint64_t max_streams,
                                        uint8_t *out, size_t out_size)
{
  uint8_t frame_type = bidirectional ? QUIC_FRAME_STREAMS_BLOCKED_BIDI
                                     : QUIC_FRAME_STREAMS_BLOCKED_UNI;
  return encode_flow_control_frame (frame_type, max_streams, 0, 1, out,
                                    out_size);
}

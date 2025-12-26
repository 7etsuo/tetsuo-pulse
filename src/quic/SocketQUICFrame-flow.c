/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICFrame-flow.c
 * @brief QUIC Flow Control Frame Encoding (RFC 9000 Sections 19.9-19.11).
 *
 * Implements encoding for MAX_DATA, MAX_STREAM_DATA, and MAX_STREAMS frames
 * which advertise flow control credit to peers.
 * @brief QUIC Flow Control Frame Encoding (RFC 9000 Sections 19.12-19.14).
 *
 * Implements encoding for:
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
  size_t pos;
  size_t encoded;

  if (!out)
    return 0;

  /* Need at least 1 byte for type + 1 byte for minimum varint */
  if (out_size < 2)
    return 0;

  pos = 0;

  /* Type: 0x10 */
  out[pos++] = QUIC_FRAME_MAX_DATA;

  /* Maximum Data */
  encoded = SocketQUICVarInt_encode (max_data, out + pos, out_size - pos);
  if (encoded == 0)
    return 0;

  pos += encoded;
#include <string.h>

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
  if (!out)
    return 0;

  /* Calculate required size: type (1 byte) + max_data (varint) */
  size_t type_len = 1;
  size_t max_data_len = SocketQUICVarInt_size (max_data);

  if (max_data_len == 0)
    return 0; /* max_data exceeds varint maximum */

  size_t total_len = type_len + max_data_len;

  if (out_size < total_len)
    return 0; /* Buffer too small */

  size_t pos = 0;

  /* Encode frame type */
  out[pos++] = QUIC_FRAME_DATA_BLOCKED;

  /* Encode max_data */
  size_t encoded = SocketQUICVarInt_encode (max_data, out + pos, out_size - pos);
  if (encoded == 0)
    return 0;
  pos += encoded;

  return pos;
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
  size_t pos;
  size_t encoded;

  if (!out)
    return 0;

  /* Need at least 1 byte for type + 2 bytes for minimum varints */
  if (out_size < 3)
    return 0;

  pos = 0;

  /* Type: 0x11 */
  out[pos++] = QUIC_FRAME_MAX_STREAM_DATA;

  /* Stream ID */
  encoded = SocketQUICVarInt_encode (stream_id, out + pos, out_size - pos);
  if (encoded == 0)
    return 0;

  pos += encoded;

  /* Maximum Stream Data */
  encoded = SocketQUICVarInt_encode (max_data, out + pos, out_size - pos);
  if (encoded == 0)
    return 0;

  pos += encoded;
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
  if (!out)
    return 0;

  /* Calculate required size: type + stream_id + max_data (all varints) */
  size_t type_len = 1;
  size_t stream_id_len = SocketQUICVarInt_size (stream_id);
  size_t max_data_len = SocketQUICVarInt_size (max_data);

  if (stream_id_len == 0 || max_data_len == 0)
    return 0; /* Value exceeds varint maximum */

  size_t total_len = type_len + stream_id_len + max_data_len;

  if (out_size < total_len)
    return 0; /* Buffer too small */

  size_t pos = 0;

  /* Encode frame type */
  out[pos++] = QUIC_FRAME_STREAM_DATA_BLOCKED;

  /* Encode stream ID */
  size_t encoded = SocketQUICVarInt_encode (stream_id, out + pos, out_size - pos);
  if (encoded == 0)
    return 0;
  pos += encoded;

  /* Encode max_data */
  encoded = SocketQUICVarInt_encode (max_data, out + pos, out_size - pos);
  if (encoded == 0)
    return 0;
  pos += encoded;

  return pos;
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
  size_t pos;
  size_t encoded;

  if (!out)
    return 0;

  /* Need at least 1 byte for type + 1 byte for minimum varint */
  if (out_size < 2)
    return 0;

  pos = 0;

  /* Type: 0x12 (bidi) or 0x13 (uni) */
  out[pos++] = bidirectional ? QUIC_FRAME_MAX_STREAMS_BIDI
                              : QUIC_FRAME_MAX_STREAMS_UNI;

  /* Maximum Streams */
  encoded = SocketQUICVarInt_encode (max_streams, out + pos, out_size - pos);
  if (encoded == 0)
    return 0;

  pos += encoded;
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
  if (!out)
    return 0;

  /* Calculate required size: type (1 byte) + max_streams (varint) */
  size_t type_len = 1;
  size_t max_streams_len = SocketQUICVarInt_size (max_streams);

  if (max_streams_len == 0)
    return 0; /* max_streams exceeds varint maximum */

  size_t total_len = type_len + max_streams_len;

  if (out_size < total_len)
    return 0; /* Buffer too small */

  size_t pos = 0;

  /* Encode frame type based on direction */
  out[pos++] = bidirectional ? QUIC_FRAME_STREAMS_BLOCKED_BIDI
                              : QUIC_FRAME_STREAMS_BLOCKED_UNI;

  /* Encode max_streams */
  size_t encoded = SocketQUICVarInt_encode (max_streams, out + pos, out_size - pos);
  if (encoded == 0)
    return 0;
  pos += encoded;

  return pos;
}

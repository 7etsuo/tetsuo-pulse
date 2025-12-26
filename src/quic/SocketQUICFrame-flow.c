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
  return pos;
}

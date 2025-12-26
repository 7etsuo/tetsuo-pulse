/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICFrame-stream.c
 * @brief QUIC Stream Frame Encoding/Decoding (RFC 9000 §19.4-19.5, §19.8).
 *
 * Implements encoding/decoding for:
 * - RESET_STREAM (0x04) - Abrupt termination of sending part of a stream
 * - STOP_SENDING (0x05) - Request peer to stop sending on a stream
 * - STREAM (0x08-0x0f) - Application data transport frames
 */

#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICVarInt.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ============================================================================
 * RESET_STREAM Frame Encoding (RFC 9000 Section 19.4)
 * ============================================================================
 */

size_t
SocketQUICFrame_encode_reset_stream (uint64_t stream_id, uint64_t error_code,
                                     uint64_t final_size, uint8_t *out,
                                     size_t out_size)
{
  size_t pos;
  size_t encoded;

  if (!out)
    return 0;

  size_t type_len = 1;
  size_t stream_id_len = SocketQUICVarInt_size (stream_id);
  size_t error_code_len = SocketQUICVarInt_size (error_code);
  size_t final_size_len = SocketQUICVarInt_size (final_size);

  if (stream_id_len == 0 || error_code_len == 0 || final_size_len == 0)
    return 0;

  size_t total_len = type_len + stream_id_len + error_code_len + final_size_len;

  if (out_size < total_len)
    return 0;

  pos = 0;
  out[pos++] = QUIC_FRAME_RESET_STREAM;

  encoded = SocketQUICVarInt_encode (stream_id, out + pos, out_size - pos);
  if (encoded == 0)
    return 0;
  pos += encoded;

  encoded = SocketQUICVarInt_encode (error_code, out + pos, out_size - pos);
  if (encoded == 0)
    return 0;
  pos += encoded;

  encoded = SocketQUICVarInt_encode (final_size, out + pos, out_size - pos);
  if (encoded == 0)
    return 0;
  pos += encoded;

  return pos;
}

/* ============================================================================
 * STOP_SENDING Frame Encoding (RFC 9000 Section 19.5)
 * ============================================================================
 */

size_t
SocketQUICFrame_encode_stop_sending (uint64_t stream_id, uint64_t error_code,
                                     uint8_t *out, size_t out_size)
{
  size_t pos;
  size_t encoded;

  if (!out)
    return 0;

  size_t type_len = 1;
  size_t stream_id_len = SocketQUICVarInt_size (stream_id);
  size_t error_code_len = SocketQUICVarInt_size (error_code);

  if (stream_id_len == 0 || error_code_len == 0)
    return 0;

  size_t total_len = type_len + stream_id_len + error_code_len;

  if (out_size < total_len)
    return 0;

  pos = 0;
  out[pos++] = QUIC_FRAME_STOP_SENDING;

  encoded = SocketQUICVarInt_encode (stream_id, out + pos, out_size - pos);
  if (encoded == 0)
    return 0;
  pos += encoded;

  encoded = SocketQUICVarInt_encode (error_code, out + pos, out_size - pos);
  if (encoded == 0)
    return 0;
  pos += encoded;

  return pos;
}

/* ============================================================================
 * STREAM Frame Encoding (RFC 9000 Section 19.8)
 * ============================================================================
 */

size_t
SocketQUICFrame_encode_stream (uint64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t len, int fin,
                               uint8_t *out, size_t out_len)
{
  size_t pos;
  size_t encoded;

  if (!out || out_len == 0)
    return 0;

  if (!data && len > 0)
    return 0;

  uint8_t frame_type = QUIC_FRAME_STREAM;

  if (fin)
    frame_type |= QUIC_FRAME_STREAM_FIN;

  frame_type |= QUIC_FRAME_STREAM_LEN;

  if (offset > 0)
    frame_type |= QUIC_FRAME_STREAM_OFF;

  size_t type_len = 1;
  size_t stream_id_len = SocketQUICVarInt_size (stream_id);
  size_t offset_len = (offset > 0) ? SocketQUICVarInt_size (offset) : 0;
  size_t length_len = SocketQUICVarInt_size (len);

  if (stream_id_len == 0 || length_len == 0)
    return 0;

  if (offset > 0 && offset_len == 0)
    return 0;

  size_t total_len = type_len + stream_id_len + offset_len + length_len + len;

  if (total_len > out_len)
    return 0;

  pos = 0;
  out[pos++] = frame_type;

  encoded = SocketQUICVarInt_encode (stream_id, out + pos, out_len - pos);
  if (encoded == 0)
    return 0;
  pos += encoded;

  if (offset > 0)
    {
      encoded = SocketQUICVarInt_encode (offset, out + pos, out_len - pos);
      if (encoded == 0)
        return 0;
      pos += encoded;
    }

  encoded = SocketQUICVarInt_encode (len, out + pos, out_len - pos);
  if (encoded == 0)
    return 0;
  pos += encoded;

  if (len > 0 && data)
    {
      memcpy (out + pos, data, len);
      pos += len;
    }

  return pos;
}

/* ============================================================================
 * STREAM Frame Decoding (RFC 9000 Section 19.8)
 * ============================================================================
 */

int
SocketQUICFrame_decode_stream (const uint8_t *data, size_t len,
                               SocketQUICFrameStream_T *frame)
{
  if (!data || !frame || len == 0)
    return -1;

  if (!SocketQUICFrame_is_stream (data[0]))
    return -1;

  SocketQUICFrame_T full_frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, len, &full_frame, &consumed);

  if (res != QUIC_FRAME_OK)
    return -1;

  *frame = full_frame.data.stream;

  return (int)consumed;
}

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICFrame-stream.c
 * @brief QUIC Stream Termination Frame Encoding (RFC 9000 §19.4-19.5).
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
#include <sys/types.h>

size_t
SocketQUICFrame_encode_reset_stream (uint64_t stream_id,
                                     uint64_t error_code,
                                     uint64_t final_size,
                                     uint8_t *out,
                                     size_t out_size)
{
  size_t pos;

  if (!out)
    return 0;

  /* Calculate required size: type + stream_id + error_code + final_size */
  size_t type_len = QUIC_FRAME_TYPE_SIZE;
  size_t stream_id_len = SocketQUICVarInt_size (stream_id);
  size_t error_code_len = SocketQUICVarInt_size (error_code);
  size_t final_size_len = SocketQUICVarInt_size (final_size);

  if (!VALIDATE_VARINT_SIZES (stream_id_len, error_code_len, final_size_len))
    return 0; /* Value exceeds varint maximum */

  size_t total_len = type_len + stream_id_len + error_code_len + final_size_len;

  if (out_size < total_len)
    return 0; /* Buffer too small */

  pos = 0;

  /* Type: 0x04 */
  out[pos++] = QUIC_FRAME_RESET_STREAM;

  /* Stream ID */
  if (!encode_varint_field (stream_id, out, &pos, out_size))
    return 0;

  /* Application Protocol Error Code */
  if (!encode_varint_field (error_code, out, &pos, out_size))
    return 0;

  /* Final Size */
  if (!encode_varint_field (final_size, out, &pos, out_size))
    return 0;

  return pos;
}

size_t
SocketQUICFrame_encode_stop_sending (uint64_t stream_id,
                                     uint64_t error_code,
                                     uint8_t *out,
                                     size_t out_size)
{
  size_t pos;

  if (!out)
    return 0;

  /* Calculate required size: type + stream_id + error_code */
  size_t type_len = QUIC_FRAME_TYPE_SIZE;
  size_t stream_id_len = SocketQUICVarInt_size (stream_id);
  size_t error_code_len = SocketQUICVarInt_size (error_code);

  if (!VALIDATE_VARINT_SIZES (stream_id_len, error_code_len))
    return 0; /* Value exceeds varint maximum */

  size_t total_len = type_len + stream_id_len + error_code_len;

  if (out_size < total_len)
    return 0; /* Buffer too small */

  pos = 0;

  /* Type: 0x05 */
  out[pos++] = QUIC_FRAME_STOP_SENDING;

  /* Stream ID */
  if (!encode_varint_field (stream_id, out, &pos, out_size))
    return 0;

  /* Application Protocol Error Code */
  if (!encode_varint_field (error_code, out, &pos, out_size))
    return 0;

  return pos;
}

size_t
SocketQUICFrame_encode_stream (uint64_t stream_id,
                               uint64_t offset,
                               const uint8_t *data,
                               size_t len,
                               int fin,
                               uint8_t *out,
                               size_t out_len)
{
  size_t pos;

  if (!out || out_len == 0)
    return 0;

  /* Null data only valid for zero-length frames */
  if (!data && len > 0)
    return 0;

  /* Calculate frame type with flags */
  uint8_t frame_type = QUIC_FRAME_STREAM;

  if (fin)
    frame_type |= QUIC_FRAME_STREAM_FIN; /* Bit 0: FIN */

  frame_type
      |= QUIC_FRAME_STREAM_LEN; /* Bit 1: LEN (always set for encoding) */

  if (offset > 0)
    frame_type |= QUIC_FRAME_STREAM_OFF; /* Bit 2: OFF */

  /* Calculate required buffer size */
  size_t type_len = QUIC_FRAME_TYPE_SIZE;
  size_t stream_id_len = SocketQUICVarInt_size (stream_id);
  size_t offset_len = (offset > 0) ? SocketQUICVarInt_size (offset) : 0;
  size_t length_len = SocketQUICVarInt_size (len);

  if (!VALIDATE_VARINT_SIZES (stream_id_len, length_len))
    return 0; /* Value exceeds varint maximum */

  if (offset > 0 && !VALIDATE_VARINT_SIZES (offset_len))
    return 0; /* Offset exceeds varint maximum */

  /* Prevent integer overflow in size calculation */
  size_t header_size = type_len + stream_id_len + offset_len + length_len;
  if (len > SIZE_MAX - header_size)
    return 0; /* Would overflow */

  size_t total_len = header_size + len;

  if (total_len > out_len)
    return 0; /* Insufficient buffer */

  pos = 0;

  /* Frame Type */
  out[pos++] = frame_type;

  /* Stream ID */
  if (!encode_varint_field (stream_id, out, &pos, out_len))
    return 0;

  /* Offset (if present) */
  if (offset > 0)
    {
      if (!encode_varint_field (offset, out, &pos, out_len))
        return 0;
    }

  /* Length */
  if (!encode_varint_field (len, out, &pos, out_len))
    return 0;

  /* Stream Data */
  if (len > 0 && data)
    {
      memcpy (out + pos, data, len);
      pos += len;
    }

  return pos;
}

ssize_t
SocketQUICFrame_decode_stream (const uint8_t *data,
                               size_t len,
                               SocketQUICFrameStream_T *frame)
{
  if (!data || !frame || len == 0)
    return -(ssize_t)QUIC_FRAME_ERROR_NULL;

  /* Verify frame type is STREAM (0x08-0x0f) */
  if (!SocketQUICFrame_is_stream (data[0]))
    return -(ssize_t)QUIC_FRAME_ERROR_TYPE;

  /* Use the full parser to decode the frame */
  SocketQUICFrame_T full_frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, len, &full_frame, &consumed);

  if (res != QUIC_FRAME_OK)
    return -(ssize_t)res;

  /* Copy stream-specific data */
  *frame = full_frame.data.stream;

  return (ssize_t)consumed;
}

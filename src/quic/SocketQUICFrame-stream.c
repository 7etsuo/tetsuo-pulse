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

/* ============================================================================
 * RESET_STREAM Frame Encoding (RFC 9000 Section 19.4)
 * ============================================================================
 *
 * Format:
 *   Type (i) = 0x04
 *   Stream ID (i)
 *   Application Protocol Error Code (i)
 *   Final Size (i)
 *
 * An endpoint uses a RESET_STREAM frame to abruptly terminate the sending
 * part of a stream. After sending the RESET_STREAM, an endpoint ceases
 * transmission and retransmission of STREAM frames on the identified stream.
 *
 * The Final Size field is the final size of the stream in bytes. This is the
 * sum of all bytes that were sent in STREAM frames for this stream.
 */

size_t
SocketQUICFrame_encode_reset_stream (uint64_t stream_id, uint64_t error_code,
                                     uint64_t final_size, uint8_t *out,
                                     size_t out_size)
{
  size_t pos;

  if (!out)
    return 0;

  /* Calculate required size: type + stream_id + error_code + final_size */
  size_t type_len = 1;
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

/* ============================================================================
 * STOP_SENDING Frame Encoding (RFC 9000 Section 19.5)
 * ============================================================================
 *
 * Format:
 *   Type (i) = 0x05
 *   Stream ID (i)
 *   Application Protocol Error Code (i)
 *
 * An endpoint uses a STOP_SENDING frame to communicate that incoming data is
 * being discarded on receipt per application request. STOP_SENDING requests
 * that a peer cease transmission on a stream.
 *
 * A STOP_SENDING frame can be sent for streams in the Recv or Size Known states.
 * Receiving a STOP_SENDING frame for a locally initiated stream that has not
 * yet been created MUST be treated as a connection error of type STREAM_STATE_ERROR.
 *
 * An endpoint that receives a STOP_SENDING frame MUST send a RESET_STREAM frame
 * if the stream is in the Ready or Send state. If the stream is in the Data Sent
 * state, the endpoint MAY defer sending the RESET_STREAM frame until the packets
 * containing outstanding data are acknowledged or declared lost. If any outstanding
 * data is declared lost, the endpoint SHOULD send a RESET_STREAM frame instead of
 * retransmitting the data.
 */

size_t
SocketQUICFrame_encode_stop_sending (uint64_t stream_id, uint64_t error_code,
                                     uint8_t *out, size_t out_size)
{
  size_t pos;

  if (!out)
    return 0;

  /* Calculate required size: type + stream_id + error_code */
  size_t type_len = 1;
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

/* ============================================================================
 * STREAM Frame Encoding (RFC 9000 Section 19.8)
 * ============================================================================
 *
 * Format:
 *   Type (i) = 0x08..0x0f
 *   Stream ID (i)
 *   [Offset (i)]
 *   [Length (i)]
 *   Stream Data (..)
 *
 * STREAM frames are the most complex frame type in QUIC. They use a variable
 * format with three flag bits encoded in the frame type:
 *
 * - Bit 0 (0x01): FIN - This is the final frame for the stream
 * - Bit 1 (0x02): LEN - Length field is present
 * - Bit 2 (0x04): OFF - Offset field is present
 *
 * The frame type ranges from 0x08 to 0x0f, representing all 8 combinations
 * of these three flags.
 *
 * Implementation Notes:
 * - When LEN bit is not set, stream data extends to the end of the packet
 * - For encoding, we always set the LEN bit for simplicity
 * - Zero-length data with FIN is valid (signals stream close)
 * - Offset defaults to 0 when OFF bit is not set
 */

size_t
SocketQUICFrame_encode_stream (uint64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t len, int fin,
                               uint8_t *out, size_t out_len)
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

  frame_type |= QUIC_FRAME_STREAM_LEN; /* Bit 1: LEN (always set for encoding) */

  if (offset > 0)
    frame_type |= QUIC_FRAME_STREAM_OFF; /* Bit 2: OFF */

  /* Calculate required buffer size */
  size_t type_len = 1;
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

/* ============================================================================
 * STREAM Frame Decoding (RFC 9000 Section 19.8)
 * ============================================================================
 *
 * Convenience wrapper around the existing SocketQUICFrame_parse() function
 * for decoding STREAM frames.
 *
 * The function extracts:
 * - Frame type and flags (FIN, LEN, OFF)
 * - Stream ID
 * - Offset (if OFF flag set, else 0)
 * - Length (if LEN flag set, else extends to end of data)
 * - Pointer to stream data (points into input buffer, not copied)
 *
 * @param data   Input buffer containing encoded STREAM frame
 * @param len    Length of input buffer
 * @param frame  Output: decoded stream frame structure
 *
 * @return Number of bytes consumed on success, or -1 on error
 */

ssize_t
SocketQUICFrame_decode_stream (const uint8_t *data, size_t len,
                               SocketQUICFrameStream_T *frame)
{
  if (!data || !frame || len == 0)
    return -1;

  /* Verify frame type is STREAM (0x08-0x0f) */
  if (!SocketQUICFrame_is_stream (data[0]))
    return -1;

  /* Use the full parser to decode the frame */
  SocketQUICFrame_T full_frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, len, &full_frame, &consumed);

  if (res != QUIC_FRAME_OK)
    return -1;

  /* Copy stream-specific data */
  *frame = full_frame.data.stream;

  return (ssize_t)consumed;
}

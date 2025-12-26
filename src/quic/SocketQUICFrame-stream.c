/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICFrame-stream.c
 * @brief QUIC Stream Termination Frame Encoding (RFC 9000 §19.4-19.5).
 */

#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICVarInt.h"

#include <stddef.h>
#include <stdint.h>

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

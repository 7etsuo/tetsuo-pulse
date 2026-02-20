/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICFrame-crypto.c
 * @brief QUIC CRYPTO Frame Encoding/Decoding (RFC 9000 §19.6).
 *
 * Implements encoding/decoding for:
 * - CRYPTO (0x06) - TLS handshake message transport
 *
 * CRYPTO frames are used to transmit cryptographic handshake messages.
 * They have a separate offset space for each encryption level (Initial,
 * Handshake, 1-RTT). Unlike STREAM frames, CRYPTO frames cannot be sent
 * in 0-RTT packets.
 */

#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICVarInt.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

size_t
SocketQUICFrame_encode_crypto (uint64_t offset,
                               const uint8_t *data,
                               size_t len,
                               uint8_t *out,
                               size_t out_len)
{
  size_t pos;

  if (!out || out_len == 0)
    return 0;

  /* Null data only valid for zero-length frames */
  if (!data && len > 0)
    return 0;

  /* Calculate required buffer size */
  size_t type_len = QUIC_FRAME_TYPE_SIZE;
  size_t offset_len = SocketQUICVarInt_size (offset);
  size_t length_len = SocketQUICVarInt_size (len);

  if (!VALIDATE_VARINT_SIZES (offset_len, length_len))
    return 0; /* Value exceeds varint maximum */

  /* Prevent integer overflow in size calculation */
  size_t header_size = type_len + offset_len + length_len;
  if (len > SIZE_MAX - header_size)
    return 0; /* Would overflow */

  size_t total_len = header_size + len;

  if (total_len > out_len)
    return 0; /* Insufficient buffer */

  pos = 0;

  /* Frame Type: 0x06 */
  out[pos++] = QUIC_FRAME_CRYPTO;

  /* Offset */
  if (!encode_varint_field (offset, out, &pos, out_len))
    return 0;

  /* Length */
  if (!encode_varint_field (len, out, &pos, out_len))
    return 0;

  /* Crypto Data */
  if (len > 0 && data)
    {
      memcpy (out + pos, data, len);
      pos += len;
    }

  return pos;
}

ssize_t
SocketQUICFrame_decode_crypto (const uint8_t *data,
                               size_t len,
                               SocketQUICFrameCrypto_T *frame)
{
  if (!data || !frame || len == 0)
    return -(ssize_t)QUIC_FRAME_ERROR_NULL;

  /* Verify frame type is CRYPTO (0x06) */
  if (data[0] != QUIC_FRAME_CRYPTO)
    return -(ssize_t)QUIC_FRAME_ERROR_TYPE;

  /* Use the full parser to decode the frame */
  SocketQUICFrame_T full_frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, len, &full_frame, &consumed);

  if (res != QUIC_FRAME_OK)
    return -(ssize_t)res;

  /* Copy crypto-specific data */
  *frame = full_frame.data.crypto;

  return (ssize_t)consumed;
}

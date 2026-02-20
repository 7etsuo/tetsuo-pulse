/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICFrame-token.c
 * @brief QUIC NEW_TOKEN Frame Encoding/Decoding (RFC 9000 §19.7).
 *
 * Implements encoding/decoding for:
 * - NEW_TOKEN (0x07) - Server-provided address validation token
 *
 * The NEW_TOKEN frame is sent by the server to provide the client with a
 * token that can be used in the Initial packet header of a future connection.
 * The token allows the server to validate the client address without requiring
 * an additional round trip (address validation via Retry packets).
 *
 * RFC 9000 Section 19.7:
 *   Type (i) = 0x07
 *   Token Length (i)
 *   Token (..)
 *
 * Restrictions:
 * - MUST only be sent by server in 1-RTT packets
 * - Tokens MUST NOT be empty (zero-length)
 * - Client stores tokens for future connections to same server
 */

#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICVarInt.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

size_t
SocketQUICFrame_encode_new_token (const uint8_t *token,
                                  size_t token_len,
                                  uint8_t *out,
                                  size_t out_len)
{
  size_t pos;

  /* Validate arguments */
  if (!out)
    return 0;

  /* Token must not be NULL if length > 0 */
  if (!token && token_len > 0)
    return 0;

  /* Empty tokens are invalid per RFC 9000 Section 19.7 */
  if (token_len == 0)
    return 0;

  /* Calculate required size: type + token_length + token */
  size_t type_len = QUIC_FRAME_TYPE_SIZE;
  size_t token_len_varint = SocketQUICVarInt_size (token_len);

  if (!VALIDATE_VARINT_SIZES (token_len_varint))
    return 0; /* Token length exceeds varint maximum */

  /* Check for integer overflow in size calculation (CWE-190).
   * If token_len is very large (approaching SIZE_MAX), adding even small
   * values like type_len (1) + token_len_varint (max 8) could overflow.
   * This would make the subsequent buffer size check unreliable and could
   * lead to buffer overflows during memcpy.
   */
  if (token_len > SIZE_MAX - (type_len + token_len_varint))
    return 0; /* Would overflow */

  size_t total_len = type_len + token_len_varint + token_len;

  if (out_len < total_len)
    return 0; /* Buffer too small */

  pos = 0;

  /* Type: 0x07 */
  out[pos++] = QUIC_FRAME_NEW_TOKEN;

  /* Token Length */
  if (!encode_varint_field (token_len, out, &pos, out_len))
    return 0;

  /* Token */
  memcpy (out + pos, token, token_len);
  pos += token_len;

  return pos;
}

int
SocketQUICFrame_decode_new_token (const uint8_t *data,
                                  size_t len,
                                  uint8_t *token_out,
                                  size_t *token_len)
{
  SocketQUICFrame_T frame;
  size_t consumed;

  /* Validate arguments */
  if (!data || !token_out || !token_len || len == 0)
    return -1;

  /* Verify frame type is NEW_TOKEN (0x07) */
  if (data[0] != QUIC_FRAME_NEW_TOKEN)
    return -1;

  /* Use the full parser to decode the frame */
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, len, &frame, &consumed);

  if (res != QUIC_FRAME_OK)
    return -1;

  /* Verify it's actually a NEW_TOKEN frame */
  if (frame.type != QUIC_FRAME_NEW_TOKEN)
    return -1;

  /* Check token fits in output buffer */
  if (frame.data.new_token.token_length > *token_len)
    return -1;

  /* Copy token data */
  *token_len = (size_t)frame.data.new_token.token_length;
  memcpy (token_out, frame.data.new_token.token, *token_len);

  return 0;
}

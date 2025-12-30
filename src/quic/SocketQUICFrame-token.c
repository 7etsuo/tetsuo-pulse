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

/* ============================================================================
 * NEW_TOKEN Frame Encoding (RFC 9000 Section 19.7)
 * ============================================================================
 *
 * Format:
 *   Type (i) = 0x07
 *   Token Length (i)
 *   Token (..)
 *
 * A server sends a NEW_TOKEN frame to provide the client with an address
 * validation token that can be used on a future connection to the server.
 *
 * The token is an opaque blob that the client includes in the Token field
 * of an Initial packet (RFC 9000 Section 17.2.2). The server can use this
 * token to validate the client's address without requiring a Retry packet.
 *
 * NEW_TOKEN frames MUST NOT be sent by a client, and MUST NOT be sent in
 * Initial or Handshake packets. They are only sent in 1-RTT packets.
 *
 * The token MUST NOT be empty (zero-length tokens are invalid).
 *
 * @param token      Opaque token data (server-generated)
 * @param token_len  Length of token in bytes (MUST be > 0)
 * @param out        Output buffer for encoded frame
 * @param out_len    Size of output buffer
 *
 * @return Number of bytes written on success, 0 on error
 *
 * Error conditions:
 * - NULL output buffer
 * - NULL token with non-zero length
 * - Zero-length token (invalid per RFC 9000)
 * - Token length exceeds varint maximum
 * - Insufficient output buffer space
 */

size_t
SocketQUICFrame_encode_new_token (const uint8_t *token, size_t token_len,
                                   uint8_t *out, size_t out_len)
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

  if (token_len_varint == 0)
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

/* ============================================================================
 * NEW_TOKEN Frame Decoding (RFC 9000 Section 19.7)
 * ============================================================================
 *
 * Decodes a NEW_TOKEN frame from wire format.
 *
 * Note: The main frame parsing logic in SocketQUICFrame.c already handles
 * NEW_TOKEN decoding as part of SocketQUICFrame_parse(). This function
 * provides a convenience wrapper for standalone NEW_TOKEN decoding.
 *
 * The decoded token pointer will reference the input data buffer directly
 * (no copy is made), so the input buffer must remain valid for the lifetime
 * of the token usage.
 *
 * @param data       Input buffer containing encoded NEW_TOKEN frame
 * @param len        Length of input buffer
 * @param token_out  Output buffer for token data
 * @param token_len  Input: size of token_out buffer
 *                   Output: actual token length
 *
 * @return 0 on success, -1 on error
 *
 * Error conditions:
 * - NULL input buffer or token_out or token_len
 * - Empty input buffer
 * - Frame type is not NEW_TOKEN (0x07)
 * - Truncated frame data
 * - Empty token (invalid per RFC 9000)
 * - Token too large for output buffer
 */

int
SocketQUICFrame_decode_new_token (const uint8_t *data, size_t len,
                                   uint8_t *token_out, size_t *token_len)
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

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICFrame-connid.c
 * @brief QUIC Connection ID Frame Encoding (RFC 9000 §19.15-19.16).
 *
 * This module implements encoding for:
 * - NEW_CONNECTION_ID (0x18): Provides a new connection ID to the peer
 * - RETIRE_CONNECTION_ID (0x19): Retires a previously issued connection ID
 *
 * RFC 9000 Section 19.15 - NEW_CONNECTION_ID Frame Format:
 *   Type (i) = 0x18
 *   Sequence Number (i)
 *   Retire Prior To (i)
 *   Length (8) = 1-20
 *   Connection ID (8..160)
 *   Stateless Reset Token (128)
 *
 * RFC 9000 Section 19.16 - RETIRE_CONNECTION_ID Frame Format:
 *   Type (i) = 0x19
 *   Sequence Number (i)
 */

#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICVarInt.h"
#include "quic/SocketQUICConnectionID.h"

#include <string.h>

/* ============================================================================
 * NEW_CONNECTION_ID Frame Encoding (RFC 9000 §19.15)
 * ============================================================================
 */

/**
 * @brief Encode a NEW_CONNECTION_ID frame.
 *
 * Format:
 *   Type (i) = 0x18
 *   Sequence Number (i)
 *   Retire Prior To (i)
 *   Length (8 bits) = cid_length
 *   Connection ID (cid_length bytes)
 *   Stateless Reset Token (128 bits = 16 bytes)
 *
 * @param sequence         Sequence number for this connection ID
 * @param retire_prior_to  Connection IDs < this value should be retired
 * @param cid_length       Length of connection ID (1-20 bytes)
 * @param cid              Connection ID bytes
 * @param reset_token      16-byte stateless reset token
 * @param out              Output buffer
 * @param out_size         Size of output buffer
 *
 * @return Number of bytes written, or 0 on error
 *
 * @note retire_prior_to MUST be <= sequence (RFC 9000 §19.15)
 * @note cid_length MUST be 1-20 (RFC 9000 §19.15)
 */
size_t
SocketQUICFrame_encode_new_connection_id (uint64_t sequence,
                                          uint64_t retire_prior_to,
                                          uint8_t cid_length,
                                          const uint8_t *cid,
                                          const uint8_t reset_token[16],
                                          uint8_t *out, size_t out_size)
{
  /* Validate inputs */
  if (!out || !cid || !reset_token)
    return 0;

  /* Validate retire_prior_to <= sequence (RFC 9000 §19.15) */
  if (retire_prior_to > sequence)
    return 0;

  /* Validate CID length (1-20 bytes for NEW_CONNECTION_ID) */
  if (cid_length < 1 || cid_length > 20)
    return 0;

  size_t pos = 0;

  /* Calculate required size */
  size_t type_len = SocketQUICVarInt_size (QUIC_FRAME_NEW_CONNECTION_ID);
  size_t seq_len = SocketQUICVarInt_size (sequence);
  size_t retire_len = SocketQUICVarInt_size (retire_prior_to);
  size_t total_len = type_len + seq_len + retire_len + 1 + cid_length + QUIC_STATELESS_RESET_TOKEN_LEN;

  if (out_size < total_len)
    return 0;

  /* Encode frame type */
  if (!encode_varint_field (QUIC_FRAME_NEW_CONNECTION_ID, out, &pos, out_size))
    return 0;

  /* Encode sequence number */
  if (!encode_varint_field (sequence, out, &pos, out_size))
    return 0;

  /* Encode retire_prior_to */
  if (!encode_varint_field (retire_prior_to, out, &pos, out_size))
    return 0;

  /* Encode CID length (1 byte) */
  out[pos++] = cid_length;

  /* Encode connection ID */
  memcpy (out + pos, cid, cid_length);
  pos += cid_length;

  /* Encode stateless reset token */
  memcpy (out + pos, reset_token, QUIC_STATELESS_RESET_TOKEN_LEN);
  pos += QUIC_STATELESS_RESET_TOKEN_LEN;

  return pos;
}

/* ============================================================================
 * RETIRE_CONNECTION_ID Frame Encoding (RFC 9000 §19.16)
 * ============================================================================
 */

/**
 * @brief Encode a RETIRE_CONNECTION_ID frame.
 *
 * Format:
 *   Type (i) = 0x19
 *   Sequence Number (i)
 *
 * The sequence number identifies which connection ID is being retired.
 *
 * @param sequence  Sequence number of the connection ID to retire
 * @param out       Output buffer
 * @param out_size  Size of output buffer
 *
 * @return Number of bytes written, or 0 on error
 */
size_t
SocketQUICFrame_encode_retire_connection_id (uint64_t sequence, uint8_t *out,
                                              size_t out_size)
{
  /* Validate inputs */
  if (!out)
    return 0;

  size_t pos = 0;

  /* Calculate required size */
  size_t type_len = SocketQUICVarInt_size (QUIC_FRAME_RETIRE_CONNECTION_ID);
  size_t seq_len = SocketQUICVarInt_size (sequence);
  size_t total_len = type_len + seq_len;

  if (out_size < total_len)
    return 0;

  /* Encode frame type */
  if (!encode_varint_field (QUIC_FRAME_RETIRE_CONNECTION_ID, out, &pos, out_size))
    return 0;

  /* Encode sequence number */
  if (!encode_varint_field (sequence, out, &pos, out_size))
    return 0;

  return pos;
}

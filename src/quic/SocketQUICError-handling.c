/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICError-handling.c
 * @brief QUIC Error Handling (RFC 9000 Section 11).
 *
 * Implements connection-level and stream-level error handling with
 * appropriate frame generation for CONNECTION_CLOSE, RESET_STREAM,
 * and STOP_SENDING.
 */

#include "quic/SocketQUICError.h"
#include "quic/SocketQUICConnection.h"
#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICStream.h"
#include "quic/SocketQUICVarInt.h"

#include <string.h>

/* ============================================================================
 * Error Classification (RFC 9000 Section 11)
 * ============================================================================
 */

int
SocketQUIC_error_is_connection_fatal (uint64_t code)
{
  /* Transport errors (0x00-0x10) are always connection-fatal */
  if (SocketQUIC_is_transport_error (code))
    return 1;

  /* Crypto errors (0x0100-0x01ff) are always connection-fatal */
  if (QUIC_IS_CRYPTO_ERROR (code))
    return 1;

  /* Application errors (>= 0x0200) may be connection-fatal */
  /* The application should decide whether to escalate to connection error */
  /* For now, we treat them as potentially fatal (return 1) */
  /* The caller can choose to send CONNECTION_CLOSE or use stream-level reset */
  if (code >= QUIC_APPLICATION_ERROR_BASE)
    return 1;

  /* Unknown error codes in reserved range (0x11-0xff) */
  return 0;
}

/* ============================================================================
 * Connection Close (RFC 9000 Section 19.19)
 * ============================================================================
 */

size_t
SocketQUIC_send_connection_close (SocketQUICConnection_T conn, uint64_t code,
                                   const char *reason, size_t reason_len,
                                   uint8_t *out, size_t out_len)
{
  size_t offset;
  uint64_t frame_type;
  int is_app_error;

  if (!conn || !out)
    return 0;

  /* Validate reason parameters: if reason is NULL, length must be 0 */
  if (!reason && reason_len != 0)
    return 0;

  /* Determine if this is an application error (0x1d) or transport error (0x1c) */
  is_app_error
      = (code >= QUIC_APPLICATION_ERROR_BASE) || (code == QUIC_APPLICATION_ERROR);

  /* Frame type */
  frame_type = is_app_error ? QUIC_FRAME_CONNECTION_CLOSE_APP
                            : QUIC_FRAME_CONNECTION_CLOSE;

  /* Clamp reason length to maximum allowed */
  if (reason_len > QUIC_MAX_REASON_LENGTH)
    reason_len = QUIC_MAX_REASON_LENGTH;

  /* Estimate minimum required buffer size:
   * - Frame type: 1 byte (varint)
   * - Error code: up to 8 bytes (varint)
   * - Frame type field (for transport errors): up to 8 bytes (varint)
   * - Reason length: up to 8 bytes (varint)
   * - Reason phrase: reason_len bytes
   */
  size_t min_size = 1 + 8 + (is_app_error ? 0 : 8) + 8 + reason_len;
  if (out_len < min_size)
    return 0;

  offset = 0;

  /* Encode frame type */
  if (!encode_varint_field (frame_type, out, &offset, out_len))
    return 0;

  /* Encode error code */
  if (!encode_varint_field (code, out, &offset, out_len))
    return 0;

  /* For transport errors (0x1c), include triggering frame type field */
  /* For application errors (0x1d), skip frame type field */
  if (!is_app_error)
    {
      /* Frame type field - use 0 for "no specific frame" */
      if (!encode_varint_field (0, out, &offset, out_len))
        return 0;
    }

  /* Encode reason phrase length */
  if (!encode_varint_field (reason_len, out, &offset, out_len))
    return 0;

  /* Copy reason phrase */
  if (reason_len > 0)
    {
      if (offset + reason_len > out_len)
        return 0;

      memcpy (out + offset, reason, reason_len);
      offset += reason_len;
    }

  return offset;
}

/* ============================================================================
 * Stream Reset (RFC 9000 Section 19.4)
 * ============================================================================
 */

size_t
SocketQUIC_send_stream_reset (SocketQUICStream_T stream, uint64_t code,
                               uint64_t final_size, uint8_t *out,
                               size_t out_len)
{
  size_t offset;
  uint64_t stream_id;

  if (!stream || !out)
    return 0;

  stream_id = SocketQUICStream_get_id (stream);

  /* RESET_STREAM frame format:
   * - Frame type (0x04): 1 byte
   * - Stream ID: varint
   * - Application error code: varint
   * - Final size: varint
   */
  size_t min_size = QUIC_FRAME_MIN_SIZE_RESET_STREAM;
  if (out_len < min_size)
    return 0;

  offset = 0;

  /* Encode frame type (RESET_STREAM = 0x04) */
  if (!encode_varint_field (QUIC_FRAME_RESET_STREAM, out, &offset, out_len))
    return 0;

  /* Encode stream ID */
  if (!encode_varint_field (stream_id, out, &offset, out_len))
    return 0;

  /* Encode application error code */
  if (!encode_varint_field (code, out, &offset, out_len))
    return 0;

  /* Encode final size */
  if (!encode_varint_field (final_size, out, &offset, out_len))
    return 0;

  return offset;
}

/* ============================================================================
 * Stop Sending (RFC 9000 Section 19.5)
 * ============================================================================
 */

size_t
SocketQUIC_send_stop_sending (SocketQUICStream_T stream, uint64_t code,
                               uint8_t *out, size_t out_len)
{
  size_t offset;
  uint64_t stream_id;

  if (!stream || !out)
    return 0;

  stream_id = SocketQUICStream_get_id (stream);

  /* STOP_SENDING frame format:
   * - Frame type (0x05): 1 byte
   * - Stream ID: varint
   * - Application error code: varint
   */
  size_t min_size = QUIC_FRAME_MIN_SIZE_STOP_SENDING;
  if (out_len < min_size)
    return 0;

  offset = 0;

  /* Encode frame type (STOP_SENDING = 0x05) */
  if (!encode_varint_field (QUIC_FRAME_STOP_SENDING, out, &offset, out_len))
    return 0;

  /* Encode stream ID */
  if (!encode_varint_field (stream_id, out, &offset, out_len))
    return 0;

  /* Encode application error code */
  if (!encode_varint_field (code, out, &offset, out_len))
    return 0;

  return offset;
}

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

#include <stdint.h>
#include <string.h>

/**
 * @brief Validate frame encoding parameters.
 *
 * Ensures that both the object pointer and output buffer are non-NULL
 * before proceeding with frame encoding. Returns 0 if validation fails.
 *
 * @param obj Object pointer (connection or stream).
 * @param out Output buffer pointer.
 */
#define VALIDATE_FRAME_PARAMS(obj, out) \
  do                                    \
    {                                   \
      if (!(obj) || !(out))             \
        return 0;                       \
    }                                   \
  while (0)

/**
 * @brief Validate frame output buffer has sufficient size.
 *
 * Checks that the output buffer is non-NULL and has at least the minimum
 * required size for frame encoding. This centralizes the validation logic
 * used across all frame encoding functions.
 *
 * @param out      Output buffer pointer.
 * @param out_len  Output buffer size in bytes.
 * @param min_size Minimum required size in bytes.
 *
 * @return 1 if buffer is valid and large enough, 0 otherwise.
 */
static inline int
validate_frame_buffer (const uint8_t *out, size_t out_len, size_t min_size)
{
  return out != NULL && out_len >= min_size;
}

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

/**
 * @brief Validate CONNECTION_CLOSE parameters and clamp reason length.
 *
 * Validates the connection pointer, output buffer, and reason parameters.
 * Clamps the reason phrase length to QUIC_MAX_REASON_LENGTH if needed.
 *
 * @param conn       Connection pointer (must be non-NULL).
 * @param out        Output buffer pointer (must be non-NULL).
 * @param reason     Reason phrase pointer (may be NULL if reason_len is 0).
 * @param reason_len Pointer to reason length (will be clamped).
 *
 * @return 1 if valid, 0 if invalid.
 */
static inline int
validate_connection_close_params (SocketQUICConnection_T conn,
                                  const uint8_t *out,
                                  const char *reason,
                                  size_t *reason_len)
{
  if (!conn || !out)
    return 0;

  /* Validate reason parameters: if reason is NULL, length must be 0 */
  if (!reason && *reason_len != 0)
    return 0;

  /* Clamp reason length to maximum allowed */
  if (*reason_len > QUIC_MAX_REASON_LENGTH)
    *reason_len = QUIC_MAX_REASON_LENGTH;

  return 1;
}

/**
 * @brief Calculate required buffer size for CONNECTION_CLOSE frame.
 *
 * Computes the minimum buffer size needed for the frame header plus
 * reason phrase, with overflow protection.
 *
 * @param is_app_error Whether this is an application error (vs transport).
 * @param reason_len   Length of reason phrase.
 *
 * @return Required size in bytes, or 0 on overflow.
 */
static inline size_t
calculate_connection_close_size (int is_app_error, size_t reason_len)
{
  size_t base_size = is_app_error
                         ? QUIC_FRAME_MIN_SIZE_CONNECTION_CLOSE_APP
                         : QUIC_FRAME_MIN_SIZE_CONNECTION_CLOSE_TRANSPORT;

  /* Check for overflow before adding reason_len (CWE-190, CERT INT30-C) */
  if (reason_len > SIZE_MAX - base_size)
    return 0;

  return base_size + reason_len;
}

/**
 * @brief Encode CONNECTION_CLOSE frame header fields.
 *
 * Encodes the frame type, error code, and conditional frame type field
 * (for transport errors only) into the output buffer.
 *
 * @param frame_type   Frame type (0x1c or 0x1d).
 * @param code         Error code.
 * @param is_app_error Whether this is an application error.
 * @param out          Output buffer.
 * @param offset       Current offset (updated on success).
 * @param out_len      Output buffer size.
 *
 * @return 1 on success, 0 on error.
 */
static inline int
encode_connection_close_header (uint64_t frame_type,
                                uint64_t code,
                                int is_app_error,
                                uint8_t *out,
                                size_t *offset,
                                size_t out_len)
{
  /* Encode frame type */
  if (!encode_varint_field (frame_type, out, offset, out_len))
    return 0;

  /* Encode error code */
  if (!encode_varint_field (code, out, offset, out_len))
    return 0;

  /* For transport errors (0x1c), include triggering frame type field */
  /* For application errors (0x1d), skip frame type field */
  if (!is_app_error)
    {
      /* Frame type field - use 0 for "no specific frame" */
      if (!encode_varint_field (0, out, offset, out_len))
        return 0;
    }

  return 1;
}

/**
 * @brief Encode reason phrase into CONNECTION_CLOSE frame.
 *
 * Encodes the reason phrase length and copies the reason data with
 * overflow protection.
 *
 * @param reason     Reason phrase pointer.
 * @param reason_len Reason phrase length.
 * @param out        Output buffer.
 * @param offset     Current offset (updated on success).
 * @param out_len    Output buffer size.
 *
 * @return 1 on success, 0 on error.
 */
static inline int
encode_reason_phrase (const char *reason,
                      size_t reason_len,
                      uint8_t *out,
                      size_t *offset,
                      size_t out_len)
{
  /* Encode reason phrase length */
  if (!encode_varint_field (reason_len, out, offset, out_len))
    return 0;

  /* Copy reason phrase */
  if (reason_len > 0)
    {
      /* Prevent integer overflow: check if reason_len > (out_len - offset) */
      if (*offset > out_len || reason_len > out_len - *offset)
        return 0;

      memcpy (out + *offset, reason, reason_len);
      *offset += reason_len;
    }

  return 1;
}

size_t
SocketQUIC_send_connection_close (SocketQUICConnection_T conn,
                                  uint64_t code,
                                  const char *reason,
                                  size_t reason_len,
                                  uint8_t *out,
                                  size_t out_len)
{
  size_t offset;
  uint64_t frame_type;
  int is_app_error;
  size_t min_size;

  /* Validate parameters and clamp reason length */
  if (!validate_connection_close_params (conn, out, reason, &reason_len))
    return 0;

  /* Determine if this is an application error (0x1d) or transport error (0x1c)
   */
  is_app_error = (code >= QUIC_APPLICATION_ERROR_BASE)
                 || (code == QUIC_APPLICATION_ERROR);

  /* Frame type */
  frame_type = is_app_error ? QUIC_FRAME_CONNECTION_CLOSE_APP
                            : QUIC_FRAME_CONNECTION_CLOSE;

  /* Calculate required buffer size with overflow protection */
  min_size = calculate_connection_close_size (is_app_error, reason_len);
  if (min_size == 0 || out_len < min_size)
    return 0;

  offset = 0;

  /* Encode frame header (type, code, optional frame type field) */
  if (!encode_connection_close_header (
          frame_type, code, is_app_error, out, &offset, out_len))
    return 0;

  /* Encode reason phrase (length + data) */
  if (!encode_reason_phrase (reason, reason_len, out, &offset, out_len))
    return 0;

  return offset;
}

size_t
SocketQUIC_send_stream_reset (SocketQUICStream_T stream,
                              uint64_t code,
                              uint64_t final_size,
                              uint8_t *out,
                              size_t out_len)
{
  size_t offset;
  uint64_t stream_id;

  VALIDATE_FRAME_PARAMS (stream, out);

  stream_id = SocketQUICStream_get_id (stream);

  /* RESET_STREAM frame format:
   * - Frame type (0x04): 1 byte
   * - Stream ID: varint
   * - Application error code: varint
   * - Final size: varint
   */
  if (!validate_frame_buffer (out, out_len, QUIC_FRAME_MIN_SIZE_RESET_STREAM))
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

size_t
SocketQUIC_send_stop_sending (SocketQUICStream_T stream,
                              uint64_t code,
                              uint8_t *out,
                              size_t out_len)
{
  size_t offset;
  uint64_t stream_id;

  VALIDATE_FRAME_PARAMS (stream, out);

  stream_id = SocketQUICStream_get_id (stream);

  /* STOP_SENDING frame format:
   * - Frame type (0x05): 1 byte
   * - Stream ID: varint
   * - Application error code: varint
   */
  if (!validate_frame_buffer (out, out_len, QUIC_FRAME_MIN_SIZE_STOP_SENDING))
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

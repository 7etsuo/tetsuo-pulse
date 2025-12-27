/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICFrame-close.c
 * @brief CONNECTION_CLOSE frame encoding (RFC 9000 Section 19.19).
 *
 * Implements encoding for both transport-level (0x1c) and application-level
 * (0x1d) CONNECTION_CLOSE frames. These frames terminate a connection and
 * include an error code, optional frame type (transport only), and optional
 * UTF-8 reason phrase.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9000#section-19.19
 */

#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICVarInt.h"

#include <string.h>

/**
 * @brief Encode CONNECTION_CLOSE frame (transport error, type 0x1c).
 *
 * Encodes a transport-level CONNECTION_CLOSE frame according to RFC 9000
 * Section 19.19. The frame includes:
 * - Frame Type (0x1c)
 * - Error Code (varint)
 * - Frame Type that triggered error (varint)
 * - Reason Phrase Length (varint)
 * - Reason Phrase (UTF-8)
 *
 * @param error_code   Transport error code from Section 20.
 * @param frame_type   Frame type that triggered the error (or 0 if unknown).
 * @param reason       UTF-8 reason phrase (may be NULL for no reason).
 * @param out          Output buffer for encoded frame.
 * @param out_len      Size of output buffer in bytes.
 *
 * @return Number of bytes written on success, 0 on error (buffer too small).
 *
 * @note The reason phrase should be UTF-8 encoded. No validation is performed.
 * @note Error code should be from the transport error code space (Section 20).
 *
 * Example:
 * @code
 * uint8_t buf[256];
 * size_t len = SocketQUICFrame_encode_connection_close_transport(
 *     0x0a,  // PROTOCOL_VIOLATION
 *     0x06,  // CRYPTO frame
 *     "Invalid handshake",
 *     buf, sizeof(buf)
 * );
 * @endcode
 */
size_t
SocketQUICFrame_encode_connection_close_transport (uint64_t error_code,
                                                    uint64_t frame_type,
                                                    const char *reason,
                                                    uint8_t *out,
                                                    size_t out_len)
{
  if (!out || out_len == 0)
    return 0;

  size_t pos = 0;

  /* Frame type (0x1c) */
  if (!encode_varint_field (QUIC_FRAME_CONNECTION_CLOSE, out, &pos, out_len))
    return 0;

  /* Error Code */
  if (!encode_varint_field (error_code, out, &pos, out_len))
    return 0;

  /* Frame Type */
  if (!encode_varint_field (frame_type, out, &pos, out_len))
    return 0;

  /* Reason Phrase Length */
  size_t reason_len = reason ? strlen (reason) : 0;
  if (!encode_varint_field (reason_len, out, &pos, out_len))
    return 0;

  /* Reason Phrase */
  if (reason_len > 0)
    {
      if (pos + reason_len > out_len)
        return 0;
      memcpy (out + pos, reason, reason_len);
      pos += reason_len;
    }

  return pos;
}

/**
 * @brief Encode CONNECTION_CLOSE frame (application error, type 0x1d).
 *
 * Encodes an application-level CONNECTION_CLOSE frame according to RFC 9000
 * Section 19.19. The frame includes:
 * - Frame Type (0x1d)
 * - Error Code (varint)
 * - Reason Phrase Length (varint)
 * - Reason Phrase (UTF-8)
 *
 * Unlike the transport variant, this does NOT include the triggering frame
 * type field.
 *
 * @param error_code   Application-defined error code.
 * @param reason       UTF-8 reason phrase (may be NULL for no reason).
 * @param out          Output buffer for encoded frame.
 * @param out_len      Size of output buffer in bytes.
 *
 * @return Number of bytes written on success, 0 on error (buffer too small).
 *
 * @note The reason phrase should be UTF-8 encoded. No validation is performed.
 * @note Error code is application-defined and not from the transport space.
 *
 * Example:
 * @code
 * uint8_t buf[256];
 * size_t len = SocketQUICFrame_encode_connection_close_app(
 *     1000,  // Application error code
 *     "User requested shutdown",
 *     buf, sizeof(buf)
 * );
 * @endcode
 */
size_t
SocketQUICFrame_encode_connection_close_app (uint64_t error_code,
                                              const char *reason,
                                              uint8_t *out, size_t out_len)
{
  if (!out || out_len == 0)
    return 0;

  size_t pos = 0;

  /* Frame type (0x1d) */
  if (!encode_varint_field (QUIC_FRAME_CONNECTION_CLOSE_APP, out, &pos, out_len))
    return 0;

  /* Error Code */
  if (!encode_varint_field (error_code, out, &pos, out_len))
    return 0;

  /* Reason Phrase Length */
  size_t reason_len = reason ? strlen (reason) : 0;
  if (!encode_varint_field (reason_len, out, &pos, out_len))
    return 0;

  /* Reason Phrase */
  if (reason_len > 0)
    {
      if (pos + reason_len > out_len)
        return 0;
      memcpy (out + pos, reason, reason_len);
      pos += reason_len;
    }

  return pos;
}

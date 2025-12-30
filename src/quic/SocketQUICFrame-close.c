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
#include "core/SocketUTF8.h"

#include <string.h>

/**
 * @brief Validate UTF-8 reason phrase and return its length.
 *
 * Uses strnlen() to limit the maximum length scanned, protecting against
 * denial-of-service attacks via extremely long reason strings (CWE-400).
 * The RFC 9000 Section 19.19 doesn't specify a hard limit, but practical
 * implementations must enforce one to prevent resource exhaustion.
 *
 * @param reason  Reason phrase to validate (may be NULL).
 * @param out_len Output: length of reason phrase (capped at QUIC_REASON_MAX_LENGTH).
 *
 * @return 1 if valid (or NULL), 0 if invalid UTF-8 or exceeds maximum length.
 */
static int
validate_utf8_reason (const char *reason, size_t *out_len)
{
  if (!reason)
    {
      *out_len = 0;
      return 1;
    }

  /* Use strnlen to limit scanning and prevent DoS via long strings.
   * Check for length+1 to detect strings that exceed the limit. */
  *out_len = strnlen (reason, QUIC_REASON_MAX_LENGTH + 1);
  if (*out_len > QUIC_REASON_MAX_LENGTH)
    return 0; /* Reason phrase too long */

  if (*out_len > 0
      && SocketUTF8_validate ((const unsigned char *)reason, *out_len)
             != UTF8_VALID)
    return 0;
  return 1;
}

/**
 * @brief Common encoding logic for CONNECTION_CLOSE frames.
 *
 * This helper function implements the shared encoding logic between transport
 * and application CONNECTION_CLOSE frames, reducing code duplication and
 * ensuring consistent handling of overflow protection and UTF-8 validation.
 *
 * @param frame_type_byte   Frame type (0x1c for transport, 0x1d for app).
 * @param error_code        Error code to encode.
 * @param frame_type_ptr    Pointer to frame type field (NULL for app variant).
 * @param reason            UTF-8 reason phrase (may be NULL).
 * @param out               Output buffer for encoded frame.
 * @param out_len           Size of output buffer in bytes.
 *
 * @return Number of bytes written on success, 0 on error.
 */
static size_t
encode_connection_close_common (uint8_t frame_type_byte, uint64_t error_code,
                                 const uint64_t *frame_type_ptr,
                                 const char *reason, uint8_t *out,
                                 size_t out_len)
{
  if (!out || out_len == 0)
    return 0;

  /* Validate UTF-8 encoding of reason phrase per RFC 9000 Section 19.19 */
  size_t reason_len;
  if (!validate_utf8_reason (reason, &reason_len))
    return 0;

  /* Calculate required size */
  size_t type_len = QUIC_FRAME_TYPE_SIZE;
  size_t error_code_len = SocketQUICVarInt_size (error_code);
  size_t frame_type_len = frame_type_ptr ? SocketQUICVarInt_size (*frame_type_ptr) : 0;
  size_t reason_len_size = SocketQUICVarInt_size (reason_len);

  if (error_code_len == 0 || reason_len_size == 0)
    return 0; /* Value exceeds varint maximum */

  if (frame_type_ptr && frame_type_len == 0)
    return 0; /* Frame type value exceeds varint maximum */

  /* Check for integer overflow in total_len calculation.
   * Prevent SIZE_MAX wraparound that could bypass buffer size check. */
  size_t fixed_size = type_len + error_code_len + frame_type_len + reason_len_size;
  if (reason_len > SIZE_MAX - fixed_size)
    return 0; /* Overflow would occur */

  size_t total_len = fixed_size + reason_len;

  if (out_len < total_len)
    return 0; /* Buffer too small */

  size_t pos = 0;

  /* Frame type */
  out[pos++] = frame_type_byte;

  /* Error Code */
  if (!encode_varint_field (error_code, out, &pos, out_len))
    return 0;

  /* Frame Type (transport variant only) */
  if (frame_type_ptr)
    {
      if (!encode_varint_field (*frame_type_ptr, out, &pos, out_len))
        return 0;
    }

  /* Reason Phrase Length */
  if (!encode_varint_field (reason_len, out, &pos, out_len))
    return 0;

  /* Reason Phrase */
  if (reason_len > 0)
    {
      memcpy (out + pos, reason, reason_len);
      pos += reason_len;
    }

  return pos;
}

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
 * @note The reason phrase must be valid UTF-8. Returns 0 if validation fails.
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
  return encode_connection_close_common (QUIC_FRAME_CONNECTION_CLOSE,
                                          error_code, &frame_type, reason, out,
                                          out_len);
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
 * @note The reason phrase must be valid UTF-8. Returns 0 if validation fails.
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
  return encode_connection_close_common (QUIC_FRAME_CONNECTION_CLOSE_APP,
                                          error_code, NULL, reason, out,
                                          out_len);
}

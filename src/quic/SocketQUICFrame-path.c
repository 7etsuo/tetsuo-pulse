/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICFrame-path.c
 * @brief QUIC PATH_CHALLENGE and PATH_RESPONSE frame encoding (RFC 9000 §19.17-19.18).
 */

#include "quic/SocketQUICFrame.h"
#include <string.h>

/* ============================================================================
 * Internal helper functions
 * ============================================================================
 *
 * These helpers eliminate code duplication between PATH_CHALLENGE and
 * PATH_RESPONSE frame encode/decode operations, which differ only in the
 * frame type constant used.
 */

/**
 * Internal helper for encoding PATH frames.
 *
 * @param frame_type  The frame type byte (0x1a for CHALLENGE, 0x1b for RESPONSE)
 * @param data        8-byte data payload
 * @param out         Output buffer (at least QUIC_PATH_FRAME_SIZE bytes)
 * @param out_size    Size of output buffer
 * @return            Number of bytes written, or 0 on error
 */
static size_t
encode_path_frame (uint8_t frame_type, const uint8_t data[QUIC_PATH_DATA_SIZE],
                   uint8_t *out, size_t out_size)
{
  if (!data || !out)
    return 0;

  if (out_size < QUIC_PATH_FRAME_SIZE)
    return 0;

  /* Frame type */
  out[0] = frame_type;

  /* Copy data payload */
  memcpy (out + 1, data, QUIC_PATH_DATA_SIZE);

  return QUIC_PATH_FRAME_SIZE;
}

/**
 * Internal helper for decoding PATH frames.
 *
 * @param expected_type  The expected frame type byte
 * @param in             Input buffer
 * @param len            Length of input buffer
 * @param data           Output buffer for 8-byte data payload
 * @return               Number of bytes consumed, or -1 on error
 */
static int
decode_path_frame (uint8_t expected_type, const uint8_t *in, size_t len,
                   uint8_t data[QUIC_PATH_DATA_SIZE])
{
  if (!in || !data || len < QUIC_PATH_FRAME_SIZE)
    return -1;

  /* Verify frame type */
  if (in[0] != expected_type)
    return -1;

  /* Copy data payload */
  memcpy (data, in + 1, QUIC_PATH_DATA_SIZE);

  return QUIC_PATH_FRAME_SIZE;
}

/* ============================================================================
 * Encode PATH_CHALLENGE frames (RFC 9000 §19.17)
 * ============================================================================
 *
 * PATH_CHALLENGE Frame {
 *   Type (i) = 0x1a,
 *   Data (64),
 * }
 *
 * The Data field contains arbitrary data (typically random).
 */

size_t
SocketQUICFrame_encode_path_challenge (const uint8_t data[QUIC_PATH_DATA_SIZE], uint8_t *out,
                                        size_t out_size)
{
  return encode_path_frame (QUIC_FRAME_PATH_CHALLENGE, data, out, out_size);
}

/* ============================================================================
 * Encode PATH_RESPONSE frames (RFC 9000 §19.18)
 * ============================================================================
 *
 * PATH_RESPONSE Frame {
 *   Type (i) = 0x1b,
 *   Data (64),
 * }
 *
 * The Data field contains the data from the PATH_CHALLENGE frame being
 * responded to.
 */

size_t
SocketQUICFrame_encode_path_response (const uint8_t data[QUIC_PATH_DATA_SIZE], uint8_t *out,
                                       size_t out_size)
{
  return encode_path_frame (QUIC_FRAME_PATH_RESPONSE, data, out, out_size);
}

/* ============================================================================
 * Decode PATH_CHALLENGE frames (RFC 9000 §19.17)
 * ============================================================================
 *
 * Convenience function for decoding PATH_CHALLENGE frames.
 * Returns the number of bytes consumed on success, or -1 on error.
 */

int
SocketQUICFrame_decode_path_challenge (const uint8_t *in, size_t len,
                                       uint8_t data[QUIC_PATH_DATA_SIZE])
{
  return decode_path_frame (QUIC_FRAME_PATH_CHALLENGE, in, len, data);
}

/* ============================================================================
 * Decode PATH_RESPONSE frames (RFC 9000 §19.18)
 * ============================================================================
 *
 * Convenience function for decoding PATH_RESPONSE frames.
 * Returns the number of bytes consumed on success, or -1 on error.
 */

int
SocketQUICFrame_decode_path_response (const uint8_t *in, size_t len,
                                      uint8_t data[QUIC_PATH_DATA_SIZE])
{
  return decode_path_frame (QUIC_FRAME_PATH_RESPONSE, in, len, data);
}

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
SocketQUICFrame_encode_path_challenge (const uint8_t data[8], uint8_t *out)
{
  if (!data || !out)
    return 0;

  /* Frame type */
  out[0] = QUIC_FRAME_PATH_CHALLENGE;

  /* Copy 8-byte challenge data */
  memcpy (out + 1, data, 8);

  return 9; /* 1 byte type + 8 bytes data */
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
SocketQUICFrame_encode_path_response (const uint8_t data[8], uint8_t *out)
{
  if (!data || !out)
    return 0;

  /* Frame type */
  out[0] = QUIC_FRAME_PATH_RESPONSE;

  /* Copy 8-byte response data (echoed from challenge) */
  memcpy (out + 1, data, 8);

  return 9; /* 1 byte type + 8 bytes data */
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
                                       uint8_t data[8])
{
  if (!in || !data || len < 9)
    return -1;

  /* Verify frame type */
  if (in[0] != QUIC_FRAME_PATH_CHALLENGE)
    return -1;

  /* Copy challenge data */
  memcpy (data, in + 1, 8);

  return 9; /* 1 byte type + 8 bytes data */
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
                                      uint8_t data[8])
{
  if (!in || !data || len < 9)
    return -1;

  /* Verify frame type */
  if (in[0] != QUIC_FRAME_PATH_RESPONSE)
    return -1;

  /* Copy response data */
  memcpy (data, in + 1, 8);

  return 9; /* 1 byte type + 8 bytes data */
}

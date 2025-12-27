/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICFrame-handshake.c
 * @brief QUIC HANDSHAKE_DONE frame encoding (RFC 9000 §19.20).
 */

#include "quic/SocketQUICFrame.h"

/* ============================================================================
 * Encode HANDSHAKE_DONE frames (RFC 9000 §19.20)
 * ============================================================================
 *
 * HANDSHAKE_DONE Frame {
 *   Type (i) = 0x1e,
 * }
 *
 * The HANDSHAKE_DONE frame is sent by the server to signal to the client
 * that the handshake is confirmed. It has no fields beyond the type byte.
 *
 * Important constraints (RFC 9000 §19.20):
 * - MUST NOT be sent by a client
 * - MUST be sent only in 1-RTT packets
 * - Signals that handshake keys can be discarded
 * - Causes client to start sending 1-RTT packets with Handshake keys discarded
 */

size_t
SocketQUICFrame_encode_handshake_done (uint8_t *out)
{
  if (!out)
    return 0;

  /* Frame type 0x1e */
  out[0] = QUIC_FRAME_HANDSHAKE_DONE;

  return 1; /* Just the type byte */
}

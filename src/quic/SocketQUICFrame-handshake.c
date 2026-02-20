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

size_t
SocketQUICFrame_encode_handshake_done (uint8_t *out, size_t out_size)
{
  if (!out || out_size < 1)
    return 0;

  /* Frame type 0x1e */
  out[0] = QUIC_FRAME_HANDSHAKE_DONE;

  return 1; /* Just the type byte */
}

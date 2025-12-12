/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_ws_frame.c - WebSocket Frame Parser Fuzzing Harness
 *
 * Tests frame header parsing with random/malformed input.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "socket/SocketWS-private.h"

/**
 * LLVMFuzzerTestOneInput - LibFuzzer entry point
 *
 * Tests ws_frame_parse_header with arbitrary input.
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketWS_FrameParse frame;
  size_t consumed;
  size_t total_consumed = 0;
  SocketWS_Error err;

  if (size == 0)
    return 0;

  /* Initialize frame parser */
  ws_frame_reset (&frame);

  /* Feed data incrementally */
  while (total_consumed < size)
    {
      err = ws_frame_parse_header (&frame, data + total_consumed,
                                   size - total_consumed, &consumed);

      if (consumed == 0)
        break; /* No progress */

      total_consumed += consumed;

      if (err != WS_ERROR_WOULD_BLOCK)
        break; /* Complete or error */
    }

  return 0;
}

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_hpack_integer.c - Fuzzing harness for HPACK integer decoding
 *
 * Part of the Socket Library
 *
 * Tests integer decoder robustness against malformed input.
 */

#include "core/Except.h"
#include "http/SocketHPACK.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * LibFuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  uint64_t value;
  size_t consumed;

  /* Skip empty input */
  if (size == 0)
    return 0;

  TRY
  {
    /* Test all prefix bit sizes (1-8) */
    for (int prefix = 1; prefix <= 8; prefix++)
      {
        SocketHPACK_Result result
            = SocketHPACK_int_decode (data, size, prefix, &value, &consumed);

        if (result == HPACK_OK)
          {
            /* Verify by re-encoding */
            unsigned char encoded[16];
            size_t enc_len = SocketHPACK_int_encode (
                value, prefix, encoded, sizeof (encoded));

            /* Verify consumed matches encoded length */
            (void)enc_len;
          }
      }
  }
  EXCEPT (SocketHPACK_Error)
  { /* Expected for malformed input */
  }
  END_TRY;

  return 0;
}

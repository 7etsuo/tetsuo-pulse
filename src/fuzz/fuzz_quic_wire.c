/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_wire.c - libFuzzer harness for QUIC Packet Number encoding
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Packet number length calculation
 * - Encoding with various largest_acked values
 * - Decoding with wrap-around handling
 * - Read/write round-trips
 * - Encode/decode round-trips
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_quic_wire
 * Run:   ./fuzz_quic_wire -fork=16 -max_len=32
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICWire.h"

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  /* Extract operation from first byte */
  uint8_t op = data[0] % 6;

  switch (op)
    {
    case 0:
      {
        /* Test pn_length with arbitrary values */
        if (size < 17)
          return 0;

        uint64_t full_pn = 0;
        uint64_t largest_acked = 0;

        memcpy (&full_pn, data + 1, 8);
        memcpy (&largest_acked, data + 9, 8);

        /* Mask to valid PN range */
        full_pn &= QUIC_PN_MAX;
        if (largest_acked != QUIC_PN_NONE)
          largest_acked &= QUIC_PN_MAX;

        unsigned len = SocketQUICWire_pn_length (full_pn, largest_acked);
        assert (len >= 1 && len <= 4);
      }
      break;

    case 1:
      {
        /* Test pn_encode with arbitrary values */
        if (size < 17)
          return 0;

        uint64_t full_pn = 0;
        uint64_t largest_acked = 0;
        uint8_t buf[4];

        memcpy (&full_pn, data + 1, 8);
        memcpy (&largest_acked, data + 9, 8);

        /* Mask to valid PN range */
        full_pn &= QUIC_PN_MAX;
        if (largest_acked != QUIC_PN_NONE)
          largest_acked &= QUIC_PN_MAX;

        size_t len
            = SocketQUICWire_pn_encode (full_pn, largest_acked, buf, sizeof (buf));
        assert (len >= 1 && len <= 4);
      }
      break;

    case 2:
      {
        /* Test pn_decode with arbitrary values */
        if (size < 18)
          return 0;

        uint64_t largest_pn = 0;
        uint64_t truncated_pn = 0;
        uint64_t full_pn;

        memcpy (&largest_pn, data + 1, 8);
        memcpy (&truncated_pn, data + 9, 8);

        unsigned pn_nbits_idx = data[17] % 4;
        unsigned pn_nbits_values[] = { 8, 16, 24, 32 };
        unsigned pn_nbits = pn_nbits_values[pn_nbits_idx];

        /* Mask truncated to valid range for bit width */
        uint64_t max_truncated = ((uint64_t)1 << pn_nbits) - 1;
        truncated_pn &= max_truncated;

        /* Mask largest_pn to valid range */
        if (largest_pn != QUIC_PN_NONE)
          largest_pn &= QUIC_PN_MAX;

        SocketQUICWire_Result res = SocketQUICWire_pn_decode (
            largest_pn, truncated_pn, pn_nbits, &full_pn);

        assert (res == QUIC_PN_OK);
        assert (full_pn <= QUIC_PN_MAX
                || largest_pn == QUIC_PN_NONE); /* May wrap near max */
      }
      break;

    case 3:
      {
        /* Test pn_read with arbitrary data */
        if (size < 6)
          return 0;

        unsigned pn_len = (data[1] % 4) + 1; /* 1-4 bytes */
        uint64_t value;

        SocketQUICWire_Result res
            = SocketQUICWire_pn_read (data + 2, size - 2, pn_len, &value);

        if (size - 2 >= pn_len)
          {
            assert (res == QUIC_PN_OK);

            /* Verify round-trip */
            uint8_t buf[4];
            size_t written
                = SocketQUICWire_pn_write (value, pn_len, buf, sizeof (buf));
            assert (written == pn_len);
            assert (memcmp (buf, data + 2, pn_len) == 0);
          }
        else
          {
            assert (res == QUIC_PN_ERROR_BUFFER);
          }
      }
      break;

    case 4:
      {
        /* Test encode/decode round-trip */
        if (size < 17)
          return 0;

        uint64_t full_pn = 0;
        uint64_t largest_acked = 0;

        memcpy (&full_pn, data + 1, 8);
        memcpy (&largest_acked, data + 9, 8);

        /* Mask to valid PN range */
        full_pn &= QUIC_PN_MAX;
        if (largest_acked != QUIC_PN_NONE)
          {
            largest_acked &= QUIC_PN_MAX;
            /* Ensure largest_acked < full_pn for valid scenario */
            if (largest_acked >= full_pn && full_pn > 0)
              largest_acked = full_pn - 1;
          }

        uint8_t buf[4];
        size_t len = SocketQUICWire_pn_encode (full_pn, largest_acked, buf,
                                               sizeof (buf));
        assert (len >= 1 && len <= 4);

        /* Read truncated value */
        uint64_t truncated;
        SocketQUICWire_Result res
            = SocketQUICWire_pn_read (buf, len, (unsigned)len, &truncated);
        assert (res == QUIC_PN_OK);

        /* Decode back */
        uint64_t decoded;
        res = SocketQUICWire_pn_decode (largest_acked, truncated,
                                        (unsigned)len * 8, &decoded);
        assert (res == QUIC_PN_OK);
        assert (decoded == full_pn);
      }
      break;

    case 5:
      {
        /* Test pn_write with arbitrary values */
        if (size < 10)
          return 0;

        uint64_t value = 0;
        memcpy (&value, data + 1, 8);

        unsigned pn_len = (data[9] % 4) + 1; /* 1-4 bytes */
        uint8_t buf[4];

        size_t written
            = SocketQUICWire_pn_write (value, pn_len, buf, sizeof (buf));
        assert (written == pn_len);

        /* Verify read back */
        uint64_t read_value;
        SocketQUICWire_Result res
            = SocketQUICWire_pn_read (buf, pn_len, pn_len, &read_value);
        assert (res == QUIC_PN_OK);

        /* Value should match in the least significant bytes */
        uint64_t mask = ((uint64_t)1 << (pn_len * 8)) - 1;
        assert ((value & mask) == read_value);
      }
      break;
    }

  /* Always verify pn_is_valid */
  if (size >= 9)
    {
      uint64_t pn = 0;
      memcpy (&pn, data + 1, 8);

      int valid = SocketQUICWire_pn_is_valid (pn);
      assert (valid == (pn <= QUIC_PN_MAX));
    }

  return 0;
}

/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_connid.c - libFuzzer harness for QUIC Connection IDs
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Connection ID initialization and setting
 * - Wire format decoding with arbitrary input
 * - Encoding/decoding round-trips
 * - Hash function with various inputs
 * - Comparison functions
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_quic_connid
 * Run:   ./fuzz_quic_connid -fork=16 -max_len=64
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICConnectionID.h"

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 1)
    return 0;

  /* Extract operation from first byte */
  uint8_t op = data[0] % 8;

  switch (op)
    {
    case 0:
      {
        /* Test Connection ID set with arbitrary data */
        SocketQUICConnectionID_T cid;
        size_t len = (size > 1) ? data[1] % 25 : 0; /* Include invalid lengths */

        SocketQUICConnectionID_Result res
            = SocketQUICConnectionID_set (&cid, data + 2, len);

        if (len <= QUIC_CONNID_MAX_LEN && size >= 2 + len)
          {
            assert (res == QUIC_CONNID_OK);
            assert (cid.len == len);
          }
        else if (len > QUIC_CONNID_MAX_LEN)
          {
            assert (res == QUIC_CONNID_ERROR_LENGTH);
          }
      }
      break;

    case 1:
      {
        /* Test Connection ID decode with length prefix */
        if (size < 2)
          return 0;

        SocketQUICConnectionID_T cid;
        size_t consumed = 0;

        SocketQUICConnectionID_Result res
            = SocketQUICConnectionID_decode (data + 1, size - 1, &cid,
                                             &consumed);

        if (res == QUIC_CONNID_OK)
          {
            assert (consumed >= 1);
            assert (consumed <= size - 1);
            assert (cid.len <= QUIC_CONNID_MAX_LEN);

            /* Verify round-trip */
            uint8_t buf[25];
            size_t encoded
                = SocketQUICConnectionID_encode_with_length (&cid, buf,
                                                             sizeof (buf));
            assert (encoded == consumed);
            assert (memcmp (buf, data + 1, consumed) == 0);
          }
      }
      break;

    case 2:
      {
        /* Test Connection ID decode with fixed length */
        if (size < 2)
          return 0;

        SocketQUICConnectionID_T cid;
        size_t cid_len = data[1] % 25;

        SocketQUICConnectionID_Result res
            = SocketQUICConnectionID_decode_fixed (data + 2, size - 2, &cid,
                                                   cid_len);

        if (res == QUIC_CONNID_OK)
          {
            assert (cid.len == cid_len);
            assert (cid.len <= QUIC_CONNID_MAX_LEN);
          }
      }
      break;

    case 3:
      {
        /* Test Connection ID comparison */
        SocketQUICConnectionID_T cid1, cid2;

        if (size < 4)
          return 0;

        size_t len1 = data[1] % (QUIC_CONNID_MAX_LEN + 1);
        size_t len2 = data[2] % (QUIC_CONNID_MAX_LEN + 1);

        if (size >= 3 + len1)
          SocketQUICConnectionID_set (&cid1, data + 3, len1);
        else
          SocketQUICConnectionID_init (&cid1);

        if (size >= 3 + len1 + len2)
          SocketQUICConnectionID_set (&cid2, data + 3 + len1, len2);
        else
          SocketQUICConnectionID_init (&cid2);

        int eq = SocketQUICConnectionID_equal (&cid1, &cid2);

        /* Verify equality is reflexive */
        assert (SocketQUICConnectionID_equal (&cid1, &cid1));
        assert (SocketQUICConnectionID_equal (&cid2, &cid2));

        /* Verify equality is symmetric */
        assert (eq == SocketQUICConnectionID_equal (&cid2, &cid1));
      }
      break;

    case 4:
      {
        /* Test hash function */
        SocketQUICConnectionID_T cid;

        if (size < 2)
          return 0;

        size_t len = data[1] % (QUIC_CONNID_MAX_LEN + 1);

        if (size >= 2 + len)
          SocketQUICConnectionID_set (&cid, data + 2, len);
        else
          SocketQUICConnectionID_init (&cid);

        uint32_t hash1 = SocketQUICConnectionID_hash (&cid);
        uint32_t hash2 = SocketQUICConnectionID_hash (&cid);

        /* Hash should be deterministic */
        assert (hash1 == hash2);
      }
      break;

    case 5:
      {
        /* Test encoding functions */
        SocketQUICConnectionID_T cid;
        uint8_t buf[25];

        if (size < 2)
          return 0;

        size_t len = data[1] % (QUIC_CONNID_MAX_LEN + 1);

        if (size >= 2 + len)
          SocketQUICConnectionID_set (&cid, data + 2, len);
        else
          SocketQUICConnectionID_init (&cid);

        /* Test all encoding functions */
        size_t n1 = SocketQUICConnectionID_encode_length (&cid, buf,
                                                          sizeof (buf));
        assert (n1 == 1);
        assert (buf[0] == cid.len);

        if (cid.len > 0)
          {
            size_t n2 = SocketQUICConnectionID_encode (&cid, buf, sizeof (buf));
            assert (n2 == cid.len);
          }

        size_t n3 = SocketQUICConnectionID_encode_with_length (&cid, buf,
                                                               sizeof (buf));
        assert (n3 == 1 + cid.len);
      }
      break;

    case 6:
      {
        /* Test copy function */
        SocketQUICConnectionID_T src, dst;

        if (size < 2)
          return 0;

        size_t len = data[1] % (QUIC_CONNID_MAX_LEN + 1);

        if (size >= 2 + len)
          SocketQUICConnectionID_set (&src, data + 2, len);
        else
          SocketQUICConnectionID_init (&src);

        src.sequence = 42;

        SocketQUICConnectionID_Result res
            = SocketQUICConnectionID_copy (&dst, &src);

        assert (res == QUIC_CONNID_OK);
        assert (SocketQUICConnectionID_equal (&dst, &src));
        assert (dst.sequence == 42);
      }
      break;

    case 7:
      {
        /* Test hex formatting */
        SocketQUICConnectionID_T cid;
        char buf[100];

        if (size < 2)
          return 0;

        size_t len = data[1] % (QUIC_CONNID_MAX_LEN + 1);

        if (size >= 2 + len)
          SocketQUICConnectionID_set (&cid, data + 2, len);
        else
          SocketQUICConnectionID_init (&cid);

        int n = SocketQUICConnectionID_to_hex (&cid, buf, sizeof (buf));

        if (cid.len == 0)
          {
            assert (n == 5); /* "empty" */
            assert (strcmp (buf, "empty") == 0);
          }
        else
          {
            assert (n > 0);
            assert ((size_t)n == cid.len * 3 - 1); /* "XX:XX:..." */
          }
      }
      break;
    }

  /* Exercise is_empty and is_valid_length with all input bytes */
  for (size_t i = 0; i < size && i < 30; i++)
    {
      int valid = SocketQUICConnectionID_is_valid_length (data[i]);
      assert (valid == (data[i] <= QUIC_CONNID_MAX_LEN));
    }

  return 0;
}

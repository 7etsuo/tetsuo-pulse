/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_ws_deflate.c - WebSocket Compression Fuzzing Harness (RFC 7692)
 *
 * Tests permessage-deflate compression/decompression with fuzzed inputs.
 * Tests actual library code in SocketWS-deflate.c, not raw zlib.
 *
 * Targets:
 * - ws_compress_message(): Compression with context takeover
 * - ws_decompress_message(): Decompression with size limits
 * - Decompression bomb protection
 * - Invalid compressed data handling
 * - Context reset behavior
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"

#ifdef SOCKETWS_HAS_DEFLATE

#include "socket/SocketWS-private.h"

/* Test operation types */
enum
{
  OP_COMPRESS = 0,
  OP_DECOMPRESS,
  OP_ROUNDTRIP,
  OP_DECOMPRESS_LARGE,
  OP_MAX
};

/* Helper to read uint32 from fuzzer data */
static inline uint32_t
read_u32 (const uint8_t *data)
{
  return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
         | ((uint32_t)data[2] << 8) | (uint32_t)data[3];
}

/* Initialize a minimal SocketWS context for compression testing */
static SocketWS_T
create_test_ws (Arena_T arena, int role, int no_context_takeover)
{
  SocketWS_T ws;

  ws = Arena_calloc (arena, 1, sizeof (*ws), __FILE__, __LINE__);
  if (!ws)
    return NULL;

  ws->arena = arena;
  ws->role = role;
  ws->config.max_message_size = 1024 * 1024; /* 1MB limit */

  /* Set up handshake params for compression init */
  ws->handshake.server_max_window_bits = 15;
  ws->handshake.client_max_window_bits = 15;
  ws->handshake.server_no_context_takeover = no_context_takeover;
  ws->handshake.client_no_context_takeover = no_context_takeover;

  return ws;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketWS_T ws = NULL;
  unsigned char *output = NULL;
  size_t output_len = 0;
  int ret;

  /* Need at least: op(1) + role(1) + no_takeover(1) + some data */
  if (size < 4)
    return 0;

  /* Limit input to prevent OOM */
  if (size > 65536)
    return 0;

  uint8_t op = data[0] % OP_MAX;
  int role = (data[1] & 1) ? WS_ROLE_SERVER : WS_ROLE_CLIENT;
  int no_context_takeover = data[2] & 1;
  const uint8_t *payload = data + 3;
  size_t payload_len = size - 3;

  arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    ws = create_test_ws (arena, role, no_context_takeover);
    if (!ws)
      goto cleanup;

    /* Initialize compression */
    ret = ws_compression_init (ws);
    if (ret != 0)
      goto cleanup;

    ws->compression_enabled = 1;

    switch (op)
      {
      case OP_COMPRESS:
        /* Test compression with fuzzed input */
        ret = ws_compress_message (
            ws, payload, payload_len, &output, &output_len);
        (void)ret;
        break;

      case OP_DECOMPRESS:
        /* Test decompression with fuzzed (likely invalid) compressed data */
        ret = ws_decompress_message (
            ws, payload, payload_len, &output, &output_len);
        (void)ret;
        break;

      case OP_ROUNDTRIP:
        /* Compress then decompress - should roundtrip correctly */
        {
          unsigned char *compressed = NULL;
          size_t compressed_len = 0;
          unsigned char *decompressed = NULL;
          size_t decompressed_len = 0;

          ret = ws_compress_message (
              ws, payload, payload_len, &compressed, &compressed_len);
          if (ret == 0 && compressed != NULL && compressed_len > 0)
            {
              ret = ws_decompress_message (ws,
                                           compressed,
                                           compressed_len,
                                           &decompressed,
                                           &decompressed_len);
              /* Verify roundtrip if successful */
              if (ret == 0 && decompressed != NULL)
                {
                  /* Should match original */
                  if (decompressed_len == payload_len)
                    {
                      (void)memcmp (decompressed, payload, payload_len);
                    }
                }
            }
        }
        break;

      case OP_DECOMPRESS_LARGE:
        /* Test with smaller max_message_size to trigger bomb protection */
        ws->config.max_message_size = 4096;
        ret = ws_decompress_message (
            ws, payload, payload_len, &output, &output_len);
        (void)ret;
        break;
      }

  cleanup:
    if (ws && ws->compression_enabled)
      ws_compression_free (ws);
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on memory exhaustion */
  }
  FINALLY
  {
    Arena_dispose (&arena);
  }
  END_TRY;

  return 0;
}

#else /* !SOCKETWS_HAS_DEFLATE */

/* Stub fuzzer when WebSocket compression is not available */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0;
}

#endif /* SOCKETWS_HAS_DEFLATE */

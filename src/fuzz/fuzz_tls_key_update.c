/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_tls_key_update.c - Fuzzer for TLS 1.3 KeyUpdate functionality
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketTLS_request_key_update() with various socket states
 * - SocketTLS_get_key_update_count() counter behavior
 * - Edge cases: non-TLS sockets, pre-handshake, TLS 1.2 sockets
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_tls_key_update
 * Run:   ./fuzz_tls_key_update corpus/tls_key_update/ -fork=16 -max_len=64
 */

#if SOCKET_HAS_TLS

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"

/* Operation codes */
enum KeyUpdateOp
{
  OP_KEY_UPDATE_NON_TLS = 0,      /* KeyUpdate on non-TLS socket */
  OP_KEY_UPDATE_BEFORE_HANDSHAKE, /* KeyUpdate before handshake */
  OP_KEY_UPDATE_GET_COUNT,        /* Get update count */
  OP_KEY_UPDATE_REQUEST_PEER,     /* Request with peer update */
  OP_KEY_UPDATE_LOCAL_ONLY,       /* Request local-only update */
  OP_KEY_UPDATE_MULTIPLE,         /* Multiple updates in sequence */
  OP_KEY_UPDATE_AFTER_DISABLE,    /* KeyUpdate after TLS disable */
  OP_COUNT
};

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Byte 1: request_peer_update flag
 * - Byte 2: Number of iterations for multiple update test
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Socket_T sock = NULL;
  SocketTLSContext_T ctx = NULL;

  if (size < 3)
    return 0;

  uint8_t op = data[0] % OP_COUNT;
  int request_peer = data[1] % 2;
  uint8_t iterations = data[2] % 10; /* Cap at 10 iterations */

  TRY
  {
    switch (op)
      {
      case OP_KEY_UPDATE_NON_TLS:
        {
          /* Test KeyUpdate on non-TLS socket */
          sock = Socket_new (AF_INET, SOCK_STREAM, 0);
          if (!sock)
            break;

          /* Should return 0 with EINVAL */
          int ret = SocketTLS_request_key_update (sock, request_peer);
          assert (ret == 0);

          /* Count should be 0 */
          assert (SocketTLS_get_key_update_count (sock) == 0);
        }
        break;

      case OP_KEY_UPDATE_BEFORE_HANDSHAKE:
        {
          /* Test KeyUpdate before handshake completes */
          sock = Socket_new (AF_INET, SOCK_STREAM, 0);
          if (!sock)
            break;

          ctx = SocketTLSContext_new_client (NULL);
          if (!ctx)
            break;

          SocketTLS_enable (sock, ctx);

          /* Should return 0 since handshake not done */
          int ret = SocketTLS_request_key_update (sock, request_peer);
          assert (ret == 0);

          /* Count should still be 0 */
          assert (SocketTLS_get_key_update_count (sock) == 0);
        }
        break;

      case OP_KEY_UPDATE_GET_COUNT:
        {
          /* Test get_key_update_count in various states */
          sock = Socket_new (AF_INET, SOCK_STREAM, 0);
          if (!sock)
            break;

          /* Non-TLS: should return 0 */
          assert (SocketTLS_get_key_update_count (sock) == 0);

          ctx = SocketTLSContext_new_client (NULL);
          if (!ctx)
            break;

          SocketTLS_enable (sock, ctx);

          /* TLS enabled but no handshake: should return 0 */
          assert (SocketTLS_get_key_update_count (sock) == 0);
        }
        break;

      case OP_KEY_UPDATE_REQUEST_PEER:
        {
          /* Test with request_peer_update = 1 */
          sock = Socket_new (AF_INET, SOCK_STREAM, 0);
          if (!sock)
            break;

          ctx = SocketTLSContext_new_client (NULL);
          if (!ctx)
            break;

          SocketTLS_enable (sock, ctx);

          /* Should return 0 (handshake not done) */
          int ret = SocketTLS_request_key_update (sock, 1);
          assert (ret == 0);
        }
        break;

      case OP_KEY_UPDATE_LOCAL_ONLY:
        {
          /* Test with request_peer_update = 0 */
          sock = Socket_new (AF_INET, SOCK_STREAM, 0);
          if (!sock)
            break;

          ctx = SocketTLSContext_new_client (NULL);
          if (!ctx)
            break;

          SocketTLS_enable (sock, ctx);

          /* Should return 0 (handshake not done) */
          int ret = SocketTLS_request_key_update (sock, 0);
          assert (ret == 0);
        }
        break;

      case OP_KEY_UPDATE_MULTIPLE:
        {
          /* Test multiple get_count calls */
          sock = Socket_new (AF_INET, SOCK_STREAM, 0);
          if (!sock)
            break;

          ctx = SocketTLSContext_new_client (NULL);
          if (!ctx)
            break;

          SocketTLS_enable (sock, ctx);

          /* Multiple count reads should be consistent */
          for (uint8_t i = 0; i < iterations; i++)
            {
              int count = SocketTLS_get_key_update_count (sock);
              assert (count == 0); /* Always 0 before handshake */
            }
        }
        break;

      case OP_KEY_UPDATE_AFTER_DISABLE:
        {
          /* Test KeyUpdate after TLS is disabled */
          sock = Socket_new (AF_INET, SOCK_STREAM, 0);
          if (!sock)
            break;

          ctx = SocketTLSContext_new_client (NULL);
          if (!ctx)
            break;

          SocketTLS_enable (sock, ctx);
          SocketTLS_disable (sock);

          /* Should return 0 since TLS is disabled */
          int ret = SocketTLS_request_key_update (sock, request_peer);
          assert (ret == 0);

          /* Count should be 0 */
          assert (SocketTLS_get_key_update_count (sock) == 0);
        }
        break;
      }
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Expected for some operations */
  }
  EXCEPT (Socket_Failed)
  {
    /* Expected for socket creation issues */
  }
  FINALLY
  {
    if (sock)
      {
        if (ctx)
          SocketTLS_disable (sock);
        Socket_free (&sock);
      }
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;

  return 0;
}

#else /* !SOCKET_HAS_TLS */

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0;
}

#endif /* SOCKET_HAS_TLS */

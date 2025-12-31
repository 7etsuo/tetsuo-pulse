/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_tls_ktls.c - Fuzzer for kTLS (Kernel TLS) Offload Support
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketTLS_ktls_available() availability detection
 * - SocketTLS_enable_ktls() enable/disable sequences
 * - SocketTLS_is_ktls_tx_active() / SocketTLS_is_ktls_rx_active() state queries
 * - kTLS configuration constant verification
 *
 * Security Focus:
 * - State machine validation (enable before/after handshake)
 * - Graceful fallback when kTLS unavailable
 * - Edge cases in offload status queries
 * - Memory safety during enable/disable cycles
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON -DENABLE_TLS=ON && make
 * fuzz_tls_ktls Run:   ./fuzz_tls_ktls corpus/tls_ktls/ -fork=16 -max_len=256
 */

#if SOCKET_HAS_TLS

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"

/* Operation codes for kTLS fuzzing */
enum KtlsOp
{
  KTLS_OP_CHECK_AVAILABLE = 0,
  KTLS_OP_ENABLE_NO_TLS,
  KTLS_OP_ENABLE_WITH_TLS,
  KTLS_OP_STATUS_NULL,
  KTLS_OP_STATUS_NO_TLS,
  KTLS_OP_STATUS_TLS_NO_HANDSHAKE,
  KTLS_OP_VERIFY_CONSTANTS,
  KTLS_OP_ENABLE_DISABLE_CYCLE,
  KTLS_OP_COUNT
};

/* Verify kTLS configuration constants are consistent */
static void
verify_ktls_constants (void)
{
  /* kTLS default enablement */
  assert (SOCKET_TLS_KTLS_ENABLED == 0 || SOCKET_TLS_KTLS_ENABLED == 1);

  /* Kernel version requirements (hex-encoded) */
  assert (SOCKET_TLS_KTLS_MIN_KERNEL_TX == 0x040D00);     /* 4.13.0 */
  assert (SOCKET_TLS_KTLS_MIN_KERNEL_RX == 0x041100);     /* 4.17.0 */
  assert (SOCKET_TLS_KTLS_MIN_KERNEL_CHACHA == 0x050B00); /* 5.11.0 */

  /* Sendfile buffer size - reasonable bounds */
  assert (SOCKET_TLS_KTLS_SENDFILE_BUFSIZE >= 4096);
  assert (SOCKET_TLS_KTLS_SENDFILE_BUFSIZE <= (1024 * 1024));
  assert ((SOCKET_TLS_KTLS_SENDFILE_BUFSIZE
           & (SOCKET_TLS_KTLS_SENDFILE_BUFSIZE - 1))
              == 0
          || SOCKET_TLS_KTLS_SENDFILE_BUFSIZE
                 == 64 * 1024); /* Power of 2 or 64KB */
}

/* Test availability detection */
static void
fuzz_check_available (void)
{
  int available = SocketTLS_ktls_available ();

  /* Result must be boolean */
  assert (available == 0 || available == 1);

  /* Multiple calls should return consistent results */
  int available2 = SocketTLS_ktls_available ();
  assert (available == available2);
}

/* Test enable on non-TLS socket (should raise exception) */
static void
fuzz_enable_no_tls (void)
{
  Socket_T sock = NULL;
  volatile int exception_raised = 0;

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    if (!sock)
      {
        /* Socket creation may fail in constrained environment */
        return;
      }

    /* This should raise SocketTLS_Failed */
    SocketTLS_enable_ktls (sock);
  }
  EXCEPT (SocketTLS_Failed)
  {
    exception_raised = 1;
  }
  FINALLY
  {
    if (sock)
      Socket_free (&sock);
  }
  END_TRY;

  /* Must have raised exception */
  assert (exception_raised == 1);
}

/* Test status queries on NULL socket */
static void
fuzz_status_null (void)
{
  /* NULL socket should return -1 */
  assert (SocketTLS_is_ktls_tx_active (NULL) == -1);
  assert (SocketTLS_is_ktls_rx_active (NULL) == -1);
}

/* Test status queries on non-TLS socket */
static void
fuzz_status_no_tls (void)
{
  Socket_T sock = NULL;

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    if (!sock)
      return;

    /* Non-TLS socket should return -1 */
    assert (SocketTLS_is_ktls_tx_active (sock) == -1);
    assert (SocketTLS_is_ktls_rx_active (sock) == -1);
  }
  FINALLY
  {
    if (sock)
      Socket_free (&sock);
  }
  END_TRY;
}

/* Test enable with TLS but no handshake */
static void
fuzz_enable_with_tls (void)
{
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    /* Create socket pair */
    SocketPair_new (SOCK_STREAM, &client, &server);
    if (!client || !server)
      return;

    /* Create minimal TLS context */
    ctx = SocketTLSContext_new_client (NULL);
    if (!ctx)
      {
        Socket_free (&client);
        Socket_free (&server);
        return;
      }

    /* Enable TLS */
    SocketTLS_enable (client, ctx);

    /* Enable kTLS - should succeed (sets flag) */
    SocketTLS_enable_ktls (client);

    /* Status should be -1 (handshake not complete) */
    assert (SocketTLS_is_ktls_tx_active (client) == -1);
    assert (SocketTLS_is_ktls_rx_active (client) == -1);
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* Test enable/disable cycle */
static void
fuzz_enable_disable_cycle (const uint8_t *data, size_t size)
{
  Socket_T client = NULL, server = NULL;
  SocketTLSContext_T ctx = NULL;

  if (size < 1)
    return;

  /* Use first byte to determine number of enable/disable cycles */
  uint8_t cycles = data[0] % 8 + 1;

  TRY
  {
    SocketPair_new (SOCK_STREAM, &client, &server);
    if (!client || !server)
      return;

    ctx = SocketTLSContext_new_client (NULL);
    if (!ctx)
      {
        Socket_free (&client);
        Socket_free (&server);
        return;
      }

    for (uint8_t i = 0; i < cycles; i++)
      {
        /* Enable TLS */
        SocketTLS_enable (client, ctx);

        /* Enable kTLS */
        SocketTLS_enable_ktls (client);

        /* Query status (should be -1) */
        (void)SocketTLS_is_ktls_tx_active (client);
        (void)SocketTLS_is_ktls_rx_active (client);

        /* Disable TLS */
        SocketTLS_disable (client);

        /* Status should be -1 after disable */
        assert (SocketTLS_is_ktls_tx_active (client) == -1);
        assert (SocketTLS_is_ktls_rx_active (client) == -1);
      }
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      Socket_free (&server);
    if (ctx)
      SocketTLSContext_free (&ctx);
  }
  END_TRY;
}

/* LibFuzzer entry point */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 1)
    return 0;

  /* First byte selects operation */
  uint8_t op = data[0] % KTLS_OP_COUNT;

  switch (op)
    {
    case KTLS_OP_CHECK_AVAILABLE:
      fuzz_check_available ();
      break;

    case KTLS_OP_ENABLE_NO_TLS:
      fuzz_enable_no_tls ();
      break;

    case KTLS_OP_ENABLE_WITH_TLS:
      fuzz_enable_with_tls ();
      break;

    case KTLS_OP_STATUS_NULL:
      fuzz_status_null ();
      break;

    case KTLS_OP_STATUS_NO_TLS:
      fuzz_status_no_tls ();
      break;

    case KTLS_OP_STATUS_TLS_NO_HANDSHAKE:
      fuzz_enable_with_tls ();
      break;

    case KTLS_OP_VERIFY_CONSTANTS:
      verify_ktls_constants ();
      break;

    case KTLS_OP_ENABLE_DISABLE_CYCLE:
      fuzz_enable_disable_cycle (data + 1, size - 1);
      break;

    default:
      break;
    }

  return 0;
}

#else /* !SOCKET_HAS_TLS */

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0;
}

#endif /* SOCKET_HAS_TLS */

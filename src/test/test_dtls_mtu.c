/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_dtls_mtu.c - DTLS MTU Configuration Tests
 *
 * Part of the Socket Library Test Suite (Section 8.1)
 *
 * Tests:
 * 1. MTU configuration on context
 * 2. MTU configuration on socket
 * 3. MTU validation
 * 4. MTU boundary conditions
 */

/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/SocketDgram.h"
#include "test/Test.h"

#if SOCKET_HAS_TLS
#include "tls/SocketDTLS.h"
#include "tls/SocketDTLSConfig.h"
#include "tls/SocketDTLSContext.h"

/* Suppress -Wclobbered for volatile variables across setjmp/longjmp */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* ==================== Context MTU Tests ==================== */

TEST (dtls_mtu_context_default)
{
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Default MTU should be SOCKET_DTLS_DEFAULT_MTU */
    size_t mtu = SocketDTLSContext_get_mtu (ctx);
    ASSERT_EQ (mtu, (size_t)SOCKET_DTLS_DEFAULT_MTU);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (dtls_mtu_context_set_valid)
{
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set various valid MTU values */
    SocketDTLSContext_set_mtu (ctx, 1400);
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx), 1400);

    SocketDTLSContext_set_mtu (ctx, 576);
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx), 576);

    SocketDTLSContext_set_mtu (ctx, 9000);
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx), 9000);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (dtls_mtu_context_min_boundary)
{
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set minimum MTU */
    SocketDTLSContext_set_mtu (ctx, SOCKET_DTLS_MIN_MTU);
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx), (size_t)SOCKET_DTLS_MIN_MTU);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (dtls_mtu_context_max_boundary)
{
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* Set maximum MTU */
    SocketDTLSContext_set_mtu (ctx, SOCKET_DTLS_MAX_MTU);
    ASSERT_EQ (SocketDTLSContext_get_mtu (ctx), (size_t)SOCKET_DTLS_MAX_MTU);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (dtls_mtu_context_too_small_fails)
{
  SocketDTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* MTU below minimum should fail */
    TRY { SocketDTLSContext_set_mtu (ctx, 100); }
    EXCEPT (SocketDTLS_Failed) { caught = 1; }
    END_TRY;

    ASSERT_EQ (caught, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (dtls_mtu_context_too_large_fails)
{
  SocketDTLSContext_T ctx = NULL;
  volatile int caught = 0;

  TRY
  {
    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    /* MTU above maximum should fail */
    TRY { SocketDTLSContext_set_mtu (ctx, 100000); }
    EXCEPT (SocketDTLS_Failed) { caught = 1; }
    END_TRY;

    ASSERT_EQ (caught, 1);
  }
  FINALLY
  {
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== Socket MTU Tests ==================== */

TEST (dtls_mtu_socket_default)
{
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ASSERT_NOT_NULL (socket);

    ctx = SocketDTLSContext_new_client (NULL);
    ASSERT_NOT_NULL (ctx);

    SocketDTLS_enable (socket, ctx);

    /* Socket MTU should inherit from context default */
    size_t mtu = SocketDTLS_get_mtu (socket);
    ASSERT_EQ (mtu, (size_t)SOCKET_DTLS_DEFAULT_MTU);
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (dtls_mtu_socket_set_custom)
{
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Set custom MTU on socket */
    SocketDTLS_set_mtu (socket, 1200);
    ASSERT_EQ (SocketDTLS_get_mtu (socket), 1200);
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
}

TEST (dtls_mtu_socket_inherits_context)
{
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);

    /* Set context MTU before enable */
    SocketDTLSContext_set_mtu (ctx, 1500);

    SocketDTLS_enable (socket, ctx);

    /* Socket should have context's MTU */
    ASSERT_EQ (SocketDTLS_get_mtu (socket), 1500);
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
}

/* ==================== Validation Macro Tests ==================== */

TEST (dtls_mtu_valid_macro)
{
  /* Test SOCKET_DTLS_VALID_MTU macro */
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (SOCKET_DTLS_MIN_MTU), 1);
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (SOCKET_DTLS_MAX_MTU), 1);
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (SOCKET_DTLS_DEFAULT_MTU), 1);
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (1400), 1);
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (100), 0);
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (100000), 0);
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (0), 0);
}

/* ==================== Configuration Constants Tests ==================== */

TEST (dtls_mtu_config_constants)
{
  /* Verify config constants are sensible */
  ASSERT (SOCKET_DTLS_MIN_MTU > 0);
  ASSERT (SOCKET_DTLS_MAX_MTU > SOCKET_DTLS_MIN_MTU);
  ASSERT (SOCKET_DTLS_DEFAULT_MTU >= SOCKET_DTLS_MIN_MTU);
  ASSERT (SOCKET_DTLS_DEFAULT_MTU <= SOCKET_DTLS_MAX_MTU);

  /* Common network MTU values should be valid */
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (576), 1);  /* IPv4 minimum */
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (1280), 1); /* IPv6 minimum */
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (1400), 1); /* Conservative default */
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (1500), 1); /* Ethernet */
  ASSERT_EQ (SOCKET_DTLS_VALID_MTU (9000), 1); /* Jumbo frames */
}

/* ==================== Edge Cases ==================== */

TEST (dtls_mtu_socket_before_enable)
{
  SocketDgram_T socket = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ASSERT_NOT_NULL (socket);

    /* Get MTU before DTLS enable - should return 0 or default */
    size_t mtu = SocketDTLS_get_mtu (socket);
    /* Implementation may return 0 or default for non-DTLS socket */
    (void)mtu;
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
  }
  END_TRY;
}

TEST (dtls_mtu_update_after_enable)
{
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  TRY
  {
    socket = SocketDgram_new (AF_INET, 0);
    ctx = SocketDTLSContext_new_client (NULL);
    SocketDTLS_enable (socket, ctx);

    /* Update MTU multiple times */
    SocketDTLS_set_mtu (socket, 1000);
    ASSERT_EQ (SocketDTLS_get_mtu (socket), 1000);

    SocketDTLS_set_mtu (socket, 1500);
    ASSERT_EQ (SocketDTLS_get_mtu (socket), 1500);

    SocketDTLS_set_mtu (socket, 800);
    ASSERT_EQ (SocketDTLS_get_mtu (socket), 800);
  }
  FINALLY
  {
    if (socket)
      SocketDgram_free (&socket);
    if (ctx)
      SocketDTLSContext_free (&ctx);
  }
  END_TRY;
}

#endif /* SOCKET_HAS_TLS */

int
main (void)
{
  /* Ignore SIGPIPE */
  signal (SIGPIPE, SIG_IGN);

  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
